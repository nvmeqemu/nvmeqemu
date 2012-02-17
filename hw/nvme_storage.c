/*
 * Copyright (c) 2011 Intel Corporation
 *
 * by
 *    Maciej Patelczyk <mpatelcz@gkslx007.igk.intel.com>
 *    Krzysztof Wierzbicki <krzysztof.wierzbicki@intel.com>
 *    Patrick Porlan <patrick.porlan@intel.com>
 *    Nisheeth Bhat <nisheeth.bhat@intel.com>
 *    Keith Busch <keith.busch@intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "nvme.h"
#include "nvme_debug.h"
#include <sys/mman.h>



void nvme_dma_mem_read(target_phys_addr_t addr, uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, buf, len, 0);
}

void nvme_dma_mem_write(target_phys_addr_t addr, uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, buf, len, 1);
}

static uint8_t do_rw_prp(NVMEState *n, uint64_t mem_addr, uint64_t *data_size_p,
    uint64_t *file_offset_p, uint8_t *mapping_addr, uint8_t rw)
{
    uint64_t data_len;

    if (*data_size_p == 0) {
        return FAIL;
    }

    /* Data Len to be written per page basis */
    data_len = PAGE_SIZE - (mem_addr % PAGE_SIZE);
    if (data_len > *data_size_p) {
        data_len = *data_size_p;
    }

    LOG_DBG("File offset for read/write:%ld", *file_offset_p);
    LOG_DBG("Length for read/write:%ld", data_len);
    LOG_DBG("Address for read/write:%ld", mem_addr);

    switch (rw) {
    case NVME_CMD_READ:
        LOG_DBG("Read cmd called");
        nvme_dma_mem_write(mem_addr, (mapping_addr + *file_offset_p), data_len);
        break;
    case NVME_CMD_WRITE:
        LOG_DBG("Write cmd called");
        nvme_dma_mem_read(mem_addr, (mapping_addr + *file_offset_p), data_len);
        break;
    default:
        LOG_ERR("Error- wrong opcode: %d", rw);
        return FAIL;
    }
    *file_offset_p = *file_offset_p + data_len;
    *data_size_p = *data_size_p - data_len;
    return NVME_SC_SUCCESS;
}

static uint8_t do_rw_prp_list(NVMEState *n, NVMECmd *command,
    uint64_t *data_size_p, uint64_t *file_offset_p, uint8_t *mapping_addr)
{
    uint64_t prp_list[512], prp_entries;
    uint16_t i = 0;
    uint8_t res = FAIL;
    struct NVME_rw *cmd = (struct NVME_rw *)command;

    LOG_DBG("Data Size remaining for read/write:%ld", *data_size_p);

    /* Logic to find the number of PRP Entries */
    prp_entries = (uint64_t) ((*data_size_p + PAGE_SIZE - 1) / PAGE_SIZE);
    nvme_dma_mem_read(cmd->prp2, (uint8_t *)prp_list,
        prp_entries * sizeof(uint64_t));

    i = 0;
    /* Read/Write on PRPList */
    while (*data_size_p != 0) {
        if (i == 511) {
            /* Calculate the actual number of remaining entries */
            prp_entries = (uint64_t) ((*data_size_p + PAGE_SIZE - 1) /
                PAGE_SIZE);
            nvme_dma_mem_read(prp_list[511], (uint8_t *)prp_list,
                prp_entries * sizeof(uint64_t));
            i = 0;
        }

        res = do_rw_prp(n, prp_list[i], data_size_p,
            file_offset_p, mapping_addr, cmd->opcode);
        LOG_DBG("Data Size remaining for read/write:%ld", *data_size_p);
        if (res == FAIL) {
            break;
        }
        i++;
    }
    return res;
}

/*********************************************************************
    Function     :    update_ns_util
    Description  :    Updates the Namespace Utilization
                      of NVME disk
    Return Type  :    void

    Arguments    :    NVMEState * : Pointer to NVME device State
                      struct NVME_rw * : NVME IO command
*********************************************************************/
static void update_ns_util(DiskInfo *disk, struct NVME_rw *e)
{
    uint64_t index;

    /* Update the namespace utilization */
    for (index = e->slba; index <= e->nlb + e->slba; index++) {
        if (!((disk->ns_util[index / 8]) & (1 << (index % 8)))) {
            disk->ns_util[(index / 8)] |= (1 << (index % 8));
            disk->idtfy_ns->nuse++;
        }
    }
}

uint8_t nvme_io_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe)
{
    uint64_t tmp;
    struct NVME_rw *e = (struct NVME_rw *)sqe;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint8_t res = FAIL;
    uint64_t data_size, file_offset;
    uint8_t *mapping_addr;
    /* Assuming 64KB as maximum bloack size */
    uint16_t nvme_blk_sz;
    DiskInfo *disk;

    sf->sc = NVME_SC_SUCCESS;
    LOG_DBG("%s(): called", __func__);

    if (sqe->opcode == NVME_CMD_FLUSH) {
        return NVME_SC_SUCCESS;
    }

    if ((sqe->opcode != NVME_CMD_READ) &&
        (sqe->opcode != NVME_CMD_WRITE)) {
        LOG_NORM("%s():Wrong IO opcode:\t\t0x%02x", __func__, sqe->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        goto exit;
    } else if (e->nsid == 0 || (e->nsid > n->num_namespaces) ||
            n->disk[e->nsid - 1] == NULL) {
        /* Check for valid values of namespace ID for IO R/W */
        LOG_NORM("%s(): Invalid Namespace ID", __func__);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        goto exit;
    }

    disk = n->disk[e->nsid - 1];
    if ((e->slba + e->nlb) >= disk->idtfy_ns->nsze) {
        LOG_NORM("%s(): LBA out of range", __func__);
        sf->sc = NVME_SC_LBA_RANGE;
        goto exit;
    } else if ((e->slba + e->nlb) >= disk->idtfy_ns->ncap) {
        LOG_NORM("%s():Capacity Exceeded", __func__);
        sf->sc = NVME_SC_CAP_EXCEEDED;
        goto exit;
    }

    /* Read in the command */
    nvme_blk_sz = NVME_BLOCK_SIZE(disk->idtfy_ns->lbafx[
        disk->idtfy_ns->flbas].lbads);
    LOG_DBG("NVME Block size: %u", nvme_blk_sz);
    data_size = (e->nlb + 1) * nvme_blk_sz;

    file_offset = e->slba * nvme_blk_sz;
    mapping_addr = disk->mapping_addr;

    /* Namespace not ready */
    if (mapping_addr == NULL) {
        LOG_NORM("%s():Namespace not ready", __func__);
        sf->sc = NVME_SC_NS_NOT_READY;
        goto exit;
    }

    /* Writing/Reading PRP1 */
    res = do_rw_prp(n, e->prp1,
        &data_size, &file_offset, mapping_addr, e->opcode);
    if (res == FAIL) {
        goto exit;
    } else if (data_size == 0) {
        goto ns_utl;
    }

    if (data_size <= PAGE_SIZE) {
        LOG_DBG("Data Size remaining for read/write:%ld", data_size);
        res = do_rw_prp(n, e->prp2,
            &data_size, &file_offset, mapping_addr, e->opcode);
        LOG_DBG("Data Size remaining for read/write:%ld", data_size);
    } else {
        res = do_rw_prp_list(n, sqe, &data_size, &file_offset, mapping_addr);
    }

    if (res == FAIL) {
        goto exit;
    }

ns_utl:
    if (e->opcode == NVME_CMD_WRITE) {
        update_ns_util(disk, e);
        if (++disk->host_write_commands[0] == 0) {
            ++disk->host_write_commands[1];
        }
        disk->write_data_counter += e->nlb + 1;
        tmp = disk->data_units_written[0];
        disk->data_units_written[0] += (disk->write_data_counter / 1000);
        disk->write_data_counter %= 1000;
        if (tmp > disk->data_units_written[0]) {
            ++disk->data_units_written[1];
        }
    } else if (e->opcode == NVME_CMD_READ) {
        if (++disk->host_read_commands[0] == 0) {
            ++disk->host_read_commands[1];
        }
        disk->read_data_counter += e->nlb + 1;
        tmp = disk->data_units_read[0];
        disk->data_units_read[0] += (disk->read_data_counter / 1000);
        disk->read_data_counter %= 1000;
        if (tmp > disk->data_units_read[0]) {
            ++disk->data_units_read[1];
        }
    }
exit:
    return res;
}

/*********************************************************************
    Function     :    nvme_create_storage_disk
    Description  :    Creates a NVME Storage Disk and the
                      namespaces within
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    uint32_t : instance number of the nvme device
                      uint32_t : namespace id
                      DiskInfo * : NVME disk to create storage for
*********************************************************************/
int nvme_create_storage_disk(uint32_t instance, uint32_t nsid, DiskInfo *disk)
{
    /* Assuming 64KB as maximum block size */
    uint16_t nvme_blk_sz;
    char str[64];

    snprintf(str, sizeof(str), "nvme_disk%d_n%d.img", instance, nsid);
    disk->nsid = nsid;

    disk->fd = open(str, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (disk->fd < 0) {
        LOG_ERR("Error while creating the storage");
        return FAIL;
    }

    nvme_blk_sz = NVME_BLOCK_SIZE(disk->idtfy_ns->
        lbafx[disk->idtfy_ns->flbas].lbads);

    if (posix_fallocate(disk->fd, 0, disk->idtfy_ns->ncap *
            nvme_blk_sz) != 0) {
        LOG_ERR("Error while allocating space for namespace");
        return FAIL;
    }

    disk->mapping_addr = NULL;
    disk->mapping_size = 0;

    return SUCCESS;
}

/*********************************************************************
    Function     :    nvme_create_storage_disks
    Description  :    Creates a NVME Storage Disks and the
                      namespaces within
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_create_storage_disks(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->disk[i] == NULL) {
            continue;
        }
        ret = nvme_create_storage_disk(n->instance, i + 1, n->disk[i]);
    }

    LOG_NORM("%s():Backing store created for instance %d", __func__,
        n->instance);

    return ret;
}

/*********************************************************************
    Function     :    nvme_del_storage_disk
    Description  :    Delete the NVME Storage Disk
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    DiskInfo * : Pointer to NVME disk
*********************************************************************/
int nvme_del_storage_disk(DiskInfo *disk)
{
    if (close(disk->fd) < 0) {
        LOG_ERR("Unable to close the nvme disk");
        return FAIL;
    }
    return SUCCESS;
}

/*********************************************************************
    Function     :    nvme_del_storage_disks
    Description  :    Deletes all NVME Storage Disks
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_del_storage_disks(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;

    /* If required do ftruncate to remove the allocated
     * memory using posix_fallocate */
    for (i = 0; i < n->num_namespaces; i++) {
        if (n->disk[i] == NULL) {
            continue;
        }
        ret = nvme_del_storage_disk(n->disk[i]);
    }
    return ret;
}

/*********************************************************************
    Function     :    nvme_del_storage_disk
    Description  :    Deletes NVME Storage Disk
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    DiskInfo * : Pointer to NVME disk
*********************************************************************/
int nvme_close_storage_disk(DiskInfo *disk)
{
    if (disk->mapping_addr != NULL) {
        if (munmap(disk->mapping_addr, disk->mapping_size) < 0) {
            LOG_ERR("Error while closing namespace: %d", disk->nsid);
            return FAIL;
        } else {
            disk->mapping_addr = NULL;
            disk->mapping_size = 0;
        }
    }
    return SUCCESS;
}

/*********************************************************************
    Function     :    nvme_close_storage_disks
    Description  :    Closes the NVME Storage Disks and the
                      associated namespaces
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_close_storage_disks(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->disk[i] == NULL) {
            continue;
        }
        ret = nvme_close_storage_disk(n->disk[i]);
    }
    return ret;
}

/*********************************************************************
    Function     :    nvme_open_storage_disk
    Description  :    Opens the NVME Storage Disk and its namespace
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    DiskInfo * : Pointer to NVME device State
*********************************************************************/
int nvme_open_storage_disk(DiskInfo *disk)
{
    uint16_t nvme_blk_sz;
    if (disk->mapping_addr == NULL) {
        nvme_blk_sz = NVME_BLOCK_SIZE(disk->idtfy_ns->lbafx[
            disk->idtfy_ns->flbas].lbads);

        disk->mapping_addr = mmap(NULL, disk->idtfy_ns->ncap * nvme_blk_sz,
            PROT_READ | PROT_WRITE, MAP_SHARED, disk->fd, 0);

        if (disk->mapping_addr == NULL) {
            LOG_ERR("Error while opening namespace: %d", disk->nsid);
            return FAIL;
        }

        disk->mapping_size = disk->idtfy_ns->ncap * nvme_blk_sz;
    }
    return SUCCESS;
}

/*********************************************************************
    Function     :    nvme_open_storage_disks
    Description  :    Opens the NVME Storage Disks and the
                      namespaces within for usage
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_open_storage_disks(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->disk[i] == NULL) {
            continue;
        }
        ret = nvme_open_storage_disk(n->disk[i]);
    }
    return ret;
}

