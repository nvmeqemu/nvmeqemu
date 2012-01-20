/*
 * Copyright (c) 2011 Intel Corporation
 *
 * by
 *    Maciej Patelczyk <mpatelcz@gkslx007.igk.intel.com>
 *    Krzysztof Wierzbicki <krzysztof.wierzbicki@intel.com>
 *    Patrick Porlan <patrick.porlan@intel.com>
 *    Nisheeth Bhat <nisheeth.bhat@intel.com>
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
static void update_ns_util(NVMEState *n, struct NVME_rw *e)
{
    uint16_t index;

    /* Update the namespace utilization */
    for (index = 0; index <= e->nlb; index++) {
        if (!(n->disk[(e->nsid - 1)].ns_util[(e->slba + index) / 8]
            & (1 << ((e->slba + index) % 8)))) {
            n->disk[(e->nsid - 1)].ns_util[((e->slba + index) / 8)] =
                n->disk[(e->nsid - 1)].ns_util[((e->slba + index) / 8)]
                    | (1 << ((e->slba + index) % 8));
            n->disk[(e->nsid - 1)].idtfy_ns->nuse++;
        }
    }
}

uint8_t nvme_io_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe)
{
    struct NVME_rw *e = (struct NVME_rw *)sqe;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint8_t res = FAIL;
    uint64_t data_size, file_offset;
    uint8_t *mapping_addr;
    /* Assuming 64KB as maximum bloack size */
    uint16_t nvme_blk_sz;

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
    } else if (e->nsid == 0 || (e->nsid > n->idtfy_ctrl->nn)) {
        /* Check for valid values of namespace ID for IO R/W */
        LOG_NORM("%s(): Invalid Namespace ID", __func__);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        goto exit;
    } else if ((e->slba + e->nlb) >= n->disk[(e->nsid - 1)].idtfy_ns->nsze) {
        LOG_NORM("%s(): LBA out of range", __func__);
        sf->sc = NVME_SC_LBA_RANGE;
        goto exit;
    } else if ((e->slba + e->nlb) >= n->disk[(e->nsid - 1)].idtfy_ns->ncap) {
        LOG_NORM("%s():Capacity Exceeded", __func__);
        sf->sc = NVME_SC_CAP_EXCEEDED;
        goto exit;
    }

    /* Read in the command */
    nvme_blk_sz = NVME_BLOCK_SIZE(n->disk[(e->nsid - 1)].
        idtfy_ns->lbafx[n->disk[(e->nsid - 1)].idtfy_ns->flbas].lbads);
    LOG_DBG("NVME Block size: %u", nvme_blk_sz);
    data_size = (e->nlb + 1) * nvme_blk_sz;

    file_offset = e->slba * nvme_blk_sz;
    mapping_addr = n->disk[(e->nsid - 1)].mapping_addr;

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
        update_ns_util(n, e);
    }
exit:
    return res;
}

/*********************************************************************
    Function     :    nvme_create_storage_disk
    Description  :    Creates a NVME Storage Disk and the
                      namespaces within
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
                      uint32_t : Disk number
*********************************************************************/
int nvme_create_storage_disk(NVMEState *n , uint32_t disk_num)
{
    uint32_t i;
    /* Assuming 1 digit (base 10) for namespace number */
    int size = 20, num, ret = SUCCESS;
    char *str, *temp_str;
    /* Assuming 64KB as maximum bloack size */
    uint16_t nvme_blk_sz;

    str = malloc(size);
    if (str == NULL) {
        LOG_ERR("Not enough memory for namespace name");
        return FAIL;
    }

    for (i = 0; i < NO_OF_NAMESPACES; i++) {

        /* Will auto adjust the size if number of namespace increases
         * to multiple digits */
        while (1) {
            num = snprintf(str, size, "nvme_disk%d_n%d.img", disk_num, i+1);
            /* If that worked, return the string. */
            if (num > -1 && num < size) {
                break;
            }
            /* Else try again with more space. */
            if (num > -1) { /* glibc 2.1 */
                size = num+1; /* precisely what is needed */
            } else {           /* glibc 2.0 */
                size *= 2;  /* twice the old size */
            }
            temp_str = realloc(str, size);
            if (temp_str == NULL) {
                LOG_ERR("Error while creating the storage");
                ret = FAIL;
                goto exit;
            } else {
              str = temp_str;
            }
        }
        n->disk[i].fd = open(str, O_RDWR |
                    O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (n->disk[i].fd < 0) {
            LOG_ERR("Error while creating the storage");
            ret = FAIL;
            goto exit;
        }
        nvme_blk_sz = NVME_BLOCK_SIZE(n->disk[i].
                idtfy_ns->lbafx[n->disk[i].idtfy_ns->flbas].lbads);

        if (posix_fallocate(n->disk[i].fd, 0,
            n->disk[i].idtfy_ns->ncap * nvme_blk_sz) != 0) {
            LOG_ERR("Error while allocating space for namespace");
            ret = FAIL;
            goto exit;
        }

        n->disk[i].mapping_addr = NULL;
        n->disk[i].mapping_size = 0;
    }

    LOG_NORM("%s():Backing store created with disk number %d", __func__,
        disk_num);
exit:
    free(str);
    return ret;
}

/*********************************************************************
    Function     :    nvme_del_storage_disk
    Description  :    Deletes a NVME Storage Disk
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
                      uint32_t : Disk number
*********************************************************************/
int nvme_del_storage_disk(NVMEState *n , uint32_t disk_num)
{
    uint32_t i;
    int ret = SUCCESS;

    /* If required do ftruncate to remove the allocated
     * memory using posix_fallocate */
    for (i = 0; i < NO_OF_NAMESPACES; i++) {
        if (close(n->disk[i].fd) < 0) {
            ret = FAIL;
            LOG_ERR("Unable to close the nvme disk");
        }
    }
    return ret;
}

/*********************************************************************
    Function     :    nvme_close_storage_disk
    Description  :    Closes the NVME Storage Disk and the
                      associated namespaces
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_close_storage_disk(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;

    for (i = 0; i < NO_OF_NAMESPACES; i++) {
        if (n->disk[i].mapping_addr != NULL) {
            if (munmap(n->disk[i].mapping_addr, n->disk[i].mapping_size) < 0) {
                ret = FAIL;
                LOG_ERR("Error while closing namespace: %d", i+1);
            } else {
                n->disk[i].mapping_addr = NULL;
                n->disk[i].mapping_size = 0;
            }
        }
    }
    return ret;
}

/*********************************************************************
    Function     :    nvme_open_storage_disk
    Description  :    Opens the NVME Storage Disk and the
                      namespaces within for usage
    Return Type  :    int (0:1 Success:Failure)

    Arguments    :    NVMEState * : Pointer to NVME device State
*********************************************************************/
int nvme_open_storage_disk(NVMEState *n)
{
    uint32_t i;
    int ret = SUCCESS;
    uint16_t nvme_blk_sz;

    for (i = 0; i < NO_OF_NAMESPACES; i++) {
        if (n->disk[i].mapping_addr == NULL) {
            nvme_blk_sz = NVME_BLOCK_SIZE(n->disk[i].
                idtfy_ns->lbafx[n->disk[i].idtfy_ns->flbas].lbads);
            n->disk[i].mapping_addr = mmap(NULL,
                n->disk[i].idtfy_ns->ncap * nvme_blk_sz,
                    PROT_READ | PROT_WRITE, MAP_SHARED, n->disk[i].fd, 0);

            if (n->disk[i].mapping_addr == NULL) {
                ret = FAIL;
                LOG_ERR("Error while opening namespace: %d", i+1);
            }
            n->disk[i].mapping_size = n->disk[i].idtfy_ns->ncap * nvme_blk_sz;
        }
    }
    return ret;
}
