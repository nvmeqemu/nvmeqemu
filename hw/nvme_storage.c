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

#define NVME_STORAGE_FILE_NAME "nvme_store.img"

void nvme_dma_mem_read(target_phys_addr_t addr, uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, buf, len, 0);
}

void nvme_dma_mem_write(target_phys_addr_t addr, uint8_t *buf, int len)
{
    cpu_physical_memory_rw(addr, buf, len, 1);
}

static uint8_t do_rw_prp(NVMEState *n, uint64_t mem_addr, uint64_t *data_size_p,
             uint64_t *file_offset_p, uint8_t rw)
{
    uint8_t *mapping_addr = n->mapping_addr;
    uint64_t data_len = 0;

    if (*data_size_p == 0)
    {
        return FAIL;
    }

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

static uint8_t do_rw_prp_list(NVMEState *n, NVMECmd *command,  uint64_t *data_size_p, uint64_t *file_offset_p)
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

        res = do_rw_prp(n, prp_list[i], data_size_p, file_offset_p, cmd->opcode);
        LOG_DBG("Data Size remaining for read/write:%ld", *data_size_p);
        if (res == FAIL) {
            break;
        }
        i++;
    }
    return res;
}

/* TODO: Make the PAGE_SIZE and NVME_BLOCK_SIZE generic */
uint8_t nvme_io_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe)
{
    struct NVME_rw *e = (struct NVME_rw *)sqe;
    uint8_t res = FAIL;
    uint64_t data_size, file_offset;

    LOG_NORM("%s(): called", __func__);

    if (sqe->opcode == NVME_CMD_FLUSH) {
        return NVME_SC_SUCCESS;
    }

    if ((sqe->opcode != NVME_CMD_READ) &&
        (sqe->opcode != NVME_CMD_WRITE)) {
        LOG_NORM("Wrong IO opcode:\t\t0x%02x", sqe->opcode);
        goto ret;
    }

    data_size = (e->nlb + 1) * NVME_BLOCK_SIZE;
    file_offset = e->slba * NVME_BLOCK_SIZE;

    /* Writing/Reading PRP1 */
    res = do_rw_prp(n, e->prp1,
        &data_size, &file_offset, e->opcode);
    if ((res == FAIL) || (data_size == 0)) {
        goto ret;
    }

    if (data_size <= PAGE_SIZE) {
        LOG_DBG("Data Size remaining for read/write:%ld", data_size);
        res = do_rw_prp(n, e->prp2,
            &data_size, &file_offset, e->opcode);
        LOG_DBG("Data Size remaining for read/write:%ld", data_size);
        if (res == FAIL) {
            goto ret;
        }
    } else {
        res = do_rw_prp_list(n, sqe, &data_size, &file_offset);
    }

ret:
    return res;
}

static int nvme_create_storage_file(NVMEState *n)
{
    n->fd = open(NVME_STORAGE_FILE_NAME, O_RDWR | O_CREAT
        | O_TRUNC, S_IRUSR | S_IWUSR);
    posix_fallocate(n->fd, 0, NVME_STORAGE_FILE_SIZE);
    LOG_NORM("Backing store created with fd %d", n->fd);
    close(n->fd);
    n->fd = -1;
    return 0;
}

int nvme_close_storage_file(NVMEState *n)
{
    if (n->fd != -1) {
        if (n->mapping_addr) {
            munmap(n->mapping_addr, n->mapping_size);
            n->mapping_addr = NULL;
            n->mapping_size = 0;
        }
        close(n->fd);
        n->fd = -1;
    }
    return 0;
}

int nvme_open_storage_file(NVMEState *n)
{
    struct stat st;
    uint8_t *mapping_addr;

    if (n->fd != -1) {
        return FAIL;
    }

    if (stat(NVME_STORAGE_FILE_NAME, &st) != 0 ||
        st.st_size != NVME_STORAGE_FILE_SIZE) {
        nvme_create_storage_file(n);
    }

    n->fd = open(NVME_STORAGE_FILE_NAME, O_RDWR);
    if (n->fd == -1) {
        return FAIL;
    }
    mapping_addr = mmap(NULL, NVME_STORAGE_FILE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, n->fd, 0);

    if (mapping_addr == NULL) {
        close(n->fd);
        return FAIL;
    }

    n->mapping_size = NVME_STORAGE_FILE_SIZE;
    n->mapping_addr = mapping_addr;

    LOG_NORM("Backing store mapped to %p", n->mapping_addr);
    return 0;
}
