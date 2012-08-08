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

/* queue is full if tail is just behind head. */
uint8_t is_cq_full(NVMEIOCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static void incr_sq_head(NVMEIOSQueue *q)
{
    q->head = (q->head + 1) % q->size;
}

static void incr_cq_tail(NVMEIOCQueue *q)
{
    q->tail += 1;
    if (q->tail >= q->size) {
        q->tail = 0;
        q->phase_tag = !q->phase_tag;
    }
}

/* Used to get the required Queue entry for discontig SQ and CQ
 * Returns- dma address
 */
static uint64_t find_discontig_queue_entry(uint32_t pg_size, uint16_t queue_ptr,
    uint32_t cmd_size, uint64_t st_dma_addr) {
    uint32_t index = 0;
    uint32_t pg_no, prp_pg_no, entr_per_pg, prps_per_pg, prp_entry, pg_entry;
    uint64_t dma_addr, entry_addr;

    LOG_DBG("%s(): called", __func__);
    /* All PRP entries start with offset 00h */
    entr_per_pg = (uint32_t) (pg_size / cmd_size);
    /* pg_no and prp_pg_no start with 0 */
    pg_no = (uint32_t) (queue_ptr / entr_per_pg);
    pg_entry = (uint32_t) (queue_ptr % entr_per_pg);

    prps_per_pg = (uint32_t) (pg_size / PRP_ENTRY_SIZE);
    prp_pg_no = (uint32_t) (pg_no / (prps_per_pg - 1));
    prp_entry = (uint32_t) (pg_no % (prps_per_pg - 1));

    /* Get to the correct page */
    for (index = 1; index <= prp_pg_no; index++) {
        nvme_dma_mem_read((st_dma_addr + ((prps_per_pg - 1) * PRP_ENTRY_SIZE)),
            (uint8_t *)&dma_addr, PRP_ENTRY_SIZE);
        st_dma_addr = dma_addr;
    }

    /* Correct offset within the prp list page */
    dma_addr = st_dma_addr + (prp_entry * PRP_ENTRY_SIZE);
    /* Reading the PRP List at required offset */
    nvme_dma_mem_read(dma_addr, (uint8_t *)&entry_addr, PRP_ENTRY_SIZE);

    /* Correct offset within the page */
    dma_addr = entry_addr + (pg_entry * cmd_size);
    return dma_addr;
}

void post_cq_entry(NVMEState *n, NVMEIOCQueue *cq, NVMEIOSQueue *sq, NVMECQE* cqe)
{
    target_phys_addr_t addr;
    uint32_t tail;
    NVMEStatusField *sf = (NVMEStatusField *) &cqe->status;

    pthread_mutex_lock(&cq->queue_lock);
    while (is_cq_full(cq)) {
        pthread_mutex_unlock(&cq->queue_lock);
        pthread_mutex_unlock(&sq->queue_lock);

        isr_notify(n, cq);
        wait_for_work(sq);

        pthread_mutex_lock(&sq->queue_lock);
        pthread_mutex_lock(&cq->queue_lock);
    }
    tail = cq->tail;
    sf->p = cq->phase_tag;
    incr_cq_tail(cq);
    pthread_mutex_unlock(&cq->queue_lock);

    if (cq->phys_contig) {
        addr = cq->dma_addr + tail * sizeof(*cqe);
    } else {
        addr = find_discontig_queue_entry(n->page_size, tail,
            sizeof(*cqe), cq->dma_addr);
    }
    nvme_dma_mem_write(addr, (uint8_t *)cqe, sizeof(*cqe));
}

int process_sq(NVMEIOSQueue *sq, NVMEIOCQueue *cq, NVMEState *n)
{
    target_phys_addr_t addr;
    NVMECmd sqe;
    NVMECQE cqe;

    if (sq->head == sq->tail) {
        return -1;
    }

    LOG_DBG("%s(): called", __func__);

    /* Process SQE */
    if (sq->phys_contig) {
        addr = sq->dma_addr + sq->head * sizeof(sqe);
    } else {
        addr = find_discontig_queue_entry(n->page_size, sq->head,
            sizeof(sqe), sq->dma_addr);
    }
    nvme_dma_mem_read(addr, (uint8_t *)&sqe, sizeof(sqe));
    memset(&cqe, 0, sizeof(cqe));
    incr_sq_head(sq);
    if (sq->id == ASQ_ID) {
        if (nvme_admin_command(n, &sqe, &cqe) == NVME_NO_COMPLETE) {
            return 0;
        }
    } else if (!cq->pdid) {
        /* TODO add support for IO commands with different sizes of Q elems */
        if (nvme_command_set(n, &sqe, &cqe, sq) == NVME_NO_COMPLETE) {
            return 0;
        }
    } else if (n->use_aon) {
        /* aon user read/write command */
        if (nvme_aon_io_command(n, &sqe, &cqe, cq->pdid) == NVME_NO_COMPLETE) {
            return 0;
        }
    } else {
        cqe.status.sc = NVME_SC_INVALID_OPCODE;
    }

    /* Filling up the CQ entry */
    cqe.sq_id = sq->id;
    cqe.sq_head = sq->head;
    cqe.command_id = sqe.cid;

    post_cq_entry(n, cq, sq, &cqe);

    return 0;
}
