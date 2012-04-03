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

uint8_t is_cq_full(NVMEState *n, uint16_t qid)
{
    return (((n->cq[qid].tail + 1) % n->cq[qid].size) == n->cq[qid].head);
}

static void incr_sq_head(NVMEIOSQueue *q)
{
    q->head = (q->head + 1) % q->size;
    LOG_DBG("%s(): (SQID, HD, SZ) = (%d, %d, %d)", __func__,
        q->id, q->head, q->size);
}

void incr_cq_tail(NVMEIOCQueue *q)
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

void post_cq_entry(NVMEState *n, NVMEIOCQueue *cq, NVMECQE* cqe)
{
    target_phys_addr_t addr;
    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * sizeof(*cqe);
    } else {
        addr = find_discontig_queue_entry(n->page_size, cq->tail,
            sizeof(*cqe), cq->dma_addr);
    }
    nvme_dma_mem_write(addr, (uint8_t *)cqe, sizeof(*cqe));

    incr_cq_tail(cq);
    if (cq->irq_enabled) {
        msix_notify(&(n->dev), cq->vector);
    } else {
        LOG_DBG("cq:%d irq not enabled", cq->id);
    }
}

int process_sq(NVMEState *n, uint16_t sq_id)
{
    target_phys_addr_t addr;
    uint16_t cq_id;
    NVMECmd sqe;
    NVMECQE cqe;
    NVMEStatusField *sf = (NVMEStatusField *) &cqe.status;

    if (n->sq[sq_id].dma_addr == 0 || n->cq[n->sq[sq_id].cq_id].dma_addr
        == 0) {
        LOG_ERR("Required Submission/Completion Queue does not exist");
        n->sq[sq_id].head = n->sq[sq_id].tail = 0;
        return -1;
    }
    cq_id = n->sq[sq_id].cq_id;
    if (is_cq_full(n, cq_id)) {
        LOG_DBG("CQ %d is full", cq_id);
        return -1;
    }
    memset(&cqe, 0, sizeof(cqe));

    LOG_DBG("%s(): called", __func__);

    /* Process SQE */
    if (sq_id == ASQ_ID || n->sq[sq_id].phys_contig) {
        addr = n->sq[sq_id].dma_addr + n->sq[sq_id].head * sizeof(sqe);
    } else {
        /* PRP implementation */
        addr = find_discontig_queue_entry(n->page_size, n->sq[sq_id].head,
            sizeof(sqe), n->sq[sq_id].dma_addr);
    }
    nvme_dma_mem_read(addr, (uint8_t *)&sqe, sizeof(sqe));

    incr_sq_head(&n->sq[sq_id]);

    if (sq_id == ASQ_ID) {
        nvme_admin_command(n, &sqe, &cqe);
        if (sqe.opcode == NVME_ADM_CMD_ASYNC_EV_REQ &&
            sf->sc == NVME_SC_SUCCESS) {
            /* completion entry is done separately */
            return 0;
        }
    } else {
       /* TODO add support for IO commands with different sizes of Q elements */
        nvme_io_command(n, &sqe, &cqe);
    }

    /* Filling up the CQ entry */
    cqe.sq_id = sq_id;
    cqe.sq_head = n->sq[sq_id].head;
    cqe.command_id = sqe.cid;

    sf->p = n->cq[cq_id].phase_tag;
    sf->m = 0;
    sf->dnr = 0; /* TODO add support for dnr */

    post_cq_entry(n, &n->cq[cq_id], &cqe);

    return 0;
}
