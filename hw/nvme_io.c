/*
 * Copyright (c) 2011 Intel Corporation
 *
 * by Patrick Porlan <patrick.porlan@intel.com>
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


/* queue is full if tail is just behind head. */

static uint8_t is_cq_full(NVMEState *n, uint16_t qid)
{
    return (n->cq[qid].tail + 1) % (n->cq[qid].size + 1) == n->cq[qid].head;
}

static void incr_sq_head(NVMEIOSQueue *q)
{
    q->head = (q->head + 1) % (q->size + 1);
}

static void incr_cq_tail(NVMEIOCQueue *q)
{
    q->tail = q->tail + 1;
    if (q->tail > q->size) {
        q->tail = 0;
        q->phase_tag = !q->phase_tag;
    }
}

static uint8_t abort_command(NVMEState *n, uint16_t sq_id, NVMECmd *sqe)
{
    uint16_t i;

    for (i = 0; i < NVME_ABORT_COMMAND_LIMIT; i++) {
        if (n->sq[sq_id].abort_cmd_id[i] == sqe->cid) {
            n->sq[sq_id].abort_cmd_id[i] = NVME_EMPTY;
            n->abort--;
            return 1;
        }
    }
    return 0;
}

void process_sq(NVMEState *n, uint16_t sq_id)
{
    target_phys_addr_t addr, pg_addr;
    uint16_t cq_id;
    NVMECmd sqe;
    NVMECQE cqe;
    /* TODO: uint32_t ret = NVME_SC_DATA_XFER_ERROR; */
    NVMEStatusField *sf = (NVMEStatusField *) &cqe.status;
    uint16_t mps;
    uint32_t pg_no, entr_per_pg;

    cq_id = n->sq[sq_id].cq_id;
    if (is_cq_full(n, cq_id)) {
        return;
    }
    memset(&cqe, 0, sizeof(cqe));

    /* Process SQE */
    if (sq_id == ASQ_ID || n->sq[sq_id].phys_contig) {
        addr = n->sq[sq_id].dma_addr + n->sq[sq_id].head * sizeof(sqe);
    } else {
        /* PRP implementation */
        memcpy(&mps, &n->cntrl_reg[NVME_CC], WORD);
        LOG_DBG("Mask: %x", MASK(4, 7));
        mps &= (uint16_t) MASK(4, 7);
        mps >>= 7;
        LOG_DBG("CC.MPS:%x", mps);
        entr_per_pg = (uint32_t) ((1 << (12 + mps))/sizeof(sqe));
        pg_no = (uint32_t) (n->sq[sq_id].head / entr_per_pg);
        nvme_dma_mem_read(n->sq[sq_id].dma_addr + (pg_no * QWORD),
            (uint8_t *)&pg_addr, QWORD);
        addr = pg_addr + (n->sq[sq_id].head % entr_per_pg) * sizeof(sqe);
    }
    nvme_dma_mem_read(addr, (uint8_t *)&sqe, sizeof(sqe));

    if (n->abort) {
        if (abort_command(n, sq_id, &sqe)) {
            incr_sq_head(&n->sq[sq_id]);
            return;
        }
    }

    if (sq_id == ASQ_ID) {
        nvme_admin_command(n, &sqe, &cqe);
    } else {
       /* TODO add support for IO commands with different sizes of Q elements */
        nvme_io_command(n, &sqe, &cqe);
    }
    cqe.sq_id = sq_id;
    cqe.sq_head = n->sq[sq_id].head;
    cqe.command_id = sqe.cid;

    sf->p = n->cq[cq_id].phase_tag;
    sf->m = 0;
    sf->dnr = 0; /* TODO add support for dnr */

    /* write cqe to completion queue */
    if (cq_id == ACQ_ID || n->cq[cq_id].phys_contig) {
        addr = n->cq[cq_id].dma_addr + n->cq[cq_id].tail * sizeof(cqe);
    } else {
        /* PRP implementation */
        memcpy(&mps, &n->cntrl_reg[NVME_CC], WORD);
        LOG_DBG("Mask: %x", MASK(4, 7));
        mps &= (uint16_t) MASK(4, 7);
        mps >>= 7;
        LOG_DBG("CC.MPS:%x", mps);
        entr_per_pg = (uint32_t) ((1 << (12 + mps))/sizeof(cqe));
        pg_no = (uint32_t) (n->cq[cq_id].tail / entr_per_pg);
        nvme_dma_mem_read(n->cq[cq_id].dma_addr + (pg_no * QWORD),
            (uint8_t *)&pg_addr, QWORD);
        addr = pg_addr + (n->cq[cq_id].tail % entr_per_pg) * sizeof(cqe);
    }
    nvme_dma_mem_write(addr, (uint8_t *)&cqe, sizeof(cqe));

    incr_sq_head(&n->sq[sq_id]);
    incr_cq_tail(&n->cq[cq_id]);

    if (cq_id == ACQ_ID) {
        /*
         3.1.9 says: "This queue is always associated
                 with interrupt vector 0"
        */
        msix_notify(&(n->dev), 0);
        return;
    }

    if (n->cq[cq_id].irq_enabled) {
        msix_notify(&(n->dev), n->cq[cq_id].vector);
    } else {
        LOG_NORM("kw q: IRQ not enabled for CQ: %d;\n", cq_id);
    }


}



