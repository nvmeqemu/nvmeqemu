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
#include "range.h"

static const VMStateDescription vmstate_nvme = {
    .name = "nvme",
    .version_id = 1,
};

uint32_t fultondale_boundary_feature[] = {
    0,
    FD_128K_BDRY,
    FD_64K_BDRY,
    FD_32K_BDRY,
    FD_16K_BDRY,
};

uint32_t fultondale_boundary[] = {
    0,
    0x20000,
    0x10000,
    0x8000,
    0x4000,
};

/* File Level scope functions */
static void clear_nvme_device(NVMEState *n);
static void pci_space_init(PCIDevice *);
static void nvme_pci_write_config(PCIDevice *, uint32_t, uint32_t, int);
static uint32_t nvme_pci_read_config(PCIDevice *, uint32_t, int);
static inline uint8_t range_covers_reg(uint64_t, uint64_t, uint64_t,
    uint64_t);
static void process_doorbell(NVMEState *, target_phys_addr_t, uint32_t);
static void read_file(NVMEState *, uint8_t);
static int nvme_irqcq_empty(NVMEState *, uint32_t);
static void msix_clr_pending(PCIDevice *, uint32_t);

void bsem_init(bsem *s)
{
    pthread_mutex_init(&s->mutex, NULL);
    pthread_cond_init(&s->cv, NULL);
    s->flag = 1;
}

void bsem_destroy(bsem *s)
{
    pthread_mutex_destroy(&s->mutex);
    pthread_cond_destroy(&s->cv);
}

void bsem_get(bsem *s)
{
    pthread_mutex_lock(&s->mutex);
    while (s->flag == 0) {
        pthread_cond_wait(&s->cv, &s->mutex);
    }
    s->flag = 0;
    pthread_mutex_unlock(&s->mutex);
}

void bsem_put(bsem *s)
{
    pthread_mutex_lock(&s->mutex);
    pthread_cond_signal(&s->cv);
    s->flag = 1;
    pthread_mutex_unlock(&s->mutex);
}

void wait_for_work(NVMEIOSQueue *sq)
{
    bsem_get(&sq->event_lock);
    if (sq->is_active) {
        return;
    }
    LOG_NORM("submission queue:%d completed:%lu thread exiting", sq->id,
        sq->completed);
    pthread_exit(NULL);
}

void isr_notify(NVMEState *n, NVMEIOCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->dev))) {
            msix_notify(&(n->dev), cq->vector);
        } else {
            qemu_irq_pulse(n->dev.irq[0]);
        }
    }
}

void enqueue_async_event(NVMEState *n, uint8_t event_type, uint8_t event_info,
    uint8_t log_page)
{
    AsyncEvent *event = (AsyncEvent *)qemu_malloc(sizeof(AsyncEvent));

    event->result.event_type = event_type;
    event->result.event_info = event_info;
    event->result.log_page   = log_page;

    QSIMPLEQ_INSERT_TAIL(&(n->async_queue), event, entry);

    qemu_mod_timer(n->async_event_timer,
            qemu_get_clock_ns(vm_clock) + 20000);
}

/* returns true or false for a one in chance event */
int random_chance(int chance)
{
    double ud = (rand() * (1.0 / (RAND_MAX + 1.0)));
    int r = ud * chance;
    return r == 0;
}

/*********************************************************************
    Function     :    process_doorbell
    Description  :    Processing Doorbell and SQ commands
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
                      uint32_t : Value to be written
*********************************************************************/
static void process_doorbell(NVMEState *nvme_dev, target_phys_addr_t addr,
    uint32_t val)
{
    /* Used to get the SQ/CQ number to be written to */
    uint32_t queue_id;
    LOG_DBG("%s(): addr = 0x%08x, val = 0x%08x", __func__,
        (unsigned)addr, val);

    /* Check if it is CQ or SQ doorbell */
    queue_id = (addr - NVME_SQ0TDBL) >> 2;

    if (queue_id & 1) {
        /* CQ */
        NVMEIOCQueue *cq;
        uint16_t new_head = val & 0xffff;
        uint16_t start_sqs = 0;
        queue_id = (addr - NVME_CQ0HDBL) >> 3;
        if (adm_check_cqid(nvme_dev, queue_id)) {
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        cq = nvme_dev->cq[queue_id];
        if (new_head >= cq->size) {
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        pthread_mutex_lock(&cq->queue_lock);
        start_sqs = is_cq_full(cq) ? 1 : 0;
        cq->head = new_head;

        /*
         * Reset the P bit if head == tail for all Queues on a specific
         * interrupt vector
         */
        if (cq->irq_enabled && !(nvme_irqcq_empty(nvme_dev, cq->vector))) {
            LOG_DBG("Reset P bit for vec:%d", cq->vector);
            msix_clr_pending(&nvme_dev->dev, cq->vector);
        }
        if (start_sqs) {
            NVMEIOSQueue *sq;
            QTAILQ_FOREACH(sq, &cq->sq_list, entry) {
                bsem_put(&sq->event_lock);
            }
        }
        if (cq->tail != cq->head) {
            /* more completion entries, submit interrupt */
            isr_notify(nvme_dev, cq);
        }
        pthread_mutex_unlock(&cq->queue_lock);
    } else {
        /* SQ */
        NVMEIOSQueue *sq;
        uint16_t new_tail = val & 0xffff;
        queue_id = (addr - NVME_SQ0TDBL) >> 3;
        if (adm_check_sqid(nvme_dev, queue_id)) {
            LOG_NORM("invalid sq %d", queue_id);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        sq = nvme_dev->sq[queue_id];
        if (new_tail >= sq->size) {
            LOG_NORM("invalid doorbell on queue:%d", queue_id);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        sq->tail = new_tail;
        LOG_DBG("set sq:%d tail to %d, current head:%d", sq->id, new_tail,
            sq->head);
        bsem_put(&sq->event_lock);
    }
    return;
}

/*********************************************************************
    Function     :    msix_clr_pending
    Description  :    Clears the Pending Bit for the passed in vector
                      in msix pba table
    Return Type  :    void
    Arguments    :    PCIDevice * : Pointer to PCI device State
                      uint32_t : Vector
*********************************************************************/
static void msix_clr_pending(PCIDevice *dev, uint32_t vector)
{
    uint8_t *pending_byte = dev->msix_table_page + MSIX_PAGE_PENDING +
        vector / 8;
    uint8_t pending_mask = 1 << (vector % 8);
    *pending_byte &= ~pending_mask;
}

/*********************************************************************
    Function     :    nvme_irqcqs_empty
    Description  :    Checks whether all the Queues associated with the
                      passed in vector are empty
    Return Type  :    int (0:1 SUCCESS:FAILURE)
    Arguments    :    NVMEState * : Pointer to NVME device State
                      uint32_t : Vector
*********************************************************************/
static int nvme_irqcq_empty(NVMEState *nvme_dev, uint32_t vector)
{
    int index;
    NVMEIOCQueue *cq;
    for (index = 0; index < NVME_MAX_QS_ALLOCATED; ++index) {
        cq = nvme_dev->cq[index];
        if (cq == NULL) {
            continue;
        }
        if (cq->vector == vector && cq->irq_enabled) {
            if (cq->head != cq->tail) {
                return FAIL;
            }
        }
    }
    return SUCCESS;
}

void *submission_queue_thread(void *arg)
{
    NVMEIOSQueue *sq = arg;
    NVMEState *n = sq->n;
    NVMEIOCQueue *cq = n->cq[sq->cq_id];
    LOG_NORM("started submission queue thread for sq:%d cq:%d", sq->id, cq->id);
    for (;;) {
        int processed = 0;
        wait_for_work(sq);

        pthread_mutex_lock(&sq->queue_lock);
        while (!process_sq(sq, cq, n)) {
            ++processed;
            ++sq->completed;
        }
        pthread_mutex_unlock(&sq->queue_lock);
        if (processed) {
            isr_notify(n, cq);
        }
    }
    return NULL;
}

/*********************************************************************
    Function     :    nvme_mmio_writeb
    Description  :    Write 1 Byte at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
                      uint32_t : Value to be written
*********************************************************************/
static void nvme_mmio_writeb(void *opaque, target_phys_addr_t addr,
    uint32_t val)
{
    NVMEState *n = opaque;

    LOG_DBG("%s(): addr = 0x%08x, val = 0x%08x",
        __func__, (unsigned)addr, val);
    LOG_NORM("writeb is not supported!");
    (void)n;
}

/*********************************************************************
    Function     :    nvme_mmio_writew
    Description  :    Write 2 Bytes at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
                      uint32_t : Value to be written
*********************************************************************/
static void nvme_mmio_writew(void *opaque, target_phys_addr_t addr,
    uint32_t val)
{
    NVMEState *n = opaque;

    LOG_DBG("%s(): addr = 0x%08x, val = 0x%08x",
        __func__, (unsigned)addr, val);
    LOG_NORM("writew is not supported!");
    (void)n;
}

/*********************************************************************
    Function     :    nvme_mmio_writel
    Description  :    Write 4 Bytes at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
                      uint32_t : Value to be written
*********************************************************************/
static void nvme_mmio_writel(void *opaque, target_phys_addr_t addr,
    uint32_t val)
{
    NVMEState *nvme_dev = (NVMEState *) opaque;
    uint32_t var; /* Variable to store reg values locally */

    /* Check if NVME controller Capabilities was written */
    if (addr < NVME_SQ0TDBL) {
        switch (addr) {
        case NVME_INTMS:
            /* Operation not defined if MSI-X is enabled */
            if (nvme_dev->dev.msix_cap != 0x00 &&
                IS_MSIX(nvme_dev)) {
                LOG_NORM("MSI-X is enabled..write to INTMS is undefined");
            } else {
                /* MSICAP or PIN based ISR is enabled*/
                nvme_cntrl_write_config(nvme_dev, NVME_INTMS,
                    val, DWORD);
            }
            break;
        case NVME_INTMC:
            /* Operation not defined if MSI-X is enabled */
            if (nvme_dev->dev.msix_cap != 0x00 &&
                IS_MSIX(nvme_dev)) {
                LOG_NORM("MSI-X is enabled..write to INTMC is undefined");
            } else {
                /* MSICAP or PIN based ISR is enabled*/
                nvme_cntrl_write_config(nvme_dev, NVME_INTMC,
                    val, DWORD);
            }
            break;
        case NVME_CC:
            /* TODO : Features for IOCQES/IOSQES,SHN,AMS,CSS,MPS */

            /* Reading in old value before write */
            /* TODO check for side effects due to le_tocpu */
            var = nvme_cntrl_read_config(nvme_dev, NVME_CC, DWORD);

            /* For 0->1 transition of CC.EN */
            if (((var & CC_EN) ^ (val & CC_EN)) && (val & CC_EN)) {
                /* Write to CC reg */
                nvme_cntrl_write_config(nvme_dev, NVME_CC, val, DWORD);
                /* Check if admin queues are ready to use and
                 * check enable bit CC.EN
                 */
                if (nvme_dev->cq[ACQ_ID]->dma_addr &&
                    nvme_dev->sq[ASQ_ID]->dma_addr) {
                    /* Update CSTS.RDY based on CC.EN and set the phase tag */
                    pthread_attr_t attr;
                    nvme_dev->cntrl_reg[NVME_CTST] |= CC_EN;
                    nvme_dev->cq[ACQ_ID]->phase_tag = 1;
                    nvme_dev->sq[ASQ_ID]->is_active = 1;
                    pthread_attr_init(&attr);
                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
                    pthread_create(&nvme_dev->sq[ASQ_ID]->process_thread, &attr,
                        submission_queue_thread, nvme_dev->sq[ASQ_ID]);

                    if ((nvme_dev->cntrl_reg[NVME_CC] & 0x70) >> 4 ==
                            AON_COMMAND_SET) {
                        /* using aon, fill aon vendor specifics */
                        AONIdCtrlVs *aon_ctrl_vs;
                        nvme_dev->use_aon = 1;

                        nvme_dev->aon_ctrl_vs = (AONIdCtrlVs *)&nvme_dev->
                            idtfy_ctrl.vs[0];
                        aon_ctrl_vs = nvme_dev->aon_ctrl_vs;

                        aon_ctrl_vs->acc = 1 | 1 << 1;
                        aon_ctrl_vs->mns = 12; /* 4KB */
                        aon_ctrl_vs->mws = 6; /* 64B */
                        aon_ctrl_vs->mnpd = NVME_AON_MAX_NUM_PDS;
                        aon_ctrl_vs->tus = nvme_dev->total_size * BYTES_PER_MB;
                        aon_ctrl_vs->mnn = nvme_dev->num_namespaces;
                        aon_ctrl_vs->mnhr = NVME_AON_MAX_NUM_STAGS;
                        aon_ctrl_vs->mnon = NVME_AON_MAX_NUM_NSTAGS;
                        aon_ctrl_vs->ows = 6;
                        aon_ctrl_vs->mows = 6;
                        aon_ctrl_vs->smpsmax = 0; /* 4k */
                        aon_ctrl_vs->smpsmin = 0; /* 4k */
                        aon_ctrl_vs->nlbaf = 3;
                        aon_ctrl_vs->mc = 1 << 1;
                        aon_ctrl_vs->dpc = 1 << 4 | 1 << 3 | 1 << 0;

                        aon_ctrl_vs->lbaf[0].lbads = 9;
                        aon_ctrl_vs->lbaf[0].ms    = 0;
                        aon_ctrl_vs->lbaf[0].rp    = 1;
                        aon_ctrl_vs->lbaf[1].lbads = 9;
                        aon_ctrl_vs->lbaf[1].ms    = 8;
                        aon_ctrl_vs->lbaf[1].rp    = 2;
                        aon_ctrl_vs->lbaf[2].lbads = 12;
                        aon_ctrl_vs->lbaf[2].ms    = 0;
                        aon_ctrl_vs->lbaf[2].rp    = 0;
                        aon_ctrl_vs->lbaf[3].lbads = 12;
                        aon_ctrl_vs->lbaf[3].ms    = 64;
                        aon_ctrl_vs->lbaf[3].rp    = 2;

                        nvme_dev->protection_domains = qemu_mallocz(
                            sizeof(NVMEAonPD *)*nvme_dev->aon_ctrl_vs->mnpd);
                        nvme_dev->stags = qemu_mallocz(
                            sizeof(NVMEAonStag *)*nvme_dev->aon_ctrl_vs->mnhr);
                        nvme_dev->nstags = qemu_mallocz(
                            sizeof(NVMEAonNStag *)*nvme_dev->aon_ctrl_vs->mnon);
                    } else {
                        nvme_dev->use_aon = 0;
                    }
                }
            } else if ((var & CC_EN) ^ (val & CC_EN)) {
                /* For 1->0 transition for CC.EN */
                /* Resetting the controller to a state defined in
                 * config file/default initialization
                 */
                LOG_NORM("Resetting the NVME device to idle state");
                clear_nvme_device(nvme_dev);
                /* Update CSTS.RDY based on CC.EN */
                nvme_dev->cntrl_reg[NVME_CTST] &= ~(CC_EN);
            } else {
                /* Writes before/after CC.EN is set */
                nvme_cntrl_write_config(nvme_dev, NVME_CC, val, DWORD);
            }
            break;
        case NVME_AQA:
            nvme_cntrl_write_config(nvme_dev, NVME_AQA, val, DWORD);
            nvme_dev->sq[ASQ_ID]->size = (val & 0xfff) + 1;
            nvme_dev->cq[ACQ_ID]->size = ((val >> 16) & 0xfff) + 1;
            break;
        case NVME_ASQ:
            nvme_cntrl_write_config(nvme_dev, NVME_ASQ, val, DWORD);
            *((uint32_t *) &nvme_dev->sq[ASQ_ID]->dma_addr) = val;
            break;
        case (NVME_ASQ + 4):
            nvme_cntrl_write_config(nvme_dev, (NVME_ASQ + 4), val, DWORD);
            *((uint32_t *) (&nvme_dev->sq[ASQ_ID]->dma_addr) + 1) = val;
            break;
        case NVME_ACQ:
            nvme_cntrl_write_config(nvme_dev, NVME_ACQ, val, DWORD);
            *((uint32_t *) &nvme_dev->cq[ACQ_ID]->dma_addr) = val;
            break;
        case (NVME_ACQ + 4):
            nvme_cntrl_write_config(nvme_dev, (NVME_ACQ + 4), val, DWORD);
            *((uint32_t *) (&nvme_dev->cq[ACQ_ID]->dma_addr) + 1) = val;
            break;
        default:
            break;
        }
    } else if (addr >= NVME_SQ0TDBL && addr <= NVME_CQMAXHDBL) {
        /* Process the Doorbell Writes and masking of higher word */
        process_doorbell(nvme_dev, addr, val);
    }
    return;
}

/*********************************************************************
    Function     :    nvme_cntrl_write_config
    Description  :    Function for NVME Controller space writes
                      (except doorbell writes)
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to NVME device State
                      target_phys_addr_t : address (offset address)
                      uint32_t : Value to write
                      uint8_t : Length to be read
    Note: Writes are done to the NVME device in Least Endian Fashion
*********************************************************************/
void nvme_cntrl_write_config(NVMEState *nvme_dev,
    target_phys_addr_t addr, uint32_t val, uint8_t len)
{
    uint8_t index;
    uint8_t * intr_vect = (uint8_t *) &nvme_dev->intr_vect;

    val = cpu_to_le32(val);
    if (range_covers_reg(addr, len, NVME_INTMS, DWORD) ||
        range_covers_reg(addr, len, NVME_INTMC, DWORD)) {
        /* Check if MSIX is enabled */
        if (nvme_dev->dev.msix_cap != 0x00 &&
            IS_MSIX(nvme_dev)) {
            LOG_NORM("MSI-X is enabled..write to INTMS/INTMC is undefined");
        } else {
            /* Specific case for Interrupt masks */
            for (index = 0; index < len && addr + index < NVME_CNTRL_SIZE;
                val >>= 8, index++) {
                /* W1C: Write 1 to Clear */
                intr_vect[index] &=
                    ~(val & nvme_dev->rwc_mask[addr + index]);
                /* W1S: Write 1 to Set */
                intr_vect[index] |=
                    (val & nvme_dev->rws_mask[addr + index]);
            }
        }
    } else {
        for (index = 0; index < len && addr + index < NVME_CNTRL_SIZE;
            val >>= 8, index++) {
            /* Settign up RW and RO mask and making reserved bits
             * non writable
             */
            nvme_dev->cntrl_reg[addr + index] =
                (nvme_dev->cntrl_reg[addr + index]
                & (~(nvme_dev->rw_mask[addr + index])
                    | ~(nvme_dev->used_mask[addr + index])))
                        | (val & nvme_dev->rw_mask[addr + index]);
            /* W1C: Write 1 to Clear */
            nvme_dev->cntrl_reg[addr + index] &=
                ~(val & nvme_dev->rwc_mask[addr + index]);
            /* W1S: Write 1 to Set */
            nvme_dev->cntrl_reg[addr + index] |=
                (val & nvme_dev->rws_mask[addr + index]);
        }
    }

}

/*********************************************************************
    Function     :    nvme_cntrl_read_config
    Description  :    Function for NVME Controller space reads
                      (except doorbell reads)
    Return Type  :    uint32_t : Value read
    Arguments    :    NVMEState * : Pointer to NVME device State
                      target_phys_addr_t : address (offset address)
                      uint8_t : Length to be read
*********************************************************************/
uint32_t nvme_cntrl_read_config(NVMEState *nvme_dev,
    target_phys_addr_t addr, uint8_t len)
{
    uint32_t val;
    /* Prints the assertion and aborts */
    assert(len == 1 || len == 2 || len == 4);
    len = MIN(len, NVME_CNTRL_SIZE - addr);
    memcpy(&val, nvme_dev->cntrl_reg + addr, len);

    if (range_covers_reg(addr, len, NVME_INTMS, DWORD) ||
        range_covers_reg(addr, len, NVME_INTMC, DWORD)) {
        /* Check if MSIX is enabled */
        if (nvme_dev->dev.msix_cap != 0x00 &&
            IS_MSIX(nvme_dev)) {
            LOG_NORM("MSI-X is enabled..read to INTMS/INTMC is undefined");
            val = 0;
        } else {
            /* Read of INTMS or INTMC should return interrupt vector */
            val = nvme_dev->intr_vect;
        }
    }
    return le32_to_cpu(val);
}
/*********************************************************************
    Function     :    nvme_mmio_readb
    Description  :    Read 1 Bytes at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
    Note:- Even though function is readb, return value is uint32_t
    coz, Qemu mapping code does the masking of repective bits
*********************************************************************/
static uint32_t nvme_mmio_readb(void *opaque, target_phys_addr_t addr)
{
    uint32_t rd_val;
    NVMEState *nvme_dev = (NVMEState *) opaque;
    LOG_DBG("%s(): addr = 0x%08x", __func__, (unsigned)addr);
    /* Check if NVME controller Capabilities was written */
    if (addr < NVME_SQ0TDBL) {
        rd_val = nvme_cntrl_read_config(nvme_dev, addr, BYTE);
    } else if (addr >= NVME_SQ0TDBL && addr <= NVME_CQMAXHDBL) {
        LOG_NORM("Undefined operation of reading the doorbell registers");
        rd_val = 0;
    } else {
        LOG_ERR("Undefined address read");
        LOG_ERR("Qemu supports only 64 queues");
        rd_val = 0 ;
    }
    return rd_val;
}

/*********************************************************************
    Function     :    nvme_mmio_readw
    Description  :    Read 2 Bytes at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
    Note:- Even though function is readw, return value is uint32_t
    coz, Qemu mapping code does the masking of repective bits
*********************************************************************/
static uint32_t nvme_mmio_readw(void *opaque, target_phys_addr_t addr)
{
    uint32_t rd_val;
    NVMEState *nvme_dev = (NVMEState *) opaque;
    LOG_DBG("%s(): addr = 0x%08x", __func__, (unsigned)addr);

    /* Check if NVME controller Capabilities was written */
    if (addr < NVME_SQ0TDBL) {
        rd_val = nvme_cntrl_read_config(nvme_dev, addr, WORD);
    } else if (addr >= NVME_SQ0TDBL && addr <= NVME_CQMAXHDBL) {
        LOG_NORM("Undefined operation of reading the doorbell registers");
        rd_val = 0;
    } else {
        LOG_ERR("Undefined address read");
        LOG_ERR("Qemu supports only 64 queues");
        rd_val = 0 ;
    }
    return rd_val;
}
/*********************************************************************
    Function     :    nvme_mmio_readl
    Description  :    Read 4 Bytes at addr/register
    Return Type  :    void
    Arguments    :    void * : Pointer to NVME device State
                      target_phys_addr_t : Address (offset address)
*********************************************************************/
static uint32_t nvme_mmio_readl(void *opaque, target_phys_addr_t addr)
{
    uint32_t rd_val = 0;
    NVMEState *nvme_dev = (NVMEState *) opaque;

    /* Check if NVME controller Capabilities was written */
    if (addr < NVME_SQ0TDBL) {
        rd_val = nvme_cntrl_read_config(nvme_dev, addr, DWORD);
    } else if (addr >= NVME_SQ0TDBL && addr <= NVME_CQMAXHDBL) {
        LOG_NORM("Undefined operation of reading the doorbell registers");
        rd_val = 0;
    } else {
        LOG_ERR("Undefined address read");
        LOG_ERR("Qemu supports only 64 queues");
        rd_val = 0 ;
    }
    return rd_val;
}

static CPUWriteMemoryFunc * const nvme_mmio_write[] = {
    nvme_mmio_writeb,
    nvme_mmio_writew,
    nvme_mmio_writel,
};

static CPUReadMemoryFunc * const nvme_mmio_read[] = {
    nvme_mmio_readb,
    nvme_mmio_readw,
    nvme_mmio_readl,
};

/*********************************************************************
    Function     :    range_covers_reg
    Description  :    Checks whether the given range covers a
                      particular register completley/partially
    Return Type  :    uint8_t : 1 : covers , 0 : does not cover
    Arguments    :    uint64_t : Start addr to write
                      uint64_t : Length to be written
                      uint64_t : Register offset in address space
                      uint64_t : Size of register
*********************************************************************/
static inline uint8_t range_covers_reg(uint64_t addr, uint64_t len,
    uint64_t reg , uint64_t reg_size)
{
    return (uint8_t) ((addr <= range_get_last(reg, reg_size)) &&
        ((range_get_last(reg, reg_size) <= range_get_last(addr, len)) ||
                (range_get_last(reg, BYTE) <= range_get_last(addr, len))));
}

/*********************************************************************
    Function     :    nvme_pci_write_config
    Description  :    Function for PCI config space writes
    Return Type  :    uint32_t : Value read
    Arguments    :    NVMEState * : Pointer to PCI device state
                      uint32_t : Address (offset address)
                      uint32_t : Value to be written
                      int : Length to be written
*********************************************************************/
static void nvme_pci_write_config(PCIDevice *pci_dev,
                                    uint32_t addr, uint32_t val, int len)
{
    val = cpu_to_le32(val);
    /* Writing the PCI Config Space */
    pci_default_write_config(pci_dev, addr, val, len);
    if (range_covers_reg(addr, len, PCI_BIST, PCI_BIST_LEN)
            && (!(pci_dev->config[PCI_BIST] & PCI_BIST_CAPABLE))) {
        /* Defaulting BIST value to 0x00 */
        pci_set_byte(&pci_dev->config[PCI_BIST], (uint8_t) 0x00);
    }

    return;
}

/*********************************************************************
    Function     :    nvme_pci_read_config
    Description  :    Function for PCI config space reads
    Return Type  :    uint32_t : Value read
    Arguments    :    PCIDevice * : Pointer to PCI device state
                      uint32_t : address (offset address)
                      int : Length to be read
*********************************************************************/
static uint32_t nvme_pci_read_config(PCIDevice *pci_dev, uint32_t addr, int len)
{
    uint32_t val; /* Value to be returned */

    val = pci_default_read_config(pci_dev, addr, len);
    if (range_covers_reg(addr, len, PCI_BASE_ADDRESS_2, PCI_BASE_ADDRESS_2_LEN)
        && (!(pci_dev->config[PCI_COMMAND] & PCI_COMMAND_IO))) {
        /* When CMD.IOSE is not set */
        val = 0 ;
    }
    return val;
}

/*********************************************************************
    Function     :    nvme_mmio_map
    Description  :    Function for registering NVME controller space
    Return Type  :    void
    Arguments    :    PCIDevice * : Pointer to PCI device state
                      int : To specify the BAR's from BAR0-BAR5
                      pcibus_t : Addr to be registered
                      pcibus_t : size to be registered
                      int : Used for similarity bewtween msix map
*********************************************************************/
static void nvme_mmio_map(PCIDevice *pci_dev, int reg_num, pcibus_t addr,
                            pcibus_t size, int type)
{
    NVMEState *n = DO_UPCAST(NVMEState, dev, pci_dev);

    if (reg_num) {
        LOG_NORM("Only bar0 is allowed! reg_num: %d", reg_num);
    }

    /* Is this hacking? */
    /* BAR 0 is shared: Registry, doorbells and MSI-X. Only
     * registry and doorbell part of BAR0 should be handled
     * by nvme mmio functions.
     * The MSI-X part of BAR0 should be mapped by MSI-X functions.
     * The msix_init function changes the bar size to add its
     * tables to it. */

    cpu_register_physical_memory(addr, n->bar0_size, n->mmio_index);
    n->bar0 = (void *) addr;

    /* Let the MSI-X part handle the MSI-X table.  */
    msix_mmio_map(pci_dev, reg_num, addr, size, type);
}

/*********************************************************************
    Function     :    nvme_set_registry
    Description  :    Default initialization of NVME Registery
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to NVME device state
*********************************************************************/
static void nvme_set_registry(NVMEState *n)
{
    /* This is the default initialization sequence when
     * config file is not found */
    uint32_t ind, index;
    uint32_t val, rw_mask, rws_mask, rwc_mask;
    for (ind = 0; ind < sizeof(nvme_reg)/sizeof(nvme_reg[0]); ind++) {
        rw_mask = nvme_reg[ind].rw_mask;
        rwc_mask = nvme_reg[ind].rwc_mask;
        rws_mask = nvme_reg[ind].rws_mask;

        val = nvme_reg[ind].reset;
        for (index = 0; index < nvme_reg[ind].len; val >>= 8, rw_mask >>= 8,
            rwc_mask >>= 8, rws_mask >>= 8, index++) {
            n->cntrl_reg[nvme_reg[ind].offset + index] = val;
            n->rw_mask[nvme_reg[ind].offset + index] = rw_mask;
            n->rws_mask[nvme_reg[ind].offset + index] = rws_mask;
            n->rwc_mask[nvme_reg[ind].offset + index] = rwc_mask;
            n->used_mask[nvme_reg[ind].offset + index] = (uint8_t)MASK(8, 0);
        }
    }
}

/*********************************************************************
    Function     :    clear_nvme_device
    Description  :    To reset Nvme Device (Controller Reset)
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to NVME device state
*********************************************************************/
static void clear_nvme_device(NVMEState *n)
{
    uint32_t i = 0;
    NVMEIoError *me, *next;
    AsyncEvent *event, *ne;

    if (!n) {
        return;
    }

    /* Saving the Admin Queue States before reset */
    n->aqstate.aqa = nvme_cntrl_read_config(n, NVME_AQA, DWORD);
    n->aqstate.asqa = nvme_cntrl_read_config(n, NVME_ASQ + 4, DWORD);
    n->aqstate.asqa = (n->aqstate.asqa << 32) |
        nvme_cntrl_read_config(n, NVME_ASQ, DWORD);
    n->aqstate.acqa = nvme_cntrl_read_config(n, NVME_ACQ + 4, DWORD);
    n->aqstate.acqa = (n->aqstate.acqa << 32) |
        nvme_cntrl_read_config(n, NVME_ACQ, DWORD);
    /* Update NVME space registery from config file */
    read_file(n, NVME_SPACE);
    n->intr_vect = 0;

    for (i = 1; i < NVME_MAX_QS_ALLOCATED; i++) {
        if (n->sq[i] != NULL) {
            pthread_mutex_lock(&n->sq[i]->queue_lock);
            n->sq[i]->is_active = 0;
            bsem_put(&n->sq[i]->event_lock);
            pthread_join(n->sq[i]->process_thread, NULL);
            bsem_destroy(&n->sq[i]->event_lock);
            pthread_mutex_unlock(&n->sq[i]->queue_lock);
            pthread_mutex_destroy(&n->sq[i]->queue_lock);
            qemu_free(n->sq[i]);
            n->sq[i] = NULL;
        }
    }
    for (i = 1; i < NVME_MAX_QS_ALLOCATED; i++) {
        if (n->cq[i] != NULL) {
            pthread_mutex_destroy(&n->cq[i]->queue_lock);
            qemu_free(n->cq[i]);
            n->cq[i] = NULL;
        }
    }

    /* Writing the Admin Queue Attributes after reset */
    nvme_cntrl_write_config(n, NVME_AQA, n->aqstate.aqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ASQ, (uint32_t) n->aqstate.asqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ASQ + 4,
        (uint32_t) (n->aqstate.asqa >> 32), DWORD);
    nvme_cntrl_write_config(n, NVME_ACQ, (uint32_t) n->aqstate.acqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ACQ + 4,
        (uint32_t) (n->aqstate.acqa >> 32), DWORD);

    n->sq[ASQ_ID]->head = n->sq[ASQ_ID]->tail = 0;
    n->cq[ACQ_ID]->head = n->cq[ACQ_ID]->tail = 0;

    if (n->sq[ASQ_ID]->is_active) {
        n->sq[ASQ_ID]->is_active = 0;
        bsem_put(&n->sq[ASQ_ID]->event_lock);
        pthread_join(n->sq[ASQ_ID]->process_thread, NULL);
    }

    n->outstanding_asyncs = 0;
    n->feature.temperature_threshold = NVME_TEMPERATURE + 10;
    n->temp_warn_issued = 0;
    n->percentage_used = 0;
    n->injected_available_spare = 0;
    n->temperature = NVME_TEMPERATURE;

    if (n->timeout_error) {
        qemu_free(n->timeout_error);
        n->timeout_error = NULL;
    }
    QTAILQ_FOREACH_SAFE(me, &n->media_err_list, entry, next) {
        QTAILQ_REMOVE(&n->media_err_list, me, entry);
        qemu_free(me);
        --n->injected_media_errors;
    }
    QSIMPLEQ_FOREACH_SAFE(event, &n->async_queue, entry, ne) {
        QSIMPLEQ_REMOVE(&n->async_queue, event, AsyncEvent, entry);
        qemu_free(event);
    }

    QSIMPLEQ_INIT(&n->async_queue);
    QTAILQ_INIT(&n->media_err_list);
}

/*********************************************************************
    Function     :    do_nvme_reset
    Description  :    TODO: Not yet implemented
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to NVME device state
*********************************************************************/
static void do_nvme_reset(NVMEState *n)
{
    (void)n;
}

/*********************************************************************
    Function     :    qdev_nvme_reset
    Description  :    Handler for NVME Reset
    Return Type  :    void
    Arguments    :    DeviceState * : Pointer to NVME device state
*********************************************************************/
static void qdev_nvme_reset(DeviceState *dev)
{
    NVMEState *n = DO_UPCAST(NVMEState, dev.qdev, dev);
    do_nvme_reset(n);
}


/*********************************************************************
    Function     :    pci_space_init
    Description  :    Hardcoded PCI space initialization
    Return Type  :    void
    Arguments    :    PCIDevice * : Pointer to the PCI device
    Note:- RO/RW/RWC masks not supported for default PCI space
    initialization
*********************************************************************/
static void pci_space_init(PCIDevice *pci_dev)
{
    NVMEState *n = DO_UPCAST(NVMEState, dev, pci_dev);
    uint8_t *pci_conf = NULL;

    pci_conf = n->dev.config;

    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_INTEL);
    /* Device id is fake  */
    pci_config_set_device_id(pci_conf, NVME_DEV_ID);

    /* STORAGE EXPRESS is not yet a standard. */
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS >> 8);

    pci_config_set_prog_interface(pci_conf,
        0xf & PCI_CLASS_STORAGE_EXPRESS);

    /* TODO: What with the rest of PCI fields? Capabilities? */

    /*other notation:  pci_config[OFFSET] = 0xff; */

    LOG_NORM("%s(): Setting PCI Interrupt PIN A", __func__);
    pci_conf[PCI_INTERRUPT_PIN] = 1;

    n->nvectors = NVME_MSIX_NVECTORS;
    n->bar0_size = NVME_REG_SIZE;
}

/*********************************************************************
    Function     :    read_file
    Description  :    Reading the config files accompanied with error
                      handling
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to the NVMEState device
                      uint8_t : Space to Read
                                NVME_SPACE and PCI_SPACE
*********************************************************************/
static void read_file(NVMEState *n, uint8_t space)
{
    /* Pointer for Config file and temp file */
    FILE *config_file;

    if (space == PCI_SPACE) {
        config_file = fopen((char *)PCI_CONFIG_FILE, "r");
    } else {
        config_file = fopen((char *)NVME_CONFIG_FILE, "r");
    }
    if (config_file == NULL) {
        LOG_NORM("Could not open the config file");
        if (space == NVME_SPACE) {
            LOG_NORM("Defaulting the NVME space..");
            nvme_set_registry(n);
        } else if (space == PCI_SPACE) {
            LOG_NORM("Defaulting the PCI space..");
            pci_space_init(&n->dev);
        }
    } else {
        /* Reads config File */
        if (read_config_file(config_file, n, space)) {
            fclose(config_file);
            LOG_ERR("Error Reading the Config File");
            if (space == NVME_SPACE) {
                LOG_NORM("Defaulting the NVME space..");
                nvme_set_registry(n);
            } else if (space == PCI_SPACE) {
                LOG_NORM("Defaulting the PCI space..");
                pci_space_init(&n->dev);
            }
        } else {
            /* Close the File */
            fclose(config_file);
        }
    }
}

/*********************************************************************
    Function     :    read_identify_cns
    Description  :    Reading in hardcoded values of Identify controller
                      and namespace structure
    Return Type  :    void
    Arguments    :    NVMEState * : Pointer to the NVMEState device
                      TODO:Readin the values from a file instead of
                      hardcoded values if required
*********************************************************************/
static void read_identify_cns(NVMEState *n)
{
    PowerStateDescriptor *power;
    int index, i;
    int last_index = n->num_namespaces - n->num_user_namespaces;
    DiskInfo *disk;
    int ms_arr[4] = {0, 8, 64, 128};

    LOG_NORM("%s(): called", __func__);
    for (index = 0; index < last_index; index++) {
        disk = (DiskInfo *)qemu_mallocz(sizeof(*disk));
        if (!disk) {
            LOG_ERR("Unable to allocate namespace");
            return;
        }

        disk->idtfy_ns.nsze = (n->ns_size * BYTES_PER_MB) / BYTES_PER_BLOCK;
        disk->idtfy_ns.ncap = (n->ns_size * BYTES_PER_MB) / BYTES_PER_BLOCK;
        disk->idtfy_ns.nuse = 0;
        disk->idtfy_ns.nlbaf = NO_LBA_FORMATS;
        disk->idtfy_ns.flbas = n->lba_index;
        disk->idtfy_ns.nsfeat = 0;

        /* meta data capabilities */
        disk->idtfy_ns.mc = 1 << 1 | 1 << 0;
        disk->idtfy_ns.dpc = 1 << 4 | 1 << 3 | 1 << 0;
        disk->idtfy_ns.dps = 0; /* user can set this with format */

        /* Filling in the LBA Format structure */
        for (i = 0; i <= NO_LBA_FORMATS; i++) {
            disk->idtfy_ns.lbaf[i].lbads = LBA_SIZE + (i / 4);
            disk->idtfy_ns.lbaf[i].ms = ms_arr[i % 4];
        }
        n->disk[index] = disk;
        set_bit(index + 1, n->nn_vector);

        LOG_NORM("Capacity of namespace %d: %lu", index+1,
            disk->idtfy_ns.ncap);
    }

    pstrcpy((char *)n->idtfy_ctrl.mn, sizeof(n->idtfy_ctrl.mn),
        "Qemu NVMe Driver 0xabcd");
    pstrcpy((char *)n->idtfy_ctrl.fr, sizeof(n->idtfy_ctrl.fr), "1.0");
    snprintf((char *)n->idtfy_ctrl.sn, sizeof(n->idtfy_ctrl.sn),
        "NVMeQx10%02x", n->instance);

    n->idtfy_ctrl.rab = 2;
    n->idtfy_ctrl.cqes = 4 << 4 | 4;
    n->idtfy_ctrl.sqes = 6 << 4 | 6;
    n->idtfy_ctrl.oacs = 0x7;
    n->idtfy_ctrl.oncs = 0x4;  /* dataset mgmt cmd */
    n->idtfy_ctrl.mdts = 5; /* 128k max transfer */
    n->idtfy_ctrl.vid = 0x8086;

    if (n->fultondale) {
        n->idtfy_ctrl.ssvid = NVME_FD_DEV_ID;
    } else {
        n->idtfy_ctrl.ssvid = NVME_DEV_ID;
    }
    /* number of supported name spaces bytes [516:519] */
    n->idtfy_ctrl.nn = n->num_namespaces - n->num_user_namespaces;
    n->idtfy_ctrl.acl = NVME_ABORT_COMMAND_LIMIT;
    n->idtfy_ctrl.aerl = ASYNC_EVENT_REQ_LIMIT;
    n->idtfy_ctrl.frmw = 1 << 1 | 0;
    n->idtfy_ctrl.npss = NO_POWER_STATE_SUPPORT;
    n->idtfy_ctrl.awun = 0xff;
    n->idtfy_ctrl.lpa = 1 << 0;

    power = &(n->idtfy_ctrl.psd[0]);
    power->mp = 0x9c4;
    power->enlat = 0x10;
    power->exlat = 0x4;

    power = &(n->idtfy_ctrl.psd[1]);
    power->mp = 0x8fc;
    power->enlat = 0x10;
    power->exlat = 0x10;
    power->rrt = 0x1;
    power->rrl = 0x1;
    power->rwt = 0x1;
    power->rwl = 0x1;

    power = &(n->idtfy_ctrl.psd[2]);
    power->mp = 0x2bc;
    power->enlat = 0x1e8480;
    power->exlat = 0x1e8480;
    power->rrt = 0x2;
    power->rrl = 0x2;
    power->rwt = 0x2;
    power->rwl = 0x1;
}

static void fw_slot_logpage_init(NVMEState *n)
{
    n->last_fw_slot = 1;
    memset(&(n->fw_slot_log), 0x0, sizeof(n->fw_slot_log));
    n->fw_slot_log.afi = 1;
    strncpy((char *)&(n->fw_slot_log.frs1[0]), "1.0", 3);
}

/*********************************************************************
    Function     :    pci_nvme_init
    Description  :    NVME initialization
    Return Type  :    int
    Arguments    :    PCIDevice * : Pointer to the PCI device
    TODO: Make any initialization here or when
         controller receives 'enable' bit?
*********************************************************************/
static int pci_nvme_init(PCIDevice *pci_dev)
{
    NVMEState *n = DO_UPCAST(NVMEState, dev, pci_dev);
    uint32_t ret;
    uint16_t mps, i;
    static uint32_t instance;
    pthread_mutexattr_t mutex_attr;

    n->start_time = time(NULL);
    n->s = B;

    if (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) {
        LOG_ERR("bad number of namespaces value:%u, must be between 1 and %d",
            n->num_namespaces, NVME_MAX_NUM_NAMESPACES);
        return -1;
    }
    if (n->ns_size == 0) {
        LOG_ERR("bad namespace size value:%u, must be at least 1",
            n->ns_size);
        return -1;
    }
    if (n->num_user_namespaces > n->num_namespaces) {
        LOG_ERR("bad user namespaces value:%u, must be less than namespaces:%u",
            n->num_user_namespaces, n->num_namespaces);
        return -1;
    }
    if (n->total_size > NVME_MAX_USER_SIZE) {
    	LOG_ERR("total size:%d exceeds max:%d, setting to max",
		n->total_size, NVME_MAX_USER_SIZE);
	n->total_size = NVME_MAX_USER_SIZE;
    }
    if (((n->num_namespaces - n->num_user_namespaces)
            * n->ns_size) > n->total_size) {
        LOG_NORM("Storage space over-allocated, namespaces:%d"
                 " reserved namespaces:%d namespace size:%d total size:%d\n",
                 n->num_namespaces, n->num_user_namespaces, n->ns_size,
                 n->total_size);
        return -1;
    }
    if (n->drop_rate != 0 && n->drop_rate < NVME_MIN_DROP_RATE) {
        LOG_NORM("drop rate too low, setting to:%d", NVME_MIN_DROP_RATE);
        n->drop_rate = NVME_MIN_DROP_RATE;
    } else if (n->drop_rate > NVME_MAX_DROP_RATE) {
        LOG_NORM("drop rate too high, setting to:%d", NVME_MAX_DROP_RATE);
        n->drop_rate = NVME_MAX_DROP_RATE;
    }
    if (n->fail_rate != 0 && n->fail_rate < NVME_MIN_FAIL_RATE) {
        LOG_NORM("I/O fail rate too low, setting to:%d", NVME_MIN_FAIL_RATE);
        n->fail_rate = NVME_MIN_FAIL_RATE;
    } else if (n->fail_rate > NVME_MAX_FAIL_RATE) {
        LOG_NORM("I/O fail rate too high, setting to:%d", NVME_MAX_FAIL_RATE);
        n->fail_rate = NVME_MAX_FAIL_RATE;
    }
    if (n->security) {
        char password[] = "Verify!!";
        LOG_NORM("Enabling NVME security, initalize lock, password: '%s'\n",
            password);
        memset(n->password, 0, sizeof(n->password));
        strncpy(n->password, password, sizeof(n->password));
        n->s = D;
    }
    if (n->fultondale != 0 && n->fultondale > ARRAY_SIZE(fultondale_boundary)) {
        LOG_NORM("Fultondale index to high:%d, set to 1", n->fultondale);
        n->fultondale = 1;
    }
    if (n->lba_index > NO_LBA_FORMATS) {
        LOG_NORM("Lba index too high:%d, set to 0", n->lba_index);
        n->lba_index = 0;
    }

    n->instance = instance++;
    n->disk = (DiskInfo **)qemu_mallocz(sizeof(DiskInfo *)*n->num_namespaces);
    n->available_space = (n->total_size - ((n->num_namespaces -
        n->num_user_namespaces) * n->ns_size)) * BYTES_PER_MB;

    n->nn_vector_size = (n->num_namespaces + sizeof(unsigned long)-1) /
        sizeof(unsigned long);
    n->nn_vector = qemu_mallocz(sizeof(unsigned long)*n->nn_vector_size);

    for (i = 0; i < NVME_MAX_QS_ALLOCATED; i++) {
        n->sq[i] = NULL;
        n->cq[i] = NULL;
    }
    memset(&n->admin_sq, 0, sizeof(n->admin_sq));
    memset(&n->admin_cq, 0, sizeof(n->admin_cq));

    /* Initialize the admin queues */
    n->admin_sq.phys_contig = 1;
    n->admin_sq.n = n;
    n->admin_sq.cq_id = ACQ_ID;

    n->admin_cq.phys_contig = 1;
    n->admin_cq.irq_enabled = 1;
    n->admin_cq.vector = 0;

    QTAILQ_INIT(&n->admin_cq.sq_list);
    QTAILQ_INSERT_TAIL(&(n->admin_cq.sq_list), &n->admin_sq, entry);

    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_NORMAL);
    pthread_mutex_init(&n->admin_sq.queue_lock, &mutex_attr);
    pthread_mutex_init(&n->admin_cq.queue_lock, &mutex_attr);

    bsem_init(&n->admin_sq.event_lock);

    n->sq[ASQ_ID] = &n->admin_sq;
    n->cq[ACQ_ID] = &n->admin_cq;

    /* TODO: pci_conf = n->dev.config; */
    n->nvectors = NVME_MSIX_NVECTORS;
    n->bar0_size = NVME_REG_SIZE;

    /* Reading the PCI space from the file */
    read_file(n, PCI_SPACE);

    if (n->fultondale) {
        pci_config_set_device_id(n->dev.config, NVME_FD_DEV_ID);
    }

    ret = msix_init((struct PCIDevice *)&n->dev,
         n->nvectors, 0, n->bar0_size);
    if (ret) {
        LOG_NORM("%s(): PCI MSI-X Failed", __func__);
    } else {
        LOG_NORM("%s(): PCI MSI-X Initialized", __func__);
    }
    LOG_NORM("%s(): Reg0 size %u, nvectors: %hu", __func__,
        n->bar0_size, n->nvectors);

    /* NVMe is Little Endian. */
    n->mmio_index = cpu_register_io_memory(nvme_mmio_read, nvme_mmio_write,
        n,  DEVICE_LITTLE_ENDIAN);

    /* Register BAR 0 (and bar 1 as it is 64bit). */
    pci_register_bar((struct PCIDevice *)&n->dev,
        0, ((n->dev.cap_present & QEMU_PCI_CAP_MSIX) ?
        n->dev.msix_bar_size : n->bar0_size),
        (PCI_BASE_ADDRESS_SPACE_MEMORY |
        PCI_BASE_ADDRESS_MEM_TYPE_64),
        nvme_mmio_map);

    /* Update NVME space registery from config file */
    read_file(n, NVME_SPACE);

    /* Defaulting the number of Queues */
    /* Indicates the number of I/O Q's allocated. This is 0's based value. */
    n->feature.number_of_queues = ((NVME_MAX_QID - 1) << 16)
        | (NVME_MAX_QID - 1);

    /* Defaulting the temperature threshold, 60 C */
    n->feature.temperature_threshold = NVME_TEMPERATURE + 10;

    /* Defaulting the async notification to all temperature and threshold */
    n->feature.asynchronous_event_configuration = 0x3;

    for (ret = 0; ret < n->nvectors; ret++) {
        msix_vector_use(&n->dev, ret);
    }

    /* Update the Identify Space of the controller */
    read_identify_cns(n);

    /* Update the firmware slots information */
    fw_slot_logpage_init(n);

    /* Reading CC.MPS field */
    memcpy(&mps, &n->cntrl_reg[NVME_CC], WORD);
    mps &= (uint16_t) MASK(4, 7);
    mps >>= 7;
    n->page_size = (1 << (12 + mps));
    LOG_DBG("Page Size: %d", n->page_size);

    /* Create the Storage Disk */
    if (nvme_create_storage_disks(n)) {
        LOG_NORM("Errors while creating NVME disk");
    }
    n->injected_available_spare = 0;
    n->percentage_used = 0;
    n->temperature = NVME_TEMPERATURE;
    n->outstanding_asyncs = 0;
    n->timeout_error = NULL;
    n->injected_media_errors = 0;
    n->password_retry = 0;

    n->async_event_timer = qemu_new_timer_ns(vm_clock,
        async_process_cb, n);
    QSIMPLEQ_INIT(&n->async_queue);
    QTAILQ_INIT(&n->media_err_list);

    return 0;
}

/*********************************************************************
    Function     :    pci_nvme_uninit
    Description  :    To unregister the NVME device from Qemu
    Return Type  :    void
    Arguments    :    PCIDevice * : Pointer to the PCI device
*********************************************************************/
static int pci_nvme_uninit(PCIDevice *pci_dev)
{
    NVMEState *n = DO_UPCAST(NVMEState, dev, pci_dev);
    int index;

    for (index = 0; index < n->num_namespaces; index++) {
        if (n->disk[index] != NULL) {
            qemu_free(n->disk[index]);
        }
    }
    if (n->async_event_timer) {
        qemu_free_timer(n->async_event_timer);
        n->async_event_timer = NULL;
    }

    nvme_close_storage_disks(n);
    LOG_NORM("Freed NVME device memory");
    return 0;
}

static PCIDeviceInfo nvme_info = {
    .qdev.name = "nvme",
    .qdev.desc = "Non-Volatile Memory Express",
    .qdev.size = sizeof(NVMEState),
    .qdev.vmsd = &vmstate_nvme,
    .qdev.reset = qdev_nvme_reset,
    .config_write = nvme_pci_write_config,
    .config_read = nvme_pci_read_config,
    .init = pci_nvme_init,
    .exit = pci_nvme_uninit,
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("namespaces", NVMEState, num_namespaces, 1),
        DEFINE_PROP_UINT32("size", NVMEState, ns_size, 512),
        DEFINE_PROP_UINT32("total_size", NVMEState, total_size,
            NVME_MAX_USER_SIZE),
        DEFINE_PROP_UINT32("unamespaces", NVMEState, num_user_namespaces, 0),
        DEFINE_PROP_UINT32("drop", NVMEState, drop_rate, 0),
        DEFINE_PROP_UINT32("fail", NVMEState, fail_rate, 0),
        DEFINE_PROP_UINT32("fultondale", NVMEState, fultondale, 0),
        DEFINE_PROP_UINT32("security", NVMEState, security, 0),
        DEFINE_PROP_UINT32("lba_index", NVMEState, lba_index, 0),
        DEFINE_PROP_END_OF_LIST(),
    }
};

static inline void _nvme_check_size(void)
{
    BUILD_BUG_ON(sizeof(NVMEIdentifyController) != 4096);
    BUILD_BUG_ON(sizeof(NVMEIdentifyNamespace) != 4096);
    BUILD_BUG_ON(sizeof(NVMESmartLog) != 512);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdFeatures) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdDeleteSQ) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdCreateSQ) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdGetLogPage) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdDeleteCQ) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdCreateCQ) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdIdentify) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdAbort) != 64);
    BUILD_BUG_ON(sizeof(NVMEAdmCmdAsyncEvRq) != 64);
    BUILD_BUG_ON(sizeof(NVMECmd) != 64);
    BUILD_BUG_ON(sizeof(NVMECmdRead) != 64);
    BUILD_BUG_ON(sizeof(NVMECmdWrite) != 64);
    BUILD_BUG_ON(sizeof(NVMEAonAdmCmdCreateSTag) != 64);
    BUILD_BUG_ON(sizeof(PowerStateDescriptor) != 32);
    BUILD_BUG_ON(sizeof(NVMECQE) != 16);
    BUILD_BUG_ON(sizeof(NVMECtrlCap) != 8);
    BUILD_BUG_ON(sizeof(NVMECtrlConf) != 8);
    BUILD_BUG_ON(sizeof(NVMEVersion) != 4);
    BUILD_BUG_ON(sizeof(NVMECtrlStatus) != 4);
    BUILD_BUG_ON(sizeof(NVMEStatusField) != 2);
    BUILD_BUG_ON(sizeof(RangeDef) != 16);
    BUILD_BUG_ON(sizeof(CtxAttrib) != 4);
}

/*********************************************************************
    Function     :    nvme_register_devices
    Description  :    Registering the NVME Device with Qemu
    Return Type  :    void
    Arguments    :    void
*********************************************************************/
static void nvme_register_devices(void)
{
    pci_qdev_register(&nvme_info);
}

device_init(nvme_register_devices);

