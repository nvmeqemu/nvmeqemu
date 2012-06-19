/*
 * Copyright (c) 2011 Intel Corporation
 *
 * by
 *    Maciej Patelczyk <mpatelcz@gkslx007.igk.intel.com>
 *    Krzysztof Wierzbicki <krzysztof.wierzbicki@intel.com>
 *    Patrick Porlan <patrick.porlan@intel.com>
 *    Nisheeth Bhat <nisheeth.bhat@intel.com>
 *    Sravan Kumar Thokala <sravan.kumar.thokala@intel.com>
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

/* File Level scope functions */
static void clear_nvme_device(NVMEState *n);
static void pci_space_init(PCIDevice *);
static void nvme_pci_write_config(PCIDevice *, uint32_t, uint32_t, int);
static uint32_t nvme_pci_read_config(PCIDevice *, uint32_t, int);
static inline uint8_t range_covers_reg(uint64_t, uint64_t, uint64_t,
    uint64_t);
static void process_doorbell(NVMEState *, target_phys_addr_t, uint32_t);
static void read_file(NVMEState *, uint8_t);
static void sq_processing_timer_cb(void *);
static int nvme_irqcq_empty(NVMEState *, uint32_t);
static void msix_clr_pending(PCIDevice *, uint32_t);

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
    int64_t deadline;

    LOG_DBG("%s(): addr = 0x%08x, val = 0x%08x",
        __func__, (unsigned)addr, val);


    /* Check if it is CQ or SQ doorbell */
    queue_id = (addr - NVME_SQ0TDBL) / sizeof(uint32_t);

    if (queue_id % 2) {
        /* CQ */
        uint16_t new_head = val & 0xffff;
        queue_id = (addr - NVME_CQ0HDBL) / QUEUE_BASE_ADDRESS_WIDTH;
        if (adm_check_cqid(nvme_dev, queue_id)) {
            LOG_NORM("Wrong CQ ID: %d", queue_id);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        if (new_head >= nvme_dev->cq[queue_id].size) {
            LOG_NORM("Bad cq head value: %d", new_head);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        if (is_cq_full(nvme_dev, queue_id)) {
            /* queue was previously full, schedule submission queue check
               in case there are commands that couldn't be processed */
            nvme_dev->sq_processing_timer_target = qemu_get_clock_ns(vm_clock)
                + 5000;
            qemu_mod_timer(nvme_dev->sq_processing_timer,
                nvme_dev->sq_processing_timer_target);
        }
        nvme_dev->cq[queue_id].head = new_head;
        /* Reset the P bit if head == tail for all Queues on
         * a specific interrupt vector */
        if (nvme_dev->cq[queue_id].irq_enabled &&
            !(nvme_irqcq_empty(nvme_dev, nvme_dev->cq[queue_id].vector))) {
            /* reset the P bit */
            LOG_DBG("Reset P bit for vec:%d", nvme_dev->cq[queue_id].vector);
            msix_clr_pending(&nvme_dev->dev, nvme_dev->cq[queue_id].vector);

        }
    } else {
        /* SQ */
        uint16_t new_tail = val & 0xffff;
        queue_id = (addr - NVME_SQ0TDBL) / QUEUE_BASE_ADDRESS_WIDTH;
        if (adm_check_sqid(nvme_dev, queue_id)) {
            LOG_NORM("Wrong SQ ID: %d", queue_id);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_sq, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        if (new_tail >= nvme_dev->sq[queue_id].size) {
            LOG_NORM("Bad sq tail value: %d", new_tail);
            enqueue_async_event(nvme_dev, event_type_error,
                event_info_err_invalid_db, NVME_LOG_ERROR_INFORMATION);
            return;
        }
        nvme_dev->sq[queue_id].tail = new_tail;

        /* Check if the SQ processing routine is scheduled for
         * execution within 5 uS.If it isn't, make it so
         */


        deadline = qemu_get_clock_ns(vm_clock) + 5000;

        if (nvme_dev->sq_processing_timer_target == 0) {
            qemu_mod_timer(nvme_dev->sq_processing_timer, deadline);
            nvme_dev->sq_processing_timer_target = deadline;
        }
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
    int index, ret_val = FAIL;
    for (index = 0; index < NVME_MAX_QS_ALLOCATED; index++) {
        if (nvme_dev->cq[index].vector == vector &&
            nvme_dev->cq[index].irq_enabled) {
            if (nvme_dev->cq[index].head != nvme_dev->cq[index].tail) {
                ret_val = FAIL;
                break;
            } else {
                ret_val = SUCCESS;
            }
        }
    }
    return ret_val;
}

static void sq_processing_timer_cb(void *param)
{
    NVMEState *n =  (NVMEState *) param;
    int sq_id;
    int entries_to_process = ENTRIES_TO_PROCESS;

    /* Check SQs for work */
    for (sq_id = 0; sq_id < NVME_MAX_QS_ALLOCATED; sq_id++) {
        while (n->sq[sq_id].head != n->sq[sq_id].tail) {
            /* Handle one SQ entry */
            if (process_sq(n, sq_id)) {
                break;
            }
            entries_to_process--;
            if (entries_to_process == 0) {
                /* Check back in a short while : 5 uS */
                n->sq_processing_timer_target = qemu_get_clock_ns(vm_clock)
                    + 5000;
                qemu_mod_timer(n->sq_processing_timer,
                    n->sq_processing_timer_target);

                /* We're done for now */
                return;
            }
        }
    }

    /* There isn't anything left to do: temporarily disable the timer */
    n->sq_processing_timer_target = 0;
    qemu_del_timer(n->sq_processing_timer);
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

    LOG_DBG("%s(): addr = 0x%08x, val = 0x%08x",
        __func__, (unsigned)addr, val);
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
                if (nvme_dev->cq[ACQ_ID].dma_addr &&
                    nvme_dev->sq[ASQ_ID].dma_addr) {
                    /* Update CSTS.RDY based on CC.EN and set the phase tag */
                    nvme_dev->cntrl_reg[NVME_CTST] |= CC_EN ;
                    nvme_dev->cq[ACQ_ID].phase_tag = 1;
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
            nvme_dev->sq[ASQ_ID].size = (val & 0xfff) + 1;
            nvme_dev->cq[ACQ_ID].size = ((val >> 16) & 0xfff) + 1;
            break;
        case NVME_ASQ:
            nvme_cntrl_write_config(nvme_dev, NVME_ASQ, val, DWORD);
            *((uint32_t *) &nvme_dev->sq[ASQ_ID].dma_addr) = val;
            break;
        case (NVME_ASQ + 4):
            nvme_cntrl_write_config(nvme_dev, (NVME_ASQ + 4), val, DWORD);
            *((uint32_t *) (&nvme_dev->sq[ASQ_ID].dma_addr) + 1) = val;
            break;
        case NVME_ACQ:
            nvme_cntrl_write_config(nvme_dev, NVME_ACQ, val, DWORD);
            *((uint32_t *) &nvme_dev->cq[ACQ_ID].dma_addr) = val;
            break;
        case (NVME_ACQ + 4):
            nvme_cntrl_write_config(nvme_dev, (NVME_ACQ + 4), val, DWORD);
            *((uint32_t *) (&nvme_dev->cq[ACQ_ID].dma_addr) + 1) = val;
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

    LOG_DBG("%s(): addr = 0x%08x", __func__, (unsigned)addr);

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

    if (!n) {
        return;
    }

    /* Inflight Operations will not be processed */
    qemu_del_timer(n->sq_processing_timer);
    n->sq_processing_timer_target = 0;

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
        memset(&(n->sq[i]), 0, sizeof(NVMEIOSQueue));
        memset(&(n->cq[i]), 0, sizeof(NVMEIOCQueue));
    }

    /* Writing the Admin Queue Attributes after reset */
    nvme_cntrl_write_config(n, NVME_AQA, n->aqstate.aqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ASQ, (uint32_t) n->aqstate.asqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ASQ + 4,
        (uint32_t) (n->aqstate.asqa >> 32), DWORD);
    nvme_cntrl_write_config(n, NVME_ACQ, (uint32_t) n->aqstate.acqa, DWORD);
    nvme_cntrl_write_config(n, NVME_ACQ + 4,
        (uint32_t) (n->aqstate.acqa >> 32), DWORD);

    n->sq[ASQ_ID].head = n->sq[ASQ_ID].tail = 0;
    n->cq[ACQ_ID].head = n->cq[ACQ_ID].tail = 0;

    n->outstanding_asyncs = 0;
    n->feature.temperature_threshold = NVME_TEMPERATURE + 10;
    n->temp_warn_issued = 0;

    QSIMPLEQ_INIT(&n->async_queue);
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
    struct power_state_description *power;
    int index, i;
    int ms_arr[4] = {0, 8, 64, 128};

    LOG_NORM("%s(): called", __func__);
    for (index = 0; index < n->num_namespaces; index++) {
        n->disk[index].idtfy_ns.nsze = (n->ns_size * BYTES_PER_MB) /
            BYTES_PER_BLOCK;
        n->disk[index].idtfy_ns.ncap = (n->ns_size * BYTES_PER_MB) /
            BYTES_PER_BLOCK;
        n->disk[index].idtfy_ns.nuse = 0;
        n->disk[index].idtfy_ns.nlbaf = NO_LBA_FORMATS;
        n->disk[index].idtfy_ns.flbas = LBA_FORMAT_INUSE;

        /* meta data capabilities */
        n->disk[index].idtfy_ns.mc = 1 << 1 | 1 << 0;
        n->disk[index].idtfy_ns.dpc = 1 << 4 | 1 << 3 | 1 << 0;
        n->disk[index].idtfy_ns.dps = 0;

        /* Filling in the LBA Format structure */
        for (i = 0 ; i <= NO_LBA_FORMATS; i++) {
            n->disk[index].idtfy_ns.lbafx[i].lbads = LBA_SIZE + (i / 4);
            n->disk[index].idtfy_ns.lbafx[i].ms = ms_arr[i % 4];
        }
        LOG_NORM("Capacity of namespace %d: %lu", index+1,
            n->disk[index].idtfy_ns.ncap);
    }

    n->idtfy_ctrl = qemu_mallocz(sizeof(*(n->idtfy_ctrl)));
    if (!n->idtfy_ctrl) {
        LOG_ERR("Identify Space not allocated!");
        return;
    }
    pstrcpy((char *)n->idtfy_ctrl->mn, sizeof(n->idtfy_ctrl->mn),
        "Qemu NVMe Driver 0xabcd");
    pstrcpy((char *)n->idtfy_ctrl->sn, sizeof(n->idtfy_ctrl->sn), "NVMeQx1000");
    pstrcpy((char *)n->idtfy_ctrl->fr, sizeof(n->idtfy_ctrl->fr), "012345");

    /* TODO: fix this hardcoded values !!!
    check identify command for details: spec chapter 5.11 bytes 512 and 513
    On each 4 bits in byte is a value of n,
    size calculation:  size=2^n,
    */

    n->idtfy_ctrl->cqes = 4 << 4 | 4;
    n->idtfy_ctrl->sqes = 6 << 4 | 6;
    n->idtfy_ctrl->oacs = 0x2;  /* set due to adm_cmd_format_nvm() */
    n->idtfy_ctrl->oncs = 0x4;  /* dataset mgmt cmd */

    n->idtfy_ctrl->vid = 0x8086;
    n->idtfy_ctrl->ssvid = 0x0111;
    /* number of supported name spaces bytes [516:519] */
    n->idtfy_ctrl->nn = n->num_namespaces;
    n->idtfy_ctrl->acl = NVME_ABORT_COMMAND_LIMIT;
    n->idtfy_ctrl->aerl = ASYNC_EVENT_REQ_LIMIT;
    n->idtfy_ctrl->frmw = 1 << 1 | 0;
    n->idtfy_ctrl->npss = NO_POWER_STATE_SUPPORT;
    n->idtfy_ctrl->awun = 0xff;
    n->idtfy_ctrl->lpa = 1 << 0;
    n->idtfy_ctrl->mdts = 5; /* 128k max transfer */

    power = (struct power_state_description *)&(n->idtfy_ctrl->psd0);
    power->mp = 1;

    power = (struct power_state_description *)&(n->idtfy_ctrl->psdx[0]);
    power->mp = 2;

    power = (struct power_state_description *)&(n->idtfy_ctrl->psdx[32]);
    power->mp = 3;
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
    uint16_t mps;
    static uint32_t instance;

    n->start_time = time(NULL);

    if (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) {
        LOG_ERR("bad number of namespaces value:%u, must be between 1 and %d",
            n->num_namespaces, NVME_MAX_NUM_NAMESPACES);
        return -1;
    }
    if (n->ns_size == 0 || n->ns_size > NVME_MAX_NAMESPACE_SIZE) {
        LOG_ERR("bad namespace size value:%u, must be between 1 and %d",
            n->ns_size, NVME_MAX_NAMESPACE_SIZE);
        return -1;
    }

    n->instance = instance++;
    n->disk = (DiskInfo *)qemu_malloc(sizeof(DiskInfo)*n->num_namespaces);

    /* Zero out the Queue Datastructures */
    memset(n->cq, 0, sizeof(NVMEIOCQueue) * NVME_MAX_QS_ALLOCATED);
    memset(n->sq, 0, sizeof(NVMEIOSQueue) * NVME_MAX_QS_ALLOCATED);

    /* Initialize the admin queues */
    n->sq[ASQ_ID].phys_contig = 1;
    n->cq[ACQ_ID].phys_contig = 1;
    n->cq[ACQ_ID].irq_enabled = 1;
    n->cq[ACQ_ID].vector = 0;

    /* TODO: pci_conf = n->dev.config; */
    n->nvectors = NVME_MSIX_NVECTORS;
    n->bar0_size = NVME_REG_SIZE;

    /* Reading the PCI space from the file */
    read_file(n, PCI_SPACE);

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

    /* Allocating space for NVME regspace & masks except the doorbells */
    n->cntrl_reg = qemu_mallocz(NVME_CNTRL_SIZE);
    n->rw_mask = qemu_mallocz(NVME_CNTRL_SIZE);
    n->rwc_mask = qemu_mallocz(NVME_CNTRL_SIZE);
    n->rws_mask = qemu_mallocz(NVME_CNTRL_SIZE);
    n->used_mask = qemu_mallocz(NVME_CNTRL_SIZE);
    /* Setting up the pointers in NVME address Space
     * TODO
     * These pointers have been defined since
     * present code uses the older defined structures
     * which has been replaced by pointers.
     * Once each and every reference is replaced by
     * offset from cntrl_reg, remove these pointers
     * becasue bit field structures are not portable
     * especially when the memory locations of the bit fields
     * have importance
     */
    n->ctrlcap = (NVMECtrlCap *) (n->cntrl_reg + NVME_CAP);
    n->ctrlv = (NVMEVersion *) (n->cntrl_reg + NVME_VER);
    n->cconf = (NVMECtrlConf *) (n->cntrl_reg + NVME_CC);
    n->cstatus = (NVMECtrlStatus *) (n->cntrl_reg + NVME_CTST);
    n->admqattrs = (NVMEAQA *) (n->cntrl_reg + NVME_AQA);

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
    n->sq_processing_timer = qemu_new_timer_ns(vm_clock,
        sq_processing_timer_cb, n);

    n->outstanding_asyncs = 0;
    n->async_event_timer = qemu_new_timer_ns(vm_clock,
        async_process_cb, n);

    QSIMPLEQ_INIT(&n->async_queue);

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

    /* Freeing space allocated for NVME regspace masks except the doorbells */
    qemu_free(n->cntrl_reg);
    qemu_free(n->rw_mask);
    qemu_free(n->rwc_mask);
    qemu_free(n->rws_mask);
    qemu_free(n->used_mask);
    qemu_free(n->idtfy_ctrl);
    qemu_free(n->disk);

    if (n->sq_processing_timer) {
        if (n->sq_processing_timer_target) {
            qemu_del_timer(n->sq_processing_timer);
            n->sq_processing_timer_target = 0;
        }
        qemu_free_timer(n->sq_processing_timer);
        n->sq_processing_timer = NULL;
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
    BUILD_BUG_ON(sizeof(NVMEIdentifyPowerDesc) != 32);
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
