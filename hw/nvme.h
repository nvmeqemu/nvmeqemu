#ifndef NVME_H_
#define NVME_H_

#include "hw.h"
#include "pci.h"
#include "qemu-timer.h"
#include "loader.h"
#include "sysemu.h"
#include "msix.h"
#include <pthread.h>
#include <sched.h>

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

/* Config FIlE names */
#define NVME_CONFIG_FILE "NVME_device_NVME_config"
#define PCI_CONFIG_FILE "NVME_device_PCI_config"
/* Page size supported by the hardware */
#define PAGE_SIZE 4096
/* Should be in pci class someday. */
#define PCI_CLASS_STORAGE_EXPRESS 0x010802
/* Device ID for NVME Device */
#define NVME_DEV_ID 0x0111
/* Maximum number of charachters on a line in any config file */
#define MAX_CHAR_PER_LINE 250
/* Width of SQ/CQ base address in bytes*/
#define QUEUE_BASE_ADDRESS_WIDTH 8
/* Length in bytes of registers in PCI space */
#define PCI_ROM_ADDRESS_LEN 0x04
#define PCI_BIST_LEN 0x01
#define PCI_BASE_ADDRESS_2_LEN 0x04
/* Defines the number of entries to process per execution */
#define ENTRIES_TO_PROCESS 4
/* bytes,word and dword in bytes */
#define BYTE 1
#define WORD 2
#define DWORD 4
#define QWORD 8

/* SUCCESS and FAILURE return values */
#define SUCCESS 0x0
#define FAIL 0x1

/* Macros to check which Interrupt is enabled */
#define IS_MSIX(n) (n->dev.config[n->dev.msix_cap + 0x03] & 0x80)

/* NVME Cntrl Space specific #defines */
#define CC_EN 1
/* Used to create masks */
/* numbr  : Number of 1's required
 * offset : Offset from LSB
 */
#define MASK(numbr, offset) ((0xffffffff ^ (0xffffffff << numbr)) << offset)

/* The spec requires giving the table structure
 * a 4K aligned region all by itself. */
#define MSIX_PAGE_SIZE 0x1000
/* Reserve second half of the page for pending bits */
#define MSIX_PAGE_PENDING (MSIX_PAGE_SIZE / 2)
/* Give 8kB for registers. Should be OK for 512 queues. */
#define NVME_REG_SIZE (1024 * 8)
/* Size of NVME Controller Registers except the Doorbells */
#define NVME_CNTRL_SIZE 0xfff

/* Maximum Q's allocated for the controller including Admin Q */
#define NVME_MAX_QS_ALLOCATED 64

/* The Q ID starts from 0 for Admin Q and ends at
 * NVME_MAX_QS_ALLOCATED minus 1 for IO Q's */
#define NVME_MAX_QID (NVME_MAX_QS_ALLOCATED - 1)

/* Size of PRP entry in bytes */
#define PRP_ENTRY_SIZE 8

/* Queue Limit.*/
#define NVME_MSIX_NVECTORS 32

/* Assume that block is 512 bytes */
#define NVME_BUF_SIZE 4096
#define NVME_BLOCK_SIZE(x) (1 << x)

/* The value is reported in terms of a power of two (2^n).
 * LBA data size=2^9=512
 */
#define LBA_SIZE 9

#define NVME_EMPTY 0xffffffff

/* Definitions regarding  Identify Namespace Datastructure */
#define NO_POWER_STATE_SUPPORT 2 /* 0 BASED */
#define NVME_ABORT_COMMAND_LIMIT 10 /* 0 BASED */
#define ASYNC_EVENT_REQ_LIMIT 4 /* 0 BASED */

/* Definitions regarding  Identify Controller Datastructure */
#define NO_LBA_FORMATS 15 /* 0 BASED */
#define LBA_FORMAT_INUSE 0 /* 0 BASED */

/* NVMe Controller Registers */
enum {
    NVME_CAP       = 0x0000, /* Controller Capabilities, 64bit */
    NVME_VER       = 0x0008, /* Version, 64bit */
    NVME_INTMS     = 0x000c, /* Interrupt Mask Set, 32bit */
    NVME_INTMC     = 0x0010, /* Interrupt Mask Clean, 32bit */
    NVME_CC        = 0x0014, /* Controller Configuration, 64bit*/
    NVME_CTST      = 0x001c, /* Controller Status, 32bit*/
    NVME_AQA       = 0x0024, /* Admin Queue Attributes, 32bit*/
    NVME_ASQ       = 0x0028, /* Admin Submission Queue Base Address, 64b.*/
    NVME_ACQ       = 0x0030, /* Admin Completion Queue Base Address, 64b.*/
    NVME_RESERVED  = 0x0038, /* Reserved */
    NVME_CMD_SS    = 0x0F00, /* Command Set Specific*/
    NVME_SQ0TDBL   = 0x1000, /* SQ 0 Tail Doorbell, 32bit (Admin) */
    NVME_CQ0HDBL   = 0x1004, /* CQ 0 Head Doorbell, 32bit (Admin)*/
    NVME_SQ1TDBL   = 0x1008, /* SQ 1 Tail Doorbell, 32bit */
    NVME_CQ1HDBL   = 0x100c, /* CQ 1 Head Doorbell, 32bit */

    NVME_SQMAXTDBL = (NVME_SQ0TDBL + 8 * NVME_MAX_QID),
    NVME_CQMAXHDBL = (NVME_CQ0HDBL + 8 * NVME_MAX_QID)
};

/* address for SQ ID. */
#define NVME_SQyTDBL(id) (NVME_SQ0TDBL + 8*(id))
/* address for CQ ID. */
#define NVME_CQyTDBL(id) (NVME_CQ0TDBL + 8*(id))

#define ASQ_ID 0    /* Admin submition queue ID == 0 */
#define ACQ_ID 0    /* Admin complition queue ID == 0 */

struct NVMEBAR0 {
    uint64_t    cap; /* */
    uint32_t    ver;
    uint32_t    intms;
    uint32_t    intmc;
    uint64_t    cc;
    uint32_t    ctst;
    uint32_t    res0;
    uint32_t    aqa;
    uint64_t    asqa;
    uint64_t    acqa;
    /* not important. */
};

/* Used to hold the ASQ,ACQ and AQA between resets */
struct AQState {
    uint32_t    aqa;
    uint64_t    asqa;
    uint64_t    acqa;
};
/* Controller Capabilities - all ReadOnly. TBD: Could be union. */
typedef struct NVMECtrlCap {
    uint16_t mqes;
    uint16_t cqr:1;
    uint16_t ams:2;
    uint16_t res0:5;
    uint16_t to:8;
    uint16_t res1:5;
    uint16_t css:4;
    uint16_t res2:7;
    uint16_t mpsmin:4;
    uint16_t mpsmax:4;
    uint16_t res3:8;
} NVMECtrlCap;

typedef struct NVMEVersion {
    uint16_t mnr; /* minor = 0. */
    uint16_t mjr; /* major = 1. */
} NVMEVersion;

/* Controller Configuration. */
typedef struct NVMECtrlConf {
    uint16_t en:1;
    uint16_t res0:3;
    uint16_t css:3;
    uint16_t mps:4;
    uint16_t ams:4;
    uint16_t shn:2;
    uint16_t iosqes:4;
    uint16_t iocqes:4;
    uint16_t res1:6;
    uint32_t res2;
} NVMECtrlConf;

typedef struct NVMECtrlStatus {
    uint32_t rdy:1;
    uint32_t cfs:1;
    uint32_t shst:2;
    uint32_t res:28;
} NVMECtrlStatus;

typedef struct NVMEAQA {
    uint32_t asqs:12;
    uint32_t res0:4;
    uint32_t acqs:12;
    uint32_t res1:4;
} NVMEAQA;

struct NVMECmd;
typedef struct NVMEIOSQueue {
    uint16_t id;
    uint16_t cq_id;
    uint16_t head;
    uint16_t tail;
    uint16_t prio;
    uint16_t phys_contig;
    uint16_t size;
    uint64_t dma_addr; /* DMA Address */
    /*FIXME: Add support for PRP List. */
    uint32_t abort_cmd_id[NVME_ABORT_COMMAND_LIMIT];
} NVMEIOSQueue;

struct NVMECQE;
typedef struct NVMEIOCQueue {
    uint16_t id;
    uint16_t usage_cnt; /* how many sq is linked */
    uint16_t head;
    uint16_t tail;
    uint32_t vector;
    uint16_t irq_enabled;
    uint16_t phys_contig;
    uint16_t size;
    uint64_t dma_addr; /* DMA Address */
    uint8_t phase_tag; /* check spec for Phase Tag details*/
} NVMEIOCQueue;

/* FIXME*/
enum {
    TH_NOT_STARTED = 0,
    TH_STARTED,
    TH_STOP,
    TH_EXIT,
};

struct abort_command {
    uint16_t sq_id;
    uint16_t cmd_id;
};

/* Figure 53: Get Features - Feature Identifiers */
/* Figure 72: Set Features – Feature Identifiers */
enum {
    NVME_FEATURE_ARBITRATION              = 1,
    NVME_FEATURE_POWER_MANAGEMENT         = 2,
    NVME_FEATURE_LBA_RANGE_TYPE           = 3, /* uses memory buffer */
    NVME_FEATURE_TEMPERATURE_THRESHOLD    = 4,
    NVME_FEATURE_ERROR_RECOVERY           = 5,
    NVME_FEATURE_VOLATILE_WRITE_CACHE     = 6,
    NVME_FEATURE_NUMBER_OF_QUEUES         = 7,
    NVME_FEATURE_INTERRUPT_COALESCING     = 8,
    NVME_FEATURE_INTERRUPT_VECTOR_CONF    = 9,
    NVME_FEATURE_WRITE_ATOMICITY          = 0x0a,
    NVME_FEATURE_ASYNCHRONOUS_EVENT_CONF  = 0x0b,
    NVME_FEATURE_SOFTWARE_PROGRESS_MARKER = 0x80, /* Set Features only*/
};

struct nvme_features {
    uint32_t arbitration;
    uint32_t power_management;
    uint32_t LBA_range_type;    /* uses memory buffer */
    uint32_t temperature_threshold;
    uint32_t error_recovery;
    uint32_t volatile_write_cache;
    uint32_t number_of_queues;
    uint32_t interrupt_coalescing;
    uint32_t interrupt_vector_configuration;
    uint32_t write_atomicity;
    uint32_t asynchronous_event_configuration;
    uint32_t software_progress_marker;
};

/*
    Common structure for admin commands:
        Set Features
        Get Features
*/
typedef struct NVMEAdmCmdFeaturs {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t fid:8; /* CDW10[0-7] Feature ID */
    uint32_t res2:24; /* CDW10[8-31] Reserved */
    uint32_t cdw11;        /* Used by Set Features, example 5.12.1.1*/
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdFeatures;

/* Identify - Controller.
 * Number in comments are in bytes.
 * Check spec NVM Express 1.0b Chapter 5.11 Identify command
 */

typedef struct NVMEIdentifyController {
    uint16_t vid;
    uint16_t ssvid;
    uint8_t sn[20];
    uint8_t mn[40];
    uint8_t fr[8];
    uint8_t rab;
    uint8_t ieee[3];
    uint8_t mic;
    uint8_t mdts;
    uint8_t rsvd255[178];
    uint16_t oacs;
    uint8_t acl;
    uint8_t aerl;
    uint8_t frmw;
    uint8_t lpa;
    uint8_t elpe;
    uint8_t npss;
    uint8_t rsvd511[248];
    uint8_t sqes;
    uint8_t cqes;
    uint16_t rsvd515;
    uint32_t nn;
    uint16_t oncs;
    uint16_t fuses;
    uint8_t fna;
    uint8_t vwc;
    uint16_t awun;
    uint16_t awupf;
    uint8_t rsvd703[174];
    uint8_t rsvd2047[1344];
    uint8_t psd0[32];
    uint8_t psdx[992];
    uint8_t vs[1024];
} NVMEIdentifyController;

struct power_state_description {
    uint16_t mp;
    uint16_t reserved;
    uint32_t enlat;
    uint32_t exlat;
    uint8_t    rrt;
    uint8_t    rrl;
    uint8_t rwt;
    uint8_t rwl;
};

/* In bits */
typedef struct NVMEIdentifyPowerDesc {
    uint16_t mp; /* [0-15] Maximum Power */
    uint16_t res0; /* [16-31] Reserved */
    uint32_t enlat; /* [32-61] Entry Latency */
    uint32_t exlat; /* [62-95] Exit Latency */
    uint8_t rrt:5; /* [96-100] Relative Read Throughput */
    uint8_t res1:3; /* [101-103] Reserved */
    uint8_t rrl:5; /* [104-108] Relative Read Latency */
    uint8_t res2:3; /* [109-111] Reserved */
    uint8_t rwt:5; /* [112-116] Relative Write Throughput */
    uint8_t res3:3; /* [117-119] Reserved */
    uint8_t rwl:5; /* [120-124] Relative Write Latency */
    uint8_t res4:3; /* [125-127] Reserved */
    uint8_t res5[128];  /* [128-255] Reserved */
} NVMEIdentifyPowerDesc;


/* Figure 68: Identify – LBA Format Data Structure,
 * NVM Command Set Specific */
struct NVMELBAFormat {        /* Dword - 32 bits */
    uint16_t ms;        /* [0-15] Metadata Size */
    uint8_t lbads;        /* [16-23] LBA Data Size in a power of 2 (2^n)*/
    uint8_t rp;        /* [24-25] Relative Performance */
                /* [26-31] Bits Reserved */
};

/* Identify - Namespace. Numbers means bytes in comments. */
typedef struct NVMEIdentifyNamespace {
    uint64_t nsze;    /* [0-7] Namespace Size */
    uint64_t ncap;    /* [8-15] Namespace Capacity */
    uint64_t nuse;    /* [16-23] Namespace Utilization */
    uint8_t nsfeat;    /* [24] Namespace Features */
    uint8_t nlbaf;    /* [25] Number of LBA Formats */
    uint8_t flbas;    /* [26] Formatted LBA Size */
    uint8_t mc;    /* [27] Metadata Capabilities */
    uint8_t dpc;    /* [28] End2end Data Protection Capabilities */
    uint8_t dps;    /* [29] End2end Data Protection Type Settings */
    uint8_t res0[98];    /* [30-127] Reserved */
    struct NVMELBAFormat lbafx[16]; /* [128-191] LBA Format 0-15 Support */
    uint8_t res1[192];    /* [192-383] Reserved */
    uint8_t vs[3712];    /* [384-4095] Vendor Specific */
} NVMEIdentifyNamespace;

typedef struct DiskInfo {
    int fd;
    size_t mapping_size;
    uint8_t *mapping_addr;
    /* Pointer to Identify Namespace Strucutre */
    NVMEIdentifyNamespace *idtfy_ns;
    /* Namespace utilization bitmasks (rounded off) */
    uint8_t *ns_util;

    uint32_t write_data_counter;
    uint32_t read_data_counter;

    uint64_t data_units_read[2];
    uint64_t data_units_written[2];
    uint64_t host_read_commands[2];
    uint64_t host_write_commands[2];
} DiskInfo;

typedef struct NVMEState {
    PCIDevice dev;
    int mmio_index;
    void *bar0;
    int bar0_size;
    uint8_t nvectors;

    /* Space for NVME Ctrl Space except doorbells */
    uint8_t *cntrl_reg;
    /* Masks for NVME Ctrl Registers */
    uint8_t *rw_mask; /* RW/RO mask */
    uint8_t *rwc_mask; /* RW1C mask */
    uint8_t *rws_mask; /* RW1S mask */
    uint8_t *used_mask; /* Used/Resv mask */

    struct nvme_features feature;
    uint32_t abort;

    NVMEIOCQueue cq[NVME_MAX_QS_ALLOCATED];
    NVMEIOSQueue sq[NVME_MAX_QS_ALLOCATED];

    DiskInfo *disk;
    uint32_t ns_size;
    uint32_t num_namespaces;
    uint32_t instance;

    time_t start_time;

    /* Used to store the AQA,ASQ,ACQ between resets */
    struct AQState aqstate;

    /* TODO
     * These pointers have been defined since
     * present code uses the older defined strucutres
     * which has been replaced by pointers.
     * Once each and every reference is replaced by
     * offset from cntrl_reg, remove these pointers
     * becasue bit field structures are not portable
     * especially when the memory locations of the bit fields
     * have importance
     */
    NVMECtrlCap *ctrlcap;
    NVMEVersion *ctrlv;
    NVMECtrlConf *cconf; /* Ctrl configuration */
    NVMECtrlStatus *cstatus; /* Ctrl status */
    NVMEAQA *admqattrs; /* Admin queues attributes. */

    QEMUTimer *sq_processing_timer;
    int64_t sq_processing_timer_target;
    /* Used for PIN based and MSI interrupts */
    uint32_t intr_vect;
    /* Page Size used by the hardware */
    uint32_t page_size;
    /* Pointer to Identify Controller Strucutre */
    NVMEIdentifyController *idtfy_ctrl;
} NVMEState;

/* Structure used for default initialization sequence (except doorbell) */
struct NVMEReg {
    uint32_t offset; /* Offset in NVME space */
    uint32_t len; /* len in bytes */
    uint32_t reset; /* reset value */
    uint32_t rw_mask; /* RW/RO mask */
    uint32_t rwc_mask; /* RW1C mask */
    uint32_t rws_mask; /* RW1S mask */
};

/* static struct for default initialization sequence (except doorbell) */

static const struct NVMEReg nvme_reg[] = {
{
    .offset = NVME_CAP,
    .len = 0x04,
    .reset = 0x0f0103FF,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_CAP + 4,
    .len = 0x04,
    .reset = 0x00000020,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_VER,
    .len = 0x04,
    .reset = 0x00010000,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_INTMS,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0xFFFFFFFF,
},

{
    .offset = NVME_INTMC,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0x00,
    .rwc_mask = 0xFFFFFFFF,
    .rws_mask = 0x00,
},

{
    .offset = NVME_CC,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0x00FFFFF1,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_CTST,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_AQA,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0x0FFF0FFF,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_ASQ,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0xFFFFF000,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_ASQ + 4,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0xFFFFFFFF,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_ACQ,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0xFFFFF000,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_ACQ + 4,
    .len = 0x04,
    .reset = 0x00,
    .rw_mask = 0xFFFFFFFF,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},
};

/*
 *    NVME Commands
 *    Each NVMe command is 64 bytes long.
 */

/* Admin Commands Opcodes*/
enum {
    NVME_ADM_CMD_DELETE_SQ     = 0x00,
    NVME_ADM_CMD_CREATE_SQ     = 0x01,
    NVME_ADM_CMD_GET_LOG_PAGE  = 0x02,
    NVME_ADM_CMD_DELETE_CQ     = 0x04,
    NVME_ADM_CMD_CREATE_CQ     = 0x05,
    NVME_ADM_CMD_IDENTIFY      = 0x06,
    NVME_ADM_CMD_ABORT         = 0x08,
    NVME_ADM_CMD_SET_FEATURES  = 0x09,
    NVME_ADM_CMD_GET_FEATURES  = 0x0a,
    NVME_ADM_CMD_ASYNC_EV_REQ  = 0x0c,
    NVME_ADM_CMD_ACTIVATE_FW   = 0x10,
    NVME_ADM_CMD_DOWNLOAD_FW   = 0x11,
    NVME_ADM_CMD_FORMAT_NVM    = 0x80,
    NVME_ADM_CMD_SECURITY_SEND = 0x81,
    NVME_ADM_CMD_SECURITY_RECV = 0x82,
    NVME_ADM_CMD_LAST,
};

/* I/O Commands Opcodes */
enum {
    NVME_CMD_FLUSH = 0x00,
    NVME_CMD_WRITE = 0x01,
    NVME_CMD_READ  = 0x02,
    NVME_CMD_LAST,
};

typedef struct NVMESmartLog {
    uint8_t  critical_warning;
    uint8_t  temperature[2];
    uint8_t  available_spare;
    uint8_t  available_spare_threshold;
    uint8_t  percentage_used;
    uint8_t  reserved1[26];
    uint64_t data_units_read[2];
    uint64_t data_units_written[2];
    uint64_t host_read_commands[2];
    uint64_t host_write_commands[2];
    uint64_t controller_busy_time[2];
    uint64_t power_cycles[2];
    uint64_t power_on_hours[2];
    uint64_t unsafe_shutdowns[2];
    uint64_t media_errors[2];
    uint64_t number_of_error_log_entries[2];
    uint8_t  reserved2[320];
} NVMESmartLog;

enum {
    NVME_LOG_ERROR_INFORMATION   = 0x01,
    NVME_LOG_SMART_INFORMATION   = 0x02,
    NVME_LOG_FW_SLOT_INFORMATION = 0x03,
};

typedef struct NVMEAdmCmdDeleteSQ {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t qid:16; /* CDW10[0-15] Queue ID */
    uint32_t res2:16; /* CDW10[16-31] Reserved */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdDeleteSQ;

typedef struct NVMEAdmCmdCreateSQ {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t qid:16; /* CDW10[0-15] Queue ID */
    uint32_t qsize:16; /* CDW10[16-31] Queue size */
    uint32_t pc:1; /* CDW11[0] Physically Contiguous */
    uint32_t qprio:2; /* CDW11[1-2] Queue Priority */
    uint32_t res2:13; /* CDW11[3-15] Reserved */
    uint32_t cqid:16; /* CDW11[16-31] Completion Queue ID */
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdCreateSQ;

typedef struct NVMEAdmCmdGetLogPage {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t lid:16; /* CDW10[0-15] Log Page ID */
    uint32_t numd:12; /* CDW10[16-27] Number of dwords */
    uint32_t res2:4; /* CDW10[28-31] Reserved */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdGetLogPage;

typedef struct NVMEAdmCmdDeleteCQ {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t qid:16; /* CDW10[0-15] Queue ID */
    uint32_t res2:16; /* CDW10[16-31] Reserved */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdDeleteCQ;

typedef struct NVMEAdmCmdCreateCQ {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t qid:16; /* CDW10[0-15] Queue ID */
    uint32_t qsize:16; /* CDW10[16-31] Queue size */
    uint32_t pc:1; /* CDW11[0] Physically Contiguous */
    uint32_t ien:1; /* CDW11[1] Interrupts Enabled */
    uint32_t res2:14; /* CDW11[2-15] Reserved */
    uint32_t iv:16; /* CDW11[16-31] Interrupt Vector */
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdCreateCQ;

typedef struct NVMEAdmCmdIdentify {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cns:1; /* CDW10[0] Controller or Namespace Structure  */
    uint32_t res2:31; /* CDW10[1-31] Reserved */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdIdentify;

typedef struct NVMEAdmCmdAbort {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t sqid:16; /* CDW10[0-15] Submission queue ID */
    uint32_t cmdid:16; /* CDW10[16-31] Command ID */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdAbort;


typedef struct NVMEAdmCmdAsyncEvRq {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdAsyncEvRq;


struct NVME_rw {
    uint8_t  opcode;
    uint8_t  fuse;
    uint16_t cid;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t slba;
    uint32_t nlb:16;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
};

typedef struct NVMECmd {
    uint8_t  opcode;
    uint8_t  fuse;
    uint16_t cid;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMECmd;

/* I/O Commands definitions.*/
typedef struct NVMECmdRead {
    uint8_t  opcode;
    uint8_t  fuse;
    uint16_t cid;

    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t slba; /* CDW10 & CDW11 - Starting LBA */
    uint32_t nlb:16; /* CDW12[0-15] Number of Logical Blocks*/
    uint32_t res2:10; /* CDW12[16-25] Reserved*/
    uint32_t prinfo:4; /* CDW12[26-29] Protection Information Field*/
    uint32_t fua:1; /* CDW12[30] Force Unit Access*/
    uint32_t lr:1; /* CDW12[31] Limited Entry*/
    uint32_t dsm:8; /* CDW13[0-7] DataSet Management*/
    uint32_t res3:24; /* CDW13[8-31] Reserved */
    uint32_t eilbrt; /* CDW14 Expected Initial Logical Block Reference Tag*/
    uint32_t elbat:16; /* CDW15[0-15] Expected Logical Block Application Tag*/
    uint32_t elbatm:16;
    /* CDW15[16-31] Expected Logical Block Application Tag Mask*/
} NVMECmdRead;

typedef struct NVMECmdWrite {
    uint8_t  opcode;
    uint8_t  fuse;
    uint16_t cid;

    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t slba; /* CDW10 & CDW11 - Starting LBA */
    uint32_t nlb:16; /* CDW12[0-15] Number of Logical Blocks*/
    uint32_t res2:10; /* CDW12[16-25] Reserved*/
    uint32_t prinfo:4; /* CDW12[26-29] Protection Information Field*/
    uint32_t fua:1; /* CDW12[30] Force Unit Access*/
    uint32_t lr:1; /* CDW12[31] Limited Entry*/
    uint32_t dsm:8; /* CDW13[0-7] DataSet Management*/
    uint32_t res3:24; /* CDW13[8-31] Reserved */
    uint32_t ilbrt; /* CDW14 Initial Logical Block Reference Tag*/
    uint32_t lbat:16; /* CDW15[0-15] Logical Block Application Tag*/
    uint32_t lbatm:16; /* CDW15[16-31] Logical Block Application Tag Mask*/
} NVMECmdWrite;

typedef struct NVMEStatusField {
    uint16_t p:1; /* phase tag */
    uint16_t sc:8; /* Status Code */
    uint16_t sct:3; /* Status Code Type*/
    uint16_t res:2;    /*Reserved*/
    uint16_t m:1; /*  More */
    uint16_t dnr:1; /* Do Not Retry */
} NVMEStatusField;

enum {                    /*Spec Chapter 4.5.1.1*/
    NVME_SCT_GEN_CMD_STATUS  = 0x00, /*Generic Command Status*/
    NVME_SCT_CMD_SPEC_ERR    = 0x01,    /*Command Specific Errors*/
    NVME_SCT_MEDIA_ERR       = 0x02,    /*Media Errors*/
    NVME_SCT_RES0            = 0x03,    /*reserved*/
    NVME_SCT_RES1            = 0x04,    /*Reserved*/
    NVME_SCT_RES2            = 0x05,    /*Reserved*/
    NVME_SCT_RES3            = 0x06,    /*Reserved*/
    NVME_SCT_VENDOR_SPECIFIC = 0x07    /*Vendor Specific*/
};

/*Spec Chapter 4.5.1.2.1*/
enum {
    NVME_SC_SUCCESS           = 0x0,
    NVME_SC_INVALID_OPCODE    = 0x1,
    NVME_SC_INVALID_FIELD     = 0x2,
    NVME_SC_CMDID_CONFLICT    = 0x3,
    NVME_SC_DATA_XFER_ERROR   = 0x4,
    NVME_SC_POWER_LOSS        = 0x5,
    NVME_SC_INTERNAL          = 0x6,
    NVME_SC_ABORT_REQ         = 0x7,
    NVME_SC_ABORT_SQ_DELETED  = 0x8,
    NVME_SC_FUSED_FAIL        = 0x9,
    NVME_SC_FUSED_MISSING     = 0xa,
    NVME_SC_INVALID_NAMESPACE = 0xb,
    NVME_SC_LBA_RANGE         = 0x80,
    NVME_SC_CAP_EXCEEDED      = 0x81,
    NVME_SC_NS_NOT_READY      = 0x82,
};

/* Figure 18: Status Code – Command Specific Errors Values */
enum {
    NVME_COMPLETION_QUEUE_INVALID   = 0x00,
    NVME_INVALID_QUEUE_IDENTIFIER   = 0x01,
    NVME_MAX_QUEUE_SIZE_EXCEEDED    = 0x02,
    NVME_ABORT_CMD_LIMIT_EXCEEDED   = 0x03,
    NVME_REQ_CMD_TO_ABORT_NOT_FOUND = 0x04,
    NVME_ASYNC_EVENT_LIMIT_EXCEEDED = 0x05,
    NVME_INVALID_FIRMWARE_SLOT      = 0x06,
    NVME_INVALID_FIRMWARE_IMAGE     = 0x07,
    NVME_INVALID_INTERRUPT_VECTOR   = 0x08,
    NVME_INVALID_LOG_PAGE           = 0x09,
    NVME_INVALID_FORMAT             = 0x0a,

    NVME_CMD_NVM_ERR_CONFLICT       = 0x80,
};

/* Figure 20: Status Code – Media Error Values */
enum {
    NVME_WRITE_FAULT                         = 0x80,
    NVME_UNRECOVERED_READ_ER                 = 0x81,
    NVME_END_TO_END_GUARD_CHECK_ER           = 0x82,
    NVME_END_TO_END_APPLICATION_TAG_CHECK_ER = 0x83,
    NVME_END_TO_END_REFERENCE_TAG_CHECK_ER   = 0x84,
    NVME_COMPARE_FAILURE                     = 0x85,
    NVME_ACCESS_DENIED                       = 0x86,
};

/* 4.5 Completion Queue Entry */
typedef struct NVMECQE {
    uint32_t cmd_specific;
    uint32_t rsvd;
    uint16_t sq_head; /* DW2[0-15] SQ Head Pointer */
    uint16_t sq_id; /* DW2[16-31] SQ ID */
    uint16_t command_id; /* DW3[0-15] Command ID */
    uint16_t status; /* DW3[16] Phase Tag & DW3[17-31] Status Field */
} NVMECQE;


/* CNS bit in Identify command */
enum {
    NVME_IDENTIFY_NAMESPACE  = 0,
    NVME_IDENTIFY_CONTROLLER = 1,
};

/* Config File Read Strucutre */
typedef struct FILERead {
    uint32_t offset;
    uint32_t len;
    uint32_t val;
    uint32_t ro_mask;
    uint32_t rw_mask;
    uint32_t rwc_mask;
    uint32_t rws_mask;
    char *cfg_name;
} FILERead;

enum {PCI_SPACE = 0, NVME_SPACE = 1};

/* Initialize IO thread */
int nvme_init_io_thread(NVMEState *n);

/* Admin command processing */
uint8_t nvme_admin_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe);

/* IO command processing */
uint8_t nvme_io_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe);

/* Storage Disk */
int nvme_open_storage_disk(NVMEState *n);
int nvme_close_storage_disk(NVMEState *n);
int nvme_create_storage_disk(NVMEState *n , uint32_t disk_num);
int nvme_del_storage_disk(NVMEState *n , uint32_t disk_num);


void nvme_dma_mem_read(target_phys_addr_t addr, uint8_t *buf, int len);
void nvme_dma_mem_write(target_phys_addr_t addr, uint8_t *buf, int len);
void process_sq(NVMEState *n, uint16_t sq_id);

/* Config file read functions */
int read_config_file(FILE *, NVMEState *, uint8_t);

/* Functions for NVME Controller space reads and writes
 * (except doorbell)
 */
uint32_t nvme_cntrl_read_config(NVMEState *,
    target_phys_addr_t, uint8_t);
void nvme_cntrl_write_config(NVMEState *,
    target_phys_addr_t, uint32_t, uint8_t);

#endif /* NVME_H_ */
