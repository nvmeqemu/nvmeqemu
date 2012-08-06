#ifndef NVME_H_
#define NVME_H_

#include "bitops.h"
#include "hw.h"
#include "pci.h"
#include "qemu-timer.h"
#include "qemu-queue.h"
#include "loader.h"
#include "sysemu.h"
#include "msix.h"
#include <pthread.h>
#include <sched.h>

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

/* Config FIlE names */
#define NVME_CONFIG_FILE "NVME_device_NVME_config"
#define PCI_CONFIG_FILE "NVME_device_PCI_config"
/* Page size supported by the hardware */
#define PAGE_SIZE 4096
/* Should be in pci class someday. */
#define PCI_CLASS_STORAGE_EXPRESS 0x010802
/* Device ID for NVME Device */
#define NVME_DEV_ID 0x0111
#define NVME_FD_DEV_ID 0x0112
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

#define NVME_NO_COMPLETE 0xff

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

#define NVME_BUF_SIZE 4096
#define NVME_BLOCK_SIZE(x) (1 << x)

/* The value is reported in terms of a power of two (2^n).
 * LBA data size=2^9=512
 */
#define LBA_SIZE 9
#define BYTES_PER_BLOCK NVME_BLOCK_SIZE(LBA_SIZE)
#define BYTES_PER_MB (1024ULL * 1024ULL)

/* Definitions regarding  Identify Namespace Datastructure */
#define NO_POWER_STATE_SUPPORT 2 /* 0 BASED */
#define NVME_ABORT_COMMAND_LIMIT 10 /* 0 BASED */
#define ASYNC_EVENT_REQ_LIMIT 3 /* 0 BASED */

/* Definitions regarding  Identify Controller Datastructure */
#define NO_LBA_FORMATS 15 /* 0 BASED */
#define LBA_FORMAT_INUSE 0 /* 0 BASED */

#define NVME_SPARE_THRESH 20
#define NVME_TEMPERATURE 0x143

#define NVME_MAX_USER_SIZE 16384
#define NVME_MAX_NAMESPACE_SIZE 8192
#define NVME_MAX_NUM_NAMESPACES 256
#define NVME_AON_MAX_NUM_PDS 2048
#define NVME_AON_MAX_NUM_STAGS 2048
#define NVME_AON_MAX_NUM_NSTAGS 2048

#define NVME_MAX_DROP_RATE 10000000
#define NVME_MIN_DROP_RATE 100
#define NVME_MAX_FAIL_RATE 10000000
#define NVME_MIN_FAIL_RATE 100

/* Definitions for fultondale */
#define ENABLE_DAS  0x01     /* Driver Assisted Striping Enable */

enum {
    FD_128K_BDRY    = 0x40000 | ENABLE_DAS,
    FD_64K_BDRY     = 0x30000 | ENABLE_DAS,
    FD_32K_BDRY     = 0x20000 | ENABLE_DAS,
    FD_16K_BDRY     = 0x10000 | ENABLE_DAS,
};

extern uint32_t fultondale_boundary[];
extern uint32_t fultondale_boundary_feature[];

enum {
    NVME_COMMAND_SET = 0x0,
    AON_COMMAND_SET  = 0x1
};

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

typedef struct CommandEntry {
    QTAILQ_ENTRY(CommandEntry) entry;
    uint16_t cid;
} CommandEntry;

typedef struct NVMEIOSQueue {
    uint16_t id;
    uint16_t cq_id;
    uint32_t head;
    uint32_t tail;
    uint16_t prio;
    uint16_t phys_contig;
    uint32_t size;
    uint64_t dma_addr; /* DMA Address */
    /*FIXME: Add support for PRP List. */
    QTAILQ_HEAD(cmd_list, CommandEntry) cmd_list;
} NVMEIOSQueue;

typedef struct NVMEIOCQueue {
    uint16_t id;
    uint16_t usage_cnt; /* how many sq is linked */
    uint32_t head;
    uint32_t tail;
    uint32_t vector;
    uint16_t irq_enabled;
    uint16_t phys_contig;
    uint32_t size;
    uint64_t dma_addr;  /* DMA Address */
    uint8_t  phase_tag; /* check spec for Phase Tag details*/
    uint32_t pdid;      /* for aon */
} NVMEIOCQueue;

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
    NVME_FEATURE_FULTON_STRIPING_CFG      = 0xf0,
};

typedef struct NVMEFeatures {
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
} NVMEFeatures;

/*
    Common structure for admin commands:
        Set Features
        Get Features
*/
typedef struct NVMEAdmCmdFeatures {
    uint32_t opcode:8;
    uint32_t fuse:2;
    uint32_t res0:6;
    uint32_t cid:16;
    uint32_t nsid;
    uint64_t res1;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t fid:8;     /* CDW10[0-7] Feature ID */
    uint32_t res2:24;   /* CDW10[8-31] Reserved */
    uint32_t cdw11;     /* Used by Set Features, example 5.12.1.1*/
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdFeatures;

typedef struct power_state_description {
    uint16_t mp;
    uint16_t reserved;
    uint32_t enlat;
    uint32_t exlat;
    uint8_t  rrt;
    uint8_t  rrl;
    uint8_t  rwt;
    uint8_t  rwl;
    uint8_t  resv[16];
} PowerStateDescriptor;

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
    PowerStateDescriptor psd[32];
    uint8_t vs[1024];
} NVMEIdentifyController;

/* Figure 68: Identify – LBA Format Data Structure,
 * NVM Command Set Specific */
typedef struct NVMELBAFormat {  /* Dword - 32 bits */
    uint16_t ms;        /* [0-15] Metadata Size */
    uint8_t lbads;      /* [16-23] LBA Data Size in a power of 2 (2^n)*/
    uint8_t rp;         /* [24-25] Relative Performance */
                        /* [26-31] Bits Reserved */
} NVMELBAFormat;

typedef struct AONIdCtrlVs {
    /* starts at the vendor specific section of nvme identify controller */
    uint16_t acc;               /* [3072-3073] */
    uint8_t mns;                /* [3074] */
    uint8_t mws;                /* [3075] */
    uint16_t mnpd;              /* [3076-3077] */
    uint16_t pad;               /* [3078-3079] */
    uint64_t tus;               /* [3080-3087] */
    uint32_t mnn;               /* [3088-3091] */
    uint32_t mnon;              /* [3092-3095] */
    uint32_t mnhr;              /* [3096-3099] */
    uint8_t ows;                /* [3100] */
    uint8_t mows;               /* [3101] */
    uint8_t smpsmax;            /* [3102] */
    uint8_t smpsmin;            /* [3103] */
    uint8_t nlbaf;              /* [3104] */
    uint8_t mc;                 /* [3105] */
    uint8_t dpc;                /* [3106] */
    uint8_t resv3107;           /* [3107] */
    NVMELBAFormat lbaf[16];     /* [3108-31] LBA Format 0-15 Support */
    uint8_t dcard_sn[20];       /* [3172-3191] */
    uint8_t baseboard_sn[20];   /* [3192-3211] */
} AONIdCtrlVs;

/* Identify - Namespace. Numbers means bytes in comments. */
typedef struct NVMEIdentifyNamespace {
    uint64_t nsze;      /* [0-7] Namespace Size */
    uint64_t ncap;      /* [8-15] Namespace Capacity */
    uint64_t nuse;      /* [16-23] Namespace Utilization */
    uint8_t  nsfeat;    /* [24] Namespace Features */
    uint8_t  nlbaf;     /* [25] Number of LBA Formats */
    uint8_t  flbas;     /* [26] Formatted LBA Size */
    uint8_t  mc;        /* [27] Metadata Capabilities */
    uint8_t  dpc;       /* [28] End2end Data Protection Capabilities */
    uint8_t  dps;       /* [29] End2end Data Protection Type Settings */
    uint8_t  res0[98];  /* [30-127] Reserved */
    NVMELBAFormat lbaf[16]; /* [128-191] LBA Format 0-15 Support */
    uint8_t  res1[192]; /* [192-383] Reserved */
    uint8_t  vs[3712];  /* [384-4095] Vendor Specific */
} NVMEIdentifyNamespace;

enum {
    NVME_FLBAS_EXTENDED_LBA = 1 << 4,
    NVME_FLBAS_LBA_MASK     = 0xf,
    NVME_MC_SEPARATE_BUFFER = 1 << 1,
    NVME_MC_EXTENDED_LBA    = 1 << 0,
    NVME_DPC_PI_LAST        = 1 << 4,
    NVME_DPC_PI_FIRST       = 1 << 3,
    NVME_DPC_TYPE_1         = 1 << 0,
    NVME_DPC_TYPE_2         = 1 << 1,
    NVME_DPC_TYPE_3         = 1 << 2,
    NVME_DPC_TYPE_MASK      = 0x7,
    NVME_DPS_PI_FIRST       = 1 << 3,
    NVME_DPS_PI_LAST        = 0 << 3,
    NVME_DPS_TYPE_1         = 1,
    NVME_DPS_TYPE_2         = 2,
    NVME_DPS_TYPE_3         = 3,
    NVME_DPS_TYPE_MASK      = 0x7,
    NVME_NSFEAT_THIN        = 1 << 0,
    NVME_NSFEAT_VOLATILE    = 1 << 1,
    NVME_NSFEAT_READ_ERR    = 1 << 2,
};

/* macros to convert DPS to DPC bits */
#define NVME_DPS_PIL(dps) (1 << (4 - ((dps >> 3) & 1)))
#define NVME_DPS_TYPE(dps) (1 << ((dps & NVME_DPS_TYPE_MASK) - 1))

static inline int nvme_dps_valid(uint16_t dps, uint16_t dpc)
{
    return !dps || ((dpc & NVME_DPS_PIL(dps)) &&
        ((dpc & NVME_DPC_TYPE_MASK) & NVME_DPS_TYPE(dps)));
}

typedef struct AsyncResult {
    uint8_t event_type;
    uint8_t event_info;
    uint8_t log_page;
    uint8_t resv;
} AsyncResult;

typedef struct AsyncEvent {
    QSIMPLEQ_ENTRY(AsyncEvent) entry;
    AsyncResult result;
} AsyncEvent;

typedef struct LBARangeType {
    uint8_t  type;
    uint8_t  attributes;
    uint8_t  rsvd2[14];
    uint64_t slba;
    uint64_t nlb;
    uint8_t  guid[16];
    uint8_t  rsvd48[16];
} LBARangeType;

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

typedef struct NVMEFwSlotInfoLog {
    uint8_t  afi;
    uint8_t  reserved1[7];
    uint8_t  frs1[8];
    uint8_t  frs2[8];
    uint8_t  frs3[8];
    uint8_t  frs4[8];
    uint8_t  frs5[8];
    uint8_t  frs6[8];
    uint8_t  frs7[8];
    uint8_t  reserved2[448];
} NVMEFwSlotInfoLog;

enum {
    NVME_LOG_ERROR_INFORMATION   = 0x01,
    NVME_LOG_SMART_INFORMATION   = 0x02,
    NVME_LOG_FW_SLOT_INFORMATION = 0x03,
};

typedef struct DiskInfo {
    int fd;
    int mfd;
    int nsid;
    size_t mapping_size;
    uint8_t *mapping_addr;

    size_t meta_mapping_size;
    uint8_t *meta_mapping_addr;

    NVMEIdentifyNamespace idtfy_ns;
    LBARangeType range_type;

    /* Namespace utilization bitmasks (rounded off) */
    uint8_t *ns_util;
    uint8_t thresh_warn_issued;

    uint32_t write_data_counter;
    uint32_t read_data_counter;

    uint64_t data_units_read[2];
    uint64_t data_units_written[2];
    uint64_t host_read_commands[2];
    uint64_t host_write_commands[2];
} DiskInfo;

typedef struct NVMEAonPD {
    uint32_t usage_count;
} NVMEAonPD;

typedef struct NVMEAonStag {
    uint32_t pdid;
    uint64_t smps;
    uint64_t prp;
    uint64_t nmp;
} NVMEAonStag;

enum {
    NVME_MEDIA_ERR_WRITE    = 0,
    NVME_MEDIA_ERR_READ     = 1,
    NVME_MEDIA_ERR_GUARD    = 2,
    NVME_MEDIA_ERR_APP_TAG  = 3,
    NVME_MEDIA_ERR_REF_TAG  = 4,
    NVME_MEDIA_ERR_COMPARE  = 5,
    NVME_MEDIA_ERR_ACCESS   = 6,
    NVME_TO_WRITE           = 1,
    NVME_TO_READ            = 2,
    NVME_TO_IO              = 3,
};

typedef struct NVMEIoError {
    QTAILQ_ENTRY(NVMEIoError) entry;
    uint32_t slba;
    uint32_t elba;
    uint32_t io_error;
} NVMEIoError;

typedef struct NVMEAonNStag {
    uint32_t pdid;
    uint32_t at;
    uint32_t nsid;
} NVMEAonNStag;

/* Refer to Safford Peak Security Management Addendum */
typedef enum SecurityState {
    A = 'A',
    B = 'B',
    C = 'C',
    D = 'D',
    E1 = 'E',
    E2 = 'E',
    F = 'F',
    G = 'G',
    H = 'H',
} SecurityState;

enum  {
    ATA_SEC_SET_PASSWORD        = 0xf1,
    ATA_SEC_UNLOCK              = 0xf2,
    ATA_SEC_ERASE_PREP          = 0xf3,
    ATA_SEC_ERASE_UNIT          = 0xf4,
    ATA_SEC_FREEZE_LOCK         = 0xf5,
    ATA_SEC_DISABLE_PASSWORD    = 0xf6,
};

#define NVME_MAX_PASSWORD_RETRY 5

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

    NVMEFeatures feature;

    NVMEIOCQueue cq[NVME_MAX_QS_ALLOCATED];
    NVMEIOSQueue sq[NVME_MAX_QS_ALLOCATED];

    DiskInfo **disk;
    uint32_t ns_size;
    uint32_t num_namespaces;
    uint32_t instance;
    uint32_t num_user_namespaces;
    uint32_t total_size;
    uint32_t drop_rate;
    uint32_t fail_rate;
    uint32_t fultondale;
    uint32_t security;
    uint32_t lba_index;

    uint64_t available_space;

    char password[32];
    uint8_t password_retry;
    SecurityState s;

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
    AONIdCtrlVs *aon_ctrl_vs;
    /* Pointer to Firmware slot info log page */
    NVMEFwSlotInfoLog fw_slot_log;
    uint8_t last_fw_slot;

    uint8_t use_aon; /* flag if aon is enabled */
    uint8_t temp_warn_issued;
    uint16_t temperature;
    uint8_t percentage_used;
    uint8_t injected_available_spare;
    uint8_t injected_media_errors;
    uint64_t media_errors;

    QEMUTimer *async_event_timer;

    uint16_t async_cid[ASYNC_EVENT_REQ_LIMIT + 1];
    uint16_t outstanding_asyncs;

    QSIMPLEQ_HEAD(async_queue, AsyncEvent) async_queue;
    QTAILQ_HEAD(media_err_list, NVMEIoError) media_err_list;
    NVMEIoError *timeout_error;

    unsigned long *nn_vector;
    unsigned long nn_vector_size;

    NVMEAonPD    **protection_domains;
    NVMEAonStag  **stags;
    NVMEAonNStag **nstags;
} NVMEState;

static inline int security_state_unlocked(NVMEState *n)
{
    if (n->s != B && n->s != H && n->s != F && n->s != E1) {
        return 0;
    }
    return 1;
}

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
    .reset = 0x0f0007FF,
    .rw_mask = 0x00,
    .rwc_mask = 0x00,
    .rws_mask = 0x00,
},

{
    .offset = NVME_CAP + 4,
    .len = 0x04,
    .reset = 0x00000060,
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
    NVME_ADM_CMD_DELETE_SQ           = 0x00,
    NVME_ADM_CMD_CREATE_SQ           = 0x01,
    NVME_ADM_CMD_GET_LOG_PAGE        = 0x02,
    NVME_ADM_CMD_DELETE_CQ           = 0x04,
    NVME_ADM_CMD_CREATE_CQ           = 0x05,
    NVME_ADM_CMD_IDENTIFY            = 0x06,
    NVME_ADM_CMD_ABORT               = 0x08,
    NVME_ADM_CMD_SET_FEATURES        = 0x09,
    NVME_ADM_CMD_GET_FEATURES        = 0x0a,
    NVME_ADM_CMD_ASYNC_EV_REQ        = 0x0c,
    NVME_ADM_CMD_ACTIVATE_FW         = 0x10,
    NVME_ADM_CMD_DOWNLOAD_FW         = 0x11,
    NVME_ADM_CMD_FORMAT_NVM          = 0x80,
    NVME_ADM_CMD_SECURITY_SEND       = 0x81,
    NVME_ADM_CMD_SECURITY_RECV       = 0x82,
    AON_ADM_CMD_CREATE_PD            = 0x84,
    AON_ADM_CMD_CREATE_STAG          = 0x85,
    AON_ADM_CMD_DELETE_PD            = 0x88,
    AON_ADM_CMD_DELETE_STAG          = 0x8c,
    AON_ADM_CMD_CREATE_NAMESPACE     = 0x90,
    AON_ADM_CMD_CREATE_NAMESPACE_TAG = 0x94,
    AON_ADM_CMD_DELETE_NAMESPACE     = 0x98,
    AON_ADM_CMD_DELETE_NAMESPACE_TAG = 0x9c,
    AON_ADM_CMD_MODIFY_NAMESPACE     = 0xa0,
    AON_ADM_CMD_INJECT_ERROR         = 0xb0,
    NVME_ADM_CMD_LAST,
};

/* I/O Commands Opcodes */
enum {
    NVME_CMD_FLUSH = 0x00,
    NVME_CMD_WRITE = 0x01,
    NVME_CMD_READ  = 0x02,
    NVME_CMD_WRITE_UNCORRECTABLE = 0x4,
    NVME_CMD_COMPARE = 0x5,
    NVME_CMD_DSM = 0x9,
    AON_CMD_USER_FLUSH = 0x40,
    AON_CMD_USER_WRITE = 0x41,
    AON_CMD_USER_READ = 0x42,
    NVME_CMD_LAST,
};

enum {
    NVME_ERR_CLEAR      = 0,
    NVME_ERR_MEDIA      = 1,
    NVME_ERR_SPARE      = 2,
    NVME_ERR_TEMP       = 3,
    NVME_ERR_WEAR       = 4,
    NVME_ERR_TIME_OUT   = 5,
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
    uint32_t qid:16;    /* CDW10[0-15] Queue ID */
    uint32_t res2:16;   /* CDW10[16-31] Reserved */
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
    uint32_t qid:16;    /* CDW10[0-15] Queue ID */
    uint32_t qsize:16;  /* CDW10[16-31] Queue size */
    uint32_t pc:1;      /* CDW11[0] Physically Contiguous */
    uint32_t qprio:2;   /* CDW11[1-2] Queue Priority */
    uint32_t res2:13;   /* CDW11[3-15] Reserved */
    uint32_t cqid:16;   /* CDW11[16-31] Completion Queue ID */
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
    uint32_t lid:16;    /* CDW10[0-15] Log Page ID */
    uint32_t numd:12;   /* CDW10[16-27] Number of dwords */
    uint32_t res2:4;    /* CDW10[28-31] Reserved */
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
    uint32_t qid:16;    /* CDW10[0-15] Queue ID */
    uint32_t res2:16;   /* CDW10[16-31] Reserved */
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
    uint32_t qid:16;    /* CDW10[0-15] Queue ID */
    uint32_t qsize:16;  /* CDW10[16-31] Queue size */
    uint32_t pc:1;      /* CDW11[0] Physically Contiguous */
    uint32_t ien:1;     /* CDW11[1] Interrupts Enabled */
    uint32_t res2:14;   /* CDW11[2-15] Reserved */
    uint32_t iv:16;     /* CDW11[16-31] Interrupt Vector */
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
    uint32_t cns:1;     /* CDW10[0] Controller or Namespace Structure */
    uint32_t res2:31;   /* CDW10[1-31] Reserved */
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
    uint32_t sqid:16;   /* CDW10[0-15] Submission queue ID */
    uint32_t cmdid:16;  /* CDW10[16-31] Command ID */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NVMEAdmCmdAbort;

enum {
    event_type_error = 0,
    event_type_smart = 1,
    event_info_err_invalid_sq = 0,
    event_info_err_invalid_db = 1,
    event_info_err_diag_fail  = 2,
    event_info_err_pers_internal_err = 3,
    event_info_err_trans_internal_err = 4,
    event_info_err_fw_img_load_err = 5,
    event_info_smart_reliability = 0,
    event_info_smart_temp_thresh = 1,
    event_info_smart_spare_thresh = 2
};

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


typedef struct NVME_rw {
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
} NVME_rw;

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
    uint64_t slba;      /* CDW10 & CDW11 - Starting LBA */
    uint32_t nlb:16;    /* CDW12[0-15] Number of Logical Blocks*/
    uint32_t res2:10;   /* CDW12[16-25] Reserved*/
    uint32_t prinfo:4;  /* CDW12[26-29] Protection Information Field*/
    uint32_t fua:1;     /* CDW12[30] Force Unit Access*/
    uint32_t lr:1;      /* CDW12[31] Limited Entry*/
    uint32_t dsm:8;     /* CDW13[0-7] DataSet Management*/
    uint32_t res3:24;   /* CDW13[8-31] Reserved */
    uint32_t eilbrt;    /* CDW14 Expected Initial Logical Block Reference Tag*/
    uint32_t elbat:16;  /* CDW15[0-15] Expected Logical Block Application Tag*/
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
    uint64_t slba;      /* CDW10 & CDW11 - Starting LBA */
    uint32_t nlb:16;    /* CDW12[0-15] Number of Logical Blocks*/
    uint32_t res2:10;   /* CDW12[16-25] Reserved*/
    uint32_t prinfo:4;  /* CDW12[26-29] Protection Information Field*/
    uint32_t fua:1;     /* CDW12[30] Force Unit Access*/
    uint32_t lr:1;      /* CDW12[31] Limited Entry*/
    uint32_t dsm:8;     /* CDW13[0-7] DataSet Management*/
    uint32_t res3:24;   /* CDW13[8-31] Reserved */
    uint32_t ilbrt;     /* CDW14 Initial Logical Block Reference Tag*/
    uint32_t lbat:16;   /* CDW15[0-15] Logical Block Application Tag*/
    uint32_t lbatm:16;  /* CDW15[16-31] Logical Block Application Tag Mask*/
} NVMECmdWrite;

typedef struct NVMEAonAdmCmdCreateSTag {
    uint32_t opcode:8;      /* CDW0[0-7]*/
    uint32_t fuse:3;        /* CDW0[8-10]*/
    uint32_t res:3;         /* CDW0[11-13]*/
    uint32_t barriers:2;    /* CDW0[14-15] */
    uint32_t cdw1;          /* CDW[1]*/
    uint32_t cdw2;          /* CCDW[2-3]*/
    uint32_t cdw3;
    uint32_t cdw4;
    uint32_t cdw5;
    uint64_t prp1;          /* CDW[6-7]*/
    uint32_t cdw8;
    uint32_t cdw9;
    uint32_t stag;          /* CDW[10]:Steering Tag*/
    uint32_t smps:8;        /* CDW[11][bits:0-7]: Stag Memory Page Size */
    uint32_t rstag:1;       /* CDW[11][bit:8]: Replace Stag */
    uint32_t res1:23;       /* CDW[11][bit:9:]:reserved*/
    uint64_t nmp;           /* CDW[12:13]:Number of memory pages*/
    uint32_t pdid;          /* CDW[14]:Protection Domain Identifier*/
    uint32_t cdw15;
} NVMEAonAdmCmdCreateSTag;

typedef struct NVMEAonUserRwCmd {
    uint32_t opcode:8;      /* CDW0[0-7]*/
    uint32_t fuse:3;        /* CDW0[8-10]*/
    uint32_t res:3;         /* CDW0[11-13]*/
    uint32_t barriers:2;    /* CDW0[14-15] */
    uint32_t cid:16;        /* CDW0[16-31]*/
    uint32_t nstag;         /* CDW[1]: Namespace Tag */
    uint64_t res1;          /* CDW[2-3]*/
    uint64_t mdsto;         /* CDW[4-5]: Metadata STag Offset */
    uint64_t sto;           /* CDW[6-7] STag Offset */
    uint32_t mdstag;        /* CDW[8]: Metadata STag */
    uint32_t stag;          /* CDW[9]: STag */
    uint64_t slba;          /* CDW[10-11] */
    uint32_t nlb:16;        /* CDW12[0-15] Number of Logical Blocks*/
    uint32_t res2:10;       /* CDW12[16-25] Reserved*/
    uint32_t prinfo:4;      /* CDW12[26-29] Protection Information Field*/
    uint32_t fua:1;         /* CDW12[30] Force Unit Access*/
    uint32_t lr:1;          /* CDW12[31] Limited Entry*/
    uint32_t dsm:8;         /* CDW13[0-7] DataSet Management*/
    uint32_t res3:24;       /* CDW13[8-31] Reserved */
    uint32_t eilbrt;        /* CDW14 Expected Initial Logical Block Reference Tag*/
    uint32_t elbat:16;      /* CDW15[0-15] Expected Logical Block Application Tag*/
    uint32_t elbatm:16;
} NVMEAonUserRwCmd;

typedef struct NVMEStatusField {
    uint16_t p:1;   /* phase tag */
    uint16_t sc:8;  /* Status Code */
    uint16_t sct:3; /* Status Code Type*/
    uint16_t res:2; /* Reserved*/
    uint16_t m:1;   /* More */
    uint16_t dnr:1; /* Do Not Retry */
} NVMEStatusField;

enum {                    /*Spec Chapter 4.5.1.1*/
    NVME_SCT_GEN_CMD_STATUS  = 0x00,    /*Generic Command Status*/
    NVME_SCT_CMD_SPEC_ERR    = 0x01,    /*Command Specific Errors*/
    NVME_SCT_MEDIA_ERR       = 0x02,    /*Media Errors*/
    NVME_SCT_RES0            = 0x03,    /*reserved*/
    NVME_SCT_RES1            = 0x04,    /*Reserved*/
    NVME_SCT_RES2            = 0x05,    /*Reserved*/
    NVME_SCT_RES3            = 0x06,    /*Reserved*/
    NVME_SCT_VENDOR_SPECIFIC = 0x07     /*Vendor Specific*/
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
    NVME_SC_CMD_SEQ_ERROR     = 0xc,
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

/* AON Specific Status Codes */
enum {
    NVME_AON_CONFLICTING_ATTRIBUTES = 0x80,
    NVME_AON_INVALID_STAG = 0x82,
    NVME_AON_INVALID_NAMESPACE_SIZE = 0x83,
    NVME_AON_INVALID_NAMESPACE_CAPACITY = 0x84,
    NVME_AON_INVALID_LOGICAL_BLOCK_FORMAT = 0x85,
    NVME_AON_INVALID_END_TO_END_DATA_PROTECTION_CONFIGURATION = 0x86,
    NVME_AON_INVALID_NAMESPACE_TAG = 0x87,
    NVME_AON_INVALID_PROTECTION_DOMAIN_IDENTIFIER = 0x88,
    NVME_AON_READ_PARTIAL_UNALLOCATED_BLOCK = 0x89,
    NVME_AON_READ_UNALLOCATED_BLOCK = 0x8a,
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
    NVMEStatusField status; /* DW3[16] Phase Tag & DW3[17-31] Status Field */
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

/* DSM context attributes */
typedef struct CtxAttrib {
    uint16_t AF        : 4;      /* access frequency */
    uint16_t AL        : 2;      /* access latency */
    uint16_t reserved0 : 2;
    uint16_t SR        : 1;      /* sequential read range */
    uint16_t SW        : 1;      /* sequential write range */
    uint16_t WP        : 1;      /* write prepared */
    uint16_t reserved1 : 13;
    uint16_t CAS       : 8;      /* cmd access size */
} __attribute__((__packed__)) CtxAttrib;


/* DSM range definition */
typedef struct RangeDef {
    struct CtxAttrib ctxAttrib;
    uint32_t  length;
    uint64_t  slba;
} __attribute__((__packed__)) RangeDef;

enum {PCI_SPACE = 0, NVME_SPACE = 1};

/* Initialize IO thread */
int nvme_init_io_thread(NVMEState *n);

/* Admin command processing */
uint8_t nvme_admin_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe);

/* IO command processing */
uint8_t nvme_aon_io_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe,
    uint32_t pdid);

/* All NVM cmd processing */
uint8_t nvme_command_set(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe,
    NVMEIOSQueue *sq);

/* Storage Disk */
int nvme_open_storage_disks(NVMEState *n);
int nvme_open_storage_disk(DiskInfo *disk);
int nvme_close_storage_disks(NVMEState *n);
int nvme_close_storage_disk(DiskInfo *disk);
int nvme_close_meta_disk(DiskInfo *disk);
int nvme_create_storage_disks(NVMEState *n);
int nvme_del_storage_disks(NVMEState *n);
int nvme_del_storage_disk(DiskInfo *disk);
int nvme_create_storage_disk(uint32_t instance, uint32_t nsid, DiskInfo *disk,
    NVMEState *n);
int nvme_create_meta_disk(uint32_t instance, uint32_t nsid, DiskInfo *disk);

void nvme_dma_mem_read(target_phys_addr_t addr, uint8_t *buf, int len);
void nvme_dma_mem_write(target_phys_addr_t addr, uint8_t *buf, int len);
int  process_sq(NVMEState *n, uint16_t sq_id);
void async_process_cb(void *);
void incr_cq_tail(NVMEIOCQueue *q);

uint32_t adm_check_cqid(NVMEState *n, uint16_t cqid);
uint32_t adm_check_sqid(NVMEState *n, uint16_t sqid);

/* Config file read functions */
int read_config_file(FILE *, NVMEState *, uint8_t);

/* Functions for NVME Controller space reads and writes
 * (except doorbell)
 */
uint32_t nvme_cntrl_read_config(NVMEState *,
    target_phys_addr_t, uint8_t);
void nvme_cntrl_write_config(NVMEState *,
    target_phys_addr_t, uint32_t, uint8_t);
void enqueue_async_event(NVMEState *n, uint8_t event_type, uint8_t event_info,
    uint8_t log_page);
int random_chance(int chance);
void post_cq_entry(NVMEState *n, NVMEIOCQueue *cq, NVMECQE* cqe);
uint8_t is_cq_full(NVMEState *n, uint16_t qid);

#endif /* NVME_H_ */
