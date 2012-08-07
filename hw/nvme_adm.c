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


#include <sys/mman.h>
#include "nvme.h"
#include "nvme_debug.h"
#include <sys/mman.h>

static uint32_t adm_cmd_del_sq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_alloc_sq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_del_cq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_alloc_cq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_get_log_page(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_identify(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_abort(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_set_features(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_get_features(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_async_ev_req(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_act_fw(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_dl_fw(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);
static uint32_t adm_cmd_format_nvm(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);

typedef uint32_t adm_command_func(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe);

static adm_command_func * const adm_cmds_funcs[] = {
    [NVME_ADM_CMD_DELETE_SQ] = adm_cmd_del_sq,
    [NVME_ADM_CMD_CREATE_SQ] = adm_cmd_alloc_sq,
    [NVME_ADM_CMD_GET_LOG_PAGE] = adm_cmd_get_log_page,
    [NVME_ADM_CMD_DELETE_CQ] = adm_cmd_del_cq,
    [NVME_ADM_CMD_CREATE_CQ] = adm_cmd_alloc_cq,
    [NVME_ADM_CMD_IDENTIFY] = adm_cmd_identify,
    [NVME_ADM_CMD_ABORT] = adm_cmd_abort,
    [NVME_ADM_CMD_SET_FEATURES] = adm_cmd_set_features,
    [NVME_ADM_CMD_GET_FEATURES] = adm_cmd_get_features,
    [NVME_ADM_CMD_ASYNC_EV_REQ] = adm_cmd_async_ev_req,
    [NVME_ADM_CMD_ACTIVATE_FW] = adm_cmd_act_fw,
    [NVME_ADM_CMD_DOWNLOAD_FW] = adm_cmd_dl_fw,
    [NVME_ADM_CMD_FORMAT_NVM] = adm_cmd_format_nvm,
    [NVME_ADM_CMD_LAST] = NULL,
};

uint8_t nvme_admin_command(NVMEState *n, NVMECmd *sqe, NVMECQE *cqe)
{
    uint8_t ret = NVME_SC_DATA_XFER_ERROR;

    NVMEStatusField *sf = (NVMEStatusField *) &cqe->status;
    adm_command_func *f;

    if ((sqe->opcode >= NVME_ADM_CMD_LAST) ||
        (!adm_cmds_funcs[sqe->opcode])) {
        sf->sc = NVME_SC_INVALID_OPCODE;
    } else {
        f = adm_cmds_funcs[sqe->opcode];
        ret = f(n, sqe, cqe);
    }
    return ret;
}

uint32_t adm_check_cqid(NVMEState *n, uint16_t cqid)
{
    /* If queue is allocated dma_addr!=NULL and has the same ID */
    if (cqid > NVME_MAX_QID) {
        return FAIL;
    } else if (n->cq[cqid].dma_addr && n->cq[cqid].id == cqid) {
        return 0;
    } else {
      return FAIL;
    }
}

uint32_t adm_check_sqid(NVMEState *n, uint16_t sqid)
{
    /* If queue is allocated dma_addr!=NULL and has the same ID */
    if (sqid > NVME_MAX_QID) {
        return FAIL;
    } else if (n->sq[sqid].dma_addr && n->sq[sqid].id == sqid) {
        return 0;
    } else {
        return FAIL;
    }
}

static uint16_t adm_get_sq(NVMEState *n, uint16_t sqid)
{
    if (sqid > NVME_MAX_QID) {
        return USHRT_MAX;
    } else if (n->sq[sqid].dma_addr && n->sq[sqid].id == sqid) {
        return sqid;
    } else {
        return USHRT_MAX;
    }
}

static uint16_t adm_get_cq(NVMEState *n, uint16_t cqid)
{
    if (cqid > NVME_MAX_QID) {
        return USHRT_MAX;
    } else if (n->cq[cqid].dma_addr && n->cq[cqid].id == cqid) {
        return cqid;
    } else {
        return USHRT_MAX;
    }

}

/* FIXME: For now allow only empty queue. */
static uint32_t adm_cmd_del_sq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    /* If something is in the queue then abort all pending messages.
     * TBD: What if there is no space in cq? */
    NVMEAdmCmdDeleteSQ *c = (NVMEAdmCmdDeleteSQ *)cmd;
    NVMEIOCQueue *cq;
    NVMEIOSQueue *sq;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint16_t i;
    sf->sc = NVME_SC_SUCCESS;

    LOG_NORM("%s(): called with QID:%d", __func__, c->qid);

    if (!n) {
        return FAIL;
    }
    /* Log's done to do unit testing */
    LOG_DBG("Delete SQ command for SQID: %u", c->qid);

    if (cmd->opcode != NVME_ADM_CMD_DELETE_SQ) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (c->qid == 0 || c->qid > NVME_MAX_QID) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        return FAIL;
    } else if (c->nsid != 0) {
        LOG_NORM("%s():Invalid namespace:%d", __func__, c->nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }

    i = adm_get_sq(n, c->qid);
    if (i == USHRT_MAX) {
        LOG_NORM("No such queue: SQ %d", c->qid);
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        return FAIL;
    }
    sq = &n->sq[i];
    if (sq->tail != sq->head) {
        /* Queue not empty */
    }

    if (sq->cq_id <= NVME_MAX_QID) {
        cq = &n->cq[sq->cq_id];
        if (cq->id > NVME_MAX_QID) {
            /* error */
            sf->sct = NVME_SCT_CMD_SPEC_ERR;
            sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
            return FAIL;
        }

        if (!cq->usage_cnt) {
            /* error FIXME */
        }

        cq->usage_cnt--;
    }

    sq->id = sq->cq_id = USHRT_MAX;
    sq->head = sq->tail = 0;
    sq->size = 0;
    sq->prio = 0;
    sq->phys_contig = 0;
    sq->dma_addr = 0;

    return 0;
}

static uint32_t adm_cmd_alloc_sq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdCreateSQ *c = (NVMEAdmCmdCreateSQ *)cmd;
    NVMEIOSQueue *sq;
    uint16_t *mqes;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    LOG_NORM("%s(): called", __func__);

    if (!n) {
        return FAIL;
    }

    if (cmd->opcode != NVME_ADM_CMD_CREATE_SQ) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    /* Log's done to do unit testing */
    LOG_DBG("Create SQ command for QID: %u", c->qid);
    LOG_DBG("Create SQ command with Qsize: %u", c->qsize);
    LOG_DBG("Create SQ command with PC bit: %u", c->pc);
    LOG_DBG("Create SQ command with unique command ID: %u", c->cid);
    LOG_DBG("Create SQ command with PRP1: %lu", c->prp1);
    LOG_DBG("Create SQ command with PRP2: %lu", c->prp2);
    LOG_DBG("Create SQ command is assoc with CQID: %u", c->cqid);

    if (c->qid == 0 || c->qid > NVME_MAX_QID) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        LOG_NORM("%s():Invalid QID:%d in Command", __func__, c->qid);
        return FAIL;
    } else if (c->nsid != 0) {
        LOG_NORM("%s():Invalid namespace id:%d", __func__, c->nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }

    /* Check if IOSQ requested be associated with ACQ */
    if (c->cqid == 0) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_COMPLETION_QUEUE_INVALID;
        LOG_NORM("%s(): Invalid cq id: %d association.", __func__, c->cqid);
        return FAIL;
    }

    /* Invalid SQID, exists*/
    if (!adm_check_sqid(n, c->qid)) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        LOG_NORM("%s():SQID:%d in command already allocated/invalid ID",
            __func__, c->qid);
        return FAIL;
    }

    /* Corresponding CQ exists?  if not return error */
    if (adm_check_cqid(n, c->cqid)) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_COMPLETION_QUEUE_INVALID;
        LOG_NORM("%s():CQID:%d in command not allocated", __func__, c->cqid);
        return FAIL;
    }
    mqes = (uint16_t *) n->cntrl_reg;

    /* Queue Size */
    if (c->qsize > *mqes) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_MAX_QUEUE_SIZE_EXCEEDED;
        LOG_NORM("%s():MQES %u exceeded", __func__, *mqes);
        return FAIL;
    }

    if ((c->pc == 0) && (*(mqes + 0x01) & 0x01)) {
        LOG_NORM("%s(): non-contiguous queue unsupported", __func__);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    /* In PRP1 is DMA address. Chapter 5.4, Figure 36 */
    if (c->prp1 == 0) {
        LOG_NORM("%s():PRP1 field is NULL", __func__);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    sq = &n->sq[c->qid];
    sq->id = c->qid;
    sq->size = c->qsize + 1;
    sq->phys_contig = c->pc;
    sq->cq_id = c->cqid;
    sq->prio = c->qprio;
    sq->dma_addr = c->prp1;

    QTAILQ_INIT(&sq->cmd_list);

    LOG_DBG("sq->id %d, sq->dma_addr 0x%x, %lu",
        sq->id, (unsigned int)sq->dma_addr,
        (unsigned long int)sq->dma_addr);

    /* Mark CQ as used by this queue. */
    n->cq[adm_get_cq(n, c->cqid)].usage_cnt++;

    return 0;
}

static uint32_t adm_cmd_del_cq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdDeleteCQ *c = (NVMEAdmCmdDeleteCQ *)cmd;
    NVMEIOCQueue *cq;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint16_t i;
    sf->sc = NVME_SC_SUCCESS;

    LOG_NORM("%s(): called", __func__);

    if (!n) {
        return FAIL;
    }

    /* Log's done to do unit testing */
    LOG_DBG("Delete CQ command for CQID:%u", c->qid);

    if (cmd->opcode != NVME_ADM_CMD_DELETE_CQ) {
        LOG_NORM("%s(): Invalid opcode %d\n", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (c->qid == 0 || c->qid > NVME_MAX_QID) {
        LOG_NORM("%s():Invalid Queue ID %d", __func__, c->qid);
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        return FAIL;
    } else if (c->nsid != 0) {
        LOG_NORM("%s():Invalid namespace:%d", __func__, c->nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }


    i = adm_get_cq(n, c->qid);
    if (i == USHRT_MAX) {
        LOG_NORM("No such queue: CQ %d", c->qid);
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        return FAIL;
    }
    cq = &n->cq[i];

    if (cq->tail != cq->head) {
        /* Queue not empty */
        /* error */
    }

    /* Do not allow to delete CQ when some SQ is pointing on it. */
    if (cq->usage_cnt) {
        LOG_ERR("Error. Some sq are still connected to CQ %d", c->qid);
        sf->sc = NVME_SC_INVALID_FIELD;
        return NVME_SC_INVALID_FIELD;
    }

    cq->id = USHRT_MAX;
    cq->head = cq->tail = 0;
    cq->size = 0;
    cq->irq_enabled = 0;
    cq->vector = 0;
    cq->dma_addr = 0;
    cq->phys_contig = 0;

    return 0;
}

static uint32_t adm_cmd_alloc_cq(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdCreateCQ *c = (NVMEAdmCmdCreateCQ *)cmd;
    NVMEIOCQueue *cq;
    uint16_t *mqes;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    LOG_NORM("%s(): called", __func__);

    if (!n) {
        return FAIL;
    }
    /* Log's done to do unit testing */
    LOG_DBG("Create CQ command for QID: %u", c->qid);
    LOG_DBG("Create CQ command with Qsize: %u", c->qsize);
    LOG_DBG("Create CQ command with PC bit: %u", c->pc);
    LOG_DBG("Create CQ command with unique command ID: %u", c->cid);
    LOG_DBG("Create CQ command with PRP1: %lu", c->prp1);
    LOG_DBG("Create CQ command with PRP2: %lu", c->prp2);

    if (cmd->opcode != NVME_ADM_CMD_CREATE_CQ) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (c->qid == 0 || c->qid > NVME_MAX_QID) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        LOG_NORM("%s(): invalid qid:%d in Command", __func__, c->qid);
        return FAIL;
    } else if (c->nsid != 0) {
        LOG_NORM("%s():Invalid namespace:%d", __func__, c->nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }

    /* check if CQ exists., If yes return error */
    if (!adm_check_cqid(n, c->qid)) {
        LOG_NORM("%s():Invalid CQ ID %d\n", __func__, c->qid);
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_QUEUE_IDENTIFIER;
        return FAIL;
    }

    mqes = (uint16_t *) n->cntrl_reg;

    /* Queue Size */
    if (c->qsize > *mqes) {
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_MAX_QUEUE_SIZE_EXCEEDED;
        LOG_NORM("%s():MQES %u exceeded", __func__, *mqes);
        return FAIL;
    }

    if ((c->pc == 0) && (*(mqes + 0x01) & 0x01)) {
        LOG_ERR("CAP.CQR set to 1");
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }
    /* In PRP1 is DMA address. */
    if (c->prp1 == 0) {
        LOG_NORM("%s():PRP1 address is NULL", __func__);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    if (c->iv > n->dev.msix_entries_nr - 1 && IS_MSIX(n)) {
        /* TODO : checks for MSI too */
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_INTERRUPT_VECTOR;
        return FAIL;
    }

    cq = &n->cq[c->qid];

    cq->id = c->qid;
    cq->dma_addr = c->prp1;
    cq->irq_enabled = c->ien;
    cq->vector = c->iv;
    cq->phase_tag = 1;

    LOG_DBG("kw q: cq[%d] phase_tag   %d", cq->id, cq->phase_tag);
    LOG_DBG("kw q: msix vector. cq[%d] vector %d irq_enabled %d",
                     cq->id, cq->vector, cq->irq_enabled);
    cq->size = c->qsize + 1;
    cq->phys_contig = c->pc;

    return 0;
}

static uint32_t adm_cmd_fw_log_info(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEFwSlotInfoLog *firmware_info = &(n->fw_slot_log);
    uint32_t len;

    LOG_NORM("%s called", __func__);

    if (((cmd->cdw10 >> 16) & 0xfff) * 4 < sizeof(*firmware_info)) {
        LOG_NORM("%s: not enough memory, needs %ld, has %d bytes.", __func__,
                sizeof(*firmware_info), ((cmd->cdw10 >> 16) & 0xfff) * 4);
        NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
        sf->sc = NVME_SC_INVALID_FIELD;
        return 0;
    }

    len = min(PAGE_SIZE - (cmd->prp1 % PAGE_SIZE), sizeof(*firmware_info));
    nvme_dma_mem_write(cmd->prp1, (uint8_t *)firmware_info, len);
    if (len < sizeof(*firmware_info)) {
        nvme_dma_mem_write(cmd->prp2,
            (uint8_t *)((uint8_t *)firmware_info + len),
            sizeof(*firmware_info) - len);
    }
    return 0;
}

static uint32_t adm_cmd_smart_info(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    uint32_t len;
    time_t current_seconds;
    NVMESmartLog smart_log;

    LOG_DBG("%s(): called", __func__);

    if (((cmd->cdw10 >> 16) & 0xfff) * 4 < sizeof(smart_log)) {
        LOG_ERR("%s: not enough memory, needs %ld, has %d bytes.", __func__,
                sizeof(smart_log), ((cmd->cdw10 >> 16) & 0xfff) * 4);
        NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    memset(&smart_log, 0x0, sizeof(smart_log));
    LOG_NORM("%s called", __func__);
    if (cmd->nsid == 0xffffffff || !(n->idtfy_ctrl->lpa & 0x1)) {
        /* return info for entire device */
        int i;
        uint64_t dur[2] = {0, 0};
        uint64_t duw[2] = {0, 0};
        uint64_t hrc[2] = {0, 0};
        uint64_t hwc[2] = {0, 0};
        uint64_t total_use = 0;
        uint64_t total_size = 0;
        for (i = 0; i < n->num_namespaces; ++i) {
            uint64_t tmp;
            DiskInfo *disk = &n->disk[i];

            tmp = dur[0];
            dur[0] += disk->data_units_read[0];
            dur[1] += disk->data_units_read[1];
            if (tmp > dur[0]) {
                ++dur[1];
            }

            tmp = duw[0];
            duw[0] += disk->data_units_written[0];
            duw[1] += disk->data_units_written[1];
            if (tmp > duw[0]) {
                ++duw[1];
            }

            tmp = hrc[0];
            hrc[0] += disk->host_read_commands[0];
            hrc[1] += disk->host_read_commands[1];
            if (tmp > hrc[0]) {
                ++hrc[1];
            }

            tmp = hwc[0];
            hwc[0] += disk->host_write_commands[0];
            hwc[1] += disk->host_write_commands[1];
            if (tmp > hwc[0]) {
                ++hwc[1];
            }

            total_size += disk->idtfy_ns.nsze;
            total_use += disk->idtfy_ns.nuse;
        }

        smart_log.data_units_read[0] = dur[0];
        smart_log.data_units_read[1] = dur[1];
        smart_log.data_units_written[0] = duw[0];
        smart_log.data_units_written[1] = duw[1];
        smart_log.host_read_commands[0] = hrc[0];
        smart_log.host_read_commands[1] = hrc[1];
        smart_log.host_write_commands[0] = hwc[0];
        smart_log.host_write_commands[1] = hwc[1];
        smart_log.available_spare = 100 - (uint32_t)((((double)total_use) /
            total_size) * 100);
    } else if (cmd->nsid > 0 && cmd->nsid <= n->num_namespaces &&
        (n->idtfy_ctrl->lpa & 0x1)) {
        LOG_NORM("getting smart log info for instance:%d nsid:%d",
            n->instance, cmd->nsid);
        DiskInfo *disk = &n->disk[cmd->nsid - 1];
        smart_log.data_units_read[0] = disk->data_units_read[0];
        smart_log.data_units_read[1] = disk->data_units_read[1];
        smart_log.data_units_written[0] = disk->data_units_written[0];
        smart_log.data_units_written[1] = disk->data_units_written[1];
        smart_log.host_read_commands[0] = disk->host_read_commands[0];
        smart_log.host_read_commands[1] = disk->host_read_commands[1];
        smart_log.host_write_commands[0] = disk->host_write_commands[0];
        smart_log.host_write_commands[1] = disk->host_write_commands[1];
        smart_log.available_spare = 100 - (uint32_t)
            ((((double)disk->idtfy_ns.nuse) / disk->idtfy_ns.nsze) * 100);
    } else {
        NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }

    /* just make up a temperature. 0x143 Kelvin is 50 degrees C. */
    smart_log.temperature[0] = NVME_TEMPERATURE & 0xff;
    smart_log.temperature[1] = (NVME_TEMPERATURE >> 8) & 0xff;

    current_seconds = time(NULL);
    smart_log.power_on_hours[0] = ((current_seconds - n->start_time) / 60) / 60;

    smart_log.available_spare_threshold = NVME_SPARE_THRESH;
    if (smart_log.available_spare <= NVME_SPARE_THRESH) {
        smart_log.critical_warning |= 1 << 0;
    }
    if (n->feature.temperature_threshold <= NVME_TEMPERATURE) {
        smart_log.critical_warning |= 1 << 1;
    }

    len = min(PAGE_SIZE - (cmd->prp1 % PAGE_SIZE), sizeof(smart_log));
    nvme_dma_mem_write(cmd->prp1, (uint8_t *)&smart_log, len);
    if (len < sizeof(smart_log)) {
        nvme_dma_mem_write(cmd->prp2,
            (uint8_t *)((uint8_t *)&smart_log + len),
            sizeof(smart_log) - len);
    }
    return 0;
}

static uint32_t adm_cmd_get_log_page(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdGetLogPage *c = (NVMEAdmCmdGetLogPage *)cmd;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    if (cmd->opcode != NVME_ADM_CMD_GET_LOG_PAGE) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    LOG_NORM("%s(): called", __func__);

    switch (c->lid) {
    case NVME_LOG_ERROR_INFORMATION:
        break;
    case NVME_LOG_SMART_INFORMATION:
        return adm_cmd_smart_info(n, cmd, cqe);
        break;
    case NVME_LOG_FW_SLOT_INFORMATION:
        return adm_cmd_fw_log_info(n, cmd, cqe);
        break;
    default:
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_INVALID_LOG_PAGE;
        break;
    }
    return 0;
}

static uint32_t adm_cmd_id_ctrl(NVMEState *n, NVMECmd *cmd)
{
    uint32_t len;
    LOG_NORM("%s(): copying %lu data into addr %lu",
        __func__, sizeof(*n->idtfy_ctrl), cmd->prp1);

    len = PAGE_SIZE - (cmd->prp1 % PAGE_SIZE);
    nvme_dma_mem_write(cmd->prp1, (uint8_t *) n->idtfy_ctrl, len);
    if (len != sizeof(*(n->idtfy_ctrl))) {
        nvme_dma_mem_write(cmd->prp2,
            (uint8_t *) ((uint8_t *) n->idtfy_ctrl + len),
                (sizeof(*(n->idtfy_ctrl)) - len));
    }
    return 0;
}

/* Needs to be checked if this namespace exists. */
static uint32_t adm_cmd_id_ns(NVMEState *n, NVMECmd *cmd)
{
    uint32_t len;
    LOG_NORM("%s(): called", __func__);

    LOG_DBG("Current Namespace utilization: %lu",
        n->disk[(cmd->nsid - 1)].idtfy_ns.nuse);

    len = PAGE_SIZE - (cmd->prp1 % PAGE_SIZE);
    nvme_dma_mem_write(cmd->prp1,
        (uint8_t *) &n->disk[(cmd->nsid - 1)].idtfy_ns, len);
    if (len != sizeof(n->disk[(cmd->nsid - 1)].idtfy_ns)) {
        nvme_dma_mem_write(cmd->prp2,
            (uint8_t *) ((uint8_t *)&n->disk[(cmd->nsid - 1)].idtfy_ns + len),
                (sizeof(n->disk[(cmd->nsid - 1)].idtfy_ns)) - len);
    }
    return 0;
}

static uint32_t adm_cmd_identify(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdIdentify *c = (NVMEAdmCmdIdentify *)cmd;
    uint8_t ret;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    LOG_NORM("%s(): called", __func__);

    if (cmd->opcode != NVME_ADM_CMD_IDENTIFY) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (c->prp1 == 0) {
        LOG_NORM("%s(): prp1 absent", __func__);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    /* Construct some data and copy it to the addr.*/
    if (c->cns == NVME_IDENTIFY_CONTROLLER) {
        if (c->nsid != 0) {
            LOG_NORM("%s(): Invalid namespace id:%d for id controller",
                __func__, c->nsid);
            sf->sc = NVME_SC_INVALID_NAMESPACE;
            return FAIL;
        }
        ret = adm_cmd_id_ctrl(n, cmd);
    } else {
        /* Check for name space */
        if (c->nsid == 0 || (c->nsid > n->idtfy_ctrl->nn)) {
            LOG_NORM("%s(): Invalid Namespace ID", __func__);
            sf->sc = NVME_SC_INVALID_NAMESPACE;
            return FAIL;
        }
        ret = adm_cmd_id_ns(n, cmd);
    }
    if (ret) {
        sf->sc = NVME_SC_INTERNAL;
    }
    return 0;
}


/* 5.1 Abort command
 * The Abort command is used to cancel/abort a specific I/O command previously
 * issued to the Admin or an I/O Submission Queue.Host software may have
 * multiple Abort commands outstanding, subject to the constraints of the
 * Abort Command Limit indicated in the Identify Controller data structure.
 * An abort is a best effort command; the command to abort may have already
 * completed, currently be in execution, or may be deeply queued.
 * It is implementation specific if/when a controller chooses to complete
 * the command with an error (i.e., Requested Command to Abort Not Found)
 * when the command to abort is not found.
*/
static uint32_t adm_cmd_abort(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdAbort *c = (NVMEAdmCmdAbort *)cmd;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    NVMEIOSQueue *sq;

    sf->sc = NVME_SC_SUCCESS;
    CommandEntry *ce;

    if (cmd->opcode != NVME_ADM_CMD_ABORT) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }
    if (c->nsid != 0) {
        LOG_NORM("%s():Invalid namespace id:%d", __func__, c->nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }
    if (c->sqid == 0 || adm_check_sqid(n, c->sqid)) {
        LOG_NORM("Invalid queue:%d to abort", c->sqid);
        sf->sct = NVME_SCT_CMD_SPEC_ERR;
        sf->sc = NVME_REQ_CMD_TO_ABORT_NOT_FOUND;
        return FAIL;
    }
    LOG_NORM("%s(): called", __func__);

    sq = &n->sq[c->sqid];
    QTAILQ_FOREACH(ce, &sq->cmd_list, entry) {
        if (ce->cid == c->cmdid) {
            uint16_t aborted_cq_id;
            NVMECQE acqe;
            NVMEIOCQueue *cq;
            NVMEStatusField *aborted_sf = (NVMEStatusField *) &acqe.status;

            aborted_cq_id = sq->cq_id;
            if (adm_check_cqid(n, aborted_cq_id)) {
                LOG_ERR("Abort, submission queue:%d has invalid cq:%d", sq->id,
                    aborted_cq_id);
                sf->sct = NVME_SCT_CMD_SPEC_ERR;
                sf->sc = NVME_REQ_CMD_TO_ABORT_NOT_FOUND;
                return FAIL;
            }
            cq = &n->cq[aborted_cq_id];

            memset(&acqe, 0, sizeof(acqe));
            aborted_sf->p = cq->phase_tag;
            aborted_sf->sc = NVME_SC_ABORT_REQ;

            acqe.sq_id = c->sqid;
            acqe.sq_head = sq->head;
            acqe.command_id = c->cmdid;

            post_cq_entry(n, cq, &acqe);

            QTAILQ_REMOVE(&sq->cmd_list, ce, entry);
            qemu_free(ce);

            LOG_NORM("Abort cmdid:%d on sq:%d success", c->cmdid, sq->id);

            return 0;
        }
    }
    LOG_NORM("Abort failed, could not find corresponding cmdid:%d on sq:%d",
        c->cmdid, sq->id);
    return FAIL;
}

static uint32_t do_features(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEAdmCmdFeatures *sqe = (NVMEAdmCmdFeatures *)cmd;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    switch (sqe->fid) {
    case NVME_FEATURE_ARBITRATION:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.arbitration = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.arbitration;
        }
        break;

    case NVME_FEATURE_POWER_MANAGEMENT:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.power_management = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.power_management;
        }
        break;

    case NVME_FEATURE_LBA_RANGE_TYPE:
        LOG_NORM("NVME_FEATURE_LBA_RANGE_TYPE not supported yet");
        break;

    case NVME_FEATURE_TEMPERATURE_THRESHOLD:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.temperature_threshold = sqe->cdw11;
            if (n->feature.temperature_threshold <= NVME_TEMPERATURE &&
                    !n->temp_warn_issued) {
                LOG_NORM("Device:%d setting temp threshold feature to:%d",
                    n->instance, n->feature.temperature_threshold);
                n->temp_warn_issued = 1;
                enqueue_async_event(n, event_type_smart,
                    event_info_smart_temp_thresh, NVME_LOG_SMART_INFORMATION);
            }
        } else {
            cqe->cmd_specific = n->feature.temperature_threshold;
        }
        break;

    case NVME_FEATURE_ERROR_RECOVERY:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.error_recovery = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.error_recovery;
        }
        break;

    case NVME_FEATURE_VOLATILE_WRITE_CACHE:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.volatile_write_cache = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.volatile_write_cache;
        }
        break;

    case NVME_FEATURE_NUMBER_OF_QUEUES:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            uint16_t cqs = sqe->cdw11 >> 16;
            uint16_t sqs = sqe->cdw11 & 0xffff;
            if (cqs > NVME_MAX_QID) {
                cqs = NVME_MAX_QID;
            }
            if (sqs > NVME_MAX_QID) {
                sqs = NVME_MAX_QID;
            }
            n->feature.number_of_queues = (((uint32_t)cqs) << 16) | sqs;
            cqe->cmd_specific = n->feature.number_of_queues;
        } else {
            cqe->cmd_specific = n->feature.number_of_queues;
        }
        break;

    case NVME_FEATURE_INTERRUPT_COALESCING:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.interrupt_coalescing = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.interrupt_coalescing;
        }
        break;

    case NVME_FEATURE_INTERRUPT_VECTOR_CONF:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.interrupt_vector_configuration = sqe->cdw11;
        } else {
            cqe->cmd_specific =
                n->feature.interrupt_vector_configuration;
        }
        break;

    case NVME_FEATURE_WRITE_ATOMICITY:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.write_atomicity = sqe->cdw11;
        } else {
            cqe->cmd_specific = n->feature.write_atomicity;
        }
        break;

    case NVME_FEATURE_ASYNCHRONOUS_EVENT_CONF:
        if (sqe->opcode == NVME_ADM_CMD_SET_FEATURES) {
            n->feature.asynchronous_event_configuration = sqe->cdw11;
        } else {
            cqe->cmd_specific =
                n->feature.asynchronous_event_configuration;
        }
        break;

    case NVME_FEATURE_SOFTWARE_PROGRESS_MARKER: /* Set Features only*/
        if (sqe->opcode == NVME_ADM_CMD_GET_FEATURES) {
            cqe->cmd_specific =
                n->feature.software_progress_marker;
        }
        break;

    default:
        LOG_NORM("Unknown feature ID: %d", sqe->fid);
        sf->sc = NVME_SC_INVALID_FIELD;
        break;
    }

    return 0;
}

static uint32_t adm_cmd_set_features(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint32_t res;

    if (cmd->opcode != NVME_ADM_CMD_SET_FEATURES) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    res = do_features(n, cmd, cqe);

    LOG_NORM("%s(): called", __func__);
    return res;
}

static uint32_t adm_cmd_get_features(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint32_t res;

    if (cmd->opcode != NVME_ADM_CMD_GET_FEATURES) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    res = do_features(n, cmd, cqe);

    LOG_NORM("%s(): called", __func__);
    return res;
}

static uint64_t DJBHash(uint8_t* str, uint32_t len)
{
    uint64_t hash = 5381;
    uint64_t i    = 0;

    for(i = 0; i < len; str++, i++) {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

static uint32_t adm_cmd_act_fw(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    int fd;
    unsigned sz_fw_buf;
    struct stat sb;
    char fw_file_name[] = "nvme_firmware_disk.img";
    uint8_t *fw_buf;
    char fw_hash[9];
    uint8_t *target_frs;

    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint32_t res = 0;

    LOG_NORM("%s(): called", __func__);

    if (cmd->opcode != NVME_ADM_CMD_ACTIVATE_FW) {
        LOG_NORM("%s(): Invalid opcode %x", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if ((cmd->cdw10 & 0x7) > 7) {
        LOG_NORM("%s(): Invalid Firmware Slot %d", __func__, cmd->cdw10 & 0x7);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    fd = open(fw_file_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        LOG_ERR("Error while creating the storage");
        return FAIL;
    }
    if (stat(fw_file_name, &sb) != 0) {
        LOG_ERR("%s(): 'stat' failed for '%s'", __func__, fw_file_name);
        res = FAIL;
        goto close;
    }
    sz_fw_buf = sb.st_size;

    fw_buf = mmap(NULL, sz_fw_buf, PROT_READ, MAP_SHARED, fd, 0);
    if (fw_buf == MAP_FAILED) {
        LOG_ERR("Error mapping FW disk backing file");
        res = FAIL;
        goto close;
    }

    snprintf(fw_hash, 9, "%lx", DJBHash(fw_buf, sz_fw_buf));

    if ((cmd->cdw10 & 0x7) > 0)
        n->fw_slot_log.afi = cmd->cdw10 & 0x7;
    else {
        uint8_t i;
        uint64_t *accessor = (uint64_t *)&(n->fw_slot_log);

        for (i = 1; i <= 7; i++) {
            if(*(accessor + i) == 0) {
                n->fw_slot_log.afi = i;
                break;
            }
        }
        if (i == 8)
            n->fw_slot_log.afi = ((n->last_fw_slot + 1) > 7) ? 1 :
                                  (n->last_fw_slot + 1);
    }
    target_frs = (uint8_t *)&(n->fw_slot_log) + (n->fw_slot_log.afi * 8);

    memcpy ((char *)target_frs, fw_hash, 8);
    memcpy ((char *)n->idtfy_ctrl->fr, fw_hash, 8);
    n->last_fw_slot = n->fw_slot_log.afi;

    munmap(fw_buf, sz_fw_buf);
    if(ftruncate(fd, 0) < 0)
        LOG_ERR("Error truncating backing firmware file");

 close:
    close(fd);
    return res;
}

static uint8_t do_dlfw_prp(NVMEState *n, uint64_t mem_addr,
    uint64_t *data_size_p, uint64_t *buf_offset, uint8_t *buf)
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

    LOG_DBG("Length of FW Img:%ld", data_len);
    LOG_DBG("Address for FW Img:%ld", mem_addr);
    nvme_dma_mem_read(mem_addr, (buf + *buf_offset), data_len);

    *buf_offset = *buf_offset + data_len;
    *data_size_p = *data_size_p - data_len;
    return NVME_SC_SUCCESS;
}

static uint8_t do_dlfw_prp_list(NVMEState *n, NVMECmd *cmd,
    uint64_t *data_size_p, uint64_t *buf_offset, uint8_t *buf)
{
    uint64_t prp_list[512], prp_entries;
    uint16_t i;
    uint8_t res = NVME_SC_SUCCESS;

    LOG_DBG("Data Size remaining for FW Image:%ld", *data_size_p);

    /* Logic to find the number of PRP Entries */
    prp_entries = (uint64_t) ((*data_size_p + PAGE_SIZE - 1) / PAGE_SIZE);
    nvme_dma_mem_read(cmd->prp2, (uint8_t *)prp_list,
        min(sizeof(prp_list), prp_entries * sizeof(uint64_t)));

    i = 0;
    /* Read/Write on PRPList */
    while (*data_size_p != 0) {
        if (i == 511 && *data_size_p > PAGE_SIZE) {
            /* Calculate the actual number of remaining entries */
            prp_entries = (uint64_t) ((*data_size_p + PAGE_SIZE - 1) /
                PAGE_SIZE);
            nvme_dma_mem_read(prp_list[511], (uint8_t *)prp_list,
                min(sizeof(prp_list), prp_entries * sizeof(uint64_t)));
            i = 0;
        }

        res = do_dlfw_prp(n, prp_list[i], data_size_p, buf_offset, buf);
        LOG_DBG("Data Size remaining for read/write:%ld", *data_size_p);
        if (res == FAIL) {
            break;
        }
        i++;
    }
    return res;
}

static uint32_t fw_get_img(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe,
                                     uint8_t *buf, uint32_t sz_fw_buf)
{
    uint32_t res = 0;
    uint64_t data_size = sz_fw_buf;
    uint64_t buf_offset = 0;
    int fd;
    uint64_t offset = 0;
    uint64_t bytes_written = 0;

    fd = open("nvme_firmware_disk.img", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        LOG_ERR("Error while creating the storage");
        return FAIL;
    }

    /* Reading PRP1 and PRP2 */
    res = do_dlfw_prp(n, cmd->prp1, &data_size, &buf_offset, buf);
    if (res == FAIL) {
        return FAIL;
    }
    if (data_size > 0) {
        if (data_size <= PAGE_SIZE) {
            res = do_dlfw_prp(n, cmd->prp2, &data_size, &buf_offset, buf);
        } else {
            res = do_dlfw_prp_list(n, cmd, &data_size, &buf_offset, buf);
        }
        if (res == FAIL) {
            return FAIL;
        }
    }

    /* Writing to Firmware image file */
    offset = cmd->cdw11 * 4;
    if (lseek(fd, (off_t)offset, SEEK_SET) != offset) {
        LOG_ERR("Error while seeking to offset %ld", offset);
        return FAIL;
    }

    LOG_NORM("Writing buffer: size = %d, offset = %ld", sz_fw_buf, offset);
    bytes_written = write(fd, buf, sz_fw_buf);
    if (bytes_written != sz_fw_buf) {
        LOG_ERR("Error while writing: %ld written out of %d", bytes_written,
                                                                sz_fw_buf);
        return FAIL;
    }

    if (close(fd) < 0) {
        LOG_ERR("Unable to close the nvme disk");
    }

    return res;
}

static uint32_t adm_cmd_dl_fw(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    uint32_t res = 0;
    uint8_t *fw_buf;
    uint32_t sz_fw_buf = 0;

    LOG_NORM("%s(): called", __func__);

    if (cmd->opcode != NVME_ADM_CMD_DOWNLOAD_FW) {
        LOG_NORM("%s(): Invalid opcode %x", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (cmd->prp1 == 0) {
        LOG_NORM("%s(): prp1 absent", __func__);
        sf->sc = NVME_SC_INVALID_FIELD;
        return FAIL;
    }

    sz_fw_buf = (cmd->cdw10 + 1) * sizeof(uint8_t) * 4;
    fw_buf = (uint8_t *) qemu_mallocz(sz_fw_buf);
    if (fw_buf == NULL) {
        return FAIL;
    }
    LOG_DBG("sz_fw_buf = %d", sz_fw_buf);
    res = fw_get_img(n, cmd, cqe, fw_buf, sz_fw_buf);

    qemu_free(fw_buf);

    return res;
}

void async_process_cb(void *param)
{
    NVMECQE cqe;
    NVMEStatusField *sf = (NVMEStatusField *)&cqe.status;
    NVMEState *n = (NVMEState *)param;
    target_phys_addr_t addr;
    AsyncResult *result;
    AsyncEvent *event;

    if (n->outstanding_asyncs <= 0) {
        LOG_NORM("%s(): called without an outstanding async event", __func__);
        return;
    }
    if (QSIMPLEQ_EMPTY(&n->async_queue)) {
        LOG_NORM("%s(): called with no outstanding events to report", __func__);
        return;
    }

    LOG_NORM("%s(): called outstanding asyncs:%d", __func__,
        n->outstanding_asyncs);

    while ((event = QSIMPLEQ_FIRST(&n->async_queue)) != NULL &&
            n->outstanding_asyncs > 0) {
        QSIMPLEQ_REMOVE_HEAD(&n->async_queue, entry);

        result = (AsyncResult *)&cqe.cmd_specific;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page   = event->result.log_page;

        qemu_free(event);

        n->outstanding_asyncs--;

        cqe.sq_id = 0;
        cqe.sq_head = n->sq[0].head;
        cqe.command_id = n->async_cid[n->outstanding_asyncs];

        sf->sc = NVME_SC_SUCCESS;
        sf->p = n->cq[0].phase_tag;
        sf->m = 0;
        sf->dnr = 0;

        addr = n->cq[0].dma_addr + n->cq[0].tail * sizeof(cqe);
        nvme_dma_mem_write(addr, (uint8_t *)&cqe, sizeof(cqe));
        incr_cq_tail(&n->cq[0]);
    }
    msix_notify(&(n->dev), 0);
}

static uint32_t adm_cmd_async_ev_req(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    sf->sc = NVME_SC_SUCCESS;

    if (cmd->opcode != NVME_ADM_CMD_ASYNC_EV_REQ) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    if (n->outstanding_asyncs > n->idtfy_ctrl->aerl) {
        LOG_NORM("%s(): too many asyncs %d %d", __func__, n->outstanding_asyncs,
            n->idtfy_ctrl->aerl);
        sf->sc = NVME_ASYNC_EVENT_LIMIT_EXCEEDED;
        return FAIL;
    }

    LOG_NORM("%s(): called", __func__);

    n->async_cid[n->outstanding_asyncs] = cmd->cid;
    qemu_mod_timer(n->async_event_timer, qemu_get_clock_ns(vm_clock) + 10000);
    n->outstanding_asyncs++;

    return 0;
}

static uint32_t adm_cmd_format_nvm(NVMEState *n, NVMECmd *cmd, NVMECQE *cqe)
{
    NVMEStatusField *sf = (NVMEStatusField *)&cqe->status;
    DiskInfo *disk;
    uint64_t old_size;
    uint32_t dw10 = cmd->cdw10;
    uint32_t nsid, block_size;
    uint8_t pil = (dw10 >> 5) & 0x8;
    uint8_t pi = (dw10 >> 5) & 0x7;
    uint8_t meta_loc = dw10 & 0x10;
    uint8_t lba_idx = dw10 & 0xf;

    sf->sc = NVME_SC_SUCCESS;
    if (cmd->opcode != NVME_ADM_CMD_FORMAT_NVM) {
        LOG_NORM("%s(): Invalid opcode %d", __func__, cmd->opcode);
        sf->sc = NVME_SC_INVALID_OPCODE;
        return FAIL;
    }

    nsid = cmd->nsid;
    if (nsid > n->num_namespaces || nsid == 0) {
        LOG_NORM("%s(): bad nsid:%d", __func__, nsid);
        sf->sc = NVME_SC_INVALID_NAMESPACE;
        return FAIL;
    }

    disk = &n->disk[nsid - 1];
    if ((lba_idx) > disk->idtfy_ns.nlbaf) {
        LOG_NORM("%s(): Invalid format %x, lbaf out of range", __func__, dw10);
        sf->sc = NVME_INVALID_FORMAT;
        return FAIL;
    }
    if (pi) {
        if (pil && !(disk->idtfy_ns.dpc & 0x10)) {
            LOG_NORM("%s(): pi requested as last 8 bytes, dpc:%x",
                __func__, disk->idtfy_ns.dpc);
            sf->sc = NVME_INVALID_FORMAT;
            return FAIL;
        }
        if (!pil && !(disk->idtfy_ns.dpc & 0x8)) {
            LOG_NORM("%s(): pi requested as first 8 bytes, dpc:%x",
                __func__, disk->idtfy_ns.dpc);
            sf->sc = NVME_INVALID_FORMAT;
            return FAIL;
        }
        if (!((disk->idtfy_ns.dpc & 0x7) & (1 << (pi - 1)))) {
            LOG_NORM("%s(): Invalid pi type:%d, dpc:%x", __func__,
                pi, disk->idtfy_ns.dpc);
            sf->sc = NVME_INVALID_FORMAT;
            return FAIL;
        }
    }
    if (meta_loc && disk->idtfy_ns.lbafx[lba_idx].ms &&
            !(disk->idtfy_ns.mc & 1)) {
        LOG_NORM("%s(): Invalid meta location:%x, mc:%x", __func__,
            meta_loc, disk->idtfy_ns.mc);
        sf->sc = NVME_INVALID_FORMAT;
        return FAIL;
    }
    if (!meta_loc && disk->idtfy_ns.lbafx[lba_idx].ms &&
            !(disk->idtfy_ns.mc & 2)) {
        LOG_NORM("%s(): Invalid meta location:%x, mc:%x", __func__,
            meta_loc, disk->idtfy_ns.mc);
        sf->sc = NVME_INVALID_FORMAT;
        return FAIL;
    }

    if (nvme_close_storage_disk(disk)) {
        return FAIL;
    }

    old_size = disk->idtfy_ns.nsze * (1 << disk->idtfy_ns.lbafx[
        disk->idtfy_ns.flbas & 0xf].lbads);
    block_size = 1 << disk->idtfy_ns.lbafx[lba_idx].lbads;

    LOG_NORM("%s(): called, previous: flbas:%x ds:%d ms:%d dps:%x"\
             "new: flbas:%x ds:%d ms:%d dpc:%x", __func__, disk->idtfy_ns.flbas,
             disk->idtfy_ns.lbafx[disk->idtfy_ns.flbas & 0xf].lbads,
             disk->idtfy_ns.lbafx[disk->idtfy_ns.flbas & 0xf].ms,
             disk->idtfy_ns.dps, lba_idx | meta_loc,
             disk->idtfy_ns.lbafx[lba_idx].lbads,
             disk->idtfy_ns.lbafx[lba_idx].ms,
             pil | pi);

    disk->idtfy_ns.nuse = 0;
    disk->idtfy_ns.flbas = lba_idx | meta_loc;
    disk->idtfy_ns.nsze = old_size / block_size;
    disk->idtfy_ns.ncap = disk->idtfy_ns.nsze;
    disk->idtfy_ns.dps = pil | pi;

    if (nvme_create_storage_disk(n->instance, nsid, disk, n)) {
        return FAIL;
    }

    return 0;
}

