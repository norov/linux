/*
 * Shared part of driver for MMC/SDHC controller on Cavium OCTEON and
 * ThunderX SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012-2016 Cavium Inc.
 * Authors:
 *   David Daney <david.daney@cavium.com>
 *   Peter Swain <pswain@cavium.com>
 *   Steven J. Hill <steven.hill@cavium.com>
 *   Jan Glauber <jglauber@cavium.com>
 */
#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/time.h>

#include "cavium_mmc.h"

/*
 * The Cavium MMC host hardware assumes that all commands have fixed
 * command and response types.  These are correct if MMC devices are
 * being used.  However, non-MMC devices like SD use command and
 * response types that are unexpected by the host hardware.
 *
 * The command and response types can be overridden by supplying an
 * XOR value that is applied to the type.  We calculate the XOR value
 * from the values in this table and the flags passed from the MMC
 * core.
 */
static struct cvm_mmc_cr_type cvm_mmc_cr_types[] = {
	{0, 0},		/* CMD0 */
	{0, 3},		/* CMD1 */
	{0, 2},		/* CMD2 */
	{0, 1},		/* CMD3 */
	{0, 0},		/* CMD4 */
	{0, 1},		/* CMD5 */
	{0, 1},		/* CMD6 */
	{0, 1},		/* CMD7 */
	{1, 1},		/* CMD8 */
	{0, 2},		/* CMD9 */
	{0, 2},		/* CMD10 */
	{1, 1},		/* CMD11 */
	{0, 1},		/* CMD12 */
	{0, 1},		/* CMD13 */
	{1, 1},		/* CMD14 */
	{0, 0},		/* CMD15 */
	{0, 1},		/* CMD16 */
	{1, 1},		/* CMD17 */
	{1, 1},		/* CMD18 */
	{3, 1},		/* CMD19 */
	{2, 1},		/* CMD20 */
	{0, 0},		/* CMD21 */
	{0, 0},		/* CMD22 */
	{0, 1},		/* CMD23 */
	{2, 1},		/* CMD24 */
	{2, 1},		/* CMD25 */
	{2, 1},		/* CMD26 */
	{2, 1},		/* CMD27 */
	{0, 1},		/* CMD28 */
	{0, 1},		/* CMD29 */
	{1, 1},		/* CMD30 */
	{1, 1},		/* CMD31 */
	{0, 0},		/* CMD32 */
	{0, 0},		/* CMD33 */
	{0, 0},		/* CMD34 */
	{0, 1},		/* CMD35 */
	{0, 1},		/* CMD36 */
	{0, 0},		/* CMD37 */
	{0, 1},		/* CMD38 */
	{0, 4},		/* CMD39 */
	{0, 5},		/* CMD40 */
	{0, 0},		/* CMD41 */
	{2, 1},		/* CMD42 */
	{0, 0},		/* CMD43 */
	{0, 0},		/* CMD44 */
	{0, 0},		/* CMD45 */
	{0, 0},		/* CMD46 */
	{0, 0},		/* CMD47 */
	{0, 0},		/* CMD48 */
	{0, 0},		/* CMD49 */
	{0, 0},		/* CMD50 */
	{0, 0},		/* CMD51 */
	{0, 0},		/* CMD52 */
	{0, 0},		/* CMD53 */
	{0, 0},		/* CMD54 */
	{0, 1},		/* CMD55 */
	{0xff, 0xff},	/* CMD56 */
	{0, 0},		/* CMD57 */
	{0, 0},		/* CMD58 */
	{0, 0},		/* CMD59 */
	{0, 0},		/* CMD60 */
	{0, 0},		/* CMD61 */
	{0, 0},		/* CMD62 */
	{0, 0}		/* CMD63 */
};

static struct cvm_mmc_cr_mods cvm_mmc_get_cr_mods(struct mmc_command *cmd)
{
	struct cvm_mmc_cr_type *cr;
	u8 hardware_ctype, hardware_rtype;
	u8 desired_ctype = 0, desired_rtype = 0;
	struct cvm_mmc_cr_mods r;

	cr = cvm_mmc_cr_types + (cmd->opcode & 0x3f);
	hardware_ctype = cr->ctype;
	hardware_rtype = cr->rtype;
	if (cmd->opcode == MMC_GEN_CMD)
		hardware_ctype = (cmd->arg & 1) ? 1 : 2;

	switch (mmc_cmd_type(cmd)) {
	case MMC_CMD_ADTC:
		desired_ctype = (cmd->data->flags & MMC_DATA_WRITE) ? 2 : 1;
		break;
	case MMC_CMD_AC:
	case MMC_CMD_BC:
	case MMC_CMD_BCR:
		desired_ctype = 0;
		break;
	}

	switch (mmc_resp_type(cmd)) {
	case MMC_RSP_NONE:
		desired_rtype = 0;
		break;
	case MMC_RSP_R1:/* MMC_RSP_R5, MMC_RSP_R6, MMC_RSP_R7 */
	case MMC_RSP_R1B:
		desired_rtype = 1;
		break;
	case MMC_RSP_R2:
		desired_rtype = 2;
		break;
	case MMC_RSP_R3: /* MMC_RSP_R4 */
		desired_rtype = 3;
		break;
	}
	r.ctype_xor = desired_ctype ^ hardware_ctype;
	r.rtype_xor = desired_rtype ^ hardware_rtype;
	return r;
}

static void check_switch_errors(struct cvm_mmc_host *host)
{
	union mio_emm_switch emm_switch;

	emm_switch.val = readq(host->base + MIO_EMM_SWITCH);
	if (emm_switch.s.switch_err0)
		dev_err(host->dev, "Switch power class error\n");
	if (emm_switch.s.switch_err1)
		dev_err(host->dev, "Switch hs timing error\n");
	if (emm_switch.s.switch_err2)
		dev_err(host->dev, "Switch bus width error\n");
}

/*
 * We never set the switch_exe bit since that would interfere
 * with the commands send by the MMC core.
 */
static void do_switch(struct cvm_mmc_host *host, u64 val)
{
	union mio_emm_rsp_sts rsp_sts;
	union mio_emm_switch emm_switch;
	int retries = 100;
	int bus_id;

	emm_switch.val = val;

	/*
	 * Modes setting only taken from slot 0. Work around that hardware
	 * issue by first switching to slot 0.
	 */
	bus_id = emm_switch.s.bus_id;
	emm_switch.s.bus_id = 0;
	writeq(emm_switch.val, host->base + MIO_EMM_SWITCH);

	emm_switch.s.bus_id = bus_id;
	writeq(emm_switch.val, host->base + MIO_EMM_SWITCH);

	/* wait for the switch to finish */
	do {
		rsp_sts.val = readq(host->base + MIO_EMM_RSP_STS);
		if (!rsp_sts.s.switch_val)
			break;
		udelay(10);
	} while (--retries);

	check_switch_errors(host);
}

static bool switch_val_changed(struct cvm_mmc_slot *slot, u64 new_val)
{
	/* Match BUS_ID, HS_TIMING, BUS_WIDTH, POWER_CLASS, CLK_HI, CLK_LO */
	u64 match = 0x3001070fffffffffull;

	return (slot->cached_switch & match) != (new_val & match);
}

static void set_wdog(struct cvm_mmc_slot *slot, unsigned int ns)
{
	u64 timeout;

	WARN_ON_ONCE(!slot->clock);
	if (ns)
		timeout = (slot->clock * ns) / NSEC_PER_SEC;
	else
		timeout = (slot->clock * 850ull) / 1000ull;
	writeq(timeout, slot->host->base + MIO_EMM_WDOG);
}

static void cvm_mmc_reset_bus(struct cvm_mmc_slot *slot)
{
	union mio_emm_switch emm_switch;
	u64 wdog = 0;

	emm_switch.val = readq(slot->host->base + MIO_EMM_SWITCH);
	wdog = readq(slot->host->base + MIO_EMM_WDOG);

	emm_switch.s.switch_exe = 0;
	emm_switch.s.switch_err0 = 0;
	emm_switch.s.switch_err1 = 0;
	emm_switch.s.switch_err2 = 0;
	emm_switch.s.bus_id = slot->bus_id;
	do_switch(slot->host, emm_switch.val);

	slot->cached_switch = emm_switch.val;

	msleep(20);

	writeq(wdog, slot->host->base + MIO_EMM_WDOG);
}

/* Switch to another slot if needed */
static void cvm_mmc_switch_to(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;
	struct cvm_mmc_slot *old_slot;
	union mio_emm_switch emm_switch;
	union mio_emm_sample emm_sample;

	if (slot->bus_id == host->last_slot)
		return;

	if (host->last_slot >= 0 && host->slot[host->last_slot]) {
		old_slot = host->slot[host->last_slot];
		old_slot->cached_switch = readq(host->base + MIO_EMM_SWITCH);
		old_slot->cached_rca = readq(host->base + MIO_EMM_RCA);
	}

	writeq(slot->cached_rca, host->base + MIO_EMM_RCA);
	emm_switch.val = slot->cached_switch;
	emm_switch.s.bus_id = slot->bus_id;
	do_switch(host, emm_switch.val);

	emm_sample.val = 0;
	emm_sample.s.cmd_cnt = slot->cmd_cnt;
	emm_sample.s.dat_cnt = slot->dat_cnt;
	writeq(emm_sample.val, host->base + MIO_EMM_SAMPLE);

	host->last_slot = slot->bus_id;
}

static void do_read(struct cvm_mmc_host *host, struct mmc_request *req,
		    u64 dbuf)
{
	struct sg_mapping_iter *smi = &host->smi;
	int data_len = req->data->blocks * req->data->blksz;
	int bytes_xfered, shift = -1;
	u64 dat = 0;

	/* Auto inc from offset zero */
	writeq((0x10000 | (dbuf << 6)), host->base + MIO_EMM_BUF_IDX);

	for (bytes_xfered = 0; bytes_xfered < data_len;) {
		if (smi->consumed >= smi->length) {
			if (!sg_miter_next(smi))
				break;
			smi->consumed = 0;
		}

		if (shift < 0) {
			dat = readq(host->base + MIO_EMM_BUF_DAT);
			shift = 56;
		}

		while (smi->consumed < smi->length && shift >= 0) {
			((u8 *)smi->addr)[smi->consumed] = (dat >> shift) & 0xff;
			bytes_xfered++;
			smi->consumed++;
			shift -= 8;
		}
	}

	sg_miter_stop(smi);
	req->data->bytes_xfered = bytes_xfered;
	req->data->error = 0;
}

static void do_write(struct mmc_request *req)
{
	req->data->bytes_xfered = req->data->blocks * req->data->blksz;
	req->data->error = 0;
}

static void set_cmd_response(struct cvm_mmc_host *host, struct mmc_request *req,
			     union mio_emm_rsp_sts *rsp_sts)
{
	u64 rsp_hi, rsp_lo;

	if (!rsp_sts->s.rsp_val)
		return;

	rsp_lo = readq(host->base + MIO_EMM_RSP_LO);

	switch (rsp_sts->s.rsp_type) {
	case 1:
	case 3:
		req->cmd->resp[0] = (rsp_lo >> 8) & 0xffffffff;
		req->cmd->resp[1] = 0;
		req->cmd->resp[2] = 0;
		req->cmd->resp[3] = 0;
		break;
	case 2:
		req->cmd->resp[3] = rsp_lo & 0xffffffff;
		req->cmd->resp[2] = (rsp_lo >> 32) & 0xffffffff;
		rsp_hi = readq(host->base + MIO_EMM_RSP_HI);
		req->cmd->resp[1] = rsp_hi & 0xffffffff;
		req->cmd->resp[0] = (rsp_hi >> 32) & 0xffffffff;
		break;
	}
}

static int get_dma_dir(struct mmc_data *data)
{
	return (data->flags & MMC_DATA_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
}

static int finish_dma_single(struct cvm_mmc_host *host, struct mmc_data *data)
{
	data->bytes_xfered = data->blocks * data->blksz;
	data->error = 0;
	return 1;
}

static int finish_dma(struct cvm_mmc_host *host, struct mmc_data *data)
{
	return finish_dma_single(host, data);
}

static bool bad_status(union mio_emm_rsp_sts *rsp_sts)
{
	if (rsp_sts->s.rsp_bad_sts || rsp_sts->s.rsp_crc_err ||
	    rsp_sts->s.rsp_timeout || rsp_sts->s.blk_crc_err ||
	    rsp_sts->s.blk_timeout || rsp_sts->s.dbuf_err)
		return true;

	return false;
}

/* Try to clean up failed DMA. */
static void cleanup_dma(struct cvm_mmc_host *host,
			union mio_emm_rsp_sts *rsp_sts)
{
	union mio_emm_dma emm_dma;

	emm_dma.val = readq(host->base + MIO_EMM_DMA);
	emm_dma.s.dma_val = 1;
	emm_dma.s.dat_null = 1;
	emm_dma.s.bus_id = rsp_sts->s.bus_id;
	writeq(emm_dma.val, host->base + MIO_EMM_DMA);
}

irqreturn_t cvm_mmc_interrupt(int irq, void *dev_id)
{
	struct cvm_mmc_host *host = dev_id;
	union mio_emm_rsp_sts rsp_sts;
	union mio_emm_int emm_int;
	struct mmc_request *req;
	bool host_done;

	/* Clear interrupt bits (write 1 clears ). */
	emm_int.val = readq(host->base + MIO_EMM_INT);
	writeq(emm_int.val, host->base + MIO_EMM_INT);

	if (emm_int.s.switch_err)
		check_switch_errors(host);

	req = host->current_req;
	if (!req)
		goto out;

	rsp_sts.val = readq(host->base + MIO_EMM_RSP_STS);
	/*
	 * dma_val set means DMA is still in progress. Don't touch
	 * the request and wait for the interrupt indicating that
	 * the DMA is finished.
	 */
	if (rsp_sts.s.dma_val && host->dma_active)
		goto out;

	if (!host->dma_active && emm_int.s.buf_done && req->data) {
		unsigned int type = (rsp_sts.val >> 7) & 3;

		if (type == 1)
			do_read(host, req, rsp_sts.s.dbuf);
		else if (type == 2)
			do_write(req);
	}

	host_done = emm_int.s.cmd_done || emm_int.s.dma_done ||
		    emm_int.s.cmd_err || emm_int.s.dma_err;

	if (!(host_done && req->done))
		goto no_req_done;

	if (bad_status(&rsp_sts))
		req->cmd->error = -EILSEQ;
	else
		req->cmd->error = 0;

	if (host->dma_active && req->data)
		if (!finish_dma(host, req->data))
			goto no_req_done;

	set_cmd_response(host, req, &rsp_sts);
	if (emm_int.s.dma_err && rsp_sts.s.dma_pend)
		cleanup_dma(host, &rsp_sts);

	host->current_req = NULL;
	req->done(req);

no_req_done:
	if (host->dmar_fixup_done)
		host->dmar_fixup_done(host);
	if (host_done)
		host->release_bus(host);
out:
	return IRQ_RETVAL(emm_int.val != 0);
}

/*
 * Program DMA_CFG and if needed DMA_ADR.
 * Returns 0 on error, DMA address otherwise.
 */
static u64 prepare_dma_single(struct cvm_mmc_host *host, struct mmc_data *data)
{
	union mio_emm_dma_cfg dma_cfg;
	int count;
	u64 addr;

	count = dma_map_sg(host->dev, data->sg, data->sg_len,
			   get_dma_dir(data));
	if (!count)
		return 0;

	dma_cfg.val = 0;
	dma_cfg.s.en = 1;
	dma_cfg.s.rw = (data->flags & MMC_DATA_WRITE) ? 1 : 0;
#ifdef __LITTLE_ENDIAN
	dma_cfg.s.endian = 1;
#endif
	dma_cfg.s.size = (sg_dma_len(&data->sg[0]) / 8) - 1;

	addr = sg_dma_address(&data->sg[0]);
	dma_cfg.s.adr = addr;
	writeq(dma_cfg.val, host->dma_base + MIO_EMM_DMA_CFG);

	pr_debug("[%s] sg_dma_len: %u  total sg_elem: %d\n",
		 (dma_cfg.s.rw) ? "W" : "R", sg_dma_len(&data->sg[0]), count);
	return addr;
}

static u64 prepare_dma(struct cvm_mmc_host *host, struct mmc_data *data)
{
	return prepare_dma_single(host, data);
}

static void prepare_ext_dma(struct mmc_host *mmc, struct mmc_request *mrq,
			    union mio_emm_dma *emm_dma)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);

	/*
	 * Our MMC host hardware does not issue single commands,
	 * because that would require the driver and the MMC core
	 * to do work to determine the proper sequence of commands.
	 * Instead, our hardware is superior to most other MMC bus
	 * hosts. The sequence of MMC commands required to execute
	 * a transfer are issued automatically by the bus hardware.
	 *
	 * - David Daney <ddaney@cavium.com>
	 */
	emm_dma->val = 0;
	emm_dma->s.bus_id = slot->bus_id;
	emm_dma->s.dma_val = 1;
	emm_dma->s.sector = mmc_card_blockaddr(mmc->card) ? 1 : 0;
	emm_dma->s.rw = (mrq->data->flags & MMC_DATA_WRITE) ? 1 : 0;
	emm_dma->s.block_cnt = mrq->data->blocks;
	emm_dma->s.card_addr = mrq->cmd->arg;
	if (mmc_card_mmc(mmc->card) || (mmc_card_sd(mmc->card) &&
	    (mmc->card->scr.cmds & SD_SCR_CMD23_SUPPORT)))
		emm_dma->s.multi = 1;

	pr_debug("[%s] blocks: %u  multi: %d\n", (emm_dma->s.rw) ? "W" : "R",
		 mrq->data->blocks, emm_dma->s.multi);
}

static void prepare_emm_int(union mio_emm_int *emm_int)
{
	emm_int->val = 0;
	emm_int->s.cmd_err = 1;
	emm_int->s.dma_done = 1;
	emm_int->s.dma_err = 1;
}

static void cvm_mmc_dma_request(struct mmc_host *mmc,
				struct mmc_request *mrq)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	union mio_emm_dma emm_dma;
	union mio_emm_int emm_int;
	struct mmc_data *data;
	u64 addr;

	if (!mrq->data || !mrq->data->sg || !mrq->data->sg_len ||
	    !mrq->stop || mrq->stop->opcode != MMC_STOP_TRANSMISSION) {
		dev_err(&mmc->card->dev,
			"Error: cmv_mmc_dma_request no data\n");
		goto error;
	}

	cvm_mmc_switch_to(slot);

	data = mrq->data;
	pr_debug("DMA request  blocks: %d  block_size: %d  total_size: %d\n",
		 data->blocks, data->blksz, data->blocks * data->blksz);
	if (data->timeout_ns)
		set_wdog(slot, data->timeout_ns);

	WARN_ON(host->current_req);
	host->current_req = mrq;

	prepare_ext_dma(mmc, mrq, &emm_dma);
	addr = prepare_dma(host, data);
	if (!addr) {
		dev_err(host->dev, "prepare_dma failed\n");
		goto error;
	}
	prepare_emm_int(&emm_int);

	host->dma_active = true;
	host->int_enable(host, emm_int.val);

	if (host->dmar_fixup)
		host->dmar_fixup(host, mrq->cmd, data, addr);

	/*
	 * If we have a valid SD card in the slot, we set the response
	 * bit mask to check for CRC errors and timeouts only.
	 * Otherwise, use the default power reset value.
	 */
	if (mmc->card && mmc_card_sd(mmc->card))
		writeq(0x00b00000ull, host->base + MIO_EMM_STS_MASK);
	else
		writeq(0xe4390080ull, host->base + MIO_EMM_STS_MASK);
	writeq(emm_dma.val, host->base + MIO_EMM_DMA);
	return;

error:
	mrq->cmd->error = -EINVAL;
	if (mrq->done)
		mrq->done(mrq);
	host->release_bus(host);
}

static void do_read_request(struct cvm_mmc_host *host, struct mmc_request *mrq)
{
	sg_miter_start(&host->smi, mrq->data->sg, mrq->data->sg_len,
		       SG_MITER_ATOMIC | SG_MITER_TO_SG);
}

static void do_write_request(struct cvm_mmc_host *host, struct mmc_request *mrq)
{
	unsigned int data_len = mrq->data->blocks * mrq->data->blksz;
	struct sg_mapping_iter *smi = &host->smi;
	unsigned int bytes_xfered;
	int shift = 56;
	u64 dat = 0;

	/* Copy data to the xmit buffer before issuing the command. */
	sg_miter_start(smi, mrq->data->sg, mrq->data->sg_len, SG_MITER_FROM_SG);

	/* Auto inc from offset zero, dbuf zero */
	writeq(0x10000ull, host->base + MIO_EMM_BUF_IDX);

	for (bytes_xfered = 0; bytes_xfered < data_len;) {
		if (smi->consumed >= smi->length) {
			if (!sg_miter_next(smi))
				break;
			smi->consumed = 0;
		}

		while (smi->consumed < smi->length && shift >= 0) {
			dat |= ((u8 *)smi->addr)[smi->consumed] << shift;
			bytes_xfered++;
			smi->consumed++;
			shift -= 8;
		}

		if (shift < 0) {
			writeq(dat, host->base + MIO_EMM_BUF_DAT);
			shift = 56;
			dat = 0;
		}
	}
	sg_miter_stop(smi);
}

static void cvm_mmc_request(struct mmc_host *mmc, struct mmc_request *mrq)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	struct mmc_command *cmd = mrq->cmd;
	union mio_emm_int emm_int;
	union mio_emm_cmd emm_cmd;
	struct cvm_mmc_cr_mods mods;
	union mio_emm_rsp_sts rsp_sts;
	int retries = 100;

	/*
	 * Note about locking:
	 * All MMC devices share the same bus and controller. Allow only a
	 * single user of the bootbus/MMC bus at a time. The lock is acquired
	 * on all entry points from the MMC layer.
	 *
	 * For requests the lock is only released after the completion
	 * interrupt!
	 */
	host->acquire_bus(host);

	if (cmd->opcode == MMC_READ_MULTIPLE_BLOCK ||
	    cmd->opcode == MMC_WRITE_MULTIPLE_BLOCK)
		return cvm_mmc_dma_request(mmc, mrq);

	cvm_mmc_switch_to(slot);

	mods = cvm_mmc_get_cr_mods(cmd);

	WARN_ON(host->current_req);
	host->current_req = mrq;

	emm_int.val = 0;
	emm_int.s.cmd_done = 1;
	emm_int.s.cmd_err = 1;

	if (cmd->data) {
		if (cmd->data->flags & MMC_DATA_READ)
			do_read_request(host, mrq);
		else
			do_write_request(host, mrq);

		if (cmd->data->timeout_ns)
			set_wdog(slot, cmd->data->timeout_ns);
	} else
		set_wdog(slot, 0);

	host->dma_active = false;
	host->int_enable(host, emm_int.val);

	emm_cmd.val = 0;
	emm_cmd.s.cmd_val = 1;
	emm_cmd.s.ctype_xor = mods.ctype_xor;
	emm_cmd.s.rtype_xor = mods.rtype_xor;
	if (mmc_cmd_type(cmd) == MMC_CMD_ADTC)
		emm_cmd.s.offset = 64 - ((cmd->data->blocks * cmd->data->blksz) / 8);
	emm_cmd.s.bus_id = slot->bus_id;
	emm_cmd.s.cmd_idx = cmd->opcode;
	emm_cmd.s.arg = cmd->arg;

	writeq(0, host->base + MIO_EMM_STS_MASK);

retry:
	rsp_sts.val = readq(host->base + MIO_EMM_RSP_STS);
	if (rsp_sts.s.dma_val || rsp_sts.s.cmd_val ||
	    rsp_sts.s.switch_val || rsp_sts.s.dma_pend) {
		udelay(10);
		if (--retries)
			goto retry;
	}
	if (!retries)
		dev_err(host->dev, "Bad status: %Lx before command write\n", rsp_sts.val);
	writeq(emm_cmd.val, host->base + MIO_EMM_CMD);
}

static void cvm_mmc_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	int clk_period, power_class = 10, bus_width = 0;
	union mio_emm_switch emm_switch;
	u64 clock;

	host->acquire_bus(host);
	cvm_mmc_switch_to(slot);

	/* Reset the chip on each POWER_OFF. */
	if (ios->power_mode == MMC_POWER_OFF) {
		cvm_mmc_reset_bus(slot);
		gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);
	} else
		gpiod_set_value_cansleep(host->global_pwr_gpiod, 1);

	switch (ios->bus_width) {
	case MMC_BUS_WIDTH_8:
		bus_width = 2;
		break;
	case MMC_BUS_WIDTH_4:
		bus_width = 1;
		break;
	case MMC_BUS_WIDTH_1:
		bus_width = 0;
		break;
	}

	slot->bus_width = bus_width;

	if (!ios->clock)
		goto out;

	/* Change the clock frequency. */
	clock = ios->clock;
	if (clock > 52000000)
		clock = 52000000;
	slot->clock = clock;
	clk_period = (host->sys_freq + clock - 1) / (2 * clock);

	emm_switch.val = 0;
	emm_switch.s.hs_timing = (ios->timing == MMC_TIMING_MMC_HS);
	emm_switch.s.bus_width = bus_width;
	emm_switch.s.power_class = power_class;
	emm_switch.s.clk_hi = clk_period;
	emm_switch.s.clk_lo = clk_period;
	emm_switch.s.bus_id = slot->bus_id;

	if (!switch_val_changed(slot, emm_switch.val))
		goto out;

	set_wdog(slot, 0);
	do_switch(host, emm_switch.val);
	slot->cached_switch = emm_switch.val;
out:
	host->release_bus(host);
}

const struct mmc_host_ops cvm_mmc_ops = {
	.request        = cvm_mmc_request,
	.set_ios        = cvm_mmc_set_ios,
	.get_ro		= mmc_gpio_get_ro,
	.get_cd		= mmc_gpio_get_cd,
};

static void cvm_mmc_set_clock(struct cvm_mmc_slot *slot, unsigned int clock)
{
	struct mmc_host *mmc = slot->mmc;

	clock = min(clock, mmc->f_max);
	clock = max(clock, mmc->f_min);
	slot->clock = clock;
}

static int cvm_mmc_init_lowlevel(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;
	union mio_emm_switch emm_switch;

	/* Enable this bus slot. */
	host->emm_cfg |= (1ull << slot->bus_id);
	writeq(host->emm_cfg, slot->host->base + MIO_EMM_CFG);
	udelay(10);

	/* Program initial clock speed and power. */
	cvm_mmc_set_clock(slot, slot->mmc->f_min);
	emm_switch.val = 0;
	emm_switch.s.power_class = 10;
	emm_switch.s.clk_hi = (slot->sclock / slot->clock) / 2;
	emm_switch.s.clk_lo = (slot->sclock / slot->clock) / 2;

	/* Make the changes take effect on this bus slot. */
	emm_switch.s.bus_id = slot->bus_id;
	do_switch(host, emm_switch.val);

	slot->cached_switch = emm_switch.val;

	/*
	 * Set watchdog timeout value and default reset value
	 * for the mask register. Finally, set the CARD_RCA
	 * bit so that we can get the card address relative
	 * to the CMD register for CMD7 transactions.
	 */
	set_wdog(slot, 0);
	writeq(0xe4390080ull, host->base + MIO_EMM_STS_MASK);
	writeq(1, host->base + MIO_EMM_RCA);
	return 0;
}

static int set_bus_width(struct device *dev, struct cvm_mmc_slot *slot, u32 id)
{
	u32 bus_width;
	int ret;

	/*
	 * The "cavium,bus-max-width" property is DEPRECATED and should
	 * not be used. We handle it here to support older firmware.
	 * Going forward, the standard "bus-width" property is used
	 * instead of the Cavium-specific property.
	 */
	if (!(slot->mmc->caps & (MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA))) {
		/* Try legacy "cavium,bus-max-width" property. */
		ret = of_property_read_u32(dev->of_node, "cavium,bus-max-width",
					   &bus_width);
		if (ret) {
			/* No bus width specified, use default. */
			bus_width = 8;
			dev_info(dev, "Default width 8 used for slot %u\n", id);
		}
	} else {
		/* Hosts capable of 8-bit transfers can also do 4 bits */
		bus_width = (slot->mmc->caps & MMC_CAP_8_BIT_DATA) ? 8 : 4;
	}

	switch (bus_width) {
	case 8:
		slot->bus_width = (MMC_BUS_WIDTH_8 - 1);
		slot->mmc->caps = MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA;
		break;
	case 4:
		slot->bus_width = (MMC_BUS_WIDTH_4 - 1);
		slot->mmc->caps = MMC_CAP_4_BIT_DATA;
		break;
	case 1:
		slot->bus_width = MMC_BUS_WIDTH_1;
		break;
	default:
		dev_err(dev, "Invalid bus width for slot %u\n", id);
		return -EINVAL;
	}
	return 0;
}

static void set_frequency(struct device *dev, struct mmc_host *mmc, u32 id)
{
	int ret;

	/*
	 * The "spi-max-frequency" property is DEPRECATED and should
	 * not be used. We handle it here to support older firmware.
	 * Going forward, the standard "max-frequency" property is
	 * used instead of the Cavium-specific property.
	 */
	if (mmc->f_max == 0) {
		/* Try legacy "spi-max-frequency" property. */
		ret = of_property_read_u32(dev->of_node, "spi-max-frequency",
					   &mmc->f_max);
		if (ret) {
			/* No frequency properties found, use default. */
			mmc->f_max = 52000000;
			dev_info(dev, "Default %u frequency used for slot %u\n",
				 mmc->f_max, id);
		}
	} else if (mmc->f_max > 52000000)
		mmc->f_max = 52000000;

	/* Set minimum frequency */
	mmc->f_min = 400000;
}

int cvm_mmc_slot_probe(struct device *dev, struct cvm_mmc_host *host)
{
	struct device_node *node = dev->of_node;
	u32 id, cmd_skew, dat_skew;
	struct cvm_mmc_slot *slot;
	struct mmc_host *mmc;
	u64 clock_period;
	int ret;

	ret = of_property_read_u32(node, "reg", &id);
	if (ret) {
		dev_err(dev, "Missing or invalid reg property on %s\n",
			of_node_full_name(node));
		return ret;
	}

	if (id >= CAVIUM_MAX_MMC || host->slot[id]) {
		dev_err(dev, "Invalid reg property on %s\n",
			of_node_full_name(node));
		return -EINVAL;
	}

	mmc = mmc_alloc_host(sizeof(struct cvm_mmc_slot), dev);
	if (!mmc)
		return -ENOMEM;

	slot = mmc_priv(mmc);
	slot->mmc = mmc;
	slot->host = host;

	ret = mmc_of_parse(mmc);
	if (ret)
		goto err;

	ret = set_bus_width(dev, slot, id);
	if (ret)
		goto err;

	set_frequency(dev, mmc, id);

	/* Octeon-specific DT properties. */
	ret = of_property_read_u32(node, "cavium,cmd-clk-skew", &cmd_skew);
	if (ret)
		cmd_skew = 0;
	ret = of_property_read_u32(node, "cavium,dat-clk-skew", &dat_skew);
	if (ret)
		dat_skew = 0;

	/*
	 * We only have a 3.3v supply, so we are calling this mostly
	 * to get a sane OCR mask for other parts of the MMC subsytem.
	 */
	ret = mmc_of_parse_voltage(node, &mmc->ocr_avail);
	if (ret == -EINVAL)
		goto err;

	/*
	 * We do not have a voltage regulator, just a single
	 * GPIO line to control power to all of the slots. It
	 * is registered in the platform code. We can, however,
	 * still set the POWER_OFF capability as long as the
	 * GPIO was registered correctly.
	 */
	if (!IS_ERR(host->global_pwr_gpiod)) {
		mmc->caps |= MMC_CAP_POWER_OFF_CARD;
		dev_info(dev, "Got global power GPIO\n");
	} else
		dev_info(dev, "Did not get global power GPIO\n");

	/* Set up host parameters */
	mmc->ops = &cvm_mmc_ops;

	mmc->caps |= MMC_CAP_MMC_HIGHSPEED | MMC_CAP_SD_HIGHSPEED |
		     MMC_CAP_ERASE | MMC_CAP_CMD23;

	mmc->max_segs = 1;

	/* DMA size field can address up to 8 MB */
	mmc->max_seg_size = 8 * 1024 * 1024;
	mmc->max_req_size = mmc->max_seg_size;
	/* External DMA is in 512 byte blocks */
	mmc->max_blk_size = 512;
	/* DMA block count field is 15 bits */
	mmc->max_blk_count = 32767;

	slot->clock = mmc->f_min;
	slot->sclock = host->sys_freq;

	/* Period in picoseconds. */
	clock_period = 1000000000000ull / slot->sclock;
	slot->cmd_cnt = (cmd_skew + clock_period / 2) / clock_period;
	slot->dat_cnt = (dat_skew + clock_period / 2) / clock_period;

	slot->bus_id = id;
	slot->cached_rca = 1;

	host->acquire_bus(host);
	host->slot[id] = slot;
	cvm_mmc_switch_to(slot);
	cvm_mmc_init_lowlevel(slot);
	host->release_bus(host);

	ret = mmc_add_host(mmc);
	if (ret) {
		dev_err(dev, "mmc_add_host() returned %d\n", ret);
		goto err;
	}

	return 0;

err:
	slot->host->slot[id] = NULL;

	gpiod_set_value_cansleep(host->global_pwr_gpiod, 0);

	mmc_free_host(slot->mmc);
	return ret;
}

int cvm_mmc_slot_remove(struct cvm_mmc_slot *slot)
{
	mmc_remove_host(slot->mmc);
	slot->host->slot[slot->bus_id] = NULL;
	gpiod_set_value_cansleep(slot->host->global_pwr_gpiod, 0);
	mmc_free_host(slot->mmc);

	return 0;
}
