/*
 * Driver for MMC and SSD cards for Cavium OCTEON and ThunderX SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012-2016 Cavium Inc.
 */
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/mmc/host.h>
#include <linux/of.h>
#include <linux/scatterlist.h>
#include <linux/semaphore.h>

#define CAVIUM_MAX_MMC		4

#define MIO_EMM_DMA_CFG		0x00
#define MIO_EMM_DMA_ADR		0x08

#define MIO_EMM_CFG		0x00
#define MIO_EMM_SWITCH		0x48
#define MIO_EMM_DMA		0x50
#define MIO_EMM_CMD		0x58
#define MIO_EMM_RSP_STS		0x60
#define MIO_EMM_RSP_LO		0x68
#define MIO_EMM_RSP_HI		0x70
#define MIO_EMM_INT		0x78
#define MIO_EMM_INT_EN		0x80
#define MIO_EMM_WDOG		0x88
#define MIO_EMM_SAMPLE		0x90
#define MIO_EMM_STS_MASK	0x98
#define MIO_EMM_RCA		0xa0
#define MIO_EMM_BUF_IDX		0xe0
#define MIO_EMM_BUF_DAT		0xe8

struct cvm_mmc_host {
	struct device *dev;
	void __iomem *base;
	void __iomem *dma_base;
	u64 emm_cfg;
	int last_slot;
	struct clk *clk;
	int sys_freq;

	struct mmc_request *current_req;
	struct sg_mapping_iter smi;
	bool dma_active;

	struct gpio_desc *global_pwr_gpiod;

	struct cvm_mmc_slot *slot[CAVIUM_MAX_MMC];

	void (*acquire_bus)(struct cvm_mmc_host *);
	void (*release_bus)(struct cvm_mmc_host *);
	void (*int_enable)(struct cvm_mmc_host *, u64);
};

struct cvm_mmc_slot {
	struct mmc_host *mmc;		/* slot-level mmc_core object */
	struct cvm_mmc_host *host;	/* common hw for all slots */

	u64 clock;
	unsigned int sclock;

	u64 cached_switch;
	u64 cached_rca;

	unsigned int cmd_cnt;		/* sample delay */
	unsigned int dat_cnt;		/* sample delay */

	int bus_width;
	int bus_id;
};

struct cvm_mmc_cr_type {
	u8 ctype;
	u8 rtype;
};

struct cvm_mmc_cr_mods {
	u8 ctype_xor;
	u8 rtype_xor;
};

/* Bitfield definitions */

union mio_emm_cmd {
	u64 val;
	struct mio_emm_cmd_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :2;
		u64 bus_id:2;
		u64 cmd_val:1;
		u64 :3;
		u64 dbuf:1;
		u64 offset:6;
		u64 :6;
		u64 ctype_xor:2;
		u64 rtype_xor:3;
		u64 cmd_idx:6;
		u64 arg:32;
#else
		u64 arg:32;
		u64 cmd_idx:6;
		u64 rtype_xor:3;
		u64 ctype_xor:2;
		u64 :6;
		u64 offset:6;
		u64 dbuf:1;
		u64 :3;
		u64 cmd_val:1;
		u64 bus_id:2;
		u64 :2;
#endif
	} s;
};

union mio_emm_dma {
	u64 val;
	struct mio_emm_dma_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :2;
		u64 bus_id:2;
		u64 dma_val:1;
		u64 sector:1;
		u64 dat_null:1;
		u64 thres:6;
		u64 rel_wr:1;
		u64 rw:1;
		u64 multi:1;
		u64 block_cnt:16;
		u64 card_addr:32;
#else
		u64 card_addr:32;
		u64 block_cnt:16;
		u64 multi:1;
		u64 rw:1;
		u64 rel_wr:1;
		u64 thres:6;
		u64 dat_null:1;
		u64 sector:1;
		u64 dma_val:1;
		u64 bus_id:2;
		u64 :2;
#endif
	} s;
};

union mio_emm_dma_cfg {
	u64 val;
	struct mio_emm_dma_cfg_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 en:1;
		u64 rw:1;
		u64 clr:1;
		u64 :1;
		u64 swap32:1;
		u64 swap16:1;
		u64 swap8:1;
		u64 endian:1;
		u64 size:20;
		u64 adr:36;
#else
		u64 adr:36;
		u64 size:20;
		u64 endian:1;
		u64 swap8:1;
		u64 swap16:1;
		u64 swap32:1;
		u64 :1;
		u64 clr:1;
		u64 rw:1;
		u64 en:1;
#endif
	} s;
};

union mio_emm_int {
	u64 val;
	struct mio_emm_int_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :57;
		u64 switch_err:1;
		u64 switch_done:1;
		u64 dma_err:1;
		u64 cmd_err:1;
		u64 dma_done:1;
		u64 cmd_done:1;
		u64 buf_done:1;
#else
		u64 buf_done:1;
		u64 cmd_done:1;
		u64 dma_done:1;
		u64 cmd_err:1;
		u64 dma_err:1;
		u64 switch_done:1;
		u64 switch_err:1;
		u64 :57;
#endif
	} s;
};

union mio_emm_rsp_sts {
	u64 val;
	struct mio_emm_rsp_sts_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :2;
		u64 bus_id:2;
		u64 cmd_val:1;
		u64 switch_val:1;
		u64 dma_val:1;
		u64 dma_pend:1;
		u64 :27;
		u64 dbuf_err:1;
		u64 :4;
		u64 dbuf:1;
		u64 blk_timeout:1;
		u64 blk_crc_err:1;
		u64 rsp_busybit:1;
		u64 stp_timeout:1;
		u64 stp_crc_err:1;
		u64 stp_bad_sts:1;
		u64 stp_val:1;
		u64 rsp_timeout:1;
		u64 rsp_crc_err:1;
		u64 rsp_bad_sts:1;
		u64 rsp_val:1;
		u64 rsp_type:3;
		u64 cmd_type:2;
		u64 cmd_idx:6;
		u64 cmd_done:1;
#else
		u64 cmd_done:1;
		u64 cmd_idx:6;
		u64 cmd_type:2;
		u64 rsp_type:3;
		u64 rsp_val:1;
		u64 rsp_bad_sts:1;
		u64 rsp_crc_err:1;
		u64 rsp_timeout:1;
		u64 stp_val:1;
		u64 stp_bad_sts:1;
		u64 stp_crc_err:1;
		u64 stp_timeout:1;
		u64 rsp_busybit:1;
		u64 blk_crc_err:1;
		u64 blk_timeout:1;
		u64 dbuf:1;
		u64 :4;
		u64 dbuf_err:1;
		u64 :27;
		u64 dma_pend:1;
		u64 dma_val:1;
		u64 switch_val:1;
		u64 cmd_val:1;
		u64 bus_id:2;
		u64 :2;
#endif
	} s;
};

union mio_emm_sample {
	u64 val;
	struct mio_emm_sample_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :38;
		u64 cmd_cnt:10;
		u64 :6;
		u64 dat_cnt:10;
#else
		u64 dat_cnt:10;
		u64 :6;
		u64 cmd_cnt:10;
		u64 :38;
#endif
	} s;
};

union mio_emm_switch {
	u64 val;
	struct mio_emm_switch_s {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 :2;
		u64 bus_id:2;
		u64 switch_exe:1;
		u64 switch_err0:1;
		u64 switch_err1:1;
		u64 switch_err2:1;
		u64 :7;
		u64 hs_timing:1;
		u64 :5;
		u64 bus_width:3;
		u64 :4;
		u64 power_class:4;
		u64 clk_hi:16;
		u64 clk_lo:16;
#else
		u64 clk_lo:16;
		u64 clk_hi:16;
		u64 power_class:4;
		u64 :4;
		u64 bus_width:3;
		u64 :5;
		u64 hs_timing:1;
		u64 :7;
		u64 switch_err2:1;
		u64 switch_err1:1;
		u64 switch_err0:1;
		u64 switch_exe:1;
		u64 bus_id:2;
		u64 :2;
#endif
	} s;
};

/* Protoypes */
irqreturn_t cvm_mmc_interrupt(int irq, void *dev_id);
int cvm_mmc_slot_probe(struct device *dev, struct cvm_mmc_host *host);
int cvm_mmc_slot_remove(struct cvm_mmc_slot *slot);
extern const struct mmc_host_ops cvm_mmc_ops;
