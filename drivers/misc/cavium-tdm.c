// SPDX-License-Identifier: GPL-2.0
/* cavium-tdm: Octeon/OcteonTX Telephony support
 *
 * Copyright (C) 2014-2017 Cavium Inc.
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/ioctl.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/stringify.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <asm/irq.h>
#include <asm/byteorder.h>

#ifdef CONFIG_MIPS
#include <linux/platform_device.h>
#include <asm/octeon/cvmx.h>
#include <asm/octeon/octeon-model.h>
#include <asm/octeon/octeon-feature.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-sysinfo.h>
#endif /* CONFIG_MIPS */

#include <linux/cavium-tdm.h>

#define DEVNAME	"tdm"

static struct proc_dir_entry *proc_tdm;

#ifdef CONFIG_CPU_BIG_ENDIAN
const bool big_endian = 1;
#else
const bool big_endian;
#endif

#if CONFIG_CAVIUM_TDM_MAX_SLOTS
# define MAX_SLOTS CONFIG_CAVIUM_TDM_MAX_SLOTS
#else
# define SPARSE_SLOTS
# define MAX_SLOTS TDM_MAX_SLOTS
#endif

/* align MAX_SLOTS up to boundary for bitmasks */
#define ALIGN_MAX_SLOTS ALIGN(MAX_SLOTS, BITS_PER_LONG/8)
/* and for mask register scans */
#define MASK_REGS	(ALIGN(ALIGN_MAX_SLOTS, 64) / 64)

/* tdm_trace mask bits are ... */
enum {
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	t_on	= 1,
#else /* no trace code, gcc eliminates at build time */
	t_on	= 0,
#endif /* !CONFIG_CAVIUM_TDM_DEBUG */
	t_err	= 0x1,		/* exceptions */
	t_read	= 0x2 * t_on,	/* read from fifo */
	t_write	= 0x4 * t_on,	/* write to fifo */
	t_misc	= 0x8 * t_on,	/* tf() */
	t_chan	= 0x10 * t_on,	/* TDMx channel setup/enable/disable */
	t_pump	= 0x20 * t_on,	/* read/write/dmahooks */
	t_csr	= 0x40 * t_on,	/* cvmx-csr decodes */
	t_rd	= 0x80 * t_on,	/* pcm read path */
	t_wr	= 0x100 * t_on,	/* pcm write path */
	t_scan	= 0x200 * t_on,	/* pcm write path */
	t_change = 0x400 * t_on, /* log everything at geometry change */
	t_init  = t_err | t_change,
	/* or'd in if t_change, at geometry change */
	t_detail = t_scan | t_csr | t_pump | t_chan | t_misc,
};

static int tdm_trace = t_init;
module_param_named(trace, tdm_trace, int, 0644);

/* event tracing, which collapses to nothing if !defined(DEBUG) */
#ifdef CONFIG_CAVIUM_TDM_DEBUG
/* trace_printk logging of interesting events (slot map changes) */
static int old_trace; /* saved trace flags over change-tracing */
static int trace_changes; /* count down on exhaustive logging */

# define tr_tdm(mask, fmt, ...) do { \
	/* unless trace_changes, trace only initial N */ \
	static int _once = 50; \
	/* TODO: adjust masks on WARN calls, rather than this strstr() */ \
	if (tdm_trace & (mask)) { \
		int _more; \
		/* if under t_change, trace forever */ \
		_more = trace_changes ? 1 : _once; \
		if (_more >= 0) { \
			char c = _more ? ' ' : '#'; \
			trace_printk("%c %d " fmt, c, __LINE__, ##__VA_ARGS__);\
		} \
	    } \
	} while (0)
#else /*!_DEBUG*/
# define tr_tdm(mask, fmt, ...) do { \
		if (tdm_trace & (mask)) \
			pr_debug(DEVNAME " " fmt, ##__VA_ARGS__);\
	} while (0)
#endif /*!_DEBUG*/

/*
 * A bus is one or more engines wired-or'd, currently exactly one,
 * but the two concepts are kept distinct for later dynamic-slot-map
 * enhancements, where engines are swapped to achieve geometry change.
 *
 * To emphasise that a bus is a virtual construct, but keep text compact,
 * use the variables tdm_bus *v; tdm_engine *e;
 */
struct tdm_engine;
struct tdm_bus;
#define NR_TDM_BUSES (NR_TDM_ENGINES - 0)
static inline int chk_v(struct tdm_bus *v);

/*
 * Global codec-dependent zero-fill for write underrun
 * 4-wide to allow alternating +0/-0 under 8 or 16bit codecs
 */
static u8 silence[4] = {
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	[0 ... 3] = '@',	/* constant lead-in for testing */
#else
	0x1, 0x81, 0x1, 0x81,	/* A-Law alternating +0, -0 */
#endif
};

#define tf(fmt, ...) tr_tdm(t_misc, fmt, ##__VA_ARGS__)

/*
 * Tracing macros simplifying code, but REQUIRING certain variables in scope:
 * Mostly used only where the needed v/vno/eno/dir already exist in calling
 * context, so reduce clutter, leaving surrounding code more readable.
 * Again, they collapse to nothing if !defined(CONFIG_CAVIUM_TDM_DEBUG).
 */
/* trace_bus_dir() -- REQUIRES v & dir in scope */
#define tvd(fmt, ...) tf("tdm%c%c%c%s %c%c%c " fmt, \
	chk_v(v) ? -1 : '0' + (v)->vno, \
	chk_v(v) ? -1 : '0' + ((v)->e[(v)->eb] ? (v)->e[(v)->eb]->eno : -1), \
	chk_v(v) ? -1 : '0' + ((v)->e[!(v)->eb] ? (v)->e[!(v)->eb]->eno : -1), \
	DirStr(dir), \
	chk_v(v) ? '/' : "-+"[!!(v)->eb], \
	chk_v(v) ? '/' : "-+"[!!FCUR(v)[!!(dir)].bno],  \
	chk_v(v) ? '/' : "-+"[!!FOLD(v)[!!(dir)].bno], \
	##__VA_ARGS__)

/* trace_bus_engine_dir() -- REQUIRES eno/v/dir in scope, for handover trace */
#define tved(fmt, ...) tvd("e%d " fmt, (int)(eno), ##__VA_ARGS__)
/* trace_engine_no() -- REQUIRES eno in scope */
#define ten(fmt, ...) tf("tdm?%d? " fmt, (int)(eno), ##__VA_ARGS__)
/* trace_bus_no() -- REQUIRES vno in scope */
#define tvn(fmt, ...) tf("tdm%d?? " fmt, (int)(vno), ##__VA_ARGS__)
/* trace_bus() -- REQUIRES v in scope */
#define tv(fmt, ...) do { \
		int vno = v->vno; \
		tf("tdm%d?? " fmt, (int)(vno), ##__VA_ARGS__); \
	} while (0)
/* tfl() -- tf() with caller __LINE__, REQUIRES line in scope */
#define tfl(fmt, ...) tf("from:%d " fmt, line, ##__VA_ARGS__)

enum {
	/* Direction enumerated for walking over both halves in irq servicing,
	 * or setup/teardown. Doesn't have to map to engine number, but it's a
	 * nice convention. All engines may Tx/Rx/Both, except that Tx on early
	 * cn81xx chips' tdm1..3 will poison other users of IOBN bus (eg bgx).
	 *
	 * Try to keep tx<rx assumption confined to for_xxx() macros below.
	 * When a property is dup'd on tx/rx flows, use e->flows[0].prop to
	 * make intention clear. That way any hardware asymmetry can be hidden.
	 */
	tx	= 0,
	rx	= 1,
	DIRS	= 2,	/* for dimensioning/looping */
	both	= 2,	/* clarifies evmask(v, both, ev_xxx) */
};
#define IsTx(d)		((d) == tx)
#define IsRx(d)		((d) != tx)
#define DirStr(d)	(IsTx(d) ? "tx" : (IsRx(dir) ? "rx" : "--"))
/* for the RARE cases when order is important... */
#define for_rx_tx(dir, cond) for ((dir) = rx; (cond) && (dir) >= tx; (dir)--)
#define for_tx_rx(dir, cond) for ((dir) = tx; (cond) && (dir) <= rx; (dir)++)
/* otherwise use the generic, which allows ordering to be build-specific */
#define for_dir(dir) for ((dir) = 0; (dir) < DIRS; (dir)++)

/* various tx/rx-specifics are summarised in xxthing[dir] */
static const u8 xxwrap[DIRS] = {
	[tx] = tdm_txwrap,
	[rx] = tdm_rxwrap,
};

static const u8 xxdma[DIRS] = {
	[tx] = tdm_txrd,
	[rx] = tdm_rxst,
};

static const u8 xxovf[DIRS] = {
	[tx] = tdm_txempty,
	[rx] = tdm_rxovf,
};

static const u8 xxbits[DIRS] = {
	[tx] = tdm_txbits,
	[rx] = tdm_rxbits,
};

union cavium_tdm_dma_cfg {
	uint64_t u64;
	struct {
		__BITFIELD_FIELD(uint64_t rdpend:1,
		__BITFIELD_FIELD(uint64_t reserved_54_62:9,
		__BITFIELD_FIELD(uint64_t rxslots:10,
		__BITFIELD_FIELD(uint64_t reserved_42_43:2,
		__BITFIELD_FIELD(uint64_t txslots:10,
		__BITFIELD_FIELD(uint64_t reserved_30_31:2,
		__BITFIELD_FIELD(uint64_t rxst:10,
		__BITFIELD_FIELD(uint64_t reserved_19_19:1,
		__BITFIELD_FIELD(uint64_t useldt:1,
		__BITFIELD_FIELD(uint64_t txrd:10,
		__BITFIELD_FIELD(uint64_t fetchsiz:4,
		__BITFIELD_FIELD(uint64_t thresh:4,
		;))))))))))))
	} s;
};

/* TDM_DBG private data */
union tdm_dbg {
	uint64_t u64;
	struct {
		__BITFIELD_FIELD(uint64_t dma_rxsf_cnt:16,
		__BITFIELD_FIELD(uint64_t dma_sf_cnt:16,
		__BITFIELD_FIELD(uint64_t dma_rxcnt_in_fr:10,
		__BITFIELD_FIELD(uint64_t dma_cnt_in_fr:10,
		__BITFIELD_FIELD(uint64_t dma_ld_pnd:1,
		__BITFIELD_FIELD(uint64_t reserved:2,
		__BITFIELD_FIELD(uint64_t dma_ld_cnt:5,
		__BITFIELD_FIELD(uint64_t dma_cnt:4,
		;))))))))
	} s;
};

#ifdef CONFIG_ARM64
static void *tdm_base;

/* TODO: flip write names, _prefix indicating noisy like read, and trim */
# define cvmx_read_csr(addr)		readq((void *)(addr))
# define cvmx_write_csr(addr, val)	writeq_relaxed(val, (void *)(addr))
#ifndef CONFIG_CAVIUM_TDM_DEBUG
#  define _cvmx_write_csr(addr, val)	cvmx_write_csr(addr, val)
#  define _cvmx_read_csr(addr)		cvmx_read_csr(addr)
# else
#  define _cvmx_write_csr(addr, val)	do { \
		void *w_a = (void *)(addr); \
		u64 w_v = (val); \
		tr_tdm(t_csr, "%p w %llx\n", w_a, w_v); \
		writeq_relaxed(w_v, w_a); \
		cvmx_read_csr(w_a); \
	} while (0)
#  define _cvmx_read_csr(addr)	({ \
		void *r_a = (void *)(addr); \
		u64 r_v = cvmx_read_csr(r_a); \
		tr_tdm(t_csr, "%p r %llx\n", r_a, r_v); \
		r_v; \
	})
# endif

# define cvmx_phys_to_ptr(v)		((void *)(v))

#else /* !CONFIG_ARM64 */

# ifndef CONFIG_CAVIUM_TDM_DEBUG
#  define _cvmx_write_csr(addr, val)	cvmx_write_csr(addr, val)
# else
#  define _cvmx_write_csr(addr, val) do { \
		tr_tdm(t_csr, "%llx w %llx\n", addr, (u64)val); \
		cvmx_write_csr(addr, val); \
	} while (0)
# endif
# define _cvmx_read_csr(addr)		cvmx_read_csr(addr)

#endif /* !CONFIG_ARM64 */

static struct device *tdmdev;

/* modparam for forcing major device, or inspecting it */
static int tdmdrv_major;
module_param(tdmdrv_major, int, 0644);

/* DMA ring size in frames */
static int ring_frames;
module_param(ring_frames, int, 0644);
/* maybe reduce _MIN to 1 if read/write_actor allows partial superframes */
#define RING_FRAMES_MIN		(2 * 8)
#define RING_FRAMES_MAX		(8 << 16)
//#define RING_FRAMES_DEFAULT	(4 * 8)
#define RING_FRAMES_DEFAULT        (2 * 8) /* default is slow for state debug */
#define FRAMES(v, dir)		((v)->ring_frames[dir])
#define SUPERS(v, dir)		(FRAMES(v, dir) >> 3)
#define STRIDE(f, dir)		((f)->fslots)

enum ev_e {
	/* events pending, fits in u8, so 8 copies fit in u64 waitfor */
	ev_off	= 1,
	ev_wrap	= 2,
	ev_xfer	= 4,	/* any txrd/rxst */
	ev_mask	= 0xff,	/* for clearing on close */
};

/* dynamic geometry handover action state */
enum s_e {
	s_off,
	s_normal,	/* 1: one-engine running */
	s_jump,		/* 2: one-engine starting */
	s_dim,
};
static const char *_s_s[s_dim] = {
	[s_off] = "s_off",
	[s_normal] = "s_normal",
	[s_jump] = "s_jump",
};
#define s_s(_s)	_s_s[_s]

enum { irqs_per_wrap = 2 };	/* could extend to N slices of DMA buffer? */

/* LDT usage per engine: (useldt & (1 << eno)) selects temporary cacheline */
static int useldt;
module_param(useldt, int, 0644);

/* if set, adjust DMA fetch size from default of 8 */
static int fetch_size; /* fetch_size == 1 + dma_cfg[fetchsiz] */
module_param(fetch_size, int, 0644);

/* if set, adjust DMA threshold from default of 8 */
static int fetch_thresh;
module_param(fetch_thresh, int, 0644);

/* global override to FSYNC, as tdmcat binary doesn't allow tweak */
static int fsyncsamp = -1;
static int fsynclen = -1;
static int fsyncloc = -1;
module_param(fsyncsamp, int, 0644);
module_param(fsynclen, int, 0644);
module_param(fsyncloc, int, 0644);

/* wide_rx - bitmask of buses which receive all slots, even when no clients */
static int wide_rx;
module_param(wide_rx, int, 0444);
#define WIDE(vno)	(wide_rx & (1 << (vno)))

/* loop_rx - bitmask of buses which receive all Tx slots */
static int loop_rx;
module_param(loop_rx, int, 0444);
#define LOOP(vno)	(loop_rx & (1 << (vno)))

enum {
	/* flog() logs details of each A,N,C,L flow */
	log_flows = 0,
};

/*
 * TODO: rename all to TDM_xxx and/or rework all as
 * ... #define [?CVMX_PCMX_?]TDM_CFG(engine) TDM_REG(engine, 2)
 * and later all union.s.xxx become bitmasks
 */
#define TDM_REG(eno, rno) \
	((u64)tdm_base + 8 * (rno) + ((eno) & 3) * TDM_RSIZE)
#define TDM_REGS 16 /* excludes xXMSK[] & MSIX */

#ifdef CONFIG_MIPS
#define TDM_RSIZE (1<<14)
#define CVMX_PCM_CLK0_CFG CVMX_ADD_IO_SEG(0x0001070000010000ull)
#define tdm_base CVMX_PCM_CLK0_CFG
#define CVMX_PCMX_INT_ENA(engine) \
	((u64)tdm_base + 0x20 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM(engine) \
	((u64)tdm_base + 0x28 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM_W1C(engine)	CVMX_PCMX_INT_SUM(engine)
#else /* !MIPS */
#define TDM_RSIZE (1<<16)
#define CVMX_PCMX_INT_SUM_W1S(engine) \
	((u64)tdm_base + 0x20 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM_W1C(engine) \
	((u64)tdm_base + 0x28 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_ENA_W1S(engine)	/*not MIPS */ \
	((u64)tdm_base + 0x70 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_ENA_W1C(engine)	/*not MIPS */ \
	((u64)tdm_base + 0x78 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM(engine)	CVMX_PCMX_INT_SUM_W1S(engine)
#define CVMX_PCMX_INT_ENA(engine)	CVMX_PCMX_INT_ENA_W1S(engine)
#endif /* !MIPS */

#define CVMX_PCM_CLKX_CFG(clk) \
	((u64)tdm_base + 0x00 + ((clk) & 1) * TDM_RSIZE)
#define CVMX_PCM_CLKX_GEN(clk) \
	((u64)tdm_base + 0x08 + ((clk) & 1) * TDM_RSIZE)
#define CVMX_PCMX_TDM_CFG(engine) \
	((u64)tdm_base + 0x10 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_DMA_CFG(engine) \
	((u64)tdm_base + 0x18 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_TDM_DBG(engine) \
	((u64)tdm_base + 0x30 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_TXSTART(engine) \
	((u64)tdm_base + 0x40 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_TXCNT(engine) \
	((u64)tdm_base + 0x48 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_TXADDR(engine) \
	((u64)tdm_base + 0x50 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_RXSTART(engine) \
	((u64)tdm_base + 0x58 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_RXCNT(engine) \
	((u64)tdm_base + 0x60 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_RXADDR(engine) \
	((u64)tdm_base + 0x68 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_TXMSKX(maskno, eng) \
	((u64)tdm_base + 0x80 + ((eng) & 3) * TDM_RSIZE + ((maskno)&7) * 8)
#define CVMX_PCMX_RXMSKX(maskno, eng) \
	((u64)tdm_base + 0xC0 + ((eng) & 3) * TDM_RSIZE + ((maskno)&7) * 8)

#ifdef CONFIG_MIPS
# define ONE_TDM_IRQ
# define NR_TDM_IRQS			1
# define TDM_IRQ(n)			OCTEON_IRQ_TDM
#endif /*MIPS*/
#ifdef CONFIG_ARM64
# define PCI_DEVICE_ID_THUNDER_TDM	0xA04E
# define NR_TDM_IRQS			NR_TDM_ENGINES
#endif /*CONFIG_ARM64 */

#define DRV_NAME	"tdm"

/* clock/framing state allows flexible ioctl ordering & defaults
 */
enum clkstate {
	c_cfg = 1,	/* clk_cfg has been set */
	c_gen = 2,	/* clk_gen has been set (except for freq) */
	c_fhz = 4,	/* frame rate has been set */
	c_ext = 8,	/* externally clocked */
	c_hz = (c_fhz | c_ext),	/* freq has been set somehow */
	c_on = 16,	/* set clock running */
};
static enum clkstate valid_clk[NR_CLKS];
static union cavium_tdm_clk_cfg clk_cfg[NR_CLKS];
static union cavium_tdm_clk_gen clk_gen[NR_CLKS];
static int pclk_hz[NR_CLKS]; /* for reporting */

/* prefer coherent allocator */
static bool use_coherent = true;
module_param(use_coherent, bool, 0644);

MODULE_DESCRIPTION("Cavium TDM Controller Module");
MODULE_AUTHOR("Peter Swain <peter.swain@marvell.com>");
MODULE_LICENSE("GPL");

static int tdm_setbuf(int vno, int dir);
static int tdm_teardown(void);

#ifdef ONE_TDM_IRQ
/* scan all engines, mips has just 1 IRQ */
static irqreturn_t tdm_handle_all(int irq, void *irqaction);
#else
/* process one engine */
static irqreturn_t tdm_handle_one(int irq, void *irqaction);
#endif

static long tdm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static inline int kickstart(struct tdm_bus *v);

static const struct file_operations tdmdrv_fops;
static struct class *tdmmodule_class;

struct tdm_slot;
typedef int (*tdm_actor) (struct tdm_slot *, u8 *dmabuf, int frames,
	int stride, bool bno, int *offp);

/* state for handling a read-or-write slot, or N consecutive slots */
#ifndef SPARSE_SLOTS
# define FIXED_FIFO_SUPERS
#endif
#define MAX_FIFO_LOG	9
#define MAX_FIFO	(1 << MAX_FIFO_LOG)
struct tdm_slot {
	u16 sno;		/* first TDM slot */
	u16 sample_bytes;	/* number of consecutive slots */
	u8 vno;
	u8 dir;
	tdm_actor actor;	/* called at irq to process completed frames */
	int skip;		/* samples to skip/fill at start */
	bool closing;
	bool active;
	struct tdm_sess *sess;

	/*
	 * FIFO of u8 for mux/demux TDM.superframes <-> user
	 * Offsets & sizes are in octets.
	 * With Tx/Rx names already confused between SLIC/TDM, think of
	 * these FIFOs as being divided into free region & content region.
	 * Consumer takes from beginning of content, incs data_off.
	 * Producer appends at free_off, incs free_off.
	 */
	int fifo_sz;		/* size in octets, must be 2^N */
	int data_off, free_off;	/* always evaluated modulo _sz, data >= free */
	/* re-zero'd every re-open up to here only */
	wait_queue_head_t fifo_have_content;
	wait_queue_head_t fifo_have_space;
#ifdef FIXED_FIFO_SUPERS
	u8 fifo[MAX_FIFO];
#else /* !FIXED_FIFO_SUPERS */
	/* fifo always allocated at end */
	u8 fifo[0];
#endif /* !FIXED_FIFO_SUPERS */
};

#define tdm_fifo_mask(s)	((s)->fifo_sz - 1)
#define tdm_fifo_content(s)	((s)->free_off - (s)->data_off)
#define tdm_fifo_space(s)	((s)->fifo_sz - tdm_fifo_content(s))
#define tdm_fifo_full(s)	(tdm_fifo_space(s) <= 0)

/*
 * struct tdm_sess:
 * describes a tx-or-rx session between a TDM slot and either
 * - a read/write connection on /dev/tdm%d
 * - another TDM slot
 * - a TDM-mode socket (not yet implemented, hooks in as tdm_read/tdm_write do)
 */
struct tdm_sess {
	struct tdm_bus *v;
	int rs, ws;		/* read/write slots */
	struct tdm_slot *slot[DIRS];	/* slot buffering/signalling */
	ktime_t geom_start[2]; /* [1]=acquire_start, [0]=release_start */
	bool bound;
};

/*
 * struct tdm_flow:
 * Either the tx or rx state of a TDM DMA engine.
 * Up to 3 instances exist concurrently, because the DMA buffer changes
 * shape as slots are added/removed, so hw's DMA under current mapping
 * can collide with copyin of new Tx data, or copyout of Rx data,
 * when slot map is changing.
 *
 * @bno: which of the superframe DMA buffers is being used.
 * @fmask: bitmap of slots in use, soft copy of txmask[]/rxmsk[].
 * @fslots: count of mask[] bits.
 * Note that fmask is typed to match bitops, not the 8 64bit registers,
 * and while it happens that u64 == unsigned long on mips64/arm64
 * types are purposefully kept distinct, but sized to contain same bitcount.
 * @changed: bitmask of fmask changes to push to hw, each represents a u64.
 * @clksel: which clocks source, hence framing details
 * @fgen: circulating flow generation number, for debug
 */
struct tdm_flow {
	bool bno;
	u16 fslots;
	s16 fgen;	/* flow generation number */
	bool clksel;	/* for frame shape */
	/* changed/fmask are ulong for bitops */
	unsigned long changed;
	unsigned long fmask[ALIGN_MAX_SLOTS / BITS_PER_LONG];
};

/* locking is done at the IRQ-granularity level, unless forced global */
#if defined(ONE_TDM_IRQ) || defined(FORCE_ONE_TDM_LOCK)
#define ONE_TDM_LOCK
static spinlock_t tdm_lock;
# define TDM_LOCK(v) tdm_lock
#else /* !ONE_TDM_IRQ */
# define TDM_LOCK(v) ((v)->bus_lock)
#endif /* !ONE_TDM_IRQ */

/*
 * struct tdm_engine / struct tdm_bus:
 * @eno:	which tdm engine 0..3.
 * @vno:	which virtual engine 0..3. (vno==eno when proxy==0)
 * @clksel:	which clock generator? -1 for unassigned.
 * @super[] & @handle[]: virtual & dma addresses of superframe buffers,
 *		two banks in each direction, which alternate when slot
 *		mapping changes to avoid overwriting.
 * @fnew[]:	pending flows, accumulate slotmap changes & Tx data.
 * @fcur[]:	currently active DMA flows.
 * @fold[]:	previous flow, or parallel when paired.
 * @ring_frames[] & @supersize[]: suggested and actual DMA buf sizes.
 * @slop[]:	dynamically allocated slot-pointer vector.
 */

struct tdm_bus {
	u8 vno;		/* const ordinal */
	s8 clksel;
	bool eb;	/* which engine/buffer fcur is using */
	struct tdm_engine *e[2]; /* engine(s), indexed [v->eb] */
	enum s_e hands;	/* handover state of the e[0/1] mapping */
	u64 waitfor;	/* the evmask(xxx) needed before handover progress */
	u16 max_slots[DIRS];	/* max slots in frame */
	u8 dead_offset[DIRS];	/* dead-zone is d_s bits up, inverse mask */
#ifndef ONE_TDM_LOCK
	spinlock_t bus_lock;
#endif /* !ONE_TDM_LOCK */
	struct semaphore sem_bind;
	u64 *super[DIRS][2]; /* indexed [dir][f->bno] */
	dma_addr_t handle[DIRS][2]; /* indexed [dir][f->bno] */
	struct tdm_flow flows[4 * DIRS]; /* mask bits, etc */
	struct tdm_flow falloc[DIRS]; /* mask bits, etc */
	int ring_frames[DIRS];
	size_t supersize[DIRS];
	s16 fgen;	/* flow generation number */
	int tseq;	/* test sequence */
	bool valid_cfg;		/* TDMSTIM issued? */
	bool valid_ssiz;	/* optional TDMSSIZE issued? */
	bool valid_flows;
	union cavium_tdm_cfg tc;	/* current CVMX_PCMX_TDM_CFG */
	union cavium_tdm_dma_cfg dc; /* current CVMX_PCMX_DMA_CFG */
	wait_queue_head_t mask_event; /* something changed? */
	int sync_pindex;	/* announce handover (testing) */
	u64 event;		/* event++ on every irq */
	bool fixed;		/* fixed (static) slotmap, Tx always on */
	struct cavium_tdm_sslots sslot; /* static (always-mapped) slots */
#ifdef SPARSE_SLOTS
	struct tdm_slot **slop[DIRS]; /* SLOt Pointers - old way, buggy? */
#else /* !SPARSE_SLOTS */
	struct tdm_slot slop[DIRS][MAX_SLOTS]; /* SLOts Themselves - new way */
#endif /* !SPARSE_SLOTS */
};

/* which role does this engine play? indexed erole[v->eb] */
static const char *erole[2] = {
	[1] = "tdm",	/* primary engine */
	[0] = "tdx",	/* proxy engine */
};


/*
 * 3 "flows" are maintained in each of tx/rx - bitmasks of active slots:
 * FALL: allocation map: ioctl(BIND) adds entries; close() removes them
 * FCUR: copied from FALL when changing config, as proxy-engine state
 * FOLD: previous state, or old engine when paired
 * When geometry change happens, the whole flow array rotates, by fgen++
 * But only 2 buffers needed (bno is 0/1), as Tx pre-loads FNEW,
 * Rx post-drains FOLD. VFLOW() cycles thru 4-way space to avoid
 * issues with overflow, which modulo-3 would bring.
 */
#define VFLOW(v, fi) (&((v)->flows[((unsigned int)((v)->fgen + fi) & 3) * 2]))
#define FALL(v)		((v)->falloc) /* pending-geom details */
#define FNEW(v)		VFLOW(v, 1) /* incoming-geom details */
#define FCUR(v)		VFLOW(v, 0) /* current-geom details */
#define FOLD(v)		VFLOW(v, -1) /* last-geom for Rx, post-proc */

struct tdm_engine {
	struct tdm_bus *v; /* bus, if any */
	struct tdm_flow *flows; /* which flows this engine owns */
	bool wrapped[DIRS];/* last processed DMA phase was a wrap */
	dma_addr_t hbase[DIRS]; /* start of DMA, flows[dir].handle[bno] */
	dma_addr_t hend[DIRS]; /* end of DMA, hbase[dir] + length */
	dma_addr_t half[DIRS]; /* midpoint */
	u64 *sbase[DIRS]; /* vaddr of hbase */
	u8 eno;		/* const ordinal for index into registers, etc */
	u8 ena;		/* soft IRQ enable state */
	u8 sum;		/* soft IRQ summary */
	u8 cumsum;	/* accumulated events since TDMGSTAT */
	ktime_t twrap[DIRS]; /* last start/wrap */
	int skip_dma[DIRS]; /* frame xfers to skip in jumpstart/handover */
	u64 lastirqs;	/* rolling (u4 state, u8 irq) log for debug */
	int rxto; /* handover: rx valid to here (frames) */
	int rxfrom; /* handover: rx valid from here (frames) */
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	int _irqstate[256]; /* detailed stats */
#endif
};

/*
 * eng[eno] manages a hardware TDM engine,
 * veng[vno] manages a TDM bus, using 0..2 engines,
 * mapping between them is controlled by "proxy"
 */
static struct tdm_engine eng[NR_TDM_ENGINES];
static struct tdm_bus veng[NR_TDM_ENGINES];

/* caller holds lock, mark an "interesting" event */
static inline void mark_change(void)
{
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	bool was_off = !old_trace;

	if (!(tdm_trace & t_change))
		return;
	trace_changes = 50; /* scans of enhanced tracing */
	if (was_off)
		old_trace = tdm_trace;
	if (was_off)
		trace_printk("tdm tracing on %x |= %x\n",
			tdm_trace, t_detail);
	tdm_trace |= t_detail;
#endif
}

/* caller holds lock, mark irq-handling done */
static inline void mark_done(void)
{
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	if (trace_changes <= 0)
		return;
	if (--trace_changes)
		return;
	trace_printk("tdm tracing off\n");
	tdm_trace = old_trace;
	old_trace = 0;
#endif
}

static unsigned long held;

/* bus state persistence, canceled by TDMSDROP */
static inline void hold(unsigned int vno, bool on)
{
	if (vno >= NR_TDM_BUSES)
		return;
	if (on && !test_and_set_bit(vno, &held)) {
		__module_get(THIS_MODULE);
	} else if (!on && test_and_clear_bit(vno, &held)) {
		/* TODO: revert vno to module-load state? */
		module_put(THIS_MODULE);
	}
}

static inline u64 get_sclk(void)
{
	static struct clk *sclk;
	static u64 sclk_hz;

	if (sclk_hz)
		return sclk_hz;

	if (IS_ERR_OR_NULL(sclk)) {
		int ret;

		sclk = devm_clk_get(tdmdev, NULL);
		if (IS_ERR_OR_NULL(sclk)) {
			pr_err("tdm: devm_clk_get() err %lld\n", (s64)sclk);
		} else {
			ret = clk_prepare_enable(sclk);
			if (ret)
				pr_err("tdm: clk_prepare_enable() err %d\n",
					ret);
			else
				sclk_hz = clk_get_rate(sclk);
		}
	}

#ifdef CONFIG_MIPS
	if (!sclk_hz) {
		pr_info("tdm: falling back to octeon_get_io_clock_rate()\n");
		sclk_hz = octeon_get_io_clock_rate();
	}
#endif /*MIPS*/

	return sclk_hz;
}

static inline int chk_eno(unsigned int eno)
{
	if (eno < NR_TDM_ENGINES)
		return 0;
	return -EINVAL;
}

static inline int _chk_vno(unsigned int vno, int line)
#define chk_vno(vno) _chk_vno(vno, __LINE__)
{
	if (vno < NR_TDM_BUSES)
		return 0;
	return -EINVAL;
}

static inline int chk_v(struct tdm_bus *v)
{
	if (!v)
		return -EINVAL;
	return chk_vno(v->vno);
}

/* respect TCMSCLKSEL, fall back to TDMCFG.useclk1, default clk0 */
static int which_clk(int vno)
{
	struct tdm_bus *v = &veng[vno];

	if (chk_vno(vno))
		return 0;
	if (v->clksel >= 0)
		return v->clksel;
	return v->tc.s.useclk1;
}

/* flow/engine/bus logging */
static bool probed;
static void _flowlog(struct tdm_bus *v, int line)
#define flowlog(v) _flowlog(v, __LINE__)
{
	int i;

	for (i = 1; i >= 0; i--) {
		bool eb = v->eb ^ !i;
		struct tdm_engine *e = v->e[eb];
		struct tdm_flow *flo;

		if (!e)
			continue;

		flo = e->flows;

		if (!flo) {
			tfl("%s%d.e[b%d]:e%d flo:NULL\n",
				erole[i], v->vno, eb, e->eno);
			continue;
		}

		tfl("%s%d.e[b%d]:e%d f%d.b%d tx:%d@%llx rx:%d@%llx\n",
			erole[i], v->vno, eb, e->eno,
			flo[tx].fgen, flo->bno,
			flo[tx].fslots, v->handle[tx][flo->bno],
			flo[rx].fslots, v->handle[rx][flo->bno]);
	}
}

static void _flog0(struct tdm_bus *v, const char *who, int line)
#define flog0(v, who) _flog0(v, who, __LINE__)
{
	if (!probed)
		return;

	tfl("tdm%d.b%d A%d N%d%c C%d%c L%d%c %s\n", v->vno, v->eb,
		FALL(v)->fgen,
		FNEW(v)->fgen, "-+"[FNEW(v)->bno],
		FCUR(v)->fgen, "-+"[FCUR(v)->bno],
		FOLD(v)->fgen, "-+"[FOLD(v)->bno], who);
	_flowlog(v, line);
}

static void flog1(struct tdm_bus *v, struct tdm_flow *f,
		int dir, char *s, int line)
{
	int m;

	f += dir;

	tfl("v%d.%s%d.%s slots:%d b%d +%lx\n", v->vno, s,
		f->fgen, DirStr(dir), f->fslots, f->bno, f->changed);

	for (m = 0; m < MASK_REGS; m++) {
		u64 msk = f->fmask[m];

		if (!msk)
			continue;
		tfl("   m%d %llx\n", m, msk);
	}
}

static void _flog(struct tdm_bus *v, const char *who, int line)
#define flog(v, who) _flog(v, who, __LINE__)
{
	_flog0(v, who, line);
	if (!log_flows)
		return;
	flog1(v, FALL(v), tx, "A", line);
	flog1(v, FALL(v), rx, "A", line);
	flog1(v, FNEW(v), tx, "N", line);
	flog1(v, FNEW(v), rx, "N", line);
	flog1(v, FCUR(v), tx, "C", line);
	flog1(v, FCUR(v), rx, "C", line);
	flog1(v, FOLD(v), tx, "L", line);
	flog1(v, FOLD(v), rx, "L", line);
}

static inline union cavium_tdm_dma_cfg read_dc(int eno)
{
	union cavium_tdm_dma_cfg dc;

	dc.u64 = cvmx_read_csr(CVMX_PCMX_DMA_CFG(eno));
	return dc;
}

static inline union cavium_tdm_dma_cfg write_dc(int eno,
			union cavium_tdm_dma_cfg dc)
{
	cvmx_write_csr(CVMX_PCMX_DMA_CFG(eno), dc.u64);

	return dc;
}

static inline void v_dc(struct tdm_bus *v, union cavium_tdm_dma_cfg dc)
{
	v->dc = dc;
}

static inline void await_rdpend(int eno)
{
	union cavium_tdm_dma_cfg dc;

	while ((dc = read_dc(eno)).s.rdpend)
		;
}

static inline union cavium_tdm_cfg read_tc(int eno)
{
	union cavium_tdm_cfg tc;

	await_rdpend(eno);
	tc.u64 = cvmx_read_csr(CVMX_PCMX_TDM_CFG(eno));
	return tc;
}

static inline void write_tc(int eno, union cavium_tdm_cfg tc)
{
	await_rdpend(eno);
	cvmx_write_csr(CVMX_PCMX_TDM_CFG(eno), tc.u64);
	await_rdpend(eno);
}

/*
 * evmask() - encode bus-level IRQ events, controlling handover.
 * Bus-level engine-handover actions must be done when all 4 DMA engines
 * are in the correct state (tx & rx sides, of one or two TDM engines).
 * evmask() encodes the required events into v->waitfor,
 * 'dirs' is either tx/rx/both.
 *
 * TODO: simplify, the whole 'waitfor' dance can be much simpler with
 * dynamic slot setup/teardown removed.
 */
static inline u64 evmask(int eno, int dirs, u64 event)
{
	u64 mask = 0, bits;
	struct tdm_flow *flows = eng[eno].flows;
	int dir;

	if (!flows)
		return 0;
	/*
	 * called with DIRS of tx or rx for single-dir
	 * or dirs=both for both-direction events
	 * Ugly - needs a name change, but inlines with constant arg
	 * better than loop
	 */
	for_dir(dir) {
		if (dirs != both && dirs != dir)
			continue;
		if (dir == tx && !flows[dir].fslots)
			continue;
		bits = event << (16 * eno + 8 * dir);
		mask |= bits;
	}

	return mask;
}

enum {
	ev_each_engine = 0x1000100010001ULL,
	ev_each_tx = ev_each_engine << (8 * tx),
	ev_each_rx = ev_each_engine << (8 * rx),
	ev_any_dir = ev_each_tx | ev_each_rx,
};

static int tdm_init(int vno, int dir);
static void tdm_exit(int vno, int dir);
static int tdm_hw_init(struct tdm_bus *v);
static struct tdm_slot *tdm_create_slot(struct tdm_bus *v,
	struct tdm_sess *, int sno, int sample_bytes,
	size_t fifo_sz, int dir, tdm_actor actor);

/* impose FNEW(v)[dir] on hardware */
static bool change_mapping(struct tdm_engine *e, int dir, bool first);
/* both directions, and wakeup */
static bool change_mappings(struct tdm_engine *e, bool first);

static int teardown;

/* stats for /proc/tdm */
struct avg {
	u64 count;
	u64 us;
	u64 max;
};
static struct pstat {
	u64 sum;
	u64 drops; /* or empty */
	u64 irqs;
	u64 missed[2]; /* missed[severity] */
	u64 nops;
	u64 hang;
	u64 noflo;
	u64 nolock;
	struct avg av[2]; /* [1]bind [0]release */
} pstat[NR_TDM_ENGINES][DIRS];

static inline void tdm_irq_enable(int eno, u8 bits)
{
	if (!chk_eno(eno)) {
#ifdef CONFIG_MIPS
		u8 ena;
		u64 r = CVMX_PCMX_INT_ENA(eno);

		ena = cvmx_read_csr(r);
		if (~ena & bits) {
			ena |= bits;
			_cvmx_write_csr(r, ena);
			eng[eno].ena = ena;
		}
#else /* !MIPS */
		_cvmx_write_csr(CVMX_PCMX_INT_ENA_W1S(eno), bits);
		eng[eno].ena |= bits;
#endif /* !MIPS */
	}
}

static inline void tdm_irq_disable(int eno, u8 bits)
{
	if (!chk_eno(eno)) {
#ifdef CONFIG_MIPS
		u8 ena;
		u64 r = CVMX_PCMX_INT_ENA(eno);

		ena = cvmx_read_csr(r);
		if (ena & bits) {
			ena &= ~bits;
			_cvmx_write_csr(r, ena);
			eng[eno].ena = ena;
		}
#else /* !MIPS */
		_cvmx_write_csr(CVMX_PCMX_INT_ENA_W1C(eno), bits);
		eng[eno].ena &= ~bits;
#endif /* !MIPS */
	}
}

static inline void tdm_irq_ack(int eno, u8 bits)
{
	if (!chk_eno(eno)) {
#if 0
		/* should be enuff */
		_cvmx_write_csr(CVMX_PCMX_INT_SUM_W1C(eno), bits);
		eng[eno].sum = cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
		eng[eno].cumsum |= eng[eno].sum;
#else
		/* explore suspected failure-to-clear */
		_cvmx_write_csr(CVMX_PCMX_INT_SUM_W1C(eno), bits);
		eng[eno].sum = _cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
		eng[eno].cumsum |= eng[eno].sum;
#endif
	}
}

/* change handover state: could be inline func, this is more traceable */
#define NEW_STATE(_v, _state) ((_v)->hands = (_state))

/* prepare to clone engine */
/* caller holds lock */
static void next_clone(struct tdm_bus *v, int eold, enum ev_e event)
{
	int next;

	/* next state depends on whether last close is happening */
	if (!(FALL(v)[tx].fslots || FALL(v)[rx].fslots)) {
		next = s_off;
	} else {
		tdm_irq_enable(eold, tdm_rxwrap);
		next = s_jump;
	}
	NEW_STATE(v, next);
}

static char *tname[2] = {
	[0] = "stop",
	[1] = "bind",
};

static void geom_stats(struct tdm_bus *v, struct tdm_sess *s)
{
#ifdef CONFIG_PROC_FS
	int enable;

	for (enable = 1; s && enable >= 0; enable--) {
		ktime_t tstart = s->geom_start[enable];
		ktime_t tend;
		int vno;
		u64 us;

		if (!tstart)
			continue;
		s->geom_start[enable] = 0;

		tend = ktime_get_boottime();
		vno = v->vno;

		us = ktime_to_ns(ktime_sub(tend, tstart)) / 1000;

		pstat[vno][0].av[enable].count++;
		pstat[vno][0].av[enable].us += us;
		if (pstat[vno][0].av[enable].max < us)
			pstat[vno][0].av[enable].max = us;
	}
#endif
}

#ifdef CONFIG_PROC_FS
static int show_tdm(struct seq_file *m, void *v)
{
	int clk, vno;
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	int eno, eold;
#endif /*CONFIG_CAVIUM_TDM_DEBUG */

	seq_printf(m, "cavium-tdm v%d buses:%d engines:%d clocks:%d default_ring_frames:%d",
		TDM_VER, NR_TDM_BUSES, NR_TDM_ENGINES, NR_CLKS, ring_frames);
#ifdef CONFIG_CAVIUM_TDM_MODULE
	seq_printf(m, " sig %7.7s\n", THIS_MODULE->srcversion);
#else
	seq_puts(m, "\n");
#endif
	for (clk = 0; clk < NR_CLKS; clk++) {
		seq_printf(m, "CLK%d", clk);
		if (!(valid_clk[clk] & c_hz))
			seq_puts(m, " clk_unset");
		else if (!pclk_hz[clk])
			seq_puts(m, " clk_external");
		else
			seq_printf(m, " framerate=%dHz", pclk_hz[clk]);
		seq_printf(m, " slots=%d bits=%d setup=%x\n",
			   clk_cfg[clk].s.numslots,
			   8 * clk_cfg[clk].s.numslots +
			   clk_cfg[clk].s.extrabit, valid_clk[clk]);
	}

	for (vno = 0; vno < NR_TDM_BUSES; vno++) {
		struct tdm_bus *v = &veng[vno];
		bool eb = v->eb;
		struct tdm_engine *e0 = v->e[eb];
		struct tdm_engine *e1 = v->e[!eb];
		struct pstat *ts = &pstat[vno][0];
		int dir;
		int i;

		if (!pstat[vno][tx].sum
		 && !pstat[vno][rx].sum
		 && !pstat[vno][tx].av[1].count
		 && !pstat[vno][rx].av[1].count)
			continue;

		seq_printf(m, "\n TDM%d bus", vno);
		seq_printf(m, " f%d %s", v->fgen, s_s(v->hands));
		seq_printf(m, " CLK%d engine", which_clk(vno));
		if (e0)
			seq_printf(m, "%d/", e0->eno);
		else
			seq_puts(m, "-/");
		if (e1)
			seq_printf(m, "%d ", e1->eno);
		else
			seq_puts(m, "- ");
		seq_puts(m, "\n");

		/* walk thru open/release stats */
		seq_puts(m, "        ");

		for (dir = 0; dir < 2; dir++) {
			if (!ts->av[dir].count)
				ts->av[dir].count = 1;
			seq_printf(m, "%s(%llu av:%llu mx:%llu)%c",
				tname[dir], ts->av[dir].count,
				ts->av[dir].us / (ts->av[dir].count * 1000),
				ts->av[dir].max / 1000,
				dir ? '\n' : ' ');
		}

		for (dir = 0; dir < DIRS; dir++) {
			struct pstat *s = &pstat[vno][dir];
			struct tdm_flow *fa = &FALL(v)[dir];
			struct tdm_flow *fc = &FCUR(v)[dir];
			struct tdm_flow *fo = &FOLD(v)[dir];

			/* skip any completely quiescent engine/dir */
			if (s->av[1].count < 2
			    && !(fo->fslots || fo->changed)
			    && !(fa->fslots || fa->changed)
			    && !(fc->fslots || fc->changed))
				continue;

			seq_printf(m, "\n  TDM%d ", vno);

			seq_printf(m,
				   "%s thresh:%d ring:%d octets:%lld\n",
				   DirStr(dir),
				   IsTx(dir) ? v->dc.s.txrd : v->dc.s.rxst,
				   v->ring_frames[dir],
				   s->sum);
			seq_printf(m, "    slots alloc:%d%c cur:%d%c old:%d%c",
				fa->fslots, "* "[!fa->changed],
				fc->fslots, "* "[!fc->changed],
				fo->fslots, "* "[!fo->changed]);
			if (e0)
				seq_printf(m, " i%xE%x/%llx",
					e0->sum, e0->ena, e0->lastirqs);
			if (e1 && e1 != e0)
				seq_printf(m, " i%xE%x/%llx",
					e1->sum, e1->ena, e1->lastirqs);
			seq_puts(m, "\n");

			for (i = 0; i < MASK_REGS; i++) {
				u64 ma = fa->fmask[i];
				u64 mc = fc->fmask[i];
				u64 mo = fo->fmask[i];
				static u8 showmask[NR_TDM_ENGINES][DIRS];
				bool mv = showmask[vno][dir] & (1 << i);

				if (!(ma | mc | mo | mv))
					continue;

				seq_printf(m,
					"  TDM%d.%smsk%d N%16.16llx",
					vno, DirStr(dir), i, ma);

				seq_printf(m, " C%c%16.16llx",
					"-+"[fc->bno], mc);
				seq_printf(m, " L%c%16.16llx",
					"-+"[fo->bno], mo);

				seq_putc(m, '\n');

				/* only hide masks which are always zero */
				showmask[vno][dir] |= (1<<i);
			}

			seq_printf(m,
				"    TDM%d%s drops:%lld nops:%llu",
				vno, DirStr(dir), s->drops, s->nops);
			seq_printf(m,
				" missed:%llu/%llu hang:%llu",
				s->missed[1], s->missed[0], s->hang);
			seq_printf(m,
				" nolock:%llu noflo:%llu irqs:%llu\n",
				s->nolock, s->noflo, s->irqs);
		}
	}

#ifdef CONFIG_CAVIUM_TDM_DEBUG
	for (eno = 0, eold = -1; eno < NR_TDM_ENGINES; eno++) {
		struct tdm_engine *e = &eng[eno];
		int i;

		for (i = 0; i < 256; i++) {
			if (e->_irqstate[i]) {
				if (eno != eold)
					seq_printf(m, "\ne%d ", eno);
				else
					seq_puts(m, "   ");
				eold = eno;
				seq_printf(m, "sum %x %d\n",
					   i, e->_irqstate[i]);
			}
		}
	}
#endif /*CONFIG_CAVIUM_TDM_DEBUG */
	seq_printf(m, "trace %x\n", tdm_trace);
	seq_printf(m, "wide_rx %x\n", wide_rx);
	seq_printf(m, "loop_rx %x\n", loop_rx);

	return 0;
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *s_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void s_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations proc_tdm_seq = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = show_tdm,
};

static int proc_tdm_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &proc_tdm_seq);
}

static const struct file_operations proc_tdm_fop = {
	.open = proc_tdm_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_MIPS
static int tdm_gpio_setup(struct device *dev)
{
	int err = 0;

	if (OCTEON_IS_MODEL(OCTEON_CN70XX)) {
		/*
		 * TDM pins are gpio, when TDM off.
		 * Must disable outputs, so TDM can use them as inputs.
		 * tdm_clk0 gpio 18,19
		 * tdm_clk1 gpio 14,15
		 * tdm_data0..3 gpio 17,16,13,12
		 */

		int gpio_lo = 12, gpio_hi = 19;
		int g;

		pr_debug("Setup CN70XX gpio pins %d..%d\n", gpio_lo, gpio_hi);
		for (g = gpio_lo; g <= gpio_hi; g++) {
			err = devm_gpio_request(dev, g, "tdm");
			if (err < 0)
				break;
			err = gpio_direction_input(g);
			if (err < 0)
				break;
		}
	}
	return err;
}
#endif /*CONFIG_MIPS */

static int _chk_clk(unsigned int vno, enum clkstate how, u64 arg, int line)
#define chk_clk(v, h, a) _chk_clk(v, h, a, __LINE__)
{
	int err = _chk_vno(vno, line);
	int clk = which_clk(vno);

	if (err)
		return -EINVAL;

	if (how & c_cfg) {
		int ns;
		clk_cfg[clk].u64 = arg;

		/* module symbols as quick tuning interface */
		if (fsyncsamp >= 0)
			clk_cfg[clk].s.fsyncsamp = fsyncsamp;
		if (fsynclen >= 0)
			clk_cfg[clk].s.fsynclen = fsynclen;
		if (fsyncloc >= 0)
			clk_cfg[clk].s.fsyncloc = fsyncloc;

		/* always Rx first+last slots */
		ns = clk_cfg[clk].s.numslots;
		pr_debug("clk%dcfg ns:%d fsync(samp:%d len:%d loc:%d)\n",
			clk,
			clk_cfg[clk].s.numslots,
			clk_cfg[clk].s.fsyncsamp,
			clk_cfg[clk].s.fsynclen,
			clk_cfg[clk].s.fsyncloc);
	}

	if (how & c_gen) {
		u64 divisor;

		clk_gen[clk].u64 = arg;
		divisor = clk_gen[clk].s.divisor;
		valid_clk[clk] &= ~c_hz;

		if (!divisor) {
			valid_clk[clk] |= c_ext;
		} else if ((valid_clk[clk] & c_cfg)
				&& clk_cfg[clk].s.numslots) {
			u64 bitclk = divisor * get_sclk();
			int framebits = (8 * clk_cfg[clk].s.numslots
					+ clk_cfg[clk].s.extrabit);

			valid_clk[clk] |= c_fhz;
			bitclk /= framebits;
			bitclk += ((bitclk & (1ull << 31)) << 1);
			bitclk >>= 32;
			pclk_hz[clk] = bitclk;
		}
		pr_debug("clk%dgen deltasamp:%d numsamp:%d divisor:%d\n",
			clk,
			clk_gen[clk].s.deltasamp,
			clk_gen[clk].s.numsamp,
			clk_gen[clk].s.divisor);
	}
	valid_clk[clk] |= (how & ~c_on);

	if (!(how & c_on))
		return 0;

	/* start clock, if fully configured */
	if (!(valid_clk[clk] & c_cfg)) {
		pr_info("TDM.CLK%d_CFG not set\n", clk);
		err = -EINVAL;
	}

	if (!(valid_clk[clk] & c_gen)) {
		pr_info("TDM.CLK%d_GEN not set\n", clk);
		err = -EINVAL;
	}

	if (!err)
		valid_clk[clk] |= c_on;

	return err;
}

static int chk_cfg(unsigned int vno, union cavium_tdm_cfg *tc)
{
	int err = chk_vno(vno);
	struct tdm_bus *v = &veng[vno];

	if (err)
		return err;
	if (v->valid_cfg)
		return 0;
	if (!tc)
		return -EINVAL;
	tc->s.enable = 0;
	v->tc = *tc;
	/* rest done in tdm_hw_init()  */
	v->valid_cfg = true;

	return 0;
}

/* setup superframes, defaulting as needed */
static int chk_dma(int vno, union cavium_tdm_bind *b)
{
	int err = chk_clk(vno, c_on, 0);

	err = chk_cfg(vno, NULL);
	if (err)
		return err;

	if (!b || !b->s.no_tx)
		err = tdm_init(vno, tx);
	if (err)
		return err;

	if (!b || !b->s.no_rx)
		err = tdm_init(vno, rx);
	return err;
}

/* chk_slots: apply slot binding (unless already bound)
 * if clk/tdm not configured, default it
 */
static int chk_slots(struct file *f, union cavium_tdm_bind *b)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_bus *v = sess->v;
	int vno = v->vno;
	int clk = v->clksel;
	int err;

	/* assume worst, if not limited by TDMSRXBUF/TDMSTXBUF */
	if (!sess->bound) {
		int frame;

		if (clk < 0)
			clk = 0;
		frame = clk_cfg[clk].s.numslots;
		if (!v->max_slots[rx] && !b->s.no_rx)
			v->max_slots[rx] = frame;
		if (!v->max_slots[tx] && !b->s.no_tx)
			v->max_slots[tx] = frame;
	}

	WARN(!b->s.slots, "sslots==0\n");
	if (!b->s.no_rx && b->s.rslot + b->s.slots > v->max_slots[rx])
		return -EINVAL;
	if (!b->s.no_tx && b->s.wslot + b->s.slots > v->max_slots[tx])
		return -EINVAL;

	v->clksel = clk;
	err = chk_dma(vno, b);
	if (err)
		return err;

	sess->bound = true;
	return 0;
}

static int tdm_flow_init(void);

static int tdm_common_init(struct device *dev)
{
	int result, i, j;

	if (!tdmdev)
		tdmdev = dev;

	result = tdm_flow_init();
	if (result)
		return result;

	result = register_chrdev(tdmdrv_major, DEVNAME, &tdmdrv_fops);
	if (result < 0) {
		pr_warn("tdm: can't get major %d\n", tdmdrv_major);
		goto ret;
	}

	if (!tdmdrv_major)
		tdmdrv_major = result;

	tdmmodule_class = class_create(THIS_MODULE, DEVNAME);
	if (IS_ERR(tdmmodule_class)) {
		result = PTR_ERR(tdmmodule_class);
		goto ret;
	}

	for (i = 0; i < NR_TDM_ENGINES; i++)
		eng[i].eno = i;

	for (i = 0; i < NR_TDM_BUSES; i++) {
		struct tdm_bus *v = &veng[i];
		int eb = 0;

		v->clksel = -1;
		v->vno = i;
		v->fgen = 1;
		v->eb = !eb;

#ifndef SPARSE_SLOTS
		for (j = 0; j < MAX_SLOTS; j++) {
			int dir;

			for_dir(dir) {
				struct tdm_slot *s = &v->slop[dir][j];

				init_waitqueue_head(&s->fifo_have_content);
				init_waitqueue_head(&s->fifo_have_space);
			}
		}
#endif /* !SPARSE_SLOTS */

		/* walk the flows, alternating buffer sets */
		/* "initial" buffer/engine is assigned until on map change */
		for_dir(j) {
			FALL(v)[j].bno = !eb;	/* ignored */
			FALL(v)[j].fgen = v->fgen + 1;	/* yes, same as FNEW */
			FNEW(v)[j].bno = eb;
			FNEW(v)[j].fgen = v->fgen + 1;
			FCUR(v)[j].bno = !eb;
			FCUR(v)[j].fgen = v->fgen + 0;
			FOLD(v)[j].bno = eb;
			FOLD(v)[j].fgen = v->fgen - 1;
		}
	}

	for (i = 0; i < NR_TDM_BUSES; i++) {
		device_create(tdmmodule_class, dev, MKDEV(tdmdrv_major, i),
			      NULL, DEVNAME "%d", i);
	}

	if (!tdmdev) {
		result = -ENOMEM;
		goto ret;
	}

	tdmdev->coherent_dma_mask = DMA_BIT_MASK(64);

#ifdef CONFIG_PROC_FS
	proc_tdm = proc_create("tdm", 0444, NULL, &proc_tdm_fop);
#endif /* CONFIG_PROC_FS */

	result = 0;
	probed = true;

ret:
	return result;
}

static void __exit tdm_common_remove(void *data)
{
	tr_tdm(t_chan | t_pump, "teardown\n");
	teardown = 1;

	tdm_teardown();
}

/* called under lock, or while probing */
static void attach_engine(struct tdm_bus *v, int i,
		struct tdm_engine *e, struct tdm_flow *f)
{
	if (e) {
		if (e->flows && v) {
			e->flows[tx].clksel = v->clksel;
			e->flows[tx].clksel = v->clksel;
		}
		e->flows = f;
		e->v = v;
	}

	v->e[i] = e;
}

static int tdm_pre_probe(void)
{
	int i;

#ifdef CONFIG_CAVIUM_TDM_DEBUG
	pr_info("TDM_VER %d ioctl generation, TDM_IOCTL='%c'=0x%2.2xxx\n",
		TDM_VER, TDM_IOCTL, TDM_IOCTL);
	pr_info("%d tdm engines, %d tdm buses\n",
		NR_TDM_ENGINES, NR_TDM_BUSES);


# ifdef CONFIG_CAVIUM_TDM_MODULE
	pr_info("sig %s\n", THIS_MODULE->srcversion);
# endif
#endif

#ifdef ONE_TDM_LOCK
	spin_lock_init(&tdm_lock);
#endif /* ONE_TDM_LOCK */

	for (i = 0; i < NR_TDM_ENGINES; i++)
		eng[i].eno = i;

	for (i = 0; i < NR_TDM_BUSES; i++) {
		struct tdm_bus *v = &veng[i];
		struct tdm_engine *e = &eng[i];

		v->vno = i;
		e->eno = i;

		init_waitqueue_head(&v->mask_event);
		sema_init(&v->sem_bind, 1);
#ifndef ONE_TDM_LOCK
		spin_lock_init(&TDM_LOCK(v));
#endif /* !ONE_TDM_LOCK */
	}

	return 0;
}

static int tdm_flow_init(void)
{
	int i;

	for (i = 0; i < NR_TDM_BUSES; i++) {
		struct tdm_bus *v = &veng[i];
		struct tdm_engine *e = &eng[i];
		unsigned long flags;

		spin_lock_irqsave(&TDM_LOCK(v), flags);
		/* same engine in both slots */
		attach_engine(v, 0, e, FCUR(v));
		attach_engine(v, 1, e, FCUR(v));
		v->sync_pindex = -1;

		spin_unlock_irqrestore(&TDM_LOCK(v), flags);
	}

	return 0;
}

#ifdef CONFIG_MIPS
static int tdm_mod_init(void)
{
	int tdm_irq;
	struct platform_device *pdev;
	struct device *dev;
	int eno;
	int err = -ENOMEM;

	err = tdm_pre_probe();
	if (err)
		return err;

	if (!(
#ifdef OCTEON_FEATURE_TDM
		octeon_has_feature(OCTEON_FEATURE_TDM)
#else
		OCTEON_IS_MODEL(OCTEON_CN30XX)
		|| OCTEON_IS_MODEL(OCTEON_CN31XX)
		|| OCTEON_IS_MODEL(OCTEON_CN50XX)
		|| OCTEON_IS_MODEL(OCTEON_CN61XX)
		|| OCTEON_IS_MODEL(OCTEON_CNF71XX)
		|| OCTEON_IS_MODEL(OCTEON_CN70XX)
#endif
		))
		return -EIO;

	tdm_irq = OCTEON_IRQ_TDM;

	pdev = platform_device_alloc("tdm", PLATFORM_DEVID_NONE);
	if (!pdev)
		return err;
	err = platform_device_add(pdev);
	if (err)
		return err;
	dev = &pdev->dev;

	err = tdm_gpio_setup(dev);
	if (err)
		return err;
	for (eno = 0; eno < NR_TDM_IRQS; eno++) {
		tdm_irq_disable(eno, tdm_irqall);
		tdm_irq_ack(eno, tdm_irqall);
	}

	if (devm_request_irq(dev, tdm_irq, tdm_handle_all,
			IRQF_NO_THREAD, DEVNAME, (void *)-1ll)) {
		pr_warn("TDM: IRQ %d is not free.\n", tdm_irq);
		return -EBUSY;
	}
	return tdm_common_init(dev);
}

static void __exit tdm_mod_exit(void)
{
	struct platform_device *pdev;

	if (!tdmdev)
		return;
	pdev = to_platform_device(tdmdev);
	tdm_common_remove(tdmdev);
	platform_device_del(pdev);
	platform_device_put(pdev);
}

module_init(tdm_mod_init);
module_exit(tdm_mod_exit);
#endif /*CONFIG_MIPS */

#ifdef CONFIG_ARM64
static bool tx0only;

static int tdm_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	int err = -ENOENT;
	int eno;
	struct property *pp;
	int gpio = -1;
	enum of_gpio_flags gflags = 0;	/* default active high */

	/* CN81XX pass 1.0/1.1 may not safely Tx on engines 1..3 */
	tx0only = MIDR_IS_CPU_MODEL_RANGE(read_cpuid_id(),
		MIDR_OCTEON_T81, 0x00, 0x01);

	err = tdm_pre_probe();

	if (err)
		return err;

	err = pci_enable_device(pdev);

	if (err) {
		dev_err(dev, "Failed to enable PCI device: err %d\n", err);
		goto err_put;
	}

	pr_debug("%s:%d of_node %p\n", __func__, __LINE__, dev->of_node);
	if (!dev->of_node) {
		struct device_node *np = of_find_node_by_name(NULL, "tdm");

		if (!IS_ERR(np)) {
			dev->of_node = np;
			pr_debug("%s:%d of_node %p\n", __func__, __LINE__,
			       dev->of_node);
			of_node_put(np);
		} else {
			err = PTR_ERR(np);
			pr_debug("%s:%d err %d\n", __func__, __LINE__, err);
			if (err == -EPROBE_DEFER)
				goto err_disable_device;
		}
	}

	pp = of_find_property(dev->of_node, "pcm-enable-gpios", NULL);

	if (IS_ERR_OR_NULL(pp)) {
		pr_debug("%s:%d pp %p\n", __func__, __LINE__, pp);
		pp = of_find_property(NULL, "pcm-enable-gpios", NULL);
	}

	pr_debug("%s:%d pp %p\n", __func__, __LINE__, pp);

	if (!IS_ERR_OR_NULL(pp)) {
		gpio = of_get_named_gpio_flags(dev->of_node,
					       "pcm-enable-gpios", 0, &gflags);
		pr_debug("%s:%d e:%d\n", __func__, __LINE__, gpio);
		if (gpio < 0 && pp)
			gpio = of_get_named_gpio(dev->of_node,
						"pcm-enable-gpios", 0);
		pr_debug("%s:%d gpio:%d flags:%x\n",
			__func__, __LINE__, gpio, gflags);

		if (pp && gpio == -EPROBE_DEFER) {
			err = gpio;
			goto err_disable_device;
		}
	}

	if (gpio >= 0) {
		err = devm_gpio_request(dev, gpio, "pcm-enable");

		if (err < 0)
			goto err_disable_device;
		err = gpio_direction_output(gpio, (gflags & OF_GPIO_ACTIVE_LOW)
					    ? GPIOF_INIT_LOW : GPIOF_INIT_HIGH);
	}

	err = pci_request_regions(pdev, DRV_NAME);

	if (err) {
		dev_err(dev, "PCI request regions failed: err %d\n", err);
		goto err_disable_device;
	}

	tdm_base = pci_ioremap_bar(pdev, 0);

	if (!tdm_base) {
		dev_err(dev, "found no memory resource\n");
		err = -ENXIO;
		goto err_unmap;
	}

	err = pci_alloc_irq_vectors(pdev,
		NR_TDM_IRQS, NR_TDM_IRQS, PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(dev, "Unable to enable MSI-X\n");
		goto err_unmap;
	}

	err = tdm_common_init(dev);

	if (err)
		goto err_irq;

	for (eno = 0; eno < NR_TDM_IRQS; eno++) {
		int irq = pci_irq_vector(pdev, eno);

		tdm_irq_disable(eno, tdm_irqall);
		tdm_irq_ack(eno, tdm_irqall);

		err = request_irq(irq, tdm_handle_one,
			    IRQF_NO_THREAD, DEVNAME, &eng[eno]);

		if (err) {
			pr_warn("TDM: IRQ %d is not free, err %d.\n", irq, err);
			goto err_irq;
		}
	}

	dev_info(dev, "cavium-tdm %d\n", TDM_VER);
	return 0;

err_irq:
	pci_free_irq_vectors(pdev);
	pdev->irq = 0;
err_unmap:
	/* harmless if NULL */
	iounmap(tdm_base);
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
err_put:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void __exit tdm_remove(struct pci_dev *pdev)
{
	int eno;

	tdm_common_remove(tdmdev);
	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		int irq = pci_irq_vector(pdev, eno);

		tdm_irq_disable(eno, tdm_irqall);
		tdm_irq_ack(eno, tdm_irqall);

		pr_debug("%s engine#%d free_irq(%d)\n", __func__, eno, irq);
		free_irq(irq, &eng[eno]);
	}

	pci_free_irq_vectors(pdev);

	if (tdm_base)
		iounmap(tdm_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static const struct pci_device_id id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_TDM)},
	{0,}			/* end of table */
};

MODULE_DEVICE_TABLE(pci, id_table);

static struct pci_driver tdm_driver = {
	.name = DRV_NAME,
	.id_table = id_table,
	.probe = tdm_probe,
	.remove = tdm_remove,
};

module_pci_driver(tdm_driver);
#endif /*CONFIG_ARM64 */

/* start engine from cold */
/* caller holds lock */
static bool enable_engine(struct tdm_engine *e)
{
	int dir, eno, vno;
	struct tdm_bus *v;

	if (!e)
		return false;
	eno = e->eno;

	v = e->v;
	vno = v->vno;

	if (!v)
		return false;

	for (dir = 0; dir < DIRS; dir++) {
		tdm_irq_ack(eno, xxbits[dir]);
		tdm_irq_enable(eno, tdm_clkbits | xxbits[dir]);
	}


	e->wrapped[tx] = true;
	e->wrapped[rx] = true;

	/* save to v->dc, this is primary engine */
	v_dc(v, write_dc(eno, v->dc));

	/* re-point the DMA engines to buffer start */
	cvmx_write_csr(CVMX_PCMX_TXSTART(eno),
		cvmx_read_csr(CVMX_PCMX_TXSTART(eno)));
	cvmx_write_csr(CVMX_PCMX_RXSTART(eno),
		cvmx_read_csr(CVMX_PCMX_RXSTART(eno)));
	wmb(); /* flush before enable */

	v->tc.s.enable = 1;
	e->twrap[tx] = e->twrap[rx] = ktime_get_boottime();

	write_tc(eno, v->tc);


	return true;
}

/* en/disable some TDM slots. caller holds lock */
/* caller holds lock */
static int __tdm_enable(struct tdm_sess *s,
	int dir, bool enable, int sno0, int slots)
{
	struct tdm_bus *v = s->v;
	int sno, _sno;
	struct tdm_flow *fa = &FALL(v)[dir];
	int last = 8 * sizeof(fa->fmask);

	/* no mask changes? */
	if (v->fixed)
		return 0;

	for (_sno = sno0; _sno < last && slots > 0; --slots, _sno++) {
		sno = _sno;

		/* under fixed slot mask, do not count forbidden slots */
		if (v->fixed && !test_bit(sno, v->sslot.mask[dir])) {
			slots++;
			continue;
		}

		if (enable) {
			if (!test_and_set_bit(sno, fa->fmask)) {
				fa->fslots++;
				set_bit(sno / 64, &fa->changed);
				mark_change();
			} else {
				/* revert any mappings set earlier */
				while (--sno >= sno0) {
					clear_bit(sno, fa->fmask);
					fa->fslots--;
				}
				return -EBUSY;
			}
		} else {
			if (test_and_clear_bit(sno, fa->fmask)) {
				fa->fslots--;
				set_bit(sno / 64, &fa->changed);
				mark_change();
			}
		}
	}

	return 0;
}

/* a quiescent flow is one for which no change is pending */
/* check is not definitive unless lock held */
static inline bool quiescent(struct tdm_bus *v, int dir)
{
	/* stubbed in this version, critical in dynamic engine/bus model */
	return true;
}

/*
 * Wait for slot-map conflicts to drain, lock engine.
 * Locking for disable is uninterruptible because there's never contention,
 * just serialization. But enable calls can conflict (collision, no clk).
 *
 * Here is where any multiple-parallel-slot-changes policy is defined.
 * Trivial in this version, critical in dynamic engine/bus model.
 *
 *Current Geometry Policy:
 * If current slot mapping has gone live (other slots have DMA data pending)
 * we cannot add/remove slots, as that would change the DMA mapping.
 * Retry until conflicts are gone in the disable (close/unbind case),
 * or return -EAGAIN on the interruptible enable case.
 *
 * On apparent success, recheck with lock held, returning 0 if uncontested
 */
/* caller ACQUIRES lock */
static inline bool bind_lock(struct tdm_bus *v, int dir,
		bool enable, unsigned long *flagp)
{
	int err = 0;

	if (!v) {
		WARN_ONCE(1, "null bus\n");
		return -EAGAIN;
	}

	if (enable)
		err = wait_event_interruptible(v->mask_event,
			quiescent(v, dir));
	else
		wait_event(v->mask_event, quiescent(v, dir));

	if (err)
		return err;

	spin_lock_irqsave(&TDM_LOCK(v), *flagp);
	if (quiescent(v, dir))
		return 0;
	spin_unlock_irqrestore(&TDM_LOCK(v), *flagp);
	return -EAGAIN;
}

/* caller holds sem_bind, fun acquires/releases TDM_LOCK(v) */
static int tdm_enable(struct file *fi, int dir,
	bool enable, int sno0, int slots)
{
	struct tdm_sess *sess = fi->private_data;
	struct tdm_bus *v = sess->v;
	int vno = v->vno;
	int eb = !v->eb; /* always act on /next/ flow */
	int eno = -1;
	struct tdm_engine *e = NULL;
	unsigned long flags = 0; /* assigned to quiet gcc */
	int err;
	bool active;

	if (!v->super[dir][0] && enable)
		tdm_setbuf(vno, dir);

	if (!v->super[dir][0])
		return -EPROTO;

	err = bind_lock(v, dir, enable, &flags);
	if (err)
		return err;

	if (v->hands == s_off) {
		active = false;
	} else {
		active = FCUR(v)[dir].fslots;
		active |= FCUR(v)[!dir].fslots;
	}

	err = __tdm_enable(sess, dir, enable, sno0, slots);
	e = v->e[eb];

	if (!e)
		e = v->e[!eb];

	if (!e) {
		err = -EBUSY;
		goto unlock;
	}
	eno = e->eno;


	/* whole-engine start/stop, TODO: move some/all to kickstart/kickstop */
	if (!err && enable && !active) {
		tdm_irq_enable(eno, tdm_clkbits | xxbits[dir]);
		/* ignore any pending startup FSYNC errors */
		tdm_irq_ack(eno, tdm_clkbits);
	}

unlock:
	spin_unlock_irqrestore(&TDM_LOCK(v), flags);

	if (err)
		return err;

	return 0;
}

static int tdm_teardown(void)
{
	int i;

	for (i = 0; i < NR_TDM_BUSES; i++)
		down(&veng[i].sem_bind);

#ifdef CONFIG_PROC_FS
	if (proc_tdm)
		proc_remove(proc_tdm);
	proc_tdm = NULL;
#endif /* CONFIG_PROC_FS */

	for (i = 0; i < NR_TDM_ENGINES; i++)
		write_tc(i, (union cavium_tdm_cfg) 0ULL);

	for (i = 0; i < NR_TDM_BUSES; i++) {
		tdm_exit(i, tx);
		tdm_exit(i, rx);
		device_destroy(tdmmodule_class,
				MKDEV(tdmdrv_major, i));
	}

	class_destroy(tdmmodule_class);
	unregister_chrdev(tdmdrv_major, DEVNAME);
	tdmdrv_major = 0;

	tdmdev = NULL;

	return 0;
}

/* Tx path Consumer: pull N frames' TX payload from write fifo */
/* caller holds lock */
static int write_actor(struct tdm_slot *s, u8 *dma, int frames,
	int stride, bool bno, int *offp)
{
	int done = 0;
	int supers = (frames + 7) / 8;
	int width = s->sample_bytes;
	int left = tdm_fifo_content(s);

	for (; supers > 0; supers--, frames -= 8) {
		int idx = *offp;
		int j, k;
		u8 *l8;
		int swept = 0;
		int squelch = 0;

		idx &= tdm_fifo_mask(s);

		l8 = &s->fifo[idx];

		/*
		 * interleave 8 N-byte samples over
		 * N successive slots of a frame
		 * TODO: generalize logic for cpu_endian +/- LSBFIRST
		 */
		for (k = 0; k < width; k++) {
			for (j = 0; j < 8 && j < frames; j++) {
				int i = 7 - j;
				u8 jth;
				int src;

				if (big_endian)
					i = j;
				src = idx + j * width + k;
				src &= tdm_fifo_mask(s);
				jth = s->fifo[src];
				if (unlikely(left <= width * j)) {
					jth = silence[(j + k) & 3];
					squelch++;
				}
				dma[8 * k + i] = jth;
				swept++;
			}
		}

		done += swept;
		swept -= squelch;
		left -= swept;
		if (swept > tdm_fifo_content(s)) {
			tr_tdm(t_on, "tdm%d.s%d WARN swept %x but %x content\n",
				s->vno, s->sno, swept, tdm_fifo_content(s));
			swept = tdm_fifo_content(s);
		}
		*offp += swept;
		dma += 8 * stride;
	}

	return done;
}

/*
 * Rx path Producer: push N frames' RX payload to read fifo, unless full.
 * TODO: consider overwriting old samples if full, by rolling data_off forward
 */
/* caller holds lock */
static int read_actor(struct tdm_slot *s, u8 *dma, int frames,
	int stride, bool bno, int *offp)
{
	int done = 0;
	int supers = (frames + 7) / 8;
	int width = s->sample_bytes;
	int left = tdm_fifo_space(s);

	for (; dma && supers > 0; supers--, frames -= 8) {
		int j = 0, k;	/* time sequence, or fifo sample sequence */
		int idx = *offp;
		int swept = 0;
		int chunks = left / width;


		/*
		 * Transcode 8 samples from DMA ring to fifo:
		 * combine hi/low bytes of 8 N-byte samples
		 * from N successive slots of a frame
		 * TODO: generalize logic for cpu_endian +/- LSBFIRST
		 */
		for (k = 0; k < width; k++) {

			for (j = 0; j < 8 && j < frames && j < chunks; j++) {
				int i = 7 - j;
				u8 jth;
				int dest;

				if (big_endian)
					i = j;
				jth = dma[8 * k + i];
				if (s->skip > j)
					continue;

				dest = idx + j * width + k;
				dest &= tdm_fifo_mask(s);
				s->fifo[dest] = jth;
				swept++;

			}
		}

		if (s->skip > 0)
			s->skip -= j;

		if (swept > tdm_fifo_space(s)) {
			tr_tdm(t_on, "tdm%d.s%d WARN swept %x but %x space\n",
				s->vno, s->sno, swept, tdm_fifo_space(s));
			swept = tdm_fifo_space(s);
		}
		*offp += swept;
		done += swept;
		dma += 8 * stride;
		left -= swept;
	}

	return done;
}

static inline void scanlog(struct tdm_engine *e, int dir, bool bno,
	int stride, int frames, u8 *sbase)
{
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	struct tdm_bus *v = e->v;
	int eno = e->eno;
	u64 *sb64 = (u64 *) sbase;
	u64 *end = (u64 *) (sbase + frames * stride) - 4;
	int off, seen = 0;

	/* show first two active slots, that are not all one-or-zero */
	for (off = 0; sb64 && sb64 + off <= end && seen < 2; off++) {
		if (!sb64[off] || !~sb64[off])
			continue;
		tved("sbase@%p b%d s%d +%x/%x %llx:%llx:%llx:%llx\n",
		     sbase, bno, off / frames, off, frames * stride,
		     sb64[off + 0], sb64[off + 1], sb64[off + 2],
		     sb64[off + 3]);
		seen++;
		off += 3;
	}
#endif /*CONFIG_CAVIUM_TDM_DEBUG */
}

/*
 * dma_xfer() - process DMA completed since last call
 * irq-time scanner which transfers between v->super
 * and the per-slot fifos which read/write clients drain/fill.
 *
 * Walk array of read/write slots (in slot order) calling an actor
 * on each to process available frames.
 *
 * Because the "slot" objects may be represent not just single-octet
 * codec data, but 16-bit wide samples, or arbitrary-width slices,
 * the scan of the interface may actually mux/demux multiple consecutive
 * slots. For compact code the read/write actors handle this decision
 * at runtime, but for efficiency a specialized 8-or-16-bit actor could
 * be assigned at slot creation time.
 */
/* caller holds lock */
static void dma_xfer(struct tdm_engine *e, bool dir, bool bno,
	int stride, int frames, u8 *sbase, dma_addr_t hbase)
{
	struct tdm_bus *v;
	struct tdm_flow *f;
#ifdef SPARSE_SLOTS
	struct tdm_slot **slop;
#else /* !SPARSE_SLOTS */
	struct tdm_slot *slop;
#endif /* !SPARSE_SLOTS */
	/* irq every SUPERS/irqs_per_wrap, dma_cfg[rxst,txrd] each IRQ_THRESH */
	int moved = 0;
	int slots = 0;
	int sno; /* slot number, scanning dma buffer */
	int vno;
	int (*actor)(struct tdm_slot *s, u8 *b8,
		int frames, int stride, bool bno, int *offp);

	v = e->v;
	if (!v || !frames || !stride)
		return;

	vno = v->vno;
	f = &e->flows[dir];
	slop = v->slop[dir];

	if (!slop)
		return;

	if (IsRx(dir) && (tdm_trace & t_scan))
		scanlog(e, dir, bno,
			stride, frames, sbase);

	for (sno = 0; slots < stride && sno < v->max_slots[dir]; sno++) {
#ifdef SPARSE_SLOTS
		struct tdm_slot *s = slop[sno];
#else /* !SPARSE_SLOTS */
		struct tdm_slot *s = &slop[sno];
#endif /* !SPARSE_SLOTS */
		int done = 0;
		int *offp;

		/*
		 * while slop[sno] contains an entry if a slot is active in any
		 * of FALL..FOLD, the slot consumes space in the current sbase
		 * DMA buffer only if its bit is set in e->flows[dir].fmask
		 */
		if (!test_bit(sno, f->fmask)) {
			/* if(s) teardown accounting? */
			continue;
		}

		/* in mask, but no s? wide_rx or closed */
		if (!s || !s->active) {
			sbase += 8;
			slots++;
			continue;
		}

		/* log setup time */
		if (v->hands == s_normal && s->sess)
			geom_stats(v, s->sess);

		actor = s->actor;

		offp = IsTx(dir) ? &s->data_off : &s->free_off;

		if (s->closing && s->active) {
			geom_stats(v, s->sess);
			s->active = false;
		}

		if (!s->active)
			break;

		if (actor && !s->closing) {
			done = actor(s, sbase, frames,
				    stride, bno, offp);
		}

		moved += done;

		sbase += 8 * s->sample_bytes;
		slots += s->sample_bytes;

		if (IsTx(dir))
			wake_up(&s->fifo_have_space);
		else
			wake_up(&s->fifo_have_content);
	}

	pstat[v->vno][dir].sum += moved;
}

static void tdm_exit(int vno, int dir)
{
	struct tdm_bus *v = &veng[vno];

	/*
	 * TODO: no waiting needed here IFF _release waits until
	 * its slots are gone from all masks
	 */
	if (v->super[dir][0] && use_coherent)
		dma_free_coherent(tdmdev,
			2 * v->supersize[dir],
			v->super[dir][0], v->handle[dir][0]);
	else
		kfree(v->super[dir][0]);

	v->super[dir][0] = NULL;
	v->super[dir][1] = NULL;

#ifdef SPARSE_SLOTS
	v->slop[dir] = NULL;
#endif /* SPARSE_SLOTS */
}

static int tdm_setbuf(int vno, int dir)
{
	struct tdm_bus *v = &veng[vno];
	int eslots;
	size_t size8; /* size in u8 of one of a pair of superframe DMA bufs */
	size_t size64; /* and in u64 to simplify code below */
	char *how = "kzalloc";
	bool bno = 0; /* but first used is bno=1 */
	int i;

	if (v->super[dir][0])
		return -EBUSY;

	/* assume worst, if not limited by TDMSRXBUF/TDMSTXBUF */
	if (!v->max_slots[dir])
		v->max_slots[dir] = MAX_SLOTS;

	/* range check, for when everything is configurable */
#if 0
	if (!SUPERS || SUPERS >= (1<<16))
		return -EINVAL;
	if (!IRQ_THRESH || IRQ_THRESH > 0x3ff)
		return -EINVAL;
#endif

	if (!v->ring_frames[dir]) {
		if (ring_frames < RING_FRAMES_MIN ||
		    ring_frames >= RING_FRAMES_MAX)
			ring_frames = RING_FRAMES_DEFAULT;
		ring_frames += 7;
		ring_frames &= ~7;
		v->ring_frames[dir] = ring_frames;
	}

	eslots = v->max_slots[dir];
	size8 = eslots * v->ring_frames[dir];
	size64 = size8 / 8;

	/* TODO: make this dynamic, re-alloc'd as growth needed? */
	if (use_coherent) {
		v->super[dir][bno] = dma_alloc_coherent(tdmdev,
			2 * size8, &v->handle[dir][bno], GFP_KERNEL);
		tf("v%d super[%s] %p/%lx\n",
			vno, DirStr(dir), v->super[dir][bno], 2 * size8);
		if (v->super[dir][bno])
			how = "dma_alloc_coherent";
	}

	if (!v->super[dir][bno]) {
		v->super[dir][bno] = kmalloc(2 * size8, GFP_KERNEL | GFP_DMA);
		tf("v%d super[%s] %p/2*%lx\n",
			vno, DirStr(dir), v->super[dir][bno], 2 * size8);
		v->handle[dir][bno] =
		    phys_to_dma(tdmdev, virt_to_phys(v->super[dir][bno]));
	}

	if (!v->super[dir][bno])
		return -ENOMEM;

	v->super[dir][!bno] = v->super[dir][bno] + size64;
	v->handle[dir][!bno] = v->handle[dir][bno] + size8;
	v->supersize[dir] = size8;

	for (i = 0; i < 2; i++) {
		u8 tag;

		tvd("bno%d sbase:%p hbase:%llx sz:%lx\n",
			i, v->super[dir][i], v->handle[dir][i], size8);

		/* init all to TDM idle pattern, revealing origin */
		if (!v->super[dir][0])
			continue;
		tag = 0xa0 + 0x10 * v->vno + 2 * dir + i;
		memset(v->super[dir][i], tag, size8);
	}

#ifdef SPARSE_SLOTS
	v->slop[dir] = devm_kcalloc(tdmdev, eslots,
				    sizeof(v->slop[0][0]), GFP_KERNEL);
#endif /* SPARSE_SLOTS */

	if (!v->slop[dir])
		goto fail;

	return 0;

fail:
	tdm_exit(vno, dir);
	return -ENOMEM;
}

static int tdm_init(int vno, int dir)
{
	int err = chk_clk(vno, c_on, 0);
	struct tdm_bus *v = &veng[vno];

	if (err)
		return err;

	if (v->super[dir][0])
		return 0;

	err = tdm_setbuf(vno, dir);
	v->valid_flows = !err;

	if (err)
		tdm_exit(vno, dir);
	return err;
}

static struct tdm_slot *tdm_create_slot(struct tdm_bus *v,
	struct tdm_sess *sess,
	int sno, int sample_bytes, size_t fifo_sz,
	int dir, tdm_actor actor)
{
	struct tdm_slot *s;
	unsigned long flags;
	int vno = v->vno;
	bool newslot = false;

	if (!fifo_sz || fifo_sz > MAX_FIFO)
		fifo_sz = MAX_FIFO;

	if (sno < 0 || sample_bytes < 1 ||
			sno + sample_bytes > v->max_slots[dir])
		return NULL;

#ifdef SPARSE_SLOTS
	if (!v->slop[dir])
		return NULL;
	s = v->slop[dir][sno];
	newslot = !s;
	if (newslot) {
#ifdef FIXED_FIFO_SUPERS
		s = kzalloc(sizeof(*s), GFP_KERNEL);
#else /* !FIXED_FIFO_SUPERS */
		s = kzalloc(sizeof(*s) + sizeof(s->fifo[0]) * fifo_sz,
			    GFP_KERNEL);
#endif /* !FIXED_FIFO_SUPERS */
	}
	if (!s)
		return NULL;
#else /* !SPARSE_SLOTS */
	s = &v->slop[dir][sno];
#endif /* !SPARSE_SLOTS */

	spin_lock_irqsave(&TDM_LOCK(v), flags);

	if (newslot) {
		/* suppress re-init to minimise close() sync */
		init_waitqueue_head(&s->fifo_have_content);
		init_waitqueue_head(&s->fifo_have_space);
	}
	s->sno = sno;
	s->sample_bytes = sample_bytes;
	s->vno = vno;
	s->dir = dir;
	s->actor = actor;
	s->closing = false;
	s->active = true;
	s->sess = sess;
	s->fifo_sz = fifo_sz;
	s->data_off = 0;
	s->free_off = 0;

	/* 1st rx-irq will have invalid data */
	s->skip = FRAMES(v, dir) / irqs_per_wrap;

#ifdef SPARSE_SLOTS
	v->slop[dir][sno] = s;
#endif /* SPARSE_SLOTS */

	spin_unlock_irqrestore(&TDM_LOCK(v), flags);


	return s;
}

static void tdm_destroy_slot(struct tdm_slot *s, int dir)
{
	unsigned long flags;
	struct tdm_bus *v = NULL;
	int sno, vno;

	if (!s)
		return;

	vno = s->vno;
	sno = s->sno; /* insecure, just for logging */


	if (!chk_vno(vno)) {
		struct tdm_sess *sess;

		v = &veng[vno];
		spin_lock_irqsave(&TDM_LOCK(v), flags);
		sno = s->sno; /* re-get under lock */
		sess = s->sess;

		if (sess)
			sess->slot[dir] = NULL;
		s->sess = NULL;

#ifdef SPARSE_SLOTS
		if (v->slop[dir] && v->slop[dir][sno]) {
			WARN_ON_ONCE(v->slop[dir][sno] != s);
			if (1) /* freed inly in tdm_exit() */
				s->active = false;
			else
				v->slop[dir][sno] = NULL;
		}
#endif /* SPARSE_SLOTS */
		spin_unlock_irqrestore(&TDM_LOCK(v), flags);
	}

#ifdef SPARSE_SLOTS
	kfree(s);
#else /* !SPARSE_SLOTS */
#endif /* !SPARSE_SLOTS */
}

/* setup v->dc's Tx-FIFO params */
static void set_txfifo(struct tdm_bus *v)
{
	/* defaults work well, but can be tweaked */
	if (!fetch_size || (unsigned int)fetch_size >= 16)
		fetch_size = 8;
	if (!fetch_thresh || (unsigned int)fetch_thresh >= 16)
		fetch_thresh = 8;
	v->dc.s.fetchsiz = fetch_size - 1;
	v->dc.s.thresh = fetch_thresh;
}

/* setup everything but tx/rxslots */
/* caller holds lock */
static union cavium_tdm_dma_cfg _setup_hw_dc(struct tdm_bus *v,
		int bno, int eno, int line)
#define setup_hw_dc(v, bno, eno) _setup_hw_dc(v, bno, eno, __LINE__)
{
	int rxslots = 0;
	int txslots = 0;
	u64 pcmRxCount = 0;
	u64 pcmTxCount = 0;

	v->dc.s.useldt = (useldt >> eno);

	set_txfifo(v);

	v->dc.s.rxst = FRAMES(v, rx) / irqs_per_wrap;
	v->dc.s.txrd = FRAMES(v, tx) / irqs_per_wrap;

	if (v->super[rx][bno])
		pcmRxCount = SUPERS(v, rx);

	if (v->super[tx][bno])
		pcmTxCount = SUPERS(v, tx);

	_cvmx_write_csr(CVMX_PCMX_RXCNT(eno), pcmRxCount);
	_cvmx_write_csr(CVMX_PCMX_TXCNT(eno), pcmTxCount);

	/* Set the TDM params but do not yet enable it.  */
	v->dc.s.txslots = txslots;
	v->dc.s.rxslots = rxslots;

	return v->dc;
}

/* (re)init TDM hw engine when tx/rx first enabled */
/* caller holds lock */
static int tdm_hw_init(struct tdm_bus *v)
{
	int vno = v->vno;
	bool eb = v->eb;
	struct tdm_engine *e = v->e[eb];
	int eno;
	struct tdm_flow *f;
	int err = chk_clk(vno, c_on, 0);
	union cavium_tdm_cfg tc;
	int m;

	if (err)
		return err;
	if (!e)
		return -EINVAL;
	f = e->flows;
	if (!f)
		return -EINVAL;

	eno = e->eno;
	tc = v->tc; /* clone from current settings */
	tc.s.enable = 0;

	setup_hw_dc(v, eb, eno);

	/* HW zeroing is the only place 8 is used rather than MASK_REGS */
	for (m = 0; m < 8; m++) {
		u64 tm = 0, rm = 0;
		int hw = m;

		if (m < MASK_REGS) {
			tm = f[tx].fmask[m];
			rm = f[rx].fmask[m];
		}
		_cvmx_write_csr(CVMX_PCMX_TXMSKX(hw, eno), tm);
		_cvmx_write_csr(CVMX_PCMX_RXMSKX(hw, eno), rm);
	}

	v->tc = tc;

	return err;
}

/* Rx path Consumer: read samples from fifo, waiting as needed for IRQ */
static int tdm_reader(struct tdm_slot *s, __user char *samples, int len)
{
	int err = -EIO;
	bool sig = false;
	int done = 0;

	if (!s)
		return 0;
	if (s->closing) {
		wake_up(&s->fifo_have_space);
		return 0;
	}

	/* TODO: remove aligned-to-superframe restriction? */
	while (len >= s->sample_bytes) {
		int start = s->data_off & tdm_fifo_mask(s);
		int chunk, remain;

		if ((start + len) > s->fifo_sz)
			len = s->fifo_sz - start;

		err = wait_event_interruptible(s->fifo_have_content,
				   tdm_fifo_content(s) >= s->sample_bytes);
		if (err)
			sig = signal_pending_state(TASK_INTERRUPTIBLE, current);

		tr_tdm(t_read | t_err * (err && err != -ERESTARTSYS),
		       "tdm%d wait(non_empty) err %d, space %x @%p\n",
		       s->vno, err, tdm_fifo_content(s), samples);
		if (err)
			return sig ? -EINTR : err;

		chunk = len;
		if (chunk > tdm_fifo_content(s))
			chunk = tdm_fifo_content(s);

		remain =
		    copy_to_user((__user char *)samples,
				 (char *)&s->fifo[start], chunk);
		chunk -= remain;
		tr_tdm(t_read, "tdm%d copied %x/%x e=%d\n",
			s->vno, chunk, len, remain);

		samples += chunk;
		done += chunk;
		len -= chunk;

		s->data_off += chunk;
		wake_up(&s->fifo_have_space);
	}

	if (done)
		tr_tdm(t_read,
			"tdm%d done=%d space=%x data=%x free=%x err=%d\n",
		       s->vno, done, tdm_fifo_space(s),
		       s->data_off, s->free_off, err);

	return done;
}

/*
 * Tx path Producer: write samples to fifo,
 * waiting while fifo full until IRQ drains it
 */
static int tdm_writer(struct tdm_slot *s, const __user char *samples, int len)
{
	int err = -EIO;
	bool sig = false;
	int done = 0;

	if (!s || s->sample_bytes <= 0)
		return 0;
	if (s->closing) {
		wake_up(&s->fifo_have_content);
		return 0;
	}

	/* TODO: remove aligned-to-superframe restriction? */
	while (len > 0 && len >= s->sample_bytes) {
		int start = s->free_off & tdm_fifo_mask(s);
		int chunk, remain;

		tr_tdm(t_write, "tdm%d space=%d data=%x free=%x\n",
		       s->vno, tdm_fifo_space(s), s->data_off, s->free_off);
		err = wait_event_interruptible(s->fifo_have_space,
			       tdm_fifo_space(s) >= s->sample_bytes);
		if (err)
			sig = signal_pending_state(TASK_INTERRUPTIBLE, current);

		tr_tdm(t_write | t_err * (err && err != -ERESTARTSYS),
		       "tdm%d wait(non_full) err %d, space %x\n",
		       s->vno, err, tdm_fifo_space(s));
		if (err)
			return sig ? -EINTR : err;

		chunk = tdm_fifo_space(s);
		if (chunk > len)
			chunk = len;

		if ((start + chunk) > s->fifo_sz)
			chunk = s->fifo_sz - start;

		tr_tdm(t_write, "tdm%d copy_from_user %x/%x ...\n",
			s->vno, chunk, (int)len);
		remain =
		    copy_from_user((char *)&s->fifo[start], samples, chunk);
		tr_tdm(t_write, "tdm%d copied %x/%x e=%d\n",
			s->vno, chunk, (int)len, remain);
		chunk -= remain;
		len -= chunk;
		samples += chunk;
		done += chunk;

		s->free_off += chunk;
		wake_up(&s->fifo_have_content);
	}

	tr_tdm(t_write, "tdm%d done=%d space=%x data=%x free=%x\n",
	       s->vno, done, tdm_fifo_space(s), s->data_off, s->free_off);

	return done;
}

/* caller should have sync'd tx/rx to same wrapped-state */
static inline void poll_change(struct tdm_engine *e, bool dir, bool wrap)
{
	int eno = e->eno;
	struct tdm_bus *v = e->v;
	struct tdm_flow *fa = FALL(v);
	int changing = (v->hands > s_normal);

	/* if change pending, prestage to start one frame after wrap */
	if (!changing && (fa[tx].changed || fa[rx].changed)) {
		changing = 2;

			/*
			 * start the handover setup right now,
			 * so things are in place to begin handover at wrap
			 */
		next_clone(v, eno, wrap ? ev_xfer : ev_wrap);
	}
}


/* cycle flow status fall->fcur->fold after hw changed */
/* caller holds lock */
static void update_flows(struct tdm_bus *v)
{
	bool eb = v->eb;
	struct tdm_engine *e = v->e[eb];
	/* without dynamic-slot complexity this code can be simplified */
	bool newgen = true;
	bool set_hw = true;
	int dir, m;

	switch (v->hands) {
	case s_jump:
		tdm_irq_enable(e->eno, tdm_txwrap | tdm_rxwrap);
		v->waitfor |= evmask(e->eno, both, ev_wrap);
		NEW_STATE(v, s_normal);
		wake_up(&v->mask_event);
		mark_done();
		break;
	default:
		break;
	}

	/*
	 * new slotmap generation: sample action
	 * sample: snapshot FALL(v) into FNEW(v)
	 */
	for (dir = 0; dir < DIRS; dir++) {
		/* seed FNEW with current FALL, under sem_bind*/
		FALL(v)[dir].changed |= FNEW(v)[dir].changed;
		FALL(v)[dir].fgen = v->fgen + 1;
		FNEW(v)[dir] = FALL(v)[dir];
		FALL(v)[dir].changed = 0;
		/* can release sem_bind now */
		FNEW(v)[dir].bno = FOLD(v)[dir].bno;
	}

	/*
	 * include any always-Rx mask bits.
	 * Policy here might include
	 * - first/last bits to ensure reliable rxwrap signal
	 * - all Tx'd bits, for loopback checking
	 * - every slot, if WIDE(v), to reduce mask churn
	 * This is the point such considerations are introduced,
	 * with FALL() knowing nothing of them, so tdm_enable()
	 * can use the bitmasks for simple availability check.
	 */
	for (dir = 0; dir < DIRS; dir++) {
		for (m = 0; m < ARRAY_SIZE(FNEW(v)[rx].fmask); m++) {
			u64 extra = 0;
			int ecount;

			if (v->fixed) {
				extra |= v->sslot.mask[dir][m];
				if (LOOP(v->vno))
					extra |= v->sslot.mask[rx][m];
			}
			extra |= FNEW(v)[tx].fmask[m];
			if (LOOP(v->vno))
				extra &= ~FNEW(v)[rx].fmask[m];
			if (extra) {
				ecount = hweight64(extra);
				if (LOOP(v->vno)) {
					FNEW(v)[rx].fslots += ecount;
					FNEW(v)[rx].fmask[m] |= extra;
				}
			}

			/* TODO: merge more of above into for()? */
			for_dir(dir) {
				if (FNEW(v)[dir].fmask[m] !=
				    FCUR(v)[dir].fmask[m])
					set_bit(m, &FNEW(v)[dir].changed);
			}

		}
	}

	/*
	 * new slotmap generation: newgen action
	 * cycle the flow generations, copying current FALL allocation
	 * map to FNEW, old FNEW to FCUR, old FCUR to FOLD
	 * (caller holds sem_bind to block changes)
	 * Because this is done by fgen++, which is referenced within
	 * all the Fxxx(v), new symbolic access gets new flow.
	 * But existing engine's e->flows remain unchanged, although
	 * their name becomes FOLD(v).
	 * A new FALL() is seeded from the old.
	 * FNEW copied to FCUR (we have too many states don't need all 4).
	 */
	if (newgen) {
		/* fgen++ jumps the Fxxx() pointers,
		 * flowing FOLD <- FCUR <- FNEW = FALL.
		 */

		v->fgen = FNEW(v)[0].fgen;
		/* old FNEW now FCUR */

		for (dir = 0; dir < DIRS; dir++) {
			FNEW(v)[dir].fgen = v->fgen + 1;
			FALL(v)[dir].fgen = v->fgen + 1;
		}
	}

	/* simplify startup or s_jump by update-in-place */
	if (set_hw) {
		bool b;
		struct tdm_flow *f = FCUR(v);

		f[tx].clksel = v->clksel;
		f[rx].clksel = v->clksel;
		b = f[0].bno;
		e->flows = f;
		v->eb = b;

		tdm_hw_init(v);
		change_mappings(e, v->hands == s_jump);

		v->dc = write_dc(e->eno, v->dc);
	}

	wake_up(&v->mask_event);
}

/*
 * change_mapping: move to the new slot-map flow 'fnew'
 * Done at the last IRQ before buffer-wrap, so the DMA between old map
 * and user FIFOs is completed, because we're switching to new 'flow'
 * comprising start/cnt/msk registers.
 * Also called from tdm_enable() when first slot activated
 * Caller holds lock.
 */
/* caller holds lock */
static inline bool change_mapping(struct tdm_engine *e, int dir, bool first)
{
	struct tdm_bus *v = e->v;
	struct tdm_flow *f = &e->flows[dir];
	bool bno = f->bno;
	dma_addr_t handle = v->handle[dir][bno];
	u64 *mask;
	int m;
	union cavium_tdm_dma_cfg dc;
	int eno, slots;

	eno = e->eno;
	dc = v->dc;

	/* intentional type pun: fmask is unsigned long for bitops */
	mask = (u64 *)f->fmask;

	/* bring in the changed slot masks, acted on at buffer wrap */
	for (m = 0; m < MASK_REGS; m++) {
		int hw = m;

		if (!test_and_clear_bit(m, &f->changed))
			continue;
		if (IsTx(dir)) {
			_cvmx_write_csr(CVMX_PCMX_TXMSKX(hw, eno),
				mask[m]);
		} else {
			_cvmx_write_csr(CVMX_PCMX_RXMSKX(hw, eno),
				mask[m]);
		}
	}
	await_rdpend(e->eno);

	if (IsTx(dir)) {
		if (f->fslots) {
			_cvmx_write_csr(CVMX_PCMX_TXSTART(eno), handle);
			if (first)
				_cvmx_write_csr(CVMX_PCMX_TXCNT(eno),
					SUPERS(v, dir));
		}
	} else {
		if (f->fslots) {
			_cvmx_write_csr(CVMX_PCMX_RXSTART(eno), handle);
			if (first)
				_cvmx_write_csr(CVMX_PCMX_RXCNT(eno),
					SUPERS(v, dir));
		}
	}

	slots = STRIDE(f, dir);
	e->sbase[dir] = v->super[dir][bno];
	e->hbase[dir] = handle;
	e->hend[dir] = handle + slots * FRAMES(v, dir);
	e->half[dir] = (handle + e->hend[dir]) / 2;


	await_rdpend(eno);

	v_dc(v, dc);

	if (!STRIDE(f, dir))
		tdm_irq_enable(eno, tdm_clkbits | xxwrap[dir]);
	else
		tdm_irq_disable(eno, xxwrap[dir]);

	return true;
}

/* caller holds lock */
static bool change_mappings(struct tdm_engine *e, bool first)
{
	struct tdm_bus *v;
	struct tdm_flow *f;
	bool changed;

	v = e->v;
	f = e->flows;
	changed = change_mapping(e, rx, first)
			| change_mapping(e, tx, first);

	if (changed) {
		v->dc.s.txslots = STRIDE(&f[tx], tx);
		v->dc.s.rxslots = STRIDE(&f[rx], rx);
		v_dc(v, write_dc(e->eno, v->dc));
	}
	return changed;
}

/*
 * jump_cut() - single-engine dynamic slotmap change (proxy==0)
 * try to change geometry, return false if timing wrong
 */
/* caller holds lock */
static bool jump_cut(struct tdm_bus *v)
{
	bool flip = change_mappings(v->e[0], false);

	if (flip)
		update_flows(v);

	flog(v, flip ? "jump completed" : "jump aborted");

	return flip;
}

/*
 * tx/rx IRQs happen at 2x buffer-wrap rate*.
 * When wrap is signalled, DMA has moved to beginning of buf,
 * so driver processes 2nd half.
 * When non-wrap IRQ happens, and DMA is seen to be in 2nd half,
 * driver processes 1st half.
 * To ensure 1st half is only processed once in a cycle, use
 * e->wrapped to only process 1 eligible txrd/rxst.
 * (* 2x wrap rate when irqs_per_wrap==2, but code not generalized
 *    for number != 2. Can't see a reason to generalize)
 */

/* handle single engine's signalled irq, called from wrappers below */
static inline
irqreturn_t __tdm_handle_irq(struct tdm_engine *e,
	u8 sum, u8 ena)
{
	ktime_t tstart = ktime_get_boottime();
	u64 ns_since_wrap[DIRS] = {0, 0};
	int eno = e->eno;
	union cavium_tdm_dma_cfg dc = read_dc(eno);
	struct tdm_bus *v = e->v;
	int vno, dir;
	int old_state;
	bool primary;
	u64 oldwait;
	u64 trigger = 0;

	/* state tracing useful in dynamic bus/engine handover */
	e->lastirqs <<= 12; /* shift the fifo of { u4 state; u8 irqsum; } */
	e->lastirqs |= sum;

	if (v) {
		spin_lock(&TDM_LOCK(v));
		e->lastirqs |= ((v->hands & 0xf) << 8);
	}

	primary = v && (e->flows && e->flows[0].bno == v->eb);

	/* "cannot happen" IRQ after engine dead/detached? */
	if (!v || v != e->v || (v->hands <= s_normal && !primary)) {
		union cavium_tdm_cfg tc;

		tdm_irq_disable(eno, tdm_irqall);
		tc = read_tc(eno);
		tc.s.enable = 0;
		write_tc(eno, tc);
		tdm_irq_ack(eno, sum);
		tf("irq%d s_unpair e%d with NO VNO\n", eno, eno);
		if (v)
			spin_unlock(&TDM_LOCK(v));
		goto bye;
	}

	vno = v->vno;
	oldwait = v->waitfor;
	old_state = v->hands;

	e->cumsum |= sum;
#ifdef CONFIG_CAVIUM_TDM_DEBUG
	e->_irqstate[sum]++;
#endif
	tdm_irq_ack(eno, sum);

	if (sum & tdm_clkbits) {
		union cavium_tdm_cfg tc;

		ten("v%d.fsync err %x\n", vno, sum);
		tc = read_tc(eno);

		/* stop/restart engine */
		tc.s.enable = 0;
		write_tc(eno, tc);
		tc.s.enable = 1;
		write_tc(eno, tc);
		tv("FSYNC err %s w%llx toggle e%dtc.enable /%llx\n",
			s_s(v->hands), v->waitfor, eno, e->lastirqs);
	}

	if (!e->flows) {
		pstat[vno][0].noflo++;
		goto unlock;
	}


	/* turn off unused engines */
	if (old_state == s_off) {
		tdm_irq_disable(eno, tdm_irqall);
		v->tc.s.enable = 0;
		write_tc(eno, v->tc);
		tdm_irq_ack(eno, sum);
		goto unlock;
	}

	/* note any state-machine triggers */
	if (sum & tdm_txrd)
		trigger |= evmask(eno, tx, ev_xfer);
	if (sum & tdm_rxst)
		trigger |= evmask(eno, rx, ev_xfer);
	if (sum & tdm_txwrap)
		trigger |= evmask(eno, tx, ev_wrap);
	if (sum & tdm_rxwrap)
		trigger |= evmask(eno, rx, ev_wrap);

	for_dir(dir) {
		if (sum & xxdma[dir])
			ns_since_wrap[dir] = ktime_to_ns(
				ktime_sub(tstart, e->twrap[dir]));
		if (sum & xxwrap[dir])
			e->twrap[dir] = tstart;
	}


	/* now sequence any engine re-plumbing which had been waiting */
	if (v->waitfor || old_state > s_normal) {
		v->waitfor &= ~trigger;
		trigger &= oldwait;


		/* precisely one action expected - consider rework */
		if (!v->waitfor && (trigger & (ev_any_dir * ev_wrap))) {
			tdm_irq_disable(e->eno, tdm_txwrap | tdm_rxwrap);
			update_flows(v);
			NEW_STATE(v, s_normal);
		}
	}

	/*
	 * BEWARE of handover action(), side-effects:
	 * if v->hands==s_unpair, we may no longer own e,
	 * or be part of v, but still hold lock.
	 */
	primary = (e->flows && e->flows[0].bno == v->eb);

	/*
	 * handle per-direction DMA actions.
	 * TODO: some dup'd above/below, not yet weeded
	 * do rx first for handover timing stability
	 */
	for_rx_tx(dir, e && e->flows) {
		struct tdm_flow *f = &e->flows[dir];
		int frames = FRAMES(v, dir);
		void *sbase = e->sbase[dir];
		dma_addr_t hbase = e->hbase[dir];
		dma_addr_t hwhere;
		u64 awhere = IsTx(dir) ?
			CVMX_PCMX_TXADDR(eno) : CVMX_PCMX_RXADDR(eno);
		int stride;
		bool dma_ready = (sum & xxdma[dir]);
		bool wrapped = (sum & xxwrap[dir]);
		bool sw_top, hw_top;

		if (!(sum & xxbits[dir])) {
			if (sum & xxbits[!dir])
				continue;
			if (!v->waitfor && !primary && v->hands <= s_normal)
				goto revoke_both;
		}

		if (v->hands == s_off)
			goto silent_revoke_both;

		if (!primary && !v->waitfor)
			goto revoke_both;

		if (!f)
			goto revoke;

		stride = STRIDE(f, dir);

		if (!sbase || !stride)
			goto revoke;

		pstat[vno][dir].irqs++;

		hwhere = _cvmx_read_csr(awhere);
#ifdef CONFIG_MIPS
		/* for octeon before cn70p2.0, beware errata#16276
		 *  "TXRD irq happens 1-byte early"
		 * so must decrement hwhere (modulo wrap)
		 */
		if ((OCTEON_IS_MODEL(OCTEON_CN70XX_PASS1_0) ||
		     OCTEON_IS_MODEL(OCTEON_CN70XX_PASS1_1)) &&
				hwhere > e->hbase[dir])
			hwhere--;
#endif /* MIPS */

		hw_top = (hwhere >= e->half[dir]);
		sw_top = !hw_top;
		poll_change(e, dir, sw_top);


		if (dma_ready)
			trigger |= evmask(eno, dir, ev_xfer);
		if (wrapped)
			trigger |= evmask(eno, dir, ev_wrap);


		if (!dma_ready && !wrapped)
			pstat[v->vno][dir].nops++;

		pstat[vno][dir].irqs += (sum & ena & xxdma[dir]);

		if (sum & xxovf[dir]) {
			pstat[vno][dir].drops++;
			tr_tdm(t_pump, "tdm%de%d %s err\n",
				vno, eno,
				IsTx(dir) ? "txempty" : "rxovf");
			tdm_irq_ack(eno, xxovf[dir]);
		}


		/* TODO: merge tx/rx here... */
		if (IsTx(dir)) {
			if (!(sum & (tdm_txempty|tdm_txrd))
					&& (ena & tdm_txwrap)) {
				tdm_irq_enable(eno, tdm_clkbits | tdm_txbits);
				if (v->hands == s_normal)
					tdm_irq_disable(eno, tdm_txwrap);
			}
		} else {
			if (!(sum & tdm_rxst) && (ena & tdm_rxwrap)) {
				tdm_irq_enable(eno, tdm_clkbits | tdm_rxst);
				if (v->hands == s_normal)
					tdm_irq_disable(eno, tdm_rxwrap);
			}

			hwhere = _cvmx_read_csr(awhere);
		}

		/*
		 * Per-direction transfer & de-dup actions,
		 * processing any half-buffer DMA service:
		 *
		 * General case: process the half-buffer the DMA
		 *   cursor is _not_ in. Because txrd/rxst counts are
		 *   half of (hend - hbase) we know sw can process
		 *   half buffer each time hw throws xxdma[dir] event
		 *
		 * Handover-Begin/-End cases: removed
		 */
		if (dma_ready) {
			int chunk = frames / irqs_per_wrap;
			int half = chunk * stride;
			int offset = half * sw_top;

			dma_xfer(e, dir, f->bno,
				stride, chunk,
				sbase + offset,
				hbase + offset);
		}

		if (sum & xxdma[dir])
			e->wrapped[dir] = sw_top;

		tr_tdm(t_pump,
			"tdm%de%d-%s w%d sum:%lld drops:%lld hang:%lld\n",
			vno, eno, DirStr(dir),
			dma_ready,
			pstat[vno][dir].sum,
			pstat[vno][dir].drops,
			pstat[vno][dir].hang);

		continue;

silent_revoke_both:
		tdm_irq_disable(eno, tdm_irqall);
		break;

revoke_both:
		tdm_irq_disable(eno, xxbits[!dir]);
		goto revoke;

revoke:
		tdm_irq_disable(eno, xxbits[dir]);
	}

	/* pre-process fnew[tx] on v->e[!eb] */
	if (old_state == s_jump && !e->wrapped[rx]) {
		jump_cut(v);

		/* v->waitfor |= NOTHING, as dance is over */
		NEW_STATE(v, s_normal);

		mark_done();
	}

unlock:
	spin_unlock(&TDM_LOCK(v));

	/* should this happen here, or after wrap event signaled by hw? */
	wake_up(&v->mask_event);

	/*
	 * Log any IRQs recurring before return.
	 * These could indicate event loss, if they correlate with other
	 * issues. By themselves, they're not necessarily a problem.
	 * The expected chatter of handover mode is demoted to a
	 * non-logging count in missed[!warn]++
	 */
	sum &= cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
	if (sum) {
		int warn = true;

		dc = read_dc(eno);

		if (warn)
			ten("pending:%x txrd:%d rxst:%d v%df%d%s /%llx\n",
				sum, dc.s.txrd, dc.s.rxst,
				vno, v->fgen, s_s(v->hands), e->lastirqs);
		if (sum & tdm_rxbits)
			pstat[vno][rx].missed[warn]++;
		else
			pstat[vno][tx].missed[warn]++;
	}

bye:
	return IRQ_HANDLED;
}

#ifdef ONE_TDM_IRQ
static irqreturn_t tdm_handle_all(int irq, void *irqaction)
{
	unsigned int eno;
	irqreturn_t any = IRQ_NONE;

	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		struct tdm_engine *e = &eng[eno];
		struct tdm_bus *v = e->v;
		u8 sum;
		u8 ena;

		if (!v || !v->tc.s.enable)
			continue;
		sum = _cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
		eng[eno].sum = sum;
		ena = _cvmx_read_csr(CVMX_PCMX_INT_ENA(eno));
		eng[eno].ena = ena;
		if (sum & ena)
			any |= __tdm_handle_irq(e, sum, ena);
	}

	if (0)
		return any;
	return IRQ_HANDLED;
}

#else /* !ONE_TDM_IRQ */

static irqreturn_t tdm_handle_one(int irq, void *irqaction)
{
	struct tdm_engine *e = irqaction;
	int eno = e->eno;
	u8 sum;
	u8 ena;

	sum = cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
	eng[eno].sum = sum;
	ena = cvmx_read_csr(CVMX_PCMX_INT_ENA(eno));
	eng[eno].ena = ena;

	return __tdm_handle_irq(e, sum, ena);
}
#endif /* !ONE_TDM_IRQ */

/* detach DMA channels from open file */
/* caller holds sem_bind */
static void tdm_unbind(struct file *f)
{
	struct tdm_sess *sess = f->private_data;
	int dir;

	for (dir = 0; sess && dir < DIRS; dir++) {
		struct tdm_slot *sl = sess->slot[dir];
		struct tdm_bus *v = sess->v;

		if (!sl || !v)
			continue;

		/* wait for tx drain: interrupt here only truncates tx data */
		if (IsTx(dir))
			wait_event_interruptible(sl->fifo_have_space,
				tdm_fifo_content(sl) < sl->sample_bytes
				|| !sl->active
				|| (current->flags & PF_EXITING));

		/* unmap from fnew */
		sl->closing = true;
		tdm_enable(f, dir, false, sl->sno, sl->sample_bytes);
		geom_stats(v, sess);
		tdm_destroy_slot(sl, dir);
	}

	if (sess)
		sess->bound = false;
}

/* (re)attach DMA channels to an open file, begins the geometry dance */
/* caller holds sem_bind, dropped on success */
static int tdm_up(struct tdm_bus *v, bool *upped)
{
	int err = 0;

	/* Need to launch first-time setup? */
	if (!v->tc.s.enable) {
		/*
		 * we already hold "sem_bind" from ioctl.
		 * drop early to allow parallel setup/teardown
		 * to cluster here, and execute in parallel
		 */
		up(&v->sem_bind);
		*upped = true;

		/* kickstart() success registers change, completed async */
		err = kickstart(v);
		if (!err)
			return 0;
	}

	return err;
}

static int chk_tx(struct file *f)
{
#ifdef CONFIG_ARM64
	/* CN81XX pass 1.0/1.1 may not safely Tx on engines 1..3 */
	/* vno == eno in this case, as proxy=0 forced */
	struct tdm_sess *sess = f->private_data;
	struct tdm_bus *v = sess->v;
	int vno = v->vno;

	if (vno > 0 && tx0only) {
		static unsigned long warned;

		if (!test_and_set_bit(vno, &warned))
			pr_err("tdm%d Tx binding not supported\n", vno);

		return -EIO;
	}
#endif

	return 0;
}

/* (re)attach DMA channels to an open file, begins the geometry dance */
/* caller holds sem_bind, dropped on success */
static int tdm_bind_up(struct file *f, union cavium_tdm_bind *b, bool *upped)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_bus *v = sess->v;
	int slots = b->s.slots;
	int fifo_log = MAX_FIFO_LOG;
	int fifo_sz;
	int err = chk_tx(f);

	if (!b->s.no_tx && err) {
		if (!*upped)
			up(&v->sem_bind);
		*upped = true;
		return err;
	}

	if (b->s.log2fifo && b->s.log2fifo < fifo_log)
		fifo_log = b->s.log2fifo;
	fifo_sz = (1 << fifo_log);

	/* check but do not act on binding */
	err = chk_slots(f, b);
	if (err)
		goto teardown;

	/* amending a binding does most of a close() */
	if (sess->bound)
		tdm_unbind(f);

	sess->geom_start[1] = ktime_get_boottime();

	/* impose the binding on hw */
	if (!b->s.no_rx) {
		int sno = b->s.rslot;

		err = tdm_enable(f, rx, true, sno, slots);
		if (err)
			goto teardown;
		sess->slot[rx] =
		    tdm_create_slot(v, sess, sno, b->s.slots,
				    fifo_sz, rx, read_actor);
	}
	if (!b->s.no_tx) {
		int sno = b->s.wslot;

		err = tdm_enable(f, tx, true, sno, slots);
		if (err) {
			if (!b->s.no_rx) {
				struct tdm_slot *sl =
					sess->slot[rx];

				tdm_enable(f, rx, false, b->s.rslot, slots);
				tdm_destroy_slot(sl, rx);
			}
			goto teardown;
		}
		sess->slot[tx] =
		    tdm_create_slot(v, sess, sno, b->s.slots,
				    fifo_sz, tx, write_actor);
	}

	err = tdm_up(v, upped);

teardown:
	return err;
}

/* start engine from cold, if appropriate (NOT holding lock) */
static inline int kickstart(struct tdm_bus *v)
{
	unsigned long flags;
	union cavium_tdm_cfg tc;
	bool bnew;
	struct tdm_engine *e;
	struct tdm_flow *f;

	spin_lock_irqsave(&TDM_LOCK(v), flags);
	tc = v->tc;
	bnew = v->eb;  /* reuse engine */
	e = v->e[bnew];

	if (!e) {
		v->eb ^= 1;
		e = v->e[v->eb];
	}
	if (!e) {
		spin_unlock_irqrestore(&TDM_LOCK(v), flags);
		return -EIO;
	}

	/*
	 * If no slots were active, no IRQs will rotate the new slot map in.
	 * But if no slots were active, no map conflicts exist, so safe.
	 */
	NEW_STATE(v, s_jump);
	update_flows(v);

	/* flip v->eb, cycle flow descriptors */
	/* update v->tc/dc with FNEW*/
	tdm_irq_enable(e->eno, tdm_txwrap | tdm_rxwrap);
	v->waitfor |= evmask(e->eno, both, ev_wrap);

	/* lay out TWO initial Tx half-dmabufs */
	f = &FCUR(v)[tx];
	dma_xfer(e, tx, f->bno,
		STRIDE(f, tx), FRAMES(v, tx),
		(u8 *)v->super[tx][f->bno],
		v->handle[tx][f->bno]);

	e->skip_dma[rx] = 3; /* first 3 frames are garbage */

	v->waitfor |= evmask(e->eno, both, ev_wrap);
	enable_engine(e);
	spin_unlock_irqrestore(&TDM_LOCK(v), flags);

	return 0;
}

static inline void tdmgstat(struct tdm_bus *v, struct cavium_tdm_stat *s)
{
	int i;
	struct tdm_flow *f = FCUR(v);
	struct tdm_engine *e = v->e[v->eb];
	int eno = e ? e->eno : 0;
	unsigned long flags;
	u64 *rm = (u64 *)f[rx].fmask;
	u64 *tm = (u64 *)f[tx].fmask;

	spin_lock_irqsave(&TDM_LOCK(v), flags);
	s->ver		= TDM_VER;
	s->int_sum	= e->cumsum;
	e->cumsum	= 0;
	s->rx_supers	= SUPERS(v, rx);
	s->tx_supers	= SUPERS(v, tx);
	s->rxaddr	= cvmx_read_csr(CVMX_PCMX_RXADDR(eno));
	s->txaddr	= cvmx_read_csr(CVMX_PCMX_TXADDR(eno));
	s->rxsize	= f[rx].fslots;
	s->txsize	= f[tx].fslots;
	s->rxlimit	= cvmx_read_csr(CVMX_PCMX_RXCNT(eno));
	s->txlimit	= cvmx_read_csr(CVMX_PCMX_TXCNT(eno));

	for (i = 0; i < ARRAY_SIZE(s->rxmask); i++) {
		s->rxmask[i] = rm[i];
		s->txmask[i] = tm[i];
	}
	spin_unlock_irqrestore(&TDM_LOCK(v), flags);
}

static long tdm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tdm_sess *sess = filp->private_data;
	void __user *uaddr = (void *)arg;
	struct tdm_bus *v = sess ? sess->v : NULL;
	unsigned int vno = v ? v->vno : 0;
	struct tdm_engine *e = NULL;
	int eb, eno = -1;
	union cavium_tdm_clk_cfg cc;
	union cavium_tdm_clk_gen cg;
	union cavium_tdm_cfg tc;
	union cavium_tdm_bind bind;
	struct cavium_tdm_stat stat;
	u64 u_64;
	int ret = chk_vno(vno);
	int clk = which_clk(vno);
	int dir = rx; /* for tx/rx pair ioctls */
	bool early_up = false;
	int mend = CONFIG_CAVIUM_TDM_MAX_SLOTS /
		(8 * sizeof(v->sslot.mask[0][0]));
	int m;
	int totslots = 0;
	bool sticky = false;

	if (!sess)
		return -EINVAL;

	if (ret)
		return ret;

	/* hold vno->eno mapping */
	ret = down_interruptible(&v->sem_bind);

	if (ret)
		return ret;

	ret = -EINVAL;

	/* most ioctl() need a valid engine/bus */
	switch (cmd) {
	/* un-named things need bus AND engine */
	default:
		if (!v)
			goto fail;
		eb = v->eb;
		e = v->e[eb];
		if (!e)
			goto fail;
		eno = e->eno;
		break;

	/* some things need only a bus */
	case TDMGBIND:
	case TDMGCLKCFG_:
	case TDMGCLKGEN_:
	case TDMGCLKCFG:
	case TDMGCLKGEN:
	case TDMGCLKSEL:
	case TDMGFRMHZ:
	case TDMGSCLK:
	case TDMGSTAT:
	case TDMSBIND:
	case TDMSCLKCFG_:
	case TDMSCLKGEN_:
	case TDMSCLKCFG:
	case TDMSCLKGEN:
	case TDMSCLKSEL:
	case TDMSRXBUF:
	case TDMSRXRING:
	case TDMSTIM:
	case TDMSTXBUF:
	case TDMSTXRING:
	case TDMGSSLOT:
	case TDMSSSLOT:
		if (!v)
			goto fail;
		break;

	/* some need neither */
	case TDMGTIM:
	case TDMSDROP:
		break;
	}

	ret = 0;

	switch (cmd) {
	case TDMGCLKCFG_:
	case TDMGCLKCFG:
		cc.u64 = cvmx_read_csr(CVMX_PCM_CLKX_CFG(clk));
		ret = copy_to_user(uaddr, &cc, sizeof(cc));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSCLKCFG_:
	case TDMSCLKCFG:
		sticky = true;
		ret = copy_from_user(&cc, uaddr, sizeof(cc));
		if (ret)
			ret = -EFAULT;
		else
			ret = chk_clk(vno, c_cfg, cc.u64);
		if (!ret)
			cvmx_write_csr(CVMX_PCM_CLKX_CFG(clk),
				clk_cfg[clk].u64);
		pr_debug("ret:%d cc:%llx\n", ret, cc.u64);
		break;
	case TDMGCLKGEN_:
	case TDMGCLKGEN:
		cg.u64 = cvmx_read_csr(CVMX_PCM_CLKX_GEN(clk));
		pr_debug("TDMGCLKGEN tdm%d clk%d %llx\n", vno, clk, cg.u64);
		ret = copy_to_user(uaddr, &cg, sizeof(cg));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSCLKGEN_:
	case TDMSCLKGEN:
		sticky = true;
		pr_debug("TDMSCLKGEN tdm%d clk%d\n", vno, clk);
		ret = copy_from_user(&cg, uaddr, sizeof(cg));
		if (ret)
			ret = -EFAULT;
		else
			ret = chk_clk(vno, c_gen, cg.u64);
		if (!ret)
			cvmx_write_csr(CVMX_PCM_CLKX_GEN(clk),
				clk_gen[clk].u64);
		pr_debug("ret:%d cg:%llx\n", ret, cg.u64);
		break;
	case TDMGTIM:
		tc = v->tc;
		pr_debug("TDMGTIM tdm%d %llx\n", vno, tc.u64);
		ret = copy_to_user(uaddr, &tc, sizeof(tc));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSTIM:
		sticky = true;
		pr_debug("TDMSTIM tdm%d\n", vno);
		ret = copy_from_user(&tc, uaddr, sizeof(tc));
		if (ret)
			ret = -EFAULT;
		if (v->clksel >= 0)
			tc.s.useclk1 = v->clksel;
		if (!ret)
			ret = chk_clk(vno, c_on, 0);
		if (!ret)
			ret = chk_cfg(vno, &tc);
		if (!ret) {
			pr_debug("CVMX_PCM%u_TDM_CFG w %llx\n", vno, tc.u64);
			if (e)
				write_tc(eno, tc);
		}
		break;

		/* other ioctl()s which do not map to registers */
	case TDMGCLKSEL:
		ret = v->clksel;
		pr_debug("TDMGCLKSEL tdm%d e?%d\n", vno, ret);
		if (ret < 0)
			ret = -EINVAL;
		break;

	case TDMSCLKSEL:
		sticky = true;
		pr_debug("TDMSCLKSEL tdm%u clk%lu\n", vno, arg);
		/* allow -1 to un-assign a clock */
		if ((int)arg >= -1 && arg < 2)
			v->clksel = arg;
		else
			ret = -EINVAL;
		break;

	case TDMGFRMHZ:
		pr_debug("TDMGFRMHZ tdm%d\n", vno);
		u_64 = pclk_hz[clk];
		ret = copy_to_user(uaddr, &u_64, sizeof(u_64));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMSTXBUF:
		dir = tx;
		/* flow into ... */
	case TDMSRXBUF:
		sticky = true;
		pr_debug("TDMS%sBUF tdm%d %lx\n", DirStr(dir), vno, arg);
		if (v->max_slots[dir])
			ret = -EPROTO;
		else
			v->max_slots[dir] = arg;
		break;

	case TDMGSTAT:
		pr_debug("TDMGSTAT tdm%d\n", vno);
		tdmgstat(v, &stat);
		ret = copy_to_user(uaddr, &stat, sizeof(stat));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMGBIND:
		pr_debug("TDMGBIND tdm%d\n", vno);
		ret = copy_to_user(uaddr, &bind, sizeof(bind));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSBIND:
		sticky = true;
		pr_debug("TDMSBIND tdm%d\n", vno);
		ret = copy_from_user(&bind, uaddr, sizeof(bind));
		if (ret)
			ret = -EFAULT;
		if (!ret)
			ret = chk_cfg(vno, NULL);
		if (!ret)
			ret = chk_clk(vno, c_on, 0);

		/*
		 * TODO: EBUSY/EAGAIN/etc interaction with NDELAY needed,
		 * on block/non bind/read/write variants?
		 */
		if ((signal_pending_state(TASK_INTERRUPTIBLE, current))
				|| (current->flags & PF_EXITING)) {
			ret = -EINTR;
		} else {
			ret = tdm_bind_up(filp, &bind, &early_up);
		}

		break;

	case TDMGSCLK:
		u_64 = get_sclk();
		pr_debug("TDMGSCLK tdm%d sclk %lld\n", vno, u_64);
		ret = copy_to_user(uaddr, &u_64, sizeof(u_64));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMSTXRING:
		dir = tx;
		/* flow into ... */
	case TDMSRXRING:
		sticky = true;
		pr_debug("TDMS%sRING tdm%d %lx\n", DirStr(dir), vno, arg);
		if (v->ring_frames[dir])
			ret = -EPROTO;
		else if ((arg & 0xf) || arg <= 0 || arg >= (8 << 16))
			ret = -EINVAL;
		else
			v->ring_frames[dir] = arg;
		break;

	case TDMSSILENCE:
		sticky = true;
		*(u32 *)silence = arg;
		break;

	case TDMGSSLOT:
		ret = copy_to_user(uaddr, &v->sslot, sizeof(v->sslot));
		break;

	case TDMSSSLOT:
		/* static slotmap can only be applied before bindings */
		sticky = true;
		pr_debug("TDMSSSLOT tdm%d\n", vno);
		ret = copy_from_user(&v->sslot,
			uaddr, sizeof(v->sslot));

		/* probe for fixed/dynamic conflict, or unsafe Tx */
		if (!ret) {
			u64 tx_msk = 0;
			int tx_unsafe = chk_tx(filp);

			for (m = 0; tx_unsafe && m < mend; m++)
				tx_msk |= v->sslot.mask[dir][m];

			/* Ok unless Tx specified on unsafe engine */
			if (tx_msk)
				ret = tx_unsafe;

			for_dir(dir) {
				struct tdm_flow *fa = &FALL(v)[dir];
				int cnt = 0;

				for (m = 0; m < mend; m++) {
					u64 msk = v->sslot.mask[dir][m];

					cnt += hweight64(msk);
				}

				/* cannot combine fixed/dynamic */
				if (cnt && fa->fslots && !ret)
					ret = -EBUSY;

				totslots += cnt;
			}

			/* fixed mask 0/0 erases old TDMSSSLOT */
			if (!totslots)
				v->fixed = false;
		}

		if (!v->fixed && !ret) {
			for_dir(dir) {
				struct tdm_flow *fa = &FALL(v)[dir];
				int cnt = 0;

				for (m = 0; m < mend; m++) {
					u64 msk = v->sslot.mask[dir][m];

					cnt += hweight64(msk);
					fa->fmask[m] = msk;
				}
				fa->fslots = cnt;
			}
			v->fixed = true;

			/* as with TDMSSBIND, this starts clock */
			ret = chk_dma(vno, NULL);
			if (!ret)
				ret = tdm_up(v, &early_up);
			if (ret == -EIO)
				ret = 0;
		}
		break;

	case TDMSDROP:
		/* static slotmap can only be applied before bindings */
		pr_debug("TDMSDROP tdm%d\n", vno);
		hold(vno, false);
		break;

	default:
		ret = -ENOTTY;
		break;
	}

fail:
	if (!early_up)
		up(&v->sem_bind);

	pr_debug("ioctl(%x) -> %x\n", cmd, ret);

	if (ret >= 0 && sticky)
		hold(vno, true);

	return ret;
}

/* read TDM data from a previously bound (bus, slot, width) */
static ssize_t tdm_read(struct file *f, char __user *u,
			size_t len, loff_t *off)
{
	struct tdm_sess *sess = f->private_data;
	int done;

	if (!sess)
		return -EINVAL;

	tr_tdm(t_read, "READ %d/%x @%llx ...\n", (int)len, (int)len, *off);
	if (!sess || !sess->slot[rx])
		return -EIO;

	done = tdm_reader(sess->slot[rx], u, len);
	if (done > 0 && off)
		*off += done;
	tr_tdm(t_read, "RX %d/%x @%llx ...\n", done, done, *off);
	return done;
}

/* write TDM data to a previously bound (bus, slot, width) */
static ssize_t tdm_write(struct file *f, const char __user *u,
				size_t len, loff_t *off)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_slot *sl;
	int done;

	tr_tdm(t_write, "WRITE %d/%x @%llx ...\n", (int)len, (int)len, *off);
	if (!sess)
		return -EIO;
	sl = sess->slot[tx];
	if (!sl)
		return -EIO;

	done = tdm_writer(sess->slot[tx], u, len);
	if (done > 0 && off)
		*off += done;
	tr_tdm(t_write, "TX %d/%x @%llx ...\n", done, done, *off);

	return done;
}

static int tdm_open(struct inode *i, struct file *f)
{
	struct tdm_sess *sess = NULL;
	int vno = iminor(i);
	struct tdm_bus *v = &veng[vno];
	int err;

	pr_debug("%s tdm%d\n", __func__, vno);

	if (vno >= NR_TDM_BUSES)
		return -EINVAL;

	err = down_interruptible(&v->sem_bind);
	if (err)
		return err;

	err = -ENODEV;

	if (teardown)
		goto teardown;
	err = chk_vno(vno);
	if (err)
		goto teardown;

	err = -ENOMEM;
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		goto teardown;

	sess->v = v;
	f->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	f->private_data = sess;
	err = 0;

teardown:
	up(&v->sem_bind);
	return err;
}

static int tdm_release(struct inode *i, struct file *f)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_bus *v;
	int vno;

	if (!sess)
		return -EINVAL;
	v = sess->v;
	if (!v)
		return 0;
	vno = v->vno;
	sess->geom_start[0] = ktime_get_boottime();
	down(&v->sem_bind);
	tdm_unbind(f);

	if (!test_bit(vno, &held)) {
		sess->v = NULL;
		f->private_data = NULL;
		kfree(sess);
	}

	up(&v->sem_bind);

	return 0;
}

static unsigned int tdm_poll(struct file *f, struct poll_table_struct *p)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_slot *rs, *ws;
	int ready = 0;
	static int was[NR_TDM_ENGINES];
	int vno;

	if (!sess)
		return -EINVAL;

	vno = sess->v->vno;
	rs = sess->slot[rx];
	ws = sess->slot[tx];

	if (rs && tdm_fifo_content(rs) >= rs->sample_bytes)
		ready |= POLLIN;

	if (ws && tdm_fifo_space(ws) >= ws->sample_bytes)
		ready |= POLLOUT;

	was[vno] = ready;

	return ready;
}

static const struct file_operations tdmdrv_fops = {
	.unlocked_ioctl =	tdm_ioctl,
	.read =			tdm_read,
	.write =		tdm_write,
	.open =			tdm_open,
	.release =		tdm_release,
	.poll =			tdm_poll,
};
