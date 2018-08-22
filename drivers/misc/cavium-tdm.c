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
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/sysrq.h>
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

#include <linux/cavium-tdm.h>

#ifdef CONFIG_MIPS
#include <asm/octeon/cvmx.h>
#include <asm/octeon/octeon-model.h>
#include <asm/octeon/octeon-feature.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-sysinfo.h>
#endif /* CONFIG_MIPS */

#ifdef CONFIG_ARM64
/* all corresponding types covered in this file */
#endif /* arm64 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/ioctl.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/poll.h>

#define DEVNAME	"tdm"

static struct proc_dir_entry *proc_tdm;

#ifdef CONFIG_CPU_BIG_ENDIAN
const bool big_endian = 1;
#else
const bool big_endian;
#endif

/* tdm_trace mask bits are ... */
enum {
#ifdef DEBUG
	t_on	= 1,
#else /* no trace code, gcc eliminates at build time */
	t_on	= 0,
#endif /* !DEBUG */
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
	t_init  = t_err,
	/* or'd in if t_change, at geometry change */
	t_detail = t_scan | t_csr | t_pump | t_chan | t_misc | t_rd | t_wr,
};

int tdm_trace = t_init;
module_param_named(trace, tdm_trace, int, 0644);

/* trace_printk logging of interesting events (slot map changes) */
static int old_trace; /* saved trace flags over change-tracing */
static int trace_changes; /* count down on exhaustive logging */

#define tr_tdm(mask, fmt, ...) do { \
	/* unless trace_changes, trace only initial N */ \
	static int once = 50; \
	if (tdm_trace & (mask)) { \
		/* if under t_change, trace forever */ \
		int more = (trace_changes ? 1 : once--); \
		if (more >= 0) { \
			char c = more ? ' ' : '#'; \
			trace_printk("%c%d " fmt, c, __LINE__, ##__VA_ARGS__); \
		} \
	    } \
	} while (0)

#define tf(fmt, ...) tr_tdm(t_misc, fmt, ##__VA_ARGS__)


/* called under lock to mark an "interesting" event */
static inline void __mark_change(void)
{
	if (!(tdm_trace & t_change))
		return;
	if (!old_trace)
		old_trace = tdm_trace;
	tdm_trace |= t_detail;
	trace_changes = 20; /* scans of enhanced tracing */
	tf("tracing on\n");
}

/* called under lock to mark irq-handling done */
static inline void __mark_done(void)
{
	if (trace_changes <= 0)
		return;
	if (--trace_changes)
		return;
	tf("tracing off\n");
	tdm_trace = old_trace;
}

enum {
	/* Direction enumerated for walking over both halves in irq servicing,
	 * or setup/teardown. Doesn't have to map to engine number, but it's a
	 * nice convention. All engines may Tx/Rx/Both, except that Tx on early
	 * cn81xx chips' tdm1..3 will poison other users of IOBN bus (eg bgx)
	 */
	tx_tdm	= 0,
	rx_tdm	= 1,
	TXRX	= 2, /* number of directions, not enum, sizes array[TXRX] */
#define IsTx(d)		((d) == tx_tdm)
#define DirStr(d)	(IsTx(d) ? "tx" : "rx")

	/* how many 8-sample superframes in ring-buffer? */
	/* ... must be divisible by 2, smaller for lower latency */
	/* TODO: make SUPERS runtime settable with TDMS(TX/RX)RING(frames) */
	SUPERS = 16,
	FRAMES = SUPERS * 8,	/* samples in ringbuffer */
	FRAMES_PER_HALF = FRAMES / 2,	/* process 1/2 ring per scan */
	/* irq every SUPERS/2, dma_cfg[rxst,txrd] each IRQ_THRESH */
	IRQS_PER_WRAP = 2, /* Note: explicit factors in code tied to this */
	IRQ_THRESH = FRAMES / IRQS_PER_WRAP,
};

#ifdef CONFIG_MIPS
#include <linux/platform_device.h>
#include <asm/octeon/cvmx-gpio-defs.h>
#endif /*MIPS*/

union cavium_tdm_dma_cfg {
	uint64_t u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		uint64_t rdpend:1;
		uint64_t reserved_54_62:9;
		uint64_t rxslots:10;
		uint64_t reserved_42_43:2;
		uint64_t txslots:10;
		uint64_t reserved_30_31:2;
		uint64_t rxst:10;
		uint64_t reserved_19_19:1;
		uint64_t useldt:1;
		uint64_t txrd:10;
		uint64_t fetchsiz:4;
		uint64_t thresh:4;
#else
		uint64_t thresh:4;
		uint64_t fetchsiz:4;
		uint64_t txrd:10;
		uint64_t useldt:1;
		uint64_t reserved_19_19:1;
		uint64_t rxst:10;
		uint64_t reserved_30_31:2;
		uint64_t txslots:10;
		uint64_t reserved_42_43:2;
		uint64_t rxslots:10;
		uint64_t reserved_54_62:9;
		uint64_t rdpend:1;
#endif
	} s;
};

#ifdef CONFIG_ARM64
static void *tdm_base;
# ifndef DEBUG
#  define cvmx_write_csr(addr, val)	writeq_relaxed(val, (void *)(addr))
# else
#  define cvmx_write_csr(addr, val)	do { \
		void *w_a = (void *)(addr); \
		u64 w_v = (val); \
		tr_tdm(t_csr, "%p w %llx\n", w_a, w_v); \
		writeq_relaxed(w_v, w_a); \
		cvmx_read_csr(w_a); \
	} while (0)
# endif
# define cvmx_read_csr(addr)		readq((void *)(addr))
# define cvmx_phys_to_ptr(v)		((void *)(v))
# define cvmx_write_sync		cvmx_write_csr
#else /* !CONFIG_ARM64 */
# define _cvmx_write_csr(addr, val) do { \
		tr_tdm(t_csr, "%llx w %llx\n", addr, (u64)val); \
		cvmx_write_csr(addr, val); \
	} while (0)
# undef cvmx_write_csr
# define cvmx_write_csr(addr, val)	_cvmx_write_csr(addr, val)
# define cvmx_write_sync(addr, val)	do { \
		u64 _a = (addr); \
		cvmx_write_csr(_a, val); \
		cvmx_read_csr(_a); \
	} while (0)
#endif /* !CONFIG_ARM64 */

static struct device *tdmdev;

/* modparam for forcing major device, or inspecting it */
static int tdmdrv_major;
module_param(tdmdrv_major, int, 0444);

/* LDT usage per engine: (useldt & (1 << eno)) selects temporary cacheline */
static int useldt;
module_param(useldt, int, 0444);

/* if set, adjust DMA fetch size from default of 8 */
static int fetch_size; /* fetch_size == 1 + dma_cfg[fetchsiz] */
module_param(fetch_size, int, 0444);

/* if set, adjust DMA threshold from default of 8 */
static int fetch_thresh;
module_param(fetch_thresh, int, 0444);

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

	pr_debug("tdm: Set system clock to %lld\n", sclk_hz);
	return sclk_hz;
}


#ifdef CONFIG_MIPS
#define TDM_RSIZE (1<<14)
#define CVMX_PCM_CLK0_CFG CVMX_ADD_IO_SEG(0x0001070000010000ull)
#define tdm_base CVMX_PCM_CLK0_CFG
#define CVMX_PCMX_INT_ENA(engine) \
	((u64)tdm_base + 0x20 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM(engine) \
	((u64)tdm_base + 0x28 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM_W1C(engine)	CVMX_PCMX_INT_SUM(engine)
#else
#define TDM_RSIZE (1<<16)
#define CVMX_PCMX_INT_SUM_W1S(engine) \
	((u64)tdm_base + 0x20 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_SUM_W1C(engine) \
	((u64)tdm_base + 0x28 + ((engine) & 3) * TDM_RSIZE)
#define CVMX_PCMX_INT_ENA_W1S(engine) \
	((u64)tdm_base + 0x70 + ((engine) & 3) * TDM_RSIZE)	/*not MIPS */
#define CVMX_PCMX_INT_ENA_W1C(engine) \
	((u64)tdm_base + 0x78 + ((engine) & 3) * TDM_RSIZE)	/*not MIPS */
#define CVMX_PCMX_INT_SUM(engine)	CVMX_PCMX_INT_SUM_W1S(engine)
#define CVMX_PCMX_INT_ENA(engine)	CVMX_PCMX_INT_ENA_W1S(engine)
#endif

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
# define CVMX_SYNC			barrier()
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
module_param(use_coherent, bool, 0444);


MODULE_DESCRIPTION("Cavium TDM Controller Module");
MODULE_AUTHOR("Peter Swain <peter.swain@marvell.com>");
MODULE_LICENSE("GPL");

static int tdm_setbuf(int eno, int dir);
static int tdm_teardown(void);

#ifdef ONE_TDM_IRQ
/* scan all engines, mips has just 1 IRQ */
static irqreturn_t tdm_handle_all(int irq, void *irqaction);
#else
/* process one engine */
static irqreturn_t tdm_handle_one(int irq, void *irqaction);
#endif

static long tdm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

static const struct file_operations tdmdrv_fops;
static struct class *tdmmodule_class;

/*
 * struct tdm_sess:
 * describes a tx-or-rx session between a TDM slot and either
 * - a read/write connection on /dev/tdm%d
 * - another TDM slot
 * - a TDM-mode socket (not yet implemented, hooks in as tdm_read/tdm_write do)
 */
struct tdm_sess {
	int eno;
	int rs, ws;		/* read/write slots */
	struct tdm_slot *slot[TXRX];	/* slot buffering/signalling */
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
 * Note that fmask is typed to match bitops, not the 8 64bit registers,
 * and while it happens that u64 == unsigned long on mips64/arm64
 * they're purposefully kept distinct, but sized to contain same bitcount.
 * @changed: bitmask of fmask changes to push to hw, each represents a u64.
 * @fslots: count of mask[] bits.
 */
struct tdm_flow {
	bool bno;	/* which DMA super/handle the flow maps */
	u16 fslots;	/* bitcount of masks, soft copy of tx/rxslots */
	unsigned long changed;
	unsigned long fmask[TDM_MAX_SLOTS / BITS_PER_LONG];
};

/* locking is done at the IRQ-granularity level */
#ifdef ONE_TDM_IRQ
static spinlock_t tdm_lock;
# define E_LOCK(e) tdm_lock
#else /* !ONE_TDM_IRQ */
# define E_LOCK(e) ((e)->elock)
#endif /* !ONE_TDM_IRQ */

/*
 * struct tdm_engine:
 * @eno:	which engine 0..3.
 * @clksel:	which clock generator? -1 for unassigned.
 * @super[] & @handle[]: virtual & dma addresses of superframe buffers,
 *		two banks in each direction, which alternate when slot
 *		mapping changes to avoid overwriting.
 * @fnew[]:	pending flow, accumulates slotmap changes & Tx data.
 * @fhw[]:	currently active DMA.
 * @frx:	previous flow, just Rx, for draining last cycle's data.
 * @ring_frames[] & @supersize[]: suggested and actual DMA buf sizes.
 * @slop[]:	dynamically allocated slot-pointer vector.
 */

struct tdm_engine {
	u8 eno;			/* ordinal for index into registers, etc */
	s8 clksel;
	u16 max_slots[TXRX];	/* max slots allowed */
#ifndef ONE_TDM_IRQ
	spinlock_t elock;
#endif /* !ONE_TDM_IRQ */
	u64 *super[TXRX][2];
	dma_addr_t handle[TXRX][2];
	struct tdm_flow fnew[TXRX];
	struct tdm_flow fhw[TXRX];
	struct tdm_flow frx;
	int ring_frames[TXRX];	/* override for SUPERS, not yet implemented */
	size_t supersize[TXRX];
	bool last_wrapped[TXRX];/* last processed IRQ was a tx/rxwrap */
	s16 pll_step[TXRX]; /* add to irq_thresh from next cycle onward */
	s16 pll_impulse[TXRX]; /* add to irq_thresh just for next cycle */
	union cavium_tdm_cfg tc;	/* current CVMX_PCMX_TDM_CFG */
	union cavium_tdm_dma_cfg dc; /* current CVMX_PCMX_DMA_CFG */
	bool valid_cfg;		/* TDMSTIM issued? */
	bool valid_ssiz;	/* optional TDMSSIZE issued? */
	struct tdm_slot **slop[TXRX];
	wait_queue_head_t mask_event;
	u8 ena;			/* soft IRQ enable state */
	u8 sum;			/* soft IRQ summary */
	u8 cumsum;		/* accumulated events since TDMGSTAT */
	int _irqstate[256]; /* stats. TODO: drop when stable */
};
static struct tdm_engine engines[NR_TDM_ENGINES];

struct tdm_slot;
typedef int (*tdm_actor) (struct tdm_slot *, u64 *b64, int frames, int stride);

/* state for handling a read-or-write slot, or N consecutive slots */
struct tdm_slot {
	int sno;		/* first TDM slot */
	u16 sample_bytes;	/* number of consecutive slots */
	struct tdm_engine *eng;
	tdm_actor actor;	/* called at irq to process completed frames */

	/*
	 * FIFO of u64 8-sample chunks for mux/demux TDM.superframes <-> user
	 * Offsets & sizes are in 64bit superframe slots, not bytes.
	 * With Tx/Rx names already confused between SLIC/TDM, think of
	 * these FIFOs as being divided into free region & content region.
	 * Consumer takes from beginning of content, incs data_off.
	 * Producer appends at free_off, incs free_off.
	 */
	int fifo_sz;		/* size in supers, must be 2^N */
#define tdm_fifo_mask(s) ((s)->fifo_sz - 1)
	int data_off, free_off;	/* always evaluated modulo _sz, data >= free */
	wait_queue_head_t fifo_have_content;
	wait_queue_head_t fifo_have_space;
#define tdm_fifo_content(s) ((s)->free_off - (s)->data_off)
#define tdm_fifo_space(s) ((s)->fifo_sz - tdm_fifo_content(s))
#define tdm_fifo_full(s) (tdm_fifo_space(s) <= 0)
	u64 fifo[0];		/* allocated at end */
};

static int tdm_init(int eno, int dir);
static void tdm_exit(int eno, int dir);
static int tdm_hw_init(int eno);
static void __change_mapping(struct tdm_engine *e, int dir, bool first);

static DEFINE_SEMAPHORE(starting);
static int teardown;

/* stats for /proc/tdm */
static struct pstat {
	u64 sum;
	u64 drop;
	u64 empty;
	u64 pll_up;
	u64 pll_dn;
	u16 hang;
} pstat[NR_TDM_ENGINES][TXRX];

/* shut down an engine and log trace buffer */
static void __tdm_dump(const char *f, int l, int eno)
#define tdm_dump(e) __tdm_dump(__func__, __LINE__, e)
{
#ifdef CONFIG_TRACING
	struct tdm_engine *e = &engines[eno];

	if (!e->tc.s.enable)
		return;
	e->tc.s.enable = 0;
	cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);
	trace_printk("tdm_dump(%d) from %s:%d\n", eno, f, l);
	ftrace_dump(DUMP_ALL);
	wake_up(&e->mask_event);
#endif
}

static inline void tdm_irq_enable(int eno, u8 bits)
{
#ifdef CONFIG_MIPS
	u8 ena;
	u64 r = CVMX_PCMX_INT_ENA(eno);

	ena = cvmx_read_csr(r);
	if (~ena & bits) {
		ena |= bits;
		cvmx_write_sync(r, ena);
		engines[eno].ena = ena;
	}
#else
	cvmx_write_csr(CVMX_PCMX_INT_ENA_W1S(eno), bits);
	engines[eno].ena |= bits;
#endif
}

static inline void tdm_irq_disable(int eno, u8 bits)
{
#ifdef CONFIG_MIPS
	u8 ena;
	u64 r = CVMX_PCMX_INT_ENA(eno);

	ena = cvmx_read_csr(r);
	if (ena & bits) {
		ena &= ~bits;
		cvmx_write_sync(r, ena);
		engines[eno].ena = ena;
	}
#else
	cvmx_write_csr(CVMX_PCMX_INT_ENA_W1C(eno), bits);
	engines[eno].ena &= ~bits;
#endif
}

static inline void tdm_irq_ack(int eno, u8 bits)
{
	cvmx_write_csr(CVMX_PCMX_INT_SUM_W1C(eno), bits);
	engines[eno].sum = cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
	engines[eno].cumsum |= engines[eno].sum;
}

static int validate_eno(unsigned int eno)
{
	if (eno < NR_TDM_ENGINES)
		return 0;
	return -EINVAL;
}

/* respect TCMSCLKSEL, fall back to TDMCFG.useclk1, default clk0 */
static int which_clk(int eno)
{
	struct tdm_engine *e = &engines[eno];

	if (!validate_eno(eno))
		return 0;
	if (e->clksel >= 0)
		return e->clksel;
	return e->tc.s.useclk1;
}

#ifdef CONFIG_PROC_FS
static int show_tdm(struct seq_file *m, void *v)
{
	int clk, eno;

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
	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		struct tdm_engine *e = &engines[eno];
		int dir;
		int seen = 0;
		int i;

		for (dir = 0; dir < TXRX; dir++) {
			struct pstat *s = &pstat[eno][dir];
			struct tdm_flow *fnew = &e->fnew[dir];
			struct tdm_flow *fhw = &e->fhw[dir];
			struct tdm_flow *frx = &e->frx;

			/* skip any completely quiescent engine/dir */
			if ((IsTx(dir)
			     || !frx->fslots)
			    && !fhw->fslots
			    && !fnew->fslots)
				continue;

			if (!seen++)
				seq_printf(m, "TDM%d CLK%d ", eno,
					   which_clk(eno));
			else
				seq_puts(m, "          ");

			seq_printf(m,
				   "%s sum:%lld d:%lld h:%x pll:%d+%lld-%lld",
				   DirStr(dir), s->sum, s->drop, s->hang,
				   IsTx(dir) ? e->dc.s.txrd : e->dc.s.rxst,
				   s->pll_up, s->pll_dn);
			seq_printf(m, " %d>%d", fnew->fslots, fhw->fslots);
			if (!IsTx(dir))
				seq_printf(m, ">%d", frx->fslots);
			seq_printf(m, " i%xE%x", e->sum, e->ena);
			seq_puts(m, "\n");

			for (i = 0; i < 8; i++) {
				u64 m0 = fnew->fmask[i];
				u64 m1 = fhw->fmask[i];
				u64 m2 = IsTx(dir) ? 0 : frx->fmask[i];

				if (!(m0 | m1 | m2))
					continue;
				seq_printf(m,
					"  TDM%d.%smsk%d %c%llx>%c%llx",
					eno, DirStr(dir), i,
					"-+"[e->fnew[dir].bno], m0,
					"-+"[e->fhw[dir].bno], m1);
				if (!IsTx(dir))
					seq_printf(m, ">%c%llx",
						"-+"[e->fhw[dir].bno], m2);
				seq_putc(m, '\n');
			}
		}
#ifdef DEBUG
		for (i = 0; i < 256; i++)
			if (e->_irqstate[i])
				seq_printf(m, "sum %x %d\n", i,
					   e->_irqstate[i]);
#endif
	}

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

static int validate_clk(unsigned int eno, enum clkstate how, u64 arg)
{
	int err = validate_eno(eno);
	int clk = which_clk(eno);

	if (err)
		return -EINVAL;
	if (how & c_cfg)
		clk_cfg[clk].u64 = arg;
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

static int validate_cfg(unsigned int eno, union cavium_tdm_cfg *tc)
{
	int err = validate_eno(eno);
	struct tdm_engine *e = &engines[eno];

	if (err)
		return err;
	if (e->valid_cfg)
		return 0;
	if (!tc)
		return -EINVAL;
	tc->s.enable = 0;
	e->tc = *tc;
	/* rest done in tdm_hw_init()  */
	e->valid_cfg = true;

	return err;
}

/* setup superframes, defaulting as needed */
static int validate_dma(int eno, union cavium_tdm_bind *b)
{
	int err = validate_clk(eno, c_on, 0);

	if (!b)
		return -EINVAL;

	err = validate_cfg(eno, NULL);
	if (err)
		return err;

	if (!b->s.no_tx)
		err = tdm_init(eno, tx_tdm);
	if (err)
		return err;

	if (!b->s.no_rx)
		err = tdm_init(eno, rx_tdm);
	if (err)
		return err;
	err = tdm_hw_init(eno);
	tf("err:%d\n", err);
	return err;
}

/* validate_slots: apply slot binding (unless already bound)
 * if clk/tdm not configured, default it
 */
static int validate_slots(struct file *f, union cavium_tdm_bind *b)
{
	struct tdm_sess *sess = f->private_data;
	int eno = sess->eno;
	struct tdm_engine *e = &engines[eno];
	int err;

	/* assume worst, if not limited by TDMSRXBUF/TDMSTXBUF */
	if (!sess->bound) {
		if (!e->max_slots[rx_tdm] && !b->s.no_rx)
			e->max_slots[rx_tdm] = TDM_MAX_SLOTS;
		if (!e->max_slots[tx_tdm] && !b->s.no_tx)
			e->max_slots[tx_tdm] = TDM_MAX_SLOTS;
	}

	WARN(!b->s.slots, "sslots==0\n");
	tf("tdm%d %c%c rs:%d ws:%d ss:%d ns:%d/%d\n",
	   eno, "r-"[b->s.no_rx], "w-"[b->s.no_tx],
	   b->s.rslot, b->s.wslot, b->s.slots,
	   e->max_slots[rx_tdm], e->max_slots[tx_tdm]);
	if (!b->s.no_rx && b->s.rslot + b->s.slots >= e->max_slots[rx_tdm])
		return -EINVAL;
	if (!b->s.no_tx && b->s.wslot + b->s.slots >= e->max_slots[tx_tdm])
		return -EINVAL;

	if (!e->tc.s.enable) {
		err = validate_dma(eno, b);
		if (err)
			return err;
	}

	sess->bound = true;
	return 0;
}

static int tdm_common_init(struct device *dev)
{
	int result, eno;

	down(&starting);
	if (!tdmdev)
		tdmdev = dev;

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

#ifdef ONE_TDM_IRQ
	spin_lock_init(&tdm_lock);
#endif /* ONE_TDM_IRQ */

	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		struct tdm_engine *e = &engines[eno];

		e->eno = eno;
		e->clksel = -1;
#ifndef ONE_TDM_IRQ
		spin_lock_init(&e->elock);
#endif /* !ONE_TDM_IRQ */

		device_create(tdmmodule_class, dev, MKDEV(tdmdrv_major, eno),
			      NULL, DEVNAME "%d", eno);
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

ret:
	up(&starting);
	return result;
}

static void __exit tdm_common_remove(void *data)
{
	tr_tdm(t_chan | t_pump, "teardown\n");
	teardown = 1;

	tdm_teardown();
}

#ifdef CONFIG_MIPS
static int __init tdm_mod_init(void)
{
	int tdm_irq;
	struct platform_device *pdev;
	struct device *dev;
	int eno;
	int err = -ENOMEM;

	if (!octeon_has_feature(OCTEON_FEATURE_TDM))
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
static int tdm_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	int err = -ENOENT;
	int eno;
	struct property *pp;
	int gpio = -1;
	enum of_gpio_flags gflags = 0;	/* default active high */

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
			    IRQF_NO_THREAD, DEVNAME, &engines[eno]);
		if (err) {
			pr_warn("TDM: IRQ %d is not free, err %d.\n", irq, err);
			goto err_irq;
		}
	}

	dev_info(dev, "TDM driver\n");
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

	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		int irq = pci_irq_vector(pdev, eno);

		tdm_irq_disable(eno, 0xff);
		tdm_irq_ack(eno, 0xff);

		pr_debug("%s engine#%d free_irq(%d)\n", __func__, eno, irq);
		free_irq(irq, &engines[eno]);
	}

	pci_free_irq_vectors(pdev);

	tdm_common_remove(tdmdev);
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

static inline void await_rdpend(int eno)
{
	union cavium_tdm_dma_cfg dmac;

	do {
		dmac.u64 = cvmx_read_csr(CVMX_PCMX_DMA_CFG(eno));
	} while (dmac.s.rdpend);
}

static inline int await_fsyncgood(int clk)
{
	union cavium_tdm_clk_cfg pcmClock;

	pr_debug("wait for CVMX_PCM_CLK%d_CFG.fsyncgood\n", clk);
	do {
		if (msleep_interruptible(1))
			return -EINTR;
		pcmClock.u64 = cvmx_read_csr(CVMX_PCM_CLKX_CFG(clk));
	} while (!pcmClock.s.fsyncgood);

	return 0;
}

/* en/disable some TDM slots. caller holds lock */
static int __tdm_enable(struct tdm_sess *s,
	int dir, bool enable, int sno0, int slots)
{
	int eno = s->eno;
	int sno;
	struct tdm_engine *e = &engines[eno];
	struct tdm_flow *fn = &e->fnew[dir];
	int send = 8 * sizeof(fn->fmask);

	for (sno = sno0; sno < send && slots > 0; --slots, sno++) {
		if (enable) {
			if (!test_and_set_bit(sno, fn->fmask)) {
				fn->fslots++;
				set_bit(sno / 64, &fn->changed);
				__mark_change();
			} else {
				/* revert the mappings set above */
				while (--sno >= sno0) {
					clear_bit(sno, fn->fmask);
					fn->fslots--;
				}
				return -EBUSY;
			}
		} else {
			if (test_and_clear_bit(sno, fn->fmask)) {
				fn->fslots--;
				set_bit(sno / 64, &fn->changed);
				__mark_change();
			}
		}
	}

	/*
	 * If no slots were active, no IRQs will rotate the new slot map in.
	 * But if no slots were active, no map conflicts exist, so safe.
	 */
	if (!e->fhw[dir].fslots)
		__change_mapping(e, dir, true);

	return 0;
}

static inline bool quiescent(struct tdm_engine *e, int dir)
{
	return !(IsTx(dir) && e->fnew[dir].changed);
}

/*
 * Wait for slot-map conflicts to drain, lock engine.
 *
 * If current slot mapping has gone live (other slots have DMA data pending)
 * we cannot add/remove slots, as that would change the DMA mapping.
 * Retry until conflicts are gone in the disable (close/unbind case),
 * or return -EAGAIN on the interruptible enable case.
 *
 * On apparent success, recheck with lock held, returning 0 if uncontested
 */
static inline bool bind_lock(struct tdm_engine *e, int dir,
		bool enable, unsigned long *flagp)
{
	int err;

	if (!enable) {
		wait_event(e->mask_event, quiescent(e, dir));
		spin_lock_irqsave(&E_LOCK(e), *flagp);
		return 0;
	}

	for (;;) {
		tf("bind_lock tdm%d%s en:%d\n", e->eno, DirStr(dir), enable);
		err = wait_event_interruptible(e->mask_event,
			quiescent(e, dir));
		if (!err) {
			spin_lock_irqsave(&E_LOCK(e), *flagp);
			if (quiescent(e, dir))
				return 0;
			spin_unlock_irqrestore(&E_LOCK(e), *flagp);
			err = -EAGAIN;
		}
		if (enable)
			return err;
	}
}

static int tdm_enable(struct file *fi, int dir,
	bool enable, int sno0, int slots)
{
	struct tdm_sess *sess = fi->private_data;
	int eno = sess->eno;
	struct tdm_engine *e = &engines[eno];
	unsigned long flags;
	struct tdm_flow *fn = &e->fnew[dir];
	int err;
	bool active;

	if (!e->slop[dir] && enable)
		tdm_setbuf(eno, dir);

	if (!e->slop[dir])
		return -EPROTO;

	err = bind_lock(e, dir, enable, &flags);
	tf("bind_lock returns %d\n", err);
	if (err)
		return err;

	active = !!e->fhw[dir].fslots;
	err = __tdm_enable(sess, dir, enable, sno0, slots);

	tf("tdm%d sno:%d w:%d %s err:%d enable:%d slots:%d:%d:%d\n",
		eno, sno0, slots, DirStr(dir), err, enable,
		fn->fslots, e->fhw[dir].fslots, e->frx.fslots);
	if (!err && enable && !active) {
		if (IsTx(dir))
			tdm_irq_enable(eno, tdm_txbits);
		else
			tdm_irq_enable(eno, tdm_rxbits);
		/* ignore any pending startup FSYNC errors */
		tdm_irq_ack(eno, tdm_clkbits);
	} else if (!err && !IsTx(dir) && !enable) {
		/* clear out stale frx state */
		int sno;

		for (sno = sno0; sno < sno0 + slots; sno++)
			if (test_and_clear_bit(sno, e->frx.fmask))
				e->frx.fslots--;
	}
	spin_unlock_irqrestore(&E_LOCK(e), flags);

	tf("tdm%d sno:%d w:%d %s err:%d enable:%d live:%d:%d:%d\n",
		eno, sno0, slots, DirStr(dir), err, enable,
		fn->fslots, e->fhw[dir].fslots, e->frx.fslots);

	if (err)
		return err;
	tf("ena%d %x t%dc %llx d%dc %llx\n",
		eno, e->ena, eno, e->tc.u64, eno, e->dc.u64);

	return 0;
}

static int tdm_teardown(void)
{
	int eno;

	down(&starting);

#ifdef CONFIG_PROC_FS
	if (proc_tdm)
		proc_remove(proc_tdm);
	proc_tdm = NULL;
#endif /* CONFIG_PROC_FS */

	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), 0);
		tdm_exit(eno, tx_tdm);
		tdm_exit(eno, rx_tdm);
		device_destroy(tdmmodule_class, MKDEV(tdmdrv_major, eno));
	}
	class_destroy(tdmmodule_class);
	unregister_chrdev(tdmdrv_major, DEVNAME);
	tdmdrv_major = 0;

	tdmdev = NULL;

	return 0;
}

/* Tx path Consumer: pull N frames' TX payload from write fifo */
static int write_actor(struct tdm_slot *s, u64 *b64, int frames, int stride)
{
	int done = 0;
	int supers = frames / 8;
	int width = s->sample_bytes;

	WARN(frames % 8, "frames:%d not 8fold\n", supers);

	for (; supers > 0; supers--) {
		u64 *linear;
		int idx = s->data_off;
		int j, k;
		bool empty = (tdm_fifo_content(s) < width);

		idx &= tdm_fifo_mask(s);

		linear = &s->fifo[idx];

		/* Superframe is always big-endian, so 1-slot case is easy */
		if (big_endian && width == 1) {
			*b64 = *linear;
		} else {
			u8 *b8 = (u8 *)b64;
			u8 *l8 = (u8 *)linear;
			/*
			 * interleave 8 N-byte samples over
			 * N successive slots of a frame
			 * TODO: generalize logic for cpu_endian +/- LSBFIRST
			 */
			for (k = 0; k < width; k++) {
				for (j = 0; j < 8; j++) {
					int i = 7 - j;

					if (big_endian)
						i = j;
					b8[8 * k + i] = l8[j * width + k];
				}
			}
		}
		tr_tdm(t_wr, "%p: %llx\n", b64, *b64);

		if (!empty)
			s->data_off += width;
		b64 += stride;
		done += width;
	}
	CVMX_SYNC;

	if (done)
		wake_up(&s->fifo_have_space);

	return done;
}

/*
 * Rx path Producer: push N frames' RX payload to read fifo, unless full.
 * TODO: consider overwriting old samples if full, by rolling data_off forward
 */
static int read_actor(struct tdm_slot *s, u64 *b64, int frames, int stride)
{
	int done = 0;
	int supers = frames / 8;
	int width = s->sample_bytes;

	WARN(frames % 8, "frames:%d not 8fold\n", supers);

	for (; b64 && supers > 0; supers--) {
		u64 *linear;
		int j, k;	/* time sequence, or fifo sample sequence */
		int idx = s->free_off;

		idx &= tdm_fifo_mask(s);

		linear = &s->fifo[idx];

		if (tdm_fifo_space(s) < width)
			break;

		/* transcode 8 samples from DMA ring to fifo */
		tr_tdm(t_rd, "%p: %llx\n", b64, *b64);
		/* Superframe is always big-endian, so 1-slot case is easy */
		if (big_endian && width == 1) {
			*linear = *b64;
		} else {
			u8 *b8 = (u8 *)b64;
			u8 *l8 = (u8 *)linear;
			/*
			 * combine hi/low bytes of 8 N-byte samples
			 * from N successive slots of a frame
			 * TODO: generalize logic for cpu_endian +/- LSBFIRST
			 */
			for (k = 0; k < width; k++) {
				for (j = 0; j < 8; j++) {
					int i = 7 - j;

					if (big_endian)
						i = j;
					l8[j * width + k] = b8[8 * k + i];
				}
			}
		}

		s->free_off += width;
		done += width;
		b64 += stride;
	}

	if (done)
		wake_up(&s->fifo_have_content);
	return done;
}


/*
 * tdm_scan_half()
 * irq-thread scanner which transfers between e->super
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
static int tdm_scan_half(struct tdm_engine *e, u64 *base,
	int stride, bool dir, struct tdm_flow *f)
{
	struct tdm_slot **slop = e->slop[dir];
	int moved = 0;
	int slots = 0;
	int n;

	for (n = 0; slop && slots < stride && n < e->max_slots[dir]; n++) {
		struct tdm_slot *s = slop[n];
		int width = 0;

		if (!s)
			continue;

		if (s->actor)
			moved +=
			    s->actor(s, base, FRAMES_PER_HALF, stride);


		if ((tdm_trace & t_scan) &&
				(base[0]|base[1]|base[2]|base[3]))
			tf("%s%d base@%p %llx:%llx:%llx:%llx s%d w%d/%d m:%x\n",
				DirStr(dir), e->eno, base,
				base[0], base[1], base[2], base[3],
				n, width, s->sample_bytes, moved);

		base += s->sample_bytes;
		slots += s->sample_bytes;
	}

	return moved;
}

static void tdm_exit(int eno, int dir)
{
	struct tdm_engine *e = &engines[eno];

	/*
	 * TODO: no waiting needed here IFF _release waits until
	 * its slots are gone from all masks
	 */
	if (e->super[dir][0] && use_coherent)
		dma_free_coherent(tdmdev, 2 * e->supersize[dir],
			e->super[dir][0], e->handle[dir][0]);
	else
		kfree(e->super[dir][0]);

	e->super[dir][0] = NULL;
	e->super[dir][1] = NULL;

	kfree(e->slop[dir]);
	e->slop[dir] = NULL;
}

static int tdm_setbuf(int eno, int dir)
{
	struct tdm_engine *e = &engines[eno];
	int eslots;
	size_t size8; /* size in u8 of one of a pair of superframe DMA bufs */
	size_t size64; /* and in u64 to simplify code below */
	char *how = "kzalloc";

	if (e->super[dir][0])
		return -EBUSY;

	/* assume worst, if not limited by TDMSRXBUF/TDMSTXBUF */
	if (!e->max_slots[dir])
		e->max_slots[dir] = TDM_MAX_SLOTS;

	eslots = e->max_slots[dir];
	size64 = eslots * SUPERS;
	size8 = 8 * size64;

	/* TODO: make this dynamic, re-alloc'd as growth needed */
	if (use_coherent) {
		e->super[dir][0] = dma_alloc_coherent(tdmdev,
			2 * size8, &e->handle[dir][0], GFP_KERNEL);
		tf("e%d super[%d] %p/2*%lx\n",
			eno, dir, e->super[dir][0], 2 * size8);
		if (e->super[dir][0]) {
			memset(e->super[dir][0], 0, 2 * size8);
			how = "dma_alloc_coherent";
		}
	}
	if (!e->super[dir][0]) {
		e->super[dir][0] = kzalloc(2 * size8, GFP_KERNEL | GFP_DMA);
		tf("e%d super[%d] %p/2*%lx\n",
			eno, dir, e->super[dir][0], 2 * size8);
		e->handle[dir][0] =
		    phys_to_dma(tdmdev, virt_to_phys(e->super[dir][0]));
	}

	if (!e->super[dir][0])
		return -ENOMEM;

	e->super[dir][1] = e->super[dir][0] + size64;
	e->handle[dir][1] = e->handle[dir][0] + size8;
	e->supersize[dir] = size8;


	/* init all to TDM idle pattern */
	memset(e->super[dir][0], 0xff, 2 * size8);

	init_waitqueue_head(&e->mask_event);

	e->slop[dir] = kcalloc(eslots, sizeof(e->slop[0][0]), GFP_KERNEL);
	tf("e%d slop[%d] %p\n", eno, dir, e->slop[dir]);

	if (e->slop[dir])
		return 0;

	tdm_exit(eno, dir);
	return -ENOMEM;
}

static int tdm_init(int eno, int dir)
{
	int err = validate_clk(eno, c_on, 0);
	struct tdm_engine *e = &engines[eno];

	if (err)
		return err;

	if (e->super[dir][0])
		return 0;

	e->fnew[dir].fslots = 0;

	err = tdm_setbuf(eno, dir);
	tf("tdm%d%s err:%d\n", eno, DirStr(dir), err);

	if (err)
		tdm_exit(eno, dir);
	return err;
}

static struct tdm_slot *tdm_create_slot(struct tdm_engine *e, int sno,
	int sample_bytes, size_t fifo_supers, int dir, tdm_actor actor)
{
	struct tdm_slot *s;
	struct tdm_slot *old_slot;
	unsigned long flags;

	tf("eno:%d.%s sno:%d..%d\n", e->eno, DirStr(dir),
		sno, sno + sample_bytes - 1);
	if (sno < 0 || sample_bytes < 1 ||
			sno + sample_bytes > e->max_slots[dir])
		return NULL;
	if (!e->slop[dir])
		return NULL;
	s = kzalloc(sizeof(*s) + sizeof(s->fifo[0]) * fifo_supers,
		    GFP_KERNEL);
	if (!s)
		return NULL;
	pr_debug("tdm: slot %p %s .sno %d\n", s, DirStr(dir), sno);
	s->sno = sno;
	s->sample_bytes = sample_bytes;
	s->eng = e;
	s->actor = actor;
	s->fifo_sz = fifo_supers;
	init_waitqueue_head(&s->fifo_have_content);
	init_waitqueue_head(&s->fifo_have_space);

	spin_lock_irqsave(&E_LOCK(e), flags);
	old_slot = e->slop[dir][sno];
	e->slop[dir][sno] = s;
	spin_unlock_irqrestore(&E_LOCK(e), flags);
	tf("replaced e->slop[%d][%d] %p with %p\n", dir, sno, old_slot, s);
	WARN_ON_ONCE(old_slot);
	kfree(old_slot);

	return s;
}

static void tdm_destroy_slot(struct tdm_slot *s, int dir)
{
	unsigned long flags;
	struct tdm_engine *e;
	int sno;

	if (!s)
		return;
	e = s->eng;
	if (!e)
		return;
	spin_lock_irqsave(&E_LOCK(e), flags);
	sno = s->sno;
	if (e->slop[dir] && e->slop[dir][sno]) {
		WARN_ON_ONCE(e->slop[dir][sno] != s);
		e->slop[dir][sno] = NULL;
	}
	spin_unlock_irqrestore(&E_LOCK(e), flags);
}

/* (re)init TDM hw engine when tx/rx first enabled */
static int tdm_hw_init(int eno)
{
	u64 pcmRxCount;
	u64 pcmTxCount;
	int err = validate_clk(eno, c_on, 0);
	struct tdm_engine *e = &engines[eno];
	int clk = which_clk(eno);
	unsigned long flags;

	if (err)
		return err;

	/* already running? */
	e->tc.u64 = cvmx_read_csr(CVMX_PCMX_TDM_CFG(eno));
	if (!e->tc.s.enable) {
		int m;

		e->dc.u64 = 0;
		e->dc.s.useldt = (useldt >> eno);

		/* defaults work well, but can be tweaked */
		if (!fetch_size || (unsigned int)fetch_size > 8)
			fetch_size = 8;
		if (!fetch_thresh || (unsigned int)fetch_thresh > 8)
			fetch_thresh = 8;
		e->dc.s.fetchsiz = fetch_size - 1;
		e->dc.s.thresh = fetch_thresh;

		for (m = 0; m < 8; m++) {
			cvmx_write_sync(CVMX_PCMX_TXMSKX(m, eno), 0);
			cvmx_write_sync(CVMX_PCMX_RXMSKX(m, eno), 0);
		}
	}

	/* range check, for when everything is configurable */
	if (!SUPERS || SUPERS >= (1<<16))
		return -EINVAL;
	if (!IRQ_THRESH || IRQ_THRESH > 0x3ff)
		return -EINVAL;

	spin_lock_irqsave(&E_LOCK(e), flags);

	e->fhw[rx_tdm].bno = 0;
	e->fhw[tx_tdm].bno = 0;
	cvmx_write_sync(CVMX_PCMX_RXSTART(e->eno),
		e->handle[rx_tdm][0]);
	cvmx_write_sync(CVMX_PCMX_TXSTART(e->eno),
		e->handle[tx_tdm][0]);
	e->frx.bno = 0;
	e->fnew[rx_tdm].bno = 1;
	e->fnew[tx_tdm].bno = 1;

	pcmRxCount = e->super[rx_tdm][0] ? SUPERS : 0;
	pcmTxCount = e->super[tx_tdm][0] ? SUPERS : 0;
	cvmx_write_csr(CVMX_PCMX_RXCNT(e->eno), pcmRxCount);
	cvmx_write_csr(CVMX_PCMX_TXCNT(e->eno), pcmTxCount);

	/* Set the TDM params but do not yet enable it.  */

	e->dc.s.txslots = 0;
	e->dc.s.rxslots = 0;

	spin_unlock_irqrestore(&E_LOCK(e), flags);

	pr_debug("setup TDM%d, using CLK%d\n", eno, clk);

	e->tc.s.enable = 0;
	tf("CVMX_PCM%d_TDM_CFG w %llx\n", eno, e->tc.u64);
	cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);
	CVMX_SYNC;

	/* no slots mapped, no IRQs yet */
	e->dc.s.rxst = 0;
	e->dc.s.txrd = 0;

	cvmx_write_sync(CVMX_PCMX_DMA_CFG(eno), e->dc.u64);

	pr_debug("Config TDM chan%d\n", eno);
	err = await_fsyncgood(clk);
	if (err)
		return err;

	if (e->fhw[tx_tdm].fslots)
		await_rdpend(eno);

	e->tc.s.enable = 1;
	tf("CVMX_PCM%d_TDM_CFG w %llx\n", eno, e->tc.u64);
	cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);

	return 0;
}

/* Rx path Consumer: read samples from fifo, waiting as needed for IRQ */
static int tdm_reader(struct tdm_slot *s, __user char *samples, int len)
{
	int err = -EIO;
	int done = 0;

	if (!s)
		return 0;

	/* TODO: remove aligned-to-superframe restriction */
	while (len >= 8 * s->sample_bytes) {
		int start = s->data_off & tdm_fifo_mask(s);
		int supers = len / 8;
		int chunk, remain;

		if ((start + supers) > s->fifo_sz)
			supers = s->fifo_sz - start;

		err = wait_event_interruptible(s->fifo_have_content,
				   tdm_fifo_content(s) >= s->sample_bytes);
		if (err && signal_pending_state(TASK_INTERRUPTIBLE, current))
			err = -EINTR;

		tr_tdm(t_read | t_err * !!err,
		       "wait(non_empty) err %d, space %x @%p\n", err,
		       tdm_fifo_content(s), samples);
		if (err)
			tr_tdm(t_read, "e=%d\n", err);
		if (err)
			return err;

		if (supers > tdm_fifo_content(s))
			supers = tdm_fifo_content(s);

		chunk = 8 * supers;

		if (chunk > len)
			chunk = len & ~((8 * s->sample_bytes) - 1);

		remain =
		    copy_to_user((__user char *)samples,
				 (char *)&s->fifo[start], chunk);
		chunk -= remain;
		tr_tdm(t_read, "copied %x/%x e=%d\n", chunk, (int)len, remain);

		len -= chunk;
		samples += chunk;
		done += chunk;

		s->data_off += chunk / 8;
		wake_up(&s->fifo_have_space);
	}
	if (done)
		tr_tdm(t_read, "done=%d space=%x data=%x free=%x err=%d\n",
		       done, tdm_fifo_space(s), s->data_off, s->free_off, err);
	return done;
}

/*
 * Tx path Producer: write samples to fifo,
 * waiting while fifo full until IRQ drains it
 */
static int tdm_writer(struct tdm_slot *s, const __user char *samples, int len)
{
	int err = -EIO;
	int done = 0;

	/* TODO: remove aligned-to-superframe restriction */
	while (len >= 8 * s->sample_bytes) {
		int start = s->free_off & tdm_fifo_mask(s);
		int chunk, supers, remain;

		tr_tdm(t_write, "space=%d data=%x free=%x\n",
		       tdm_fifo_space(s), s->data_off, s->free_off);
		err = wait_event_interruptible(s->fifo_have_space,
			       tdm_fifo_space(s) >= 8 * s->sample_bytes);
		if (err && signal_pending_state(TASK_INTERRUPTIBLE, current))
			err = -EINTR;
		tr_tdm(t_write | t_err * !!err,
		       "wait(non_full) err %d, space %x\n", err,
		       tdm_fifo_space(s));
		if (err)
			return err;

		chunk = 8 * tdm_fifo_space(s);
		if (chunk > len)
			chunk = len;

		supers = chunk / 8;

		if ((start + supers) > s->fifo_sz)
			supers = s->fifo_sz - start;

		/*
		 * len bytes = len/8 supers = len/sample_bytes samples.
		 * Sample_bytes is mostly ignored in this flow:
		 * in 16bit case we know that the free space is always
		 * produced/consumed in 2*super quantities, and fifo_size
		 * is not odd, and the while() above protects against
		 * unbalancing that with single-sample fragments.
		 * So there's just one more test, to keep 16bit case aligned...
		 */
		supers &= ~(s->sample_bytes - 1);

		chunk = 8 * supers;
		tr_tdm(t_write, "copy_from_user %x/%x ...\n", chunk, (int)len);
		remain =
		    copy_from_user((char *)&s->fifo[start], samples, chunk);
		tr_tdm(t_write, "copied %x/%x e=%d\n", chunk, (int)len, remain);
		chunk -= remain;
		len -= chunk;
		samples += chunk;
		done += chunk;

		s->free_off += chunk / 8;
	}
	tr_tdm(t_write, "done=%d space=%x data=%x free=%x\n",
	       done, tdm_fifo_space(s), s->data_off, s->free_off);
	return done;
}

/*
 * tdm_process() - process DMA completed since last call
 * 'phase' is which half of fhw's DMA buffer the software owns.
 *  Hardware may be active on other half.
 *  We get interrupts when a TDM engine crosses halfway (RXST=TXRD=frames/2)
 *  so this flips phase.
 *  After a phase switch we have frames/2 frame-times to ready the other half.
 * Note: could be more than 2 phases, if so change "half" teminology everywhere
 */
static inline int tdm_process(struct tdm_engine *e, bool dir,
	struct tdm_flow *f, void *sbase, dma_addr_t hbase, dma_addr_t hwhere)
{
	int eno = e->eno;
	dma_addr_t halfway;
	dma_addr_t hend;
	bool phase;
	int stride = f->fslots;
	int irq_thresh = 0;
	int old_thresh;
	int max_thresh = (IRQ_THRESH * 3) / 2;
	int pll_adjust = 0;
	int impulse = 0;
	int slice = -1;
	int unchanged = !!f->fslots;
	int done;

	hend = hbase + stride * FRAMES;
	halfway = (hbase + hend) / 2;

	/* which phase does software own? The one hw's hwhere is _not_ in! */
	phase = (hwhere < halfway);

	/* Now compare DMA address to goal, implementing PhaseLockedLoop:
	 * Adjust the PLL so interrupt happens 1/4..3/4 thru next phase,
	 * so DMA has had time to settle, but not so late that processing
	 * will not complete before wrapped DMA reuses buffer.
	 * Full buffer length: (stride * SUPERS * 8) == (stride * FRAMES)
	 * Captured in 2 phases, but the IRQs for these phases should happen
	 * shortly after DMA crosses into other phase, ~ 1/8 of total buffer.
	 */
	slice = (hwhere - hbase) / (SUPERS * stride);
	impulse = 1 - (slice & 3);

	if (impulse > 0)
		pstat[eno][dir].pll_up++;
	else if (impulse < 0)
		pstat[eno][dir].pll_dn++;

	/* apply IRQ threshold adjustments noted in earlier cycles */
	pll_adjust = e->pll_step[dir]; /* ongoing correction */
	impulse += e->pll_impulse[dir]; /* onetime correction */

	/* apply phase-shifting impulse, undone next cycle */
	e->pll_step[dir] = -impulse;
	e->pll_impulse[dir] = 0;
	pll_adjust += impulse;

	e->dc.u64 = cvmx_read_csr(CVMX_PCMX_DMA_CFG(eno));

	if (IsTx(dir))
		old_thresh = irq_thresh = e->dc.s.txrd;
	else
		old_thresh = irq_thresh = e->dc.s.rxst;

	irq_thresh += pll_adjust;

	if (irq_thresh > max_thresh)
		irq_thresh = max_thresh;
	if (irq_thresh <= 0)
		irq_thresh = 1;

	if (IsTx(dir))
		e->dc.s.txrd = irq_thresh;
	else
		e->dc.s.rxst = irq_thresh;

	if (irq_thresh != old_thresh) {
		cvmx_write_sync(CVMX_PCMX_DMA_CFG(eno), e->dc.u64);
		unchanged = 0;
		tf("tdm%d%s:%d PLL %+d -> %d %d/8 %llx/%llx/%llx\n",
			eno, DirStr(dir), f->fslots,
			pll_adjust, irq_thresh, slice,
			hbase, hwhere, hend);
	}

	if (e->last_wrapped[dir] == phase) {
		/* either a dropped half-buf, or a too-early IRQ */
		pstat[eno][dir].drop += unchanged;
		pstat[eno][dir].hang += unchanged;
		if (pstat[eno][dir].hang > 6)
			tdm_dump(eno);
		if (pstat[eno][dir].drop > 20)
			tdm_dump(eno);
		return 0;
	}

	pstat[eno][dir].hang = 0;

	if (phase)
		sbase += stride * FRAMES / 2;

	done = tdm_scan_half(e, sbase, stride, dir, f);
	pstat[eno][dir].sum += done;
	e->last_wrapped[dir] = phase;
	return done;
}

/*
 * __change_mapping: move to the new slot-map flow 'fnew'
 * Done at the last IRQ before buffer-wrap, so the DMA between old map
 * and user FIFOs is completed, because we're switching to new 'flow'
 * comprising start/cnt/msk registers.
 * Also called from tdm_enable() when first slot activated
 * Caller holds lock.
 */
static void __change_mapping(struct tdm_engine *e, int dir, bool first)
{
	int eno = e->eno;
	bool bno = e->fnew[dir].bno;
	dma_addr_t handle = e->handle[dir][bno];
	u64 *mask;
	int m;
	int eighth = IRQ_THRESH / 4; /* irq target is 1/8 of buffer */
	bool pause = true;

	__mark_change();
	e->dc.u64 = cvmx_read_csr(CVMX_PCMX_DMA_CFG(eno));

	/* frx is the after-DMA flow from buffer to per-slot FIFO */
	if (!IsTx(dir))
		e->frx = e->fhw[rx_tdm];

	/* fhw is the flow for next DMA cycle, with new buf & superframe map */
	e->fhw[dir] = e->fnew[dir];

	/* intentional type pun: fmask is unsigned long for bitops */
	mask = (u64 *)e->fhw[dir].fmask;

	/*
	 * set up fnew for the next round:
	 * flip to other DMA buffer,
	 * zero the changed-fmask indicator,
	 * and remain dormant until something sets .changed
	 */
	e->fnew[dir].bno ^= 1;
	e->fnew[dir].changed = 0;
	e->last_wrapped[dir] = -1;

	/* need if first time??? */
	if (!e->tc.s.enable || IsTx(dir))
		pause = true;

	/* pause engine while reshuffling */
	if (pause) {
		// could we just disable dir by xXCNT=0 ?
		e->tc.s.enable = 0;
		cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);
	}

	/* first IRQ corrects period, establishing correct phasing */
	if (first)
		e->pll_step[dir] = 3 * eighth;

	if (IsTx(dir)) {
		e->dc.s.txslots = e->fhw[dir].fslots;
		if (first) {
			e->dc.s.txrd = eighth;
			cvmx_write_sync(CVMX_PCMX_TXADDR(eno), handle);
			cvmx_write_sync(CVMX_PCMX_TXCNT(eno), SUPERS);
		}
		cvmx_write_sync(CVMX_PCMX_TXSTART(eno), handle);
	} else {
		e->dc.s.rxslots = e->fhw[dir].fslots;
		if (first) {
			e->dc.s.rxst = eighth;
			cvmx_write_sync(CVMX_PCMX_RXADDR(eno), handle);
			cvmx_write_sync(CVMX_PCMX_RXCNT(eno), SUPERS);
		}
		cvmx_write_sync(CVMX_PCMX_RXSTART(eno), handle);
	}

	cvmx_write_sync(CVMX_PCMX_DMA_CFG(eno), e->dc.u64);
	/* bring in the changed slot masks, acted on at buffer wrap */
	for (m = 0; m < 8; m++) {
		if (!test_bit(m, &e->fhw[dir].changed))
			continue;
		if (IsTx(dir))
			cvmx_write_sync(CVMX_PCMX_TXMSKX(m, eno), mask[m]);
		else /* IsRx */
			cvmx_write_sync(CVMX_PCMX_RXMSKX(m, eno), mask[m]);
	}

	if (e->fhw[dir].fslots)
		tdm_irq_disable(eno, IsTx(dir) ? tdm_txwrap : tdm_rxwrap);
	else
		tdm_irq_enable(eno, IsTx(dir) ? tdm_txwrap : tdm_rxwrap);

	if (pause) {
		e->tc.s.enable = 1;
		await_rdpend(eno);
		cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);
	}

	wake_up(&e->mask_event);
}

/* handle single engine's signalled irq, called from wrappers below */
static inline irqreturn_t __tdm_handle_irq(struct tdm_engine *e,
	u8 sum, u8 ena)
{
	int eno = e->eno;
	int dir;

	e->cumsum |= sum;
	e->_irqstate[sum]++;

	tf("irq%d ena:%x sum:%x\n", eno, ena, sum);


	if (sum & tdm_clkbits)
		tr_tdm(t_pump, "tdm%d fsync err %x\n", eno, sum);

	for (dir = 0; dir < TXRX; dir++) {
		struct tdm_flow *f = &e->fhw[dir];
		void *sbase = e->super[dir][f->bno];
		dma_addr_t hbase = e->handle[dir][f->bno];
		dma_addr_t hwhere;
		/* TODO: drop intake/work and fold actions inline? */
		u8 work = 0;
		u8 wrapped = 0;
		bool tx_intake = false;
		bool rx_intake = false;
		bool rx_still_draining = !IsTx(dir) && e->frx.fslots;

		if (!sbase)
			continue;

		/*
		 * tx/rx IRQs happen at 2x buffer-wrap rate.
		 * When wrap is signalled, DMA has moved to beginning of buf,
		 * so driver processes 2nd half.
		 * When non-wrap IRQ happens, and DMA is seen to be in 2nd half,
		 * driver processes 1st half.
		 * To ensure 1st half is only processed once in a cycle, use
		 * e->last_wrapped event to only process one eligible txrd/rxst.
		 *
		 * if intake, we have a map change coming which
		 * would conflict with the hw scan and/or rx fifo filling,
		 * by differently interpreting the superframe space
		 * under differing tx/rxmask.
		 * Intake implies next IRQ is at wrap, so must prepare
		 * flipped registers to latch at wrap.
		 * But if rx, and frx.live, leave it one more cycle
		 * to avoid fnew re-using the dma-buffer that is being scanned
		 * to fifos under old slot-map.
		 */
		if (IsTx(dir)) {
			if ((sum & tdm_txrd) && (ena & tdm_txwrap)) {
				tdm_irq_enable(eno, tdm_txrd);
				tdm_irq_disable(eno, tdm_txwrap);
			}

			if (sum & tdm_txempty)
				tr_tdm(t_pump, "tdm%d txempty err\n", eno);

			hwhere = cvmx_read_csr(CVMX_PCMX_TXADDR(eno));
#ifdef CONFIG_MIPS
			/* for octeon before cn70p2.0, beware errata#16276
			 *  "TXRD irq happens 1-byte early"
			 * so must decrement hwhere (modulo wrap)
			 */
			if ((OCTEON_IS_MODEL(OCTEON_CN70XX_PASS1_0) ||
			     OCTEON_IS_MODEL(OCTEON_CN70XX_PASS1_1)) &&
					hwhere > hbase + 8)
				hwhere -= 8;
#endif
			wrapped = (sum & tdm_txwrap);
			if (f->fslots) {
				work = (sum & tdm_txrd);
				tx_intake = work && !wrapped;
			} else {
				tx_intake = wrapped;
			}
		} else {
			if ((sum & tdm_rxst) && (ena & tdm_rxwrap)) {
				tdm_irq_enable(eno, tdm_rxst);
				tdm_irq_disable(eno, tdm_rxwrap);
			}

			if (sum & tdm_rxovf)
				tr_tdm(t_pump, "tdm%d rxovf err\n", eno);

			hwhere = cvmx_read_csr(CVMX_PCMX_RXADDR(eno));
			wrapped = (sum & tdm_rxwrap);
			if (f->fslots) {
				work = (sum & tdm_rxst);
				rx_intake = work && !wrapped;
			} else {
				rx_intake = wrapped;
			}
		}

		/* DMA must never walk outside buffers */
		if (hwhere < e->handle[dir][0] ||
		    hwhere >= e->handle[dir][0] + 2 * e->supersize[dir]) {
			tf("escaped tdm%d%s handle %llx<%llx<%llx\n",
				eno, DirStr(dir), e->handle[dir][0], hwhere,
				e->handle[dir][0] + 2 * e->supersize[dir]);
			tdm_dump(eno);
		}

		if (work)
			tdm_irq_ack(eno, work | wrapped);

		if (tx_intake && e->fnew[tx_tdm].changed) {
			/*
			 * DMA Tx is running on latched values from
			 * handle[dir][old_bno] and will soon hit
			 * the wall, restarting from the new_bno values
			 * installed by __change_mapping()
			 */
			__change_mapping(e, tx_tdm, false);
			/*
			 * So for the processing of the next scan phase,
			 * which would usually be lower half of h[d][old_bno]
			 * we fake the DMA cursor as if in h[d][new_bno],
			 * as that's the TDM engines's state when it reads.
			 */
			sbase = e->super[dir][f->bno];
			hbase = e->handle[dir][f->bno];
			hwhere = hbase;
			hwhere += (f->fslots * FRAMES_PER_HALF) / 4;

		}

		if (work)
			tdm_process(e, dir, &e->fhw[dir],
				sbase, hbase, hwhere);

		if (rx_intake && rx_still_draining)
			e->frx.fslots = 0;
		else if (rx_intake && e->fnew[rx_tdm].changed)
			__change_mapping(e, rx_tdm, false);

		tr_tdm(t_pump, "%s.%d w%x p%d sum:%lld drop:%lld hang:%d\n",
		       DirStr(dir), eno, wrapped, work,
		       pstat[eno][dir].sum,
		       pstat[eno][dir].drop,
		       pstat[eno][dir].hang);

		if (!work)
			continue;

		/*
		 * if current flow live, IRQ is from DMA-progress,
		 * and wrap event is observed, but does not trigger.
		 * But wrap clocks teardown, when no DMA scheduled
		 */
		if (e->fhw[dir].fslots && (tx_intake || rx_intake)) {
			if (IsTx(dir)) {
				tdm_irq_enable(eno, tdm_clkbits
					| (tdm_txbits & ~tdm_txwrap));
				tdm_irq_disable(eno, tdm_txwrap);
			} else {
				tdm_irq_enable(eno, tdm_clkbits
					| (tdm_rxbits & ~tdm_rxwrap));
				tdm_irq_disable(eno, tdm_rxwrap);
			}
		}
	}

	__mark_done();

	return IRQ_HANDLED;
}

#ifdef ONE_TDM_IRQ
static irqreturn_t tdm_handle_all(int irq, void *irqaction)
{
	unsigned int eno;
	irqreturn_t any = IRQ_NONE;

	for (eno = 0; eno < NR_TDM_ENGINES; eno++) {
		struct tdm_engine *e = &engines[eno];
		u8 sum;
		u8 ena;

		if (!e->tc.s.enable)
			continue;
		sum = cvmx_read_csr(CVMX_PCMX_INT_SUM(eno));
		engines[eno].sum = sum;
		ena = cvmx_read_csr(CVMX_PCMX_INT_ENA(eno));
		engines[eno].ena = ena;
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
	engines[eno].sum = sum;
	ena = cvmx_read_csr(CVMX_PCMX_INT_ENA(eno));
	engines[eno].ena = ena;

	return __tdm_handle_irq(e, sum, ena);
}
#endif /* !ONE_TDM_IRQ */

/* detach DMA channels from open file */
static void tdm_unbind(struct file *f)
{
	struct tdm_sess *sess = f->private_data;
	int dir;

	for (dir = 0; sess && dir < TXRX; dir++) {
		struct tdm_slot *sl = sess->slot[dir];
		struct tdm_engine *e = &engines[sess->eno];

		if (!sl)
			continue;

		/* wait for tx drain: interrupt here only truncates tx data */
		if (IsTx(dir))
			wait_event_interruptible(e->mask_event,
				tdm_fifo_content(sl) < sl->sample_bytes);

		/* unmap from fnew */
		tdm_enable(f, dir, false, sl->sno, sl->sample_bytes);

		tdm_destroy_slot(sl, dir);
		sess->slot[dir] = NULL;
		kfree(sl);
	}

	if (sess)
		sess->bound = false;
}

/* (re)attach DMA channels to open file */
static int tdm_bind(struct file *f, union cavium_tdm_bind *b)
{
	struct tdm_sess *sess = f->private_data;
	int eno = sess->eno;
	struct tdm_engine *e = &engines[eno];
	int slots = b->s.slots;
	int err;
	int fifo_log = PAGE_SHIFT - 3;
	int fifo_sz;

	if (b->s.log2fifo)
		fifo_log = b->s.log2fifo;
	fifo_sz = (8 << fifo_log);

	pr_debug("%s tdm%d%s m=%o fifo=%d r%d w%d l%d\n",
	       __func__, eno,
	       sess->bound ? " rebind" : "",
	       f->f_mode, fifo_sz,
	       b->s.rslot, b->s.wslot, b->s.slots);

#ifdef CONFIG_ARM64
	/* CN81XX pass 1.0/1.1 may not safely Tx on engines 1..3 */
	if (!b->s.no_tx && eno > 0 &&
	    MIDR_IS_CPU_MODEL_RANGE(read_cpuid_id(),
				    MIDR_THUNDERX_81XX, 0x00, 0x00)) {
		static unsigned long warned;

		if (!test_and_set_bit(eno, &warned))
			pr_err("tdm%d Tx binding not supported\n", eno);
		return -EIO;
	}
#endif

	err = down_interruptible(&starting);
	if (err)
		return err;

	/* check but do not act on binding */
	err = validate_slots(f, b);
	if (err)
		goto teardown;

	/* amending a binding does most of a close() */
	if (sess->bound)
		tdm_unbind(f);

	/* impose the binding on hw */
	if (!b->s.no_rx) {
		int sno = b->s.rslot;

		err = tdm_enable(f, rx_tdm, true, sno, slots);
		if (err)
			goto teardown;
		sess->slot[rx_tdm] =
		    tdm_create_slot(e, sno, b->s.slots,
				    fifo_sz, rx_tdm, read_actor);
	}
	if (!b->s.no_tx) {
		int sno = b->s.wslot;

		err = tdm_enable(f, tx_tdm, true, sno, slots);
		if (err) {
			if (!b->s.no_rx) {
				tdm_enable(f, rx_tdm, false, b->s.rslot, slots);
				tdm_destroy_slot(sess->slot[rx_tdm], rx_tdm);
			}
			goto teardown;
		}
		sess->slot[tx_tdm] =
		    tdm_create_slot(e, sno, b->s.slots,
				    fifo_sz, tx_tdm, write_actor);
	}

teardown:
	up(&starting);
	return err;
}

static inline void tdmgstat(struct tdm_engine *e, struct cavium_tdm_stat *s)
{
	int i;
	unsigned long flags;
	u64 *rm = (u64 *)e->fhw[rx_tdm].fmask;
	u64 *tm = (u64 *)e->fhw[tx_tdm].fmask;

	spin_lock_irqsave(&E_LOCK(e), flags);
	s->ver		= TDM_VER;
	s->int_sum	= e->cumsum;
	e->cumsum	= 0;
	s->supers	= SUPERS;
	s->rxaddr	= cvmx_read_csr(CVMX_PCMX_RXADDR(e->eno));
	s->txaddr	= cvmx_read_csr(CVMX_PCMX_TXADDR(e->eno));
	s->rxsize	= e->fhw[rx_tdm].fslots;
	s->txsize	= e->fhw[tx_tdm].fslots;
	s->rxlimit	= cvmx_read_csr(CVMX_PCMX_RXCNT(e->eno));
	s->txlimit	= cvmx_read_csr(CVMX_PCMX_TXCNT(e->eno));

	for (i = 0; i < ARRAY_SIZE(s->rxmask); i++) {
		s->rxmask[i] = rm[i];
		s->txmask[i] = tm[i];
	}
	spin_unlock_irqrestore(&E_LOCK(e), flags);
}

static long tdm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tdm_sess *sess = filp->private_data;
	void __user *uaddr = (void *)arg;
	unsigned int eno = sess ? sess->eno : 0;
	struct tdm_engine *e = &engines[eno];
	union cavium_tdm_clk_cfg cc;
	union cavium_tdm_clk_gen cg;
	union cavium_tdm_cfg tc;
	union cavium_tdm_bind bind;
	struct cavium_tdm_stat stat;
	u64 u_64;
	int ret = validate_eno(eno);
	int clk = which_clk(eno);
	int dir = rx_tdm; /* for tx/rx pair ioctls */

	pr_debug("ioctl(tdm%d, %x, %lx) ...\n", eno, cmd, arg);

	switch (cmd) {
	case TDMGCLKCFG:
		cc.u64 = cvmx_read_csr(CVMX_PCM_CLKX_CFG(clk));
		pr_debug("TDMGCLKCFG tdm%d %llx\n", eno, cc.u64);
		ret = copy_to_user(uaddr, &cc, sizeof(cc));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSCLKCFG:
		pr_debug("TDMSCLKCFG tdm%d clk%d\n", eno, clk);
		ret = copy_from_user(&cc, uaddr, sizeof(cc));
		if (ret)
			ret = -EFAULT;
		else
			ret = validate_clk(eno, c_cfg, cc.u64);
		if (!ret)
			cvmx_write_sync(CVMX_PCM_CLKX_CFG(clk),
				clk_cfg[clk].u64);
		pr_debug("ret:%d cc:%llx\n", ret, cc.u64);
		break;
	case TDMGCLKGEN:
		cg.u64 = cvmx_read_csr(CVMX_PCM_CLKX_GEN(clk));
		pr_debug("TDMGCLKGEN tdm%d clk%d %llx\n", eno, clk, cg.u64);
		ret = copy_to_user(uaddr, &cg, sizeof(cg));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSCLKGEN:
		pr_debug("TDMSCLKGEN tdm%d clk%d\n", eno, clk);
		ret = copy_from_user(&cg, uaddr, sizeof(cg));
		if (ret)
			ret = -EFAULT;
		else
			ret = validate_clk(eno, c_gen, cg.u64);
		if (!ret)
			cvmx_write_sync(CVMX_PCM_CLKX_GEN(clk),
				clk_gen[clk].u64);
		pr_debug("ret:%d cg:%llx\n", ret, cg.u64);
		break;
	case TDMGTIM:
		tc.u64 = cvmx_read_csr(CVMX_PCMX_TDM_CFG(eno));
		pr_debug("TDMGTIM tdm%d %llx\n", eno, tc.u64);
		ret = copy_to_user(uaddr, &tc, sizeof(tc));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSTIM:
		pr_debug("TDMSTIM tdm%d\n", eno);
		ret = copy_from_user(&tc, uaddr, sizeof(tc));
		if (ret)
			ret = -EFAULT;
		if (!ret)
			ret = validate_clk(eno, c_on, 0);
		if (!ret)
			ret = validate_cfg(eno, &tc);
		if (!ret) {
			e->tc = tc;
			pr_debug("CVMX_PCM%u_TDM_CFG w %llx\n", eno, e->tc.u64);
			cvmx_write_sync(CVMX_PCMX_TDM_CFG(eno), e->tc.u64);
			e->valid_cfg = true;
		}
		break;

		/* other ioctl()s which do not map to registers */
	case TDMGCLKSEL:
		ret = e->clksel;
		if (ret < 0)
			ret = -EINVAL;
		break;

	case TDMSCLKSEL:
		pr_debug("TDMSCLKSEL tdm%u clk%lu\n", eno, arg);
		/* allow -1 to un-assign a clock */
		if ((int)arg >= -1 && arg < 2) {
			e->clksel = arg;
			ret = 0;
		} else {
			ret = -EINVAL;
		}
		break;

	case TDMGFRMHZ:
		pr_debug("TDMGFRMHZ tdm%d\n", eno);
		u_64 = pclk_hz[clk];
		ret = copy_to_user(uaddr, &u_64, sizeof(u_64));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMSTXBUF:
		dir = tx_tdm;
		/* flow into ... */
	case TDMSRXBUF:
		pr_debug("TDMS%sBUF tdm%d %lx\n", DirStr(dir), eno, arg);
		if (e->max_slots[dir])
			ret = -EPROTO;
		else
			e->max_slots[dir] = arg;
		break;

	case TDMGSTAT:
		pr_debug("TDMGSTAT tdm%d\n", eno);
		tdmgstat(e, &stat);
		ret = copy_to_user(uaddr, &stat, sizeof(stat));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMGBIND:
		pr_debug("TDMGBIND tdm%d\n", eno);
		ret = copy_to_user(uaddr, &bind, sizeof(bind));
		if (ret)
			ret = -EFAULT;
		break;
	case TDMSBIND:
		pr_debug("TDMSBIND tdm%d\n", eno);
		ret = copy_from_user(&bind, uaddr, sizeof(bind));
		if (ret)
			ret = -EFAULT;
		if (!ret)
			ret = validate_cfg(eno, NULL);
		if (!ret)
			ret = validate_clk(eno, c_on, 0);
		if (!ret)
			ret = tdm_bind(filp, &bind);
		break;

	case TDMGSCLK:
		u_64 = get_sclk();
		pr_debug("TDMGSCLK tdm%d sclk %lld\n", eno, u_64);
		ret = copy_to_user(uaddr, &u_64, sizeof(u_64));
		if (ret)
			ret = -EFAULT;
		break;

	case TDMSTXRING:
		dir = tx_tdm;
		/* flow into ... */
	case TDMSRXRING:
		pr_debug("TDMS%sRING tdm%d %lx\n", DirStr(dir), eno, arg);
		if (e->ring_frames[dir])
			ret = -EPROTO;
		else if ((arg & 0xf) || arg <= 0 || arg >= (8 << 16))
			ret = -EINVAL;
		else
			e->ring_frames[dir] = arg;
		break;

	default:
		ret = -ENOTTY;
		break;
	}
	pr_debug("ioctl(%x) -> %x\n", cmd, ret);

	return ret;
}

static ssize_t tdm_read(struct file *f, char __user *u, size_t len, loff_t *off)
{
	struct tdm_sess *sess = f->private_data;
	int done;

	tr_tdm(t_read, "READ %d/%x @%llx ...\n", (int)len, (int)len, *off);
	if (!sess || !sess->slot[rx_tdm])
		return -EIO;

	done = tdm_reader(sess->slot[rx_tdm], u, len);
	if (done > 0 && off)
		*off += done;
	tr_tdm(t_read, "RX %d/%x @%llx ...\n", done, done, *off);
	return done;
}

static ssize_t tdm_write(struct file *f, const char __user *u,
		size_t len, loff_t *off)
{
	struct tdm_sess *sess = f->private_data;
	int done;

	tr_tdm(t_write, "WRITE %d/%x @%llx ...\n", (int)len, (int)len, *off);
	if (!sess || !sess->slot[tx_tdm])
		return -EIO;

	done = tdm_writer(sess->slot[tx_tdm], u, len);
	if (done > 0 && off)
		*off += done;
	tr_tdm(t_write, "TX %d/%x @%llx ...\n", done, done, *off);
	return done;
}

static int tdm_open(struct inode *i, struct file *f)
{
	struct tdm_sess *sess = NULL;
	int eno = iminor(i);
	int err;

	pr_debug("%s tdm%d teardown=%d\n", __func__, eno, teardown);

	err = down_interruptible(&starting);
	if (err)
		return err;

	err = -ENODEV;

	if (teardown)
		goto teardown;
	err = validate_eno(eno);
	if (err)
		goto teardown;

	err = -ENOMEM;
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		goto teardown;

	__module_get(THIS_MODULE);
	sess->eno = eno;
	f->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	f->private_data = sess;
	err = 0;

teardown:
	up(&starting);
	return err;
}

static int tdm_release(struct inode *i, struct file *f)
{
	struct tdm_sess *sess = f->private_data;

	if (sess) {
		down(&starting);
		tdm_unbind(f);
		f->private_data = NULL;
		up(&starting);
		kfree(sess);
		module_put(THIS_MODULE);
	}
	return 0;
}

static unsigned int tdm_poll(struct file *f, struct poll_table_struct *p)
{
	struct tdm_sess *sess = f->private_data;
	struct tdm_slot *rs, *ws;
	int ready = 0;
	static int was[NR_TDM_ENGINES];

	if (!sess)
		return -EIO;

	rs = sess->slot[rx_tdm];
	ws = sess->slot[tx_tdm];

	if (rs && tdm_fifo_content(rs) >= rs->sample_bytes)
		ready |= POLLIN;

	if (ws && tdm_fifo_space(ws) >= ws->sample_bytes)
		ready |= POLLOUT;

	was[sess->eno] = ready;

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
