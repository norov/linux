#ifndef _UAPI_CAVM_TDM_H
#define _UAPI_CAVM_TDM_H
/* user interface to Octeon/OcteonTX TDM engines */

#include <linux/types.h>
#include <linux/ioctl.h>

#define TDM_VER		1	/* ioctl API version */
#define NR_TDM_ENGINES	4
#define NR_CLKS		2
/* FIXME: dynamic: default 9, settable as TDMSSCALE(log2_slots), min 5 */
#define TDM_SLOT_SHIFT	9	/* log2(8*64), matching tx/rxmsk[0..7] */
#define TDM_MAX_SLOTS	(1 << TDM_SLOT_SHIFT)

/* some TDM hardware registers are visible thru ioctl()s */
union cavium_tdm_clk_cfg {
	__u64 u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		__u64 fsyncgood:1;
		__u64 reserved_48_62:15;
		__u64 fsyncsamp:16;
		__u64 reserved_26_31:6;
		__u64 fsynclen:5;
		__u64 fsyncloc:5;
		__u64 numslots:10;
		__u64 extrabit:1;
		__u64 bitlen:2;
		__u64 bclkpol:1;
		__u64 fsyncpol:1;
		__u64 ena:1;
#else
		__u64 ena:1;
		__u64 fsyncpol:1;
		__u64 bclkpol:1;
		__u64 bitlen:2;
		__u64 extrabit:1;
		__u64 numslots:10;
		__u64 fsyncloc:5;
		__u64 fsynclen:5;
		__u64 reserved_26_31:6;
		__u64 fsyncsamp:16;
		__u64 reserved_48_62:15;
		__u64 fsyncgood:1;
#endif
	} s;
};

union cavium_tdm_clk_gen {
	__u64 u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		__u64 deltasamp:16;
		__u64 numsamp:16;
		__u64 divisor:32; /* called N in hardware ref manual */
#else
		__u64 divisor:32;
		__u64 numsamp:16;
		__u64 deltasamp:16;
#endif
	} s;
};

union cavium_tdm_cfg {
	__u64 u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		__u64 drvtim:16;
		__u64 samppt:16;
		__u64 reserved_3_31:29;
		__u64 lsbfirst:1;
		__u64 useclk1:1;
		__u64 enable:1;
#else
		__u64 enable:1;
		__u64 useclk1:1;
		__u64 lsbfirst:1;
		__u64 reserved_3_31:29;
		__u64 samppt:16;
		__u64 drvtim:16;
#endif
	} s;
};

/* TDM IRQ bits */
enum {
	tdm_rxovf	= (1<<7), /* RX byte overflowed			*/
	tdm_txempty	= (1<<6), /* TX byte was empty when sampled	*/
	tdm_txrd	= (1<<5), /* DMA engine frame read interrupt	*/
	tdm_txwrap	= (1<<4), /* TX region wrap interrupt		*/
	tdm_rxst	= (1<<3), /* DMA engine frame store interrupt	*/
	tdm_rxwrap	= (1<<2), /* RX region wrap interrupt		*/
	tdm_fsyncextra	= (1<<1), /* FSYNC extra interrupt		*/
	tdm_fsyncmissed	= (1<<0), /* FSYNC missed interrupt		*/
	tdm_clkbits	= tdm_fsyncmissed | tdm_fsyncextra,
	tdm_rxbits	= tdm_rxwrap | tdm_rxst | tdm_rxovf,
	tdm_txbits	= tdm_txwrap | tdm_txrd | tdm_txempty,
	tdm_irqall	= 0xff,
};

/* some ioctl()s map to TDM CSR reads/writes, and are numbered accordingly */
#define TDM_IOCTL	'p'
#define TDMGCLKCFG	_IOR(TDM_IOCTL, 0x0, union cavium_tdm_clk_cfg)
#define TDMSCLKCFG	_IOW(TDM_IOCTL, 0x0, union cavium_tdm_clk_cfg)
#define TDMGCLKGEN	_IOR(TDM_IOCTL, 0x8, union cavium_tdm_clk_gen)
#define TDMSCLKGEN	_IOW(TDM_IOCTL, 0x8, union cavium_tdm_clk_gen)
#define TDMGTIM		_IOR(TDM_IOCTL, 0x10, union cavium_tdm_cfg)
#define TDMSTIM		_IOW(TDM_IOCTL, 0x10, union cavium_tdm_cfg)

/* other ioctl()s have numbers not divisible by 8 */
#define TDMGFRMHZ	_IOR(TDM_IOCTL, 0x5, __u64)	/* get frame freq */
#define TDMGCLKSEL	_IO(TDM_IOCTL, 0x9)	/* get clock selector */
#define TDMSCLKSEL	_IO(TDM_IOCTL, 0xa)	/* set clock selector */
#define TDMGSCLK	_IOR(TDM_IOCTL, 0xb, __u64)	/* get SCLK */

/* get user-visible state of TDM engine */
struct cavium_tdm_stat {
	__u16 ver;		/* version of the tdm API */
	__u16 supers;
	__u8 int_sum;	/* events seen since last TDMGSTAT */
	__u64 rxaddr;	/* DMA offset of last Rx sample */
	__u64 txaddr;	/* DMA offset of last Tx sample */
	__u64 rxsize;	/* size of current Rx sample space */
	__u64 txsize;	/* size of current Tx sample space */
	__u64 rxlimit;	/* size of config'd Rx frame space */
	__u64 txlimit;	/* size of config'd Tx frame space */
	unsigned long rxmask[TDM_MAX_SLOTS / (8 * sizeof(unsigned long))];
	unsigned long txmask[TDM_MAX_SLOTS / (8 * sizeof(unsigned long))];
};
#define TDMGSTAT	_IOR(TDM_IOCTL, 0x2, struct cavium_tdm_stat)

#define TDMSRXBUF	_IO(TDM_IOCTL, 0x6)	/* set rx superframe space */
#define TDMSTXBUF	_IO(TDM_IOCTL, 0x7)	/* set rx superframe space */

/*
 * TDMSBIND - bind a file descriptor to read/write slots in the TDM frame.
 * This must be done before read() and write() operations can be used on an fd..
 * Binding is released on close(), or another TDMSBIND call on same fd.
 * 'slots' is the number of contiguous slots, typically 1 or 2 for single voice,
 * but may be many more when multiplexing TDM streams.
 * 'rslot' and 'wslot' are the first slot numbers in that 'slots'-wide slice.
 * 'no_rx' and 'no_tx' disable respective directions.
 * 'log2fifo', if set, alters the kernel<->user FIFOs which buffer DMA engines
 */
union cavium_tdm_bind {
	__u64 u64;
	struct {
		__u64 slots:10;
		__u64 rslot:10;
		__u64 wslot:10;
		__u64 no_rx:1;
		__u64 no_tx:1;
		__u64 log2fifo:4;
	} s;
};
#define TDMGBIND	_IOR(TDM_IOCTL, 0x3, union cavium_tdm_bind)
#define TDMSBIND	_IOW(TDM_IOCTL, 0x3, union cavium_tdm_bind)

#define TDMSTXRING	_IO(TDM_IOCTL, 0xc) /* set Tx DMA ring size in frames */
#define TDMSRXRING	_IO(TDM_IOCTL, 0xd) /* set Rx DMA ring size in frames */

#endif /* _UAPI_CAVM_TDM_H */
