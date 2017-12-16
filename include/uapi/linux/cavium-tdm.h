#ifndef _UAPI_CAVM_TDM_H
#define _UAPI_CAVM_TDM_H
/* user interface to Octeon/OcteonTX TDM engines */

#include <asm/byteorder.h>

#define TDM_VER		3	/* ioctl API version */
#define NR_TDM_ENGINES	4
#define NR_CLKS		2
#define TDM_SLOT_SHIFT	9	/* log2(8*64), matching tx/rxmsk[0..7] */
#define TDM_MAX_SLOTS	(1 << TDM_SLOT_SHIFT)
enum { tdm_tx = 0, tdm_rx = 1, TDM_DIRS = 2, };

/* from mips, useful all bi-endian archs, perhaps could move to asm-generic? */
#ifndef __BITFIELD_FIELD
# ifdef __BIG_ENDIAN_BITFIELD
#  define __BITFIELD_FIELD(field, more)	field; more
# else /* little-endian */
#  define __BITFIELD_FIELD(field, more)	more field;
# endif /* little-endian */
#endif /* !__BITFIELD_FIELD */

/* some TDM hardware registers are visible thru ioctl()s */
union cavium_tdm_clk_cfg {
	uint64_t u64;
	struct {
		__BITFIELD_FIELD(uint64_t fsyncgood:1,
		__BITFIELD_FIELD(uint64_t reserved_48_62:15,
		__BITFIELD_FIELD(uint64_t fsyncsamp:16,
		__BITFIELD_FIELD(uint64_t reserved_26_31:6,
		__BITFIELD_FIELD(uint64_t fsynclen:5,
		__BITFIELD_FIELD(uint64_t fsyncloc:5,
		__BITFIELD_FIELD(uint64_t numslots:10,
		__BITFIELD_FIELD(uint64_t extrabit:1,
		__BITFIELD_FIELD(uint64_t bitlen:2,
		__BITFIELD_FIELD(uint64_t bclkpol:1,
		__BITFIELD_FIELD(uint64_t fsyncpol:1,
		__BITFIELD_FIELD(uint64_t ena:1,
		;))))))))))))
	} s;
};

union cavium_tdm_clk_gen {
	uint64_t u64;
	struct {
		__BITFIELD_FIELD(uint64_t deltasamp:16,
		__BITFIELD_FIELD(uint64_t numsamp:16,
		__BITFIELD_FIELD(uint64_t divisor:32, /* aka N in HW docs */
		;)))
	} s;
};

union cavium_tdm_cfg {
	uint64_t u64;
	struct {
		__BITFIELD_FIELD(uint64_t drvtim:16,
		__BITFIELD_FIELD(uint64_t samppt:16,
		__BITFIELD_FIELD(uint64_t reserved_3_31:29,
		__BITFIELD_FIELD(uint64_t lsbfirst:1,
		__BITFIELD_FIELD(uint64_t useclk1:1,
		__BITFIELD_FIELD(uint64_t enable:1,
		;))))))
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

/* where ioctl()s map to TDM CSR reads/writes, use analogous numbers */
#define TDM_IOCTL	'p'
/* legacy values, clashing with builtin compat_ioctl values on MIPS/k4.9 ... */
#define TDMGCLKCFG_	_IOR(TDM_IOCTL, 0x0, union cavium_tdm_clk_cfg)
#define TDMSCLKCFG_	_IOW(TDM_IOCTL, 0x0, union cavium_tdm_clk_cfg)
#define TDMGCLKGEN_	_IOR(TDM_IOCTL, 0x8, union cavium_tdm_clk_gen)
#define TDMSCLKGEN_	_IOW(TDM_IOCTL, 0x8, union cavium_tdm_clk_gen)
/* += 0x20 to avoid clash */
#define TDMGCLKCFG	_IOR(TDM_IOCTL, 0x20, union cavium_tdm_clk_cfg)
#define TDMSCLKCFG	_IOW(TDM_IOCTL, 0x20, union cavium_tdm_clk_cfg)
#define TDMGCLKGEN	_IOR(TDM_IOCTL, 0x28, union cavium_tdm_clk_gen)
#define TDMSCLKGEN	_IOW(TDM_IOCTL, 0x28, union cavium_tdm_clk_gen)
/* but these are safe ... */
#define TDMGTIM		_IOR(TDM_IOCTL, 0x10, union cavium_tdm_cfg)
#define TDMSTIM		_IOW(TDM_IOCTL, 0x10, union cavium_tdm_cfg)

/* other ioctl()s have numbers not divisible by 8 */
#define TDMGFRMHZ	_IOR(TDM_IOCTL, 0x5, uint64_t)	/* get frame freq */
#define TDMGCLKSEL	_IO(TDM_IOCTL, 0x9)	/* get clock selector */
#define TDMSCLKSEL	_IO(TDM_IOCTL, 0xa)	/* set clock selector */
#define TDMGSCLK	_IOR(TDM_IOCTL, 0xb, uint64_t)	/* get SCLK */

/* get user-visible state of TDM engine */
struct cavium_tdm_stat {
	uint16_t ver;		/* version of the tdm API */
	uint16_t rx_supers;	/* DMA buffer size in superframes */
	uint16_t tx_supers;	/* DMA buffer size in superframes */
	uint8_t int_sum;	/* events seen since last TDMGSTAT */
	uint64_t rxaddr;	/* DMA offset of last Rx sample */
	uint64_t txaddr;	/* DMA offset of last Tx sample */
	uint64_t rxsize;	/* size of current Rx sample space */
	uint64_t txsize;	/* size of current Tx sample space */
	uint64_t rxlimit;	/* size of config'd Rx frame space */
	uint64_t txlimit;	/* size of config'd Tx frame space */
	unsigned long rxmask[TDM_MAX_SLOTS / (8 * sizeof(unsigned long))];
	unsigned long txmask[TDM_MAX_SLOTS / (8 * sizeof(unsigned long))];
};
#define TDMGSTAT	_IOR(TDM_IOCTL, 0x2, struct cavium_tdm_stat)

#define TDMSRXBUF	_IO(TDM_IOCTL, 0x6)	/* set rx superframe space */
#define TDMSTXBUF	_IO(TDM_IOCTL, 0x7)	/* set tx superframe space */

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
	uint64_t u64;
	struct {
		uint64_t slots:10;
		uint64_t rslot:10;
		uint64_t wslot:10;
		uint64_t no_rx:1;
		uint64_t no_tx:1;
		uint64_t log2fifo:4;
		uint64_t manual:1;
	} s;
};
#define TDMGBIND	_IOR(TDM_IOCTL, 0x3, union cavium_tdm_bind)
#define TDMSBIND	_IOW(TDM_IOCTL, 0x3, union cavium_tdm_bind)

#define TDMSTXRING	_IO(TDM_IOCTL, 0xc) /* set Tx DMA ring size in frames */
#define TDMSRXRING	_IO(TDM_IOCTL, 0xd) /* set Rx DMA ring size in frames */
#define TDMSSILENCE	_IO(TDM_IOCTL, 0xe) /* Tx underrun pattern */


/* static slotmap, permanent tx/rx bindings */
struct cavium_tdm_sslots {
	unsigned long	mask[TDM_DIRS][TDM_MAX_SLOTS/sizeof(unsigned long)];
};
#define TDMGSSLOT	_IOR(TDM_IOCTL, 0x13, struct cavium_tdm_sslots)
#define TDMSSSLOT	_IOW(TDM_IOCTL, 0x13, struct cavium_tdm_sslots)

/*
 * When built-in, TDM bus state persists even when no /dev/tdmX are open.
 * If cavium-tdm is a module, it wwill normally unload on last /dev/tdmX close,
 * but setting any state (clock, stotmap, etc) holds bus alive even when
 * no instance open.
 * TDMSDROP releases this hold, allowing module to unload on last close.
 */
#define TDMSDROP	_IO(TDM_IOCTL, 0x14)	/* release persistent state */

#endif /* _UAPI_CAVM_TDM_H */
