/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */
#ifndef ZIP_H
#define ZIP_H

#include <linux/pci.h>
#include "octeontx.h"

/* PCI DEV IDs */
#define PCI_DEVICE_ID_OCTEONTX_ZIP_PF	0xA01A
#define PCI_DEVICE_ID_OCTEONTX_ZIP_VF	0xA037

#define ZIP_VF_CFG_SIZE			0x100000
#define ZIP_VF_OFFSET(__x)		(0x20000000 |  \
					(ZIP_VF_CFG_SIZE * (__x)))

#define ZIP_MAX_VF			8

#define PCI_ZIP_PF_CFG_BAR		0
#define PCI_ZIP_PF_MSIX_BAR		4

#define PCI_ZIP_VF_CFG_BAR		0
#define PCI_ZIP_VF_MSIX_BAR		4
#define ZIP_VF_MSIX_COUNT		2

/* ZIP PF register offsets */
#define ZIP_PF_CMD_CTL			(0x0)
#define ZIP_PF_QUEX_GMCTL(x)		(0x800  | ((x) << 20))
#define ZIP_PF_QUEX_SBUF_CTL(x)		(0x1200 | ((x) << 3))
#define ZIP_PF_QUEX_MAP(x)		(0x1400 | ((x) << 3))
#define ZIP_PF_FIFE_INT			0x78
#define ZIP_PF_FIFE_INT_W1S		0x80
#define ZIP_PF_FIFE_ENA_W1S		0x88
#define ZIP_PF_FIFE_ENA_W1C		0x90
#define ZIP_PF_ECCE_INT			0x580
#define ZIP_PF_ECCE_INT_W1S		0x588
#define ZIP_PF_ECCE_ENA_W1S		0x590
#define ZIP_PF_ECCE_ENA_W1C		0x998
#define ZIP_PF_MBOX_INT			0x900
#define ZIP_PF_MBOX_INT_W1S		0x920
#define ZIP_PF_MBOX_ENA_W1C		0x940
#define ZIP_PF_MBOX_ENA_W1S		0x960
#define ZIP_PF_VFX_MBOXX(x, y)		(0x2000 | ((x) << 4) | ((y) << 3))
#define ZIP_VF_PF_MBOXX(x)		(0x400 | ((x) << 3))
#define ZIP_PF_MSIX_COUNT		3
#define ZIP_SRIOV_ENABLED		1
#define ZIP_PF_SRIOV_ENABLED		BIT(0)

/* ZIP Mailbox message commands */
#define ZIP_MBOX0_INDEX			0
#define ZIP_MBOX1_INDEX			1

#define ZIP_MBOX_SET_CMD_BUF_SIZE	0x1

/***************** Structures *****************/
struct zippf_vf {
	struct octeontx_pf_vf	domain;
};

struct zippf {
	struct pci_dev		*pdev;
	void __iomem		*reg_base;
	int			id;
	struct msix_entry	*msix_entries;
	struct list_head	list;

	int			total_vfs;
	int			vfs_in_use;
	u32			flags;

	struct zippf_vf		vf[ZIP_MAX_VF];
};

struct zippf_com_s {
	int (*create_domain)(u32 id, u16 domain_id, u32 num_vfs,
			     void *master, void *master_data,
			     struct kobject *kobj);
	int (*destroy_domain)(u32 id, u16 domain_id, struct kobject *kobj);
	int (*reset_domain)(u32 id, u16 domain_id);
	int (*receive_message)(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req, union mbox_data *resp,
			       void *mdata);
	int (*get_vf_count)(u32 id);
};

extern struct zippf_com_s zippf_com;

/**
 * Register (NCB) zip_que#_map
 *
 * ZIP Queue Mapping Registers
 * These registers control how each instruction queue maps to ZIP cores.
 */
union zip_quex_map {
	u64 u;
	struct zip_quex_map_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_6_63         : 58;
		u64 zce                   : 6;
#else /* Word 0 - Little Endian */
		u64 zce                   : 6;
		u64 reserved_6_63         : 58;
#endif /* Word 0 - End */
	} s;
	/* struct zip_quex_map_s cn83xx; */
};

/**
 * Register (NCB) zip_que#_sbuf_ctl
 *
 * ZIP Queue Buffer Parameter Registers
 * These registers set the buffer parameters for the instruction queues.
 * When quiescent (i.e. outstanding doorbell count is 0), it is safe to
 * rewrite this register to effectively reset the command buffer state
 * machine. These registers must be programmed before software programs
 * the corresponding ZIP_QUE(0..7)_SBUF_ADDR.
 */
union zip_quex_sbuf_ctl {
	u64 u;
	struct zip_quex_sbuf_ctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_45_63        : 19;
		u64 size                  : 13;
		u64 inst_be               : 1;
		u64 inst_free             : 1;
		u64 reserved_24_29        : 6;
		u64 stream_id             : 8;
		u64 reserved_12_15        : 4;
		u64 aura                  : 12;
#else /* Word 0 - Little Endian */
		u64 aura                  : 12;
		u64 reserved_12_15        : 4;
		u64 stream_id             : 8;
		u64 reserved_24_29        : 6;
		u64 inst_free             : 1;
		u64 inst_be               : 1;
		u64 size                  : 13;
		u64 reserved_45_63        : 19;
#endif /* Word 0 - End */
	} s;
	/* struct zip_quex_sbuf_ctl_s cn83xx; */
};

/**
 * Register (NCB) zip_cmd_ctl
 *
 * ZIP Clock/Reset Control Register
 * This register controls clock and reset.
 */
union zip_cmd_ctl {
	u64 u;
	struct zip_cmd_ctl_s {
#if defined(__BIG_ENDIAN_BITFIELD) /* Word 0 - Big Endian */
		u64 reserved_2_63         : 62;
		u64 forceclk              : 1;
		u64 reset                 : 1;
#else /* Word 0 - Little Endian */
		u64 reset                 : 1;
		u64 forceclk              : 1;
		u64 reserved_2_63         : 62;
#endif /* Word 0 - End */
	} s;
};

#endif
