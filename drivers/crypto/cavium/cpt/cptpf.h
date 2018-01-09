/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __CPTPF_H
#define __CPTPF_H

#include "octeontx.h"
#include "cpt_common.h"

#define CSR_DELAY 30
#define CPT_MAX_CORE_GROUPS 8
#define	CPT_81XX_PF_MSIX_VECTORS 3
#define	CPT_83XX_PF_MSIX_VECTORS 4
#define	CPT_PF_MSIX_VECTORS CPT_83XX_PF_MSIX_VECTORS
#define CPT_81XX_PF_MBOX_INT 2
#define CPT_83XX_PF_MBOX_INT 3
#define CPT_PF_INT_VEC_E_MBOXX(x, a) ((x) + (a))
#define CPT_UCODE_VERSION_SZ 32
#define CPT_81XX 1
#define CPT_AE_83XX 2
#define CPT_SE_83XX 3

struct cpt_device;

struct microcode {
	u8 is_mc_valid;
	u8 is_ae;
	u8 group;
	u8 num_cores;
	u32 code_size;
	u64 core_mask;
	u8 version[CPT_UCODE_VERSION_SZ];
	/* Base info */
	dma_addr_t phys_base;
	void *code;
};

struct cptpf_vf {
	struct octeontx_pf_vf domain;
};

/**
 * cpt device structure
 */
struct cpt_device {
	struct cptpf_vf vf[CPT_MAX_VF_NUM]; /* Per VF info */
	struct list_head list;
	u8 pf_type; /* PF type 83xx_SE or 83xx_AE */
	u8 max_vfs; /* Maximum number of VFs supported by the CPT */
	u8 vfs_enabled; /* Number of enabled VFs */
	u8 vfs_in_use; /* Number of VFs in use */
	u32 flags; /* Flags to hold device status bits */
	int node;

	void __iomem *reg_base; /* Register start address */
	struct pci_dev *pdev; /* pci device handle */

	struct microcode mcode[CPT_MAX_CORE_GROUPS];
	u8 next_mc_idx; /* next microcode index */
	u8 next_group;
	u8 max_se_cores;
	u8 max_ae_cores;
};

void cpt_mbox_intr_handler(struct cpt_device *cpt, int mbx);

#endif /* __CPTPF_H */
