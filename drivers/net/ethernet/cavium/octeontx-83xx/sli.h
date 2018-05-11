/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __SLI_H__
#define __SLI_H__

#include <linux/pci.h>
#include <linux/types.h>
#include "octeontx.h"

/* PCI DEV IDs */
#define PCI_DEVICE_ID_OCTEONTX_SLI_PF	0xA038

#define PCI_SLI_PF_CFG_BAR		0
#define PCI_SLI_PF_MSIX_BAR		4

struct slipf {
	struct pci_dev		*pdev;
	void __iomem		*reg_base;
	int			id;
	struct msix_entry	*msix_entries;
	struct list_head    list; /* List of SLI devices */
	int   sli_idx; /* CPU-local SLI device index.*/
	int   port_count;
	int   node; /* CPU node */

	u32	  flags;
};

struct slipf_com_s {
	int (*create_domain)(u32 id, u16 domain_id,
			     struct octtx_sdp_port *port_tbl, int ports,
			     struct octeontx_master_com_t *com, void *domain,
			     struct kobject *kobj);
	int (*destroy_domain)(u32 id, u16 domain_id, struct kobject *kobj);
	int (*reset_domain)(u32 id, u16 domain_id);
	int (*receive_message)(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req, union mbox_data *resp,
				void *mdata);
	int (*get_num_ports)(int node);
	bool (*get_link_status)(int node, int sdp, int lmac);
	int (*set_pkind)(u32 id, u16 domain_id, int port, int pkind);
};

extern struct slipf_com_s slipf_com;

#endif /* __SLI_H__ */
