/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef OCTEONTX_H
#define OCTEONTX_H

#include <linux/netdevice.h>

#include "octeontx_mbox.h"

#define OCTTX_MAX_NODES	1 /* Maximum number of CPU devices/nodes */

#define get_gmid(x) (x)

struct octeontx_pf_vf {
	bool			in_use;
	u16			domain_id;
	u16			subdomain_id;
	u32			gmid;

	void __iomem		*reg_base;
	struct octeontx_master_com_t *master;
	void			*master_data;
};

struct octeontx_master_com_t {
	int (*send_message)(struct mbox_hdr *hdr,
			    union mbox_data *req,
			    union mbox_data *resp,
			    void *master_data,
			    void *add_data);
	int (*receive_message)(struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp,
			       void *master_data,
			       void *add_data);
	int (*reset_domain)(void *master_data);
};

struct wqe_s {
	u64 work0;
	u64 *work1;
};

struct intr_hand {
	u64	mask;
	char	name[50];
	u64	coffset;
	u64	soffset;
	irqreturn_t (*handler)(int, void *);
};

enum domain_type {
	APP_NET = 0,
	HOST_NET
};

/* Domain network (BGX) port */
#define OCTEONTX_MAX_BGX_PORTS 16 /* Maximum BGX ports per System */

struct octtx_bgx_port {
	struct list_head list;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of BGX port */
	int	glb_port_idx; /* System global index of BGX port */
	int	node; /* CPU node */
	int	bgx; /* Node-local BGX device index */
	int	lmac; /* BGX-local port/LMAC number/index */
	int	base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	num_chans;
	int	pkind; /* PKI port number */
	int	link_up; /* Last retrieved link status */
};

/* Domain internal (LBK) port */
#define OCTEONTX_MAX_LBK_PORTS 2 /* Maximum LBK ports per System */

struct octtx_lbk_port {
	struct list_head list;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of LBK port */
	int	glb_port_idx; /* System global index of LBK port */
	int	node; /* CPU node */
	int	ilbk; /* Node-local index of ingress LBK device */
	int	olbk; /* Node-local index of egress LBK device */
	int	ilbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	ilbk_num_chans;
	int	olbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	olbk_num_chans;
	int	pkind; /* PKI port number */
};
#endif

