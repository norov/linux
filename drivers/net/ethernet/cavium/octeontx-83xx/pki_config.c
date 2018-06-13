/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include "pki.h"

#define MAX_BGX_PKIND	16
#define MAX_LBK_PKIND	16
#define MAX_SDP_PKIND	16

#define BGX_PKIND_BASE	1
#define LBK_PKIND_BASE	20
#define SDP_PKIND_BASE	40
#define PKI_DROP_STYLE	0

#define QPG_INVALID	((u32)-1)

enum PKI_PORT_STATE {
	PKI_PORT_CLOSE	 = 0,
	PKI_PORT_OPEN	 = 1,
	PKI_PORT_START	 = 2,
	PKI_PORT_STOP	 = 3
};


static int pki_frmlen_reg(struct pki_t *pki, u16 maxlen, u16 minlen)
{
	u64 cfg;
	int i;

	for (i = 0; i < NUM_FRAME_LEN_REG; i++) {
		cfg = pki_reg_read(pki, PKI_FRM_LEN_CHKX(i));
		if (((cfg & 0xff) == minlen) &&
		    (((cfg >> 15) & 0xff) == maxlen))
		return i;
	}
	return -1;
}

void pki_port_reset_regs(struct pki_t *pki, struct pki_port *port)
{
	u32 style = port->init_style;
	u32 qpg_base = port->qpg_base;
	int i;
	u64 cfg;

	for (i = 0; i < pki->max_cls; i++) {
		/*TO_DO read and then write */
		cfg = PKI_DROP_STYLE;
		pki_reg_write(pki, PKI_CLX_PKINDX_STYLE(i, port->pkind), cfg);
		cfg = 0x0;
		pki_reg_write(pki, PKI_CLX_PKINDX_CFG(i, port->pkind), cfg);
		pki_reg_write(pki, PKI_CLX_PKINDX_SKIP(i, port->pkind), cfg);
		pki_reg_write(pki, PKI_CLX_PKINDX_L2_CUSTOM(i, port->pkind),
			      cfg);
		pki_reg_write(pki, PKI_CLX_PKINDX_LG_CUSTOM(i, port->pkind),
			      cfg);
		cfg = 0x1ull << PKI_STYLE_CFG_DROP_SHIFT;
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG(i, style), cfg);
		cfg = 0x0;
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG2(i, style), cfg);
		pki_reg_write(pki, PKI_CLX_STYLEX_ALG(i, style), cfg);
	}
	cfg = 0x0;
	pki_reg_write(pki, PKI_STYLEX_TAG_MASK(style), cfg);
	pki_reg_write(pki, PKI_STYLEX_TAG_SEL(style), cfg);
	pki_reg_write(pki, PKI_STYLEX_WQ2(style), cfg);
	pki_reg_write(pki, PKI_STYLEX_WQ4(style), cfg);

	cfg = 0x6ull << PKI_STYLEX_BUF_FIRST_SKIP_SHIFT |
#ifdef __BIG_ENDIAN
		0x1ull << PKI_STYLEX_BUF_WQE_BEND_SHIFT |
#endif
		0x20ull << PKI_STYLEX_BUF_MB_SIZE_SHIFT;
	pki_reg_write(pki, PKI_STYLEX_BUF(style), cfg);
	cfg = 0;
	for (i = 0; i < port->num_entry; i++) {
		pki_reg_write(pki, PKI_QPG_TBLX(qpg_base + i), cfg);
		pki_reg_write(pki, PKI_QPG_TBLBX(qpg_base + i), cfg);
	}
}

int assign_pkind_bgx(struct pkipf_vf *vf, struct octtx_bgx_port *port)
{
	int pkind;

	if (vf->bgx_port[port->dom_port_idx].valid)
		return -EEXIST;

	/* TO_DO use alloc/free resource */
	pkind = BGX_PKIND_BASE + (port->bgx * 4) + port->lmac;

	if (pkind > (BGX_PKIND_BASE + MAX_BGX_PKIND))
		return -EINVAL;
	vf->bgx_port[port->dom_port_idx].valid = true;
	vf->bgx_port[port->dom_port_idx].pkind = pkind;
	/* by default disable fcs for bgx port as BGX is stripping it,
	 * should be controllabe by app
	 */
	vf->bgx_port[port->dom_port_idx].has_fcs = false;
	vf->bgx_port[port->dom_port_idx].state = PKI_PORT_CLOSE;

	return pkind;
}

int assign_pkind_lbk(struct pkipf_vf *vf, struct octtx_lbk_port *port)
{
	int pkind;

	if (vf->lbk_port[port->dom_port_idx].valid)
		return -EEXIST;

	pkind = LBK_PKIND_BASE + port->glb_port_idx;

	if (pkind > (LBK_PKIND_BASE + MAX_LBK_PKIND))
		return -EINVAL;

	vf->lbk_port[port->dom_port_idx].valid = true;
	vf->lbk_port[port->dom_port_idx].pkind = pkind;
	/* by default disable fcs for lbk port,
	 * should be controllable by app
	 */
	vf->lbk_port[port->dom_port_idx].has_fcs = false;
	vf->lbk_port[port->dom_port_idx].state = PKI_PORT_CLOSE;

	return pkind;
}

int assign_pkind_sdp(struct pkipf_vf *vf, struct octtx_sdp_port *port)
{
	int pkind;

	if (vf->sdp_port[port->dom_port_idx].valid)
		return -EEXIST;

	/* TO_DO use alloc/free resource */
	pkind = SDP_PKIND_BASE;

	if (pkind > (SDP_PKIND_BASE + MAX_SDP_PKIND))
		return -EINVAL;
	vf->sdp_port[port->dom_port_idx].valid = true;
	vf->sdp_port[port->dom_port_idx].pkind = pkind;

	/* by default disable fcs for bgx port as BGX is stripping it,
	 * should be controllabe by app
	 */
	vf->sdp_port[port->dom_port_idx].has_fcs = false;
	vf->sdp_port[port->dom_port_idx].state = PKI_PORT_CLOSE;

	return pkind;
}

void init_styles(struct pki_t *pki)

{
	u32 i, j;
	u64 cfg = 0x1ull << PKI_STYLE_CFG_DROP_SHIFT;
	u64 buf = 0x6ull << PKI_STYLEX_BUF_FIRST_SKIP_SHIFT |
#ifdef __BIG_ENDIAN
		0x1ull << PKI_STYLEX_BUF_WQE_BEND_SHIFT |
#endif
		0x20ull << PKI_STYLEX_BUF_MB_SIZE_SHIFT;

	for (i = 0; i < pki->max_fstyles; i++) {
		pki_reg_write(pki, PKI_STYLEX_BUF(i), buf);
		for (j = 0; j < pki->max_cls; j++)
			pki_reg_write(pki, PKI_CLX_STYLEX_CFG(j, i), cfg);
	}
}

static u32 qpg_range_lookup_by_domain(struct pki_t *pki, u32 qpg_base,
				      u32 qpg_num, u16 domain_id)
{
	u32 curr_num = 0;

	while (curr_num < qpg_num && (qpg_base + curr_num) < pki->max_qpgs) {
		if (pki->qpg_domain[qpg_base + curr_num] == (u16)(~domain_id)) {
			curr_num++;
		} else {
			qpg_base = qpg_base + curr_num + 1;
			curr_num = 0;
			continue;
		}
	}

	if (curr_num == qpg_num)
		return qpg_base;

	return QPG_INVALID;
}

static void qpg_range_assign_to_domain(struct pki_t *pki, u32 qpg_base,
				       u32 qpg_num, u16 domain_id)
{
	u32 qpg_id = qpg_base;

	while (qpg_id < qpg_base + qpg_num) {
		pki->qpg_domain[qpg_id] = ~domain_id;
		qpg_id++;
	}
}

static u32 qpg_range_alloc(struct pki_t *pki, u16 qpg_num, u16 domain_id)
{
	u16 null_domain = ~((u16)0u);
	u32 qpg_base = qpg_range_lookup_by_domain(pki, 0, qpg_num, null_domain);

	if (qpg_base == QPG_INVALID)
		goto exit;
	qpg_range_assign_to_domain(pki, qpg_base, qpg_num, domain_id);
exit:
	return qpg_base;
}

static int qpg_range_free(struct pki_t *pki, u32 qpg_base, u32 qpg_num,
			  u16 domain_id)
{
	u16 null_domain = ~((u16)0u);
	u32 qpg_id = qpg_range_lookup_by_domain(pki, qpg_base, qpg_num,
						domain_id);

	if (qpg_id != qpg_base)
		return -1;
	qpg_range_assign_to_domain(pki, qpg_base, qpg_num, null_domain);

	return 0;
}

int pki_port_open(struct pkipf_vf *vf, u16 vf_id,
		  mbox_pki_port_t *port_data)
{
	struct pki_port *port;
	struct pki_t *pki = vf->pki;
	u64 cfg;
	int i;

	switch (port_data->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state != PKI_PORT_CLOSE && port->valid != true)
		return MBOX_RET_INVALID; /* modify fro virtual ports later*/
	/* Release 1.0 assign style = pkind
	 * later modify it to alloc from max_style
	 * for this vf
	 */
	port->init_style = port->pkind;
	cfg = port->init_style & PKI_PKIND_STYLE_MASK;
	for (i = 0; i < pki->max_cls; i++)
		pki_reg_write(pki, PKI_CLX_PKINDX_STYLE(i, port->pkind), cfg);

	if (port_data->port_type == OCTTX_PORT_TYPE_NET) {
		cfg = port->has_fcs ? (0x1ULL << PKI_PKIND_CFG_FCS_SHIFT) : 0;
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki, PKI_CLX_PKINDX_CFG(i, port->pkind),
				      cfg);
		/* Initialize style typical values*/
		cfg = 0;
		if (port->has_fcs) {
			cfg |= (0x1ULL << PKI_STYLE_CFG_FCS_CHK_SHIFT);
			cfg |= (0x1ULL << PKI_STYLE_CFG_FCS_STRIP_SHIFT);
		}
		cfg |= (0x1ULL << PKI_STYLE_CFG_LENERR_EN_SHIFT);
		cfg |= (0x1ull << PKI_STYLE_CFG_DROP_SHIFT);
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki,
				      PKI_CLX_STYLEX_CFG(i, port->init_style),
				      cfg);

		cfg = 0;
		cfg |= (0x1ULL << PKI_STYLE_CFG2_CSUM_LC_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_CSUM_LD_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_CSUM_LE_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_CSUM_LF_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_LEN_LC_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_LEN_LD_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_LEN_LE_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_LEN_LF_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_TAG_DLC_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_TAG_DLF_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_TAG_SLC_SHIFT);
		cfg |= (0x1ULL << PKI_STYLE_CFG2_TAG_SLF_SHIFT);
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki,
				      PKI_CLX_STYLEX_CFG2(i, port->init_style),
				      cfg);
	} else { /* For OCTTX_PORT_TYPE_PCI */
		for (i = 0; i < pki->max_cls; i++) {
			cfg = pki_reg_read(pki,
					   PKI_CLX_PKINDX_CFG(i, port->pkind));
			cfg |= (0x1ULL << PKI_PKIND_CFG_INST_SHIFT);
			pki_reg_write(pki, PKI_CLX_PKINDX_CFG(i, port->pkind),
				      cfg);
		}

		cfg  = 0;
		for (i = 0; i < pki->max_cls; i++) {
			pki_reg_write(pki,
				      PKI_CLX_STYLEX_CFG(i, port->init_style),
				      cfg);
		}
	} /* END OCTTX_PORT_TYPE_PCI */

	port->state = PKI_PORT_OPEN;
	port->qpg_base = QPG_INVALID;
	port->num_entry = 0;
	cfg = pki_reg_read(pki, PKI_FRM_LEN_CHKX(0));
	port->min_frame_len = cfg & 0xff;
	port->max_frame_len = (cfg >> 15) & 0xff;
	return MBOX_RET_SUCCESS;
}

int pki_port_alloc_qpg(struct pkipf_vf *vf, u16 vf_id,
		       struct mbox_pki_port_qpg_attr *qpg_attr)
{
	struct pki_port *port;
	int qpg_base;
	int ret = MBOX_RET_INVALID;

	switch (qpg_attr->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		goto exit;
	}

	if ((port->state != PKI_PORT_OPEN && port->state != PKI_PORT_STOP))
		return MBOX_RET_INVALID;

	/* Do not allocate QPGs if there are ones already allocated */
	if (port->qpg_base != QPG_INVALID || port->num_entry != 0)
		goto exit;

	qpg_base = qpg_range_alloc(vf->pki, qpg_attr->qpg_num,
				   vf->domain.domain_id);

	if (qpg_base != QPG_INVALID) {
		qpg_attr->qpg_base = qpg_base;
		port->qpg_base = qpg_base;
		port->num_entry = qpg_attr->qpg_num;
		ret = MBOX_RET_SUCCESS;
	}
exit:
	return ret;
}

int pki_port_free_qpg(struct pkipf_vf *vf, u16 vf_id,
		      struct mbox_pki_port_qpg_attr *qpg_attr)
{
	struct pki_port *port;
	int ret = MBOX_RET_INVALID;

	switch (qpg_attr->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		goto exit;
	}

	if ((port->state != PKI_PORT_OPEN && port->state != PKI_PORT_STOP))
		return MBOX_RET_INVALID;

	/* Do not free QPGs if not all will be released */
	if (port->qpg_base != qpg_attr->qpg_base ||
	    port->num_entry != qpg_attr->qpg_num)
		goto exit;

	if (qpg_range_free(vf->pki, qpg_attr->qpg_base, qpg_attr->qpg_num,
			   vf->domain.domain_id) < 0)
		goto exit;

	port->qpg_base = QPG_INVALID;
	port->num_entry = 0;
	ret = MBOX_RET_SUCCESS;
exit:
	return ret;
}

int pki_port_create_qos(struct pkipf_vf *vf, u16 vf_id,
			mbox_pki_qos_cfg_t *qcfg)
{
	struct pki_port *port;
	struct mbox_pki_qos_entry *qpg;
	struct pki_t	*pki = vf->pki;
	int qpg_base;
	u64 cfg;
	int i;
	int style;

	switch (qcfg->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if ((port->state != PKI_PORT_OPEN && port->state != PKI_PORT_STOP))
		return MBOX_RET_INVALID;
	style = port->init_style;
	if (port->qpg_base == QPG_INVALID) {
		qpg_base = qpg_range_alloc(pki, qcfg->num_entry,
					   vf->domain.domain_id);
		if (qpg_base == QPG_INVALID)
			return MBOX_RET_INVALID;
		port->qpg_base = qpg_base;
		port->num_entry = qcfg->num_entry;
	} else {
		if (port->num_entry < qcfg->num_entry)
			return MBOX_RET_INVALID;
		qpg_base = port->qpg_base;
	}
	for (i = 0; i < pki->max_cls; i++) {
		cfg = pki_reg_read(pki, PKI_CLX_STYLEX_ALG(i, style));
		cfg |= (1ull << PKI_STYLE_ALG_TAG_PRT_SHIFT);
		set_field(&cfg, PKI_STYLE_ALG_QPG_QOS_MASK,
			  PKI_STYLE_ALG_QPG_QOS_SHIFT, qcfg->qpg_qos);
		set_field(&cfg, PKI_STYLE_ALG_TT_MASK,
			  PKI_STLYE_ALG_TT_SHIFT, qcfg->tag_type);
		pki_reg_write(pki, PKI_CLX_STYLEX_ALG(i, style), cfg);
	}
	for (i = 0; i < qcfg->num_entry; i++) {
		qpg = &qcfg->qos_entry[i];
		cfg = pki_reg_read(pki, PKI_QPG_TBLX(qpg_base + i));
		set_field(&cfg, PKI_QPG_TBL_GAURA_MASK,
			  PKI_QPG_TBL_GAURA_SHIFT, qpg->gaura);
		set_field(&cfg, PKI_QPG_TBL_GRP_OK_MASK,
			  PKI_QPG_TBL_GRP_OK_SHIFT, qpg->ggrp_ok);
		set_field(&cfg, PKI_QPG_TBL_GRP_BAD_MASK,
			  PKI_QPG_TBL_GRP_BAD_SHIFT, qpg->ggrp_bad);
		set_field(&cfg, PKI_QPG_TBL_PORT_ADD_MASK,
			  PKI_QPG_TBL_PORT_ADD_SHIFT, qpg->port_add);
		set_field(&cfg, PKI_QPG_TBL_GRPTAG_BAD_MASK,
			  PKI_QPG_TBL_GRPTAG_BAD_SHIFT, qpg->grptag_bad);
		set_field(&cfg, PKI_QPG_TBL_GRPTAG_OK_MASK,
			  PKI_QPG_TBL_GRPTAG_OK_SHIFT, qpg->grptag_ok);
		pki_reg_write(pki, PKI_QPG_TBLX(qpg_base + i), cfg);
		dev_dbg(&pki->pdev->dev, "PKI : PKI_QPG_TBLX[%d] :: %llx\n",
			(qpg_base + i),
			pki_reg_read(pki, PKI_QPG_TBLX(qpg_base + i)));
		cfg = pki_reg_read(pki, PKI_QPG_TBLBX(qpg_base + i));
		set_field(&cfg, PKI_QPG_TBLB_STRM_MASK,
			  PKI_QPG_TBLB_STRM_SHIFT, vf->stream_id);
		set_field(&cfg, PKI_QPG_TBLB_ENA_RED_MASK,
			  PKI_QPG_TBLB_ENA_RED_SHIFT, qpg->ena_red);
		set_field(&cfg, PKI_QPG_TBLB_ENA_DROP_MASK,
			  PKI_QPG_TBLB_ENA_DROP_SHIFT, qpg->ena_drop);
		pki_reg_write(pki, PKI_QPG_TBLBX(qpg_base + i), cfg);
		dev_dbg(&pki->pdev->dev, "PKI : PKI_QPG_TBLBX[%d] :: %llx\n",
			(qpg_base + i),
			pki_reg_read(pki, PKI_QPG_TBLBX(qpg_base + i)));
		dev_dbg(&pki->pdev->dev, "PKI : PKI_STREAM[%d] CFG ::%llx\n",
			vf->stream_id,
			pki_reg_read(pki, PKI_STRMX_CFG(vf->stream_id)));
	}
	for (i = 0; i < pki->max_cls; i++) {
		cfg = pki_reg_read(pki, PKI_CLX_STYLEX_CFG(i, style));
		set_field(&cfg, PKI_STYLE_CFG_QPG_BASE_MASK, 0, port->qpg_base);
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG(i, style), cfg);
	}

	dev_dbg(&pki->pdev->dev, "PKI : vf_id::[%d] port QPG BASE::%d type: %d\n",
		vf_id, port->qpg_base, qcfg->port_type);

	port->state = PKI_PORT_STOP;
	return MBOX_RET_SUCCESS;
}

int pki_set_port_config(struct pkipf_vf *vf, u16 vf_id,
			mbox_pki_prt_cfg_t *port_cfg)
{
	struct pki_port *port;
	struct pki_t	*pki = vf->pki;
	u64 cfg, skip, style;
	bool cfg_change, skip_change, style_change;
	int i = 0;
	int ret = MBOX_RET_SUCCESS;

	switch (port_cfg->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state != PKI_PORT_STOP && port->state != PKI_PORT_OPEN)
		return MBOX_RET_INVALID;

	cfg = pki_reg_read(pki, PKI_CLX_PKINDX_CFG(i, port->pkind));
	skip = pki_reg_read(pki, PKI_CLX_PKINDX_SKIP(i, port->pkind));
	style = pki_reg_read(pki, PKI_CLX_PKINDX_STYLE(i, port->pkind));

	cfg_change = false;
	skip_change = false;
	style_change = false;

	if (port_cfg->mmask.parse_mode) {
		switch (port_cfg->parse_mode) {
		case 0x0:
		case 0x1:
		case 0x3:
		case 0x7f:
			break;
		default:
			return MBOX_RET_INVALID;
		}
		set_field(&style, PKI_PKIND_STYLE_PM_MASK,
			  PKI_PKIND_STYLE_PM_SHIFT, port_cfg->parse_mode);
		style_change = true;
	}

	if (port_cfg->mmask.fcs_skip) {
		if (port_cfg->fcs_skip & 0x1)
			return MBOX_RET_INVALID;
		set_field(&skip, PKI_PKIND_SKIP_FCS_MASK,
			  PKI_PKIND_SKIP_FCS_SHIFT, port_cfg->fcs_skip);
		skip_change = true;
	}
	if (port_cfg->mmask.inst_skip) {
		if (port_cfg->inst_skip & 0x1)
			return MBOX_RET_INVALID;
		set_field(&skip, PKI_PKIND_SKIP_INST_MASK,
			  PKI_PKIND_SKIP_INST_SHIFT, port_cfg->inst_skip);
		skip_change = true;
	}

	if (port_cfg->mmask.fcs_pres) {
		set_field(&cfg, PKI_PKIND_CFG_FCS_MASK,
			  PKI_PKIND_CFG_FCS_SHIFT, port_cfg->fcs_pres);
		cfg_change = true;
	}
	if (port_cfg->mmask.fulc_parse) {
		set_field(&cfg, PKI_PKIND_CFG_FULC_MASK,
			  PKI_PKIND_CFG_FULC_SHIFT, port_cfg->fulc_parse);
		cfg_change = true;
	}
	if (port_cfg->mmask.inst_hdr_parse) {
		set_field(&cfg, PKI_PKIND_CFG_INST_MASK,
			  PKI_PKIND_CFG_INST_SHIFT, port_cfg->inst_hdr_parse);
		cfg_change = true;
	}
	if (port_cfg->mmask.mpls_parse) {
		set_field(&cfg, PKI_PKIND_CFG_MPLS_MASK,
			  PKI_PKIND_CFG_MPLS_SHIFT, port_cfg->mpls_parse);
		cfg_change = true;
	}
	if (port_cfg->mmask.hg2_parse) {
		set_field(&cfg, PKI_PKIND_CFG_HG2_MASK, PKI_PKIND_CFG_HG2_SHIFT,
			  port_cfg->hg2_parse);
		cfg_change = true;
	}
	if (port_cfg->mmask.hg_parse) {
		set_field(&cfg, PKI_PKIND_CFG_HG_MASK, PKI_PKIND_CFG_HG_SHIFT,
			  port_cfg->hg_parse);
		cfg_change = true;
	}
	if (port_cfg->mmask.dsa_parse) {
		set_field(&cfg, PKI_PKIND_CFG_DSA_MASK, PKI_PKIND_CFG_DSA_SHIFT,
			  port_cfg->dsa_parse);
		cfg_change = true;
	}

	if (cfg_change) {
		switch ((cfg >> PKI_PKIND_CFG_FULC_DSA_HG_SHIFT) &
			PKI_PKIND_CFG_FULC_DSA_HG_MASK) {
		case 0:
		case (PKI_PKIND_CFG_FULC_MASK << PKI_PKIND_CFG_FULC_SHIFT):
		case (PKI_PKIND_CFG_DSA_MASK << PKI_PKIND_CFG_DSA_SHIFT):
		case (PKI_PKIND_CFG_HG_MASK << PKI_PKIND_CFG_HG_SHIFT):
		case (PKI_PKIND_CFG_HG_MASK << PKI_PKIND_CFG_HG2_SHIFT):
			break;
		default:
			return MBOX_RET_INVALID;
		}
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki, PKI_CLX_PKINDX_CFG(i, port->pkind),
				      cfg);
	}
	if (style_change)
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki, PKI_CLX_PKINDX_STYLE(i, port->pkind),
				      style);
	if (skip_change)
		for (i = 0; i < pki->max_cls; i++)
			pki_reg_write(pki, PKI_CLX_PKINDX_SKIP(i, port->pkind),
				      skip);

	return ret;
}

int pki_port_start(struct pkipf_vf *vf, u16 vf_id,
		   mbox_pki_port_t *port_data)
{
	struct pki_port *port;
	struct pki_t	*pki = vf->pki;
	u64 cfg;
	int i;

	switch (port_data->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state != PKI_PORT_STOP || port->qpg_base == QPG_INVALID)
		return MBOX_RET_INVALID;
	for (i = 0; i < pki->max_cls; i++) {
		cfg = pki_reg_read(pki, PKI_CLX_STYLEX_CFG(i,
							   port->init_style));
		cfg &= ~(0x1ULL << PKI_STYLE_CFG_DROP_SHIFT);
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG(i,
						      port->init_style), cfg);

		dev_dbg(&pki->pdev->dev,
			"PKI: PKI_CL[%d]_STYLE[%d]_CFG : 0x%llx\n", i,
			port->init_style,
			pki_reg_read(pki,
				     PKI_CLX_STYLEX_CFG(i, port->init_style)));
	}
	port->state = PKI_PORT_START;
	return MBOX_RET_SUCCESS;
}

int pki_port_stop(struct pkipf_vf *vf, u16 vf_id,
		  mbox_pki_port_t *port_data)
{
	struct pki_port *port;
	u64 cfg;
	int i;
	struct pki_t *pki = vf->pki;

	switch (port_data->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state != PKI_PORT_START)
		return MBOX_RET_INVALID;
	for (i = 0; i < pki->max_cls; i++) {
		cfg = pki_reg_read(pki, PKI_CLX_STYLEX_CFG(i,
							   port->init_style));
		cfg |= (0x1ULL << PKI_STYLE_CFG_DROP_SHIFT);
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG(i,
						      port->init_style), cfg);
	}
	port->state = PKI_PORT_STOP;
	return MBOX_RET_SUCCESS;
}

int pki_port_close(struct pkipf_vf *vf, u16 vf_id,
		   mbox_pki_port_t *port_data)
{
	struct pki_port *port;

	switch (port_data->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (qpg_range_free(vf->pki, port->qpg_base, port->num_entry,
			   vf->domain.domain_id) < 0)
		return MBOX_RET_INVALID;
	/*TO_DO free up all the resources*/
	/* TO_DO should we write all the register with reset
	 * values at this point?
	 */
	pki_port_reset_regs(vf->pki, port);
	port->init_style = PKI_DROP_STYLE;
	port->qpg_base = QPG_INVALID;
	port->num_entry = 0;
	port->shared_mask = 0;
	port->state = PKI_PORT_CLOSE;
	return MBOX_RET_SUCCESS;
}

int pki_port_pktbuf_cfg(struct pkipf_vf *vf, u16 vf_id,
			mbox_pki_pktbuf_cfg_t *pcfg)
{
	struct pki_port *port;
	struct pki_t *pki = vf->pki;
	u64 reg;
	u8 pkt_outside_wqe, wqe_endian, cache_mode, wqe_hsz;
	u16 mbuff_size, wqe_skip, first_skip, later_skip;

	switch (pcfg->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state != PKI_PORT_OPEN && port->state != PKI_PORT_STOP)
		return MBOX_RET_INVALID;

	reg = pki_reg_read(pki, PKI_STYLEX_BUF(port->init_style));
	/* Read current values */
	wqe_hsz = (reg >> PKI_STYLEX_BUF_WQE_HSZ_SHIFT)
			  & PKI_STYLEX_BUF_WQE_HSZ_MASK;
	pkt_outside_wqe = (reg >> PKI_STYLEX_BUF_DIS_WQ_DAT_SHIFT)
			  & PKI_STYLEX_BUF_DIS_WQ_DAT_MASK;
	wqe_endian = (reg >> PKI_STYLEX_BUF_WQE_BEND_SHIFT)
			  & PKI_STYLEX_BUF_WQE_BEND_MASK;
	cache_mode = (reg >> PKI_STYLEX_BUF_OPC_MODE_SHIFT)
			  & PKI_STYLEX_BUF_OPC_MODE_MASK;
	mbuff_size = (reg >> PKI_STYLEX_BUF_MB_SIZE_SHIFT)
			  & PKI_STYLEX_BUF_MB_SIZE_MASK;
	wqe_skip = (reg >> PKI_STYLEX_BUF_WQE_SKIP_SHIFT)
			  & PKI_STYLEX_BUF_WQE_SKIP_MASK;
	first_skip = (reg >> PKI_STYLEX_BUF_FIRST_SKIP_SHIFT)
			  & PKI_STYLEX_BUF_FIRST_SKIP_MASK;
	later_skip = (reg >> PKI_STYLEX_BUF_LATER_SKIP_SHIFT)
			  & PKI_STYLEX_BUF_LATER_SKIP_MASK;

	/* Update with values from request */
	if (pcfg->mmask.f_mbuff_size) {
		if (pcfg->mbuff_size & 0xf)
			return MBOX_RET_INVALID;
		mbuff_size = (pcfg->mbuff_size >> 3)
			     & PKI_STYLEX_BUF_MB_SIZE_MASK;
	}
	if (pcfg->mmask.f_wqe_skip)
		wqe_skip = (pcfg->wqe_skip >> 7)
			     & PKI_STYLEX_BUF_WQE_SKIP_MASK;
	if (pcfg->mmask.f_first_skip) {
		if (pcfg->first_skip & 0xf)
			return MBOX_RET_INVALID;
		first_skip = (pcfg->first_skip >> 3)
			      & PKI_STYLEX_BUF_FIRST_SKIP_MASK;
	}
	if (pcfg->mmask.f_later_skip) {
		if (pcfg->later_skip & 0xf)
			return MBOX_RET_INVALID;
		later_skip = (pcfg->later_skip >> 3)
			      & PKI_STYLEX_BUF_LATER_SKIP_MASK;
	}
	if (pcfg->mmask.f_pkt_outside_wqe)
		pkt_outside_wqe = pcfg->pkt_outside_wqe
				  & PKI_STYLEX_BUF_DIS_WQ_DAT_MASK;
	if (pcfg->mmask.f_wqe_endian)
		wqe_endian = pcfg->wqe_endian & PKI_STYLEX_BUF_WQE_BEND_MASK;
	if (pcfg->mmask.f_cache_mode)
		cache_mode = pcfg->cache_mode & PKI_STYLEX_BUF_OPC_MODE_MASK;

	/* Validate new configuration */
	if (later_skip > (mbuff_size - 18))
		return MBOX_RET_INVALID;
	if (pkt_outside_wqe) {
		if ((((wqe_skip * 16) + 18) > mbuff_size) ||
		    (first_skip > (mbuff_size - 18)))
			return MBOX_RET_INVALID;
	} else {
		if ((first_skip < ((wqe_skip * 16) + 6)) ||
		    (first_skip > (mbuff_size - 18)))
			return MBOX_RET_INVALID;
	}

	/* Write the register */
	reg = ((u64)wqe_endian << PKI_STYLEX_BUF_WQE_BEND_SHIFT)
	      | ((u64)wqe_hsz << PKI_STYLEX_BUF_WQE_HSZ_SHIFT)
	      | ((u64)wqe_skip << PKI_STYLEX_BUF_WQE_SKIP_SHIFT)
	      | ((u64)first_skip << PKI_STYLEX_BUF_FIRST_SKIP_SHIFT)
	      | ((u64)later_skip << PKI_STYLEX_BUF_LATER_SKIP_SHIFT)
	      | ((u64)cache_mode << PKI_STYLEX_BUF_OPC_MODE_SHIFT)
	      | ((u64)pkt_outside_wqe << PKI_STYLEX_BUF_DIS_WQ_DAT_SHIFT)
	      | ((u64)mbuff_size << PKI_STYLEX_BUF_MB_SIZE_SHIFT);

	pki_reg_write(pki, PKI_STYLEX_BUF(port->init_style), reg);

	dev_dbg(&pki->pdev->dev,
		"PKI: PKI_STYLE[%d]_BUF :: 0x%llx\n", port->init_style,
		pki_reg_read(pki, PKI_STYLEX_BUF(port->init_style)));

	return MBOX_RET_SUCCESS;
}

int pki_port_errchk(struct pkipf_vf *vf, u16 vf_id,
		    mbox_pki_errcheck_cfg_t *cfg)
{
	struct pki_port *port;
	int style;
	u64 scfg;
	u64 scfg2;
	u8 val = 0;
	int i;
	struct pki_t *pki = vf->pki;

	switch (cfg->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state == PKI_PORT_CLOSE)
		return MBOX_RET_INVALID;

	style = port->init_style;
	/*All cluster have same values in 83xx so just read the cluster 0 */
	scfg = pki_reg_read(pki, PKI_CLX_STYLEX_CFG(0, style));
	scfg2 = pki_reg_read(pki, PKI_CLX_STYLEX_CFG2(0, style));

	if (cfg->mmask.f_csum_lc)
		set_clear_bit(&scfg2, cfg->csum_lc,
			      PKI_STYLE_CFG2_CSUM_LC_SHIFT);
	if (cfg->mmask.f_csum_ld)
		set_clear_bit(&scfg2, cfg->csum_ld,
			      PKI_STYLE_CFG2_CSUM_LD_SHIFT);
	if (cfg->mmask.f_csum_le)
		set_clear_bit(&scfg2, cfg->csum_le,
			      PKI_STYLE_CFG2_CSUM_LE_SHIFT);
	if (cfg->mmask.f_csum_lf)
		set_clear_bit(&scfg2, cfg->csum_lf,
			      PKI_STYLE_CFG2_CSUM_LF_SHIFT);
	if (cfg->mmask.f_len_lc)
		set_clear_bit(&scfg2, cfg->len_lc, PKI_STYLE_CFG2_LEN_LC_SHIFT);
	if (cfg->mmask.f_len_ld)
		set_clear_bit(&scfg2, cfg->len_ld, PKI_STYLE_CFG2_LEN_LD_SHIFT);
	if (cfg->mmask.f_len_le)
		set_clear_bit(&scfg2, cfg->len_le, PKI_STYLE_CFG2_LEN_LE_SHIFT);
	if (cfg->mmask.f_len_lf)
		set_clear_bit(&scfg2, cfg->len_lf, PKI_STYLE_CFG2_LEN_LF_SHIFT);

	if (cfg->mmask.f_fcs_chk)
		set_clear_bit(&scfg, cfg->fcs_chk, PKI_STYLE_CFG_FCS_CHK_SHIFT);
	if (cfg->mmask.f_fcs_strip)
		set_clear_bit(&scfg, cfg->fcs_strip,
			      PKI_STYLE_CFG_FCS_STRIP_SHIFT);
	if (cfg->mmask.f_ip6_udp_opt)
		set_clear_bit(&scfg, cfg->ip6_udp_opt,
			      PKI_STYLE_CFG_IP6UDP_SHIFT);
	if (cfg->mmask.f_lenerr_en)
		set_clear_bit(&scfg, cfg->lenerr_en,
			      PKI_STYLE_CFG_LENERR_EN_SHIFT);
	if (cfg->mmask.f_maxerr_en)
		set_clear_bit(&scfg, cfg->maxerr_en,
			      PKI_STYLE_CFG_MAXERR_EN_SHIFT);
	if (cfg->mmask.f_minerr_en)
		set_clear_bit(&scfg, cfg->maxerr_en,
			      PKI_STYLE_CFG_MINERR_EN_SHIFT);
	if (cfg->mmask.f_min_frame_len && cfg->mmask.f_max_frame_len) {
		val = pki_frmlen_reg(pki, cfg->max_frame_len,
				     cfg->min_frame_len);
		if (val >= 0) {
			port->max_frame_len = cfg->max_frame_len;
			port->min_frame_len = cfg->min_frame_len;
		}
	} else if (cfg->mmask.f_max_frame_len) {
		val = pki_frmlen_reg(pki, cfg->max_frame_len,
				     port->min_frame_len);
		if (val >= 0)
			port->max_frame_len = cfg->max_frame_len;
	} else if (cfg->mmask.f_min_frame_len) {
		val = pki_frmlen_reg(pki, port->max_frame_len,
				     cfg->min_frame_len);
		if (val >= 0)
			port->min_frame_len = cfg->min_frame_len;
	}
	if (val >= 0)
		set_clear_bit(&scfg, val, PKI_STYLE_CFG_MINMAX_SEL_SHIFT);

	for (i = 0; i < pki->max_cls; i++) {
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG(i, style), scfg);
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG2(i, style), scfg2);
	}
	return MBOX_RET_SUCCESS;
}

int pki_port_hashcfg(struct pkipf_vf *vf, u16 vf_id,
		     mbox_pki_hash_cfg_t *cfg)
{
	struct pki_port *port;
	int style;
	u64 salg;
	u64 scfg2;
	int i;
	struct pki_t *pki = vf->pki;

	switch (cfg->port_type) {
	case OCTTX_PORT_TYPE_NET:
		port = &vf->bgx_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_PCI:
		port = &vf->sdp_port[vf_id];
		break;
	case OCTTX_PORT_TYPE_INT:
		port = &vf->lbk_port[vf_id];
		break;
	default:
		return MBOX_RET_INVALID;
	}
	if (port->state == PKI_PORT_CLOSE)
		return MBOX_RET_INVALID;

	style = port->init_style;
	salg = pki_reg_read(pki, PKI_CLX_STYLEX_ALG(0, style));
	scfg2 = pki_reg_read(pki, PKI_CLX_STYLEX_CFG2(0, style));

	set_clear_bit(&salg, cfg->tag_vni, PKI_STYLE_ALG_TAG_VNI_SHIFT);
	set_clear_bit(&salg, cfg->tag_gtp, PKI_STYLE_ALG_TAG_GTP_SHIFT);
	set_clear_bit(&salg, cfg->tag_spi, PKI_STYLE_ALG_TAG_SPI_SHIFT);
	set_clear_bit(&salg, cfg->tag_sync, PKI_STYLE_ALG_TAG_SYN_SHIFT);
	set_clear_bit(&salg, cfg->tag_ip_pctl, PKI_STYLE_ALG_TAG_PCTL_SHIFT);
	set_clear_bit(&salg, cfg->tag_vlan1, PKI_STYLE_ALG_TAG_VS1_SHIFT);
	set_clear_bit(&salg, cfg->tag_vlan0, PKI_STYLE_ALG_TAG_VS0_SHIFT);
	set_clear_bit(&salg, cfg->tag_prt, PKI_STYLE_ALG_TAG_PRT_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_slc, PKI_STYLE_CFG2_TAG_SLC_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_sld, PKI_STYLE_CFG2_TAG_SLD_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_sle, PKI_STYLE_CFG2_TAG_SLE_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_slf, PKI_STYLE_CFG2_TAG_SLF_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_dlc, PKI_STYLE_CFG2_TAG_DLC_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_dld, PKI_STYLE_CFG2_TAG_DLD_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_dle, PKI_STYLE_CFG2_TAG_DLE_SHIFT);
	set_clear_bit(&scfg2, cfg->tag_dlf, PKI_STYLE_CFG2_TAG_DLF_SHIFT);

	for (i = 0; i < pki->max_cls; i++) {
		pki_reg_write(pki, PKI_CLX_STYLEX_ALG(i, style), salg);
		pki_reg_write(pki, PKI_CLX_STYLEX_CFG2(i, style), scfg2);
	}
	return MBOX_RET_SUCCESS;
}
