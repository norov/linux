/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/random.h>

#include "pki.h"

#define DRV_NAME "octeontx-pki"
#define DRV_VERSION "0.1"

static atomic_t pki_count = ATOMIC_INIT(0);

static DEFINE_SPINLOCK(octeontx_pki_devices_lock);
static LIST_HEAD(octeontx_pki_devices);

static irqreturn_t pki_gen_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki_irq;
	u64 gen_int = pki_reg_read(pki, PKI_GEN_INT);

	printk_once("Received GEN INT(%llx)", gen_int);

	pki_reg_write(pki, PKI_GEN_INT, gen_int);
	return IRQ_HANDLED;
}

static irqreturn_t pki_ecc_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki;
	u64 reg;

	dev_err(&pki->pdev->dev, "Received ECC INT\n");
	reg = pki_reg_read(pki, PKI_ECC0_INT);
	dev_err(&pki->pdev->dev, "ecc0:%llx \t", reg);
	pki_reg_write(pki, PKI_ECC0_INT, reg);
	reg = pki_reg_read(pki, PKI_ECC1_INT);
	dev_err(&pki->pdev->dev, "ecc1:%llx \t", reg);
	pki_reg_write(pki, PKI_ECC1_INT, reg);
	reg = pki_reg_read(pki, PKI_ECC2_INT);
	dev_err(&pki->pdev->dev, "ecc2:%llx\n", reg);
	pki_reg_write(pki, PKI_ECC2_INT, reg);

	return IRQ_HANDLED;
}

static irqreturn_t pki_cl_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki_irq;
	u64 reg;

	dev_err(&pki->pdev->dev, "Cluster INT received\n");
	reg = pki_reg_read(pki, PKI_CLX_INT(0));
	dev_err(&pki->pdev->dev, "cl0_int: %llx \t", reg);
	pki_reg_write(pki, PKI_CLX_INT(0), reg);
	reg = pki_reg_read(pki, PKI_CLX_INT(1));
	dev_err(&pki->pdev->dev, "cl1_int: %llx\n", reg);
	pki_reg_write(pki, PKI_CLX_INT(1), reg);

	return IRQ_HANDLED;
}

static irqreturn_t pki_cl_ecc_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki_irq;
	u64 reg;

	dev_err(&pki->pdev->dev, "Cluster ECC INT received\n");
	reg = pki_reg_read(pki, PKI_CLX_ECC_INT(0));
	dev_err(&pki->pdev->dev, "cl0_ecc0_int: %llx \t", reg);
	pki_reg_write(pki, PKI_CLX_ECC_INT(0), reg);
	reg = pki_reg_read(pki, PKI_CLX_ECC_INT(1));
	dev_err(&pki->pdev->dev, "cl1_ecc1_int: %llx\n", reg);
	pki_reg_write(pki, PKI_CLX_ECC_INT(1), reg);

	return IRQ_HANDLED;
}

static irqreturn_t pki_alloc_flt_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki_irq;
	u64 reg;

	dev_err(&pki->pdev->dev, "FPA alloc failed\n");
	reg = pki_reg_read(pki, PKI_ALLOC_FLTX_INT(0));
	dev_err(&pki->pdev->dev, "flt0: %llx \t", reg);
	pki_reg_write(pki, PKI_ALLOC_FLTX_INT(0), reg);
	reg = pki_reg_read(pki, PKI_ALLOC_FLTX_INT(1));
	dev_err(&pki->pdev->dev, "flt1: %llx \t", reg);
	pki_reg_write(pki, PKI_ALLOC_FLTX_INT(1), reg);
	reg = pki_reg_read(pki, PKI_ALLOC_FLTX_INT(2));
	dev_err(&pki->pdev->dev, "flt2: %llx \t", reg);
	pki_reg_write(pki, PKI_ALLOC_FLTX_INT(2), reg);
	reg = pki_reg_read(pki, PKI_ALLOC_FLTX_INT(3));
	dev_err(&pki->pdev->dev, "flt3: %llx\n", reg);
	pki_reg_write(pki, PKI_ALLOC_FLTX_INT(3), reg);

	return IRQ_HANDLED;
}

static irqreturn_t pki_store_flt_intr_handler(int irq, void *pki_irq)
{
	struct pki_t *pki = (struct pki_t *)pki_irq;
	u64 reg;

	dev_err(&pki->pdev->dev, "NCB store fualt\n");
	reg = pki_reg_read(pki, PKI_STRM_FLTX_INT(0));
	dev_err(&pki->pdev->dev, "strm0: %llx \t", reg);
	pki_reg_write(pki, PKI_STRM_FLTX_INT(0), reg);
	reg = pki_reg_read(pki, PKI_STRM_FLTX_INT(1));
	dev_err(&pki->pdev->dev, "strm1: %llx \t", reg);
	pki_reg_write(pki, PKI_STRM_FLTX_INT(1), reg);
	reg = pki_reg_read(pki, PKI_STRM_FLTX_INT(2));
	dev_err(&pki->pdev->dev, "strm2: %llx \t", reg);
	pki_reg_write(pki, PKI_STRM_FLTX_INT(2), reg);
	reg = pki_reg_read(pki, PKI_STRM_FLTX_INT(3));
	dev_err(&pki->pdev->dev, "strm3: %llx \t", reg);
	pki_reg_write(pki, PKI_STRM_FLTX_INT(3), reg);

	return IRQ_HANDLED;
}

static struct intr_hand intr[] = {
	{0x2, "pki gen intr", PKI_GEN_INT_ENA_W1C,
		PKI_GEN_INT_ENA_W1S, pki_gen_intr_handler},
	{0xffff, "pki ecc0 intr", PKI_ECC0_INT_ENA_W1C,
		PKI_ECC0_INT_ENA_W1S, pki_ecc_intr_handler},
	{0x3ffc0f3cff, "pki ecc1 intr", PKI_ECC1_INT_ENA_W1C,
		PKI_ECC1_INT_ENA_W1S, pki_ecc_intr_handler},
	{0x3, "pki ecc2 intr", PKI_ECC2_INT_ENA_W1C,
		PKI_ECC2_INT_ENA_W1S, pki_ecc_intr_handler},
	{0xf, "pki cluster0 intr", PKI_CLX_INT_ENA_W1C(0),
		PKI_CLX_INT_ENA_W1S(0), pki_cl_intr_handler},
	{0xf, "pki cluster1 intr", PKI_CLX_INT_ENA_W1C(1),
		PKI_CLX_INT_ENA_W1S(1), pki_cl_intr_handler},
	{0xff, "pki cluster0 ecc intr", PKI_CLX_ECC_INT_ENA_W1C(0),
		PKI_CLX_ECC_INT_ENA_W1S(0), pki_cl_ecc_intr_handler},
	{0xff, "pki cluster1 ecc intr", PKI_CLX_ECC_INT_ENA_W1C(1),
		PKI_CLX_ECC_INT_ENA_W1S(1), pki_cl_ecc_intr_handler},
	{0xffffffffffffffff, "pki NCB store intr(0)",
		PKI_STRM_FLTX_INT_ENA_W1C(0),
		PKI_STRM_FLTX_INT_ENA_W1S(0), pki_store_flt_intr_handler},
	{0xffffffffffffffff, "pki NCB store intr(1)",
		PKI_STRM_FLTX_INT_ENA_W1C(1),
		PKI_STRM_FLTX_INT_ENA_W1S(1), pki_store_flt_intr_handler},
	{0xffffffffffffffff, "pki NCB store intr(2)",
		PKI_STRM_FLTX_INT_ENA_W1C(2),
		PKI_STRM_FLTX_INT_ENA_W1S(2), pki_store_flt_intr_handler},
	{0xffffffffffffffff, "pki NCB store intr(3)",
		PKI_STRM_FLTX_INT_ENA_W1C(3),
		PKI_STRM_FLTX_INT_ENA_W1S(3), pki_store_flt_intr_handler},
	{0xffffffffffffffff, "pki Alloc fualt intr(0)",
		PKI_ALLOC_FLTX_INT_ENA_W1C(0),
		PKI_ALLOC_FLTX_INT_ENA_W1S(0), pki_alloc_flt_intr_handler},
	{0xffffffffffffffff, "pki Alloc fualt intr(1)",
		PKI_ALLOC_FLTX_INT_ENA_W1C(1),
		PKI_ALLOC_FLTX_INT_ENA_W1S(1), pki_alloc_flt_intr_handler},
	{0xffffffffffffffff, "pki Alloc fualt intr(2)",
		PKI_ALLOC_FLTX_INT_ENA_W1C(2),
		PKI_ALLOC_FLTX_INT_ENA_W1S(2), pki_alloc_flt_intr_handler},
	{0xffffffffffffffff, "pki Alloc fualt intr(3)",
		PKI_ALLOC_FLTX_INT_ENA_W1C(3),
		PKI_ALLOC_FLTX_INT_ENA_W1S(3), pki_alloc_flt_intr_handler}
};

static inline void write_ltype(struct pki_t *pki, u64 ltype, u64 beltype)
{
	u64 reg = PKI_BELTYPE(beltype);

	pki_reg_write(pki, PKI_LTYPEX_MAP(PKI_LTYPE(ltype)), reg);
}

static inline void setup_ltype_map(struct pki_t *pki)
{
	write_ltype(pki, PKI_LTYPE_E_NONE, PKI_BLTYPE_E_NONE);
	write_ltype(pki, PKI_LTYPE_E_ENET, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_VLAN, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_SNAP_PAYLD, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_ARP, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_RARP, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_IP4, PKI_BLTYPE_E_IP4);
	write_ltype(pki, PKI_LTYPE_E_IP4_OPT, PKI_BLTYPE_E_IP4);
	write_ltype(pki, PKI_LTYPE_E_IP6, PKI_BLTYPE_E_IP6);
	write_ltype(pki, PKI_LTYPE_E_IP6_OPT, PKI_BLTYPE_E_IP6);
	write_ltype(pki, PKI_LTYPE_E_IPSEC_ESP, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_IPFRAG, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_IPCOMP, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_TCP, PKI_BLTYPE_E_TCP);
	write_ltype(pki, PKI_LTYPE_E_UDP, PKI_BLTYPE_E_UDP);
	write_ltype(pki, PKI_LTYPE_E_SCTP, PKI_BLTYPE_E_SCTP);
	write_ltype(pki, PKI_LTYPE_E_UDP_VXLAN, PKI_BLTYPE_E_UDP);
	write_ltype(pki, PKI_LTYPE_E_GRE, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_NVGRE, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_GTP, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_UDP_GENEVE, PKI_BLTYPE_E_UDP);
	write_ltype(pki, PKI_LTYPE_E_SW28, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_SW29, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_SW30, PKI_BLTYPE_E_MISC);
	write_ltype(pki, PKI_LTYPE_E_SW31, PKI_BLTYPE_E_MISC);
}

static int load_ucode(struct pki_t *pki)
{
	extern const u64 PKI_MICROCODE_CN83XX_LENGTH;
	extern const u64 PKI_MICROCODE_CN83XX[];
	unsigned int i;

	if (PKI_MICROCODE_CN83XX_LENGTH > PKI_SRAM_SZIE)
		return -1;

	for (i = 0; i < PKI_MICROCODE_CN83XX_LENGTH; i++)
		pki_reg_write(pki, PKI_IMEM(i), PKI_MICROCODE_CN83XX[i]);

	return 0;
}

/*locks should be used by caller
 */
static struct pkipf_vf *pki_get_vf(u32 id, u16 domain_id)
{
	struct pki_t *pki = NULL;
	struct pki_t *curr;
	int i;
	int vf_idx = -1;

	list_for_each_entry(curr, &octeontx_pki_devices, list) {
		if (curr->id == id) {
			pki = curr;
			break;
		}
	}

	if (!pki)
		return NULL;

	for (i = 0; i < PKI_MAX_VF; i++) {
		if (pki->vf[i].domain.domain_id == domain_id) {
			vf_idx = i;
			break;
		}
	}
	if (vf_idx >= 0)
		return &pki->vf[vf_idx];
	else
		return NULL;
}

static int pki_remove_domain(u32 id, u16 domain_id)
{
	struct pki_t *pki = NULL;
	struct pki_t *curr;
	int i;

	spin_lock(&octeontx_pki_devices_lock);
	list_for_each_entry(curr, &octeontx_pki_devices, list) {
		if (curr->id == id) {
			pki = curr;
			break;
		}
	}
	if (!pki) {
		spin_unlock(&octeontx_pki_devices_lock);
		return -ENODEV;
	}

	for (i = 0; i < PKI_MAX_VF; i++) {
		if (pki->vf[i].domain.in_use &&
		    pki->vf[i].domain.domain_id == domain_id)
			pki->vf[i].domain.in_use = false;
	}
	spin_unlock(&octeontx_pki_devices_lock);
	return 0;
}

static int pki_create_domain(u32 id, u16 domain_id,
			     struct octeontx_master_com_t *master_com,
			     void *data,
		struct kobject *kobj, char *g_name)
{
	struct pki_t *pki = NULL;
	struct pki_t *curr;
	int i;
	u8 stream;
	u64 cfg;
	bool found = false;
	struct pci_dev *virtfn;

	spin_lock(&octeontx_pki_devices_lock);
	list_for_each_entry(curr, &octeontx_pki_devices, list) {
		if (curr->id == id) {
			pki = curr;
			break;
		}
	}
	spin_unlock(&octeontx_pki_devices_lock);
	if (!pki)
		return -ENODEV;

	for (i = 0; i < PKI_MAX_VF; i++) {
		if (pki->vf[i].domain.in_use) {/* pki port config */

			continue;
		} else {
			pki->vf[i].domain.domain_id = domain_id;
			pki->vf[i].domain.subdomain_id = 0;
			pki->vf[i].domain.gmid = get_gmid(domain_id);

			if (kobj && g_name) {
				virtfn = pci_get_domain_bus_and_slot(
						pci_domain_nr(pki->pdev->bus),
						pci_iov_virtfn_bus(pki->pdev,
								   i),
						pci_iov_virtfn_devfn(pki->pdev,
								     i));
				if (!virtfn)
					break;
				sysfs_add_link_to_group(kobj, g_name,
							&virtfn->dev.kobj,
					virtfn->dev.kobj.name);
			}

			pki->vf[i].domain.in_use = true;
			stream = i + 1;
			pki->vf[i].stream_id = stream;
			pki->vf[i].pki = pki;
			/* TO_DO if pki resource virtualization implemented*/
			pki->vf[i].max_fstyles = pki->max_fstyles;
			pki->vf[i].max_auras = pki->max_auras;
			pki->vf[i].max_qpgs = pki->max_qpgs;
			pki->vf[i].max_pcam_ents = pki->max_pcam_ents;
			cfg = pki_reg_read(pki, PKI_STRMX_CFG(stream));
			cfg |= (pki->vf[i].domain.gmid) &
				PKI_STRM_CFG_GMID_MASK;
			pki_reg_write(pki, PKI_STRMX_CFG(stream), cfg);
			found = true;
			break;
		}
	}
	if (!found)
		return -ENODEV;

	return 0;
}

static int pki_receive_message(u32 id, u16 domain_id,
			       struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp, void *mdata)
{
	struct pkipf_vf *vf = NULL;

	if (!mdata)
		return -ENOMEM;

	hdr->res_code = MBOX_RET_SUCCESS;
	resp->data = 0;
	spin_lock(&octeontx_pki_devices_lock);

	vf = pki_get_vf(id, domain_id);

	if (!vf) {
		hdr->res_code = MBOX_RET_INVALID;
		spin_unlock(&octeontx_pki_devices_lock);
		return -ENODEV;
	}
	spin_unlock(&octeontx_pki_devices_lock);

	switch (hdr->msg) {
	case MBOX_PKI_PORT_OPEN:
		hdr->res_code = pki_port_open(vf, hdr->vfid, mdata);
		break;
	case MBOX_PKI_PORT_CREATE_QOS:
		hdr->res_code = pki_port_create_qos(vf, hdr->vfid,
						    mdata);
		break;
	case MBOX_PKI_PORT_START:
		hdr->res_code = pki_port_start(vf, hdr->vfid, mdata);
		break;
	case MBOX_PKI_PORT_STOP:
		hdr->res_code = pki_port_stop(vf, hdr->vfid, mdata);
		break;
	case MBOX_PKI_PORT_CLOSE:
		hdr->res_code = pki_port_close(vf, hdr->vfid, mdata);
		break;
	case MBOX_PKI_PORT_PKTBUF_CONFIG:
		hdr->res_code = pki_port_pktbuf_cfg(vf, hdr->vfid,
						    mdata);
		break;
	case MBOX_PKI_PORT_ERRCHK_CONFIG:
		hdr->res_code = pki_port_errchk(vf, hdr->vfid,
						mdata);
		break;
	case MBOX_PKI_PORT_HASH_CONFIG:
		hdr->res_code = pki_port_hashcfg(vf, hdr->vfid, mdata);
		break;
	}
	return 0;
}

int pki_reset_domain(u32 id, u16 domain_id)
{
	/* TO_DO*/
	return 0;
}

/* Add a new port to PKI
 * return PKIND on success, -ERR on failure
 */
int pki_add_bgx_port(u32 id, u16 domain_id, struct octtx_bgx_port *port)
{
	struct pkipf_vf *vf = NULL;
	int pkind;

	spin_lock(&octeontx_pki_devices_lock);

	vf = pki_get_vf(id, domain_id);
	if (!vf) {
		spin_unlock(&octeontx_pki_devices_lock);
		return -ENODEV;
	}

	pkind = assign_pkind_bgx(vf, port);

	spin_unlock(&octeontx_pki_devices_lock);
	return pkind;
}

int pki_add_lbk_port(u32 id, u16 domain_id, struct octtx_lbk_port *port)
{
	struct pkipf_vf *vf = NULL;
	int pkind;

	spin_lock(&octeontx_pki_devices_lock);

	vf = pki_get_vf(id, domain_id);
	if (!vf) {
		spin_unlock(&octeontx_pki_devices_lock);
		return -ENODEV;
	}

	/*TO_DO it needs channel number too*/
	pkind = assign_pkind_lbk(vf, port);

	spin_unlock(&octeontx_pki_devices_lock);
	return pkind;
}

struct pki_com_s pki_com  = {
	.create_domain = pki_create_domain,
	.free_domain = pki_remove_domain,
	.reset_domain = pki_reset_domain,
	.receive_message = pki_receive_message,
	.add_bgx_port = pki_add_bgx_port,
	.add_lbk_port = pki_add_lbk_port
};
EXPORT_SYMBOL(pki_com);

static void pki_irq_free(struct pki_t *pki)
{
	int i;

	/*clear intr */
	for (i = 0; i < PKI_MSIX_COUNT; i++) {
		pki_reg_write(pki, intr[i].coffset, intr[i].mask);
		if (pki->msix_entries[i].vector)
			free_irq(pki->msix_entries[i].vector, pki);
	}
	pci_disable_msix(pki->pdev);
}

static int pki_irq_init(struct pki_t *pki)
{
	int i;
	int ret = 0;

	/*clear intr */
	for (i = 0; i < PKI_MSIX_COUNT; i++)
		pki_reg_write(pki, intr[i].coffset, intr[i].mask);

	pki->msix_entries = devm_kzalloc(&pki->pdev->dev,
			PKI_MSIX_COUNT * sizeof(struct msix_entry), GFP_KERNEL);

	if (!pki->msix_entries)
		return -ENOMEM;

	for (i = 0; i < PKI_MSIX_COUNT; i++)
		pki->msix_entries[i].entry = i;

	ret = pci_enable_msix_exact(pki->pdev, pki->msix_entries, PKI_MSIX_COUNT);
	if (ret < 0) {
		dev_err(&pki->pdev->dev, "Enabling msix failed\n");
		return ret;
	}

	for (i = 0; i < PKI_MSIX_COUNT; i++) {
		ret = request_irq(pki->msix_entries[i].vector, intr[i].handler,
				  0, intr[i].name, pki);
		if (ret)
			goto free_irq;
	}

	/*enable intr */
	for (i = 0; i < PKI_MSIX_COUNT; i++)
		pki_reg_write(pki, intr[i].soffset, intr[i].mask);

	return 0;
free_irq:
	for ( ; i < PKI_MSIX_COUNT; i++)
		pki->msix_entries[i].vector = 0;
	pki_irq_free(pki);
	return ret;
}

static void pki_init(struct pki_t *pki)
{
	u64 reg;
	u32 delay;

	/* wait till SFT rest is feasable*/
	while (true) {
		if (!pki_reg_read(pki, PKI_SFT_RST))
			break;
	}
	pki_reg_write(pki, PKI_SFT_RST, 0x1);
	/* wait till RST complete */
	while (true) {
		if (!pki_reg_read(pki, PKI_SFT_RST))
			break;
	}

	reg = pki_reg_read(pki, PKI_CONST);
	pki->max_auras = (reg >> PKI_CONST_AURAS_SHIFT) & PKI_CONST_AURAS_MASK;
	pki->max_bpid = (reg >> PKI_CONST_BPID_SHIFT) & PKI_CONST_BPID_MASK;
	pki->max_pkinds = (reg >> PKI_CONST_PKNDS_SHIFT) & PKI_CONST_PKNDS_MASK;
	pki->max_fstyles = (reg >> PKI_CONST_FSTYLES_SHIFT) &
			PKI_CONST_FSTYLES_MASK;

	reg = pki_reg_read(pki, PKI_CONST1);
	pki->max_cls = (reg >> PKI_CONST1_CLS_SHIFT) & PKI_CONST1_CLS_MASK;
	pki->max_ipes = (reg >> PKI_CONST1_IPES_SHIFT) & PKI_CONST1_IPES_MASK;
	pki->max_pcams = (reg >> PKI_CONST1_PCAMS_SHIFT) &
			PKI_CONST1_PCAMS_MASK;

	reg = pki_reg_read(pki, PKI_CONST2);
	pki->max_pcam_ents = (reg >> PKI_CONST2_PCAM_ENTS_SHIFT) &
			PKI_CONST2_PCAM_ENTS_MASK;
	pki->max_qpgs = (reg >> PKI_CONST2_QPGS_SHIFT) & PKI_CONST2_QPGS_MASK;
	pki->max_dstats = (reg >> PKI_CONST2_DSTATS_SHIFT) &
			PKI_CONST2_DSTATS_MASK;
	pki->max_stats = (reg >> PKI_CONST2_STATS_SHIFT) &
			PKI_CONST2_STATS_MASK;

	load_ucode(pki);
	delay = max(0xa0, (800 / pki->max_cls));
	reg = PKI_ICG_CFG_MAXIPE_USE(0x14) | PKI_ICG_CFG_CLUSTERS(0x3) |
	       PKI_ICG_CFG_PENA(1) | PKI_ICG_CFG_DELAY(delay);
	pki_reg_write(pki, PKI_ICGX_CFG(0), reg);

	setup_ltype_map(pki);
	init_styles(pki);
	/*enable PKI*/
	reg = pki_reg_read(pki, PKI_BUF_CTL);
	reg |= 0x1;
	pki_reg_write(pki, PKI_BUF_CTL, reg);
}

static int pki_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct pki_t *pki = pci_get_drvdata(pdev);
	int ret = -EBUSY;
	int disable = 0;

	if (pki->vfs_in_use != 0)
		return ret;

	ret = 0;
	if (pki->flags & PKI_SRIOV_ENABLED)
		disable = 1;

	if (disable) {
		pci_disable_sriov(pdev);
		pki->flags &= ~PKI_SRIOV_ENABLED;
		pki->total_vfs = 0;
	}

	if (numvfs > 0) {
		ret = pci_enable_sriov(pdev, numvfs);
		if (ret == 0) {
			pki->flags |= PKI_SRIOV_ENABLED;
			pki->total_vfs = numvfs;
			ret = numvfs;
		}
	}
	return ret;
}

static int pki_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct pki_t *pki;
	int err = -ENOMEM;

	pki = devm_kzalloc(dev, sizeof(*pki), GFP_KERNEL);
	if (!pki)
		return err;

	pci_set_drvdata(pdev, pki);
	pki->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed\n");
		return err;
	}

	/*Map CFG registers */
	pki->reg_base = pcim_iomap(pdev, PCI_PKI_CFG_BAR, 0);
	if (!pki->reg_base) {
		dev_err(dev, "Can't map CFG space\n");
		err = -ENOMEM;
		return err;
	}

	/*set PKI ID */
	pki->id = atomic_add_return(1, &pki_count);
	pki->id -= 1;

	pki_init(pki);

	err = pki_irq_init(pki);
	if (err) {
		dev_err(dev, "failed init irqs\n");
		err = -EINVAL;
		return err;
	}

	INIT_LIST_HEAD(&pki->list);
	spin_lock(&octeontx_pki_devices_lock);
	list_add(&pki->list, &octeontx_pki_devices);
	spin_unlock(&octeontx_pki_devices_lock);

	return 0;
}

static void pki_remove(struct pci_dev *pdev)
{
	struct pki_t *pki = pci_get_drvdata(pdev);
	struct pki_t *curr;

	if (!pki)
		return;

	spin_lock(&octeontx_pki_devices_lock);
	list_for_each_entry(curr, &octeontx_pki_devices, list) {
		if (curr == pki) {
			list_del(&pki->list);
			break;
		}
	}
	spin_unlock(&octeontx_pki_devices_lock);

	pki_irq_free(pki);
}

/* devices supported */
static const struct pci_device_id pki_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_PKI) },
	{ 0, }  /* end of table */
};

static struct pci_driver pki_driver = {
	.name = DRV_NAME,
	.id_table = pki_id_table,
	.probe = pki_probe,
	.remove = pki_remove,
	.sriov_configure = pki_sriov_configure,
};

MODULE_AUTHOR("Tirumalesh Chalamarla");
MODULE_DESCRIPTION("Cavium OCTEONTX input packet parser(PKI) Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, pki_id_table);

static int __init pki_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&pki_driver);
}

static void __exit pki_cleanup_module(void)
{
	pci_unregister_driver(&pki_driver);
}

module_init(pki_init_module);
module_exit(pki_cleanup_module);
