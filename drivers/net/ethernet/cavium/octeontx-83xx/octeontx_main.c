/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/arm-smccc.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>

#include "octeontx.h"
#include "octeontx_mbox.h"
#include "fpa.h"
#include "fpa.h"
#include "sso.h"
#include "bgx.h"
#include "pko.h"
#include "lbk.h"
#include "tim.h"
#include "pki.h"
#include "dpi.h"

#define DRV_NAME "octeontx"
#define DRV_VERSION "0.1"
#define DEVICE_NAME "octtx-ctr"
#define CLASS_NAME "octeontx-rm"

static struct cdev *octtx_cdev;
static struct device *octtx_device;
static struct class *octtx_class;
static dev_t octtx_dev;

#define	MIN_DOMAIN_ID	4
static atomic_t gbl_domain_id = ATOMIC_INIT(MIN_DOMAIN_ID);

static struct bgx_com_s *bgx;
static struct lbk_com_s *lbk;
static struct fpapf_com_s *fpapf;
static struct ssopf_com_s *ssopf;
static struct pkopf_com_s *pkopf;
static struct timpf_com_s *timpf;
static struct ssowpf_com_s *ssowpf;
static struct pki_com_s *pki;
static struct dpipf_com_s *dpipf;

struct delayed_work dwork;
struct delayed_work dwork_reset;
struct workqueue_struct *check_link;
struct workqueue_struct *reset_domain;

#define MAX_GPIO 80

struct octtx_domain {
	struct list_head list;
	int node;
	int domain_id;
	int setup;
	int type;
	char name[1024];

	int pko_vf_count;
	int fpa_vf_count;
	int sso_vf_count;
	int ssow_vf_count;
	int tim_vf_count;
	int dpi_vf_count;

	u64 aura_set;
	u64 grp_mask;

	int bgx_count;
	int lbk_count;
	struct octtx_bgx_port bgx_port[OCTTX_MAX_BGX_PORTS];
	struct octtx_lbk_port lbk_port[OCTTX_MAX_LBK_PORTS];

	struct attribute_group sysfs_group;
	struct device_attribute sysfs_domain_id;
	bool sysfs_group_created;
	bool sysfs_domain_id_created;

	bool fpa_domain_created;
	bool ssow_domain_created;
	bool sso_domain_created;
	bool pki_domain_created;
	bool lbk_domain_created;
	bool bgx_domain_created;
	bool pko_domain_created;
	bool tim_domain_created;
	bool dpi_domain_created;
};

static int gpio_in_use;
static int gpio_installed[MAX_GPIO];
static struct thread_info *gpio_installed_threads[MAX_GPIO];

static DEFINE_SPINLOCK(octeontx_domains_lock);
static LIST_HEAD(octeontx_domains);

MODULE_AUTHOR("Tirumalesh Chalamarla");
MODULE_DESCRIPTION("Cavium OCTEONTX coprocessor management Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);

static int octeontx_create_domain(const char *name, int type, int sso_count,
				  int fpa_count, int ssow_count, int pko_count,
				  int pki_count, int tim_count, int bgx_count,
				  int lbk_count, int dpi_count,
				  const long int *bgx_port,
				  const long int *lbk_port);

static void octeontx_remove_domain(const char *domain_name);

static void do_remove_domain(struct octtx_domain *domain);

static int octeontx_reset_domain(void *master_data);

static ssize_t octtx_destroy_domain_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf,
					  size_t count)
{
	char tmp_buf[64];
	char *tmp_ptr;
	ssize_t used;

	strlcpy(tmp_buf, buf, 64);
	used = strlen(tmp_buf);
	tmp_ptr = strim(tmp_buf);
	octeontx_remove_domain(tmp_ptr);

	return used;
}

static ssize_t octtx_create_domain_store(struct device *dev,
					 struct device_attribute *attr,
					const char *buf,
					size_t count)
{
	int ret = 0;
	char *start;
	char *end;
	char *ptr;
	char *name;
	char *temp;
	long int type;
	long int sso_count = 0;
	long int fpa_count = 0;
	long int ssow_count = 0;
	long int pko_count = 0;
	long int tim_count = 0;
	long int bgx_count = 0;
	long int lbk_count = 0;
	long int dpi_count = 0;
	long int pki_count = 0;
	long int lbk_port[OCTTX_MAX_LBK_PORTS];
	long int bgx_port[OCTTX_MAX_BGX_PORTS];

	end = kzalloc(PAGE_SIZE, GFP_KERNEL);
	ptr = end;
	memcpy(end, buf, count);

	start = strsep(&end, ";");
	if (!start)
		goto error;

	name = strim(strsep(&start, ":"));
	if (!strcmp(name, ""))
		goto error;
	if (!start)
		type = APP_NET;
	else if (kstrtol(strim(start), 10, &type))
		goto error;

	for (;;) {
		start = strsep(&end, ";");
		if (!start)
			break;
		start = strim(start);
		if (!*start)
			continue;

		if (!strncmp(strim(start), "ssow", sizeof("ssow") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &ssow_count))
				goto error;
		} else if (!strncmp(strim(start), "fpa", sizeof("fpa") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &fpa_count))
				goto error;
		} else if (!strncmp(strim(start), "sso", sizeof("sso") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &sso_count))
				goto error;
		} else if (!strncmp(strim(start), "pko", sizeof("pko") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &pko_count))
				goto error;
		} else if (!strncmp(strim(start), "pki", sizeof("pki") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &pki_count))
				goto error;
		} else if (!strncmp(strim(start), "tim", sizeof("tim") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &tim_count))
				goto error;
		} else if (!strncmp(strim(start), "net", sizeof("net") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &bgx_port[bgx_count]))
				goto error;
			bgx_count++;
		} else if (!strncmp(strim(start), "virt", sizeof("virt") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(strim(start), 10, &lbk_port[lbk_count]))
				goto error;
			lbk_count++;
		} else if (!strncmp(start, "dpi", sizeof("dpi") - 1)) {
			temp = strsep(&start, ":");
			if (!start)
				goto error;
			if (kstrtol(start, 10, &dpi_count))
				goto error;
		} else {
			goto error;
		}
	}

	ret = octeontx_create_domain(name, type, sso_count, fpa_count,
				     ssow_count, pko_count, pki_count,
				     tim_count, bgx_count, lbk_count,
				     dpi_count, (const long int *)bgx_port,
				     (const long int *)lbk_port);
	if (ret)
		goto error;

	kfree(ptr);
	return count;
error:
	dev_err(dev, "Command failed..\n");
	kfree(ptr);
	return count;
}

static struct attribute *octtx_domain_attrs[] = {
	NULL
};

static DEVICE_ATTR(create_domain, 0200, NULL,
		   octtx_create_domain_store);

static DEVICE_ATTR(destroy_domain, 0200, NULL,
		   octtx_destroy_domain_store);

static struct attribute *octtx_attrs[] = {
	&dev_attr_create_domain.attr,
	&dev_attr_destroy_domain.attr,
	NULL
};

static struct attribute_group octtx_attr_group = {
	.name = "octtx_attr",
	.attrs = octtx_attrs,
};

int octtx_sysfs_init(struct device *octtx_device)
{
	int ret;

	ret = sysfs_create_group(&octtx_device->kobj, &octtx_attr_group);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		return ret;
	}
	return 0;
}

void octtx_sysfs_remove(struct device *octtx_device)
{
	sysfs_remove_group(&octtx_device->kobj, &octtx_attr_group);
}

static int octtx_master_receive_message(struct mbox_hdr *hdr,
					union mbox_data *req,
					union mbox_data *resp,
					void *master_data,
					void *add_data)
{
	struct octtx_domain *domain = master_data;

	switch (hdr->coproc) {
	case PKI_COPROC:
		pki->receive_message(0, domain->domain_id, hdr, req,
					resp, add_data);
		break;
	case FPA_COPROC:
		fpapf->receive_message(0, domain->domain_id, hdr, req, resp,
				       add_data);
		break;
	case BGX_COPROC:
		bgx->receive_message(0, domain->domain_id, hdr,
				req, resp, add_data);
		break;
	case LBK_COPROC:
		lbk->receive_message(0, domain->domain_id, hdr,
				req, resp, add_data);
		break;
	case PKO_COPROC:
		pkopf->receive_message(0, domain->domain_id, hdr, req, resp);
		break;
	case TIM_COPROC:
		timpf->receive_message(0, domain->domain_id, hdr,
				req, resp, add_data);
		break;
	case SSO_COPROC:
		if (hdr->msg == SSO_GETDOMAINCFG) {
			struct dcfg_resp *dcfg = add_data;

			dcfg->sso_count = domain->sso_vf_count;
			dcfg->ssow_count = domain->ssow_vf_count;
			dcfg->fpa_count = domain->fpa_vf_count;
			dcfg->pko_count = domain->pko_vf_count;
			dcfg->tim_count = domain->tim_vf_count;
			dcfg->net_port_count = domain->bgx_count;
			dcfg->virt_port_count = domain->lbk_count;
			resp->data = sizeof(struct dcfg_resp);
			hdr->res_code = MBOX_RET_SUCCESS;
			break;
		}
	case DPI_COPROC:
		dpipf->receive_message(0, domain->domain_id, hdr,
				       req, resp, add_data);
		break;
	case SSOW_COPROC:
	default:
		dev_err(octtx_device, "invalid mbox message\n");
		hdr->res_code = MBOX_RET_INVALID;
		break;
	}
	return 0;
}

static struct octeontx_master_com_t octtx_master_com = {
	.receive_message = octtx_master_receive_message,
};

void octeontx_remove_domain(const char *domain_name)
{
	struct octtx_domain *domain = NULL;
	struct octtx_domain *curr;

	spin_lock(&octeontx_domains_lock);
	list_for_each_entry(curr, &octeontx_domains, list) {
		if (!strcmp(curr->name, domain_name)) {
			domain = curr;
			break;
		}
	}

	if (domain) {
		octeontx_reset_domain(domain);
		do_remove_domain(domain);
		list_del(&domain->list);
		module_put(THIS_MODULE);
		kfree(domain);
	}

	spin_unlock(&octeontx_domains_lock);
}

static void do_remove_domain(struct octtx_domain *domain)
{
	u32 ret, node;
	u16 domain_id;

	if (!domain)
		return;

	node = domain->node;
	domain_id = domain->domain_id;

	if (domain->bgx_domain_created) {
		ret = bgx->destroy_domain(node, domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove BGX of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->lbk_domain_created) {
		ret = lbk->destroy_domain(node, domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove LBK of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->pko_domain_created) {
		ret = pkopf->destroy_domain(node, domain_id,
					    &octtx_device->kobj,
					    domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove PKO of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->pki_domain_created) {
		ret = pki->destroy_domain(node, domain_id, &octtx_device->kobj,
					  domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove PKI of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->sso_domain_created) {
		ret = ssopf->destroy_domain(node, domain_id,
					    &octtx_device->kobj,
					    domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove SSO of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->ssow_domain_created) {
		ret = ssowpf->destroy_domain(node, domain_id,
					     &octtx_device->kobj,
					     domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove SSOW of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->tim_domain_created) {
		ret = timpf->destroy_domain(node, domain_id,
					    &octtx_device->kobj,
					    domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove TIM of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->fpa_domain_created) {
		ret = fpapf->destroy_domain(node, domain_id,
					    &octtx_device->kobj,
					    domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove FPA of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->dpi_domain_created) {
		ret = dpipf->destroy_domain(node, domain_id,
					    &octtx_device->kobj,
					    domain->name);
		if (ret) {
			dev_err(octtx_device,
				"Failed to remove dpi of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->sysfs_domain_id_created)
		sysfs_remove_file_from_group(&octtx_device->kobj,
					     &domain->sysfs_domain_id.attr,
					     domain->name);
	if (domain->sysfs_group_created)
		sysfs_remove_group(&octtx_device->kobj,
				   &domain->sysfs_group);
}

static ssize_t octtx_domain_id_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct octtx_domain *domain;

	domain = container_of(attr, struct octtx_domain, sysfs_domain_id);

	return snprintf(buf, PAGE_SIZE, "%d\n", domain->domain_id);
}

int octeontx_create_domain(const char *name, int type, int sso_count,
			   int fpa_count, int ssow_count, int pko_count,
			   int pki_count, int tim_count, int bgx_count,
			   int lbk_count, int dpi_count,
			   const long int *bgx_port,
			   const long int *lbk_port)
{
	void *ssow_ram_mbox_addr = NULL;
	struct octtx_domain *domain;
	u16 domain_id;
	int ret = -EINVAL;
	int node = 0;
	bool found = false;
	int i;

	list_for_each_entry(domain, &octeontx_domains, list) {
		if (!strcmp(name, domain->name)) {
			dev_err(octtx_device,
				"Domain name \"%s\" already exists\n", name);
			return -EEXIST;
		}
	}

	if (!sso_count) {
		dev_err(octtx_device, "Domain has to include at least 1 SSO\n");
		return -EINVAL;
	}

	if (!ssow_count) {
		dev_err(octtx_device,
			"Domain has to include at least 1 SSOW\n");
		return -EINVAL;
	}

	if ((bgx_count + lbk_count) != 0 && pki_count != 1) {
		dev_err(octtx_device, "Domain has to include exactly 1 PKI if there are BGX or LBK ports\n");
		return -EINVAL;
	}

	if (pko_count != bgx_count + lbk_count) {
		dev_err(octtx_device,
			"Domain has to include as many PKOs as there are BGX and LBK ports\n");
		return -EINVAL;
	}

	/*get DOMAIN ID */
	while (!found) {
		domain_id = atomic_add_return(1, &gbl_domain_id);
		domain_id -= 1;
		if (domain_id < MIN_DOMAIN_ID)
			continue;
		found = true;
		list_for_each_entry(domain, &octeontx_domains, list) {
			if (domain->domain_id == domain_id) {
				found = false;
				break;
			}
		}
	}

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return -ENOMEM;

	domain->node = node;
	domain->domain_id = domain_id;
	memcpy(domain->name, name, strlen(name));
	domain->type = type;

	domain->sysfs_group.name = domain->name;
	domain->sysfs_group.attrs = octtx_domain_attrs;
	ret = sysfs_create_group(&octtx_device->kobj, &domain->sysfs_group);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		goto error;
	}
	domain->sysfs_group_created = true;

	domain->fpa_vf_count = fpa_count;
	if (domain->fpa_vf_count) {
		domain->aura_set = fpapf->create_domain(node, domain_id,
							domain->fpa_vf_count,
							&octtx_device->kobj,
							domain->name);
		if (!domain->aura_set) {
			dev_err(octtx_device, "Failed to create FPA domain\n");
			ret = -ENODEV;
			goto error;
		}
		domain->fpa_domain_created = true;
	}

	domain->ssow_vf_count = ssow_count;
	ret = ssowpf->create_domain(node, domain_id, domain->ssow_vf_count,
				    &octtx_master_com, domain,
				    &octtx_device->kobj, domain->name);
	if (ret) {
		dev_err(octtx_device, "Failed to create SSOW domain\n");
		goto error;
	}
	domain->ssow_domain_created = true;

	domain->sso_vf_count = sso_count;
	domain->grp_mask = ssopf->create_domain(node, domain_id,
				domain->sso_vf_count,
				&octtx_master_com, domain,
				&octtx_device->kobj, domain->name);
	if (!domain->grp_mask) {
		dev_err(octtx_device, "Failed to create SSO domain\n");
		goto error;
	}
	domain->sso_domain_created = true;

	ret = ssowpf->get_ram_mbox_addr(node, domain_id, &ssow_ram_mbox_addr);
	if (ret) {
		dev_err(octtx_device, "Failed to get_ssow_ram_mbox_addr\n");
		goto error;
	}

	ret = ssopf->set_mbox_ram(node, domain_id,
				  ssow_ram_mbox_addr, SSOW_RAM_MBOX_SIZE);
	if (ret) {
		dev_err(octtx_device, "Failed to set_ram_addr\n");
		goto error;
	}

	ret = pki->create_domain(node, domain_id, &octtx_master_com, domain,
				 &octtx_device->kobj, domain->name);
	if (ret) {
		dev_err(octtx_device, "Failed to create PKI domain\n");
		goto error;
	}
	domain->pki_domain_created = true;

	/* OCTEONTX allows to create two internal duplex (from the dataplane
	 * user point of view) ports out of four available LBK devices:
	 * virt0: transferring packets between PKO and PKI (LBK0);
	 * virt1: transferring packets between PKO/PKI and NIC (LBK1 + LBK2).
	 * NOTE: The domain specification validity should be done here.
	 */
	domain->lbk_count = lbk_count;
	for (i = 0; i < domain->lbk_count; i++) {
		if (lbk_port[i] > 1) {
			dev_err(octtx_device, "LBK invalid port g%ld\n",
				lbk_port[i]);
			goto error;
		}

		domain->lbk_port[i].domain_id = domain_id;
		domain->lbk_port[i].dom_port_idx = i;
		domain->lbk_port[i].glb_port_idx = lbk_port[i];
		domain->lbk_port[i].pkind = pki->add_lbk_port(node, domain_id,
							&domain->lbk_port[i]);
		if (domain->lbk_port[i].pkind < 0) {
			dev_err(octtx_device,
				"LBK failed to allocate PKIND for port l%d(g%d)\n",
				domain->lbk_port[i].dom_port_idx,
				domain->lbk_port[i].glb_port_idx);
			goto error;
		}
	}

	if (domain->lbk_count) {
		ret = lbk->create_domain(node, domain_id, domain->lbk_port, i,
					 &octtx_master_com, domain);
		if (ret) {
			dev_err(octtx_device, "Failed to create LBK domain\n");
			goto error;
		}
		domain->lbk_domain_created = true;
	}

	/* There is a global list of all network (BGX-based) ports
	 * detected by the thunder driver and provided to this driver.
	 * This list is maintained in bgx.c (octeontx_bgx_ports).
	 * In general domain creation, a list of domain local ports
	 * is constructed as a subset of global ports, where mapping
	 * of domain-local to global indexes is provided as follows:
	 * domain->bgx_port[i].port_idx = i; -- domain-local port index.
	 * domain->bgx_port[i].port_gidx = n; -- global port index.
	 * In this, default configuraiton, all available ports are
	 * given to this domain, except port 0, which is under
	 * Linux, hosting the dataplane application, control.
	 */
	domain->bgx_count = bgx_count;
	if (domain->bgx_count) {
		for (i = 0; i < domain->bgx_count; i++) {
			domain->bgx_port[i].domain_id = domain_id;
			domain->bgx_port[i].dom_port_idx = i;
			domain->bgx_port[i].glb_port_idx = bgx_port[i];
		}
		ret = bgx->create_domain(node, domain_id, domain->bgx_port, i,
				&octtx_master_com, domain);
		if (ret) {
			dev_err(octtx_device, "Failed to create BGX domain\n");
			goto error;
		}
		domain->bgx_domain_created = true;
	}

	/* Now that we know which exact ports we have, set pkinds for them. */
	for (i = 0; i < domain->bgx_count; i++) {
		ret = pki->add_bgx_port(node, domain_id, &domain->bgx_port[i]);
		if (ret < 0) {
			dev_err(octtx_device,
				"BGX failed to allocate PKIND for port l%d(g%d)\n",
				domain->bgx_port[i].dom_port_idx,
				domain->bgx_port[i].glb_port_idx);
			goto error;
		}
		domain->bgx_port[i].pkind = ret;
		ret = bgx->set_pkind(node, domain_id,
				     domain->bgx_port[i].dom_port_idx,
				     domain->bgx_port[i].pkind);
		if (ret < 0) {
			dev_err(octtx_device,
				"BGX failed to set PKIND for port l%d(g%d)\n",
				domain->bgx_port[i].dom_port_idx,
				domain->bgx_port[i].glb_port_idx);
			goto error;
		}
	}

	/* remove this once PKO init extends for LBK. */
	domain->pko_vf_count = bgx_count + lbk_count;
	if (domain->pko_vf_count) {
		ret = pkopf->create_domain(node, domain_id,
					domain->pko_vf_count,
					domain->bgx_port, domain->bgx_count,
					domain->lbk_port, domain->lbk_count,
					&octtx_master_com, domain,
					&octtx_device->kobj, domain->name);
		if (ret) {
			dev_err(octtx_device, "Failed to create PKO domain\n");
			goto error;
		}
		domain->pko_domain_created = true;
	}

	domain->tim_vf_count = tim_count;
	if (domain->tim_vf_count) {
		ret = timpf->create_domain(node, domain_id,
			domain->tim_vf_count, &octtx_master_com, domain,
			&octtx_device->kobj, domain->name);
		if (ret) {
			dev_err(octtx_device, "Failed to create TIM domain\n");
			goto error;
		}
	}
	domain->tim_domain_created = true;

	domain->dpi_vf_count = dpi_count;
	if (domain->dpi_vf_count > 0) {
		ret = dpipf->create_domain(node, domain_id,
					   domain->dpi_vf_count,
					   &octtx_master_com, domain,
					   &octtx_device->kobj, domain->name);
		if (ret) {
			dev_err(octtx_device, "Failed to create DPI domain\n");
			goto error;
		}
	}
	domain->dpi_domain_created = true;

	domain->sysfs_domain_id.show = octtx_domain_id_show;
	domain->sysfs_domain_id.attr.name = "domain_id";
	domain->sysfs_domain_id.attr.mode = 0444;
	sysfs_attr_init(&domain->sysfs_domain_id.attr);
	ret = sysfs_add_file_to_group(&octtx_device->kobj,
				      &domain->sysfs_domain_id.attr,
				      domain->name);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		goto error;
	}
	domain->sysfs_domain_id_created = true;

	spin_lock(&octeontx_domains_lock);
	INIT_LIST_HEAD(&domain->list);
	list_add(&domain->list, &octeontx_domains);
	try_module_get(THIS_MODULE);
	spin_unlock(&octeontx_domains_lock);
	return 0;
error:
	do_remove_domain(domain);
	kfree(domain);
	return ret;
}

static int octeontx_reset_domain(void *master_data)
{
	struct octtx_domain *domain = master_data;
	void *ssow_ram_mbox_addr = NULL;
	int node = domain->node;
	int ret;

	/* Reset co-processors */
	if (domain->bgx_domain_created) {
		ret = bgx->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset BGX of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->lbk_domain_created) {
		ret = lbk->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset LBK of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->tim_domain_created) {
		ret = timpf->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset TIM of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->pko_domain_created) {
		ret = pkopf->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset PKO of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->pki_domain_created) {
		ret = pki->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset PKI of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->sso_domain_created) {
		ret = ssopf->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset SSO of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->ssow_domain_created) {
		ret = ssowpf->reset_domain(node, domain->domain_id,
					   domain->grp_mask);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset SSOW of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	/* FPA reset should be the last one to call*/
	if (domain->fpa_domain_created) {
		ret = fpapf->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset FPA of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	if (domain->dpi_domain_created) {
		ret = dpipf->reset_domain(node, domain->domain_id);
		if (ret) {
			dev_err(octtx_device,
				"Failed to reset DPI of domain %d on node %d.\n",
				domain->domain_id, node);
		}
	}

	/* Reset mailbox */
	ret = ssowpf->get_ram_mbox_addr(node, domain->domain_id,
					&ssow_ram_mbox_addr);
	if (ret) {
		dev_err(octtx_device,
			"Failed ram_mbox_addr for node (%d): domain (%d)\n",
			node, domain->domain_id);
		return ret;
	}
	ret = ssopf->set_mbox_ram(node, domain->domain_id,
				  ssow_ram_mbox_addr, SSOW_RAM_MBOX_SIZE);
	if (ret) {
		dev_err(octtx_device,
			"Failed to set_ram_addr for node (%d): domain (%d)\n",
			node, domain->domain_id);
		return ret;
	}

	return 0;
}

static void poll_for_link(struct work_struct *work)
{
	struct octtx_domain *domain;
	int i, node, bgx_idx, lmac;
	int link_up;

	spin_lock(&octeontx_domains_lock);
	list_for_each_entry(domain, &octeontx_domains, list) {
		/* don't bother if setup is not done */
		if (!domain->setup)
			continue;

		for (i = 0; i < domain->bgx_count; i++) {
			node = domain->bgx_port[i].node;
			bgx_idx = domain->bgx_port[i].bgx;
			lmac = domain->bgx_port[i].lmac;
			link_up = bgx->get_link_status(node, bgx_idx, lmac);
			/* Inform only if link status changed */
			if (link_up == domain->bgx_port[i].link_up)
				continue;

			domain->bgx_port[i].link_up = link_up;
		}
	}
	spin_unlock(&octeontx_domains_lock);
	queue_delayed_work(check_link, &dwork, HZ * 2);
}

void octtx_reset_domain(struct work_struct *work)
{
	struct octtx_domain *domain;
	int i, master_sso;
	u64 mask = -1;
	u64 val;

	spin_lock(&octeontx_domains_lock);
	list_for_each_entry(domain, &octeontx_domains, list) {
		/* find first SSO from domain */
		master_sso = __ffs(domain->grp_mask);
		for_each_set_bit(i, (unsigned long *)&domain->grp_mask,
				 sizeof(domain->grp_mask) * 8) {
			val = atomic_read(&octtx_sso_reset[i]);
			if ((master_sso == i) && val) {
				spin_unlock(&octeontx_domains_lock);
				octeontx_reset_domain(domain);
				spin_lock(&octeontx_domains_lock);
			}
			atomic_set(&octtx_sso_reset[i], 0);
		}
		mask &= ~domain->grp_mask;
	}

	for_each_set_bit(i, (unsigned long *)&mask, sizeof(mask) * 8) {
		if (atomic_read(&octtx_sso_reset[i]))
			atomic_set(&octtx_sso_reset[i], 0);
	}

	/*make sure the other end receives it*/
	mb();

	spin_unlock(&octeontx_domains_lock);
	queue_delayed_work(reset_domain, &dwork_reset, 10);
}

static DEFINE_SPINLOCK(el3_inthandler_lock);

static inline int __install_el3_inthandler(unsigned long gpio_num,
					   unsigned long sp,
					   unsigned long cpu,
					   unsigned long ttbr0)
{
	struct arm_smccc_res res;
	unsigned long flags;
	int retval = -1;

	spin_lock_irqsave(&el3_inthandler_lock, flags);
	if (!gpio_installed[gpio_num]) {
		arm_smccc_smc(THUNDERX_INSTALL_GPIO_INT, gpio_num,
			      sp, cpu, ttbr0, 0, 0, 0, &res);
		if (res.a0 == 0) {
			gpio_installed[gpio_num] = 1;
			retval = 0;
		}
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static inline int __remove_el3_inthandler(unsigned long gpio_num)
{
	struct arm_smccc_res res;
	unsigned long flags;
	unsigned int retval;

	spin_lock_irqsave(&el3_inthandler_lock, flags);
	if (gpio_installed[gpio_num]) {
		arm_smccc_smc(THUNDERX_REMOVE_GPIO_INT, gpio_num,
			      0, 0, 0, 0, 0, 0, &res);
		gpio_installed[gpio_num] = 0;
		retval = 0;
	} else {
		retval = -1;
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static long octtx_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct octtx_gpio_usr_data gpio_usr;
	u64 gpio_ttbr, gpio_isr_base, gpio_sp, gpio_cpu, gpio_num;
	int ret;
	//struct task_struct *task = current;

	if (!gpio_in_use)
		return -EINVAL;

	if (_IOC_TYPE(cmd) != OCTTX_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg,
				 _IOC_SIZE(cmd));
	else if (_IOC_TYPE(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user *)arg,
				 _IOC_SIZE(cmd));

	if (err)
		return -EFAULT;

	switch (cmd) {
	case OCTTX_IOC_SET_GPIO_HANDLER: /*Install GPIO ISR handler*/
		ret = copy_from_user(&gpio_usr, (void *)arg, _IOC_SIZE(cmd));
		if (gpio_usr.gpio_num >= MAX_GPIO)
			return -EINVAL;
		if (ret)
			return -EFAULT;
		gpio_ttbr = 0;
		//TODO: reserve a asid to avoid asid rollovers
		asm volatile("mrs %0, ttbr0_el1\n\t" : "=r"(gpio_ttbr));
		gpio_isr_base = gpio_usr.isr_base;
		gpio_sp = gpio_usr.sp;
		gpio_cpu = gpio_usr.cpu;
		gpio_num = gpio_usr.gpio_num;
		ret = __install_el3_inthandler(gpio_num, gpio_sp,
					       gpio_cpu, gpio_isr_base);
		if (ret == 0)
			gpio_installed_threads[gpio_usr.gpio_num]
				= current_thread_info();
		else
			return -EEXIST;
		break;
	case OCTTX_IOC_CLR_GPIO_HANDLER: /*Clear GPIO ISR handler*/
		gpio_usr.gpio_num = arg;
		if (gpio_usr.gpio_num >= MAX_GPIO)
			return -EINVAL;
		ret = __remove_el3_inthandler(gpio_usr.gpio_num);
		if (ret != 0)
			return -ENOENT;
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

void cleanup_el3_irqs(struct thread_info *thread)
{
	int i;

	for (i = 0; i < MAX_GPIO; i++) {
		if (gpio_installed[i] && (gpio_installed_threads[i] == thread))
			__remove_el3_inthandler(i);
	}
}

static int octtx_dev_open(struct inode *inode, struct file *fp)
{
	gpio_in_use = 1;
	return 0;
}

static int octtx_dev_release(struct inode *inode, struct file *fp)
{
	int i;

	if (gpio_in_use == 0)
		return -EINVAL;

	for (i = 0; i < MAX_GPIO; i++)
		if (gpio_installed[i] != 0)
			__remove_el3_inthandler(i);

	gpio_in_use = 0;
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = octtx_dev_open,
	.release = octtx_dev_release,
	.unlocked_ioctl = octtx_dev_ioctl
};

static int __init octeontx_init_module(void)
{
	int ret;

	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	bgx = bgx_octeontx_init();
	if (!bgx)
		return -ENODEV;
	lbk = try_then_request_module(symbol_get(lbk_com), "lbk");
	if (!lbk)
		return -ENODEV;
	fpapf = try_then_request_module(symbol_get(fpapf_com), "fpapf");
	if (!fpapf) {
		ret = -ENODEV;
		goto fpapf_err;
	}
	ssopf = try_then_request_module(symbol_get(ssopf_com), "ssopf");
	if (!ssopf) {
		ret = -ENODEV;
		goto ssopf_err;
	}
	ssowpf = try_then_request_module(symbol_get(ssowpf_com), "ssowpf");
	if (!ssowpf) {
		ret = -ENODEV;
		goto ssowpf_err;
	}
	pki = try_then_request_module(symbol_get(pki_com), "pki");
	if (!pki) {
		ret = -ENODEV;
		goto pki_err;
	}
	pkopf = try_then_request_module(symbol_get(pkopf_com), "pkopf");
	if (!pkopf) {
		ret = -ENODEV;
		goto pkopf_err;
	}

	dpipf = try_then_request_module(symbol_get(dpipf_com), "dpipf");
	if (!dpipf) {
		ret = -ENODEV;
		goto dpipf_err;
	}

	timpf = try_then_request_module(symbol_get(timpf_com), "timpf");
	if (!timpf) {
		ret = -ENODEV;
		goto timpf_err;
	}

	/* Register a physical link status poll fn() */
	check_link = alloc_workqueue("octeontx_check_link_status",
				     WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!check_link) {
		ret = -ENOMEM;
		goto wq_err;
	}

	/* Register a physical link status poll fn() */
	reset_domain = alloc_workqueue("octeontx_reset_domain",
				       WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!reset_domain) {
		ret = -ENOMEM;
		goto wq_err;
	}

	INIT_DELAYED_WORK(&dwork, poll_for_link);
	INIT_DELAYED_WORK(&dwork_reset, octtx_reset_domain);
	queue_delayed_work(check_link, &dwork, 0);
	queue_delayed_work(reset_domain, &dwork_reset, 0);

	/* create a char device */
	ret = alloc_chrdev_region(&octtx_dev, 1, 1, DEVICE_NAME);
	if (ret != 0) {
		ret = -ENODEV;
		goto alloc_chrdev_err;
	}

	octtx_cdev = cdev_alloc();
	if (!octtx_cdev) {
		ret = -ENODEV;
		goto cdev_alloc_err;
	}

	cdev_init(octtx_cdev, &fops);
	ret = cdev_add(octtx_cdev, octtx_dev, 1);
	if (ret < 0) {
		ret = -ENODEV;
		goto cdev_add_err;
	}

	/* create new class for sysfs*/
	octtx_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(octtx_class)) {
		ret = -ENODEV;
		goto class_create_err;
	}

	octtx_device = device_create(octtx_class, NULL, octtx_dev, NULL,
				     DEVICE_NAME);
	if (IS_ERR(octtx_device)) {
		ret = -ENODEV;
		goto device_create_err;
	}

	ret = octtx_sysfs_init(octtx_device);
	if (ret != 0) {
		ret = -ENODEV;
		goto  sysfs_init_err;
	}

	/* Done */
	return 0;

sysfs_init_err:
	device_destroy(octtx_class, octtx_dev);

device_create_err:
	class_unregister(octtx_class);
	class_destroy(octtx_class);

class_create_err:
cdev_add_err:
	cdev_del(octtx_cdev);

cdev_alloc_err:
	unregister_chrdev_region(octtx_dev, 1);

alloc_chrdev_err:
wq_err:
	symbol_put(timpf_com);

timpf_err:
	symbol_put(dpipf_com);

dpipf_err:
	symbol_put(pkopf_com);

pkopf_err:
	symbol_put(pki_com);

pki_err:
	symbol_put(ssowpf_com);

ssowpf_err:
	symbol_put(ssopf_com);

ssopf_err:
	symbol_put(fpapf_com);

fpapf_err:
	symbol_put(lbk_com);

	return ret;
}

static void __exit octeontx_cleanup_module(void)
{
	cancel_delayed_work_sync(&dwork);
	cancel_delayed_work_sync(&dwork_reset);
	flush_workqueue(check_link);
	flush_workqueue(reset_domain);
	destroy_workqueue(check_link);
	destroy_workqueue(reset_domain);

	octtx_sysfs_remove(octtx_device);
	device_destroy(octtx_class, octtx_dev);
	class_unregister(octtx_class);
	class_destroy(octtx_class);

	cdev_del(octtx_cdev);
	unregister_chrdev_region(octtx_dev, 1);

	symbol_put(pki_com);
	symbol_put(ssopf_com);
	symbol_put(ssowpf_com);
	symbol_put(fpapf_com);
	symbol_put(pkopf_com);
	symbol_put(timpf_com);
	symbol_put(lbk_com);
	symbol_put(thunder_bgx_com);
}

module_init(octeontx_init_module);
module_exit(octeontx_cleanup_module);
