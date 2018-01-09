/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __CPT_H__
#define __CPT_H__

#include <linux/pci.h>
#include <linux/types.h>
#include "octeontx.h"

struct cptpf_com_s {
	int (*create_domain)(u32, u16, u32, struct kobject *kobj);
	int (*destroy_domain)(u32 id, u16 domain_id, struct kobject *kobj);
	int (*reset_domain)(u32, u16);
};

extern struct cptpf_com_s cptpf_com;

#endif /* __CPT_H__ */

