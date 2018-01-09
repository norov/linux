/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef _CPTPF_FW_H_
#define _CPTPF_FW_H_

int get_fw_from_blob(const struct firmware **firmware_p, bool is_ae);

#endif
