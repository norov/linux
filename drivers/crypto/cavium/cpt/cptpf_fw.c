/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/firmware.h>
#include "cptpf_fw.h"

struct blob {
	u8 *begin;
	u8 *end;
	u8 *name;
};

#define DEFINE_BLOB(tag, file) \
	__asm__( \
		".section \".rodata\", \"a\", @progbits\n" \
		#tag "_blob_begin:\n" \
		".incbin " #file "\n" \
		#tag "_blob_end:\n" \
		".string " #file "\n" \
		".previous\n" \
	       )

#define DECLARE_BLOB(tag) \
	extern u8 tag ##_blob_begin; \
	extern u8 tag ##_blob_end \

#define INIT_BLOB(tag) { \
	.begin = &tag ##_blob_begin, \
	.end = &tag ##_blob_end, \
	.name = &tag ##_blob_end \
}

#define BLOB_NAME(blob) ((blob)->name)
#define BLOB_DATA(blob) ((blob)->begin)
#define BLOB_SIZE(blob) ((blob)->end - (blob)->begin)

DEFINE_BLOB(fw_se_blob, "drivers/crypto/cavium/cpt/cpt_8x_se.bin");
DECLARE_BLOB(fw_se_blob);
static struct blob fw_se_blob = INIT_BLOB(fw_se_blob);
static struct firmware fw_se;

int get_fw_from_blob(const struct firmware **firmware_p, bool is_ae)
{
	if (!firmware_p)
		return -EFAULT;

	/* Currently we do not use AE therefore
	 * we don't support blob for AE
	 */
	if (is_ae)
		return -EINVAL;

	fw_se.data = BLOB_DATA(&fw_se_blob);
	fw_se.size = BLOB_SIZE(&fw_se_blob);
	*firmware_p = &fw_se;

	return 0;
}
