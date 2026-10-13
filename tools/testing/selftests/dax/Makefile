# SPDX-License-Identifier: GPL-2.0
all:

TEST_PROGS := dax-kmem-hotplug.sh
TEST_PROGS += kmem_private.sh
TEST_PROGS += kmem_private_services.sh
TEST_PROGS += kmem_private_policy.sh
TEST_FILES := private_node_common.sh
TEST_GEN_FILES := kmem_private_policy_tool

CFLAGS += -Wall $(KHDR_INCLUDES)

include ../lib.mk
