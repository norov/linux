#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Exercise the kmem "private" attribute across memory hotplug: when it may
# change, and whether onlined memory joins has_memory_noalloc or
# has_memory.
#
# Needs root and DAX_KMEM_TEST_DEV=<daxX.Y|auto>, see private_node_common.sh.

# shellcheck disable=SC1091
DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

trap pn_unbind_kmem_private EXIT
pn_setup

if ! echo unplugged > "$D/state" 2>/dev/null ||
   pn_node_has_memory "$PN"; then
	ktap_exit_fail_msg "private memory cannot be unplugged"
fi

ktap_set_plan 8

name="private mode can be selected while unplugged"
if echo 0 > "$D/private" 2>/dev/null && echo 1 > "$D/private" 2>/dev/null &&
   [ "$(cat "$D/private")" = 1 ]; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="invalid private setting is rejected"
if ! echo invalid > "$D/private" 2>/dev/null &&
   [ "$(cat "$D/private")" = 1 ]; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="private online publishes private memory"
if echo online_movable > "$D/state" 2>/dev/null &&
   pn_node_is_private "$PN" && ! pn_node_in "$PN" has_memory; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

# Writing the current value again is accepted.
name="private mode cannot change while memory blocks exist"
if ! echo 0 > "$D/private" 2>/dev/null &&
   [ "$(cat "$D/private")" = 1 ] && echo 1 > "$D/private" 2>/dev/null; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="unplug removes the private node from memory lists"
if echo unplugged > "$D/state" 2>/dev/null &&
   ! pn_node_in "$PN" has_memory &&
   ! pn_node_in "$PN" has_memory_noalloc; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="common mode preserves normal kmem behavior"
if echo 0 > "$D/private" 2>/dev/null &&
   echo online_movable > "$D/state" 2>/dev/null &&
   pn_node_in "$PN" has_memory && ! pn_node_is_private "$PN"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="online common memory cannot be reclassified as private"
if ! echo 1 > "$D/private" 2>/dev/null &&
   [ "$(cat "$D/private")" = 0 ]; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="private mode can be restored through an unplug cycle"
if echo unplugged > "$D/state" 2>/dev/null &&
   echo 1 > "$D/private" 2>/dev/null &&
   echo online_movable > "$D/state" 2>/dev/null &&
   pn_node_is_private "$PN"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

ktap_finished
