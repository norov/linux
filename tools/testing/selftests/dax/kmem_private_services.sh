#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check which MM services a private kmem node gets: no HugeTLB pool pages,
# but kswapd, kcompactd and per-node compaction and reclaim.
#
# Needs root and DAX_KMEM_TEST_DEV=<daxX.Y|auto>, see private_node_common.sh.

# shellcheck disable=SC1091
DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

trap pn_unbind_kmem_private EXIT
pn_setup

ktap_set_plan 5

# Use the default size: a gigantic page may not fit the device at all.
hsize=$(awk '/^Hugepagesize:/ { print $2 }' /proc/meminfo)
pool="$NODE_BASE/node$PN/hugepages/hugepages-${hsize}kB/nr_hugepages"
global=/sys/kernel/mm/hugepages/hugepages-${hsize}kB/nr_hugepages
name_node="per-node HugeTLB pool growth skips private memory"
name_global="HugeTLB pool growth falls back to other nodes"
if [ -z "$hsize" ] || [ ! -w "$pool" ] || [ ! -w "$global" ]; then
	ktap_print_msg "HugeTLB pools unavailable"
	ktap_test_skip "$name_node"
	ktap_test_skip "$name_global"
else
	before=$(cat "$pool")
	echo $((before + 8)) > "$pool" 2>/dev/null
	after=$(cat "$pool")
	echo "$before" > "$pool" 2>/dev/null
	if [ "$after" = "$before" ]; then
		ktap_test_pass "$name_node"
	else
		ktap_print_msg "private-node pool grew $before->$after"
		ktap_test_fail "$name_node"
	fi

	gbefore=$(cat "$global")
	echo $((gbefore + 64)) > "$global" 2>/dev/null
	gafter=$(cat "$global")
	after=$(cat "$pool")
	echo "$gbefore" > "$global" 2>/dev/null
	if [ "$gafter" -le "$gbefore" ]; then
		ktap_print_msg "HugeTLB pool could not grow on any node"
		ktap_test_skip "$name_global"
	elif [ "$after" = "$before" ]; then
		ktap_test_pass "$name_global"
	else
		ktap_print_msg "private-node pool grew $before->$after"
		ktap_test_fail "$name_global"
	fi
fi

compact="$NODE_BASE/node$PN/compact"
name="kswapd and kcompactd run for the private node"
if ! pgrep -x "kswapd$PN" >/dev/null; then
	ktap_print_msg "kswapd$PN is not running"
	ktap_test_fail "$name"
elif [ ! -e "$compact" ]; then
	ktap_print_msg "kcompactd unavailable without compaction"
	ktap_test_skip "$name"
elif pgrep -x "kcompactd$PN" >/dev/null; then
	ktap_test_pass "$name"
else
	ktap_print_msg "kcompactd$PN is not running"
	ktap_test_fail "$name"
fi

name="private-node compaction is accepted"
if [ ! -e "$compact" ]; then
	ktap_print_msg "per-node compaction unavailable"
	ktap_test_skip "$name"
elif echo 1 > "$compact" 2>/dev/null; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

reclaim="$NODE_BASE/node$PN/reclaim"
name="private-node reclaim is accepted"
if [ ! -e "$reclaim" ]; then
	ktap_print_msg "per-node reclaim unavailable"
	ktap_test_skip "$name"
elif err=$(export LC_ALL=C; echo 1M 2>&1 > "$reclaim"); then
	ktap_test_pass "$name"
elif [[ $err == *"Resource temporarily unavailable"* ]]; then
	# An idle node may have nothing to reclaim.
	ktap_test_pass "$name"
else
	ktap_print_msg "$err"
	ktap_test_fail "$name"
fi

ktap_finished
