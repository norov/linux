#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check memory policy, migration, reclaim and exhaustion on private kmem
# memory. The checks live in kmem_private_policy_tool, which reports the
# KTAP plan and results.
#
# Needs root, DAX_KMEM_TEST_DEV=<daxX.Y|auto> (see private_node_common.sh)
# and one common memory node. A memoryless node, swap and a cgroup-v2 memory
# controller enable a few more checks.

# shellcheck disable=SC1091
DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR/kmem_private_policy_tool"
CG="$CGROOT/kmem-private-policy-$$"

# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup()
{
	[ -d "$CG" ] && rmdir "$CG" 2>/dev/null
	if [ -n "${MEMCG_ENABLED:-}" ]; then
		echo -memory > "$CGROOT/cgroup.subtree_control" 2>/dev/null
	fi
	pn_unbind_kmem_private
}
trap cleanup EXIT

pn_setup
[ -x "$TOOL" ] || pn_skip "kmem_private_policy_tool not built"
pn_find_common_nodes 1
pn_require_mask_nodes "$PN" "${COMMON[0]}"

# A memoryless node lets the tool check that a private binding names one node.
MEMLESS=
possible=$(cat "$NODE_BASE/possible")
for ((nid = 0; nid < $(getconf LONG_BIT); nid++)); do
	pn_nodelist_has "$possible" "$nid" || continue
	pn_node_has_memory "$nid" && continue
	MEMLESS=$nid
	break
done

# memcg reclaim needs the tool in a non-root memory cgroup.
CG_PROCS=/dev/null
if [ "$(stat -fc %T "$CGROOT" 2>/dev/null)" = cgroup2fs ] &&
   grep -qw memory "$CGROOT/cgroup.controllers" 2>/dev/null; then
	if ! grep -qw memory "$CGROOT/cgroup.subtree_control" &&
	   echo +memory > "$CGROOT/cgroup.subtree_control" 2>/dev/null; then
		MEMCG_ENABLED=1
	fi
	mkdir "$CG" 2>/dev/null && CG_PROCS="$CG/cgroup.procs"
fi

# An empty MEMLESS omits the optional argument.
sh -c "echo \$\$ > '$CG_PROCS'; exec '$TOOL' '$PN' '${COMMON[0]}' $MEMLESS"
