#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check that cgroup-v2 cpuset.mems may name a private kmem node without
# exposing it to ordinary allocations.
#
# Needs root, DAX_KMEM_TEST_DEV=<daxX.Y|auto> (see private_node_common.sh),
# one common memory node and the cgroup-v2 cpuset controller.

# shellcheck disable=SC1091
DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR/kmem_private_rebind_tool"
CG="$CGROOT/kmem-private-cpuset-$$"

# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup()
{
	pn_cpuset_cleanup "$CG"
	pn_unbind_kmem_private
}
trap cleanup EXIT

pn_setup
[ -x "$TOOL" ] || pn_skip "kmem_private_rebind_tool not built"
pn_find_common_nodes 1
pn_require_mask_nodes "$PN" "${COMMON[0]}"
pn_cpuset_cgroup "$CG"

ktap_set_plan 4

name="mixed common/private cpuset.mems is accepted"
if echo "${COMMON[0]},$PN" > "$CG/cpuset.mems" 2>/dev/null &&
   pn_nodelist_has "$(cat "$CG/cpuset.mems.effective")" "$PN"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="a private-only request keeps the node and inherits common memory"
if echo "$PN" > "$CG/cpuset.mems" 2>/dev/null &&
   pn_nodelist_has "$(cat "$CG/cpuset.mems")" "$PN" &&
   pn_nodelist_has "$(cat "$CG/cpuset.mems.effective")" "$PN" &&
   pn_nodelist_has "$(cat "$CG/cpuset.mems.effective")" "${COMMON[0]}"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

name="ordinary allocation in the cpuset stays on common memory"
out=$(timeout 60 sh -c "echo \$\$ > '$CG/cgroup.procs'; exec '$TOOL' \
	ordinary '$PN' '${COMMON[0]}' '${COMMON[0]}'")
if [ "$out" = "private=0" ]; then
	ktap_test_pass "$name"
else
	ktap_print_msg "$out"
	ktap_test_fail "$name"
fi

name="removing the private node revokes it"
if echo "${COMMON[0]}" > "$CG/cpuset.mems" 2>/dev/null &&
   ! pn_nodelist_has "$(cat "$CG/cpuset.mems.effective")" "$PN"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

ktap_finished
