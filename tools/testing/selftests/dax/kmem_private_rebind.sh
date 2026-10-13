#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check memory policies on private kmem memory while a cgroup-v2 cpuset is
# reshaped, tasks move between cpusets, and the node is hotplugged. Each case
# starts kmem_private_rebind_tool, changes the cpuset or the node, and sends
# the tool SIGUSR1 to check where its memory went.
#
# Needs root, DAX_KMEM_TEST_DEV=<daxX.Y|auto> (see private_node_common.sh),
# two common memory nodes and the cgroup-v2 cpuset controller.

# shellcheck disable=SC1091
DIR="$(dirname "$(readlink -f "$0")")"
. "$DIR"/../kselftest/ktap_helpers.sh
. "$DIR"/private_node_common.sh

TOOL="$DIR/kmem_private_rebind_tool"
CG="$CGROOT/kmem-private-rebind-$$"
CGCOMMON="$CGROOT/kmem-private-rebind-common-$$"
OUT=$(mktemp)

# CHILD is the timeout wrapper and TARGET the tool, which may be its child.
stop_tool()
{
	[ -n "${TARGET:-}" ] && kill "$TARGET" 2>/dev/null
	[ -n "${CHILD:-}" ] && kill "$CHILD" 2>/dev/null
	[ -n "${CHILD:-}" ] && wait "$CHILD" 2>/dev/null
	TARGET=
	CHILD=
}

# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup()
{
	stop_tool
	rm -f "$OUT"
	pn_cpuset_cleanup "$CG" "$CGCOMMON"
	pn_unbind_kmem_private
}
trap cleanup EXIT

wait_output()
{
	local pattern=$1 i

	for ((i = 0; i < 100; i++)); do
		grep -q "$pattern" "$OUT" && return 0
		kill -0 "$CHILD" 2>/dev/null || break
		sleep 0.1
	done
	return 1
}

# Start the tool in mode $1, inside cgroup $2 if given, and wait until it is
# ready for the first SIGUSR1.
start_tool()
{
	local mode=$1 cg=${2:-}

	: > "$OUT"
	if [ -n "$cg" ]; then
		timeout 60 sh -ec "echo \$\$ > '$cg/cgroup.procs'; exec '$TOOL' \
			'$mode' '$PN' '${COMMON[0]}' '${COMMON[1]}'" > "$OUT" 2>&1 &
	else
		timeout 60 "$TOOL" "$mode" "$PN" "${COMMON[0]}" "${COMMON[1]}" \
			> "$OUT" 2>&1 &
	fi
	CHILD=$!
	wait_output '^ready pid=' || return 1
	TARGET=$(sed -n 's/^ready pid=//p' "$OUT")
}

# Signal the tool to check stage $1 and report its result as test $2.
# Returns 1 if the tool did not answer.
report_stage()
{
	local stage=$1 name=$2 line

	if ! kill -USR1 "$TARGET" || ! wait_output "^stage=$stage "; then
		ktap_print_msg "no answer from the tool"
		ktap_test_fail "$name"
		return 1
	fi
	line=$(grep "^stage=$stage " "$OUT")
	ktap_print_msg "$line"
	if grep -q 'ok=1$' <<<"$line"; then
		ktap_test_pass "$name"
	else
		ktap_test_fail "$name"
	fi
}

# Run task policy mode $1 in the cpuset across one cpuset.mems change. The
# tool's result is the last line of $OUT.
run_task_policy()
{
	echo "${COMMON[0]},$PN" > "$CG/cpuset.mems"
	if ! start_tool "$1" "$CG" ||
	   ! echo "${COMMON[1]},$PN" > "$CG/cpuset.mems" ||
	   ! kill -USR1 "$TARGET" || ! wait "$CHILD"; then
		stop_tool
		echo "tool failed" >> "$OUT"
		return 1
	fi
	CHILD=
	TARGET=
}

# Allow or revoke the private node at stage $2, by attaching the tool to
# another cpuset or by writing mask $3 to cpuset.mems, for action $1.
transition_cpuset()
{
	local action=$1 stage=$2 mask=$3

	case "$action:$stage" in
	attach:1) echo "$TARGET" > "$CGCOMMON/cgroup.procs" ;;
	attach:*) echo "$TARGET" > "$CG/cgroup.procs" ;;
	*) echo "$mask" > "$CG/cpuset.mems" ;;
	esac
}

# A private binding in tool mode $1 while its cpuset allows, revokes and
# allows the private node again, by action reshape or attach.
run_private_transitions()
{
	local mode=$1 label=$2 action=${3:-reshape}
	local stage mask title cg=
	local titles=("keeps private pages and placement while the node stays allowed"
		"evacuates private pages and uses common placement when access is revoked"
		"restores the original private request when access returns")

	echo "${COMMON[0]},$PN" > "$CG/cpuset.mems"
	if [ "$action" = attach ]; then
		echo "${COMMON[1]},$PN" > "$CG/cpuset.mems"
	fi
	# Shared-policy parents and task-attachment tools start at the root.
	if [ "$mode" = private-anon ] && [ "$action" = reshape ]; then
		cg=$CG
	fi
	if ! start_tool "$mode" "$cg"; then
		ktap_print_msg "tool setup failed"
		for title in "${titles[@]}"; do
			ktap_test_fail "$label $title"
		done
		stop_tool
		return
	fi
	if [ "$mode" = private-shared ] && [ "$action" = reshape ]; then
		echo "$TARGET" > "$CG/cgroup.procs"
	fi
	for stage in 0 1 2; do
		mask=${COMMON[1]}
		[ "$stage" = 1 ] || mask+=",$PN"
		if ! transition_cpuset "$action" "$stage" "$mask"; then
			ktap_print_msg "cannot change the cpuset"
			ktap_test_fail "$label ${titles[$stage]}"
			continue
		fi
		report_stage "$stage" "$label ${titles[$stage]}"
	done
	wait "$CHILD"
	CHILD=
	TARGET=
}

# Take the private node through stage $1: offline, common, offline, private.
retype_node()
{
	case "$1" in
	0|2) echo unplugged > "$D/state" ;;
	1) echo 0 > "$D/private" && echo online_movable > "$D/state" ;;
	3) echo 1 > "$D/private" && echo online_movable > "$D/state" ;;
	esac
}

# A private binding in tool mode $1 while its node is hotplugged and retyped.
run_private_retype()
{
	local mode=$1 label=$2
	local stage name ready=false
	local titles=("falls back while the private node is offline"
		"binds the original node when it returns as common memory"
		"falls back again after draining the common node"
		"restores private placement when the node returns as private memory")

	echo "${COMMON[1]},$PN" > "$CG/cpuset.mems"
	start_tool "$mode" "$CG" && ready=true
	for stage in 0 1 2 3; do
		name="$label ${titles[$stage]}"
		if [ "$ready" != true ]; then
			ktap_print_msg "tool is not running"
			ktap_test_fail "$name"
		elif ! retype_node "$stage"; then
			ktap_print_msg "cannot hotplug $(basename "$D")"
			ktap_test_fail "$name"
			ready=false
		elif ! report_stage "$stage" "$name"; then
			ready=false
		fi
	done
	stop_tool
	pn_bind_kmem_private "$D"
}

# A static binding in tool mode $1 of a common node that becomes private.
run_common_retype()
{
	local mode=$1 name=$2 line

	if ! echo unplugged > "$D/state" || ! echo 0 > "$D/private" ||
	   ! echo online_movable > "$D/state"; then
		ktap_print_msg "cannot provision common kmem memory"
		ktap_test_fail "$name"
		return
	fi
	echo "${COMMON[0]},$PN" > "$CG/cpuset.mems"
	if ! start_tool "$mode" "$CG"; then
		ktap_print_msg "tool setup failed"
		ktap_test_fail "$name"
		stop_tool
		return
	fi
	if ! echo unplugged > "$D/state" || ! echo 1 > "$D/private" ||
	   ! echo online_movable > "$D/state" ||
	   ! echo "${COMMON[1]},$PN" > "$CG/cpuset.mems"; then
		ktap_print_msg "cannot retype kmem memory"
		ktap_test_fail "$name"
		stop_tool
		return
	fi
	kill -USR1 "$TARGET"
	if wait "$CHILD"; then
		line=$(tail -1 "$OUT")
		ktap_print_msg "$line"
		if grep -q 'ok=1$' <<<"$line"; then
			ktap_test_pass "$name"
		else
			ktap_test_fail "$name"
		fi
	else
		ktap_print_msg "tool failed or timed out"
		ktap_test_fail "$name"
	fi
	CHILD=
	TARGET=
}

pn_setup
[ -x "$TOOL" ] || pn_skip "kmem_private_rebind_tool not built"
pn_find_common_nodes 2
pn_require_mask_nodes "$PN" "${COMMON[@]}"
pn_cpuset_cgroup "$CG"
pn_cpuset_cgroup "$CGCOMMON"
echo "${COMMON[0]},$PN" > "$CG/cpuset.mems" ||
	ktap_exit_fail_msg "cannot set cpuset.mems of $CG"
echo "${COMMON[1]}" > "$CGCOMMON/cpuset.mems" ||
	ktap_exit_fail_msg "cannot set cpuset.mems of $CGCOMMON"

ktap_set_plan 25

run_task_policy interleave
line=$(tail -1 "$OUT")
ktap_print_msg "$line"
name="interleave policy cannot reacquire private memory on rebind"
if grep -q '^private=0 ' <<<"$line"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

run_task_policy bind
line=$(tail -1 "$OUT")
ktap_print_msg "$line"
name="positional cpuset migration excludes private memory"
if grep -q '^private=0 ' <<<"$line"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi
name="removed common-node pages migrate to common fallback"
if grep -q ' new_common=64$' <<<"$line"; then
	ktap_test_pass "$name"
else
	ktap_test_fail "$name"
fi

run_private_transitions private-anon "anonymous binding"
run_private_transitions private-shared \
	"shared binding across distinct mapper cpusets"
run_private_transitions private-anon \
	"anonymous binding across task attachment" attach
run_private_transitions private-shared \
	"shared binding across task attachment" attach
run_private_retype retype-anon "anonymous private binding"
run_private_retype retype-shared "shared private binding"
run_common_retype static \
	"shared common binding falls back after its node becomes private"
run_common_retype static-mixed \
	"shared common binding requires an allowed common target"

ktap_finished
