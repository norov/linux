# SPDX-License-Identifier: GPL-2.0
# shellcheck shell=bash disable=SC2034
# Helpers shared by the kmem_private*.sh selftests, sourced after
# ../kselftest/ktap_helpers.sh.
#
# DAX_KMEM_TEST_DEV=<daxX.Y|auto> opts into reconfiguring a device-dax
# instance as private kmem memory. "auto" only uses devices whose memory is
# not online and that no process has open or mapped. A named device is used
# whatever its state. Either is restored on exit.
#
# pn_setup() sets D to the sysfs directory of that device and PN to its node.

DAX_BASE=/sys/bus/dax/devices
NODE_BASE=/sys/devices/system/node

# Whether nodelist $1 (e.g. "0-2,4") contains node $2.
pn_nodelist_has()
{
	local nid=$2 token low high

	for token in ${1//,/ }; do
		low=${token%-*}
		high=${token#*-}
		if [ "$nid" -ge "$low" ] 2>/dev/null &&
		   [ "$nid" -le "$high" ] 2>/dev/null; then
			return 0
		fi
	done
	return 1
}

# Whether node $1 is in the node state list $2, e.g. has_memory.
pn_node_in()
{
	[ -r "$NODE_BASE/$2" ] &&
		pn_nodelist_has "$(cat "$NODE_BASE/$2")" "$1"
}

pn_node_is_private()
{
	pn_node_in "$1" has_memory_noalloc
}

# Whether node $1 has any online memory, ordinary or private.
pn_node_has_memory()
{
	pn_node_in "$1" has_memory || pn_node_is_private "$1"
}

# Whether any process has device node $1 open or mapped.
pn_dev_in_use()
{
	local fd

	for fd in /proc/[0-9]*/fd/*; do
		[ "$(readlink "$fd" 2>/dev/null)" = "$1" ] && return 0
	done
	grep -qs " $1\$" /proc/[0-9]*/maps
}

# Record the original configuration of device $1, bound to driver $2, for
# pn_unbind_kmem_private().
pn_record_kmem()
{
	# Binding the recorded device again keeps its original configuration.
	[ "${PN_DEV:-}" != "$1" ] || return 0
	PN_DEV=$1
	PN_ORIG_DRIVER=$2
	PN_ORIG_STATE=$(cat "$1/state" 2>/dev/null)
	PN_ORIG_PRIVATE=$(cat "$1/private" 2>/dev/null)
	PN_NEW_ID=
}

# Move device $1 from driver $2 to kmem and online it as private memory on
# node $3.
pn_online_private()
{
	local dev=$1 driver=$2 nid=$3 name

	name=$(basename "$dev")
	if [ "$driver" = kmem ]; then
		echo unplugged > "$dev/state" || return 1
	elif [ -n "$driver" ]; then
		echo "$name" > "/sys/bus/dax/drivers/$driver/unbind" || return 1
	fi
	# A private node holds the memory of this device only.
	if pn_node_has_memory "$nid"; then
		return 1
	fi
	if [ "$driver" != kmem ]; then
		echo "$name" > /sys/bus/dax/drivers/kmem/new_id || return 1
		PN_NEW_ID=1
	fi
	echo unplugged > "$dev/state" &&
		echo 1 > "$dev/private" &&
		echo online_movable > "$dev/state" &&
		pn_node_is_private "$nid"
}

# Online device $1 as private kmem memory, or return 1 if it is unusable.
pn_bind_kmem_private()
{
	local dev=$1 name driver nid

	name=$(basename "$dev")
	nid=$(cat "$dev/target_node" 2>/dev/null) || return 1
	driver=$(basename "$(readlink "$dev/driver" 2>/dev/null)" 2>/dev/null)
	if [ "$driver" = kmem ] &&
	   [ "$(cat "$dev/state" 2>/dev/null)" != unplugged ]; then
		# Leave online kmem memory alone unless it is ours or was named.
		if [ "$DAX_KMEM_TEST_DEV" = auto ] &&
		   [ "${PN_DEV:-}" != "$dev" ]; then
			return 1
		fi
		if [ "$(cat "$dev/private" 2>/dev/null)" = 1 ] &&
		   pn_node_is_private "$nid"; then
			pn_record_kmem "$dev" "$driver"
			return 0
		fi
	elif pn_node_has_memory "$nid"; then
		return 1
	elif [ "$DAX_KMEM_TEST_DEV" = auto ] && pn_dev_in_use "/dev/$name"; then
		return 1
	fi

	pn_record_kmem "$dev" "$driver"
	if ! pn_online_private "$dev" "$driver" "$nid" 2>/dev/null; then
		pn_unbind_kmem_private
		return 1
	fi
}

# Restore the device recorded by pn_bind_kmem_private(), if any.
pn_unbind_kmem_private()
{
	local dev=${PN_DEV:-} name

	[ -n "$dev" ] || return 0
	PN_DEV=
	name=$(basename "$dev")
	if [ "$(basename "$(readlink "$dev/driver" 2>/dev/null)")" = kmem ]; then
		echo unplugged > "$dev/state" 2>/dev/null || return 1
		if [ -n "$PN_ORIG_PRIVATE" ]; then
			echo "$PN_ORIG_PRIVATE" > "$dev/private" 2>/dev/null
		fi
	fi
	if [ "$PN_ORIG_DRIVER" = kmem ]; then
		case "$PN_ORIG_STATE" in
		unplugged) ;;
		offline)
			# kmem cannot restore blocks onlined behind its back.
			ktap_print_msg "$name was offline and is left unplugged"
			;;
		*) echo "$PN_ORIG_STATE" > "$dev/state" 2>/dev/null ;;
		esac
		return 0
	fi
	if [ -e "$dev/driver" ]; then
		echo "$name" > /sys/bus/dax/drivers/kmem/unbind 2>/dev/null
	fi
	if [ -n "$PN_NEW_ID" ]; then
		echo "$name" > /sys/bus/dax/drivers/kmem/remove_id 2>/dev/null
	fi
	if [ -n "$PN_ORIG_DRIVER" ]; then
		echo "$name" > "/sys/bus/dax/drivers/$PN_ORIG_DRIVER/bind" \
			2>/dev/null
	fi
	return 0
}

pn_skip()
{
	ktap_skip_all "$1"
	exit "$KSFT_SKIP"
}

# An explicitly selected device must provision, auto may find none.
pn_skip_or_fail()
{
	if [ "$DAX_KMEM_TEST_DEV" = auto ]; then
		pn_skip "$1"
	fi
	ktap_exit_fail_msg "$1"
}

# Print the KTAP header, check the prerequisites and bind a private kmem
# device, setting D and PN.
pn_setup()
{
	local dev nid

	ktap_print_header
	[ "$(id -u)" = 0 ] || pn_skip "must be run as root"
	[ -n "${DAX_KMEM_TEST_DEV:-}" ] ||
		pn_skip "set DAX_KMEM_TEST_DEV=<daxX.Y|auto> to select a test device"
	[ -e "$NODE_BASE/has_memory_noalloc" ] ||
		pn_skip "kernel lacks private memory nodes"
	modprobe -q kmem 2>/dev/null
	[ -d /sys/bus/dax/drivers/kmem ] || pn_skip "dax kmem driver unavailable"

	for dev in "$DAX_BASE"/dax*; do
		if [ "$DAX_KMEM_TEST_DEV" != auto ] &&
		   [ "$(basename "$dev")" != "$DAX_KMEM_TEST_DEV" ]; then
			continue
		fi
		nid=$(cat "$dev/target_node" 2>/dev/null) || continue
		[ "$nid" -ge 0 ] 2>/dev/null || continue
		pn_bind_kmem_private "$dev" || continue
		D=$dev
		PN=$nid
		return 0
	done
	pn_skip_or_fail "no private kmem device"
}
