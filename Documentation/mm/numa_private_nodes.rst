.. SPDX-License-Identifier: GPL-2.0

====================
Private memory nodes
====================

A private memory node is a NUMA node whose memory the kernel does not use for
ordinary allocations. Applications place memory there only by asking for that
node explicitly. This keeps specialized memory, such as HBM or coherent device
memory, visible as a NUMA node without making it a general fallback for every
allocation. Memory that is not private is called common memory.

The kernel manages a private node's memory with the usual page allocator. The
driver that provides the memory decides which memory management services the
node also gets. The dax kmem private mode described below enables reclaim,
compaction and explicit placement by applications.

``/sys/devices/system/node/has_memory_noalloc`` lists the private nodes, and
``has_memory`` lists nodes available to ordinary allocations. The lists are
disjoint; their union contains all nodes with online memory.

The corresponding kernel states are ``N_MEMORY_NOALLOC`` and ``N_MEMORY``.
Topology and per-node accounting include both sets. Private nodes can still
serve explicit private allocations and opt into individual MM services.

Creating a private node
=======================

Private memory is added through memory hotplug and requires ``CONFIG_NUMA``.
With ``CONFIG_DEV_DAX_KMEM`` and ``CONFIG_MEMORY_HOTREMOVE``, a device-dax
instance bound to ``kmem`` can be onlined as private memory. Select private mode
while the device's memory is unplugged::

    echo unplugged > /sys/bus/dax/devices/daxX.Y/state
    echo 1 > /sys/bus/dax/devices/daxX.Y/private
    echo online_movable > /sys/bus/dax/devices/daxX.Y/state

The ``private`` attribute defaults to 0, which keeps ordinary kmem behavior.
Its value can change only while the device is unplugged. Unbinding kmem
discards the setting. Bind the device with memory auto-onlining disabled, so
that its memory is not onlined as common memory first.

All System RAM on a node shares one configuration. Adding memory with a
different configuration to a node that already has System RAM fails with
``-EBUSY``. To change the configuration, remove every System RAM block on the
node first. Offlining the blocks is not enough, since offline blocks keep their
configuration so they can be onlined again.

A private node may have CPUs. Like the CPUs of a memoryless node, they get
ordinary memory from the nearest common nodes.

Using private memory
====================

An application binds an anonymous or shmem-backed mapping to one private node
with ``mbind(2)``, passing ``MPOL_BIND | MPOL_F_PRIVATE_NODES``, before it
faults the pages in::

    buf = mmap(NULL, length, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /* mask contains exactly the chosen private node */
    mbind(buf, length, MPOL_BIND | MPOL_F_PRIVATE_NODES, mask, maxnode, 0);
    memset(buf, 0, length);

``mbind(2)`` rejects a private binding with ``-EINVAL`` if:

- the mask names more than one node, or a node that is not private memory
  with userspace placement enabled.
- the mode is not ``MPOL_BIND``, or the flag is combined with
  ``MPOL_F_STATIC_NODES``, ``MPOL_F_RELATIVE_NODES`` or
  ``MPOL_F_NUMA_BALANCING``.
- the mapping is a HugeTLB mapping. Private nodes hold no HugeTLB pages.
- the node is not in the caller's cpuset.

Kernels without private node support reject the flag with ``-EINVAL``, so
applications can probe for it. ``get_mempolicy(2)`` reports the flag.

Without ``MPOL_F_PRIVATE_NODES``, private nodes in a ``set_mempolicy(2)`` or
``mbind(2)`` mask are ignored, as nodes outside the cpuset are. A mask that
names only private nodes is therefore rejected with ``-EINVAL``.
``set_mempolicy(2)`` does not accept the flag, because a task policy also
applies to the kernel's allocations on behalf of the task. Preferred,
interleave and preferred-many policies, tmpfs ``mpol=`` mount options, HugeTLB
pools and automatic NUMA balancing use only common memory.

``move_pages(2)`` and ``migrate_pages(2)`` can move pages to a private node
with userspace placement enabled, subject to their usual permission checks.
They take no flag. ``move_pages(2)`` rejects other private nodes with
``-ENODEV``, and ``migrate_pages(2)`` ignores them, as it ignores nodes outside
the caller's cpuset.

Page cache for regular files is never allocated from private memory.
Copy-on-write pages of a private file mapping follow a binding like anonymous
memory, and explicit migration can move existing file pages to a private node.
A private binding on a shmem-backed mapping allocates its pages from the
private node, and reclaim swaps them out like other shmem pages.

guest_memfd memory cannot be moved, so a binding places it on a private node
only if the node has memory onlined as ``online`` or ``online_kernel``.

Controlling access
==================

``cpuset.mems`` includes private nodes by default, so any task can bind to a
private node and use up its capacity. Use ``cpuset.mems`` to limit which tasks
may use a private node. Listing a private node in ``cpuset.mems`` permits
private bindings to it. Tasks do not otherwise allocate from it.

In cgroup v2, a ``cpuset.mems`` that names only private nodes is accepted, and
the parent's common nodes are added to ``cpuset.mems.effective`` so that tasks
always have memory for ordinary allocations. The parent's other private nodes
are not added. An empty ``cpuset.mems`` inherits the parent's effective nodes,
private nodes included.

In cgroup v1, writing a ``cpuset.mems`` that names only private nodes, or
attaching a task to such a cpuset, fails with ``-ENOSPC``. When memory hotplug
leaves a v1 cpuset with only private memory, its tasks move to an ancestor.

Cpuset memory migration never moves pages to a private node. It moves pages
off a private node only when the cpuset no longer allows that node.

When a node becomes unavailable
===============================

A private binding applies while its node is online private memory with
userspace placement enabled and the task's cpuset allows it. While it applies,
allocations use only that node and never fall back to common memory.

Otherwise the binding is suspended and allocations use the task's common
memory. The binding is never rebound to another node. It applies again when
its node becomes available again. If the node comes back as common memory, the
binding acts like an ordinary binding to that node. ``get_mempolicy(2)`` keeps
reporting the original binding throughout.

==============================  ==================  =========================
Event                           New allocations     Existing private pages
==============================  ==================  =========================
cpuset removes the node         common memory       migrated to common memory
cpuset allows the node again    the private node    not migrated back
node is being hot-removed       the private node    migrated to common memory
node is removed                 common memory       none remain
node returns as private memory  the private node
node returns as common memory   that common node
==============================  ==================  =========================

While a node is being hot-removed, its free memory is no longer available, so
faults on mappings bound to it can fail with ``SIGBUS`` until removal finishes.

Allocations that cannot use ``ZONE_MOVABLE``, such as guest_memfd memory, ignore
a binding to a private node whose memory is all movable and use common memory.
Long-term pins migrate pages out of ``ZONE_MOVABLE`` as usual.

An ordinary policy that is not rebound, such as a static binding or a shared
memory policy, can name a node that later comes back as private memory. If the
task may use no common node in such a policy, the policy is ignored and the
allocation uses common memory.

Exhaustion and OOM
==================

A private node is a fixed pool, like a HugeTLB pool. When the node is full and
reclaim cannot free enough memory on it, an allocation for a private binding
fails without invoking the OOM killer and without falling back to common
memory. A page fault then gets ``SIGBUS``, as with an exhausted HugeTLB pool.
Other callers see an error, such as ``-ENOMEM`` from ``write(2)`` to a shmem
file or ``-EFAULT`` from a write through ``/proc/pid/mem`` or
``process_vm_writev(2)``. Allocations succeed again once memory on the node is
freed.

Private pages are charged to memory cgroups like other memory. Reaching a
memory cgroup limit causes reclaim and OOM handling as usual, and memcg reclaim
also reclaims private nodes that permit reclaim.

Tasks whose cpusets overlap only on private nodes are not chosen as OOM victims
for each other.

Shared memory
=============

A private binding on a shmem-backed mapping, such as memfd, tmpfs or shared
anonymous memory, applies to the file's offset range, not to each task that
maps it. Whether a new page is allocated on the private node depends on the
cpuset of the task that faults it in. A task whose cpuset excludes the node
allocates the page on common memory, and every task that maps the file then
uses that page. A file can therefore hold both private and common pages.

Shared pages keep using private memory until they are freed. Unmapping the
file does not free them while the file still exists or another task keeps it
open. Truncate the file or punch holes in it to return the memory.

Memory management services
==========================

kswapd and kcompactd run on a private node only if its driver enables reclaim
and compaction, as the dax kmem private mode does. Writing to ``nodeN/reclaim``
or ``nodeN/compact`` fails with ``-EOPNOTSUPP`` for a private node without the
service. ``MADV_COLD``, ``MADV_PAGEOUT`` and ``MADV_FREE`` act only on pages on
nodes that permit reclaim.

Private nodes are excluded from KSM merging, THP collapse, automatic NUMA
balancing, DAMON actions, demotion between memory tiers and HugeTLB pool
growth. A KSM page that is explicitly migrated to a private node remains
shareable while it is mapped.

Memory hot-remove and soft offline migrate pages on a private node to common
memory. Pinned or otherwise unmovable pages can still prevent removal.

Accounting
==========

``MemTotal`` and ``MemFree`` in ``/proc/meminfo`` include private memory with
userspace placement enabled, such as dax kmem private memory, since it holds
ordinary application data. They leave out other private memory. The overcommit
limit (``CommitLimit``) and other limits sized from total memory follow
``MemTotal``.

``MemAvailable`` and the dirty page limits count free memory on common nodes
only, since free private memory serves only private bindings. ``MemTotal``
minus ``MemAvailable`` therefore includes free private memory.

Per-node statistics, including ``nodeN/meminfo``, ``/proc/vmstat`` and
``memory.numa_stat``, count all memory, private memory included.

Limitations
===========

- A task's OOM score includes its resident private pages.
- Free page reporting reports free private pages like other free pages.
