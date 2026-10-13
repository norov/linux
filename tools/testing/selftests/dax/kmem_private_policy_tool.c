// SPDX-License-Identifier: GPL-2.0
/*
 * Memory policy, migration, reclaim and exhaustion on a private memory node,
 * reported as KTAP results. kmem_private_policy.sh prints the KTAP header,
 * provisions the node and runs:
 *
 *   kmem_private_policy_tool <private-nid> <common-nid> [memoryless-nid]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/mempolicy.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest.h"

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif

#ifndef MPOL_F_PRIVATE_NODES
#define MPOL_F_PRIVATE_NODES (1 << 12)
#endif

#define NR_PAGES 64
#define PATTERN 0xab
#define NR_THPS 8
/* The kernel reads maxnode - 1 bits. */
#define MAXNODE (8 * sizeof(unsigned long) + 1)

enum { FAIL, PASS, SKIP };

static long page_size;
static size_t huge_len;

static void report(int result, const char *name)
{
	if (result == SKIP)
		ksft_test_result_skip("%s\n", name);
	else
		ksft_test_result(result == PASS, "%s\n", name);
}

static void *anon_map(size_t len)
{
	void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	return ptr == MAP_FAILED ? NULL : ptr;
}

/* How many of the @nr pages at @addr are on @nid, by a move_pages() query. */
static long pages_on_node(void *addr, long nr, int nid)
{
	void **pages = calloc(nr, sizeof(*pages));
	int *status = calloc(nr, sizeof(*status));
	long i, count = -1;

	if (pages && status) {
		for (i = 0; i < nr; i++)
			pages[i] = addr + i * page_size;
		if (!syscall(SYS_move_pages, 0, nr, pages, NULL, status, 0UL)) {
			count = 0;
			for (i = 0; i < nr; i++)
				count += status[i] == nid;
		}
	}
	free(pages);
	free(status);
	return count;
}

static long mbind_mask(void *addr, size_t len, int mode, unsigned long mask)
{
	return syscall(SYS_mbind, addr, len, mode, &mask, MAXNODE, 0UL);
}

static long bind_private(void *addr, size_t len, int nid)
{
	return mbind_mask(addr, len, MPOL_BIND | MPOL_F_PRIVATE_NODES,
			  1UL << nid);
}

static int rejected(long rc)
{
	return rc == -1 && errno == EINVAL;
}

static long read_long(const char *path)
{
	FILE *file = fopen(path, "r");
	long val = -1;

	if (file) {
		if (fscanf(file, "%ld", &val) != 1)
			val = -1;
		fclose(file);
	}
	return val;
}

/* A field of /sys/devices/system/node/node<nid>/meminfo, in kB. */
static long node_meminfo(int nid, const char *field)
{
	char path[64], line[256], key[64];
	FILE *file;
	long val = -1;

	snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo",
		 nid);
	snprintf(key, sizeof(key), " %s:", field);
	file = fopen(path, "r");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		char *pos = strstr(line, key);

		if (pos) {
			val = atol(pos + strlen(key));
			break;
		}
	}
	fclose(file);
	return val;
}

static int thp_disabled(void)
{
	char mode[128] = "";
	FILE *file = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");

	if (!file)
		return 1;
	if (!fgets(mode, sizeof(mode), file))
		mode[0] = '\0';
	fclose(file);
	return strstr(mode, "[never]") != NULL;
}

/*
 * Reclaim through @path splits partially unmapped THPs on a private node,
 * returning the unmapped subpages.
 */
static int thp_split_reclaimed(int nid, const char *path)
{
	size_t len = NR_THPS * huge_len;
	char stat[256], *map, *buf;
	long before, partial;
	FILE *file;
	int i;

	if (!huge_len)
		return SKIP;
	snprintf(stat, sizeof(stat),
		 "/sys/kernel/mm/transparent_hugepage/hugepages-%zukB/stats/nr_anon_partially_mapped",
		 huge_len >> 10);
	before = read_long(stat);
	if (before < 0)
		return SKIP;
	map = anon_map(len + huge_len);
	if (!map)
		return FAIL;
	buf = (char *)(((unsigned long)map + huge_len - 1) & ~(huge_len - 1));
	if (madvise(buf, len, MADV_HUGEPAGE) || bind_private(buf, len, nid)) {
		munmap(map, len + huge_len);
		return SKIP;
	}
	memset(buf, PATTERN, len);
	if (pages_on_node(buf, len / page_size, nid) !=
	    (long)(len / page_size)) {
		munmap(map, len + huge_len);
		return FAIL;
	}
	for (i = 0; i < NR_THPS; i++)
		madvise(buf + i * huge_len + huge_len / 2, huge_len / 2,
			MADV_DONTNEED);

	/* With THP enabled, a private binding must get its THPs. */
	partial = read_long(stat) - before;
	if (partial < NR_THPS) {
		munmap(map, len + huge_len);
		return thp_disabled() ? SKIP : FAIL;
	}
	file = fopen(path, "w");
	if (file) {
		fputs("64M", file);
		fclose(file);
	}
	partial = read_long(stat) - before;
	munmap(map, len + huge_len);
	return partial <= NR_THPS / 4 ? PASS : FAIL;
}

static int swap_active(void)
{
	char line[256];
	FILE *file = fopen("/proc/swaps", "r");
	int lines = 0;

	if (!file)
		return 0;
	while (fgets(line, sizeof(line), file))
		lines++;
	fclose(file);
	return lines > 1;
}

/* Reclaim advice pages out private memory, given active swap. */
static int pageout_acts(void *addr, size_t len, int nid)
{
	if (!swap_active())
		return SKIP;
	if (bind_private(addr, len, nid))
		return FAIL;
	memset(addr, PATTERN, len);
	if (pages_on_node(addr, NR_PAGES, nid) != NR_PAGES ||
	    madvise(addr, len, MADV_PAGEOUT))
		return FAIL;
	/* Reclaim may skip a few pages, for example ones still in a batch. */
	return pages_on_node(addr, NR_PAGES, nid) <= NR_PAGES / 4 ? PASS : FAIL;
}

/* Find memory.reclaim of the non-root cgroup this task runs in. */
static int memcg_reclaim_path(char *path, size_t size)
{
	/* Short enough that the memory.reclaim path always fits @path. */
	char line[2048], *cgroup = NULL;
	FILE *file = fopen("/proc/self/cgroup", "r");

	if (!file)
		return 0;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "0::/", 4)) {
			line[strcspn(line, "\n")] = 0;
			cgroup = line + 3;
			break;
		}
	}
	fclose(file);
	if (!cgroup || !strcmp(cgroup, "/"))
		return 0;
	snprintf(path, size, "/sys/fs/cgroup%s/memory.reclaim", cgroup);
	return !access(path, W_OK);
}

/*
 * A relative or static policy whose mask names the private node must still
 * place memory on common nodes, and keep the user's mask.
 */
static int common_policy(void *addr, size_t len, int nid, int requested_mode,
			 unsigned long mask, int task_policy)
{
	unsigned long reported = 0;
	int mode = 0;
	long rc;

	if (task_policy) {
		if (syscall(SYS_mbind, addr, len, MPOL_DEFAULT, NULL, 0UL, 0UL))
			return FAIL;
		rc = syscall(SYS_set_mempolicy, requested_mode, &mask, MAXNODE);
	} else {
		rc = mbind_mask(addr, len, requested_mode, mask);
	}
	if (rc)
		return FAIL;

	rc = syscall(SYS_get_mempolicy, &mode, &reported, MAXNODE,
		     task_policy ? NULL : addr, task_policy ? 0 : MPOL_F_ADDR);
	if (task_policy)
		syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0UL);
	if (rc || mode != requested_mode || reported != mask ||
	    madvise(addr, len, MADV_DONTNEED))
		return FAIL;
	memset(addr, PATTERN, len);
	return pages_on_node(addr, NR_PAGES, nid) == 0 ? PASS : FAIL;
}

/* The flag binds exactly one private node and excludes the other modes. */
static int private_flag_validated(void *addr, size_t len,
				  unsigned long private_mask,
				  unsigned long common_mask)
{
	const struct {
		int mode;
		unsigned long mask;
	} cases[] = {
		{ MPOL_BIND | MPOL_F_PRIVATE_NODES | MPOL_F_STATIC_NODES,
		  private_mask },
		{ MPOL_BIND | MPOL_F_PRIVATE_NODES | MPOL_F_RELATIVE_NODES,
		  private_mask },
		{ MPOL_BIND | MPOL_F_PRIVATE_NODES | MPOL_F_NUMA_BALANCING,
		  private_mask },
		{ MPOL_PREFERRED | MPOL_F_PRIVATE_NODES, private_mask },
		{ MPOL_BIND | MPOL_F_PRIVATE_NODES, common_mask },
		{ MPOL_BIND | MPOL_F_PRIVATE_NODES, private_mask | common_mask },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		errno = 0;
		if (!rejected(mbind_mask(addr, len, cases[i].mode,
					 cases[i].mask)))
			return FAIL;
	}
	return PASS;
}

/* Run @fn in a child, so its effects on this process do not leak. */
static int in_child(int (*fn)(int), int nid)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return FAIL;
	if (!pid)
		_exit(fn(nid));
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return FAIL;
	return WEXITSTATUS(status);
}

/* migrate_pages(2) moves a task's pages onto the private node. */
static int migrate_to_private(int nid)
{
	unsigned long old_nodes, new_nodes = 1UL << nid;
	char *addr = anon_map(NR_PAGES * page_size);
	void *page;
	int status;

	if (!addr)
		return FAIL;
	memset(addr, PATTERN, NR_PAGES * page_size);
	page = addr;
	if (syscall(SYS_move_pages, 0, 1UL, &page, NULL, &status, 0UL) ||
	    status < 0 || status == nid)
		return FAIL;
	old_nodes = 1UL << status;
	if (syscall(SYS_migrate_pages, 0, MAXNODE, &old_nodes, &new_nodes) < 0)
		return FAIL;
	return pages_on_node(addr, NR_PAGES, nid) >= NR_PAGES * 3 / 4 ?
	       PASS : FAIL;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * Fork a child that faults @kb of locked memory bound to the private node,
 * so that reclaim cannot make room, then writes to @ready and sleeps.
 */
static pid_t start_faulter(int nid, long kb, int ready)
{
	size_t len = (size_t)kb << 10, off;
	char *addr;
	pid_t pid;

	pid = fork();
	if (pid)
		return pid;
	addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (addr == MAP_FAILED || bind_private(addr, len, nid) ||
	    madvise(addr, len, MADV_NOHUGEPAGE) ||
	    syscall(SYS_mlock2, addr, len, MLOCK_ONFAULT))
		_exit(2);
	for (off = 0; off < len; off += page_size)
		addr[off] = 1;
	if (write(ready, "", 1) != 1)
		_exit(2);
	pause();
	_exit(0);
}

/* Wait up to @secs for a faulter to write to @ready. */
static int faulter_ready(int ready, int secs)
{
	struct pollfd pfd = { .fd = ready, .events = POLLIN };
	char byte;

	return poll(&pfd, 1, secs * 1000) == 1 && read(ready, &byte, 1) == 1;
}

/* Wait up to @secs for @pid to exit and return its status, or -1. */
static int wait_exit(pid_t pid, double secs)
{
	double end = now() + secs;
	int status;

	do {
		if (waitpid(pid, &status, WNOHANG) == pid)
			return status;
		usleep(100000);
	} while (now() < end);
	return -1;
}

static int alive(pid_t pid)
{
	return waitpid(pid, NULL, WNOHANG) == 0;
}

static void stop(pid_t pid)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

/*
 * Exhausting private memory fails the fault with SIGBUS, as an exhausted
 * HugeTLB pool does, and leaves other tasks on the node alone.
 */
static void private_exhaustion(int nid)
{
	const char *name = "exhausting private memory fails the fault with SIGBUS";
	long free_kb = node_meminfo(nid, "MemFree");
	long total_kb = node_meminfo(nid, "MemTotal");
	int pipefd[2], status = -1, result = FAIL;
	pid_t holder, faulter;

	/* Strict overcommit refuses the oversized mapping before it faults. */
	if (read_long("/proc/sys/vm/overcommit_memory") == 2) {
		report(SKIP, name);
		return;
	}
	if (free_kb <= 0 || total_kb <= 0 || pipe(pipefd)) {
		report(FAIL, name);
		return;
	}

	/* Another task holding memory on the node must be left alone. */
	holder = start_faulter(nid, free_kb * 6 / 10, pipefd[1]);
	if (holder > 0 && faulter_ready(pipefd[0], 60)) {
		faulter = start_faulter(nid, total_kb * 2, pipefd[1]);
		if (faulter > 0) {
			status = wait_exit(faulter, 60);
			if (status == -1)
				stop(faulter);
		}
		if (status != -1 && WIFSIGNALED(status) &&
		    WTERMSIG(status) == SIGBUS && alive(holder))
			result = PASS;
	}
	report(result, name);

	if (holder > 0)
		stop(holder);
	close(pipefd[0]);
	close(pipefd[1]);
}

int main(int argc, char **argv)
{
	unsigned long private_mask, common_mask, mixed_mask, allowed = 0;
	void *ordinary, *bound, *probe, *mixed, *paged, *huge;
	int nid, common, memless = -1, mode, status, result;
	char path[4096];
	void *pages[1];
	int nodes[1];
	long len, rc;

	if (argc != 3 && argc != 4)
		ksft_exit_fail_msg("usage: %s <private-nid> <common-nid> [memoryless-nid]\n",
				   argv[0]);
	nid = atoi(argv[1]);
	common = atoi(argv[2]);
	if (argc == 4)
		memless = atoi(argv[3]);

	page_size = sysconf(_SC_PAGESIZE);
	rc = read_long("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size");
	huge_len = rc > 0 ? rc : 0;
	len = NR_PAGES * page_size;
	private_mask = 1UL << nid;
	common_mask = 1UL << common;
	mixed_mask = private_mask | common_mask;

	ordinary = anon_map(len);
	bound = anon_map(len);
	probe = anon_map(len);
	mixed = anon_map(len);
	paged = anon_map(len);
	if (!ordinary || !bound || !probe || !mixed || !paged)
		ksft_exit_fail_msg("mmap failed\n");

	ksft_set_plan(20);

	memset(ordinary, PATTERN, len);
	report(pages_on_node(ordinary, NR_PAGES, nid) == 0 ? PASS : FAIL,
	       "ordinary allocation stays off private memory");

	rc = syscall(SYS_get_mempolicy, &mode, &allowed, MAXNODE, NULL,
		     MPOL_F_MEMS_ALLOWED);
	report(!rc && (allowed & private_mask) ? PASS : FAIL,
	       "mems_allowed reports the private node");

	errno = 0;
	rc = syscall(SYS_set_mempolicy, MPOL_BIND | MPOL_F_PRIVATE_NODES,
		     &private_mask, MAXNODE);
	report(rejected(rc) ? PASS : FAIL,
	       "set_mempolicy() rejects MPOL_F_PRIVATE_NODES");
	syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0UL);

	rc = bind_private(bound, len, nid);
	memset(bound, PATTERN, len);
	report(!rc && pages_on_node(bound, NR_PAGES, nid) == NR_PAGES &&
	       pages_on_node(bound, NR_PAGES, common) == 0 ? PASS : FAIL,
	       "a private binding places memory on the private node");

	mode = 0;
	rc = syscall(SYS_get_mempolicy, &mode, NULL, 0UL, bound, MPOL_F_ADDR);
	report(!rc && mode == (MPOL_BIND | MPOL_F_PRIVATE_NODES) ? PASS : FAIL,
	       "get_mempolicy() reports MPOL_F_PRIVATE_NODES");

	/* A mixed mask is an ordinary binding narrowed to common memory. */
	rc = mbind_mask(mixed, len, MPOL_BIND, mixed_mask);
	memset(mixed, PATTERN, len);
	report(!rc && pages_on_node(mixed, NR_PAGES, common) == NR_PAGES ?
	       PASS : FAIL,
	       "an unflagged mixed mask uses only common memory");

	/* Without the flag, a private-only mask has no usable node. */
	errno = 0;
	report(rejected(mbind_mask(probe, len, MPOL_BIND, private_mask)) ?
	       PASS : FAIL, "an unflagged private-only mask is rejected");

	report(private_flag_validated(probe, len, private_mask, common_mask),
	       "MPOL_F_PRIVATE_NODES rejects other modes, flags and masks");

	/* Adding a memoryless node to a private binding must fail. */
	if (memless < 0) {
		result = SKIP;
	} else {
		errno = 0;
		result = rejected(mbind_mask(probe, len,
					     MPOL_BIND | MPOL_F_PRIVATE_NODES,
					     private_mask | (1UL << memless))) ?
			 PASS : FAIL;
	}
	report(result, "a private binding names exactly one node");

	/* Private nodes cannot hold HugeTLB pages. */
	huge = huge_len ? mmap(NULL, huge_len, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
			       MAP_NORESERVE, -1, 0) : MAP_FAILED;
	if (huge == MAP_FAILED) {
		result = SKIP;
	} else {
		errno = 0;
		result = rejected(bind_private(huge, huge_len, nid)) ?
			 PASS : FAIL;
		munmap(huge, huge_len);
	}
	report(result, "a private binding on HugeTLB memory is rejected");

	/* Relative bits are positions in the common-node set, not node IDs. */
	report(common_policy(probe, len, nid, MPOL_BIND | MPOL_F_RELATIVE_NODES,
			     private_mask, 1),
	       "a relative task policy stays on common memory");
	report(common_policy(probe, len, nid, MPOL_BIND | MPOL_F_RELATIVE_NODES,
			     private_mask, 0),
	       "a relative binding stays on common memory");
	/* Filtering the effective policy must not alter its user mask. */
	report(common_policy(probe, len, nid, MPOL_BIND | MPOL_F_STATIC_NODES,
			     mixed_mask, 1),
	       "a static task policy keeps its mask and uses common memory");

	pages[0] = ordinary;
	nodes[0] = nid;
	rc = syscall(SYS_move_pages, 0, 1UL, pages, nodes, &status,
		     MPOL_MF_MOVE);
	report(!rc && pages_on_node(ordinary, NR_PAGES, nid) == 1 ? PASS : FAIL,
	       "move_pages() moves a page to the private node");

	pages[0] = bound;
	nodes[0] = common;
	rc = syscall(SYS_move_pages, 0, 1UL, pages, nodes, &status,
		     MPOL_MF_MOVE);
	report(!rc && pages_on_node(bound, NR_PAGES, common) == 1 ? PASS : FAIL,
	       "move_pages() moves a private page to common memory");

	report(in_child(migrate_to_private, nid),
	       "migrate_pages() moves pages to the private node");

	report(pageout_acts(paged, len, nid),
	       "MADV_PAGEOUT pages out private memory");

	snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/reclaim",
		 nid);
	report(thp_split_reclaimed(nid, path),
	       "node reclaim splits partially mapped private THPs");

	/* memcg reclaim may page out the mappings above, so it runs late. */
	report(memcg_reclaim_path(path, sizeof(path)) ?
	       thp_split_reclaimed(nid, path) : SKIP,
	       "memcg reclaim splits partially mapped private THPs");

	munmap(paged, len);
	munmap(probe, len);
	munmap(mixed, len);
	munmap(bound, len);
	munmap(ordinary, len);

	private_exhaustion(nid);

	ksft_finished();
}
