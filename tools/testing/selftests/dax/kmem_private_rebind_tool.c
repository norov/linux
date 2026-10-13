// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for kmem_private_cpuset.sh and kmem_private_rebind.sh. Most modes
 * place memory under a policy, print "ready pid=<pid>" and wait for SIGUSR1
 * while the script changes the cpuset or the node, then report where the
 * memory went. Modes with several stages wait for one SIGUSR1 per stage and
 * print one "stage=<n> ... ok=<0|1>" line each.
 *
 * Modes that check their own results exit 1 when a check fails. All modes
 * exit 2 on usage or setup errors.
 */
#define _GNU_SOURCE
#include <linux/mempolicy.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MPOL_F_PRIVATE_NODES
#define MPOL_F_PRIVATE_NODES (1 << 12)
#endif

#define NR_PAGES 64
/* The kernel reads maxnode - 1 bits. */
#define MAXNODE (8 * sizeof(unsigned long) + 1)

enum mode {
	ORDINARY,
	INTERLEAVE,
	BIND,
	PRIVATE_ANON,
	PRIVATE_SHARED,
	RETYPE_ANON,
	RETYPE_SHARED,
	STATIC,
	STATIC_MIXED,
	NR_MODES,
};

static const struct {
	const char *name;
	const char *help;
} modes[NR_MODES] = {
	[ORDINARY] = { "ordinary", "allocate without a policy" },
	[INTERLEAVE] = { "interleave",
			 "task interleave over <private> and <common1>" },
	[BIND] = { "bind", "task bind to <common1>" },
	[PRIVATE_ANON] = { "private-anon",
			   "private binding of anonymous memory" },
	[PRIVATE_SHARED] = { "private-shared",
			     "private binding of shared memory, two mappers" },
	[RETYPE_ANON] = { "retype-anon",
			  "private-anon across node hotplug" },
	[RETYPE_SHARED] = { "retype-shared",
			    "private-shared across node hotplug" },
	[STATIC] = { "static", "static binding of shared memory to <private>" },
	[STATIC_MIXED] = { "static-mixed",
			   "static binding to <private> and <common1>" },
};

static void print_usage(const char *prog)
{
	int i;

	fprintf(stderr, "usage: %s <mode> <private> <common1> <common2>\n",
		prog);
	for (i = 0; i < NR_MODES; i++)
		fprintf(stderr, "  %-15s %s\n", modes[i].name, modes[i].help);
	exit(2);
}

/* Node masks are a single unsigned long. */
static bool node_fits(int nid)
{
	return nid >= 0 && nid < (int)(8 * sizeof(unsigned long));
}

static void *map_anon(long len)
{
	return mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void *map_shared(int *fd, long len)
{
	*fd = memfd_create("private-rebind", 0);
	if (*fd < 0 || ftruncate(*fd, len))
		return MAP_FAILED;
	return mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
}

static void announce_ready(void)
{
	printf("ready pid=%d\n", getpid());
	fflush(stdout);
}

static long count_node(void *addr, long page_size, int nid)
{
	void *pages[NR_PAGES];
	int status[NR_PAGES];
	long i, count = 0;

	for (i = 0; i < NR_PAGES; i++)
		pages[i] = addr + i * page_size;
	if (syscall(SYS_move_pages, 0, NR_PAGES, pages, NULL, status, 0UL))
		return -1;
	for (i = 0; i < NR_PAGES; i++)
		count += status[i] == nid;
	return count;
}

static bool range_matches(void *ptr, long page_size, unsigned char value)
{
	long i;

	for (i = 0; i < NR_PAGES; i++)
		if (*(unsigned char *)(ptr + i * page_size) != value)
			return false;
	return true;
}

static int bind_mapping(void *ptr, long len, unsigned long mask, int flags)
{
	return syscall(SYS_mbind, ptr, len, MPOL_BIND | flags,
		       &mask, MAXNODE, 0UL);
}

static bool policy_matches(void *ptr, unsigned long mask, int flags)
{
	unsigned long actual = 0;
	int mode;

	return !syscall(SYS_get_mempolicy, &mode, &actual, MAXNODE,
			ptr, MPOL_F_ADDR) &&
		mode == (MPOL_BIND | flags) && actual == mask;
}

/* Report how many pages are on the private node. */
static int ordinary(long page_size, int priv)
{
	long len = NR_PAGES * page_size;
	void *ptr = map_anon(len);

	if (ptr == MAP_FAILED)
		return 2;
	memset(ptr, 0xab, len);
	printf("private=%ld\n", count_node(ptr, page_size, priv));
	return 0;
}

static void report_placement(void *ptr, long page_size, int priv,
			     int common1, int common2)
{
	printf("private=%ld old_common=%ld new_common=%ld\n",
	       count_node(ptr, page_size, priv),
	       count_node(ptr, page_size, common1),
	       count_node(ptr, page_size, common2));
}

/* Interleave over the private node and allocate after the cpuset change. */
static int task_interleave(long page_size, int priv, int common1,
			   int common2, const sigset_t *waitset)
{
	unsigned long mask = (1UL << common1) | (1UL << priv);
	long len = NR_PAGES * page_size;
	void *ptr;
	int sig;

	if (syscall(SYS_set_mempolicy, MPOL_INTERLEAVE, &mask, MAXNODE))
		return 2;
	announce_ready();
	sigwait(waitset, &sig);
	ptr = map_anon(len);
	if (ptr == MAP_FAILED)
		return 2;
	memset(ptr, 0xcd, len);
	report_placement(ptr, page_size, priv, common1, common2);
	munmap(ptr, len);
	return 0;
}

/* Bind to the first common node and allocate before the cpuset change. */
static int task_bind(long page_size, int priv, int common1, int common2,
		     const sigset_t *waitset)
{
	unsigned long mask = 1UL << common1;
	long len = NR_PAGES * page_size;
	void *ptr;
	int sig;

	if (syscall(SYS_set_mempolicy, MPOL_BIND, &mask, MAXNODE))
		return 2;
	ptr = map_anon(len);
	if (ptr == MAP_FAILED)
		return 2;
	memset(ptr, 0xab, len);
	announce_ready();
	sigwait(waitset, &sig);
	report_placement(ptr, page_size, priv, common1, common2);
	munmap(ptr, len);
	return 0;
}

struct shared_result {
	long private_pages;
	long shared_pages;
};

/* Keep one mapper outside the cpuset that is being changed. */
static int shared_mapper(void *ptr, long len, long page_size, int priv,
			 int common, int requests, int replies, pid_t child)
{
	struct shared_result result;
	int stage, status;
	bool contents;
	void *range;

	while (read(requests, &stage, sizeof(stage)) == sizeof(stage)) {
		range = ptr + (stage + 4) * len;
		memset(range, 0xef, len);
		result.private_pages = count_node(range, page_size, priv);

		/* Existing shared pages are not reallocated for another mapper. */
		range = ptr + (stage + 1) * len;
		contents = range_matches(range, page_size, 0xcd);
		result.shared_pages = count_node(range, page_size,
						 stage == 1 ? common : priv);
		if (!contents)
			result.shared_pages = -1;
		if (write(replies, &result, sizeof(result)) != sizeof(result))
			break;
	}
	close(requests);
	close(replies);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

/*
 * A private binding across three cpuset changes that allow, revoke and allow
 * the node again. Range 0 of the mapping is populated up front and range
 * 1 + stage at each stage. For shared memory the parent stays outside the
 * cpuset as a second mapper and populates range 4 + stage.
 */
static int private_rebind(bool shared, long page_size, int priv, int common,
			  const sigset_t *waitset)
{
	unsigned long mask = 1UL << priv;
	long len = NR_PAGES * page_size;
	long total = (shared ? 7 : 4) * len;
	int fd = -1, requests[2], replies[2];
	int stage, sig, failed = 0;
	struct shared_result other;
	long private_pages, common_pages, existing, existing_common;
	bool policy, contents, ok;
	pid_t child;
	void *ptr, *range;

	if (shared)
		ptr = map_shared(&fd, total);
	else
		ptr = map_anon(total);
	if (ptr == MAP_FAILED ||
	    bind_mapping(ptr, total, mask, MPOL_F_PRIVATE_NODES))
		return 2;
	/* Keep later ranges absent until their respective cpuset transition. */
	if (madvise(ptr, total, MADV_NOHUGEPAGE))
		return 2;
	memset(ptr, 0xab, len);
	if (count_node(ptr, page_size, priv) != NR_PAGES)
		return 1;

	if (shared) {
		if (pipe(requests) || pipe(replies))
			return 2;
		child = fork();
		if (child < 0)
			return 2;
		if (child) {
			close(requests[1]);
			close(replies[0]);
			failed = shared_mapper(ptr, len, page_size, priv, common,
					       requests[0], replies[1], child);
			goto out;
		}
		close(requests[0]);
		close(replies[1]);
		/* Populate the child's PTEs before cpuset-requested migration. */
		if (!range_matches(ptr, page_size, 0xab))
			return 2;
	}

	announce_ready();
	for (stage = 0; stage < 3; stage++) {
		if (sigwait(waitset, &sig))
			return 2;
		range = ptr + (stage + 1) * len;
		memset(range, 0xcd, len);
		private_pages = count_node(range, page_size, priv);
		common_pages = count_node(range, page_size, common);
		/* File-backed PTEs can be populated lazily after fork. */
		contents = range_matches(ptr, page_size, 0xab);
		existing = count_node(ptr, page_size, priv);
		existing_common = count_node(ptr, page_size, common);
		policy = policy_matches(ptr, mask, MPOL_F_PRIVATE_NODES);
		ok = policy && contents;
		/* Old pages leave the private node only once it is revoked. */
		if (stage == 0)
			ok &= existing == NR_PAGES && existing_common == 0;
		else
			ok &= existing == 0 && existing_common == NR_PAGES;
		if (stage == 1)
			ok &= common_pages == NR_PAGES && private_pages == 0;
		else
			ok &= private_pages == NR_PAGES && common_pages == 0;
		other.private_pages = -1;
		other.shared_pages = -1;
		if (shared) {
			if (write(requests[1], &stage, sizeof(stage)) != sizeof(stage) ||
			    read(replies[0], &other, sizeof(other)) != sizeof(other))
				return 2;
			ok &= other.private_pages == NR_PAGES &&
				other.shared_pages == NR_PAGES;
		}
		printf("stage=%d private=%ld common=%ld existing_private=%ld ",
		       stage, private_pages, common_pages, existing);
		printf("existing_common=%ld ", existing_common);
		printf("policy=%d other_private=%ld shared_pages=%ld ok=%d\n",
		       policy, other.private_pages, other.shared_pages, ok);
		fflush(stdout);
		failed |= !ok;
	}
	if (shared) {
		close(requests[1]);
		close(replies[0]);
	}
out:
	munmap(ptr, total);
	if (fd >= 0)
		close(fd);
	return failed;
}

/*
 * A private binding while the node goes offline, returns as common memory,
 * goes offline again and returns as private memory. Range @stage of the
 * mapping is populated at each stage.
 */
static int private_retype(bool shared, long page_size, int target, int common,
			  const sigset_t *waitset)
{
	unsigned long mask = 1UL << target;
	long len = NR_PAGES * page_size;
	long private_pages, common_pages;
	int fd = -1, stage, sig, i, failed = 0;
	bool policy, contents, ok;
	void *ptr, *range;

	if (shared)
		ptr = map_shared(&fd, 4 * len);
	else
		ptr = map_anon(4 * len);
	if (ptr == MAP_FAILED ||
	    bind_mapping(ptr, 4 * len, mask, MPOL_F_PRIVATE_NODES) ||
	    madvise(ptr, 4 * len, MADV_NOHUGEPAGE))
		return 2;

	/* Keep the policy alive without preventing the initial hot-unplug. */
	announce_ready();
	for (stage = 0; stage < 4; stage++) {
		if (sigwait(waitset, &sig))
			return 2;
		range = ptr + stage * len;
		memset(range, 0xa0 + stage, len);
		private_pages = count_node(range, page_size, target);
		common_pages = count_node(range, page_size, common);
		policy = policy_matches(ptr, mask, MPOL_F_PRIVATE_NODES);
		contents = true;
		for (i = 0; i <= stage; i++)
			contents &= range_matches(ptr + i * len, page_size,
						  0xa0 + i);
		ok = policy && contents;
		if (stage & 1)
			ok &= private_pages == NR_PAGES && common_pages == 0;
		else
			ok &= private_pages == 0 && common_pages == NR_PAGES;
		printf("stage=%d target=%ld common=%ld policy=%d contents=%d ok=%d\n",
		       stage, private_pages, common_pages, policy, contents, ok);
		fflush(stdout);
		failed |= !ok;
	}
	munmap(ptr, 4 * len);
	if (fd >= 0)
		close(fd);
	return failed;
}

/*
 * A static binding of shared memory to a common node, optionally with a
 * second common node, that the script turns private before a second mapper
 * faults the pages in.
 */
static int common_retype(bool mixed, long page_size, int target,
			 int old_common, int new_common,
			 const sigset_t *waitset)
{
	unsigned long mask = 1UL << target;
	long len = NR_PAGES * page_size;
	long private_pages, common_pages;
	int fd, sig;
	bool policy, ok;
	void *ptr, *other;

	if (mixed)
		mask |= 1UL << old_common;
	ptr = map_shared(&fd, len);
	if (ptr == MAP_FAILED ||
	    bind_mapping(ptr, len, mask, MPOL_F_STATIC_NODES))
		return 2;
	other = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (other == MAP_FAILED)
		return 2;
	/* No resident pages: the target can be removed and retyped. */
	announce_ready();
	if (sigwait(waitset, &sig))
		return 2;
	memset(other, 0xcd, len);
	private_pages = count_node(other, page_size, target);
	common_pages = count_node(other, page_size, new_common);
	policy = policy_matches(other, mask, MPOL_F_STATIC_NODES);
	ok = private_pages == 0 && common_pages == NR_PAGES && policy;
	printf("private=%ld common=%ld policy=%d ok=%d\n",
	       private_pages, common_pages, policy, ok);
	munmap(other, len);
	munmap(ptr, len);
	close(fd);
	return !ok;
}

int main(int argc, char **argv)
{
	long page_size = sysconf(_SC_PAGESIZE);
	int priv, common1, common2, mode;
	sigset_t waitset;

	if (argc != 5)
		print_usage(argv[0]);
	for (mode = 0; mode < NR_MODES; mode++)
		if (!strcmp(argv[1], modes[mode].name))
			break;
	if (mode == NR_MODES)
		print_usage(argv[0]);
	priv = atoi(argv[2]);
	common1 = atoi(argv[3]);
	common2 = atoi(argv[4]);
	if (!node_fits(priv) || !node_fits(common1) || !node_fits(common2)) {
		fprintf(stderr, "node ids must be 0 to %zu\n",
			8 * sizeof(unsigned long) - 1);
		return 2;
	}

	sigemptyset(&waitset);
	sigaddset(&waitset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &waitset, NULL);

	switch (mode) {
	case ORDINARY:
		return ordinary(page_size, priv);
	case INTERLEAVE:
		return task_interleave(page_size, priv, common1, common2,
				       &waitset);
	case BIND:
		return task_bind(page_size, priv, common1, common2, &waitset);
	case PRIVATE_ANON:
	case PRIVATE_SHARED:
		return private_rebind(mode == PRIVATE_SHARED, page_size, priv,
				      common2, &waitset);
	case RETYPE_ANON:
	case RETYPE_SHARED:
		return private_retype(mode == RETYPE_SHARED, page_size, priv,
				      common2, &waitset);
	case STATIC:
	case STATIC_MIXED:
		return common_retype(mode == STATIC_MIXED, page_size, priv,
				     common1, common2, &waitset);
	}
	return 2;
}
