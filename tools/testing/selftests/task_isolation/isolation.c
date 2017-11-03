/*
 * This test program tests the features of task isolation.
 *
 * - Makes sure enabling task isolation fails if you are unaffinitized
 *   or on a non-task-isolation cpu.
 *
 * - Validates that various synchronous exceptions are fatal in isolation
 *   mode:
 *
 *   * Page fault
 *   * System call
 *   * TLB invalidation from another thread [1]
 *   * Unaligned access [2]
 *
 * - Tests that taking a user-defined signal for the above faults works.
 *
 * - Tests that you can prctl(PR_TASK_ISOLATION, 0) to turn isolation off.
 *
 * - Tests that receiving a signal turns isolation off.
 *
 * - Tests that having another process schedule into the core where the
 *   isolation process is running correctly kills the isolation process.
 *
 * [1] TLB invalidations do not cause IPIs on some platforms, e.g. arm64
 * [2] Unaligned access only causes exceptions on some platforms, e.g. tile
 *
 *
 * You must be running under a kernel configured with TASK_ISOLATION.
 *
 * You must have booted with e.g. "nohz_full=1-15 isolcpus=1-15" to
 * enable some task-isolation cores.  If you get interrupt reports, you
 * can also add the boot argument "task_isolation_debug" to learn more.
 * If you get jitter but no reports, define DEBUG_TASK_ISOLATION to add
 * isolation checks in every user_exit() call.
 *
 * NOTE: you must disable the code in tick_nohz_stop_sched_tick()
 * that limits the tick delta to the maximum scheduler deferment
 * by making it conditional not just on "!ts->inidle" but also
 * on !current->task_isolation_flags.  This is around line 756
 * in kernel/time/tick-sched.c (as of kernel 4.14).
 *
 *
 * To compile the test program, run "make".
 *
 * Run the program as "./isolation" and if you want to run the
 * jitter-detection loop for longer than 10 giga-cycles, specify the
 * number of giga-cycles to run it for as a command-line argument.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include "../kselftest.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) (*(volatile typeof(x) *)&(x) = (val))

#ifndef PR_TASK_ISOLATION   /* Not in system headers yet? */
# define PR_TASK_ISOLATION		48
# define PR_TASK_ISOLATION_ENABLE	(1 << 0)
# define PR_TASK_ISOLATION_SET_SIG(sig)	(((sig) & 0x7f) << 8)
# define PR_TASK_ISOLATION_GET_SIG(bits) (((bits) >> 8) & 0x7f)
#endif

/* The cpu we are using for isolation tests. */
static int task_isolation_cpu;

/* Overall status, maintained as tests run. */
static int exit_status = KSFT_PASS;

/* Data shared between parent and children. */
static struct {
	/* Set to true when the parent's isolation prctl is successful. */
	bool parent_isolated;
} *shared;

/* Set affinity to a single cpu or die if trying to do so fails. */
static void set_my_cpu(int cpu)
{
	cpu_set_t set;
	int rc;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	rc = sched_setaffinity(0, sizeof(cpu_set_t), &set);
	assert(rc == 0);
}

#define timeout_init(tv) gettimeofday((tv), NULL)

static int timeout(struct timeval *start, double secs)
{
	struct timeval tv;
	double time;

	gettimeofday(&tv, NULL);
	time = (tv.tv_sec - start->tv_sec) +
		(tv.tv_usec - start->tv_usec) / 1000000.0;
	return time >= secs;
}

static inline int prctl_isolation(int flags)
{
	return prctl(PR_TASK_ISOLATION, flags, 0, 0, 0);
}

static void set_task_isolation(int flags)
{
	int rc;
	struct timeval start;

	/* Wait for up to a second for the kernel to isolate this core. */
	timeout_init(&start);
	do {
		rc = prctl_isolation(flags);
		if (rc == 0 || errno != EAGAIN)
			break;
	} while (!timeout(&start, 1));
	if (rc != 0) {
		prctl_isolation(0);
		printf("couldn't enable isolation (%d): FAIL\n", errno);
		ksft_exit_fail();
	}
}

/*
 * Run a child process in task isolation mode and report its status.
 * The child does mlockall() and moves itself to the task isolation cpu.
 * It then runs SETUP_FUNC (if specified), calls prctl(PR_TASK_ISOLATION)
 * with FLAGS (if non-zero), and then invokes TEST_FUNC and exits
 * with its status.
 */
static int run_test(void (*setup_func)(), int (*test_func)(), int flags)
{
	int pid, rc, status;

	fflush(stdout);
	pid = fork();
	assert(pid >= 0);
	if (pid != 0) {
		/* In parent; wait for child and return its status. */
		waitpid(pid, &status, 0);
		return status;
	}

	/* In child. */
	rc = mlockall(MCL_CURRENT);
	assert(rc == 0);
	set_my_cpu(task_isolation_cpu);
	if (setup_func)
		setup_func();
	if (flags)
		set_task_isolation(flags);
	rc = test_func();
	exit(rc);
}

/* Run a test and make sure it exits with success. */
static void test_ok(const char *testname, void (*setup_func)(),
		    int (*test_func)())
{
	int status;

	status = run_test(setup_func, test_func, PR_TASK_ISOLATION_ENABLE);
	if (status == KSFT_PASS) {
		printf("%s: OK\n", testname);
	} else {
		printf("%s: FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}
}

/*
 * Run a test and ensure it is killed with SIGKILL by default,
 * for whatever misdemeanor is committed in TEST_FUNC.
 * Also test it with SIGUSR1 as well to make sure that works.
 */
static void test_killed(const char *testname, void (*setup_func)(),
			int (*test_func)())
{
	int status;

	status = run_test(setup_func, test_func, PR_TASK_ISOLATION_ENABLE);
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
		printf("%s: OK\n", testname);
	} else {
		printf("%s: FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}

	status = run_test(setup_func, test_func,
			  PR_TASK_ISOLATION_ENABLE |
			  PR_TASK_ISOLATION_SET_SIG(SIGUSR1));
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR1) {
		printf("%s (SIGUSR1): OK\n", testname);
	} else {
		printf("%s (SIGUSR1): FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}
}

/* Mapping address passed from setup function to test function. */
static char *fault_file_mapping;

/* mmap() a file in so we can test touching an unmapped page. */
static void setup_fault(void)
{
	char fault_file[] = "/tmp/isolation_XXXXXX";
	int fd, rc;

	fd = mkstemp(fault_file);
	assert(fd >= 0);
	rc = ftruncate(fd, getpagesize());
	assert(rc == 0);
	fault_file_mapping = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd, 0);
	assert(fault_file_mapping != MAP_FAILED);
	close(fd);
	unlink(fault_file);
}

/* Now touch the unmapped page (and be killed). */
static int do_fault(void)
{
	*fault_file_mapping = 1;
	return KSFT_FAIL;
}

/* Make a syscall (and be killed). */
static int do_syscall(void)
{
	static const char *msg = "goodbye, world\n";
	int rc;

	rc = write(STDOUT_FILENO, msg, strlen(msg));
	assert(rc == (int)strlen(msg));
	return KSFT_FAIL;
}

/* Turn isolation back off and don't be killed. */
static int do_syscall_off(void)
{
	const char *msg = "==> hello, world\n";
	int rc;

	prctl_isolation(0);
	rc = write(STDOUT_FILENO, msg, strlen(msg));
	assert(rc == (int)strlen(msg));
	return KSFT_PASS;
}

/* Test that isolation is off in signal handlers. */
static void segv_handler(int sig)
{
	printf("Received signal %d successfully\n", sig);
	exit(0);
}

static void setup_segv(void)
{
	signal(SIGSEGV, segv_handler);
}

static int do_segv(void)
{
	*(volatile int *)0 = 0;
	return KSFT_FAIL;   /* should not get here */
}

/* ARM64 uses tlbi instructions so doesn't need to interrupt the remote core. */
#ifndef __aarch64__
#define TEST_MUNMAP

/*
 * Fork a thread that will munmap() after a short while.
 * It will deliver a TLB flush to the task isolation core.
 */

static void *start_munmap(void *p)
{
	usleep(500000);   /* 0.5s */
	munmap(p, getpagesize());
	return 0;
}

static void setup_munmap(void)
{
	pthread_t thr;
	void *p;
	int rc;

	/* First, go back to cpu 0 and allocate some memory. */
	set_my_cpu(0);
	p = mmap(0, getpagesize(), PROT_READ|PROT_WRITE,
		 MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, 0, 0);
	assert(p != MAP_FAILED);

	/*
	 * Now fire up a thread that will wait half a second on cpu 0
	 * and then munmap the mapping.
	 */
	rc = pthread_create(&thr, NULL, start_munmap, p);
	assert(rc == 0);

	/* Back to the task-isolation cpu. */
	set_my_cpu(task_isolation_cpu);
}

/* Global variable to avoid the compiler outsmarting us. */
int munmap_spin;

static int do_munmap(void)
{
	while (munmap_spin < 1000000000)
		WRITE_ONCE(munmap_spin, munmap_spin + 1);
	return KSFT_FAIL;
}
#endif

#ifdef __tilegx__
#define TEST_UNALIGNED

/*
 * Make an unaligned access (and be killed).
 * Only for tilegx, since other platforms don't do in-kernel fixups.
 */
static int do_unaligned(void)
{
	static int buf[2];
	int *addr = (int *)((char *)buf + 1);

	READ_ONCE(*addr);

	asm("nop");
	return KSFT_FAIL;
}
#endif

/*
 * Test to make sure that if a process is scheduled to run on the same core
 * as a task isolation process, the task isolation process will be signalled.
 */

static void setup_schedule(void)
{
	struct timeval start;
	int rc, child_pid;

	/*
	 * First, go back to cpu 0 to ensure that the child we create here
	 * doesn't race with task isolation by the parent in do_schedule().
	 */
	set_my_cpu(0);

	/* Fork and fault in all memory in both. */
	child_pid = fork();
	assert(child_pid >= 0);
	rc = mlockall(MCL_CURRENT);
	assert(rc == 0);
	if (child_pid != 0) {
		/* Send parent back to the task isolation cpu. */
		set_my_cpu(task_isolation_cpu);
		return;
	}

	/*
	 * In child.  Wait until parent notifies us that it has completed
	 * its prctl, then reschedule onto its cpu.
	 */
	timeout_init(&start);
	while (!shared->parent_isolated) {
		if (timeout(&start, 1)) {
			printf("child: no parent post-prctl\n");
			exit(1);
		}
	}
	set_my_cpu(task_isolation_cpu);

	/*
	 * We are now running on the task isolation cpu, which should have
	 * killed the parent by forcing the OS to run the scheduler.  No
	 * need to run any code beyond just invoking exit().
	 */
	exit(0);
}

static int do_schedule(void)
{
	struct timeval start;

	/* Notify the child to switch to our cpu. */
	shared->parent_isolated = true;

	/*
	 * Wait for child to come disturb us.  Note that we require
	 * gettimeofday() to run via vDSO for this waiting idiom to work;
	 * if it were a syscall we would get signalled just for calling it.
	 */
	timeout_init(&start);
	while (!timeout(&start, 5))
		;
	printf("parent: no interrupt from scheduler\n");
	exit(1);
}

#ifdef __tile__
#include <arch/spr_def.h>
#endif

static inline u_int64_t get_cycle_count(void)
{
#ifdef __x86_64__
	unsigned int lower, upper;

	asm volatile("rdtsc" : "=a"(lower), "=d"(upper));
	return lower | ((unsigned long)upper << 32);
#elif defined(__tile__)
	return __insn_mfspr(SPR_CYCLE);
#elif defined(__aarch64__)
	unsigned long vtick;

	asm volatile("mrs %0, cntvct_el0" : "=r" (vtick));
	return vtick;
#elif defined(__arm__)
	u_int64_t cval;

	asm volatile("mrrc p15, 1, %Q0, %R0, c14" : "=r" (cval));
	return cval;
#else
#error Unsupported architecture
#endif
}

/*
 * Histogram of cycle counts up to HISTSIZE cycles.  Any loop that takes
 * more than this number of cycles is considered an error, since we likely
 * entered the kernel (rather than just, say, having to refetch caches
 * lines or equivalent).
 */
#define HISTSIZE 600
static long hist[HISTSIZE];

/* Information on loss of control of the cpu (more than HISTSIZE cycles). */
struct jitter_info {
	unsigned long at;      /* cycle of jitter event */
	long cycles;           /* how long we lost the cpu for */
};
#define MAX_EVENTS 100
static struct jitter_info jitter[MAX_EVENTS];
static unsigned int count;            /* index into jitter[] */

static void jitter_summarize(void)
{
	unsigned int i;

	printf("INFO: loop times:\n");
	for (i = 0; i < HISTSIZE; ++i)
		if (hist[i])
			printf("  %d cycles (count: %ld)\n", i, hist[i]);

	if (count)
		printf("ERROR: jitter:\n");
	for (i = 0; i < count; ++i)
		printf("  %ld: %ld cycles\n", jitter[i].at, jitter[i].cycles);
	if (count == ARRAY_SIZE(jitter))
		printf("  ... more\n");
}

/*
 * A DEBUG_TASK_ISOLATION kernel will issue a SIGUSR right after this
 * variable is set, during the prctl_isolation(0).  Handle that case
 * by checking the variable and basically ignoring the signal.
 */
static bool jitter_test_complete;

static void jitter_handler(int sig)
{
	if (jitter_test_complete)
		return;

	if (sig == SIGUSR1) {
		exit_status = KSFT_FAIL;
		printf("ERROR: Program unexpectedly entered kernel.\n");
	}
	jitter_summarize();
	exit(exit_status);
}

static void test_jitter(unsigned long waitticks)
{
	u_int64_t start, last, elapsed;
	int rc;

	printf("testing task isolation jitter for %ld ticks\n", waitticks);

	signal(SIGINT, jitter_handler);
	signal(SIGUSR1, jitter_handler);
	set_my_cpu(task_isolation_cpu);
	rc = mlockall(MCL_CURRENT);
	assert(rc == 0);

	set_task_isolation(PR_TASK_ISOLATION_ENABLE |
			   PR_TASK_ISOLATION_SET_SIG(SIGUSR1));

	last = start = get_cycle_count();
	do {
		u_int64_t next = get_cycle_count();
		u_int64_t delta = next - last;

		elapsed = next - start;
		if (__builtin_expect(delta > HISTSIZE, 0)) {
			exit_status = KSFT_FAIL;
			if (count < ARRAY_SIZE(jitter)) {
				jitter[count].cycles = delta;
				jitter[count].at = elapsed;
				WRITE_ONCE(count, count + 1);
			}
		} else {
			hist[delta]++;
		}
		last = next;

	} while (elapsed < waitticks);

	jitter_test_complete = true;
	prctl_isolation(0);
	jitter_summarize();
}

int main(int argc, char **argv)
{
	/* How many billion ticks to wait after running the other tests? */
	unsigned long waitticks;
	char buf[100];
	char *result, *end;
	FILE *f;

	if (argc == 1)
		waitticks = 10;
	else if (argc == 2)
		waitticks = strtol(argv[1], NULL, 10);
	else {
		printf("syntax: isolation [gigaticks]\n");
		ksft_exit_fail();
	}
	waitticks *= 1000000000;

	/* Get a core from the /sys nohz_full device. */
	f = fopen("/sys/devices/system/cpu/nohz_full", "r");
	if (f == NULL)
		ksft_exit_skip("/sys nohz_full: SKIP (%s)\n", strerror(errno));
	result = fgets(buf, sizeof(buf), f);
	assert(result == buf);
	fclose(f);
	if (*buf == '\n')
		ksft_exit_skip("No nohz_full cores configured.\n");
	task_isolation_cpu = strtol(buf, &end, 10);
	assert(end != buf);
	assert(*end == ',' || *end == '-' || *end == '\n');
	assert(task_isolation_cpu >= 0);

	/* Make sure it matches the first core from the /sys isolated device. */
	f = fopen("/sys/devices/system/cpu/isolated", "r");
	if (f == NULL)
		ksft_exit_skip("/sys isolated: SKIP (%s)\n", strerror(errno));
	result = fgets(buf, sizeof(buf), f);
	assert(result == buf);
	fclose(f);
	if (*buf == '\n')
		ksft_exit_skip("No isolated cores configured.\n");
	if (task_isolation_cpu != strtol(buf, &end, 10))
		ksft_exit_skip("Isolated and nohz_full cores don't match.\n");
	assert(end != buf);
	assert(*end == ',' || *end == '-' || *end == '\n');

	printf("/sys devices: OK (using task isolation cpu %d)\n",
	       task_isolation_cpu);

	/* Test to see if with no mask set, we fail. */
	if (prctl_isolation(PR_TASK_ISOLATION_ENABLE) == 0 ||
	    errno != EINVAL) {
		printf("prctl unaffinitized: FAIL\n");
		exit_status = KSFT_FAIL;
	} else {
		printf("prctl unaffinitized: OK\n");
	}

	/* Or if affinitized to the wrong cpu. */
	set_my_cpu(0);
	if (prctl_isolation(PR_TASK_ISOLATION_ENABLE) == 0 ||
	    errno != EINVAL) {
		printf("prctl on cpu 0: FAIL\n");
		exit_status = KSFT_FAIL;
	} else {
		printf("prctl on cpu 0: OK\n");
	}

	/* Allocate some memory to be used for parent/child communication. */
	shared = mmap(0, getpagesize(), PROT_READ|PROT_WRITE,
		      MAP_ANONYMOUS|MAP_SHARED, 0, 0);
	assert(shared != MAP_FAILED);

	/* Run the positive tests. */
#ifndef DEBUG_TASK_ISOLATION
	test_ok("test_off", NULL, do_syscall_off);
	test_ok("test_segv", setup_segv, do_segv);
#endif

	/* Run the negative tests. */
	test_killed("test_fault", setup_fault, do_fault);
	test_killed("test_syscall", NULL, do_syscall);
#ifdef TEST_MUNMAP
	test_killed("test_munmap", setup_munmap, do_munmap);
#endif
#ifdef TEST_UNALIGNED
	test_killed("test_unaligned", NULL, do_unaligned);
#endif
	test_killed("test_schedule", setup_schedule, do_schedule);

	/* Exit failure if any test failed. */
	if (exit_status != KSFT_PASS) {
		printf("Skipping jitter testing due to test failures\n");
		return exit_status;
	}

	test_jitter(waitticks);

	return exit_status;
}
