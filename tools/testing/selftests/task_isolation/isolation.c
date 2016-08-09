/*
 * This test program tests the features of task isolation.
 * 
 * - Makes sure enabling task isolation fails if you are unaffinitized 
 *   or on a non-task-isolation cpu.
 * 
 * - Tests that /sys/devices/system/cpu/task_isolation works correctly.
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
 * - Tests that isolation in "no signal" mode works as expected: you can
 *   perform multiple system calls without a signal, and if another
 *   process bumps you, you return to userspace without any extra jitter.
 * 
 * [1] TLB invalidations do not cause IPIs on some platforms, e.g. arm64
 * [2] Unaligned access only causes exceptions on some platforms, e.g. tile
 * 
 * 
 * You must be running under a kernel configured with TASK_ISOLATION.
 * 
 * You must either have configured with TASK_ISOLATION_ALL or else
 * booted with an argument like "task_isolation=1-15" to enable some
 * task-isolation cores.  If you get interrupts, you can also add
 * the boot argument "task_isolation_debug" to learn more.
 * 
 * NOTE: you must disable the code in tick_nohz_stop_sched_tick()
 * that limits the tick delta to the maximum scheduler deferment
 * by making it conditional not just on "!ts->inidle" but also
 * on !test_thread_flag(TIF_TASK_ISOLATION).  This is around line 1292
 * in kernel/time/tick-sched.c (as of kernel 4.7).
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
#include "../kselftest.h"

#ifndef PR_SET_TASK_ISOLATION   /* Not in system headers yet? */
# define PR_SET_TASK_ISOLATION		48
# define PR_GET_TASK_ISOLATION		49
# define PR_TASK_ISOLATION_ENABLE	(1 << 0)
# define PR_TASK_ISOLATION_USERSIG	(1 << 1)
# define PR_TASK_ISOLATION_SET_SIG(sig)	(((sig) & 0x7f) << 8)
# define PR_TASK_ISOLATION_GET_SIG(bits) (((bits) >> 8) & 0x7f)
# define PR_TASK_ISOLATION_NOSIG \
    (PR_TASK_ISOLATION_USERSIG | PR_TASK_ISOLATION_SET_SIG(0))
#endif

/* The cpu we are using for isolation tests. */
static int task_isolation_cpu;

/* Overall status, maintained as tests run. */
static int exit_status = KSFT_PASS;

/* Set affinity to a single cpu or die if trying to do so fails. */
void set_my_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	int rc = sched_setaffinity(0, sizeof(cpu_set_t), &set);
	assert(rc == 0);
}

/*
 * Run a child process in task isolation mode and report its status.
 * The child does mlockall() and moves itself to the task isolation cpu.
 * It then runs SETUP_FUNC (if specified), calls prctl(PR_SET_TASK_ISOLATION, )
 * with FLAGS (if non-zero), and then invokes TEST_FUNC and exits
 * with its status.
 */
static int run_test(void (*setup_func)(), int (*test_func)(), int flags)
{
	fflush(stdout);
	int pid = fork();
	assert(pid >= 0);
	if (pid != 0) {
		/* In parent; wait for child and return its status. */
		int status;
		waitpid(pid, &status, 0);
		return status;
	}

	/* In child. */
	int rc = mlockall(MCL_CURRENT);
	assert(rc == 0);
	set_my_cpu(task_isolation_cpu);
	if (setup_func)
		setup_func();
	if (flags) {
		int rc;
		do
			rc = prctl(PR_SET_TASK_ISOLATION, flags);
		while (rc != 0 && errno == EAGAIN);
		if (rc != 0) {
			printf("couldn't enable isolation (%d): FAIL\n", errno);
			ksft_exit_fail();
		}
	}
	rc = test_func();
	exit(rc);
}

/*
 * Run a test and ensure it is killed with SIGKILL by default,
 * for whatever misdemeanor is committed in TEST_FUNC.
 * Also test it with SIGUSR1 as well to make sure that works.
 */
static void test_killed(const char *testname, void (*setup_func)(),
			int (*test_func)())
{
	int status = run_test(setup_func, test_func, PR_TASK_ISOLATION_ENABLE);
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
		printf("%s: OK\n", testname);
	} else {
		printf("%s: FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}

	status = run_test(setup_func, test_func,
			  PR_TASK_ISOLATION_ENABLE | PR_TASK_ISOLATION_USERSIG |
			  PR_TASK_ISOLATION_SET_SIG(SIGUSR1));
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR1) {
		printf("%s (SIGUSR1): OK\n", testname);
	} else {
		printf("%s (SIGUSR1): FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}
}

/* Run a test and make sure it exits with success. */
static void test_ok(const char *testname, void (*setup_func)(),
		    int (*test_func)())
{
	int status = run_test(setup_func, test_func, PR_TASK_ISOLATION_ENABLE);
	if (status == KSFT_PASS) {
		printf("%s: OK\n", testname);
	} else {
		printf("%s: FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}
}

/* Run a test with no signals and make sure it exits with success. */
static void test_nosig(const char *testname, void (*setup_func)(),
		       int (*test_func)())
{
	int status =
		run_test(setup_func, test_func,
			 PR_TASK_ISOLATION_ENABLE | PR_TASK_ISOLATION_NOSIG);
	if (status == KSFT_PASS) {
		printf("%s: OK\n", testname);
	} else {
		printf("%s: FAIL (%#x)\n", testname, status);
		exit_status = KSFT_FAIL;
	}
}

/* Mapping address passed from setup function to test function. */
static char *fault_file_mapping;

/* mmap() a file in so we can test touching an unmapped page. */
static void setup_fault(void)
{
	char fault_file[] = "/tmp/isolation_XXXXXX";
	int fd = mkstemp(fault_file);
	assert(fd >= 0);
	int rc = ftruncate(fd, getpagesize());
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
	write(STDOUT_FILENO, "goodbye, world\n", 13);
	return KSFT_FAIL;
}

/* Turn isolation back off and don't be killed. */
static int do_syscall_off(void)
{
	prctl(PR_SET_TASK_ISOLATION, 0);
	write(STDOUT_FILENO, "==> hello, world\n", 17);
	return KSFT_PASS;
}

/* If we're not getting a signal, make sure we can do multiple system calls. */
static int do_syscall_multi(void)
{
	write(STDOUT_FILENO, "==> hello, world 1\n", 19);
	write(STDOUT_FILENO, "==> hello, world 2\n", 19);
	return KSFT_PASS;
}

#ifdef __aarch64__
/* ARM64 uses tlbi instructions so doesn't need to interrupt the remote core. */
static void test_munmap(void) {}
#else

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
	/* First, go back to cpu 0 and allocate some memory. */
	set_my_cpu(0);
	void *p = mmap(0, getpagesize(), PROT_READ|PROT_WRITE,
		       MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, 0, 0);
	assert(p != MAP_FAILED);

	/*
	 * Now fire up a thread that will wait half a second on cpu 0
	 * and then munmap the mapping.
	 */
	pthread_t thr;
	int rc = pthread_create(&thr, NULL, start_munmap, p);
	assert(rc == 0);

	/* Back to the task-isolation cpu. */
	set_my_cpu(task_isolation_cpu);
}

/* Global variable to avoid the compiler outsmarting us. */
volatile int munmap_spin;

static int do_munmap(void)
{
	while (munmap_spin < 1000000000)
		++munmap_spin;
	return KSFT_FAIL;
}

static void test_munmap(void)
{
	test_killed("test_munmap", setup_munmap, do_munmap);
}
#endif

#ifdef __tilegx__
/*
 * Make an unaligned access (and be killed).
 * Only for tilegx, since other platforms don't do in-kernel fixups.
 */
static int
do_unaligned(void)
{
	static int buf[2];
	volatile int* addr = (volatile int *)((char *)buf + 1);

	*addr;

	asm("nop");
	return KSFT_FAIL;
}

static void test_unaligned(void)
{
	test_killed("test_unaligned", NULL, do_unaligned);
}
#else
static void test_unaligned(void) {}
#endif

/*
 * Fork a process that will spin annoyingly on the same core
 * for a second.  Since prctl() won't work if this task is actively
 * running, we following this handshake sequence:
 *
 * 1. Child (in setup_quiesce, here) starts up, sets state 1 to let the
 *    parent know it's running, and starts doing short sleeps waiting on a
 *    state change.
 * 2. Parent (in do_quiesce, below) starts up, spins waiting for state 1,
 *    then spins waiting on prctl() to succeed.  At that point it is in
 *    isolation mode and the child is completing its most recent sleep.
 *    Now, as soon as the parent is scheduled out, it won't schedule back
 *    in until the child stops spinning.
 * 3. Child sees the state change to 2, sets it to 3, and starts spinning
 *    waiting for a second to elapse, at which point it exits.
 * 4. Parent spins waiting for the state to get to 3, then makes one
 *    syscall.  This should take about a second even though the child
 *    was spinning for a whole second after changing the state to 3.
 */

volatile int *statep, *childstate;
struct timeval quiesce_start, quiesce_end;
int child_pid;

static void setup_quiesce(void)
{
	/* First, go back to cpu 0 and allocate some shared memory. */
	set_my_cpu(0);
	statep = mmap(0, getpagesize(), PROT_READ|PROT_WRITE,
		      MAP_ANONYMOUS|MAP_SHARED, 0, 0);
	assert(statep != MAP_FAILED);
	childstate = statep + 1;

	gettimeofday(&quiesce_start, NULL);

	/* Fork and fault in all memory in both. */
	child_pid = fork();
	assert(child_pid >= 0);
	if (child_pid == 0)
		*childstate = 1;
	int rc = mlockall(MCL_CURRENT);
	assert(rc == 0);
	if (child_pid != 0) {
		set_my_cpu(task_isolation_cpu);
		return;
	}

	/*
	 * In child.  Wait until parent notifies us that it has completed
	 * its prctl, then jump to its cpu and let it know.
	 */
	*childstate = 2;
	while (*statep == 0)
		;
	*childstate = 3;
	set_my_cpu(task_isolation_cpu);
	*statep = 2;
	*childstate = 4;

	/*
	 * Now we are competing for the runqueue on task_isolation_cpu.
	 * Spin for one second to ensure the parent gets caught in kernel space.
	 */
	struct timeval start, tv;
	gettimeofday(&start, NULL);
	while (1) {
		gettimeofday(&tv, NULL);
		double time = (tv.tv_sec - start.tv_sec) +
			(tv.tv_usec - start.tv_usec) / 1000000.0;
		if (time >= 0.5)
			exit(0);
	}
}

static int do_quiesce(void)
{
	double time;
	int rc;

	rc = prctl(PR_SET_TASK_ISOLATION,
		   PR_TASK_ISOLATION_ENABLE | PR_TASK_ISOLATION_NOSIG);
	if (rc != 0) {
		prctl(PR_SET_TASK_ISOLATION, 0);
		printf("prctl failed: rc %d", rc);
		goto fail;
	}
	*statep = 1;
    
	/* Wait for child to come disturb us. */
	while (*statep == 1) {
		gettimeofday(&quiesce_end, NULL);
		time = (quiesce_end.tv_sec - quiesce_start.tv_sec) +
			(quiesce_end.tv_usec - quiesce_start.tv_usec)/1000000.0;
		if (time > 0.1 && *statep == 1)	{
			prctl(PR_SET_TASK_ISOLATION, 0);
			printf("timed out at %gs in child migrate loop (%d)\n",
			       time, *childstate);
			char buf[100];
			sprintf(buf, "cat /proc/%d/stack", child_pid);
			system(buf);
			goto fail;
		}
	}
	assert(*statep == 2);

	/*
	 * At this point the child is spinning, so any interrupt will keep us
	 * in kernel space.  Make a syscall to make sure it happens at least
	 * once during the second that the child is spinning.
	 */
	kill(0, 0);
	gettimeofday(&quiesce_end, NULL);
	prctl(PR_SET_TASK_ISOLATION, 0);
	time = (quiesce_end.tv_sec - quiesce_start.tv_sec) +
		(quiesce_end.tv_usec - quiesce_start.tv_usec) / 1000000.0;
	if (time < 0.4 || time > 0.6) {
		printf("expected 1s wait after quiesce: was %g\n", time);
		goto fail;
	}
	kill(child_pid, SIGKILL);
	return KSFT_PASS;

fail:
	kill(child_pid, SIGKILL);
	return KSFT_FAIL;
}

#ifdef __tile__
#include <arch/spr_def.h>
#endif

static inline unsigned long get_cycle_count(void)
{
#ifdef __x86_64__
	unsigned int lower, upper;
	__asm__ __volatile__("rdtsc" : "=a"(lower), "=d"(upper));
	return lower | ((unsigned long)upper << 32);
#elif defined(__tile__)
	return __insn_mfspr(SPR_CYCLE);
#elif defined(__aarch64__)
	unsigned long vtick;
	__asm__ volatile("mrs %0, cntvct_el0" : "=r" (vtick));
	return vtick;
#else
#error Unsupported architecture
#endif
}

/* Histogram of cycle counts up to HISTSIZE cycles. */
#define HISTSIZE 500
long hist[HISTSIZE];

/* Information on loss of control of the cpu (more than HISTSIZE cycles). */
struct jitter_info {
	unsigned long at;      /* cycle of jitter event */
	long cycles;           /* how long we lost the cpu for */
};
#define MAX_EVENTS 100
volatile struct jitter_info jitter[MAX_EVENTS];
unsigned int count;            /* index into jitter[] */

void jitter_summarize(void)
{
	printf("INFO: loop times:\n");
	unsigned int i;
	for (i = 0 ;i < HISTSIZE; ++i)
		if (hist[i])
			printf("  %d x %ld\n", i, hist[i]);

	if (count)
		printf("ERROR: jitter:\n");
	for (i = 0; i < count; ++i)
		printf("  %ld: %ld cycles\n", jitter[i].at, jitter[i].cycles);
	if (count == sizeof(jitter)/sizeof(jitter[0]))
		printf("  ... more\n");
}

void jitter_handler(int sig)
{
	printf("\n");
	if (sig == SIGUSR1) {
		exit_status = KSFT_FAIL;
		printf("ERROR: Program unexpectedly entered kernel.\n");
	}
	jitter_summarize();
	exit(exit_status);
}

void test_jitter(unsigned long waitticks)
{
	printf("testing task isolation jitter for %ld ticks\n", waitticks);

	signal(SIGINT, jitter_handler);
	signal(SIGUSR1, jitter_handler);
	set_my_cpu(task_isolation_cpu);
	int rc = mlockall(MCL_CURRENT);
	assert(rc == 0);

	do
		rc = prctl(PR_SET_TASK_ISOLATION, 
			   PR_TASK_ISOLATION_ENABLE |
			   PR_TASK_ISOLATION_USERSIG |
			   PR_TASK_ISOLATION_SET_SIG(SIGUSR1));
	while (rc != 0 && errno == EAGAIN);
	if (rc != 0) {
		printf("couldn't enable isolation (%d): FAIL\n", errno);
		ksft_exit_fail();
	}

	unsigned long start = get_cycle_count();
	unsigned long last = start;
	unsigned long elapsed;
	do {
		unsigned long next = get_cycle_count();
		unsigned long delta = next - last;
		elapsed = next - start;
		if (__builtin_expect(delta > HISTSIZE, 0)) {
			exit_status = KSFT_FAIL;
			if (count < sizeof(jitter)/sizeof(jitter[0])) {
				jitter[count].cycles = delta;
				jitter[count].at = elapsed;
				++count;
			}
		} else {
			hist[delta]++;
		}
		last = next;

	} while (elapsed < waitticks);

	prctl(PR_SET_TASK_ISOLATION, 0);
	jitter_summarize();
}

int main(int argc, char **argv)
{
	/* How many billion ticks to wait after running the other tests? */
	unsigned long waitticks;
	if (argc == 1)
		waitticks = 10;
	else if (argc == 2)
		waitticks = strtol(argv[1], NULL, 10);
	else {
		printf("syntax: isolation [gigaticks]\n");
		ksft_exit_fail();
	}
	waitticks *= 1000000000;

	/* Test that the /sys device is present and pick a cpu. */
	FILE *f = fopen("/sys/devices/system/cpu/task_isolation", "r");
	if (f == NULL) {
		printf("/sys device: SKIP (%s)\n", strerror(errno));
		ksft_exit_skip();
	}
	char buf[100];
	char *result = fgets(buf, sizeof(buf), f);
	assert(result == buf);
	fclose(f);
	if (*buf == '\n') {
		printf("No task_isolation cores configured.\n");
		ksft_exit_skip();
	}
	char *end;
	task_isolation_cpu = strtol(buf, &end, 10);
	assert(end != buf);
	assert(*end == ',' || *end == '-' || *end == '\n');
	assert(task_isolation_cpu >= 0);
	printf("/sys device : OK (using task isolation cpu %d)\n",
	       task_isolation_cpu);

	/* Test to see if with no mask set, we fail. */
	if (prctl(PR_SET_TASK_ISOLATION, PR_TASK_ISOLATION_ENABLE) == 0 ||
	    errno != EINVAL) {
		printf("prctl unaffinitized: FAIL\n");
		exit_status = KSFT_FAIL;
	} else {
		printf("prctl unaffinitized: OK\n");
	}

	/* Or if affinitized to the wrong cpu. */
	set_my_cpu(0);
	if (prctl(PR_SET_TASK_ISOLATION, PR_TASK_ISOLATION_ENABLE) == 0 ||
	    errno != EINVAL) {
		printf("prctl on cpu 0: FAIL\n");
		exit_status = KSFT_FAIL;
	} else {
		printf("prctl on cpu 0: OK\n");
	}

	/* Run the tests. */
	test_killed("test_fault", setup_fault, do_fault);
	test_killed("test_syscall", NULL, do_syscall);
	test_munmap();
	test_unaligned();
	test_ok("test_off", NULL, do_syscall_off);
	test_nosig("test_multi", NULL, do_syscall_multi);
	test_nosig("test_quiesce", setup_quiesce, do_quiesce);

	/* Exit failure if any test failed. */
	if (exit_status != KSFT_PASS) {
		printf("Skipping jitter testing due to test failures\n");
		return exit_status;
	}

	test_jitter(waitticks);

	return exit_status;
}
