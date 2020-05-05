#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* [project 1] List of processes sleeping after timer_sleep() */
static struct list sleep_list;

/* [project 1] List of all processes as implementing mlfqs */
static struct list mlfqs_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* [project 1] system load average */
static struct fixed_1714 load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the global thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&sleep_list);
	list_init (&destruction_req);
	list_init (&all_list);

	if(thread_mlfqs) {
		list_init (&mlfqs_list);
	}

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	//printf("[thread_start] calling thread_create\n");
	thread_create ("idle", PRI_MIN, idle, &idle_started);
	//printf("[thread_start] thread created \n");

	struct thread* curr = thread_current();
	//printf("[thread_start] current thread id: %d \n", curr->tid);
	//printf("[thread_start] current thread status: %s \n", curr->status);

	

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {

	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
	{
		//printf("[thread_create] tid error \n");
		return TID_ERROR;
	}
	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	// [project 1]
	if(thread_mlfqs) { // inheritance of niceness
		t->nice = thread_current()->nice;
	}
	// try to yield CPU to higher priority thread
	thread_try_yield();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	//list_push_back (&ready_list, &t->elem);
	// [project 1] insert ordered as priority
	list_insert_ordered(&ready_list, &t->elem, thread_cmp_priority, greater);
	// this affects 1) priority scheduling, and
	// 2) round robin for each prirority ready queue of mlfqs

	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	
	thread_current()->is_exit=true;
  	list_remove (&thread_current()->allelem);
	// [project 1] remove from mlfqs list
	if(thread_mlfqs) {
		list_remove(&thread_current()->mlfqs_elem);
	}
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;
	//printf("[thread_yield] current thread id: %d \n", curr->tid);
	//printf("[thread_yield] current thread status: %s \n", curr->status);


	ASSERT (!intr_context ());

	old_level = intr_disable ();
	// if (curr != idle_thread)
	// 	list_push_back (&ready_list, &curr->elem);
	// [project 1] push back (round robin) for each priority
	// NOTE : DON'T YIELD too much!!!
	if(curr != idle_thread)
		list_insert_ordered(&ready_list, &curr->elem, thread_cmp_priority, greater);
	//curr->status = THREAD_READY;
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	//thread_current ()->priority = new_priority;
	enum intr_level old_level = intr_disable();
	struct thread *curr = thread_current();
	curr->original_priority = new_priority;
	if(thread_mlfqs) {
		curr->priority = new_priority; // this would not be called
		// TODO : needless?
	} else {
		thread_reperioritize_from_waiters();
	}
	thread_try_yield();
	intr_set_level(old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	ASSERT(nice >= -20 && nice <= 20);
	thread_current()->nice = nice;
	thread_reperioritize_mlfqs(); // NOTE : this automatically calls try_yield.
	//DON'T call another yield.
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return fp_f2i_to_zero(fp_mult_fi(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return fp_f2i_to_zero(fp_mult_fi(thread_current()->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	//printf("[idle] current thread id: %d \n", idle_thread->tid);
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);


	//[project 2]
	//printf("[init_thread] called \n");

	//printf("[init_thread] initializing thread for : %s \n", name);

	int i=0;
  	t->childSize = 0;
  	for(i=0;i<MAX_CHILD;++i)
    	t->child_list[i] = 0;

	t->is_exit=false;
	t->return_value = 0;


	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;



	// [project 1]
	list_init(&t->aquired_locks);
	t->original_priority = priority;
	if(thread_mlfqs) {
		enum intr_level old_level = intr_disable();
		list_push_back(&mlfqs_list, &t->mlfqs_elem);
		intr_set_level(old_level);
	}

	//[project 2]
	list_push_back (&all_list, &t->allelem);
}



//[project 2]
struct thread* get_thread(tid_t tid)
{
    struct list_elem *e;
    
    for (e = list_begin (&all_list); 
         e != list_end (&all_list);
         e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      if( t != NULL && t->tid == tid){
          return t;
      }
    }    
    
    return NULL;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* [project 1] register current thread to sleep_list and block it.
Interrupt blocking is done here.
"ticks_to_wake_up" must be for timer_ticks() of timer.c, not thread_ticks. */
void
thread_register_sleep(int64_t ticks_to_wake_up) {
	// set interrupt disable
	enum intr_level old_level = intr_disable();
	
	// set wake up time and push into list
	struct thread* curr = thread_current();

	// but, it should not be idle_thread
	if(curr == idle_thread) {
		intr_set_level(old_level);
		return;
	}
	
	curr->ticks_to_wake_up = ticks_to_wake_up;
	// list ordered!
	list_insert_ordered(&sleep_list, &(curr->elem), thread_cmp_awake_tick, less);
	//printf("thread %p sleep %lld\n", curr, ticks_to_wake_up);

	// blocking curr, rather than looping
	thread_block();

	// set old interrupt level
	intr_set_level(old_level);
}

/* [project 1] Awake all threads whose ticks_to_wake_up is <= "ticks_now",
then unblock and push them into ready_list */
void
thread_awake_sleep(int64_t ticks_now) {
	// TODO: optimize further more? (ex: run loop only if it must be done)

	struct list_elem* sleep_begin = list_begin(&sleep_list);
	struct list_elem* sleep_end = list_end(&sleep_list);

	// loop for every threads in sleep_list
	for(struct list_elem* it = sleep_begin; it != sleep_end; it = list_next(it)) {
		struct thread* here = list_entry(it, struct thread, elem);
		const bool WAKEUP = here->ticks_to_wake_up <= ticks_now;

		if(WAKEUP) {
			it = list_prev(list_remove(it));
			//printf("thread %p awake\n", here);

			barrier(); // to force order "remove -> unblock"
			// TODO: is this really needed?

			thread_unblock(here);
		} else {
			break; // as sleep_list is ordered!
		}
	}
}

/* [project 1] Priority donation : when higher priority thread is blocked by a lock,
it donates its priority to lock takers, recursively.
NOTE : interrupt must be disabled ahead outside. */
void
thread_donate_blockers() {
	struct thread *th = thread_current();
	int new_priority = th->priority;

	int donation_remain = 10; // it limits donation chain
	while(donation_remain > 0) {
		struct lock *lock = th->blocking_lock;
		if(lock == NULL) break;

		struct thread *blocker = lock->holder;
		ASSERT(is_thread(blocker));

		if(blocker->priority < new_priority) {
			blocker->priority = new_priority;
		} else {
			break;
		}

		th = blocker; // chain
		--donation_remain;
	}
}

/* [project 1] Recalculate priority of current thread,
as giving up donated priority(lock release) or newly getting donation(lock acquire)..
NOTE : interrupt must be disabled ahead outside. */
void
thread_reperioritize_from_waiters() {
	struct thread *curr = thread_current();

	int ret = curr->original_priority;
	struct list_elem *begin = list_begin(&curr->aquired_locks);
	struct list_elem *end = list_end(&curr->aquired_locks);

	for(struct list_elem *it = begin; it != end; it = list_next(it)) {
		struct lock *lock = list_entry(it, struct lock, elem);
		struct list *waiters = &(lock->semaphore.waiters);

		for(struct list_elem *wit = list_begin(waiters);
			wit != list_end(waiters);
			wit = list_next(wit)) {
			struct thread *th = list_entry(wit, struct thread, elem);
			ASSERT(is_thread(th));

			if(ret < th->priority) ret = th->priority;
		}
	}

	curr->priority = ret;
}

/* [project 1] Sort ready list by priority.
NOTE : interrupt must be disabled ahead outside. */
void
thread_sort_ready_list() {
	list_sort(&ready_list, thread_cmp_priority, greater);
}

/* [project 1] try to yield current to higher priority thread, if any
 in ready_list */
void
thread_try_yield() {
	enum intr_level old_level = intr_disable();

	if(!list_empty(&ready_list)) {
		int priority_now = thread_get_priority();

		struct list_elem *begin = list_begin(&ready_list);
		struct thread *highest = list_entry(begin, struct thread, elem);
		ASSERT(is_thread(highest));

		const bool YIELD = highest->priority >=  priority_now;
		if(YIELD) {
			if(intr_context()) intr_yield_on_return();
			else thread_yield();
		}
	}

	intr_set_level(old_level);
}

/* [project 1] calculate load_avg (will be done per a second) */
void
thread_update_load_avg() {
	int32_t not_idle = (int32_t)(thread_current() != idle_thread);
	int32_t ready_threads = (int32_t)list_size(&ready_list) + not_idle;

	load_avg = fp_lerp_i(load_avg, fp_i2f(ready_threads), 1, 60);
}

/* [project 1] update recent_cpu for every threads */
void
thread_update_recent_cpu() {
	ASSERT(thread_mlfqs);
	enum intr_level old_level = intr_disable();

	struct fixed_1714 load_avg_2 = fp_mult_fi(load_avg, 2);
	struct fixed_1714 load_avg_2_plus_1 = fp_plus_fi(load_avg_2, 1);
	struct fixed_1714 load_avg_factor = fp_div_ff(load_avg_2, load_avg_2_plus_1);

	struct list_elem *begin = list_begin(&mlfqs_list);
	struct list_elem *end = list_end(&mlfqs_list);
	for(struct list_elem *it = begin; it != end; it = list_next(it)) {
		struct thread *th = list_entry(it, struct thread, mlfqs_elem);
		
		// idle thread must be excluded
		if(th == idle_thread) continue;

		th->recent_cpu = fp_plus_fi(fp_mult_ff(load_avg_factor, th->recent_cpu), th->nice);
	}

	intr_set_level(old_level);
}

/* [project 1] increment current recent cpu */
void
thread_increment_recent_cpu() {
	struct thread *curr = thread_current();

	// idle thread must be excluded
	if(curr == idle_thread) return;

	curr->recent_cpu = fp_plus_fi(curr->recent_cpu, 1);
}

/* [project 1] recalculate priority of all threads as mlfqs 
NOTE : this will finally call try_yield */
void
thread_reperioritize_mlfqs() {
	enum intr_level old_level = intr_disable();

	struct list_elem *begin = list_begin(&mlfqs_list);
	struct list_elem *end = list_end(&mlfqs_list);

	for(struct list_elem *it = begin; it != end; it = list_next(it)) {
		struct thread *th = list_entry(it, struct thread, mlfqs_elem);
		ASSERT(is_thread(th));

		struct fixed_1714 rc_4 = fp_div_fi(th->recent_cpu, 4);
		th->priority = fp_clamp_i(
			fp_minus_fi(fp_minus_ff(fp_i2f(PRI_MAX), rc_4), th->nice * 2),
			PRI_MIN, PRI_MAX, fp_f2i_nearest
		); // NOTE : fp_f2i_nearest must be used instead of to_zero
	}

	thread_sort_ready_list();
	thread_try_yield();

	intr_set_level(old_level);
}

/* [project 1] compare function of threads w.r.t. priority.
aux should be set as either 'less' or 'greater'. (default 0 indicates 'less') */
bool
thread_cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux) {
	enum cmp_policy policy = (enum cmp_policy)aux;
	const struct thread *at = list_entry(a, struct thread, elem);
	const struct thread *bt = list_entry(b, struct thread, elem);
	
	if(policy == greater) {
		return at->priority > bt->priority;
	}
	return at->priority < bt->priority;
}

/* [project 1] compare function of threads w.r.t. ticks_to_wake_up.
aux should be set as either 'less' or 'greater'. (default 0 indicates 'less') */
bool
thread_cmp_awake_tick(const struct list_elem *a, const struct list_elem *b, void *aux) {
	enum cmp_policy policy = (enum cmp_policy)aux;
	const struct thread *at = list_entry(a, struct thread, elem);
	const struct thread *bt = list_entry(b, struct thread, elem);

	if(policy == greater) {
		return at->ticks_to_wake_up > bt->ticks_to_wake_up;
	}
	return at->ticks_to_wake_up < bt->ticks_to_wake_up;
}

/* [project 1] compare function of threads

/** static functions **/

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
