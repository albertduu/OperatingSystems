// File:	thread-worker.c
// List all group member's name:
// username of iLab:
// iLab Server:

#include "thread-worker.h"
#include <time.h>
#include <stdint.h>

static inline int64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000);
}

//Global counter for total context switches and 
//average turn around and response time
long tot_cntx_switches = 0;
double avg_turn_time = 0.0;
double avg_resp_time = 0.0;

queue *ready_queues[NUMPRIO];   // multi-level ready queues (for MLFQ)
queue *mutex_wait_queue;        // blocked threads on mutexes
queue *terminated_queue;        // finished threads for cleanup

tcb *current_thread = NULL;     // currently running thread
tcb *scheduler_thread = NULL;   // dedicated scheduler context

struct sigaction sa;
struct itimerval timer;

static int scheduler_initialized = 0;
static int thread_counter = 1;
static int scheduled_threads = 0;
static int completed_threads = 0;
int64_t last_refresh_time;

static void schedule_dispatch();
static void sched_psjf();
static void sched_mlfq();
static void timer_handler(int signum);

static void initialize_scheduler();
static void cleanup_scheduler();
static tcb *create_tcb(worker_t *tid);
static void setup_context(tcb *thread);
static void context_switch_to(tcb *next);
static void start_thread_timer(tcb *thread);
static void pause_thread_timer();
static void resume_thread_timer(tcb *thread);
static void compute_response_time(tcb *thread);
static void compute_turnaround_time(tcb *thread);
static tcb *find_thread(worker_t tid);



int worker_create(worker_t * thread, pthread_attr_t * attr, 
                      void *(*function)(void*), void * arg) {

    if (!scheduler_initialized)
        initialize_scheduler();

    tcb *new_tcb = create_tcb(thread);
    getcontext(new_tcb->context);
    setup_context(new_tcb);

    makecontext(new_tcb->context, (void (*)(void))function, 1, arg);
    enqueue_prio(ready_queues, new_tcb, __FILE__, __LINE__);
    return 0;
};

/* give CPU possession to other user-level worker threads voluntarily */
int worker_yield() {
	enqueue_prio(ready_queues, current_thread, __FILE__, __LINE__);
    context_switch_to(scheduler_thread);
    return 0;
};

/* terminate a thread */
void worker_exit(void *value_ptr) {
	tcb *exiting = current_thread;
    exiting->retval = value_ptr;
    exiting->status = TERMINATED;

    compute_turnaround_time(exiting);
    enqueue(terminated_queue, exiting, __FILE__, __LINE__);

    free(exiting->stack);
    free(exiting->context);
    exiting->stack = NULL;
    exiting->context = NULL;

    context_switch_to(scheduler_thread);
};

/* Wait for thread termination */
int worker_join(worker_t thread, void **value_ptr) {
	pause_thread_timer();
    tcb *target = find_thread(thread);
    if (!target)
        return 1;

    resume_thread_timer(current_thread);
    while (target->status != TERMINATED)
        ; // spin wait

    if (value_ptr)
        *value_ptr = target->retval;
    return 0;
};

/* initialize the mutex lock */
int worker_mutex_init(worker_mutex_t *mutex, 
                          const pthread_mutexattr_t *mutexattr) {
	atomic_flag_clear(&mutex->locked);
    mutex->owner_id = -1;
    return 0;
};



int worker_mutex_lock(worker_mutex_t *mutex) {
    while (atomic_flag_test_and_set(&mutex->locked)) {
        current_thread->status = BLOCKED;
        enqueue(mutex_wait_queue, current_thread, __FILE__, __LINE__);
        context_switch_to(scheduler_thread);
    }
    mutex->owner_id = current_thread->id;
    return 0;
};

/* release the mutex lock */
int worker_mutex_unlock(worker_mutex_t *mutex) {
	atomic_flag_clear(&mutex->locked);
    mutex->owner_id = -1;

    while (!is_empty(mutex_wait_queue)) {
        tcb *wakeup = dequeue(mutex_wait_queue);
        wakeup->status = READY;
        enqueue_prio(ready_queues, wakeup, __FILE__, __LINE__);
    }
    return 0;
};


/* destroy the mutex */
int worker_mutex_destroy(worker_mutex_t *mutex) {
	(void)mutex;
	return 0;
};

static void schedule_dispatch() {
#if defined(MLFQ)
    while (1) sched_mlfq();
#else
    while (1) sched_psjf();
#endif
}

/* Pre-emptive Shortest Job First (POLICY_PSJF) scheduling algorithm */
static void sched_psjf() {
    tcb *next = evict_min_elapsed_time(ready_queues[NUMPRIO - 1]);
    if (!next) return;

    if (!next->scheduled)
        compute_response_time(next);

    if (next->residual_time <= 0) {
        next->residual_time = QUANTUM;
        next->elapsed_time += QUANTUM;
    }

    start_thread_timer(next);
    context_switch_to(next);

    if (next->status == SCHEDULED) {
        next->status = READY;
        enqueue_prio(ready_queues, next, __FILE__, __LINE__);
    }
}


/* Preemptive MLFQ scheduling algorithm */
static void sched_mlfq() {
	tcb *next = get_prio_thread(ready_queues);
    if (!next) return;

    if (!next->scheduled)
        compute_response_time(next);

    if (next->residual_time <= 0) {
        next->residual_time = QUANTUM;
        next->priority = (next->priority > 0) ? next->priority - 1 : 0;
    }

    start_thread_timer(next);
    context_switch_to(next);

    if (next->status == SCHEDULED) {
        next->status = READY;
        enqueue_prio(ready_queues, next, __FILE__, __LINE__);
    }

    time_t now = clock();
    if (now - last_refresh_time >= R_QUANTUM) {
        reset_prio(ready_queues);
        last_refresh_time = now;
    }
}

/* Completely fair scheduling algorithm */
static void sched_cfs(){

    tcb *next = evict_min_elapsed_time(ready_queues[NUMPRIO - 1]);
    if (!next)
        return;

    int runnable_threads = queue_size(ready_queues[NUMPRIO - 1]);
    if (runnable_threads == 0)
        runnable_threads = 1;

    long time_slice = TARGET_LATENCY / runnable_threads;
    if (time_slice < MIN_SCHED_GRN)
        time_slice = MIN_SCHED_GRN;

    if (!next->scheduled)
        compute_response_time(next);

    next->residual_time = time_slice;

    int64_t run_start = now_us();
    start_thread_timer(next);
    context_switch_to(next);

    int64_t ran_us = now_us() - run_start;
    next->elapsed_time += ran_us;
    next->status = READY;

    if (next->status != TERMINATED)
        enqueue_prio(ready_queues, next, __FILE__, __LINE__);
}


/* scheduler */
static void schedule() {
	// - every time a timer interrupt occurs, your worker thread library 
	// should be contexted switched from a thread context to this 
	// schedule() function
	
	//YOUR CODE HERE

	// - invoke scheduling algorithms according to the policy (PSJF or MLFQ or CFS)
#if defined(PSJF)
    sched_psjf();
#elif defined(MLFQ)
	sched_mlfq();
#elif defined(CFS)
    sched_cfs();  
#else
	# error "Define one of PSJF, MLFQ, or CFS when compiling. e.g. make SCHED=MLFQ"
#endif
}




//DO NOT MODIFY THIS FUNCTION
/* Function to print global statistics. Do not modify this function.*/
void print_app_stats(void) {

       fprintf(stderr, "Total context switches %ld \n", tot_cntx_switches);
       fprintf(stderr, "Average turnaround time %lf \n", avg_turn_time);
       fprintf(stderr, "Average response time  %lf \n", avg_resp_time);
}

static void timer_handler(int signum) {
    (void)signum;
    if (current_thread && current_thread->id != scheduler_thread->id) {
        enqueue_prio(ready_queues, current_thread, __FILE__, __LINE__);
    }
    context_switch_to(scheduler_thread);
}

static void start_thread_timer(tcb *thread) {
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = thread->residual_time;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_PROF, &timer, NULL);
}

static void pause_thread_timer() {
    struct itimerval cur;
    getitimer(ITIMER_PROF, &cur);
    current_thread->residual_time = cur.it_value.tv_usec;

    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_PROF, &timer, NULL);
}

static void resume_thread_timer(tcb *thread) {
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = thread->residual_time;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_PROF, &timer, NULL);
}

static void initialize_scheduler() {
    scheduler_initialized = 1;
    last_refresh_time = now_us();

    for (int i = 0; i < NUMPRIO; i++) ready_queues[i] = init_queue();
    mutex_wait_queue = init_queue();
    terminated_queue = init_queue();

    scheduler_thread = create_tcb(NULL);
    getcontext(scheduler_thread->context);
    setup_context(scheduler_thread);
    makecontext(scheduler_thread->context, (void (*)(void))schedule_dispatch, 0);

    current_thread = create_tcb(NULL);
    current_thread->context = (ucontext_t*)malloc(sizeof(ucontext_t));
    getcontext(current_thread->context);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &timer_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPROF, &sa, NULL);

    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = QUANTUM;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_PROF, &timer, NULL);

    atexit(cleanup_scheduler);
}

static void cleanup_scheduler() {
    for (int i = 0; i < NUMPRIO; i++) free_queue(ready_queues[i]);
    free_queue(mutex_wait_queue);
    free_queue(terminated_queue);

    if (scheduler_thread) {
        free(scheduler_thread->stack);
        free(scheduler_thread->context);
        free(scheduler_thread);
        scheduler_thread = NULL;
    }

    setitimer(ITIMER_PROF, NULL, NULL);
}

static void context_switch_to(tcb *next) {
    tcb *prev = current_thread;
    current_thread = next;
    current_thread->status = SCHEDULED;

    if (prev && next && next->id != prev->id) tot_cntx_switches++;

    if (prev && prev->status != TERMINATED) {
        prev->status = READY;
        swapcontext(prev->context, next->context);
    } else {
        setcontext(next->context);
    }
}

static tcb *create_tcb(worker_t *tid) {
    tcb *t = (tcb*)malloc(sizeof(tcb));
    if (!t) return NULL;

    t->id = thread_counter++;
    if (tid) *tid = t->id;

    t->status = READY;
    t->context = (ucontext_t*)malloc(sizeof(ucontext_t));
    t->stack = NULL;
    t->retval = NULL;

    t->priority = NUMPRIO - 1;
    t->scheduled = 0;
    t->elapsed_time = 0;
    t->residual_time = QUANTUM;
    t->start_us = now_us();

    return t;
}

static void setup_context(tcb *thread) {
    if (!thread) return;
    getcontext(thread->context);

    thread->stack = malloc(STACK_SIZE);
    if (!thread->stack) return;

    thread->context->uc_stack.ss_sp = thread->stack;
    thread->context->uc_stack.ss_size = STACK_SIZE;
    thread->context->uc_link = NULL;
    thread->context->uc_flags = 0;
}

static void compute_response_time(tcb *thread) {
    int64_t resp = now_us() - thread->start_us;
    avg_resp_time = (avg_resp_time * scheduled_threads + (double)resp) / (double)(++scheduled_threads);
    thread->scheduled = 1;
}

static void compute_turnaround_time(tcb *thread) {
    int64_t turn = now_us() - thread->start_us;
    avg_turn_time = (avg_turn_time * completed_threads + (double)turn) / (double)(++completed_threads);
}

static tcb *find_thread(worker_t tid) {
    tcb *t = find_all(ready_queues, tid);
    if (!t) t = find(mutex_wait_queue, tid);
    if (!t) t = find(terminated_queue, tid);
    return t;
}

