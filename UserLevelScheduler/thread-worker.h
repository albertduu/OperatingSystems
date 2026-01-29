// File:	worker_t.h

// List all group member's name:
// username of iLab:
// iLab Server:

#ifndef WORKER_T_H
#define WORKER_T_H

#define _GNU_SOURCE

/* To use Linux pthread Library in Benchmark, you have to comment the USE_WORKERS macro */
#define USE_WORKERS 1

/* Targeted latency in milliseconds */
#define TARGET_LATENCY   20000  

/* Minimum scheduling granularity in milliseconds */
#define MIN_SCHED_GRN    5000

/* Time slice quantum in milliseconds */
#define QUANTUM 10000

/* include lib header files that you need here: */
#include <ucontext.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define STACK_SIZE  (64 * 1024)
#define NUMPRIO     3              
#define R_QUANTUM   100000      
#define DEBUG       0


#define READY       0
#define SCHEDULED   1
#define BLOCKED     2
#define TERMINATED  3


typedef uint worker_t;

typedef struct TCB {
	worker_t id;
    int status;
    ucontext_t *context;
    void *stack;
    void *retval;
    int priority;
    int scheduled;
    long elapsed_time;
    long residual_time;
    int64_t start_us;
    long long vruntime_us;
    int nice;       
    long timeslice_us;
} tcb; 

/* mutex struct definition */
typedef struct worker_mutex_t {
	atomic_flag locked;
    int owner_id;
} worker_mutex_t;

/* define your data structures here: */
// Feel free to add your own auxiliary data structures (linked list or queue etc...)
typedef struct node {
    tcb *thread;
    struct node *next;
} node;


typedef struct queue {
    node *head;
    node *tail;
    int size;
} queue;


/* Function Declarations: */
queue *init_queue();
void free_queue(queue *q);
int is_empty(queue *q);
void enqueue(queue *q, tcb *t, char *file, int line);
void enqueue_prio(queue **run_queue, tcb *t, char *file, int line);
tcb *dequeue(queue *q);
tcb *find(queue *q, worker_t id);
tcb *find_all(queue **run_queue, worker_t id);
tcb *evict_min_elapsed_time(queue *q);
tcb *get_prio_thread(queue **run_queue);
void reset_prio(queue **run_queue);
static void schedule_cfs(void);
int runnable_count_cfs(queue **rq);
tcb *cfs_pick_min(queue **rq);
int queue_size(queue *q);

/* create a new thread */
int worker_create(worker_t * thread, pthread_attr_t * attr, void
    *(*function)(void*), void * arg);

/* give CPU pocession to other user level worker threads voluntarily */
int worker_yield();

/* terminate a thread */
void worker_exit(void *value_ptr);

/* wait for thread termination */
int worker_join(worker_t thread, void **value_ptr);

/* initial the mutex lock */
int worker_mutex_init(worker_mutex_t *mutex, const pthread_mutexattr_t
    *mutexattr);

/* aquire the mutex lock */
int worker_mutex_lock(worker_mutex_t *mutex);

/* release the mutex lock */
int worker_mutex_unlock(worker_mutex_t *mutex);

/* destroy the mutex */
int worker_mutex_destroy(worker_mutex_t *mutex);


/* Function to print global statistics. Do not modify this function.*/
void print_app_stats(void);

#ifdef USE_WORKERS
#define pthread_t worker_t
#define pthread_mutex_t worker_mutex_t
#define pthread_create worker_create
#define pthread_exit worker_exit
#define pthread_join worker_join
#define pthread_mutex_init worker_mutex_init
#define pthread_mutex_lock worker_mutex_lock
#define pthread_mutex_unlock worker_mutex_unlock
#define pthread_mutex_destroy worker_mutex_destroy
#endif

#endif
