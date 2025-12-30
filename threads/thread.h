#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "threads/fixed-point.h"

/* [新增] 前置声明，防止 process.c 报错 */
struct process;

/* Types of scheduler that the user can request the kernel
 * use to schedule threads at runtime. */
enum sched_policy {
  SCHED_FIFO,  // First-in, first-out scheduler
  SCHED_PRIO,  // Strict-priority scheduler with round-robin tiebreaking
  SCHED_FAIR,  // Implementation-defined fair scheduler
  SCHED_MLFQS, // Multi-level Feedback Queue Scheduler
};
#define SCHED_DEFAULT SCHED_FIFO

/* Determines which scheduling policy the kernel should use. */
extern enum sched_policy active_sched_policy;

/* States in a thread's life cycle. */
enum thread_status {
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* A kernel thread or user process. */
struct thread {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* === Task 1: Priority Scheduling === */
    int base_priority;                  /* Base priority (before donation). */
    struct list locks;                  /* Locks held by the thread. */
    struct lock *lock_waiting;          /* Lock the thread is currently waiting for. */

    /* === Task 2: MLFQS === */
    int nice;                           /* Nice value (-20 to 20). */
    fixed_point_t recent_cpu;           /* Recent CPU usage (fixed-point). */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* [修复] 修改为 struct process*，解决 process.c 报错 */
    struct process *pcb;                /* Process Control Block */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
};

/* [Task 2] 全局负载平均值 */
extern fixed_point_t load_avg;

/* [Task 1] 优先级比较函数声明 */
bool thread_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void* aux);
tid_t thread_create(const char* name, int priority, thread_func*, void*);

void thread_block(void);
void thread_unblock(struct thread*);

struct thread* thread_current(void);
tid_t thread_tid(void);
const char* thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

typedef void thread_action_func(struct thread* t, void* aux);
void thread_foreach(thread_action_func*, void*);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

#endif /* threads/thread.h */
