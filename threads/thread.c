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
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "threads/fixed-point.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

#define THREAD_MAGIC 0xcd6abf4b

/* 声明调度函数类型 */
typedef struct thread* scheduler_func(void);

static struct list fifo_ready_list;
static struct list all_list;
static struct thread* idle_thread;
static struct thread* initial_thread;
static struct lock tid_lock;
static uint8_t initial_fpu_state[108];

struct kernel_thread_frame {
  void* eip;
  thread_func* function;
  void* aux;
};

static long long idle_ticks;
static long long kernel_ticks;
static long long user_ticks;

#define TIME_SLICE 4
static unsigned thread_ticks;

/* MLFQS 全局变量 */
fixed_point_t load_avg;

static void init_thread(struct thread*, const char* name, int priority);
static bool is_thread(struct thread*) UNUSED;
static void* alloc_frame(struct thread*, size_t size);
static void schedule(void);
static void thread_enqueue(struct thread* t);
static tid_t allocate_tid(void);
void thread_switch_tail(struct thread* prev);

static void kernel_thread(thread_func*, void* aux);
static void idle(void* aux UNUSED);
static struct thread* running_thread(void);

static struct thread* next_thread_to_run(void);
static struct thread* thread_schedule_fifo(void);
static struct thread* thread_schedule_prio(void);
static struct thread* thread_schedule_fair(void);
static struct thread* thread_schedule_mlfqs(void);
static struct thread* thread_schedule_reserved(void);

/* MLFQS 辅助计算函数 */
void mlfqs_calculate_priority(struct thread *t, void *aux UNUSED);
void mlfqs_calculate_recent_cpu(struct thread *t, void *aux UNUSED);
void mlfqs_calculate_load_avg(void);
void mlfqs_increment_recent_cpu(void);

/* Task 1: 优先级比较函数声明 */
bool thread_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

enum sched_policy active_sched_policy;

/* 调度策略跳转表 */
scheduler_func* scheduler_jump_table[8] = {thread_schedule_fifo,     thread_schedule_prio,
                                           thread_schedule_fair,     thread_schedule_mlfqs,
                                           thread_schedule_reserved, thread_schedule_reserved,
                                           thread_schedule_reserved, thread_schedule_reserved};

void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);
  lock_init(&tid_lock);
  list_init(&fifo_ready_list);
  list_init(&all_list);
  load_avg = fix_int(0);
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
}

void thread_start(void) {
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);
  /* === 核心操作：生成并保存 FPU 金标准状态 === */
  uint32_t cr0;
  asm volatile ("movl %%cr0, %0" : "=r" (cr0));
  cr0 &= ~0x0C; /* 清除 EM 和 TS，解锁 FPU */
  asm volatile ("movl %0, %%cr0" :: "r" (cr0));
  
  asm volatile ("fninit"); /* 初始化硬件 FPU */
  asm volatile ("fsave %0" : "=m" (initial_fpu_state)); /* 将干净状态保存到全局变量 */
  /* =========================================== */
  intr_enable();
  sema_down(&idle_started);
}

void thread_tick(void) {
  struct thread* t = thread_current();
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pcb != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* [Fix] 同时为 MLFQS 和 FAIR 策略启用动态优先级计算 */
  if (active_sched_policy == SCHED_MLFQS || active_sched_policy == SCHED_FAIR) {
      mlfqs_increment_recent_cpu();
      if (timer_ticks() % TIMER_FREQ == 0) {
          mlfqs_calculate_load_avg();
          thread_foreach(mlfqs_calculate_recent_cpu, NULL);
      }
      if (timer_ticks() % 4 == 0) {
          thread_foreach(mlfqs_calculate_priority, NULL);
          if (!list_empty(&fifo_ready_list)) {
              /* 重新排序就绪队列，因为优先级可能已经改变 */
              list_sort(&fifo_ready_list, thread_cmp_priority, NULL);
          }

          /* [核心修复] 优先级更新后，必须检查抢占！
             如果当前线程不是 idle，且优先级低于就绪队列中最高的线程，立即让出 CPU */
          if (!list_empty(&fifo_ready_list)) {
              struct thread *max_ready = list_entry(list_begin(&fifo_ready_list), struct thread, elem);
              if (t != idle_thread && t->priority < max_ready->priority) {
                  intr_yield_on_return();
              }
          }
      }
  }

  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();
}

void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks,
         user_ticks);
}

tid_t thread_create(const char* name, int priority, thread_func* function, void* aux) {
  struct thread* t;
  struct kernel_thread_frame* kf;
  struct switch_entry_frame* ef;
  struct switch_threads_frame* sf;
  tid_t tid;

  ASSERT(function != NULL);
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL) return TID_ERROR;

  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  thread_unblock(t);

  /* Task 1: 抢占 */
  if (thread_current()->priority < t->priority) {
      thread_yield();
  }
  return tid;
}

void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);
  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

static void thread_enqueue(struct thread* t) {
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(is_thread(t));
  list_insert_ordered(&fifo_ready_list, &t->elem, thread_cmp_priority, NULL);
}

void thread_unblock(struct thread* t) {
  enum intr_level old_level;
  ASSERT(is_thread(t));
  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  thread_enqueue(t);
  t->status = THREAD_READY;
  intr_set_level(old_level);
}

const char* thread_name(void) { return thread_current()->name; }

struct thread* thread_current(void) {
  struct thread* t = running_thread();
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);
  return t;
}

tid_t thread_tid(void) { return thread_current()->tid; }

void thread_exit(void) {
  ASSERT(!intr_context());
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

void thread_yield(void) {
  struct thread* cur = thread_current();
  enum intr_level old_level;
  ASSERT(!intr_context());
  old_level = intr_disable();
  if (cur != idle_thread)
    thread_enqueue(cur);
  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

void thread_foreach(thread_action_func* func, void* aux) {
  struct list_elem* e;
  ASSERT(intr_get_level() == INTR_OFF);
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

void thread_set_priority(int new_priority) { 
    if (active_sched_policy == SCHED_MLFQS || active_sched_policy == SCHED_FAIR)
        return;

    struct thread *cur = thread_current();
    int old_priority = cur->priority;
    
    cur->base_priority = new_priority;
    refresh_priority(cur);
    
    if (cur->priority < old_priority) {
        thread_yield();
    }
}

int thread_get_priority(void) { return thread_current()->priority; }

void thread_set_nice(int nice) {
    if (nice > 20) nice = 20;
    if (nice < -20) nice = -20;
    struct thread *cur = thread_current();
    cur->nice = nice;
    mlfqs_calculate_priority(cur, NULL);
    if (cur->priority < 0) cur->priority = 0;
    if (cur->priority > PRI_MAX) cur->priority = PRI_MAX;
    thread_yield();
}

int thread_get_nice(void) { return thread_current()->nice; }

int thread_get_load_avg(void) { return fix_round(fix_scale(load_avg, 100)); }

int thread_get_recent_cpu(void) { return fix_round(fix_scale(thread_current()->recent_cpu, 100)); }

static void idle(void* idle_started_ UNUSED) {
  struct semaphore* idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);
  for (;;) {
    intr_disable();
    thread_block();
    asm volatile("sti; hlt" : : : "memory");
  }
}

static void kernel_thread(thread_func* function, void* aux) {
  ASSERT(function != NULL);
  /* === 3. 核心修复：新线程启动时加载干净 FPU 状态 === */
  /* 确保 CPU 寄存器是空的，不会触发 Stack Overflow */
  asm volatile ("clts"); /* 确保 FPU 解锁 */
  asm volatile ("frstor %0" : : "m" (running_thread()->fpu_state));
  /* ================================================= */
  /* =========================================== */
  intr_enable(); 
  function(aux); 
  thread_exit(); 
}

struct thread* running_thread(void) {
  uint32_t* esp;
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

static bool is_thread(struct thread* t) { return t != NULL && t->magic == THREAD_MAGIC; }

static void init_thread(struct thread* t, const char* name, int priority) {
  enum intr_level old_level;
  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);
  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t*)t + PGSIZE;
  t->priority = priority;
  t->base_priority = priority;
  list_init(&t->locks);
  t->lock_waiting = NULL;
  t->nice = 0;
  t->recent_cpu = fix_int(0);
  if (t != initial_thread) {
      if (running_thread()->magic == THREAD_MAGIC) {
        struct thread *parent = running_thread();
        t->nice = parent->nice;
        t->recent_cpu = parent->recent_cpu;
      }
  }

  /* [核心修复] MLFQS 模式下，线程创建时必须立即计算正确的优先级 */
  /* 否则新线程会以默认优先级(31)运行直到下一次 tick 更新，这会破坏 hierarchy 测试 */
  if (active_sched_policy == SCHED_MLFQS || active_sched_policy == SCHED_FAIR) {
      mlfqs_calculate_priority(t, NULL);
  }

#ifdef USERPROG
  t->pcb = NULL;
#endif
/* === 核心修复：直接复制金标准状态 === */
  /* 这比 memset 安全，比 asm 稳定 */
  memcpy(t->fpu_state, initial_fpu_state, sizeof(t->fpu_state));
  /* ================================= */
  t->magic = THREAD_MAGIC;
  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);
  intr_set_level(old_level);
}

static void* alloc_frame(struct thread* t, size_t size) {
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);
  t->stack -= size;
  return t->stack;
}

static struct thread* thread_schedule_fifo(void) {
  if (!list_empty(&fifo_ready_list))
    return list_entry(list_pop_front(&fifo_ready_list), struct thread, elem);
  else
    return idle_thread;
}

static struct thread* thread_schedule_prio(void) {
  return thread_schedule_fifo();
}

static struct thread* thread_schedule_fair(void) {
  return thread_schedule_prio();
}

static struct thread* thread_schedule_mlfqs(void) {
  return thread_schedule_fifo();
}

static struct thread* thread_schedule_reserved(void) {
  PANIC("Invalid scheduler policy value: %d", active_sched_policy);
}

static struct thread* next_thread_to_run(void) {
  return (scheduler_jump_table[active_sched_policy])();
}

void thread_switch_tail(struct thread* prev) {
  struct thread* cur = running_thread();
  ASSERT(intr_get_level() == INTR_OFF);
  cur->status = THREAD_RUNNING;
  thread_ticks = 0;
#ifdef USERPROG
  process_activate();
#endif
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

static void schedule(void) {
  struct thread* cur = running_thread();
  struct thread* next = next_thread_to_run();
  struct thread* prev = NULL;
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));
  if (cur != next)
  /* 1. 保存当前 FPU */
      /* 为了防止 cur 根本没用过 FPU (导致 fninit 没执行过)，
         我们可以先 fninit 一下再 fsave (为了安全)，或者直接 fsave。
         但在 Pintos 里，最稳妥的是：如果 CR0 显示 FPU 开启了，就保存。
         不过简化版直接 fsave 也可以，因为我们有 exception.c 兜底。*/
      asm volatile ("clts");
      asm volatile ("fsave %0" : "=m" (cur->fpu_state));
    prev = switch_threads(cur, next);
    /* 2. 恢复新线程 FPU */
    asm volatile ("clts");
      struct thread *my_thread = running_thread ();
      asm volatile ("frstor %0" : : "m" (my_thread->fpu_state));
  thread_switch_tail(prev);
}

static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;
  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);
  return tid;
}

uint32_t thread_stack_ofs = offsetof(struct thread, stack);

bool thread_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
    return list_entry(a, struct thread, elem)->priority > list_entry(b, struct thread, elem)->priority;
}

void mlfqs_calculate_priority(struct thread *t, void *aux UNUSED) {
    if (t == idle_thread) return;
    fixed_point_t term1 = fix_div_int(t->recent_cpu, 4);
    int term2 = t->nice * 2;
    fixed_point_t p = fix_sub(fix_int(PRI_MAX), term1);
    p = fix_sub(p, fix_int(term2));
    int new_p = fix_trunc(p);
    if (new_p < PRI_MIN) new_p = PRI_MIN;
    if (new_p > PRI_MAX) new_p = PRI_MAX;
    t->priority = new_p;
}

void mlfqs_calculate_recent_cpu(struct thread *t, void *aux UNUSED) {
    if (t == idle_thread) return;
    fixed_point_t double_load = fix_mul_int(load_avg, 2);
    fixed_point_t coeff = fix_div(double_load, fix_add_int(double_load, 1));
    t->recent_cpu = fix_add_int(fix_mul(coeff, t->recent_cpu), t->nice);
}

void mlfqs_calculate_load_avg(void) {
    int ready_threads = list_size(&fifo_ready_list);
    struct thread *cur = thread_current();
    if (cur != idle_thread) ready_threads++;
    fixed_point_t term1 = fix_mul(fix_frac(59, 60), load_avg);
    fixed_point_t term2 = fix_mul_int(fix_frac(1, 60), ready_threads);
    load_avg = fix_add(term1, term2);
}

void mlfqs_increment_recent_cpu(void) {
    struct thread *cur = thread_current();
    if (cur != idle_thread) {
        cur->recent_cpu = fix_add_int(cur->recent_cpu, 1);
    }
}
