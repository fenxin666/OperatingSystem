#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "devices/pit.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

/* [Fix] 睡眠等待队列 */
static struct list sleep_list;

/* [Fix] 睡眠事件结构体 */
struct sleep_event {
    int64_t wakeup_ticks;       /* 唤醒时间 */
    struct semaphore sema;      /* 用于阻塞的信号量 */
    struct list_elem elem;      /* 链表元素 */
};

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);
static void real_time_delay(int64_t num, int32_t denom);

/* Sets up the timer to interrupt TIMER_FREQ times per second,
   and registers the corresponding interrupt. */
void timer_init(void) {
  pit_configure_channel(0, 2, TIMER_FREQ);
  intr_register_ext(0x20, timer_interrupt, "8254 Timer");
  /* [Fix] 初始化睡眠队列 */
  list_init(&sleep_list);
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void timer_calibrate(void) {
  unsigned high_bit, test_bit;

  ASSERT(intr_get_level() == INTR_ON);
  printf("Calibrating timer...  ");

  /* Approximate loops_per_tick as the largest power-of-two
     still less than one timer tick. */
  loops_per_tick = 1u << 10;
  while (!too_many_loops(loops_per_tick << 1)) {
    loops_per_tick <<= 1;
    ASSERT(loops_per_tick != 0);
  }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops(loops_per_tick | test_bit))
      loops_per_tick |= test_bit;

  printf("%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t timer_ticks(void) {
  enum intr_level old_level = intr_disable();
  int64_t t = ticks;
  intr_set_level(old_level);
  return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t timer_elapsed(int64_t then) { return timer_ticks() - then; }

/* [Fix] 比较函数，用于维护睡眠队列有序 */
static bool timer_less_func(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
    struct sleep_event *sa = list_entry(a, struct sleep_event, elem);
    struct sleep_event *sb = list_entry(b, struct sleep_event, elem);
    return sa->wakeup_ticks < sb->wakeup_ticks;
}

/* Sleeps for approximately TICKS timer ticks.  Interrupts must
   be turned on. */
void timer_sleep(int64_t ticks) {
  int64_t start = timer_ticks();

  ASSERT(intr_get_level() == INTR_ON);
  
  /* [Fix] 使用阻塞式睡眠代替忙等待 */
  if (ticks <= 0) return;

  struct sleep_event event;
  event.wakeup_ticks = start + ticks;
  sema_init(&event.sema, 0);

  enum intr_level old_level = intr_disable();
  list_insert_ordered(&sleep_list, &event.elem, timer_less_func, NULL);
  intr_set_level(old_level);

  sema_down(&event.sema);
}

/* Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void timer_msleep(int64_t ms) { real_time_sleep(ms, 1000); }

/* Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void timer_usleep(int64_t us) { real_time_sleep(us, 1000 * 1000); }

/* Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void timer_nsleep(int64_t ns) { real_time_sleep(ns, 1000 * 1000 * 1000); }

/* Busy waits. */
void timer_mdelay(int64_t ms) { real_time_delay(ms, 1000); }
void timer_udelay(int64_t us) { real_time_delay(us, 1000 * 1000); }
void timer_ndelay(int64_t ns) { real_time_delay(ns, 1000 * 1000 * 1000); }

void timer_print_stats(void) { printf("Timer: %" PRId64 " ticks\n", timer_ticks()); }

/* Timer interrupt handler. */
static void timer_interrupt(struct intr_frame* args UNUSED) {
  ticks++;
  thread_tick();

  /* [Fix] 检查并唤醒睡眠时间已到的线程 */
  if (!list_empty(&sleep_list)) {
      struct list_elem *e = list_begin(&sleep_list);
      while (e != list_end(&sleep_list)) {
          struct sleep_event *event = list_entry(e, struct sleep_event, elem);
          if (ticks >= event->wakeup_ticks) {
              e = list_remove(e);
              sema_up(&event->sema);
          } else {
              /* 因为队列有序，如果头部没到时间，后面的肯定也没到 */
              break;
          }
      }
  }
}

static bool too_many_loops(unsigned loops) {
  int64_t start = ticks;
  while (ticks == start)
    barrier();
  start = ticks;
  busy_wait(loops);
  barrier();
  return start != ticks;
}

static void NO_INLINE busy_wait(int64_t loops) {
  while (loops-- > 0)
    barrier();
}

static void real_time_sleep(int64_t num, int32_t denom) {
  int64_t ticks = num * TIMER_FREQ / denom;
  ASSERT(intr_get_level() == INTR_ON);
  if (ticks > 0) {
    timer_sleep(ticks);
  } else {
    real_time_delay(num, denom);
  }
}

static void real_time_delay(int64_t num, int32_t denom) {
  ASSERT(denom % 1000 == 0);
  busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
}
