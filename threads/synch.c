#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* 外部函数原型 */
extern bool thread_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

/* 内部函数原型 (注意 refresh_priority 已经在头文件中声明，这里不需要再次声明为内部) */
void donate_priority(void);
bool cond_sema_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux);

void sema_init (struct semaphore *sema, unsigned value) {
  ASSERT (sema != NULL);
  sema->value = value;
  list_init (&sema->waiters);
}

void sema_down (struct semaphore *sema) {
  enum intr_level old_level;
  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) {
      list_insert_ordered (&sema->waiters, &thread_current ()->elem, thread_cmp_priority, NULL);
      thread_block ();
  }
  sema->value--;
  intr_set_level (old_level);
}

bool sema_try_down (struct semaphore *sema) {
  enum intr_level old_level;
  bool success;
  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) {
      sema->value--;
      success = true; 
  } else {
      success = false;
  }
  intr_set_level (old_level);
  return success;
}

void sema_up (struct semaphore *sema) {
  enum intr_level old_level;
  bool preempt = false;
  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)) {
      list_sort(&sema->waiters, thread_cmp_priority, NULL);
      struct thread *t = list_entry (list_pop_front (&sema->waiters), struct thread, elem);
      thread_unblock (t);
      if (t->priority > thread_current()->priority) {
          preempt = true;
      }
  }
  sema->value++;
  
  if (preempt && !intr_context()) {
      thread_yield();
  }
  intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

void sema_self_test (void) {
  struct semaphore sema[2];
  int i;
  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  for (i = 0; i < 10; i++) {
      char name[16];
      snprintf (name, sizeof name, "Sema %d", i);
      thread_create (name, PRI_DEFAULT, sema_test_helper, &sema);
  }
  sema_down (&sema[0]);
  printf ("done.\n");
}

static void sema_test_helper (void *sema_) {
  struct semaphore *sema = sema_;
  int i;
  for (i = 0; i < 10; i++) {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
  }
}

void lock_init (struct lock *lock) {
  ASSERT (lock != NULL);
  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
  lock->max_priority = 0;
}

void donate_priority(void) {
    struct thread *cur = thread_current();
    struct lock *lock = cur->lock_waiting;
    int depth = 0;
    
    while (lock != NULL && depth < 8) {
        if (lock->holder == NULL) break;
        struct thread *holder = lock->holder;
        if (holder->priority < cur->priority) {
            holder->priority = cur->priority;
        } else {
            break; 
        }
        lock = holder->lock_waiting;
        cur = holder;
        depth++;
    }
}

void lock_acquire (struct lock *lock) {
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));

  enum intr_level old_level = intr_disable();
  if (lock->holder != NULL) {
      struct thread *cur = thread_current();
      cur->lock_waiting = lock; 
      donate_priority();
  }
  sema_down (&lock->semaphore);
  struct thread *cur = thread_current();
  cur->lock_waiting = NULL; 
  lock->holder = cur;
  list_push_back(&cur->locks, &lock->elem);
  if (lock->max_priority < cur->priority) {
      lock->max_priority = cur->priority;
  }
  intr_set_level(old_level);
}

bool lock_try_acquire (struct lock *lock) {
  bool success;
  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success) {
    lock->holder = thread_current ();
    enum intr_level old_level = intr_disable();
    list_push_back(&thread_current()->locks, &lock->elem);
    intr_set_level(old_level);
  }
  return success;
}

/* [核心函数] 重新计算线程优先级 */
void refresh_priority(struct thread *t) {
    int max_priority = t->base_priority;
    
    struct list_elem *e;
    for (e = list_begin(&t->locks); e != list_end(&t->locks); e = list_next(e)) {
        struct lock *lock = list_entry(e, struct lock, elem);
        if (!list_empty(&lock->semaphore.waiters)) {
            struct thread *waiter = list_entry(list_front(&lock->semaphore.waiters), 
                                               struct thread, elem);
            if (waiter->priority > max_priority) {
                max_priority = waiter->priority;
            }
        }
    }
    t->priority = max_priority;
}

void lock_release (struct lock *lock) {
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  enum intr_level old_level = intr_disable();
  lock->holder = NULL;
  list_remove(&lock->elem);
  refresh_priority(thread_current());
  sema_up (&lock->semaphore);
  intr_set_level(old_level);
}

bool lock_held_by_current_thread (const struct lock *lock) {
  ASSERT (lock != NULL);
  return lock->holder == thread_current ();
}

struct semaphore_elem {
    struct list_elem elem;
    struct semaphore semaphore;
};

bool cond_sema_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
    struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
    struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);
    if (list_empty(&sa->semaphore.waiters) || list_empty(&sb->semaphore.waiters)) return false; 
    struct thread *ta = list_entry(list_front(&sa->semaphore.waiters), struct thread, elem);
    struct thread *tb = list_entry(list_front(&sb->semaphore.waiters), struct thread, elem);
    return ta->priority > tb->priority;
}

void cond_init (struct condition *cond) {
  ASSERT (cond != NULL);
  list_init (&cond->waiters);
}

void cond_wait (struct condition *cond, struct lock *lock) {
  struct semaphore_elem waiter;
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  sema_init (&waiter.semaphore, 0);
  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

void cond_signal (struct condition *cond, struct lock *lock UNUSED) {
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters)) {
      list_sort(&cond->waiters, cond_sema_cmp_priority, NULL);
      sema_up (&list_entry (list_pop_front (&cond->waiters),
                            struct semaphore_elem, elem)->semaphore);
    }
}

void cond_broadcast (struct condition *cond, struct lock *lock) {
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
