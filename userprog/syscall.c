#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame*);
struct lock filesys_lock;

void syscall_init(void) { 
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/* === 辅助函数：统一处理异常退出 === */
static void exit_special(void) {
    struct thread *cur = thread_current();
    if (cur->pcb) {
        cur->pcb->exit_status = -1;
    }
    printf("%s: exit(-1)\n", cur->name);
    process_exit();
    thread_exit();
}

/* === 核心检查 1：检查地址是否有效 (单字节) === */
static void check_ptr(const void *vaddr) {
    if (vaddr == NULL || !is_user_vaddr(vaddr) || 
        pagedir_get_page(thread_current()->pcb->pagedir, vaddr) == NULL) {
        exit_special();
    }
}

/* === 核心检查 2：检查一段内存是否有效 (用于读取 4字节参数) === */
/* 解决 sc-boundary-3 和 exec-bound-2 的关键 */
static void check_valid_buffer(const void *vaddr, unsigned size) {
    const char *ptr = (const char *)vaddr;
    /* 检查首地址 */
    check_ptr(ptr);
    /* 检查尾地址 (防止跨页到非法区域) */
    check_ptr(ptr + size - 1);
}

/* === 核心检查 3：检查字符串 === */
static void check_string(const char *str) {
    check_ptr(str);
    while (*str != '\0') {
        str++;
        check_ptr(str);
    }
}

/* === 核心检查 4：检查大的缓冲区 (用于 read/write) === */
static void check_buffer_safe(const void *buffer, unsigned size) {
    if (size == 0) return;
    const char *ptr = (const char *)buffer;
    /* 检查首尾和每个页边界 */
    for (unsigned i = 0; i < size; i++) {
        check_ptr(ptr + i);
        unsigned remainder = PGSIZE - ((uintptr_t)(ptr + i) % PGSIZE);
        i += remainder - 1; 
        if (i >= size) break;
    }
    check_ptr(ptr + size - 1);
}

static struct file_desc* get_file_desc(int fd) {
    struct thread *cur = thread_current();
    if (cur->pcb == NULL) return NULL;
    struct list_elem *e;
    for (e = list_begin(&cur->pcb->file_descriptors); e != list_end(&cur->pcb->file_descriptors); e = list_next(e)) {
        struct file_desc *fd_struct = list_entry(e, struct file_desc, elem);
        if (fd_struct->id == fd) return fd_struct;
    }
    return NULL;
}

static void syscall_handler(struct intr_frame* f) {
  /* 1. 检查栈指针 ESP 的 4 个字节是否都有效 (读取 syscall number) */
  check_valid_buffer(f->esp, 4);
  
  int *args = (int *)f->esp;
  int sys_code = args[0];

  /* 宏定义：安全获取参数 */
  /* 检查参数 args[i] 在栈上的存储位置是否合法 (4字节检查) */
  #define CHECK_ARG(i) check_valid_buffer(args + i, 4)
  #define ARG(i) (*(args + i))

  switch (sys_code) {
      case SYS_HALT:
          shutdown_power_off();
          break;

      case SYS_EXIT:
          CHECK_ARG(1);
          int status = ARG(1);
          struct thread *cur = thread_current();
          if (cur->pcb) cur->pcb->exit_status = status;
          printf("%s: exit(%d)\n", cur->name, status);
          process_exit();
          thread_exit();
          break;

      case SYS_EXEC:
          CHECK_ARG(1);
          check_string((const char *)ARG(1)); 
          f->eax = process_execute((const char *)ARG(1));
          break;

      case SYS_WAIT:
          CHECK_ARG(1);
          f->eax = process_wait((pid_t)ARG(1));
          break;

      case SYS_CREATE:
          CHECK_ARG(1); CHECK_ARG(2);
          check_string((const char *)ARG(1));
          lock_acquire(&filesys_lock);
          f->eax = filesys_create((const char *)ARG(1), (unsigned)ARG(2));
          lock_release(&filesys_lock);
          break;

      case SYS_REMOVE:
          CHECK_ARG(1);
          check_string((const char *)ARG(1));
          lock_acquire(&filesys_lock);
          f->eax = filesys_remove((const char *)ARG(1));
          lock_release(&filesys_lock);
          break;

      case SYS_OPEN:
          CHECK_ARG(1);
          check_string((const char *)ARG(1));
          lock_acquire(&filesys_lock);
          struct file *file = filesys_open((const char *)ARG(1));
          if (file == NULL) {
              f->eax = -1;
          } else {
              struct file_desc *fd_struct = malloc(sizeof(struct file_desc));
              if (fd_struct == NULL) {
                  file_close(file);
                  f->eax = -1;
              } else {
                  struct thread *curr = thread_current();
                  fd_struct->file = file;
                  fd_struct->id = curr->pcb->next_fd++;
                  list_push_back(&curr->pcb->file_descriptors, &fd_struct->elem);
                  f->eax = fd_struct->id;
              }
          }
          lock_release(&filesys_lock);
          break;

      case SYS_FILESIZE:
          CHECK_ARG(1);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_s = get_file_desc(ARG(1));
          f->eax = fd_s ? file_length(fd_s->file) : -1;
          lock_release(&filesys_lock);
          break;

      case SYS_READ:
          CHECK_ARG(1); CHECK_ARG(2); CHECK_ARG(3);
          check_buffer_safe((const void *)ARG(2), (unsigned)ARG(3));
          
          int fd_r = ARG(1);
          void *buffer_r = (void *)ARG(2);
          unsigned size_r = ARG(3);
          
          if (fd_r == 0) { // STDIN
              uint8_t *buf = buffer_r;
              for (unsigned i = 0; i < size_r; i++) buf[i] = input_getc();
              f->eax = size_r;
          } else {
              lock_acquire(&filesys_lock);
              struct file_desc *fd_struct = get_file_desc(fd_r);
              f->eax = fd_struct ? file_read(fd_struct->file, buffer_r, size_r) : -1;
              lock_release(&filesys_lock);
          }
          break;

      case SYS_WRITE:
          CHECK_ARG(1); CHECK_ARG(2); CHECK_ARG(3);
          check_buffer_safe((const void *)ARG(2), (unsigned)ARG(3));
          
          int fd_w = ARG(1);
          const void *buf_w = (const void *)ARG(2);
          unsigned size_w = ARG(3);
          
          if (fd_w == 1) { // STDOUT
              putbuf(buf_w, size_w);
              f->eax = size_w;
          } else {
              lock_acquire(&filesys_lock);
              struct file_desc *fd_struct = get_file_desc(fd_w);
              f->eax = fd_struct ? file_write(fd_struct->file, buf_w, size_w) : -1;
              lock_release(&filesys_lock);
          }
          break;

      case SYS_SEEK:
          CHECK_ARG(1); CHECK_ARG(2);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_seek = get_file_desc(ARG(1));
          if (fd_seek) file_seek(fd_seek->file, ARG(2));
          lock_release(&filesys_lock);
          break;

      case SYS_TELL:
          CHECK_ARG(1);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_tell = get_file_desc(ARG(1));
          f->eax = fd_tell ? file_tell(fd_tell->file) : -1;
          lock_release(&filesys_lock);
          break;

      case SYS_CLOSE:
          CHECK_ARG(1);
          lock_acquire(&filesys_lock);
          struct thread *cur_t = thread_current();
          int close_id = ARG(1);
          struct list_elem *el;
          for (el = list_begin(&cur_t->pcb->file_descriptors); el != list_end(&cur_t->pcb->file_descriptors); el = list_next(el)) {
              struct file_desc *fd_struct = list_entry(el, struct file_desc, elem);
              if (fd_struct->id == close_id) {
                  file_close(fd_struct->file);
                  list_remove(el);
                  free(fd_struct);
                  break;
              }
          }
          lock_release(&filesys_lock);
          break;
      
      /* 修复 practice 测试 */
      case SYS_PRACTICE: 
          CHECK_ARG(1);
          f->eax = ARG(1) + 1;
          break;

      default:
          exit_special();
  }
}
