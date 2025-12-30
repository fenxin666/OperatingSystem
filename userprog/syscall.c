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

/* 检查地址是否合法 */
static void check_addr(const void *vaddr) {
    if (vaddr == NULL || !is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pcb->pagedir, vaddr) == NULL) {
        if (thread_current()->pcb) {
            thread_current()->pcb->exit_status = -1;
        }
        printf("%s: exit(-1)\n", thread_current()->name); 
        process_exit();
        thread_exit(); /* 确保线程终止 */
    }
}

/* 从文件描述符获取文件结构 */
static struct file_desc* get_file_desc(int fd) {
    struct thread *cur = thread_current();
    if (cur->pcb == NULL) return NULL;
    
    struct list_elem *e;
    for (e = list_begin(&cur->pcb->file_descriptors); e != list_end(&cur->pcb->file_descriptors); e = list_next(e)) {
        struct file_desc *fd_struct = list_entry(e, struct file_desc, elem);
        if (fd_struct->id == fd) {
            return fd_struct;
        }
    }
    return NULL;
}

static void syscall_handler(struct intr_frame* f) {
  check_addr(f->esp); // 检查栈指针
  
  int *args = (int *)f->esp;
  int sys_code = args[0];

  switch (sys_code) {
      case SYS_HALT:
          shutdown_power_off();
          break;

      case SYS_EXIT:
          check_addr(&args[1]);
          int status = args[1];
          struct thread *cur = thread_current();
          if (cur->pcb) cur->pcb->exit_status = status;
          printf("%s: exit(%d)\n", cur->name, status);
          process_exit();
          thread_exit();
          break;

      case SYS_EXEC:
          check_addr(&args[1]);
          const char *cmd_line = (const char *)args[1];
          check_addr(cmd_line);
          
          /* process_execute 现在已经处理了加载等待逻辑，直接返回结果即可 */
          f->eax = process_execute(cmd_line);
          break;

      case SYS_WAIT:
          check_addr(&args[1]);
          f->eax = process_wait((pid_t)args[1]);
          break;

      case SYS_CREATE:
          check_addr(&args[1]);
          check_addr(&args[2]);
          check_addr((const void *)args[1]); 
          lock_acquire(&filesys_lock);
          f->eax = filesys_create((const char *)args[1], (unsigned)args[2]);
          lock_release(&filesys_lock);
          break;

      case SYS_REMOVE:
          check_addr(&args[1]);
          check_addr((const void *)args[1]);
          lock_acquire(&filesys_lock);
          f->eax = filesys_remove((const char *)args[1]);
          lock_release(&filesys_lock);
          break;

      case SYS_OPEN:
          check_addr(&args[1]);
          check_addr((const void *)args[1]);
          lock_acquire(&filesys_lock);
          struct file *file = filesys_open((const char *)args[1]);
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
          check_addr(&args[1]);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_s = get_file_desc(args[1]);
          if (fd_s) {
              f->eax = file_length(fd_s->file);
          } else {
              f->eax = -1;
          }
          lock_release(&filesys_lock);
          break;

      case SYS_READ:
          check_addr(&args[1]);
          check_addr(&args[2]);
          check_addr(&args[3]);
          check_addr((const void *)args[2]); 
          int fd_r = args[1];
          void *buffer_r = (void *)args[2];
          unsigned size_r = args[3];
          
          if (fd_r == 0) { // STDIN
              uint8_t *buf = buffer_r;
              for (unsigned i = 0; i < size_r; i++) {
                  buf[i] = input_getc();
              }
              f->eax = size_r;
          } else {
              lock_acquire(&filesys_lock);
              struct file_desc *fd_struct = get_file_desc(fd_r);
              if (fd_struct) {
                  f->eax = file_read(fd_struct->file, buffer_r, size_r);
              } else {
                  f->eax = -1;
              }
              lock_release(&filesys_lock);
          }
          break;

      case SYS_WRITE:
          check_addr(&args[1]);
          check_addr(&args[2]);
          check_addr(&args[3]);
          check_addr((const void *)args[2]);
          int fd_w = args[1];
          const void *buf_w = (const void *)args[2];
          unsigned size_w = args[3];
          
          if (fd_w == 1) { // STDOUT
              putbuf(buf_w, size_w);
              f->eax = size_w;
          } else {
              lock_acquire(&filesys_lock);
              struct file_desc *fd_struct = get_file_desc(fd_w);
              if (fd_struct) {
                  f->eax = file_write(fd_struct->file, buf_w, size_w);
              } else {
                  f->eax = -1;
              }
              lock_release(&filesys_lock);
          }
          break;

      case SYS_SEEK:
          check_addr(&args[1]);
          check_addr(&args[2]);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_seek = get_file_desc(args[1]);
          if (fd_seek) {
              file_seek(fd_seek->file, args[2]);
          }
          lock_release(&filesys_lock);
          break;

      case SYS_TELL:
          check_addr(&args[1]);
          lock_acquire(&filesys_lock);
          struct file_desc *fd_tell = get_file_desc(args[1]);
          if (fd_tell) {
              f->eax = file_tell(fd_tell->file);
          } else {
              f->eax = -1;
          }
          lock_release(&filesys_lock);
          break;

      case SYS_CLOSE:
          check_addr(&args[1]);
          lock_acquire(&filesys_lock);
          struct thread *cur_t = thread_current();
          int close_id = args[1];
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

      default:
          printf("Unknown system call: %d\n", sys_code);
          thread_exit();
  }
}
