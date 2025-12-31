#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

/* === ELF 定义 === */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

#define PE32Wx PRIx32 
#define PE32Ax PRIx32 
#define PE32Ox PRIx32 
#define PE32Hx PRIx16 

struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

#define PT_NULL    0          
#define PT_LOAD    1          
#define PT_DYNAMIC 2          
#define PT_INTERP  3          
#define PT_NOTE    4          
#define PT_SHLIB   5          
#define PT_PHDR    6          
#define PT_STACK   0x6474e551 

#define PF_X 1 
#define PF_W 2 
#define PF_R 4 

/* 辅助结构：传递给 start_process */
struct start_aux {
    char *file_name;
    struct process *pcb;
};

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, struct file **save_file);

/* Forward declarations */
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static bool setup_stack (void **esp);
static bool install_page (void *upage, void *kpage, bool writable);

/* 参数压栈函数 */
/* 核心修复：16字节对齐的参数入栈函数 */
void push_argument_stack(char **argv, int argc, void **esp) {
    char *sp = (char *)(*esp);
    char *arg_addrs[128]; 

    /* 1. 压入参数字符串 */
    for (int i = argc - 1; i >= 0; i--) {
        int len = strlen(argv[i]) + 1;
        sp -= len;
        memcpy(sp, argv[i], len);
        arg_addrs[i] = sp;
    }

    /* 2. 计算对其所需的 Padding */
    int meta_size = (argc + 4) * 4;
    uintptr_t current_sp = (uintptr_t)sp;
    
    /* 关键修改：我们要让 final_sp % 16 == 12 (0xC) */
    /* 所以 target_sp 应该是 (current_sp - meta_size) 往下找最近的一个 结尾为 0xC 的地址 */
    
    /* 先找到最近的 16 字节对齐地址 */
    uintptr_t rounded_sp = (current_sp - meta_size) & ~0xF;
    
    /* 然后减去 4，使其变为 ...C */
    uintptr_t target_sp = rounded_sp - 4;
    
    /* 如果减去 4 后反而比 (current_sp - meta_size) 大了（这在无符号数溢出时才可能，但为了逻辑严密），
       或者我们希望保持紧凑，这通常是安全的。
       但在某些边界情况下，如果 rounded_sp - 4 > current_sp - meta_size，我们需要再减 16。
       不过由于 rounded_sp 是向下取整的，rounded_sp <= current_sp - meta_size。
       所以 rounded_sp - 4 肯定更小，一定是安全的。*/
    
    int padding = current_sp - (target_sp + meta_size);
    
    /* 3. 压入 Padding */
    sp -= padding;
    memset(sp, 0, padding);

    /* 4. 压入 argv[argc] (NULL) */
    sp -= 4;
    *(char **)sp = NULL;

    /* 5. 压入 argv 指针 */
    for (int i = argc - 1; i >= 0; i--) {
        sp -= 4;
        *(char **)sp = arg_addrs[i];
    }

    /* 6. 压入 argv (char **) */
    char *argv_base = sp;
    sp -= 4;
    *(char **)sp = argv_base;

    /* 7. 压入 argc */
    sp -= 4;
    *(int *)sp = argc;

    /* 8. 压入 Fake Return Address */
    sp -= 4;
    *(void **)sp = NULL;

    *esp = sp;
}

/* 初始化主线程 PCB */
void userprog_init (void) {
    struct thread *t = thread_current();
    t->pcb = malloc(sizeof(struct process));
    if (t->pcb != NULL) {
        t->pcb->pid = t->tid;
        t->pcb->main_thread = t;
        t->pcb->parent = NULL;
        t->pcb->exit_status = 0;
        t->pcb->load_success = true;
        t->pcb->next_fd = 2;
        t->pcb->executable = NULL;
        t->pcb->pagedir = NULL; 
        sema_init(&t->pcb->wait_sema, 0);
        sema_init(&t->pcb->load_sema, 0);
        list_init(&t->pcb->children);
        list_init(&t->pcb->file_descriptors);
        strlcpy(t->pcb->process_name, "main", sizeof t->pcb->process_name);
    }
}

pid_t process_execute (const char *file_name) {
  char *fn_copy;
  tid_t tid;

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *cmd_name = palloc_get_page(0);
  if (cmd_name == NULL) {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  strlcpy(cmd_name, file_name, PGSIZE);
  char *save_ptr;
  char *prog_name = strtok_r(cmd_name, " ", &save_ptr);

  struct process *child_pcb = malloc(sizeof(struct process));
  if (child_pcb == NULL) {
      palloc_free_page(fn_copy);
      palloc_free_page(cmd_name);
      return TID_ERROR;
  }

  child_pcb->parent = thread_current()->pcb; 
  child_pcb->exit_status = 0;
  child_pcb->load_success = false;
  child_pcb->executable = NULL;
  child_pcb->next_fd = 2;
  sema_init(&child_pcb->wait_sema, 0);
  sema_init(&child_pcb->load_sema, 0);
  list_init(&child_pcb->children);
  list_init(&child_pcb->file_descriptors);
  strlcpy(child_pcb->process_name, prog_name, sizeof child_pcb->process_name);

  struct start_aux *aux = malloc(sizeof(struct start_aux));
  if (aux == NULL) {
      free(child_pcb);
      palloc_free_page(fn_copy);
      palloc_free_page(cmd_name);
      return TID_ERROR;
  }
  aux->file_name = fn_copy;
  aux->pcb = child_pcb;

  tid = thread_create (prog_name, PRI_DEFAULT, start_process, aux);
  
  palloc_free_page(cmd_name);

  if (tid == TID_ERROR) {
    free(child_pcb);
    free(aux);
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  
  child_pcb->pid = tid;
  if (thread_current()->pcb) {
      list_push_back(&thread_current()->pcb->children, &child_pcb->child_elem);
  }

  /* 等待子进程加载完成 */
  sema_down(&child_pcb->load_sema);
  
  if (!child_pcb->load_success) {
      /* 加载失败，清理资源并返回错误 */
      list_remove(&child_pcb->child_elem);
      free(child_pcb);
      return TID_ERROR;
  }

  return tid;
}

static void start_process (void *aux_) {
  struct start_aux *aux = (struct start_aux *)aux_;
  char *file_name = aux->file_name;
  struct process *pcb = aux->pcb;
  free(aux);

  struct intr_frame if_;
  bool success;
  struct thread *t = thread_current ();

  char *argv[128];
  int argc = 0;
  char *token, *save_ptr;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
      argv[argc++] = token;
  }

  t->pcb = pcb;
  pcb->main_thread = t;
  
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  /* === 修改开始: 接收打开的文件 === */
  struct file *executable_file = NULL;
  success = load (argv[0], &if_.eip, &if_.esp, &executable_file);
  pcb->load_success = success;

  if (success) {
      /* 文件已经在 load 中打开，不需要再次 filesys_open */
      if (executable_file) {
          lock_acquire(&filesys_lock);
          file_deny_write(executable_file); /* 立即禁止写入 */
          lock_release(&filesys_lock);
          pcb->executable = executable_file;
      }
  }
  /* === 修改结束 === */

  sema_up(&pcb->load_sema);

  if (!success) {
      palloc_free_page (file_name);
      thread_exit ();
  }

  /* 参数压栈 */
  push_argument_stack(argv, argc, &if_.esp);
  
  /* [Fix] 必须在压栈完成后才能释放 file_name，因为 argv 指针指向这里 */
  palloc_free_page (file_name); 

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

int process_wait (tid_t child_tid) {
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct process *child_pcb = NULL;

  if (cur->pcb == NULL) return -1;

  for (e = list_begin(&cur->pcb->children); e != list_end(&cur->pcb->children); e = list_next(e)) {
      struct process *p = list_entry(e, struct process, child_elem);
      if (p->pid == child_tid) {
          child_pcb = p;
          break;
      }
  }

  if (child_pcb == NULL) return -1; 

  sema_down(&child_pcb->wait_sema);
  
  int status = child_pcb->exit_status;
  
  list_remove(&child_pcb->child_elem);
  free(child_pcb); 
  
  return status;
}

void process_exit (void) {
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* === 步骤 1：清理文件资源 === */
  if (cur->pcb != NULL) {
      // 1.1 关闭所有打开的文件
      while (!list_empty(&cur->pcb->file_descriptors)) {
          struct list_elem *e = list_pop_front(&cur->pcb->file_descriptors);
          struct file_desc *fd_struct = list_entry(e, struct file_desc, elem);
          lock_acquire(&filesys_lock);
          file_close(fd_struct->file);
          lock_release(&filesys_lock);
          free(fd_struct);
      }
      
      // 1.2 关闭自身可执行文件
      if (cur->pcb->executable) {
          lock_acquire(&filesys_lock);
          file_close(cur->pcb->executable);
          lock_release(&filesys_lock);
      }
  }

  /* === 步骤 2：安全地销毁页表 === */
  pd = NULL;
  if (cur->pcb != NULL) {
      pd = cur->pcb->pagedir;   // 先把页表指针存到局部变量 pd
      cur->pcb->pagedir = NULL; // 将 PCB 里的指针置空，防止后续误用
  }
  
  // 切换回内核页目录（必须在销毁当前页目录前做）
  pagedir_activate (NULL);

  // 真正销毁页目录内存
  if (pd != NULL) {
      pagedir_destroy (pd);
  }

  /* === 步骤 3：最后一步唤醒父进程 === */
  /* ⚠️ 警告：一旦执行 sema_up，父进程可能会立即释放 cur->pcb 的内存。
     所以这行代码之后，绝对不能再访问 cur->pcb 的任何成员！ 
     这就为什么它必须是最后一步。*/
  if (cur->pcb != NULL) {
      cur->pcb->exit_status = cur->pcb->exit_status; // (可选) 确保状态写入内存
      sema_up(&cur->pcb->wait_sema);
  }
}
void process_activate (void) {
  struct thread *t = thread_current ();
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate (t->pcb->pagedir);
  else
    pagedir_activate (NULL);
  tss_update ();
}

static bool load (const char *file_name, void (**eip) (void), void **esp, struct file **save_file) {
    struct thread *t = thread_current ();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    if (t->pcb == NULL) return false;
    t->pcb->pagedir = pagedir_create ();
    if (t->pcb->pagedir == NULL)
      goto done;
    process_activate ();

    lock_acquire(&filesys_lock);
    file = filesys_open (file_name);
    lock_release(&filesys_lock);
    
    if (file == NULL) {
        printf ("load: %s: open failed\n", file_name);
        goto done;
    }

    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
        || ehdr.e_phnum > 1024)
      {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
      }

    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
      {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length (file))
          goto done;
        file_seek (file, file_ofs);

        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
          goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
          {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                  }
                else
                  {
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
          }
      }

    if (!setup_stack (esp))
      goto done;

    *eip = (void (*) (void)) ehdr.e_entry;

    success = true;

   done:
    /* === 关键修改 === */
    if (success) {
        /* 如果成功，且 save_file 不为空，则保存文件指针，不要关闭 */
        if (save_file != NULL) {
            *save_file = file;
        } else {
            /* 如果不需要保存，正常关闭 */
            lock_acquire(&filesys_lock);
            file_close (file);
            lock_release(&filesys_lock);
        }
    } else {
        /* 如果失败，必须关闭 */
        if (file) {
            lock_acquire(&filesys_lock);
            file_close (file);
            lock_release(&filesys_lock);
        }
    }
    return success;
}

static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file) {
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  if (phdr->p_memsz == 0)
    return false;

  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  if (phdr->p_vaddr < PGSIZE)
    return false;

  return true;
}

static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false;
        }

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

static bool setup_stack (void **esp) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current ();
  return (pagedir_get_page (t->pcb->pagedir, upage) == NULL
          && pagedir_set_page (t->pcb->pagedir, upage, kpage, writable));
}

bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }
