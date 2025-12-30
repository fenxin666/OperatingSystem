#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

/* 文件描述符结构体 */
struct file_desc {
    int id;
    struct file *file;
    struct list_elem elem;
};

/* 进程控制块 (PCB) */
struct process {
    pid_t pid;                          /* 进程 ID */
    int exit_status;                    /* 退出状态码 */
    struct thread *main_thread;         /* 指向主线程 */
    
    struct process *parent;             /* 父进程 */
    struct list children;               /* 子进程列表 */
    struct list_elem child_elem;        /* 用于父进程的 children 列表 */
    
    struct semaphore wait_sema;         /* 父进程等待子进程退出的信号量 */
    struct semaphore load_sema;         /* 父进程等待子进程加载的信号量 */
    bool load_success;                  /* 加载是否成功 */
    
    struct list file_descriptors;       /* 打开的文件描述符列表 */
    int next_fd;                        /* 下一个可用的 fd */
    struct file *executable;            /* 当前运行的可执行文件 (用于禁止写入) */
    
    /* 这里的 process_name 和 pagedir 在原版 process.c 中由 malloc 管理 */
    char process_name[16];
    uint32_t *pagedir;
};

/* 辅助函数声明 */
void userprog_init(void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* 参数压栈函数 */
void push_argument_stack(char **argv, int argc, void **esp);

/* 辅助判断函数 */
bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

#endif /* userprog/process.h */
