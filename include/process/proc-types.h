#pragma once

#include <process/wait_queue.h>
#include <mm/memory.h>
#include <fs/fs.h>

// 进程最大可拥有的文件描述符数量
#define PROC_MAX_FD_NUM 16

// 进程的内核栈大小 64K
#define STACK_SIZE (65536UL)

// 进程的运行状态
// 正在运行
#define PROC_RUNNING (1 << 0)
// 可被中断
#define PROC_INTERRUPTIBLE (1 << 1)
// 不可被中断
#define PROC_UNINTERRUPTIBLE (1 << 2)
// 挂起
#define PROC_ZOMBIE (1 << 3)
// 已停止
#define PROC_STOPPED (1 << 4)

// 内核代码段基地址
#define KERNEL_CS (0x08)
// 内核数据段基地址
#define KERNEL_DS (0x10)
// 用户代码段基地址
#define USER_CS (0x28)
// 用户数据段基地址
#define USER_DS (0x30)

// 进程初始化时的数据拷贝标志位
#define CLONE_FS (1 << 0) // 在进程间共享打开的文件
#define CLONE_SIGNAL (1 << 1)
#define CLONE_VM (1 << 2) // 在进程间共享虚拟内存空间

struct thread_struct
{
	// 内核层栈基指针
	uint64_t rbp; // in tss rsp0
	// 内核层代码指针
	uint64_t rip;
	// 内核层栈指针
	uint64_t rsp;

	uint64_t fs, gs;

	uint64_t cr2;
	// 异常号
	uint64_t trap_num;
	// 错误码
	uint64_t err_code;
};

// ========= pcb->flags =========
// 进程标志位
#define PF_KTHREAD (1UL << 0)	 // 内核线程
#define PF_NEED_SCHED (1UL << 1) // 进程需要被调度
#define PF_VFORK (1UL << 2)		 // 标志进程是否由于vfork而存在资源共享
#define PF_KFORK (1UL << 3)		 // 标志在内核态下调用fork（临时标记，do_fork()结束后会将其复位）

struct mm_struct
{
	pml4t_t *pgd; // 内存页表指针
	// 动态内存分配区（堆区域）
	uint64_t brk_start, brk_end;
	// 应用层栈基地址
	uint64_t stack_start;
};

struct process_control_block
{
	// 进程的状态
	volatile long state;
	// 进程标志：进程、线程、内核线程
	unsigned long flags;
	int64_t preempt_count; // 持有的自旋锁的数量
	long signal;
	long cpu_id; // 当前进程在哪个CPU核心上运行
	// 内存空间分布结构体， 记录内存页表和程序段信息
	struct mm_struct *mm;

	// 进程切换时保存的状态信息
	struct thread_struct *thread;

	// 连接各个pcb的双向链表
	struct List list;

	// 地址空间范围
	// 用户空间： 0x0000 0000 0000 0000 ~ 0x0000 7fff ffff ffff
	// 内核空间： 0xffff 8000 0000 0000 ~ 0xffff ffff ffff ffff
	uint64_t addr_limit;

	long pid;
	long priority;			 // 优先级
	int64_t virtual_runtime; // 虚拟运行时间

	// 进程拥有的文件描述符的指针数组
	// todo: 改用动态指针数组
	struct vfs_file_t *fds[PROC_MAX_FD_NUM];

	// 链表中的下一个pcb
	struct process_control_block *next_pcb;
	// 父进程的pcb
	struct process_control_block *parent_pcb;

	int32_t exit_code;						// 进程退出时的返回码
	wait_queue_node_t wait_child_proc_exit; // 子进程退出等待队列
};

struct tss_struct
{
	unsigned int reserved0;
	uint64_t rsp0;
	uint64_t rsp1;
	uint64_t rsp2;
	uint64_t reserved1;
	uint64_t ist1;
	uint64_t ist2;
	uint64_t ist3;
	uint64_t ist4;
	uint64_t ist5;
	uint64_t ist6;
	uint64_t ist7;
	uint64_t reserved2;
	unsigned short reserved3;
	// io位图基地址
	unsigned short io_map_base_addr;
} __attribute__((packed)); // 使用packed表明是紧凑结构，编译器不会对成员变量进行字节对齐。
