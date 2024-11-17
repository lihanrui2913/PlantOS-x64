#pragma once

#include <glib.h>
#include <syscall/syscall.h>
#include <spinlock.h>
#include "ptrace.h"
#include <errno.h>
#include <process/wait_queue.h>

#include "proc-types.h"

#define MAX_CPU_NUM 256

#pragma GCC push_options
#pragma GCC optimize("O0")

struct process_control_block;
// 获取当前的pcb
static inline struct process_control_block *get_current_pcb()
{
	struct process_control_block *current = NULL;
	// 利用了当前pcb和栈空间总大小为4k大小对齐，将rsp低12位清空，即可获得pcb的起始地址
	__asm__ __volatile__("andq %%rsp, %0   \n\t"
						 : "=r"(current)
						 : "0"(~(STACK_SIZE - 1)));
	return current;
};
#define current_pcb get_current_pcb()

#pragma GCC pop_options

#define INITIAL_PROC(proc)                \
	{                                     \
		.state = PROC_UNINTERRUPTIBLE,    \
		.flags = PF_KTHREAD,              \
		.preempt_count = 0,               \
		.signal = 0,                      \
		.cpu_id = 0,                      \
		.mm = &initial_mm,                \
		.thread = &initial_thread,        \
		.addr_limit = 0xffffffffffffffff, \
		.pid = 0,                         \
		.priority = 2,                    \
		.virtual_runtime = 0,             \
		.fds = {0},                       \
		.next_pcb = &proc,                \
		.parent_pcb = &proc,              \
		.exit_code = 0,                   \
		.wait_child_proc_exit = 0,        \
	}

// 设置初始进程的tss
#define INITIAL_TSS                                                                   \
	{                                                                                 \
		.reserved0 = 0,                                                               \
		.rsp0 = (uint64_t)(initial_proc_union.stack + STACK_SIZE / sizeof(uint64_t)), \
		.rsp1 = (uint64_t)(initial_proc_union.stack + STACK_SIZE / sizeof(uint64_t)), \
		.rsp2 = (uint64_t)(initial_proc_union.stack + STACK_SIZE / sizeof(uint64_t)), \
		.reserved1 = 0,                                                               \
		.ist1 = 0xffff800000007c00,                                                   \
		.ist2 = 0xffff800000007c00,                                                   \
		.ist3 = 0xffff800000007c00,                                                   \
		.ist4 = 0xffff800000007c00,                                                   \
		.ist5 = 0xffff800000007c00,                                                   \
		.ist6 = 0xffff800000007c00,                                                   \
		.ist7 = 0xffff800000007c00,                                                   \
		.reserved2 = 0,                                                               \
		.reserved3 = 0,                                                               \
		.io_map_base_addr = 0}

#define GET_CURRENT_PCB    \
	"movq %rsp, %rbx \n\t" \
	"andq $-32768, %rbx\n\t"

#define switch_proc(prev, next)                                                                     \
	do                                                                                              \
	{                                                                                               \
		__asm__ __volatile__("pushq	%%rbp	\n\t"                                                     \
							 "pushq	%%rax	\n\t"                                                     \
							 "movq	%%rsp,	%0	\n\t"                                                  \
							 "movq	%2,	%%rsp	\n\t"                                                  \
							 "leaq	switch_proc_ret_addr(%%rip),	%%rax	\n\t"                         \
							 "movq	%%rax,	%1	\n\t"                                                  \
							 "pushq	%3		\n\t"                                                       \
							 "jmp	__switch_to	\n\t"                                                 \
							 "switch_proc_ret_addr:	\n\t"                                           \
							 "popq	%%rax	\n\t"                                                      \
							 "popq	%%rbp	\n\t"                                                      \
							 : "=m"(prev->thread->rsp), "=m"(prev->thread->rip)                     \
							 : "m"(next->thread->rsp), "m"(next->thread->rip), "D"(prev), "S"(next) \
							 : "memory");                                                           \
	} while (0)

extern bool process_init_done;

/**
 * @brief 初始化系统的第一个进程
 *
 */
void init_process();

/**
 * @brief fork当前进程
 *
 * @param regs 新的寄存器值
 * @param clone_flags 克隆标志
 * @param stack_start 堆栈开始地址
 * @param stack_size 堆栈大小
 * @return unsigned long
 */
int do_fork(struct pt_regs *regs, unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size);

/**
 * @brief 根据pid获取进程的pcb
 *
 * @param pid
 * @return struct process_control_block*
 */
struct process_control_block *process_get_pcb(long pid);

/**
 * @brief 将进程加入到调度器的就绪队列中
 *
 * @param pcb 进程的pcb
 */
void process_wakeup(struct process_control_block *pcb);

/**
 * @brief 将进程加入到调度器的就绪队列中，并标志当前进程需要被调度
 *
 * @param pcb 进程的pcb
 */
void process_wakeup_immediately(struct process_control_block *pcb);

/**
 * @brief 使当前进程去执行新的代码
 *
 * @param regs 当前进程的寄存器
 * @param path 可执行程序的路径
 * @param argv 参数列表
 * @param envp 环境变量
 * @return uint64_t 错误码
 */
uint64_t do_execve(struct pt_regs *regs, char *path, char *argv[], char *envp[]);

/**
 * @brief 释放进程的页表
 *
 * @param pcb 要被释放页表的进程
 * @return uint64_t
 */
uint64_t process_exit_mm(struct process_control_block *pcb);

/**
 * @brief 进程退出时执行的函数
 *
 * @param code 返回码
 * @return ul
 */
uint64_t process_do_exit(uint64_t code);

/**
 * @brief 当子进程退出后向父进程发送通知
 *
 */
void process_exit_notify();

/**
 * @brief 初始化内核进程
 *
 * @param fn 目标程序的地址
 * @param arg 向目标程序传入的参数
 * @param flags
 * @return int
 */

int kernel_thread(unsigned long (*fn)(unsigned long), unsigned long arg, unsigned long flags);

/**
 * @brief 切换页表
 * @param prev 前一个进程的pcb
 * @param next 下一个进程的pcb
 *
 */
#define process_switch_mm(next_pcb)                                            \
	do                                                                         \
	{                                                                          \
		__asm__ __volatile__("movq %0, %%cr3	\n\t" ::"r"(next_pcb->mm->pgd) \
							 : "memory");                                      \
	} while (0)

// 获取当前cpu id
#define proc_current_cpu_id (current_pcb->cpu_id)

extern struct tss_struct initial_tss[MAX_CPU_NUM];
extern struct mm_struct initial_mm;
extern struct thread_struct initial_thread;
extern union proc_union initial_proc_union;
extern struct process_control_block *initial_proc[MAX_CPU_NUM];
