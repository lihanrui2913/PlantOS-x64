#include "syscall/syscall.h"
#include "gate.h"

syscall_handler_t system_call_table[MAX_SYSCALL_NUM];

extern void syscall_int();

void do_syscall_int(struct pt_regs *regs, unsigned long error_code)
{
    uint64_t ret = system_call_table[regs->rax](regs);
    regs->rax = ret;
}

SYSCALL_DEFINER(sys_read)
{
}

SYSCALL_DEFINER(sys_write)
{
}

SYSCALL_DEFINER(sys_open)
{
}

SYSCALL_DEFINER(sys_close)
{
}

SYSCALL_DEFINER(sys_stat)
{
}

SYSCALL_DEFINER(sys_fstat)
{
}

SYSCALL_DEFINER(sys_lstat)
{
}

SYSCALL_DEFINER(sys_lseek)
{
}

SYSCALL_DEFINER(sys_mmap)
{
}

SYSCALL_DEFINER(sys_munmap)
{
}

SYSCALL_DEFINER(sys_fork)
{
}

SYSCALL_DEFINER(sys_vfork)
{
}

#include "display/printk.h"

SYSCALL_DEFINER(sys_print)
{
    color_printk(WHITE, BLACK, (const char *)regs->rdi);
}

void init_syscall()
{
    system_call_table[SYS_READ] = sys_read;
    system_call_table[SYS_WRITE] = sys_write;
    system_call_table[SYS_OPEN] = sys_open;
    system_call_table[SYS_CLOSE] = sys_close;
    system_call_table[SYS_STAT] = sys_stat;
    system_call_table[SYS_FSTAT] = sys_fstat;
    system_call_table[SYS_LSTAT] = sys_lstat;
    system_call_table[SYS_LSEEK] = sys_lseek;
    system_call_table[SYS_MMAP] = sys_mmap;
    system_call_table[SYS_MUNMAP] = sys_munmap;
    system_call_table[SYS_FORK] = sys_fork;
    system_call_table[SYS_VFORK] = sys_vfork;
    system_call_table[SYS_PRINT] = sys_print;

    set_system_trap_gate(0x80, 0, syscall_int);
}

uint64_t enter_syscall_int(uint64_t rax, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    uint64_t ret;
    __asm__ __volatile__(
        "movq %%rdi, %%rax\n\t"
        "movq %%rsi, %%rdi\n\t"
        "movq %%rdx, %%rsi\n\t"
        "movq %%r10, %%rdx\n\t"
        "movq %%r8, %%r10\n\t"
        "movq %%r9, %%r8\n\t"
        "movq %1, %%r9\n\t"
        "int $0x80\n\t" : "=a"(ret) : "r"(arg6));
    return ret;
}
