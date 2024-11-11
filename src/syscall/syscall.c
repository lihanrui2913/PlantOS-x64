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

    set_system_trap_gate(0x80, 0, syscall_int);
}
