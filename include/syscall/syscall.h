#pragma once

#include "asm.h"
#include "glib.h"
#include "ptrace.h"

void init_syscall();

#define SYSCALL_DEFINER(name) uint64_t SYMBOL_NAME(name)(struct pt_regs * regs)

typedef uint64_t (*syscall_handler_t)(struct pt_regs *regs);

#define MAX_SYSCALL_NUM 1024

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_LSTAT 6
#define SYS_POLL 7
#define SYS_LSEEK 8
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_MUNMAP 11
#define SYS_MBRK 12
#define SYS_IOCTL 16
#define SYS_ACCESS 21
#define SYS_PIPE 21
#define SYS_SCHED_YIELD 24
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_PAUSE 34
#define SYS_FORK 57
#define SYS_VFORK 58
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_KILL 62
#define SYS_UNAME 63
#define SYS_FCNTL 72
#define SYS_GETCWD 79
#define SYS_CHDIR 80

// different of linuxc
#define SYS_PRINT 513

uint64_t enter_syscall_int(uint64_t rax, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
