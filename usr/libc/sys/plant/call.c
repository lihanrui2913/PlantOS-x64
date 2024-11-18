#include "call.h"

uint64_t syscall_invoke(uint64_t rax, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
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
};
