#ifndef __GATE_H__
#define __GATE_H__

#include <mm/memory.h>

void init_gdt();
void init_ap_gdt();

// 描述符表的结构体
struct desc_struct
{
    unsigned char x[8];
};

// 门的结构体
struct gate_struct
{
    unsigned char x[16];
};

extern struct gate_struct IDT_Table[256]; // IDT_Table是trap.c中的IDT_Table

struct gdtr
{
    uint16_t size;
    uint64_t gdt_vaddr;
} __attribute__((packed));

struct idtr
{
    uint16_t size;
    uint64_t idt_vaddr;
} __attribute__((packed));

#define _set_gate(gate_selector_addr, attr, ist, code_addr)                                                 \
    do                                                                                                      \
    {                                                                                                       \
        unsigned long __d0, __d1;                                                                           \
        __asm__ __volatile__("movw	%%dx,	%%ax	\n\t"                                                         \
                             "andq	$0x7,	%%rcx	\n\t"                                                        \
                             "addq	%4,	%%rcx	\n\t"                                                          \
                             "shlq	$32,	%%rcx	\n\t"                                                         \
                             "addq	%%rcx,	%%rax	\n\t"                                                       \
                             "xorq	%%rcx,	%%rcx	\n\t"                                                       \
                             "movl	%%edx,	%%ecx	\n\t"                                                       \
                             "shrq	$16,	%%rcx	\n\t"                                                         \
                             "shlq	$48,	%%rcx	\n\t"                                                         \
                             "addq	%%rcx,	%%rax	\n\t"                                                       \
                             "movq	%%rax,	%0	\n\t"                                                          \
                             "shrq	$32,	%%rdx	\n\t"                                                         \
                             "movq	%%rdx,	%1	\n\t"                                                          \
                             : "=m"(*((unsigned long *)(gate_selector_addr))),                              \
                               "=m"(*(1 + (unsigned long *)(gate_selector_addr))), "=&a"(__d0), "=&d"(__d1) \
                             : "i"(attr << 8),                                                              \
                               "3"((unsigned long *)(code_addr)), "2"(0x8 << 16), "c"(ist)                  \
                             : "memory");                                                                   \
    } while (0)

/**
 * @brief 加载任务状态段寄存器
 * @param n TSS基地址在GDT中的第几项
 * 左移3位的原因是GDT每项占8字节
 */
#define load_TR(n)                                        \
    do                                                    \
    {                                                     \
        __asm__ __volatile__("ltr %%ax" ::"a"((n) << 3)); \
    } while (0)

/**
 * @brief 设置中断门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_intr_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate(IDT_Table + n, 0x8E, ist, addr); // p=1，DPL=0, type=E
}

/**
 * @brief 设置64位，DPL=0的陷阱门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_trap_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate(IDT_Table + n, 0x8F, ist, addr); // p=1，DPL=0, type=F
}

/**
 * @brief 设置64位，DPL=3的陷阱门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_system_trap_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate(IDT_Table + n, 0xEF, ist, addr); // p=1，DPL=3, type=F
}

static inline void set_system_intr_gate(unsigned int n, unsigned char ist, void *addr) // int3
{
    _set_gate(IDT_Table + n, 0xEE, ist, addr); // P,DPL=3,TYPE=E
}

#endif