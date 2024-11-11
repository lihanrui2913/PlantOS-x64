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

extern struct desc_struct GDT_Table[];    // GDT_Table是gdt.S中的GDT_Table
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

#define _set_gate(gate_selector_addr, attr, ist, code_addr)                                            \
    do                                                                                                 \
    {                                                                                                  \
        uint64_t __d0, __d1;                                                                           \
        __asm__ __volatile__("movw	%%dx,	%%ax	\n\t"                                                    \
                             "andq	$0x7,	%%rcx	\n\t"                                                   \
                             "addq	%4,	%%rcx	\n\t"                                                     \
                             "shlq	$32,	%%rcx	\n\t"                                                    \
                             "addq	%%rcx,	%%rax	\n\t"                                                  \
                             "xorq	%%rcx,	%%rcx	\n\t"                                                  \
                             "movl	%%edx,	%%ecx	\n\t"                                                  \
                             "shrq	$16,	%%rcx	\n\t"                                                    \
                             "shlq	$48,	%%rcx	\n\t"                                                    \
                             "addq	%%rcx,	%%rax	\n\t"                                                  \
                             "movq	%%rax,	%0	\n\t"                                                     \
                             "shrq	$32,	%%rdx	\n\t"                                                    \
                             "movq	%%rdx,	%1	\n\t"                                                     \
                             : "=m"(*((uint64_t *)(gate_selector_addr))),                              \
                               "=m"(*(1 + (uint64_t *)(gate_selector_addr))), "=&a"(__d0), "=&d"(__d1) \
                             : "i"(attr << 8),                                                         \
                               "3"((uint64_t *)(code_addr)), "2"(0x8 << 16), "c"(ist)                  \
                             : "memory");                                                              \
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

static inline void set_tss_descriptor(unsigned int n, void *addr)
{
    uint64_t limit = 103;

    *(uint64_t *)(GDT_Table + n) = (limit & 0xffff) | (((uint64_t)addr & 0xffff) << 16) | ((((uint64_t)addr >> 16) & 0xff) << 32) | ((uint64_t)0x89 << 40) | ((limit >> 16 & 0xf) << 48) | (((uint64_t)addr >> 24 & 0xff) << 56); /////89 is attribute
    *(uint64_t *)(GDT_Table + n + 1) = (((uint64_t)addr >> 32) & 0xffffffff) | 0;
}

static inline void set_tss64(unsigned int *Table, uint64_t rsp0, uint64_t rsp1, uint64_t rsp2, uint64_t ist1, uint64_t ist2, uint64_t ist3,
                             uint64_t ist4, uint64_t ist5, uint64_t ist6, uint64_t ist7)
{
    *(uint64_t *)(Table + 1) = rsp0;
    *(uint64_t *)(Table + 3) = rsp1;
    *(uint64_t *)(Table + 5) = rsp2;

    *(uint64_t *)(Table + 9) = ist1;
    *(uint64_t *)(Table + 11) = ist2;
    *(uint64_t *)(Table + 13) = ist3;
    *(uint64_t *)(Table + 15) = ist4;
    *(uint64_t *)(Table + 17) = ist5;
    *(uint64_t *)(Table + 19) = ist6;
    *(uint64_t *)(Table + 21) = ist7;
}

#endif