#include "irq.h"
#include <driver/apic.h>
#include <asm.h>
#include <display/kprint.h>
#include "gate.h"
#include <mm/memory.h>

// 这几个表一定要放在这里，否则在HPET初始化后收到中断，会产生page fault
irq_desc_t interrupt_desc[IRQ_NUM] = {0};
irq_desc_t local_apic_interrupt_desc[LOCAL_APIC_IRQ_NUM] = {0};
irq_desc_t SMP_IPI_desc[SMP_IRQ_NUM] = {0};

#define SAVE_ALL             \
    "cld;			\n\t"            \
    "pushq	%rax;		\n\t"      \
    "pushq	%rax;		\n\t"      \
    "movq	%es,	%rax;	\n\t"   \
    "pushq	%rax;		\n\t"      \
    "movq	%ds,	%rax;	\n\t"   \
    "pushq	%rax;		\n\t"      \
    "xorq	%rax,	%rax;	\n\t"  \
    "pushq	%rbp;		\n\t"      \
    "pushq	%rdi;		\n\t"      \
    "pushq	%rsi;		\n\t"      \
    "pushq	%rdx;		\n\t"      \
    "pushq	%rcx;		\n\t"      \
    "pushq	%rbx;		\n\t"      \
    "pushq	%r8;		\n\t"       \
    "pushq	%r9;		\n\t"       \
    "pushq	%r10;		\n\t"      \
    "pushq	%r11;		\n\t"      \
    "pushq	%r12;		\n\t"      \
    "pushq	%r13;		\n\t"      \
    "pushq	%r14;		\n\t"      \
    "pushq	%r15;		\n\t"      \
    "movq	$0x10,	%rdx;	\n\t" \
    "movq	%rdx,	%ds;	\n\t"   \
    "movq	%rdx,	%es;	\n\t"

#define IRQ_NAME2(nr) nr##interrupt(void)
#define IRQ_NAME(nr) IRQ_NAME2(IRQ##nr)

#define Build_IRQ(nr)                                                                                  \
    void IRQ_NAME(nr);                                                                                 \
    __asm__(".section .text\n\t" SYMBOL_NAME_STR(IRQ) #nr "interrupt:		\n\t"                           \
                                                          "pushq	$0x00				\n\t" SAVE_ALL \
                                                          "movq	%rsp,	%rdi			\n\t"                     \
                                                          "leaq	ret_from_intr(%rip),	%rax	\n\t"        \
                                                          "pushq	%rax				\n\t"                         \
                                                          "movq	$" #nr ",	%rsi			\n\t"                 \
                                                          "jmp	do_IRQ	\n\t");

// 构造中断入口
Build_IRQ(0x20);
Build_IRQ(0x21);
Build_IRQ(0x22);
Build_IRQ(0x23);
Build_IRQ(0x24);
Build_IRQ(0x25);
Build_IRQ(0x26);
Build_IRQ(0x27);
Build_IRQ(0x28);
Build_IRQ(0x29);
Build_IRQ(0x2a);
Build_IRQ(0x2b);
Build_IRQ(0x2c);
Build_IRQ(0x2d);
Build_IRQ(0x2e);
Build_IRQ(0x2f);
Build_IRQ(0x30);
Build_IRQ(0x31);
Build_IRQ(0x32);
Build_IRQ(0x33);
Build_IRQ(0x34);
Build_IRQ(0x35);
Build_IRQ(0x36);
Build_IRQ(0x37);

// 初始化中断数组
void (*interrupt_table[24])(void) =
    {
        IRQ0x20interrupt,
        IRQ0x21interrupt,
        IRQ0x22interrupt,
        IRQ0x23interrupt,
        IRQ0x24interrupt,
        IRQ0x25interrupt,
        IRQ0x26interrupt,
        IRQ0x27interrupt,
        IRQ0x28interrupt,
        IRQ0x29interrupt,
        IRQ0x2ainterrupt,
        IRQ0x2binterrupt,
        IRQ0x2cinterrupt,
        IRQ0x2dinterrupt,
        IRQ0x2einterrupt,
        IRQ0x2finterrupt,
        IRQ0x30interrupt,
        IRQ0x31interrupt,
        IRQ0x32interrupt,
        IRQ0x33interrupt,
        IRQ0x34interrupt,
        IRQ0x35interrupt,
        IRQ0x36interrupt,
        IRQ0x37interrupt,
};

/**
 * @brief 声明10个IPI消息处理程序，向量号从200(0xc8)开始
 *
 */

/*
 */
Build_IRQ(0xc8);
Build_IRQ(0xc9);
Build_IRQ(0xca);
Build_IRQ(0xcb);
Build_IRQ(0xcc);
Build_IRQ(0xcd);
Build_IRQ(0xce);
Build_IRQ(0xcf);
Build_IRQ(0xd0);
Build_IRQ(0xd1);

// 初始化IPI中断服务程序数组
void (*SMP_interrupt_table[SMP_IRQ_NUM])(void) =
    {
        IRQ0xc8interrupt,
        IRQ0xc9interrupt,
        IRQ0xcainterrupt,
        IRQ0xcbinterrupt,
        IRQ0xccinterrupt,
        IRQ0xcdinterrupt,
        IRQ0xceinterrupt,
        IRQ0xcfinterrupt,
        IRQ0xd0interrupt,
        IRQ0xd1interrupt,
};

// 初始化local apic中断服务程序数组
Build_IRQ(0x96);
Build_IRQ(0x97);
Build_IRQ(0x98);
Build_IRQ(0x99);
Build_IRQ(0x9a);
Build_IRQ(0x9b);
Build_IRQ(0x9c);
Build_IRQ(0x9d);
Build_IRQ(0x9e);
Build_IRQ(0x9f);

void (*local_apic_interrupt_table[LOCAL_APIC_IRQ_NUM])(void) =
    {
        IRQ0x96interrupt,
        IRQ0x97interrupt,
        IRQ0x98interrupt,
        IRQ0x99interrupt,
        IRQ0x9ainterrupt,
        IRQ0x9binterrupt,
        IRQ0x9cinterrupt,
        IRQ0x9dinterrupt,
        IRQ0x9einterrupt,
        IRQ0x9finterrupt,
};

/**
 * @brief 中断注册函数
 *
 * @param irq_num 中断向量号
 * @param arg 传递给中断安装接口的参数
 * @param handler 中断处理函数
 * @param paramater 中断处理函数的参数
 * @param controller 中断控制器结构
 * @param irq_name 中断名
 * @return int
 */
int irq_register(uint64_t irq_num, void *arg, void (*handler)(uint64_t irq_num, uint64_t parameter, struct pt_regs *regs), uint64_t paramater, hardware_intr_controller *controller, char *irq_name)
{
    // 由于为I/O APIC分配的中断向量号是从32开始的，因此要减去32才是对应的interrupt_desc的元素
    irq_desc_t *p = NULL;
    if (irq_num >= 32 && irq_num < 0x80)
        p = &interrupt_desc[irq_num - 32];
    else if (irq_num >= 150 && irq_num < 200)
        p = &local_apic_interrupt_desc[irq_num - 150];
    else
    {
        kerror("irq_register(): invalid irq num: %ld.", irq_num);
        return -1;
    }
    p->controller = controller;
    if (p->irq_name == NULL)
    {
        int namelen = strlen(irq_name) + 1;
        p->irq_name = (char *)kalloc(namelen);
        memset(p->irq_name, 0, namelen);
        strncpy(p->irq_name, irq_name, namelen);
    }

    p->parameter = paramater;
    p->flags = 0;
    p->handler = handler;

    p->controller->install(irq_num, arg);
    p->controller->enable(irq_num);

    return 0;
}

/**
 * @brief 中断注销函数
 *
 * @param irq_num 中断向量号
 * @return int
 */
int irq_unregister(uint64_t irq_num)
{
    irq_desc_t *p = &interrupt_desc[irq_num - 32];
    p->controller->disable(irq_num);
    p->controller->uninstall(irq_num);

    p->controller = NULL;
    if (p->irq_name)
        kfree(p->irq_name);
    p->irq_name = NULL;
    p->parameter = 0;
    p->flags = 0;
    p->handler = NULL;

    return 0;
}

void ipi_send_IPI(uint32_t dest_mode, uint32_t deliver_status, uint32_t level, uint32_t trigger,
                  uint32_t vector, uint32_t deliver_mode, uint32_t dest_shorthand, bool apic_type, uint32_t destination)
{
    struct INT_CMD_REG icr_entry;
    icr_entry.dest_mode = dest_mode;
    icr_entry.deliver_status = deliver_status;
    icr_entry.res_1 = 0;
    icr_entry.level = level;
    icr_entry.trigger = trigger;
    icr_entry.res_2 = 0;
    icr_entry.res_3 = 0;

    icr_entry.vector = vector;
    icr_entry.deliver_mode = deliver_mode;
    icr_entry.dest_shorthand = dest_shorthand;

    icr_entry.destination.x2apic_destination = destination;
    wrmsr(0x830, *(unsigned long *)&icr_entry); // 发送ipi
}

int ipi_regiserIPI(uint64_t irq_num, void *arg,
                   void (*handler)(uint64_t irq_num, uint64_t param, struct pt_regs *regs),
                   uint64_t param, hardware_intr_controller *controller, char *irq_name)
{
    irq_desc_t *p = &SMP_IPI_desc[irq_num - 200];
    p->controller = NULL;
    p->irq_name = irq_name;
    p->parameter = param;
    p->flags = 0;
    p->handler = handler;
    return 0;
}

/**
 * @brief 初始化中断模块
 */
void init_irq()
{
    memset((void *)interrupt_desc, 0, sizeof(irq_desc_t) * IRQ_NUM);
    memset((void *)local_apic_interrupt_desc, 0, sizeof(irq_desc_t) * LOCAL_APIC_IRQ_NUM);

    apic_init();
}
