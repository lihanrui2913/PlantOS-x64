#include "trap.h"
#include "gate.h"
#include "ptrace.h"

__attribute__((used, section(".data"))) struct gate_struct IDT_Table[256];

// 0 #DE 除法错误
void do_divide_error(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Divide Error(0)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 1 #DB 调试异常
void do_debug(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Debug(1)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 2 不可屏蔽中断
void do_nmi(struct pt_regs *regs, unsigned long error_code)
{
    kerror("NMI(2)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 3 #BP 断点异常
void do_int3(struct pt_regs *regs, unsigned long error_code)
{
    kwarn("Breakpoint(3)");
    kwarn("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 4 #OF 溢出异常
void do_overflow(struct pt_regs *regs, unsigned long error_code)
{
    kwarn("Overflow(4)");
    kwarn("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 5 #BR 越界异常
void do_bounds(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Bounds(5)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 6 #UD 无效/未定义的机器码
void do_undefined_opcode(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Undefined Opcode(6)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 7 #NM 设备异常（FPU不存在）
void do_dev_not_avaliable(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Device Not Avaliable(7)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 8 #DF 双重错误
void do_double_fault(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Double Fault(8)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 9 协处理器越界（保留）
void do_coprocessor_segment_overrun(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Compressor Segment Overrun(9)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 10 #TS 无效的TSS段
void do_invalid_TSS(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Invalid TSS (10)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);

    color_printk(YELLOW, BLACK, "Information:\n");

    if (error_code & 0x01)
        printk("The exception occurred during delivery of an event external to the program.\n");

    if (error_code & 0x02)
        printk("Refers to a descriptor in the IDT.\n");
    else
        if (error_code & 0x04)
            printk("Refers to a descriptor in the current LDT.\n");
        else
            printk("Refers to a descriptor in the GDT.\n");

    printk("Segment Selector Index:%10x\n", error_code & 0xfff8);

    while (1) hlt();
}

// 11 #NP 段不存在
void do_segment_not_exists(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Segment Not Exists(11)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 12 #SS SS段错误
void do_stack_segment_fault(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Stack Segment Fault(12)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 13 #GP 通用保护性异常
void do_general_protection(struct pt_regs *regs, unsigned long error_code)
{
    kerror("General Protection(13)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);

    if (error_code & 0x01)
    {
        kerror("The exception occurred during delivery of an event external to the program.");
        kerror("Such as an interrupt or an earlier exception");
    }

    if (error_code & 0x02)
    {
        kerror("Refers to a gate descriptor in the IDT");
    }
    else
        kerror("Refers to a descriptor in the GDT or the current LDT");

    if ((error_code & 0x02) == 0)
    {
        if (error_code & 0x04)
        {
            kerror("Refers to a segment or gate descriptor in the LDT");
        }
        else
            kerror("Refers to a descriptor in the current GDT");
    }

    kerror("Segment Selector Index:%#010x\n", error_code & 0xfff8);
    while (1) hlt();
}

// 14 #PF 页故障
void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
    unsigned long cr2 = 0;

    __asm__ __volatile__("movq	%%cr2,	%0"
                         : "=r"(cr2)::"memory");

    kerror("Page Fault (14)");
    kerror("Error code: %#018lx, RSP: %#018lx, RIP: %#018lx", error_code, regs->rsp, regs->rip);
    kerror("RBP: %#018lx, CR2: %#018lx", regs->rbp, cr2);

    kerror("%s%s%s%s%s",
        (!(error_code & 0x01)) ? "Page Not-Present | " : "",
        (error_code & 0x02) ? "Write Cause Fault | " : "Read Cause Fault | ",
        (error_code & 0x04) ? "Fault in user (3) | " : "Fault in supervisor (0,1,2) | ",
        (error_code & 0x08) ? "Reserved Bit Cause Fault | " : "",
        (error_code & 0x10) ? "Instruction fetch Cause Fault" : "");

    while (1) hlt();
}

// 15 Intel保留，请勿使用

// 16 #MF x87FPU错误
void do_x87_FPU_error(struct pt_regs *regs, unsigned long error_code)
{
    kerror("x87 FPU Error (16)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 17 #AC 对齐检测
void do_alignment_check(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Alignment Check (17)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 18 #MC 机器检测
void do_machine_check(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Machine Check (18)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 19 #XM SIMD浮点异常
void do_SIMD_exception(struct pt_regs *regs, unsigned long error_code)
{
    kerror("SIMD Exception (19)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 20 #VE 虚拟化异常
void do_virtualization_exception(struct pt_regs *regs, unsigned long error_code)
{
    kerror("Virtualization Exception (20)");
    kerror("Error Code: %#18lx, RSP: %#18lx, RIP: %#18lx", error_code, regs->rsp, regs->rip);
    while (1) hlt();
}

// 21-21 Intel保留，请勿使用

void sys_vector_init()
{
    set_trap_gate(0, 0, divide_error);
    set_trap_gate(1, 0, debug);
    set_intr_gate(2, 0, nmi);
    set_system_trap_gate(3, 0, int3);
    set_system_trap_gate(4, 0, overflow);
    set_system_trap_gate(5, 0, bounds);
    set_trap_gate(6, 0, undefined_opcode);
    set_trap_gate(7, 0, dev_not_avaliable);
    set_trap_gate(8, 0, double_fault);
    set_trap_gate(9, 0, coprocessor_segment_overrun);
    set_trap_gate(10, 0, invalid_TSS);
    set_trap_gate(11, 0, segment_not_exists);
    set_trap_gate(12, 0, stack_segment_fault);
    set_trap_gate(13, 0, general_protection);
    set_trap_gate(14, 0, page_fault);
    // 中断号15由Intel保留，不能使用
    set_trap_gate(16, 0, x87_FPU_error);
    set_trap_gate(17, 0, alignment_check);
    set_trap_gate(18, 0, machine_check);
    set_trap_gate(19, 0, SIMD_exception);
    set_trap_gate(20, 0, virtualization_exception);
    // 中断号21-31由Intel保留，不能使用

    // 32-255为用户自定义中断内部

    init_gdt();
}