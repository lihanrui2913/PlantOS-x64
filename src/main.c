#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <limine.h>

#include "display/printk.h"
#include "mm/memory.h"
#include "trap.h"
#include "gate.h"

#include "process/process.h"

__attribute__((used, section(".limine_requests"))) static volatile LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end"))) static volatile LIMINE_REQUESTS_END_MARKER;

void kmain(void)
{
    if (LIMINE_BASE_REVISION_SUPPORTED == false)
    {
        for (;;)
            __asm__("hlt");
    }

    __asm__ __volatile__("movq %0, %%rbp" ::"r"((uint64_t)initial_proc_union.stack + STACK_SIZE));
    __asm__ __volatile__("movq %0, %%rsp" ::"r"((uint64_t)initial_proc_union.stack + STACK_SIZE));

    init_printk();

    color_printk(WHITE, BLACK, "Plant OS x64 starting...\n");

    struct idtr p;
    p.idt_vaddr = (uint64_t)IDT_Table;
    p.size = sizeof(IDT_Table) - 1;
    __asm__ __volatile__("lidt %0" ::"m"(p));

    sys_vector_init();
}

#include "driver/acpi.h"
#include "irq.h"
#include "driver/hpet.h"
#include "smp.h"
#include "sched/sched.h"
#include "syscall/syscall.h"
#include "driver/apic_timer.h"
#include "softirq.h"
#include "timer.h"

void kstage2(void)
{
    init_pmm();
    init_vmm();

    set_tss_descriptor(10, &initial_tss[0]);
    uint64_t tss_item_addr = (uint64_t)phy_2_virt(0x7c00);
    set_tss64((uint32_t *)&initial_tss[0], (uint64_t)initial_proc_union.stack + STACK_SIZE, (uint64_t)initial_proc_union.stack + STACK_SIZE, (uint64_t)initial_proc_union.stack + STACK_SIZE, tss_item_addr,
              tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr);

    load_TR(10); // 加载TR寄存器

    uint8_t *ptr = (uint8_t *)kalloc(STACK_SIZE) + STACK_SIZE;
    ((struct process_control_block *)(ptr - STACK_SIZE))->cpu_id = 0;

    initial_tss[0].ist1 = (uint64_t)ptr;
    initial_tss[0].ist2 = (uint64_t)ptr;
    initial_tss[0].ist3 = (uint64_t)ptr;
    initial_tss[0].ist4 = (uint64_t)ptr;
    initial_tss[0].ist5 = (uint64_t)ptr;
    initial_tss[0].ist6 = (uint64_t)ptr;
    initial_tss[0].ist7 = (uint64_t)ptr;

    acpi_init();

    init_softirq();
    init_irq();

    init_timer();

    HPET_init();
    HPET_measure_freq();

    init_smp();

    apic_timer_init();

    current_pcb->cpu_id = 0;
    current_pcb->preempt_count = 0;
    init_syscall();
    init_sched();
    init_process();

    process_init_done = true;

    for (;;)
    {
        sti();
        hlt();
    }
}
