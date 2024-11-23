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

__attribute__((used, section(".limine_requests"))) static volatile struct limine_stack_size_request stack_size_request =
    {
        .id = LIMINE_STACK_SIZE_REQUEST,
        .revision = 3,
        .stack_size = STACK_SIZE,
};

__attribute__((used, section(".limine_requests_start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end"))) static volatile LIMINE_REQUESTS_END_MARKER;

void kmain(void)
{
    if (LIMINE_BASE_REVISION_SUPPORTED == false)
    {
        for (;;)
            __asm__("hlt");
    }

    init_printk();

    struct idtr p;
    p.idt_vaddr = (uint64_t)IDT_Table;
    p.size = sizeof(IDT_Table) - 1;
    __asm__ __volatile__("lidt %0" ::"m"(p));

    sys_vector_init();
}

#include "display/terminal.h"
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
    uint64_t tss_item_addr = (uint64_t)kalloc_aligned(STACK_SIZE, STACK_SIZE) + STACK_SIZE;
    set_tss64((uint32_t *)&initial_tss[0], tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr,
              tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr);

    load_TR(10); // 加载TR寄存器

    init_terminal();

    color_printk(GREEN, BLACK, "Plant OS x64 starting...\n");

    acpi_init();

    init_softirq();
    current_pcb->preempt_count = 0;
    init_irq();

    init_timer();

    HPET_init();
    HPET_measure_freq();

    init_smp();

    init_syscall();
    init_sched();
    current_pcb->cpu_id = 0;
    init_process();

    apic_timer_init();

    process_init_done = true;

    for (;;)
    {
        sti();
        hlt();
    }
}
