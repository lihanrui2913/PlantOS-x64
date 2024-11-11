#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <limine.h>

#include "display/printk.h"
#include "mm/memory.h"
#include "trap.h"
#include "gate.h"
#include "smp.h"

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

void kstage2(void)
{
    init_pmm();
    init_vmm();

    acpi_init();

    init_irq();

    init_smp();

    HPET_init();

    for (;;)
    {
        sti();
        hlt();
    }
}
