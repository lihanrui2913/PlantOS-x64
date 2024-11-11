#include "smp.h"
#include "gate.h"
#include "glib.h"
#include "driver/apic.h"

__attribute__((used, section(".limine_requests"))) static volatile struct limine_smp_request smp_request =
    {
        .id = LIMINE_SMP_REQUEST,
        .revision = 0,
};

void kap_main(struct limine_smp_info *cpu)
{
    struct idtr p;
    p.idt_vaddr = (uint64_t)IDT_Table;
    p.size = sizeof(IDT_Table) - 1;
    __asm__ __volatile__("lidt %0" ::"m"(p));

    init_ap_gdt();
}

void init_smp()
{
    for (uint64_t cpu = 0; cpu < smp_request.response->cpu_count; cpu++)
    {
        if (smp_request.response->cpus[cpu]->lapic_id != smp_request.response->bsp_lapic_id)
        {
            smp_request.response->cpus[cpu]->goto_address = kap_main;
        }
    }
}

void kap_stage2(struct limine_smp_info *cpu)
{
    apic_init_ap_core_local_apic();

    for (;;)
    {
        sti();
        hlt();
    }
}
