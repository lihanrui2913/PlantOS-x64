#include "smp.h"
#include "gate.h"
#include "glib.h"
#include "display/kprint.h"
#include "process/process.h"
#include "driver/apic.h"
#include "driver/apic_timer.h"

struct cpu_core_info_t
{
    uint64_t tss_vaddr; // tss地址
};

struct cpu_core_info_t cpu_core_info[MAX_CPU_NUM];

__attribute__((used, section(".limine_requests"))) static volatile struct limine_smp_request smp_request =
    {
        .id = LIMINE_SMP_REQUEST,
        .revision = 0,
};

void kap_main(struct limine_smp_info *cpu)
{
    ksuccess("AP %d starting", cpu->processor_id);

    struct idtr p;
    p.idt_vaddr = (uint64_t)IDT_Table;
    p.size = sizeof(IDT_Table) - 1;
    __asm__ __volatile__("lidt %0" ::"m"(p));

    init_ap_gdt(cpu);
}

void init_smp()
{
    for (uint64_t cpu = 0; cpu < smp_request.response->cpu_count; cpu++)
    {
        if (smp_request.response->cpus[cpu]->lapic_id != smp_request.response->bsp_lapic_id)
        {
            memset(&initial_tss[smp_request.response->cpus[cpu]->processor_id], 0, sizeof(struct tss_struct));
            cpu_core_info[smp_request.response->cpus[cpu]->processor_id].tss_vaddr = (uint64_t)&initial_tss[smp_request.response->cpus[cpu]->processor_id];

            set_tss_descriptor(10 + smp_request.response->cpus[cpu]->processor_id * 2, (void *)cpu_core_info[smp_request.response->cpus[cpu]->processor_id].tss_vaddr);
            io_mfence();
            smp_request.response->cpus[cpu]->goto_address = kap_main;
        }
    }
}

void kap_stage2(struct limine_smp_info *cpu)
{
    uint64_t tss_item_addr = (uint64_t)phy_2_virt(0x7c00);
    set_tss64((uint32_t *)cpu_core_info[cpu->processor_id].tss_vaddr, (uint64_t)current_pcb, (uint64_t)current_pcb, (uint64_t)current_pcb, tss_item_addr,
              tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr, tss_item_addr);

    load_TR(10 + cpu->processor_id * 2);

    apic_init_ap_core_local_apic();

    while (process_init_done == false)
        pause();

    memcpy(&initial_process, current_pcb, sizeof(struct process_control_block));
    current_pcb->cpu_id = cpu->processor_id;
    current_pcb->preempt_count = 0;
    initial_proc[proc_current_cpu_id] = current_pcb;

    apic_timer_ap_core_init();

    for (;;)
    {
        sti();
        hlt();
    }
}
