#include "smp.h"
#include "gate.h"
#include "glib.h"
#include "display/kprint.h"
#include "process/process.h"
#include "driver/apic.h"
#include "driver/apic_timer.h"

struct cpu_core_info_t
{
    uint64_t stack_start;     // 栈基地址
    uint64_t ist_stack_start; // IST栈基地址
    uint64_t tss_vaddr;       // tss地址
};

struct cpu_core_info_t cpu_core_info[MAX_CPU_NUM];

__attribute__((used, section(".limine_requests"))) static volatile struct limine_smp_request smp_request =
    {
        .id = LIMINE_SMP_REQUEST,
        .revision = 0,
};

void kap_main(struct limine_smp_info *cpu)
{
    ksuccess("AP successfully started...");

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
            cpu_core_info[smp_request.response->cpus[cpu]->processor_id].stack_start = (uint64_t)kalloc(STACK_SIZE) + STACK_SIZE;
            cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start = (uint64_t)kalloc(STACK_SIZE) + STACK_SIZE;
            cpu_core_info[smp_request.response->cpus[cpu]->processor_id].tss_vaddr = (uint64_t)&initial_tss[smp_request.response->cpus[cpu]->processor_id];

            set_tss_descriptor(10 + smp_request.response->cpus[cpu]->processor_id * 2, (void *)cpu_core_info[smp_request.response->cpus[cpu]->processor_id].tss_vaddr);
            io_mfence();
            set_tss64((uint32_t *)cpu_core_info[smp_request.response->cpus[cpu]->processor_id].tss_vaddr, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].stack_start,
                      cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start, cpu_core_info[smp_request.response->cpus[cpu]->processor_id].ist_stack_start);

            smp_request.response->cpus[cpu]->goto_address = kap_main;
        }
    }
}

void kap_stage2(struct limine_smp_info *cpu)
{
    load_TR(10 + cpu->processor_id * 2);

    uint64_t stack_start;
    __asm__ __volatile__("movq %%rsp, %0" : "=r"(stack_start));

    set_tss64((uint32_t *)&initial_tss[cpu->processor_id], stack_start, stack_start, stack_start, cpu_core_info[cpu->processor_id].stack_start,
              cpu_core_info[cpu->processor_id].ist_stack_start, cpu_core_info[cpu->processor_id].ist_stack_start, cpu_core_info[cpu->processor_id].ist_stack_start, cpu_core_info[cpu->processor_id].ist_stack_start, cpu_core_info[cpu->processor_id].ist_stack_start, cpu_core_info[cpu->processor_id].ist_stack_start);

    apic_init_ap_core_local_apic();

    apic_timer_ap_core_init();

    while (process_init_done == false)
        hlt();

    memset(current_pcb, 0, sizeof(struct process_control_block));

    current_pcb->state = PROC_RUNNING;
    current_pcb->flags = PF_KTHREAD;
    current_pcb->mm = &initial_mm;

    list_init(&current_pcb->list);
    current_pcb->addr_limit = PAGE_OFFSET;
    current_pcb->priority = 2;
    current_pcb->virtual_runtime = 0;

    current_pcb->thread = (struct thread_struct *)(current_pcb + 1); // 将线程结构体放置在pcb后方
    current_pcb->thread->rbp = initial_mm.stack_start;
    current_pcb->thread->rsp = initial_mm.stack_start;
    current_pcb->thread->fs = KERNEL_DS;
    current_pcb->thread->gs = KERNEL_DS;
    current_pcb->cpu_id = cpu->processor_id;

    initial_proc[proc_current_cpu_id] = current_pcb;

    current_pcb->preempt_count = 0;

    for (;;)
    {
        sti();
        hlt();
    }
}
