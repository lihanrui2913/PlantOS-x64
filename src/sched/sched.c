#include "sched/sched.h"
#include <display/kprint.h>
#include <spinlock.h>

struct sched_queue_t sched_cfs_ready_queue[MAX_CPU_NUM]; // 就绪队列

/**
 * @brief 从就绪队列中取出PCB
 *
 * @return struct process_control_block*
 */
struct process_control_block *sched_cfs_dequeue()
{
    if (list_empty(&sched_cfs_ready_queue[proc_current_cpu_id].proc_queue.list))
    {
        return &initial_proc_union.pcb;
    }

    struct process_control_block *proc = container_of(list_next(&sched_cfs_ready_queue[proc_current_cpu_id].proc_queue.list), struct process_control_block, list);

    list_del(&proc->list);
    --sched_cfs_ready_queue[proc_current_cpu_id].count;
    return proc;
}

/**
 * @brief 将PCB加入就绪队列
 *
 * @param pcb
 */
void sched_cfs_enqueue(struct process_control_block *pcb)
{
    if (pcb == initial_proc[proc_current_cpu_id])
        return;
    struct process_control_block *proc = container_of(list_next(&sched_cfs_ready_queue[proc_current_cpu_id].proc_queue.list), struct process_control_block, list);
    if ((list_empty(&sched_cfs_ready_queue[proc_current_cpu_id].proc_queue.list)) == 0)
    {
        while (proc->virtual_runtime < pcb->virtual_runtime)
        {
            proc = container_of(list_next(&proc->list), struct process_control_block, list);
        }
    }
    list_append(&proc->list, &pcb->list);
    ++sched_cfs_ready_queue[proc_current_cpu_id].count;
}

/**
 * @brief 包裹shced_cfs_enqueue(),将PCB加入就绪队列
 *
 * @param pcb
 */
void sched_enqueue(struct process_control_block *pcb)
{
    sched_cfs_enqueue(pcb);
}

/**
 * @brief 调度函数
 *
 */
void sched_cfs()
{
    cli();

    current_pcb->flags &= ~PF_NEED_SCHED;
    struct process_control_block *proc = sched_cfs_dequeue();
    if (current_pcb->virtual_runtime >= proc->virtual_runtime || current_pcb->state != PROC_RUNNING) // 当前进程运行时间大于了下一进程的运行时间，进行切换
    {
        if (current_pcb->state == PROC_RUNNING) // 本次切换由于时间片到期引发，则再次加入就绪队列，否则交由其它功能模块进行管理
            sched_enqueue(current_pcb);

        if (sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies <= 0)
        {
            switch (proc->priority)
            {
            case 0:
            case 1:
                sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies = 4 / sched_cfs_ready_queue[proc_current_cpu_id].count;
                break;
            case 2:
            default:
                sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies = (4 / sched_cfs_ready_queue[proc_current_cpu_id].count) << 2;
                break;
            }
        }

        process_switch_mm(proc);

        switch_proc(current_pcb, proc);
    }
    else // 不进行切换
    {
        sched_cfs_enqueue(proc);

        if (sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies <= 0)
        {
            switch (proc->priority)
            {
            case 0:
            case 1:
                sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies = 4 / sched_cfs_ready_queue[proc_current_cpu_id].count;
                break;
            case 2:
            default:
                sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies = (4 / sched_cfs_ready_queue[proc_current_cpu_id].count) << 2;
                break;
            }
        }
    }

    sti();
}

/**
 * @brief 包裹sched_cfs(),调度函数
 *
 */
void sched()
{
    sched_cfs();
}

/**
 * @brief 当时钟中断到达时，更新时间片
 *
 */
void sched_update_jiffies()
{
    switch (current_pcb->priority)
    {
    case 0:
    case 1:
        --sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies;
        ++current_pcb->virtual_runtime;
        break;
    case 2:
    default:
        sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies -= 2;
        current_pcb->virtual_runtime += 2;
        break;
    }
    // 时间片耗尽，标记可调度
    if (sched_cfs_ready_queue[proc_current_cpu_id].cpu_exec_proc_jiffies <= 0)
        current_pcb->flags |= PF_NEED_SCHED;
}

/**
 * @brief 初始化进程调度器
 *
 */
void init_sched()
{
    memset(&sched_cfs_ready_queue, 0, sizeof(struct sched_queue_t) * MAX_CPU_NUM);
    for (int i = 0; i < MAX_CPU_NUM; ++i)
    {
        list_init(&sched_cfs_ready_queue[i].proc_queue.list);
        sched_cfs_ready_queue[i].count = 1; // 因为存在IDLE进程，因此为1
        sched_cfs_ready_queue[i].cpu_exec_proc_jiffies = 5;
        sched_cfs_ready_queue[i].proc_queue.virtual_runtime = 0x7fffffffffffffff;
    }
}