#include "driver/apic_timer.h"
#include <irq.h>
#include <process/process.h>
#include <display/kprint.h>
#include <sched/sched.h>

uint64_t apic_timer_ticks_result = 0;

void apic_timer_enable(uint64_t irq_num)
{
    // 启动apic定时器
    uint64_t val = apic_timer_get_LVT();
    val &= (~APIC_LVT_INT_MASKED);
    apic_timer_write_LVT(val);
}

void apic_timer_disable(uint64_t irq_num)
{
    apic_timer_stop();
}

/**
 * @brief 安装local apic定时器中断
 *
 * @param irq_num 中断向量号
 * @param arg 初始计数值
 * @return uint64_t
 */
uint64_t apic_timer_install(uint64_t irq_num, void *arg)
{
    // 设置div16
    apic_timer_stop();
    apic_timer_set_div(APIC_TIMER_DIVISOR);

    // 设置初始计数
    apic_timer_set_init_cnt(*(uint64_t *)arg);
    // 填写LVT
    apic_timer_set_LVT(APIC_TIMER_IRQ_NUM, 1, APIC_LVT_Timer_Periodic);
}

void apic_timer_uninstall(uint64_t irq_num)
{
    apic_timer_write_LVT(APIC_LVT_INT_MASKED);
}

hardware_intr_controller apic_timer_intr_controller =
    {
        .enable = apic_timer_enable,
        .disable = apic_timer_disable,
        .install = apic_timer_install,
        .uninstall = apic_timer_uninstall,
        .ack = apic_local_apic_edge_ack,
};

/**
 * @brief local apic定时器的中断处理函数
 *
 * @param number 中断向量号
 * @param param 参数
 * @param regs 寄存器值
 */
void apic_timer_handler(uint64_t number, uint64_t param, struct pt_regs *regs)
{
    sched_update_jiffies();
}

void apic_timer_ap_core_init()
{
    apic_timer_install(APIC_TIMER_IRQ_NUM, &apic_timer_ticks_result);
    apic_timer_enable(APIC_TIMER_IRQ_NUM);
}

/**
 * @brief 初始化local APIC定时器
 *
 */
void apic_timer_init()
{
    kinfo("Initializing apic timer for cpu %d", proc_current_cpu_id);
    irq_register(APIC_TIMER_IRQ_NUM, &apic_timer_ticks_result, &apic_timer_handler, 0, &apic_timer_intr_controller, "apic timer");
    kinfo("Successfully initialized apic timer for cpu %d", proc_current_cpu_id);
}
