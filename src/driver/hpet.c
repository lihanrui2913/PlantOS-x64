#include "driver/hpet.h"
#include "driver/apic_timer.h"
#include <display/kprint.h>
#include <mm/memory.h>
#include <driver/apic.h>
#include <process/process.h>
#include <sched/sched.h>

#pragma GCC push_options
#pragma GCC optimize("O0")
static struct acpi_HPET_description_table_t *hpet_table;
static uint64_t HPET_REG_BASE = 0;
static uint32_t HPET_COUNTER_CLK_PERIOD = 0; // 主计数器时间精度（单位：飞秒）
static double HPET_freq = 0;                 // 主计时器频率
static uint8_t HPET_NUM_TIM_CAP = 0;         // 定时器数量
static char measure_apic_timer_flag;         // 初始化apic时钟时所用到的标志变量

enum
{
    GCAP_ID = 0x00,
    GEN_CONF = 0x10,
    GINTR_STA = 0x20,
    MAIN_CNT = 0xf0,
    TIM0_CONF = 0x100,
    TIM0_COMP = 0x108,
    TIM1_CONF = 0x120,
    TIM1_COMP = 0x128,
    TIM2_CONF = 0x140,
    TIM2_COMP = 0x148,
    TIM3_CONF = 0x160,
    TIM3_COMP = 0x168,
    TIM4_CONF = 0x180,
    TIM4_COMP = 0x188,
    TIM5_CONF = 0x1a0,
    TIM5_COMP = 0x1a8,
    TIM6_CONF = 0x1c0,
    TIM6_COMP = 0x1c8,
    TIM7_CONF = 0x1e0,
    TIM7_COMP = 0x1e8,
};

hardware_intr_controller HPET_intr_controller =
    {
        .enable = apic_ioapic_enable,
        .disable = apic_ioapic_disable,
        .install = apic_ioapic_install,
        .uninstall = apic_ioapic_uninstall,
        .ack = apic_ioapic_edge_ack,
};

/**
 * @brief 测定apic定时器以及tsc的频率的中断回调函数
 *
 */
void HPET_measure_handler(uint64_t number, uint64_t param, struct pt_regs *regs)
{
    // 停止apic定时器
    apic_timer_stop();
    apic_timer_ticks_result = 0xFFFFFFFF - apic_timer_get_current();
    measure_apic_timer_flag = true;
}

/**
 * @brief 测定apic定时器以及tsc的频率
 *
 */
void HPET_measure_freq()
{
    kinfo("Measuring local APIC timer's frequency...");
    const uint64_t interval = APIC_TIMER_INTERVAL; // 测量给定时间内的计数
    struct apic_IO_APIC_RTE_entry entry;

    // 使用I/O APIC 的IRQ2接收hpet定时器0的中断
    apic_make_rte_entry(&entry, 34, IO_APIC_FIXED, DEST_PHYSICAL, IDLE, POLARITY_HIGH, IRR_RESET, EDGE_TRIGGER, MASKED, 0);

    // 计算HPET0间隔多少个时钟周期触发一次中断
    uint64_t clks_to_intr = 0.001 * interval * HPET_freq;
    kdebug("clks_to_intr=%#ld", clks_to_intr);
    if (clks_to_intr <= 0 || clks_to_intr > (HPET_freq * 8))
    {
        kBUG("HPET0: Numof clocks to generate interrupt is INVALID! value=%lld", clks_to_intr);
        while (1)
            hlt();
    }
    *(uint64_t *)(HPET_REG_BASE + MAIN_CNT) = 0;
    io_mfence();
    *(uint64_t *)(HPET_REG_BASE + TIM0_CONF) = 0x0044; // 设置定时器0为非周期，边沿触发，默认投递到IO APIC的2号引脚
    io_mfence();
    *(uint64_t *)(HPET_REG_BASE + TIM0_COMP) = clks_to_intr;

    io_mfence();

    measure_apic_timer_flag = false;

    // 注册中断
    irq_register(34, &entry, &HPET_measure_handler, 0, &HPET_intr_controller, "HPET0 measure");

    // 设置div16
    apic_timer_stop();
    apic_timer_set_div(APIC_TIMER_DIVISOR);

    // 设置初始计数
    apic_timer_set_init_cnt(0xFFFFFFFF);

    // 启动apic定时器
    apic_timer_set_LVT(151, 0, APIC_LVT_Timer_One_Shot);
    *(uint64_t *)(HPET_REG_BASE + GEN_CONF) = 3; // 置位旧设备中断路由兼容标志位、定时器组使能标志位，开始计时
    io_mfence();
    sti();
    while (measure_apic_timer_flag == false)
        ;
    cli();
    kdebug("wait done");

    irq_unregister(34);

    *(uint64_t *)(HPET_REG_BASE + GEN_CONF) = 0; // 停用HPET定时器
    io_mfence();
    kinfo("Local APIC timer's freq: %d ticks/ms.", apic_timer_ticks_result);
}

int HPET_init()
{
    kinfo("Initializing HPET...");
    // 从acpi获取hpet结构体
    uint64_t hpet_table_addr = 0;
    acpi_iter_SDT(acpi_get_HPET, &hpet_table_addr);

    hpet_table = (struct acpi_HPET_description_table_t *)hpet_table_addr;
    // kdebug("hpet_table_addr=%#018lx", hpet_table_addr);

    // 由于这段内存与io/apic的映射在同一物理页内，因此不需要重复映射
    HPET_REG_BASE = SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + hpet_table->address;

    // 读取计时精度并计算频率
    uint64_t tmp;
    tmp = *(uint64_t *)(HPET_REG_BASE + GCAP_ID);
    HPET_COUNTER_CLK_PERIOD = (tmp >> 32) & 0xffffffff;
    HPET_freq = 1.0 * 1e15 / HPET_COUNTER_CLK_PERIOD;
    HPET_NUM_TIM_CAP = (tmp >> 8) & 0x1f; // 读取计时器数量
    kinfo("Total HPET timers: %d", HPET_NUM_TIM_CAP);

    kinfo("HPET driver Initialized.");
    // kinfo("HPET CLK_PERIOD=%#03lx Frequency=%f", HPET_COUNTER_CLK_PERIOD, (double)HPET_freq);
    // kdebug("HPET_freq=%ld", (long)HPET_freq);
    // kdebug("HPET_freq=%lf", HPET_freq);
}
#pragma GCC pop_options
