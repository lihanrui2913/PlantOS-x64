#include "driver/hpet.h"
#include <display/kprint.h>
#include <mm/memory.h>
#include <driver/apic.h>

#include <sched/sched.h>

static struct acpi_HPET_description_table_t *hpet_table;
static uint64_t HPET_REG_BASE = 0;
static char measure_apic_timer_flag; // 初始化apic时钟时所用到的标志变量

static volatile uint64_t timer_jiffies = 0;

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

void HPET_handler(uint64_t number, uint64_t param, struct pt_regs *regs)
{
    switch (param)
    {
    case 0:
        io_mfence();
        sched_update_jiffies();
        io_mfence();
        break;
    default:
        kwarn("Unsupported HPET irq: %d.", number);
        break;
    }
}

int HPET_init()
{
    kinfo("Initializing HPET...");
    uint64_t hpet_table_addr = 0;
    acpi_iter_SDT(acpi_get_HPET, &hpet_table_addr);

    hpet_table = (struct acpi_HPET_description_table_t *)hpet_table_addr;
    HPET_REG_BASE = SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + hpet_table->address;
    kdebug("HPET_REG_BASE=%#018lx", HPET_REG_BASE);

    struct apic_IO_APIC_RTE_entry entry;
    // 使用I/O APIC 的IRQ2接收hpet定时器0的中断
    apic_make_rte_entry(&entry, 34, IO_APIC_FIXED, DEST_PHYSICAL, IDLE, POLARITY_HIGH, IRR_RESET, EDGE_TRIGGER, MASKED, 0);

    // kdebug("[HPET0] conf register=%#018lx  conf register[63:32]=%#06lx", (*(uint64_t *)(HPET_REG_BASE + TIM0_CONF)), ((*(uint64_t *)(HPET_REG_BASE + TIM0_CONF)) >> 32) & 0xffffffff);
    *(uint64_t *)(HPET_REG_BASE + MAIN_CNT) = 0;
    io_mfence();
    *(uint64_t *)(HPET_REG_BASE + TIM0_CONF) = 0x004c; // 设置定时器0为周期定时，边沿触发，默认投递到IO APIC的2号引脚(看conf寄存器的高32bit，哪一位被置1，则可以投递到哪一个I/O apic引脚)
    io_mfence();
    *(uint64_t *)(HPET_REG_BASE + TIM0_COMP) = 14318179; // 1s 产生一次interrupt

    io_mfence();

    kinfo("HPET0 enabled.");

    *(uint64_t *)(HPET_REG_BASE + GEN_CONF) = 3; // 置位旧设备中断路由兼容标志位、定时器组使能标志位
    io_mfence();
    // 注册中断
    irq_register(34, &entry, &HPET_handler, 0, &HPET_intr_controller, "HPET0");

    kinfo("HPET driver Initialized.");
}