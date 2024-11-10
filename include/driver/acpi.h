#pragma once

#include <glib.h>
#include <mm/memory.h>

#define ACPI_ICS_TYPE_PROCESSOR_LOCAL_APIC 0
#define ACPI_ICS_TYPE_IO_APIC 1
#define ACPI_ICS_TYPE_INTERRUPT_SOURCE_OVERRIDE 2
#define ACPI_ICS_TYPE_NMI_SOURCE 3
#define ACPI_ICS_TYPE_LOCAL_APIC_NMI 4
#define ACPI_ICS_TYPE_LOCAL_APIC_ADDRESS_OVERRIDE 5
#define ACPI_ICS_TYPE_IO_SAPIC 6
#define ACPI_ICS_TYPE_LOCAL_SAPIC 7
#define ACPI_ICS_TYPE_PLATFORM_INTERRUPT_SOURCES 8
#define ACPI_ICS_TYPE_PROCESSOR_LOCAL_x2APIC 9
#define ACPI_ICS_TYPE_PROCESSOR_LOCAL_x2APIC_NMI 0xA
#define ACPI_ICS_TYPE_PROCESSOR_GICC 0xB
#define ACPI_ICS_TYPE_PROCESSOR_GICD 0xC
#define ACPI_ICS_TYPE_PROCESSOR_GIC_MSI_Frame 0xD
#define ACPI_ICS_TYPE_PROCESSOR_GICR 0xE
#define ACPI_ICS_TYPE_PROCESSOR_GIC_ITS 0xF
// 0x10-0x7f Reserved. OSPM skips structures of the reserved type.
// 0x80-0xff Reserved for OEM use

#define ACPI_RSDT_VIRT_ADDR_BASE SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + ACPI_RSDT_MAPPING_OFFSET
#define ACPI_XSDT_VIRT_ADDR_BASE SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + ACPI_XSDT_MAPPING_OFFSET
#define ACPI_DESCRIPTION_HEDERS_BASE ACPI_RSDT_VIRT_ADDR_BASE + (PAGE_2M_SIZE)
#define ACPI_XSDT_DESCRIPTION_HEDERS_BASE ACPI_XSDT_VIRT_ADDR_BASE + (PAGE_2M_SIZE)

struct acpi_RSDP_t
{
    unsigned char Signature[8];
    unsigned char Checksum;
    unsigned char OEMID[6];

    unsigned char Revision;

    // 32bit physical address of the RSDT
    uint32_t RsdtAddress;
} __attribute__((packed));

struct acpi_RSDP_2_t
{
    struct acpi_RSDP_t rsdp1;

    // fields below are only valid when the revision value is 2 or above
    // 表的长度（单位：字节）从offset=0开始算
    uint32_t Length;
    // 64bit的XSDT的物理地址
    uint64_t XsdtAddress;
    unsigned char ExtendedChecksum; // 整个表的checksum，包括了之前的checksum区域

    unsigned char Reserved[3];
} __attribute__((packed));

struct acpi_system_description_table_header_t
{
    // The ascii string representation of the table header.
    unsigned char Signature[4];
    // 整个表的长度（单位：字节），包括了header，从偏移量0处开始
    uint32_t Length;
    // The revision of the  structure corresponding to the signature field for this table.
    unsigned char Revision;
    // The entire table, including the checksum field, must add to zero to be considered valid.
    char Checksum;

    unsigned char OEMID[6];
    unsigned char OEM_Table_ID[8];
    uint32_t OEMRevision;
    uint32_t CreatorID;
    uint32_t CreatorRevision;
} __attribute__((packed));

// HPET描述符结构体，sign为HPET
struct acpi_HPET_description_table_t
{
    struct acpi_system_description_table_header_t header;

    uint8_t hardware_rev_id;
    uint8_t comparator_count : 5; // Number of Comparators in 1st Timer Block
    uint8_t counter_size : 1;     // COUNT_SIZE_CAP counter size
    uint8_t reserved0 : 1;
    uint8_t legacy_replacement : 1; //  LegacyReplacement IRQ Routing Capable
    uint16_t pci_vendor_id;         // PCI Vendor ID of 1st Timer Block

    uint8_t address_space_id; // 0 - system memory, 1 - system I/O
    uint8_t register_bit_width;
    uint8_t register_bit_offset;
    uint8_t reserved1;
    uint64_t address;

    uint8_t hpet_number;
    uint16_t minimum_tick; // The minimum clock ticks can be set without lost interrupts while the counter is programmed to operate in periodic mode

    uint8_t page_protection;

} __attribute__((packed));

// =========== MADT结构，其中Signature为APIC ============
struct acpi_Multiple_APIC_Description_Table_t
{
    struct acpi_system_description_table_header_t header;

    // 32bit的，每个处理器可访问的local中断控制器的物理地址
    uint32_t Local_Interrupt_Controller_Address;

    // Multiple APIC flags, 详见 ACPI Specification Version 6.3, Table 5-44
    uint32_t flags;

    // 接下来的(length-44)字节是Interrupt Controller Structure
};

struct apic_Interrupt_Controller_Structure_header_t
{
    unsigned char type;
    unsigned char length;
};

struct acpi_Processor_Local_APIC_Structure_t
{
    // type=0
    struct apic_Interrupt_Controller_Structure_header_t header;
    unsigned char ACPI_Processor_UID;
    // 处理器的local apic id
    unsigned char local_apic_id;
    // 详见 ACPI Specification Version 6.3, Table 5-47
    uint32_t flags;
};

struct acpi_IO_APIC_Structure_t
{
    // type=1
    struct apic_Interrupt_Controller_Structure_header_t header;
    unsigned char IO_APIC_ID;
    unsigned char Reserved;
    // 32bit的IO APIC物理地址 （每个IO APIC都有一个独立的物理地址）
    uint32_t IO_APIC_Address;
    // 当前IO APIC的全局系统中断向量号起始值
    // The number of intr inputs is determined by the IO APIC's Max Redir Entry register.
    uint32_t Global_System_Interrupt_Base;
};

// =========== RSDT 结构 =============
struct acpi_RSDT_Structure_t
{
    // 通过RSDT的header->Length可以计算出entry的数量n
    // n = (length - 32)/4
    struct acpi_system_description_table_header_t header;

    // 一个包含了n个32bit物理地址的数组，指向了其他的description headers
    uint32_t Entry;
};

// =========== XSDT 结构 =============
struct acpi_XSDT_Structure_t
{
    // 通过RSDT的header->Length可以计算出entry的数量n
    // n = (length - 36)/8
    struct acpi_system_description_table_header_t header;
    // 一个包含了n个64bit物理地址的数组，指向了其他的description headers
    uint64_t Entry;
};

/**
 * @brief 迭代器，用于迭代描述符头（位于ACPI标准文件的Table 5-29）
 * @param  _fun            迭代操作调用的函数
 * @param  _data           数据
 */
void acpi_iter_SDT(bool (*_fun)(const struct acpi_system_description_table_header_t *, void *),
                   void *_data);

/**
 * @brief 获取MADT信息 Multiple APIC Description Table
 *
 * @param _iter_data 要被迭代的信息的结构体
 * @param _data 返回的MADT的虚拟地址
 * @param count 返回数组的长度
 * @return true
 * @return false
 */
bool acpi_get_MADT(const struct acpi_system_description_table_header_t *_iter_data, void *_data);

/**
 * @brief 获取HPET HPET_description_table
 *
 * @param _iter_data 要被迭代的信息的结构体
 * @param _data 返回的HPET表的虚拟地址
 * @return true
 * @return false
 */
bool acpi_get_HPET(const struct acpi_system_description_table_header_t *_iter_data, void *_data);

// 初始化acpi模块
void acpi_init();
