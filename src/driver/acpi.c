#include "driver/acpi.h"
#include "display/kprint.h"

__attribute__((used, section(".limine_requests"))) static volatile struct limine_rsdp_request rsdp_request = {
    .id = LIMINE_RSDP_REQUEST,
    .revision = 0};

bool acpi_use_xsdt = false;

#define acpi_get_RSDT_entry_vaddr(phys_addr) (ACPI_DESCRIPTION_HEDERS_BASE + (phys_addr) - acpi_RSDT_entry_phys_base) // 获取RSDT entry的虚拟地址
#define acpi_get_XSDT_entry_vaddr(phys_addr) (ACPI_DESCRIPTION_HEDERS_BASE + (phys_addr) - acpi_XSDT_entry_phys_base) // 获取XSDT entry的虚拟地址

static struct acpi_RSDP_t *rsdpv1;
static struct acpi_RSDP_2_t *rsdpv2;
static struct acpi_RSDT_Structure_t *rsdt;
static struct acpi_XSDT_Structure_t *xsdt;

static uint64_t acpi_RSDT_offset = 0;
static uint64_t acpi_XSDT_offset = 0;
static uint32_t acpi_RSDT_Entry_num = 0;
static uint32_t acpi_XSDT_Entry_num = 0;

static uint64_t acpi_RSDT_entry_phys_base = 0; // RSDT中的第一个entry所在物理页的基地址
static uint64_t acpi_madt_vaddr = 0;           // MADT的虚拟地址

/**
 * @brief 迭代器，用于迭代描述符头（位于ACPI标准文件的Table 5-29）
 * @param  _fun            迭代操作调用的函数
 * @param  _data           数据
 */
void acpi_iter_SDT(bool (*_fun)(const struct acpi_system_description_table_header_t *, void *),
                   void *_data)
{

    struct acpi_system_description_table_header_t *sdt_header;
    if (acpi_use_xsdt)
    {
        uint64_t *ent = &(xsdt->Entry);
        for (int i = 0; i < acpi_XSDT_Entry_num; ++i)
        {
            vmm_mmap((uint64_t)get_cr3(), true, ACPI_XSDT_DESCRIPTION_HEDERS_BASE + PAGE_2M_SIZE * i, (*(ent + i)) & PAGE_2M_MASK, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
            sdt_header = (struct acpi_system_description_table_header_t *)((uint64_t)(ACPI_XSDT_DESCRIPTION_HEDERS_BASE + PAGE_2M_SIZE * i));

            if (_fun(sdt_header, _data) == true)
                return;
        }
    }
    else
    {
        uint32_t *ent = &(rsdt->Entry);
        for (int i = 0; i < acpi_RSDT_Entry_num; ++i)
        {
            sdt_header = (struct acpi_system_description_table_header_t *)(acpi_get_RSDT_entry_vaddr((uint64_t)(*(ent + i))));

            if (_fun(sdt_header, _data) == true)
                return;
        }
    }

    return;
}

/**
 * @brief 获取MADT信息 Multiple APIC Description Table
 *
 * @param _iter_data 要被迭代的信息的结构体
 * @param _data 返回的MADT的虚拟地址
 * @param count 返回数组的长度
 * @return true
 * @return false
 */
bool acpi_get_MADT(const struct acpi_system_description_table_header_t *_iter_data, void *_data)
{
    if (!(_iter_data->Signature[0] == 'A' && _iter_data->Signature[1] == 'P' && _iter_data->Signature[2] == 'I' && _iter_data->Signature[3] == 'C'))
        return false;
    //*(struct acpi_Multiple_APIC_Description_Table_t *)_data = *(struct acpi_Multiple_APIC_Description_Table_t *)_iter_data;
    // 返回MADT的虚拟地址
    *(uint64_t *)_data = (uint64_t)_iter_data;
    acpi_madt_vaddr = (uint64_t)_iter_data;
    return true;
}

/**
 * @brief 获取HPET HPET_description_table
 *
 * @param _iter_data 要被迭代的信息的结构体
 * @param _data 返回的HPET表的虚拟地址
 * @return true
 * @return false
 */
bool acpi_get_HPET(const struct acpi_system_description_table_header_t *_iter_data, void *_data)
{
    if (!(_iter_data->Signature[0] == 'H' && _iter_data->Signature[1] == 'P' && _iter_data->Signature[2] == 'E' && _iter_data->Signature[3] == 'T'))
        return false;
    *(uint64_t *)_data = (uint64_t)_iter_data;
    return true;
}

/**
 * @brief 初始化acpi模块
 *
 */
void acpi_init()
{
    kinfo("Initializing ACPI...");

    uint64_t rsdp_address = (uint64_t)phy_2_virt(rsdp_request.response->address);
    vmm_mmap((uint64_t)get_cr3(), true, rsdp_address, (uint64_t)rsdp_request.response->address, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
    rsdpv2 = (struct acpi_RSDP_2_t *)rsdp_address;
    rsdpv1 = (struct acpi_RSDP_t *)rsdp_address;

    // An ACPI-compatible OS must use the XSDT if present
    if (rsdpv2->XsdtAddress != 0x00UL)
    {
        // acpi_use_xsdt = true;
        // uint64_t xsdt_phys_base = rsdpv2->XsdtAddress & PAGE_2M_MASK;
        // acpi_XSDT_offset = rsdpv2->XsdtAddress - xsdt_phys_base;
        // vmm_mmap((uint64_t)get_cr3(), true, ACPI_XSDT_VIRT_ADDR_BASE, xsdt_phys_base, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        // kdebug("XSDT mapped!");
        // xsdt = (struct acpi_XSDT_Structure_t *)(ACPI_XSDT_VIRT_ADDR_BASE + acpi_XSDT_offset);
        // // 计算RSDT Entry的数量
        // kdebug("offset=%d", sizeof(xsdt->header));
        // kdebug("xsdt sign=%s", xsdt->header.Signature);
        // acpi_XSDT_Entry_num = (xsdt->header.Length - sizeof(xsdt->header)) / 8;

        // color_printk(MAGENTA, BLACK, "XSDT Length=%dbytes.\n", xsdt->header.Length);
        // color_printk(MAGENTA, BLACK, "XSDT Entry num=%d\n", acpi_XSDT_Entry_num);

        // vmm_mmap((uint64_t)get_cr3(), true, ACPI_XSDT_VIRT_ADDR_BASE, xsdt_phys_base, xsdt->header.Length + PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        // // 映射所有的Entry的物理地址
        // uint64_t *ent = &(xsdt->Entry);
        // for (int j = 0; j < acpi_XSDT_Entry_num; ++j)
        // {
        //     kdebug("entry=%#018lx, virt=%#018lx", (*(ent + j)) & PAGE_2M_MASK, ACPI_XSDT_DESCRIPTION_HEDERS_BASE + PAGE_2M_SIZE * j);
        //     // 映射RSDT ENTRY的物理地址
        //     vmm_mmap((uint64_t)get_cr3(), true, ACPI_XSDT_DESCRIPTION_HEDERS_BASE + PAGE_2M_SIZE * j, (*(ent + j)), PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        // }

        // 映射RSDT的物理地址到页表
        // 暂定字节数为2MB
        // 由于页表映射的原因，需要清除低21位地址，才能填入页表
        uint64_t rsdt_phys_base = rsdpv2->rsdp1.RsdtAddress & PAGE_2M_MASK;
        acpi_RSDT_offset = rsdpv2->rsdp1.RsdtAddress - rsdt_phys_base;
        vmm_mmap((uint64_t)get_cr3(), true, ACPI_RSDT_VIRT_ADDR_BASE, rsdt_phys_base, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        kdebug("RSDT(v2) mapped!");
        rsdt = (struct acpi_RSDT_Structure_t *)(ACPI_RSDT_VIRT_ADDR_BASE + acpi_RSDT_offset);
        // 计算RSDT Entry的数量
        kdebug("offset=%d", sizeof(rsdt->header));
        acpi_RSDT_Entry_num = (rsdt->header.Length - 36) / 4;

        color_printk(MAGENTA, BLACK, "RSDT Length=%dbytes.\n", rsdt->header.Length);
        color_printk(MAGENTA, BLACK, "RSDT Entry num=%d\n", acpi_RSDT_Entry_num);

        vmm_mmap((uint64_t)get_cr3(), true, ACPI_RSDT_VIRT_ADDR_BASE, rsdt_phys_base, rsdt->header.Length + PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        // 映射所有的Entry的物理地址
        acpi_RSDT_entry_phys_base = ((uint64_t)(rsdt->Entry)) & PAGE_2M_MASK;
        // 由于地址只是32bit的，并且存在脏数据，这里需要手动清除高32bit，否则会触发#GP
        acpi_RSDT_entry_phys_base = acpi_RSDT_entry_phys_base & 0xFFFFFFFF;

        kdebug("entry=%#018lx", rsdt->Entry);
        kdebug("acpi_RSDT_entry_phys_base=%#018lx", acpi_RSDT_entry_phys_base);
        // 映射RSDT ENTRY的物理地址
        vmm_mmap((uint64_t)get_cr3(), true, ACPI_DESCRIPTION_HEDERS_BASE, acpi_RSDT_entry_phys_base, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
    }
    else if (rsdpv1->RsdtAddress != (uint32_t)0x00UL)
    { // 映射RSDT的物理地址到页表
        // 暂定字节数为2MB
        // 由于页表映射的原因，需要清除低21位地址，才能填入页表
        uint64_t rsdt_phys_base = rsdpv1->RsdtAddress & PAGE_2M_MASK;
        acpi_RSDT_offset = rsdpv1->RsdtAddress - rsdt_phys_base;
        vmm_mmap((uint64_t)get_cr3(), true, ACPI_RSDT_VIRT_ADDR_BASE, rsdt_phys_base, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        kdebug("RSDT mapped!");
        rsdt = (struct acpi_RSDT_Structure_t *)(ACPI_RSDT_VIRT_ADDR_BASE + acpi_RSDT_offset);
        // 计算RSDT Entry的数量
        kdebug("offset=%d", sizeof(rsdt->header));
        acpi_RSDT_Entry_num = (rsdt->header.Length - 36) / 4;

        color_printk(MAGENTA, BLACK, "RSDT Length=%dbytes.\n", rsdt->header.Length);
        color_printk(MAGENTA, BLACK, "RSDT Entry num=%d\n", acpi_RSDT_Entry_num);

        vmm_mmap((uint64_t)get_cr3(), true, ACPI_RSDT_VIRT_ADDR_BASE, rsdt_phys_base, rsdt->header.Length + PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
        // 映射所有的Entry的物理地址
        acpi_RSDT_entry_phys_base = ((uint64_t)(rsdt->Entry)) & PAGE_2M_MASK;
        // 由于地址只是32bit的，并且存在脏数据，这里需要手动清除高32bit，否则会触发#GP
        acpi_RSDT_entry_phys_base = acpi_RSDT_entry_phys_base & 0xFFFFFFFF;

        kdebug("entry=%#018lx", rsdt->Entry);
        kdebug("acpi_RSDT_entry_phys_base=%#018lx", acpi_RSDT_entry_phys_base);
        // 映射RSDT ENTRY的物理地址
        vmm_mmap((uint64_t)get_cr3(), true, ACPI_DESCRIPTION_HEDERS_BASE, acpi_RSDT_entry_phys_base, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
    }
    else
    {
        kbug("At acpi_init(): Cannot get right SDT!");
        while (1)
            hlt();
    }

    kinfo("ACPI module initialized!");
}