#pragma once

#include "glib.h"
#include "limine.h"

#define PTRS_PER_PAGE 512

extern uint64_t PAGE_OFFSET;

#define PAGE_GDT_SHIFT 39
#define PAGE_1G_SHIFT 30
#define PAGE_2M_SHIFT 21
#define PAGE_4K_SHIFT 12

#define PAGE_1G_SIZE (1UL << PAGE_1G_SHIFT)
#define PAGE_2M_SIZE (1UL << PAGE_2M_SHIFT)
#define PAGE_4K_SIZE (1UL << PAGE_4K_SHIFT)

#define PAGE_2M_MASK (~(PAGE_2M_SIZE - 1))
#define PAGE_4K_MASK (~(PAGE_4K_SIZE - 1))

#define PAGE_2M_ALIGN(addr) (((uint64_t)(addr) + PAGE_2M_SIZE - 1) & PAGE_2M_MASK)
#define PAGE_4K_ALIGN(addr) (((uint64_t)(addr) + PAGE_4K_SIZE - 1) & PAGE_4K_MASK)

#define virt_2_phy(addr) ((uint64_t)(addr) - PAGE_OFFSET)
#define phy_2_virt(addr) ((uint64_t *)((uint64_t)(addr) + PAGE_OFFSET))

//	bit 63	Execution Disable:
#define PAGE_XD (1UL << 63)
#define PAGE_PAT (1UL << 7)
//	bit 8	Global Page:1,global;0,part
#define PAGE_GLOBAL (1UL << 8)
//	bit 7	Page Size:1,big page;0,small page;
#define PAGE_PS (1UL << 7)
//	bit 6	Dirty:1,dirty;0,clean;
#define PAGE_DIRTY (1UL << 6)
//	bit 5	Accessed:1,visited;0,unvisited;
#define PAGE_ACCESSED (1UL << 5)
//	bit 4	Page Level Cache Disable
#define PAGE_PCD (1UL << 4)
//	bit 3	Page Level Write Through
#define PAGE_PWT (1UL << 3)
//	bit 2	User Supervisor:1,user and supervisor;0,supervisor;
#define PAGE_U_S (1UL << 2)
//	bit 1	Read Write:1,read and write;0,read;
#define PAGE_R_W (1UL << 1)
//	bit 0	Present:1,present;0,no present;
#define PAGE_PRESENT (1UL << 0)

/* PMM */

void init_pmm();

uint64_t allocate_frame();
void deallocate_frame(uint64_t frame);

uint64_t *get_cr3();

/* VMM */

#define HEAP_START 0xFFFFFFFFC0000000
#define HEAP_SIZE 0x10000

#define SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE 0xFFFFA00000000000
#define ACPI_RSDT_MAPPING_OFFSET 0x10000000
#define ACPI_XSDT_MAPPING_OFFSET 0x20000000
#define IO_APIC_MAPPING_OFFSET 0xfec00000
#define LOCAL_APIC_MAPPING_OFFSET 0xfee00000

#define flush_tlb()                 \
    do                              \
    {                               \
        uint64_t tmp;               \
        io_mfence();                \
        __asm__ __volatile__(       \
            "movq %%cr3, %0\n\t"    \
            "movq %0, %%cr3\n\t"    \
            : "=r"(tmp)::"memory"); \
                                    \
    } while (0);

/**
 * @brief 内存页表结构体
 *
 */
typedef struct
{
    unsigned long pml4t;
} pml4t_t;

typedef struct
{
    unsigned long pdpt;
} pdpt_t;

typedef struct
{
    unsigned long pdt;
} pdt_t;

typedef struct
{
    unsigned long pt;
} pt_t;

#define mk_pml4t(addr, attr) ((unsigned long)(addr) | (unsigned long)(attr))
#define set_pml4t(pml4tptr, pml4tval) (*(pml4tptr) = (pml4tval))

#define mk_pdpt(addr, attr) ((unsigned long)(addr) | (unsigned long)(attr))
#define set_pdpt(pdptptr, pdptval) (*(pdptptr) = (pdptval))

#define mk_pdt(addr, attr) ((unsigned long)(addr) | (unsigned long)(attr))
#define set_pdt(pdtptr, pdtval) (*(pdtptr) = (pdtval))

#define mk_pt(addr, attr) ((unsigned long)(addr) | (unsigned long)(attr))
#define set_pt(ptptr, ptval) (*(ptptr) = (ptval))

void init_vmm();

void vmm_mmap(uint64_t proc_page_table_addr, bool is_phys, uint64_t virt_addr_start, uint64_t phys_addr_start, uint64_t length, uint64_t flags, bool user, bool flush);

void *kalloc(uint64_t size);
void kfree(void *p);
