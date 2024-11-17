#include "mm/memory.h"
#include "display/printk.h"

/* PMM */

uint64_t *get_cr3()
{
    uint64_t *tmp;
    __asm__ __volatile__(
        "movq %%cr3, %0\n\t"
        : "=r"(tmp)::"memory");
    return tmp;
}

__attribute__((used, section(".limine_requests"))) static volatile struct limine_hhdm_request hhdm_request = {
    .id = LIMINE_HHDM_REQUEST,
    .revision = 0};

uint64_t PAGE_OFFSET;

__attribute__((used, section(".limine_requests"))) static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST,
    .revision = 0};

uint8_t *bitmap;
bool bitmap_initialized;

uint64_t mem_size = 0;

void bitmap_set(uint64_t index)
{
    bitmap[index / 8] |= (1 << (index % 8));
}

void bitmap_clear(uint64_t index)
{
    bitmap[index / 8] &= ~(1 << (index % 8));
}

uint8_t bitmap_get(uint64_t index)
{
    return bitmap[index / 8] & (1 << (index % 8));
}

void init_pmm()
{
    PAGE_OFFSET = hhdm_request.response->offset;

    struct limine_memmap_response *response = memmap_request.response;

    for (uint64_t i = 0; i < response->entry_count; i++)
    {
        struct limine_memmap_entry *entry = response->entries[i];

        if (entry->type == LIMINE_MEMMAP_USABLE)
        {
            mem_size += entry->length;
        }
    }

    uint64_t bitmap_size = mem_size / PAGE_4K_SIZE / 8;
    uint64_t bitmap_phys_address = 0;

    for (uint64_t i = 0; i < response->entry_count; i++)
    {
        struct limine_memmap_entry *entry = response->entries[i];

        if (entry->type == LIMINE_MEMMAP_USABLE && entry->length >= bitmap_size && !bitmap_initialized)
        {
            bitmap = (uint8_t *)phy_2_virt(entry->base);
            bitmap_initialized = true;

            for (uint64_t j = entry->base / PAGE_4K_SIZE; j < (entry->base + bitmap_size + PAGE_4K_SIZE - 1) / PAGE_4K_SIZE; j++)
                bitmap_clear(j);

            for (uint64_t i = (entry->base + bitmap_size + PAGE_4K_SIZE - 1) / PAGE_4K_SIZE; i < (entry->base + entry->length + PAGE_4K_SIZE - 1) / PAGE_4K_SIZE; i++)
                bitmap_set(i);
        }
    }

    for (uint64_t i = 0; i < response->entry_count; i++)
    {
        struct limine_memmap_entry *entry = response->entries[i];

        if (entry->type == LIMINE_MEMMAP_USABLE && entry->base != bitmap_phys_address)
        {
            for (uint64_t i = entry->base / PAGE_4K_SIZE; i < (entry->length / PAGE_4K_SIZE); i++)
            {
                bitmap_set(i);
            }
        }
    }

    for (uint64_t i = 0; i < 0x100000; i += PAGE_4K_SIZE)
    {
        bitmap_clear(i / PAGE_4K_SIZE);
    }

    color_printk(WHITE, BLACK, "mem_size = %#018lx\n", mem_size);
}

uint64_t allocate_frame()
{
    for (uint64_t i = 0; i <= mem_size / PAGE_4K_SIZE; i++)
    {
        if (bitmap_get(i) != 0)
        {
            bitmap_clear(i);
            return i * PAGE_4K_SIZE;
        }
    }
    color_printk(RED, WHITE, "No enougth memory for allocate\n");
    return 0;
}

void deallocate_frame(uint64_t frame)
{
    bitmap_set(frame / PAGE_4K_SIZE);
}

/* VMM */

uint64_t heap = HEAP_START;

void init_vmm()
{
    for (uint64_t i = HEAP_START; i < HEAP_START + HEAP_SIZE + PAGE_4K_SIZE; i += PAGE_4K_SIZE)
    {
        uint64_t phys = allocate_frame();
        // color_printk(WHITE, BLACK, "mapping heap: %#018lx -> %#018lx\n", i, phys);
        vmm_mmap((uint64_t)get_cr3(), true, i, phys, PAGE_4K_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
    }

    *((uint64_t *)heap) = HEAP_SIZE - 0x10;
    *((uint64_t *)(heap + HEAP_SIZE - 0x08)) = ~(0ULL);
}

typedef struct
{
    int64_t num_PML4E;
    int64_t num_PDPTE;
    int64_t num_PDE;
    int64_t num_PTE;
} mm_pgt_entry_num_t;

static void mm_calculate_entry_num(uint64_t length, mm_pgt_entry_num_t *ent)
{
    if (ent == NULL)
        return;

    ent->num_PML4E = (length + (1UL << PAGE_GDT_SHIFT) - 1) >> PAGE_GDT_SHIFT;
    ent->num_PDPTE = (length + PAGE_1G_SIZE - 1) >> PAGE_1G_SHIFT;
    ent->num_PDE = (length + PAGE_2M_SIZE - 1) >> PAGE_2M_SHIFT;
    ent->num_PTE = (length + PAGE_4K_SIZE - 1) >> PAGE_4K_SHIFT;
}

void vmm_mmap(uint64_t proc_page_table_addr, bool is_phys, uint64_t virt_addr_start, uint64_t phys_addr_start, uint64_t length, uint64_t flags, bool user, bool flush)
{
    // 计算线性地址对应的pml4页表项的地址
    mm_pgt_entry_num_t pgt_num;
    mm_calculate_entry_num(length, &pgt_num);

    // 已映射的内存大小
    uint64_t length_mapped = 0;

    // 对user标志位进行校正
    if ((flags & PAGE_U_S) != 0)
        user = true;
    else
        user = false;

    uint64_t pml4e_id = ((virt_addr_start >> PAGE_GDT_SHIFT) & 0x1ff);
    uint64_t *pml4_ptr;
    if (is_phys)
        pml4_ptr = phy_2_virt((uint64_t *)((uint64_t)proc_page_table_addr & (~0xfffUL)));
    else
        pml4_ptr = (uint64_t *)((uint64_t)proc_page_table_addr & (~0xfffUL));

    // 循环填写顶层页表
    for (; (pgt_num.num_PML4E > 0) && pml4e_id < 512; ++pml4e_id)
    {
        // 剩余需要处理的pml4E -1
        --(pgt_num.num_PML4E);

        uint64_t *pml4e_ptr = pml4_ptr + pml4e_id;

        // 创建新的二级页表
        if (*pml4e_ptr == 0)
        {
            uint64_t *addr = (uint64_t *)allocate_frame();
            set_pml4t(pml4e_ptr, mk_pml4t(addr, (user ? (PAGE_PRESENT | PAGE_R_W | PAGE_U_S) : (PAGE_PRESENT | PAGE_R_W))));
        }

        uint64_t pdpte_id = (((virt_addr_start + length_mapped) >> PAGE_1G_SHIFT) & 0x1ff);
        uint64_t *pdpt_ptr = (uint64_t *)phy_2_virt(*pml4e_ptr & (~0xfffUL));

        // 循环填写二级页表
        for (; (pgt_num.num_PDPTE > 0) && pdpte_id < 512; ++pdpte_id)
        {
            --pgt_num.num_PDPTE;
            uint64_t *pdpte_ptr = (pdpt_ptr + pdpte_id);

            // 创建新的三级页表
            if (*pdpte_ptr == 0)
            {
                uint64_t *addr = (uint64_t *)allocate_frame();
                set_pdpt(pdpte_ptr, mk_pdpt(addr, (user ? (PAGE_PRESENT | PAGE_R_W | PAGE_U_S) : (PAGE_PRESENT | PAGE_R_W))));
            }

            uint64_t pde_id = (((virt_addr_start + length_mapped) >> PAGE_2M_SHIFT) & 0x1ff);
            uint64_t *pd_ptr = (uint64_t *)phy_2_virt(*pdpte_ptr & (~0xfffUL));

            // 循环填写三级页表，初始化2M物理页
            for (; (pgt_num.num_PDE > 0) && pde_id < 512; ++pde_id)
            {
                --pgt_num.num_PDE;
                // 计算当前2M物理页对应的pdt的页表项的物理地址
                uint64_t *pde_ptr = pd_ptr + pde_id;
                if (*pde_ptr & (1 << 7))
                {
                    // 当前页表项已经被映射了2MB物理页
                    goto failed;
                }
                if (*pde_ptr == 0)
                {
                    // 创建四级页表
                    uint64_t *addr = (uint64_t *)allocate_frame();
                    set_pdt(pde_ptr, mk_pdt(addr, (user ? (PAGE_PRESENT | PAGE_R_W | PAGE_U_S) : (PAGE_PRESENT | PAGE_R_W))));
                }

                uint64_t pte_id = (((virt_addr_start + length_mapped) >> PAGE_4K_SHIFT) & 0x1ff);
                uint64_t *pt_ptr = (uint64_t *)phy_2_virt(*pde_ptr & (~0xfffUL));

                // 循环填写4级页表，初始化4K页
                for (; (pgt_num.num_PTE > 0) && pte_id < 512; ++pte_id)
                {
                    --pgt_num.num_PTE;
                    uint64_t *pte_ptr = pt_ptr + pte_id;

                    set_pt(pte_ptr, mk_pt((uint64_t)phys_addr_start + length_mapped, flags | (user ? (PAGE_PRESENT | PAGE_R_W | PAGE_U_S) : (PAGE_PRESENT | PAGE_R_W))));
                    length_mapped += PAGE_4K_SIZE;
                }
            }
        }
    }
    if (flush)
        flush_tlb();

    return;
failed:;
    color_printk(RED, BLACK, "Map memory failed. vaddr=%#018lx, paddr=%#018lx\n", virt_addr_start, phys_addr_start);
}

void *kalloc(uint64_t size)
{
    size = (((size - 1) >> 3) + 1) << 3;
    uint64_t *block = (uint64_t *)heap;

    while (~*block)
    {
        // Block is free
        if (!(*block & 1))
        {
            // Merge free blocks
            uint64_t *next = block + (*block >> 3);
            next++;
            while (!(*next & 1))
            {
                *block += (*next & (~0ULL << 3));
                *block += 8;
                next += *next >> 3;
                next++;
            }
            // Check block size
            uint64_t blockSize = (*block >> 3) << 3;
            if (blockSize >= size)
            {
                // Not whole block
                if (blockSize > size)
                {
                    // Split to two blocks
                    next = block;
                    *next = size;
                    next += (size >> 3);
                    next++;
                    *next = blockSize - size - 8;
                }
                // Use this block
                *block |= 1;
                return ++block;
            }
        }

        // Next block
        block += *block >> 3;
        block++;
    }
    return 0;
}

void kfree(void *p)
{
    uint64_t *block = ((uint64_t *)(((uint64_t)p) - 8));
    *block = (*block >> 1) << 1;
}

uint64_t physical_mapping(uint64_t linear)
{
    uint64_t addressMask = 0x07FFFFFFFFFFF000;
    uint16_t idx0 = (linear >> 39) & 0x1FF;
    uint16_t idx1 = (linear >> 30) & 0x1FF;
    uint16_t idx2 = (linear >> 21) & 0x1FF;
    uint16_t idx3 = (linear >> 12) & 0x1FF;

    uint64_t *L0 = phy_2_virt(get_cr3());
    if (!(L0[idx0] & 1))
    {
        return ~(0ULL);
    }

    uint64_t *L1 = phy_2_virt((L0[idx0] & ~0xFFF));
    if (!(L1[idx1] & 1))
    {
        return ~(0ULL);
    }
    if (L1[idx1] & 0x80)
    {
        return (L1[idx1] & addressMask) + (linear & ((1 << 30) - 1));
    }

    uint64_t *L2 = phy_2_virt((L1[idx1] & ~0xFFF));
    if (!(L2[idx2] & 1))
    {
        return ~(0ULL);
    }
    if (L2[idx2] & 0x80)
    {
        return (L2[idx2] & addressMask) + (linear & ((1 << 21) - 1));
    }

    uint64_t *L3 = phy_2_virt((L2[idx2] & ~0xFFF));
    if (!(L3[idx3] & 1))
    {
        return ~(0ULL);
    }
    return (L3[idx3] & addressMask) + (linear & ((1 << 12) - 1));
}
