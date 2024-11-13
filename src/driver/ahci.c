#include "driver/ahci.h"
#include "display/kprint.h"

struct pci_device_structure_general_device_t *ahci_devs[4];

static uint32_t ahci_bus, ahci_slot, ahci_func, port, ahci_ports_base_addr;
static uint32_t drive_mapping[0xff];
static uint32_t ports[32];
static uint32_t port_total = 0;
static HBA_MEM *hba_mem_address;
static uint8_t *cache;

static int check_type(HBA_PORT *port)
{
    uint32_t ssts = port->ssts;

    uint8_t ipm = (ssts >> 8) & 0x0F;
    uint8_t det = ssts & 0x0F;
    // https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf
    // 3.3.10
    if (det != HBA_PORT_DET_PRESENT)
        return AHCI_DEV_NULL;
    if (ipm != HBA_PORT_IPM_ACTIVE)
        return AHCI_DEV_NULL;

    switch (port->sig)
    {
    case SATA_SIG_ATAPI:
        return AHCI_DEV_SATAPI;
    case SATA_SIG_SEMB:
        return AHCI_DEV_SEMB;
    case SATA_SIG_PM:
        return AHCI_DEV_PM;
    default:
        return AHCI_DEV_SATA;
    }
}
void ahci_search_ports(HBA_MEM *abar)
{
    // Search disk in implemented ports
    uint32_t pi = abar->pi;
    int i = 0;
    while (i < 32)
    {
        if (pi & 1)
        {
            int dt = check_type(&abar->ports[i]);
            if (dt == AHCI_DEV_SATA)
            {
                kinfo("SATA drive found at port %d", i);
                port = i;
                ports[port_total++] = i;
            }
            else if (dt == AHCI_DEV_SATAPI)
            {
                kinfo("SATAPI drive found at port %d", i);
                port = i;
                ports[port_total++] = i;
            }
            else if (dt == AHCI_DEV_SEMB)
            {
                kinfo("SEMB drive found at port %d", i);
            }
            else if (dt == AHCI_DEV_PM)
            {
                kinfo("PM drive found at port %d", i);
            }
            else
            {
                // kinfo("No drive found at port %d", i);
            }
        }

        pi >>= 1;
        i++;
    }
}
// Start command engine
void start_cmd(HBA_PORT *port)
{
    // Wait until CR (bit15) is cleared
    while (port->cmd & HBA_PxCMD_CR)
        ;

    // Set FRE (bit4) and ST (bit0)
    port->cmd |= HBA_PxCMD_FRE;
    port->cmd |= HBA_PxCMD_ST;
}

// Stop command engine
void stop_cmd(HBA_PORT *port)
{
    // Clear ST (bit0)
    port->cmd &= ~HBA_PxCMD_ST;

    // Clear FRE (bit4)
    port->cmd &= ~HBA_PxCMD_FRE;

    // Wait until FR (bit14), CR (bit15) are cleared
    while (1)
    {
        if (port->cmd & HBA_PxCMD_FR)
            continue;
        if (port->cmd & HBA_PxCMD_CR)
            continue;
        break;
    }
}

int find_cmdslot(HBA_PORT *port);
void flush_cache(void *addr);

#define ATA_DEV_BUSY 0x80
#define ATA_DEV_DRQ 0x08
#define AHCI_CMD_READ_DMA_EXT 0x25
#define AHCI_CMD_WRITE_DMA_EXT 0x35

bool ahci_read(HBA_PORT *port, uint32_t startl, uint32_t starth, uint32_t count, uint16_t *buf)
{
    port->is = (uint32_t)-1; // Clear pending interrupt bits
    int spin = 0;            // Spin lock timeout counter
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)phy_2_virt(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t); // Command FIS size
    cmdheader->w = 0;                                        // Read from device
    cmdheader->c = 1;
    cmdheader->p = 1;
    cmdheader->prdtl = (uint16_t)((count - 1) >> 4) + 1; // PRDT entries count

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)phy_2_virt(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    // 8K bytes (16 sectors) per PRDT
    int i;
    for (i = 0; i < cmdheader->prdtl - 1; i++)
    {
        flush_cache(buf);

        cmdtbl->prdt_entry[0].dba = (uint32_t)phy_2_virt(buf) & 0xffffffff;
        cmdtbl->prdt_entry[0].dbau = (uint32_t)(((uint64_t)phy_2_virt(buf) >> 32) & 0xffffffff);
        cmdtbl->prdt_entry[i].dbc = 8 * 1024 - 1; // 8K bytes (this value should always be set to 1 less
                                                  // than the actual value)
        cmdtbl->prdt_entry[i].i = 1;
        buf += 4 * 1024; // 4K words
        count -= 16;     // 16 sectors
    }
    // Last entry
    cmdtbl->prdt_entry[0].dba = (uint32_t)phy_2_virt(buf) & 0xffffffff;
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(((uint64_t)phy_2_virt(buf) >> 32) & 0xffffffff);
    cmdtbl->prdt_entry[i].dbc = (count << 9) - 1; // 512 bytes per sector
    cmdtbl->prdt_entry[i].i = 1;

    // Setup command
    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);

    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1; // Command
    cmdfis->command = AHCI_CMD_READ_DMA_EXT;

    cmdfis->lba0 = (uint8_t)startl;
    cmdfis->lba1 = (uint8_t)(startl >> 8);
    cmdfis->lba2 = (uint8_t)(startl >> 16);
    cmdfis->device = 1 << 6; // LBA mode

    cmdfis->lba3 = (uint8_t)(startl >> 24);
    cmdfis->lba4 = (uint8_t)starth;
    cmdfis->lba5 = (uint8_t)(starth >> 8);

    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    // The below loop waits until the port is no longer busy before issuing a new
    // command
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
    {
        spin++;
    }
    if (spin == 1000000)
    {
        kinfo("Port is hung");
        return false;
    }

    port->ci = 1 << slot; // Issue command

    // Wait for completion
    while (1)
    {
        // In some longer duration reads, it may be helpful to spin on the DPS bit
        // in the PxIS port field as well (1 << 5)
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) // Task file error
        {
            kinfo("Read disk error");
            return false;
        }
    }

    // Check again
    if (port->is & HBA_PxIS_TFES)
    {
        kinfo("Read disk error");
        return false;
    }

    flush_cache(buf);
    return true;
}

bool ahci_identify(HBA_PORT *port, void *buf)
{
    port->is = (uint32_t)-1; // Clear pending interrupt bits
    int spin = 0;            // Spin lock timeout counter
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)phy_2_virt(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t); // Command FIS size
    cmdheader->w = 0;                                        // Read from device
    cmdheader->prdtl = 1;                                    // PRDT entries count
    cmdheader->c = 1;
    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)phy_2_virt(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    cmdtbl->prdt_entry[0].dba = (uint32_t)phy_2_virt(buf) & 0xffffffff;
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(((uint64_t)phy_2_virt(buf) >> 32) & 0xffffffff);
    cmdtbl->prdt_entry[0].dbc = 0x200 - 1;
    cmdtbl->prdt_entry[0].i = 1;

    // Setup command
    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);

    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;          // Command
    cmdfis->command = 0xec; // ATA IDENTIFY

    // The below loop waits until the port is no longer busy before issuing a new
    // command
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
    {
        spin++;
    }
    if (spin == 1000000)
    {
        kinfo("Port is hung");
        return false;
    }

    port->ci = 1 << slot; // Issue command

    // Wait for completion
    while (1)
    {
        // In some longer duration reads, it may be helpful to spin on the DPS bit
        // in the PxIS port field as well (1 << 5)
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) // Task file error
        {
            kinfo("Read disk error");
            return false;
        }
    }

    // Check again
    if (port->is & HBA_PxIS_TFES)
    {
        kinfo("Read disk error");
        return false;
    }

    return true;
}

bool ahci_write(HBA_PORT *port, uint32_t startl, uint32_t starth, uint32_t count, uint16_t *buf)
{
    port->is = (uint32_t)-1; // Clear pending interrupt bits
    int spin = 0;            // Spin lock timeout counter
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)port->clb;
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t); // Command FIS size
    cmdheader->w = 1;                                        // 写硬盘
    cmdheader->p = 1;
    cmdheader->c = 1;
    cmdheader->prdtl = (uint16_t)((count - 1) >> 4) + 1; // PRDT entries count

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)phy_2_virt(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    // 8K bytes (16 sectors) per PRDT
    int i;
    for (i = 0; i < cmdheader->prdtl - 1; i++)
    {
        flush_cache(buf);

        cmdtbl->prdt_entry[0].dba = (uint32_t)phy_2_virt(buf) & 0xffffffff;
        cmdtbl->prdt_entry[0].dbau = (uint32_t)(((uint64_t)phy_2_virt(buf) >> 32) & 0xffffffff);
        cmdtbl->prdt_entry[i].dbc = 8 * 1024 - 1; // 8K bytes (this value should always be set to 1 less
                                                  // than the actual value)
        cmdtbl->prdt_entry[i].i = 1;
        buf += 4 * 1024; // 4K words
        count -= 16;     // 16 sectors
    }
    // Last entry

    cmdtbl->prdt_entry[0].dba = (uint32_t)phy_2_virt(buf) & 0xffffffff;
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(((uint64_t)phy_2_virt(buf) >> 32) & 0xffffffff);
    cmdtbl->prdt_entry[i].dbc = (count << 9) - 1; // 512 bytes per sector
    cmdtbl->prdt_entry[i].i = 1;

    // Setup command
    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);

    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1; // Command
    cmdfis->command = AHCI_CMD_WRITE_DMA_EXT;

    cmdfis->lba0 = (uint8_t)startl;
    cmdfis->lba1 = (uint8_t)(startl >> 8);
    cmdfis->lba2 = (uint8_t)(startl >> 16);
    cmdfis->device = 1 << 6; // LBA mode

    cmdfis->lba3 = (uint8_t)(startl >> 24);
    cmdfis->lba4 = (uint8_t)starth;
    cmdfis->lba5 = (uint8_t)(starth >> 8);

    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    // The below loop waits until the port is no longer busy before issuing a new
    // command
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
    {
        spin++;
    }
    if (spin == 1000000)
    {
        kinfo("Port is hung");
        return false;
    }

    port->ci = 1 << slot; // Issue command

    // Wait for completion
    while (1)
    {
        // In some longer duration reads, it may be helpful to spin on the DPS bit
        // in the PxIS port field as well (1 << 5)
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) // Task file error
        {
            kinfo("Write disk error");
            return false;
        }
    }

    // Check again
    if (port->is & HBA_PxIS_TFES)
    {
        kinfo("Write disk error");
        return false;
    }
    flush_cache(buf);
    return true;
}
// Find a free command list slot
int find_cmdslot(HBA_PORT *port)
{
    // If not set in SACT and CI, the slot is free
    uint32_t slots = (port->sact | port->ci);
    int cmdslots = (hba_mem_address->cap & 0x1f00) >> 8;
    for (int i = 0; i < cmdslots; i++)
    {
        if ((slots & 1) == 0)
            return i;
        slots >>= 1;
    }
    kinfo("Cannot find free command list entry");
    return -1;
}
void port_rebase(HBA_PORT *port, int portno)
{
    stop_cmd(port); // Stop command engine

    // Command list offset: 1K*portno
    // Command list entry size = 32
    // Command list entry maxim count = 32
    // Command list maxim size = 32*32 = 1K per port
    port->clb = ahci_ports_base_addr + (portno << 10);
    port->clbu = 0;
    memset(phy_2_virt(port->clb), 0, 1024);

    // FIS offset: 32K+256*portno
    // FIS entry size = 256 bytes per port
    port->fb = ahci_ports_base_addr + (32 << 10) + (portno << 8);
    port->fbu = 0;
    memset(phy_2_virt(port->fb), 0, 256);

    // Command table offset: 40K + 8K*portno
    // Command table size = 256*32 = 8K per port
    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)phy_2_virt(port->clb);
    for (int i = 0; i < 32; i++)
    {
        cmdheader[i].prdtl = 8; // 8 prdt entries per command table
                                // 256 bytes per command table, 64+16+48+16*8
        // Command table offset: 40K + 8K*portno + cmdheader_index*256
        cmdheader[i].ctba = ahci_ports_base_addr + (40 << 10) + (portno << 13) + (i << 8);
        cmdheader[i].ctbau = 0;
        memset(phy_2_virt(cmdheader[i].ctba), 0, 256);
    }

    start_cmd(port); // Start command engine
}
static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *regs)
{
    asm volatile("cpuid"
                 : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
                 : "a"(leaf), "c"(subleaf));
}

// 获取缓存行大小
uint32_t get_cache_line_size()
{
    uint32_t regs[4] = {0};
    cpuid(0x00000001, 0, regs);

    // EAX寄存器的第8-11位包含缓存行的字节数
    return (regs[1] >> 8) & 0xFF;
}

#define PAGE_SIZE 4096
int cache_line_size = 0;
// 刷新缓存函数
void flush_cache(void *addr)
{
    uintptr_t address = (uintptr_t)addr;

    // 计算需要刷新的页的起始地址
    uintptr_t page_start = address & ~(PAGE_SIZE - 1);

    // 遍历并刷新整页的所有缓存行
    for (uintptr_t cache_line = page_start; cache_line < page_start + PAGE_SIZE;
         cache_line += cache_line_size)
    {
        asm volatile("clflush (%0)" : : "r"(cache_line) : "memory");
    }
}

static void ahci_blockdev_read(dev_t self_dev_id, void *dev, void *buf, size_t count, int idx, int flags)
{
    int i;
    for (i = 0; i < 5; i++)
        if (ahci_read(&(hba_mem_address->ports[drive_mapping[self_dev_id]]), idx, 0, count, cache))
        {
            break;
        }
    if (i == 5)
    {
        printk("AHCI Read Error! Read %d %d", count, idx);
        while (true)
            ;
    }
    flush_cache(cache);
    flush_cache(cache + 0x1000);
    memcpy(cache, buf, count * 512);
}

static void ahci_blockdev_write(dev_t self_dev_id, void *dev, void *buf, size_t count, int idx, int flags)
{
    memcpy(buf, cache, count * 512);
    flush_cache(cache);
    flush_cache(cache + 0x1000);

    int i;
    for (i = 0; i < 5; i++)
        if (ahci_write(&(hba_mem_address->ports[drive_mapping[self_dev_id]]), idx, 0, count, cache))
        {
            break;
        }
    if (i == 5)
    {
        printk("AHCI Write Error!");
        while (true)
            ;
    }
}

void init_ahci()
{
    struct pci_device_structure_general_device_t *ahci_devs[8];
    uint32_t ahci_count;
    kinfo("ahci_count = %d", ahci_count);
    pci_get_device_structure(0x1, 0x6, ahci_devs, &ahci_count);
    struct pci_device_structure_general_device_t *ahci_pci = ahci_devs[0];

    ahci_bus = ahci_pci->header.bus;
    ahci_slot = ahci_pci->header.device;
    ahci_func = ahci_pci->header.func;

    if (!ahci_count)
    {
        kinfo("Couldn't find AHCI Controller");
        return;
    }
    cache_line_size = get_cache_line_size();
    kinfo("cache line size = %d", cache_line_size);
    hba_mem_address = (HBA_MEM *)phy_2_virt(pci_read_config(ahci_bus, ahci_slot, ahci_func, 0x10 + 4 * 5));
    vmm_mmap((uint64_t)get_cr3(), true, (uint64_t)hba_mem_address, virt_2_phy(hba_mem_address), PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_PWT | PAGE_PCD, false, true);
    kinfo("HBA Address has been Mapped in %08x ", hba_mem_address);
    // 设置允许中断产生
    uint32_t conf = pci_read_config(ahci_bus, ahci_slot, ahci_func, 0x04);
    conf &= 0xffff0000;
    conf |= 0x7;
    pci_write_config(ahci_bus, ahci_slot, ahci_func, 0x04, conf);

    // 设置HBA中 GHC控制器的 AE（AHCI Enable）位，关闭AHCI控制器的IDE仿真模式
    hba_mem_address->ghc |= (1 << 31);
    kinfo("AHCI Enable = %08x", (hba_mem_address->ghc & (1 << 31)) >> 31);

    ahci_search_ports(hba_mem_address);

    ahci_ports_base_addr = AHCI_MAPPING_BASE;

    cache = kalloc(1048576);
    kinfo("AHCI port base address has been alloced in %#018lx !", ahci_ports_base_addr);
    kinfo("Total ports are %d. The Useable Ports:", port_total);

    for (uint32_t i = 0; i < port_total; i++)
    {
        kinfo("%d ", ports[i]);
        port_rebase(&(hba_mem_address->ports[ports[i]]), ports[i]);
    }

    for (uint32_t i = 0; i < port_total; i++)
    {
        SATA_ident_t buf;
        int a = ahci_identify(&(hba_mem_address->ports[ports[i]]), &buf);
        if (!a)
        {
            kinfo("SATA Drive %d identify error.", ports[i]);
            continue;
        }
        kinfo("ports %d: total sector = %d", ports[i], buf.lba_capacity);
        dev_t drive = device_install(DEV_BLOCK, DEV_SATA_DISK, NULL, "SATADISK", 0, NULL, ahci_blockdev_read, ahci_blockdev_write);
        kinfo("drive: %d", drive);
        drive_mapping[drive] = ports[i];
    }
}