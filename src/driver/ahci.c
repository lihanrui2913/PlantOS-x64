#include "driver/device.h"
#include "driver/ahci.h"
#include "driver/apic.h"
#include "irq.h"

// ATA

void sata_read_error(struct hba_port *port)
{
    uint32_t tfd = port->regs[HBA_RPxTFD];
    port->device->last_error = (tfd >> 8) & 0xff;
    port->device->last_status = tfd & 0xff;
}

int __sata_buffer_io(struct hba_port *port,
                     uint64_t lba,
                     void *buffer,
                     uint32_t size,
                     int write)
{
    struct hba_cmdh *header;
    struct hba_cmdt *table;
    int slot = hba_prepare_cmd(port, &table, &header, buffer, size);
    int bitmask = 1 << slot;

    // 确保端口是空闲的
    wait_until(!(port->regs[HBA_RPxTFD] & (HBA_PxTFD_BSY | HBA_PxTFD_DRQ)));

    port->regs[HBA_RPxIS] = 0;

    header->options |= HBA_CMDH_WRITE * (write == 1);

    uint16_t count = ICEIL(size, port->device->block_size);
    struct sata_reg_fis *fis = (struct sata_reg_fis *)table->command_fis;

    if ((port->device->flags & HBA_DEV_FEXTLBA))
    {
        // 如果该设备支持48位LBA寻址
        sata_create_fis(
            fis, write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT, lba, count);
    }
    else
    {
        sata_create_fis(fis, write ? ATA_WRITE_DMA : ATA_READ_DMA, lba, count);
    }
    /*
          确保我们使用的是LBA寻址模式
          注意：在ACS-3中（甚至在ACS-4），只有在(READ/WRITE)_DMA_EXT指令中明确注明了需要将这一位置位
        而并没有在(READ/WRITE)_DMA注明。
          但是这在ACS-2中是有的！于是这也就导致了先前的测试中，LBA=0根本无法访问，因为此时
        的访问模式是在CHS下，也就是说LBA=0 => Sector=0，是非法的。
          所以，我猜测，这要么是QEMU/VirtualBox根据ACS-2来编写的AHCI模拟，
        要么是标准出错了（毕竟是working draft）
    */
    fis->dev = (1 << 6);

    int retries = 0;

    while (retries < MAX_RETRY)
    {
        port->regs[HBA_RPxCI] = bitmask;

        wait_until(!(port->regs[HBA_RPxCI] & bitmask));

        if ((port->regs[HBA_RPxTFD] & HBA_PxTFD_ERR))
        {
            // 有错误
            sata_read_error(port);
            retries++;
        }
        else
        {
            kfree(table);
            return 1;
        }
    }

fail:
    kfree(table);
    return 0;
}

int sata_read_buffer(struct hba_port *port,
                     uint64_t lba,
                     void *buffer,
                     uint32_t size)
{
    return __sata_buffer_io(port, lba, buffer, size, 0);
}

int sata_write_buffer(struct hba_port *port,
                      uint64_t lba,
                      void *buffer,
                      uint32_t size)
{
    return __sata_buffer_io(port, lba, buffer, size, 1);
}

// ATAPI

void scsi_create_packet12(struct scsi_cdb12 *cdb,
                          uint8_t opcode,
                          uint32_t lba,
                          uint32_t alloc_size)
{
    memset(cdb, 0, sizeof(*cdb));
    cdb->opcode = opcode;
    cdb->lba_be = SCSI_FLIP(lba);
    cdb->length = SCSI_FLIP(alloc_size);
}

void scsi_create_packet16(struct scsi_cdb16 *cdb,
                          uint8_t opcode,
                          uint64_t lba,
                          uint32_t alloc_size)
{
    memset(cdb, 0, sizeof(*cdb));
    cdb->opcode = opcode;
    cdb->lba_be_hi = SCSI_FLIP((uint32_t)(lba >> 32));
    cdb->lba_be_lo = SCSI_FLIP((uint32_t)lba);
    cdb->length = SCSI_FLIP(alloc_size);
}

void scsi_parse_capacity(struct hba_device *device, uint32_t *parameter)
{
    device->max_lba = SCSI_FLIP(*(parameter + 1));
    device->block_size = SCSI_FLIP(*(parameter + 2));
}

void __scsi_buffer_io(struct hba_port *port,
                      uint64_t lba,
                      void *buffer,
                      uint32_t size,
                      int write)
{
    struct hba_cmdh *header;
    struct hba_cmdt *table;
    int slot = hba_prepare_cmd(port, &table, &header, buffer, size);
    int bitmask = 1 << slot;

    // 确保端口是空闲的
    wait_until(!(port->regs[HBA_RPxTFD] & (HBA_PxTFD_BSY | HBA_PxTFD_DRQ)));

    port->regs[HBA_RPxIS] = 0;

    header->options |= (HBA_CMDH_WRITE * (write == 1)) | HBA_CMDH_ATAPI;

    uint32_t count = ICEIL(size, port->device->block_size);

    struct sata_reg_fis *fis = (struct sata_reg_fis *)table->command_fis;
    void *cdb = table->atapi_cmd;
    sata_create_fis(fis, ATA_PACKET, (size << 8), 0);
    fis->feature = 1 | ((!write) << 2);

    if (port->device->cbd_size == 16)
    {
        scsi_create_packet16((struct scsi_cdb16 *)cdb,
                             write ? SCSI_WRITE_BLOCKS_16 : SCSI_READ_BLOCKS_16,
                             lba,
                             count);
    }
    else
    {
        scsi_create_packet12((struct scsi_cdb12 *)cdb,
                             write ? SCSI_WRITE_BLOCKS_12 : SCSI_READ_BLOCKS_12,
                             lba,
                             count);
    }

    // field: cdb->misc1
    *((uint8_t *)cdb + 1) = 3 << 5; // RPROTECT=011b 禁用保护检查

    int retries = 0;

    while (retries < MAX_RETRY)
    {
        port->regs[HBA_RPxCI] = bitmask;

        wait_until(!(port->regs[HBA_RPxCI] & bitmask));

        if ((port->regs[HBA_RPxTFD] & HBA_PxTFD_ERR))
        {
            // 有错误
            sata_read_error(port);
            retries++;
        }
        else
        {
            kfree(table);
            return;
        }
    }

fail:
    kfree(table);
    return;
}

int scsi_read_buffer(struct hba_port *port,
                     uint64_t lba,
                     void *buffer,
                     uint32_t size)
{
    __scsi_buffer_io(port, lba, buffer, size, 0);
    return size;
}

int scsi_write_buffer(struct hba_port *port,
                      uint64_t lba,
                      void *buffer,
                      uint32_t size)
{
    __scsi_buffer_io(port, lba, buffer, size, 1);
    return size;
}

// MAIN

#define HBA_FIS_SIZE 256
#define HBA_CLB_SIZE 1024

struct pci_device_structure_header_t *ahci_dev[32];
uint32_t ahci_count;

struct ahci_hba hba;

hardware_intr_controller ahci_hardware_controller = {
    .ack = apic_ioapic_edge_ack,
    .disable = apic_ioapic_disable,
    .enable = apic_ioapic_enable,
    .install = apic_ioapic_install,
    .uninstall = apic_ioapic_uninstall,
};

void ahci_handler(uint64_t irq_num, uint64_t parameter, struct pt_regs *regs)
{
    // kinfo("AHCI HANDLER IRQ = %d", irq_num);
}

void __hba_reset_port(hba_reg_t *port_reg)
{
    // 根据：SATA-AHCI spec section 10.4.2 描述的端口重置流程
    port_reg[HBA_RPxCMD] &= ~HBA_PxCMD_ST;
    port_reg[HBA_RPxCMD] &= ~HBA_PxCMD_FRE;

    int cnt = wait_until_expire(!(port_reg[HBA_RPxCMD] & HBA_PxCMD_CR), 500000);
    if (cnt)
    {
        return;
    }
    // 如果port未响应，则继续执行重置
    port_reg[HBA_RPxSCTL] = (port_reg[HBA_RPxSCTL] & ~0xf) | 1;
    int t = 100000;
    while (--t)
        nop();
    port_reg[HBA_RPxSCTL] &= ~0xf;
}

int ahci_init_device(struct hba_port *port);

int ahci_read(void *dev, void *buf, size_t count, idx_t idx, int flags)
{
    struct hba_port *port = (struct hba_port *)dev;
    port->device->ops.read_buffer(port, idx, buf, count);
}

int ahci_write(void *dev, void *buf, size_t count, idx_t idx, int flags)
{
    struct hba_port *port = (struct hba_port *)dev;
    port->device->ops.write_buffer(port, idx, buf, count);
}

void init_ahci()
{
    pci_get_device_structure(0x01, 0x06, ahci_dev, &ahci_count);

    for (int i = 0; i < ahci_count; i++)
    {
        struct pci_device_structure_general_device_t *ahci = (struct pci_device_structure_general_device_t *)ahci_dev[i];
        uint32_t bar5 = ahci->BAR5;

        uint32_t cmd = pci_read_config(ahci->header.bus, ahci->header.device, ahci->header.func, 0x4);
        cmd |= (PCI_RCMD_MM_ACCESS | PCI_RCMD_DISABLE_INTR | PCI_RCMD_BUS_MASTER);
        pci_write_config(ahci->header.bus, ahci->header.device, ahci->header.func, 0x4, cmd);

        struct msi_desc_t msi_desc;
        msi_desc.pci_dev = (struct pci_device_structure_header_t *)ahci;
        msi_desc.assert = 1;
        msi_desc.edge_trigger = 1;
        msi_desc.processor = 0;
        msi_desc.pci.msi_attribute.is_64 = 1;
        msi_desc.irq_num = AHCI_IRQ_NUM;
        int retval = pci_enable_msi(&msi_desc);
        kdebug("Installed AHCI irq, retval = %d", retval);

        struct apic_IO_APIC_RTE_entry entry;
        apic_make_rte_entry(&entry, AHCI_IRQ_NUM, IO_APIC_FIXED, DEST_PHYSICAL, IDLE, POLARITY_HIGH, IRR_RESET, EDGE_TRIGGER, MASKED, 0);
        irq_register(AHCI_IRQ_NUM, &entry, &ahci_handler, 0, &ahci_hardware_controller, "AHCI");

        retval = pci_start_msi(ahci);
        kdebug("Enabled AHCI irq, retval = %d", retval);

        memset(&hba, 0, sizeof(hba));

        vmm_mmap((uint64_t)get_cr3(), true, (uint64_t)AHCI_MAPPING_BASE, (bar5 & PAGE_2M_MASK), PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W, false, true);
        hba.base = (hba_reg_t *)(AHCI_MAPPING_BASE + bar5 - (bar5 & PAGE_2M_MASK));

        hba.base[HBA_RGHC] |= HBA_RGHC_RESET;
        wait_until(!(hba.base[HBA_RGHC] & HBA_RGHC_RESET));

        hba.base[HBA_RGHC] |= HBA_RGHC_ahci_ENABLE;
        hba.base[HBA_RGHC] |= HBA_RGHC_INTR_ENABLE;

        hba_reg_t cap = hba.base[HBA_RCAP];
        hba_reg_t pmap = hba.base[HBA_RPI];

        hba.ports_num = (cap & 0x1f) + 1;  // CAP.PI
        hba.cmd_slots = (cap >> 8) & 0x1f; // CAP.NCS
        hba.version = hba.base[HBA_RVER];
        hba.ports_bmp = pmap;

        uintptr_t clb_pg_addr, fis_pg_addr, clb_pa, fis_pa;
        for (size_t i = 0, fisp = 0, clbp = 0; i < 32;
             i++, pmap >>= 1, fisp = (fisp + 1) % 16, clbp = (clbp + 1) % 4)
        {
            if (!(pmap & 0x1))
            {
                continue;
            }

            struct hba_port *port =
                (struct hba_port *)kalloc(sizeof(struct hba_port));
            hba_reg_t *port_regs =
                (hba_reg_t *)(&hba.base[HBA_RPBASE + i * HBA_RPSIZE]);

            __hba_reset_port(port_regs);

            if (!clbp)
            {
                // 每页最多4个命令队列
                vmm_mmap((uint64_t)get_cr3(), true, (uint64_t)AHCI_MAPPING_BASE + PAGE_2M_SIZE, 0, PAGE_4K_SIZE, PAGE_PRESENT | PAGE_R_W, false, true);
                clb_pa = physical_mapping(AHCI_MAPPING_BASE + PAGE_2M_SIZE);
                clb_pg_addr = (uintptr_t)(AHCI_MAPPING_BASE + PAGE_2M_SIZE);
                memset((void *)clb_pg_addr, 0, PAGE_4K_SIZE);
            }
            if (!fisp)
            {
                // 每页最多16个FIS
                vmm_mmap((uint64_t)get_cr3(), true, (uint64_t)AHCI_MAPPING_BASE + PAGE_2M_SIZE + PAGE_4K_SIZE, 0, PAGE_4K_SIZE, PAGE_PRESENT | PAGE_R_W, false, true);
                fis_pa = physical_mapping(AHCI_MAPPING_BASE + PAGE_2M_SIZE + PAGE_4K_SIZE);
                fis_pg_addr = (uintptr_t)(AHCI_MAPPING_BASE + PAGE_2M_SIZE + PAGE_4K_SIZE);
                memset((void *)fis_pg_addr, 0, PAGE_4K_SIZE);
            }

            /* 重定向CLB与FIS */
            port_regs[HBA_RPxCLB] = clb_pa + clbp * HBA_CLB_SIZE;
            port_regs[HBA_RPxFB] = fis_pa + fisp * HBA_FIS_SIZE;

            *port = (struct hba_port){.regs = port_regs,
                                      .ssts = port_regs[HBA_RPxSSTS],
                                      .cmdlst = (struct hba_cmdh *)(clb_pg_addr + clbp * HBA_CLB_SIZE),
                                      .fis = (void *)(fis_pg_addr + fisp * HBA_FIS_SIZE)};

            port_regs[HBA_RPxCI] = 0;
            port_regs[HBA_RPxSERR] = -1;

            port_regs[HBA_RPxIE] |= (HBA_PxINTR_D2HR);

            hba.ports[i] = port;

            if (!HBA_RPxSSTS_IF(port->ssts))
            {
                continue;
            }

            wait_until(!(port_regs[HBA_RPxCMD] & HBA_PxCMD_CR));
            port_regs[HBA_RPxCMD] |= HBA_PxCMD_FRE;
            port_regs[HBA_RPxCMD] |= HBA_PxCMD_ST;

            if (!ahci_init_device(port))
            {
                kerror("fail to init device");
            }
        }
    }

    ksuccess("AHCI initialized");
}

int ahci_init_device(struct hba_port *port)
{
    /* 发送ATA命令，参考：SATA AHCI Spec Rev.1.3.1, section 5.5 */
    struct hba_cmdt *cmd_table;
    struct hba_cmdh *cmd_header;

    // 确保端口是空闲的
    wait_until(!(port->regs[HBA_RPxTFD] & (HBA_PxTFD_BSY)));

    // 预备DMA接收缓存，用于存放HBA传回的数据
    uint16_t *data_in = (uint16_t *)kalloc(512);

    int slot = hba_prepare_cmd(port, &cmd_table, &cmd_header, data_in, 512);

    // 清空任何待响应的中断
    port->regs[HBA_RPxIS] = 0;
    port->device = kalloc(sizeof(struct hba_device));

    // 在命令表中构建命令FIS
    struct sata_reg_fis *cmd_fis = (struct sata_reg_fis *)cmd_table->command_fis;

    // 根据设备类型使用合适的命令
    if (port->regs[HBA_RPxSIG] == HBA_DEV_SIG_ATA)
    {
        // ATA 一般为硬盘
        kinfo("Found ATA device");
        sata_create_fis(cmd_fis, ATA_IDENTIFY_DEVICE, 0, 0);
    }
    else if (port->regs[HBA_RPxSIG] == HBA_DEV_SIG_ATAPI)
    {
        // ATAPI 一般为光驱，软驱，或者磁带机0
        kinfo("Found ATAPI device");
        port->device->flags |= HBA_DEV_FATAPI;
        sata_create_fis(cmd_fis, ATA_IDENTIFY_PAKCET_DEVICE, 0, 0);
    }
    else
    {
        return 0;
    }

    // PxCI寄存器置位，告诉HBA这儿有个数据需要发送到SATA端口
    port->regs[HBA_RPxCI] = (1 << slot);

    wait_until(!(port->regs[HBA_RPxCI] & (1 << slot)));

    if ((port->regs[HBA_RPxTFD] & HBA_PxTFD_ERR))
    {
        // 有错误
        sata_read_error(port);
        goto fail;
    }

    /*
        等待数据到达内存
        解析IDENTIFY DEVICE传回来的数据。
          参考：
            * ATA/ATAPI Command Set - 3 (ACS-3), Section 7.12.7
    */
    ahci_parse_dev_info(port->device, data_in);

    if (!(port->device->flags & HBA_DEV_FATAPI))
    {
        goto done;
    }

    /*
        注意：ATAPI设备是无法通过IDENTIFY PACKET DEVICE 获取容量信息的。
        我们需要使用SCSI命令的READ_CAPACITY(16)进行获取。
        步骤如下：
            1. 因为ATAPI走的是SCSI，而AHCI对此专门进行了SATA的封装，
               也就是通过SATA的PACKET命令对SCSI命令进行封装。所以我们
               首先需要构建一个PACKET命令的FIS
            2. 接着，在ACMD中构建命令READ_CAPACITY的CDB - 一种SCSI命令的封装
            3. 然后把cmd_header->options的A位置位，表示这是一个送往ATAPI的命令。
                一点细节：
                    1. HBA往底层SATA控制器发送PACKET FIS
                    2. SATA控制器回复PIO Setup FIS
                    3. HBA读入ACMD中的CDB，打包成Data FIS进行答复
                    4. SATA控制器解包，拿到CDB，通过SCSI协议转发往ATAPI设备。
                    5. ATAPI设备回复Return Parameter，SATA通过DMA Setup FIS
                       发起DMA请求，HBA介入，将Return Parameter写入我们在PRDT
                       里设置的data_in位置。
            4. 最后照常等待HBA把结果写入data_in，然后直接解析就好了。
          参考：
            * ATA/ATAPI Command Set - 3 (ACS-3), Section 7.18
            * SATA AHCI HBA Spec, Section 5.3.7
            * SCSI Command Reference Manual, Section 3.26
    */
    struct scsi_cdb16 *cdb16 = (struct scsi_cdb16 *)cmd_table->atapi_cmd;

    sata_create_fis(cmd_fis, ATA_PACKET, 512 << 8, 0);
    scsi_create_packet16(cdb16, SCSI_READ_CAPACITY_16, 0, 512);

    cdb16->misc1 = 0x10; // service action
    cmd_header->transferred_size = 0;
    cmd_header->options |= HBA_CMDH_ATAPI;

    port->regs[HBA_RPxCI] = (1 << slot);
    wait_until(!(port->regs[HBA_RPxCI] & (1 << slot)));

    if ((port->regs[HBA_RPxTFD] & HBA_PxTFD_ERR))
    {
        // 有错误
        sata_read_error(port);
        goto fail;
    }

    scsi_parse_capacity(port->device, (uint32_t *)data_in);

done:
    ahci_register_ops(port);
    device_install(DEV_BLOCK, DEV_DISK, port, "AHCI DISK", 0, NULL, ahci_read, ahci_write);

    kfree(data_in);
    kfree(cmd_table);

    return 1;

fail:
    kfree(data_in);
    kfree(cmd_table);

    return 0;
}

int ahci_identify_device(struct hba_port *port)
{
    // 用于重新识别设备（比如在热插拔的情况下）
    kfree(port->device);
    return ahci_init_device(port);
}

void ahci_register_ops(struct hba_port *port)
{
    port->device->ops.identify = ahci_identify_device;
    if (!(port->device->flags & HBA_DEV_FATAPI))
    {
        port->device->ops.read_buffer = sata_read_buffer;
        port->device->ops.write_buffer = sata_write_buffer;
    }
    else
    {
        port->device->ops.read_buffer = scsi_read_buffer;
        port->device->ops.write_buffer = scsi_write_buffer;
    }
}

/* UTILS */

#define IDDEV_OFFMAXLBA 60
#define IDDEV_OFFMAXLBA_EXT 230
#define IDDEV_OFFLSECSIZE 117
#define IDDEV_OFFWWN 108
#define IDDEV_OFFSERIALNUM 10
#define IDDEV_OFFMODELNUM 27
#define IDDEV_OFFADDSUPPORT 69
#define IDDEV_OFFALIGN 209
#define IDDEV_OFFLPP 106
#define IDDEV_OFFCAPABILITIES 49

void ahci_parse_dev_info(struct hba_device *dev_info, uint16_t *data)
{
    dev_info->max_lba = *((uint32_t *)(data + IDDEV_OFFMAXLBA));
    dev_info->block_size = *((uint32_t *)(data + IDDEV_OFFLSECSIZE));
    dev_info->cbd_size = (*data & 0x3) ? 16 : 12;
    dev_info->wwn = *(uint64_t *)(data + IDDEV_OFFWWN);
    dev_info->block_per_sec = 1 << (*(data + IDDEV_OFFLPP) & 0xf);
    dev_info->alignment_offset = *(data + IDDEV_OFFALIGN) & 0x3fff;
    dev_info->capabilities = *((uint32_t *)(data + IDDEV_OFFCAPABILITIES));

    if (!dev_info->block_size)
    {
        dev_info->block_size = 512;
    }

    if ((*(data + IDDEV_OFFADDSUPPORT) & 0x8))
    {
        dev_info->max_lba = *((uint64_t *)(data + IDDEV_OFFMAXLBA_EXT));
        dev_info->flags |= HBA_DEV_FEXTLBA;
    }

    ahci_parsestr(dev_info->serial_num, data + IDDEV_OFFSERIALNUM, 10);
    ahci_parsestr(dev_info->model, data + IDDEV_OFFMODELNUM, 20);
}

void ahci_parsestr(char *str, uint16_t *reg_start, int size_word)
{
    int j = 0;
    for (int i = 0; i < size_word; i++, j += 2)
    {
        uint16_t reg = *(reg_start + i);
        str[j] = (char)(reg >> 8);
        str[j + 1] = (char)(reg & 0xff);
    }
    str[j - 1] = '\0';
}

int __get_free_slot(struct hba_port *port)
{
    hba_reg_t pxsact = port->regs[HBA_RPxSACT];
    hba_reg_t pxci = port->regs[HBA_RPxCI];
    hba_reg_t free_bmp = pxsact | pxci;
    uint32_t i = 0;
    for (; i <= hba.cmd_slots && (free_bmp & 0x1); i++, free_bmp >>= 1)
        ;
    return i | -(i > hba.cmd_slots);
}

void sata_create_fis(struct sata_reg_fis *cmd_fis,
                     uint8_t command,
                     uint64_t lba,
                     uint16_t sector_count)
{
    cmd_fis->head.type = SATA_REG_FIS_H2D;
    cmd_fis->head.options = SATA_REG_FIS_COMMAND;
    cmd_fis->head.status_cmd = command;
    cmd_fis->dev = 0;

    cmd_fis->lba0 = SATA_LBA_COMPONENT(lba, 0);
    cmd_fis->lba8 = SATA_LBA_COMPONENT(lba, 8);
    cmd_fis->lba16 = SATA_LBA_COMPONENT(lba, 16);
    cmd_fis->lba24 = SATA_LBA_COMPONENT(lba, 24);

    cmd_fis->lba32 = SATA_LBA_COMPONENT(lba, 32);
    cmd_fis->lba40 = SATA_LBA_COMPONENT(lba, 40);

    cmd_fis->count = sector_count;
}

int hba_prepare_cmd(struct hba_port *port,
                    struct hba_cmdt **cmdt,
                    struct hba_cmdh **cmdh,
                    void *buffer,
                    unsigned int size)
{
    int slot = __get_free_slot(port);

    // 构建命令头（Command Header）和命令表（Command Table）
    struct hba_cmdh *cmd_header = &port->cmdlst[slot];
    struct hba_cmdt *cmd_table = (struct hba_cmdt *)kalloc(sizeof(struct hba_cmdt));

    memset(cmd_header, 0, sizeof(*cmd_header));

    // 将命令表挂到命令头上
    cmd_header->cmd_table_base = physical_mapping((uint64_t)cmd_table);
    cmd_header->options =
        HBA_CMDH_FIS_LEN(sizeof(struct sata_reg_fis)) | HBA_CMDH_CLR_BUSY;

    if (buffer)
    {
        cmd_header->prdt_len = 1;
        cmd_table->entries[0] =
            (struct hba_prdte){.data_base = physical_mapping((uint64_t)buffer),
                               .byte_count = size - 1};
    }

    *cmdh = cmd_header;
    *cmdt = cmd_table;

    return slot;
}
