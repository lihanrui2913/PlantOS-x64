#include "driver/ahci.h"

#define AHCI_GHC_RST (0x00000001) /* reset controller; self-clear */
#define AHCI_GHC_IE (0x00000002)  /* global IRQ enable */
#define AHCI_GHC_AE (0x80000000)  /* AHCI enabled */

#define AHCI_PORT_CMD_ST 0x00000001  // Start
#define AHCI_PORT_CMD_SUD 0x00000002 // Spin-Up Device
#define AHCI_PORT_CMD_POD 0x00000004 // Power On Device
#define AHCI_PORT_CMD_CLO 0x00000008 // Command List Override
#define AHCI_PORT_CMD_FRE 0x00000010 // FIS Receive Enable
#define AHCI_PORT_CMD_FR 0x00004000  // FIS Receive Running
#define AHCI_PORT_CMD_CR 0x00008000  // Command List Running

#define AHCI_PORT_DEV_BUSY 0x80
#define AHCI_PORT_DEV_DRQ 0x08

#define AHCI_PORT_IST_TFES 0x40000000 // Task File Error Status

#define AHCI_PORT_SIG_ATA 0x00000101   // SATA drive
#define AHCI_PORT_SIG_ATAPI 0xEB140101 // SATAPI drive
#define AHCI_PORT_SIG_SEMB 0xC33C0101  // Enclosure management bridge
#define AHCI_PORT_SIG_PM 0x96690101    // Port multiplier

#define ATA_CMD_READ_DMA_EXT 0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35
#define ATA_CMD_IDENTIFY_DEVICE 0xEC

void AHCICommandRST(AHCI_HBA_PORT *port)
{
    // Clear ST
    port->CMD &= ~AHCI_PORT_CMD_ST;
    // Clear FRE
    port->CMD &= ~AHCI_PORT_CMD_FRE;
    // Wait FR and CR clear
    while (port->CMD & (AHCI_PORT_CMD_FR | AHCI_PORT_CMD_CR))
        hlt();
}
uint32_t AHCICommandEN(AHCI_HBA_PORT *port)
{
    AHCICommandRST(port);

    uint32_t cmd = port->CMD;
    cmd |= AHCI_PORT_CMD_FRE;
    cmd |= AHCI_PORT_CMD_SUD;
    cmd |= AHCI_PORT_CMD_ST;
    port->CMD = cmd;
    // Wait for LINK UP
    int t = 100000;
    while (t--)
        while (1)
        {
            if ((port->SAS & 7) == 3)
                return 0;
            if (t <= 0)
                break;
        }
    kerror("AHCI PORT LINK DOWN\n");
    return -1;
}
uint32_t AHCICommandWR(uint32_t cmd)
{
    switch (cmd)
    {
    case ATA_CMD_WRITE_DMA_EXT:
        return 1;
    }
    return 0;
}
uint32_t OperationATA(AHCI_HBA_PORT *port, uint64_t lba, uint16_t count, uint32_t cmd, void *buf)
{
    if (!count)
        return 0;
    if (count > 128)
        count = 128;
    if (cmd == ATA_CMD_IDENTIFY_DEVICE)
        count = 1;

    port->IST = -1;
    int slot = 0; // SearchCMD
    int t = 0;

    AHCI_COMMAND_HEAD *cmdh = (AHCI_COMMAND_HEAD *)(&port->CLB);
    cmdh += slot;
    cmdh->CFL = 5; // sizeof(FIS_REG_H2D) / sizeof(uint32_t)
    cmdh->WRT = AHCICommandWR(cmd);
    cmdh->DTL = ((count - 1) >> 4) + 1; // UPPER BOUND (count / 16)

    AHCI_COMMAND_TABLE *tbl = (AHCI_COMMAND_TABLE *)(&cmdh->TBL);
    memset(tbl, 0, sizeof(AHCI_COMMAND_TABLE) + (cmdh->DTL * sizeof(AHCI_PRDT_ENTRY)));

    uint64_t bufAddr = (uint64_t)buf;
    uint16_t count1 = count;
    uint32_t i = 0;
    while (count1)
    {
        uint32_t cnt = (count1 < 16) ? count1 : 16;
        tbl->PRD[i].DBA = bufAddr;
        tbl->PRD[i].DBC = (cnt << 9) - 1;
        tbl->PRD[i].IOC = 0; // Wrong ?
        count1 -= cnt;
        bufAddr += ((uint64_t)cnt) << 9;
        i++;
    }

    AHCI_FIS_H2D *fis = &tbl->FIS;
    memset(fis, 0, sizeof(AHCI_FIS_H2D));

    fis->TYP = 0x27; // H2D
    fis->CCC = 1;    // Command
    fis->CMD = cmd;
    fis->FTL = 1;

    fis->BA0 = (lba >> 0x00) & 0xFF;
    fis->BA1 = (lba >> 0x08) & 0xFF;
    fis->BA2 = (lba >> 0x10) & 0xFF;
    fis->DVC = 1 << 6; // LBA MODE
    fis->BA3 = (lba >> 0x18) & 0xFF;
    fis->BA4 = (lba >> 0x20) & 0xFF;
    fis->BA5 = (lba >> 0x28) & 0xFF;

    fis->CNT = count;

    port->SAE = port->SAE;
    // The below loop waits until the prot is no longer busy before issuing a new command
    t = 100000;
    while (t--)
        pause();
    while ((port->TFD & (AHCI_PORT_DEV_DRQ | AHCI_PORT_DEV_BUSY)))
    {
        if (t <= 0)
        {
            kerror("AHCI WAIT DEVICE BSY TIMEOUT\n");
            return 1 << 16; // Timeout
        }
    }
    port->CIS = 1 << slot;

    // Wait for completion
    t = 100000;
    while (t--)
        pause();

    while ((port->CIS & (1 << slot)) && !(port->IST & AHCI_PORT_IST_TFES))
    {
        pause();
    }
    if (port->IST & AHCI_PORT_IST_TFES)
    {
        kerror("Read disk error");
        return 2 << 16;
    }

    return count;
}

// 读设备
int AHCIDeviceRead(dev_t self_dev_id, void *dev, void *buf, size_t count, uint64_t idx, int flags)
{
    return OperationATA(dev, idx, count, ATA_CMD_READ_DMA_EXT, buf);
}

// 写设备
int AHCIDeviceWrite(dev_t self_dev_id, void *dev, void *buf, size_t count, uint64_t idx, int flags)
{
    return OperationATA(dev, idx, count, ATA_CMD_WRITE_DMA_EXT, buf);
}

void init_ahci()
{
    kinfo("Initializing AHCI");

    struct pci_device_structure_header_t *ahci_devs[8];
    uint32_t ahci_count = 0;
    pci_get_device_structure(0x01, 0x06, ahci_devs, &ahci_count);

    for (uint32_t i = 0; i < ahci_count; i++)
    {
        struct pci_device_structure_general_device_t *ahci_pci = (struct pci_device_structure_general_device_t *)ahci_devs[i];
        vmm_mmap((uint64_t)get_cr3(), true, AHCI_MAPPING_BASE, ((uint64_t)ahci_pci->BAR5 & PAGE_2M_MASK), PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W, false, true);
        uint64_t iobase = AHCI_MAPPING_BASE + (uint64_t)ahci_pci->BAR5 - ((uint64_t)ahci_pci->BAR5 & PAGE_2M_MASK);

        AHCI_CONTROLLER *ctrl = (AHCI_CONTROLLER *)kalloc(sizeof(AHCI_CONTROLLER));
        memset(ctrl, 0, sizeof(AHCI_CONTROLLER));

        ctrl->DVC = ahci_pci;
        ctrl->HBA = (AHCI_HBA_MEMORY *)iobase;

        ctrl->HBA->GHC |= AHCI_GHC_AE;
        uint32_t pi = ctrl->HBA->PTI;
        uint32_t pn = 0;
        while (pi)
        {
            if (pi & 1)
            {
                AHCI_HBA_PORT *port = &(ctrl->HBA->PRT[pn]);
                uint32_t sas = port->SAS;
                uint8_t ipm = (sas >> 8) & 0xF;
                uint8_t det = (sas >> 0) & 0xF;
                if (port->SIG == AHCI_PORT_SIG_ATA)
                {
                    kdebug("Found SATA drive");
                    // Maybe not need to realloc
                    if (AHCICommandEN(port))
                    {
                        AHCICommandRST(port);
                        goto AHCI_NEXT_PORT;
                    }
                    kdebug("Installing SATA drive");

                    device_install(DEV_BLOCK, DEV_DISK, port, "DISK", 0, NULL, AHCIDeviceRead, AHCIDeviceWrite);
                }
                else if (port->SIG == AHCI_PORT_SIG_ATAPI)
                {
                    kdebug("Found SATAPI drive");
                    // Maybe not need to realloc
                    if (AHCICommandEN(port))
                    {
                        AHCICommandRST(port);
                        goto AHCI_NEXT_PORT;
                    }

                    kdebug("Installing SATAPI drive");
                    device_install(DEV_BLOCK, DEV_CD, port, "CDROM", 0, NULL, AHCIDeviceRead, AHCIDeviceWrite);
                }
            }
        AHCI_NEXT_PORT:;
            pi >>= 1;
            pn++;
        }
    }

    ksuccess("AHCI initialized");
}
