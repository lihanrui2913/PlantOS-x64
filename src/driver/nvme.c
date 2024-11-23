#include <driver/device.h>
#include <driver/nvme.h>
#include <driver/pci.h>
#include <display/kprint.h>
#include <mm/memory.h>

#define NVME_CSTS_FATAL (1U << 1)
#define NVME_CSTS_RDY (1U << 0)

#define NVME_SQE_OPC_ADMIN_CREATE_IO_SQ 1U
#define NVME_SQE_OPC_ADMIN_CREATE_IO_CQ 5U
#define NVME_SQE_OPC_ADMIN_IDENTIFY 6U

#define NVME_SQE_OPC_IO_WRITE 1U
#define NVME_SQE_OPC_IO_READ 2U

#define NVME_ADMIN_IDENTIFY_CNS_ID_NS 0x00U
#define NVME_ADMIN_IDENTIFY_CNS_ID_CTRL 0x01U
#define NVME_ADMIN_IDENTIFY_CNS_ACT_NSL 0x02U

void *NVME_DMA_MEMORY = NULL;

void NVMEConfigureQ(NVME_CONTROLLER *ctrl, NVME_QUEUE_COMMON *q, uint32_t idx, uint32_t len)
{
    memset(q, 0, sizeof(NVME_QUEUE_COMMON));
    q->DBL = (uint32_t *)(((uint8_t *)ctrl->CAP) + 0x1000 + idx * ctrl->DST);
    q->MSK = len - 1;
}
int NVMEConfigureCQ(NVME_CONTROLLER *ctrl, NVME_COMPLETION_QUEUE *cq, uint32_t idx, uint32_t len)
{
    NVMEConfigureQ(ctrl, &cq->COM, idx, len);
    cq->CQE = 0;
    uint64_t phyAddr = (uint64_t)phy_2_virt(allocate_frame());
    cq->CQE = (NVME_COMPLETION_QUEUE_ENTRY *)(phyAddr);
    memset(cq->CQE, 0, 4096);
    cq->COM.HAD = 0;
    cq->COM.TAL = 0;
    cq->COM.PHA = 1;
    return 0;
}
int NVMEConfigureSQ(NVME_CONTROLLER *ctrl, NVME_SUBMISSION_QUEUE *sq, uint32_t idx, uint32_t len)
{
    NVMEConfigureQ(ctrl, &sq->COM, idx, len);
    sq->SQE = 0;
    uint64_t phyAddr = (uint64_t)phy_2_virt(allocate_frame());
    sq->SQE = (NVME_SUBMISSION_QUEUE_ENTRY *)(phyAddr);
    memset(sq->SQE, 0, 4096);
    sq->COM.HAD = 0;
    sq->COM.TAL = 0;
    sq->COM.PHA = 0;
    return 0;
}
int NVMEWaitingRDY(NVME_CONTROLLER *ctrl, uint32_t rdy)
{
    uint32_t csts;
    while (rdy != ((csts = ctrl->CAP->CST) & NVME_CSTS_RDY))
    {
        hlt();
        if (csts & NVME_CSTS_FATAL)
        {
            kerror("NVME FATAL ERROR DURING WAITING CONTROLLER READY\n");
            return -1;
        }
    }
    return 0;
}
NVME_COMPLETION_QUEUE_ENTRY NVMEWaitingCMD(NVME_SUBMISSION_QUEUE *sq, NVME_SUBMISSION_QUEUE_ENTRY *e)
{
    NVME_COMPLETION_QUEUE_ENTRY errcqe;
    memset(&errcqe, 0xFF, sizeof(NVME_COMPLETION_QUEUE_ENTRY));

    if (((sq->COM.HAD + 1) % (sq->COM.MSK + 1ULL)) == sq->COM.TAL)
    {
        kerror("SUBMISSION QUEUE IS FULL\n");
        return errcqe;
    }

    // Commit
    NVME_SUBMISSION_QUEUE_ENTRY *sqe = sq->SQE + sq->COM.TAL;
    memcpy(e, sqe, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    sqe->CDW0 |= sq->COM.TAL << 16;

    // Doorbell
    sq->COM.TAL++;
    sq->COM.TAL %= (sq->COM.MSK + 1ULL);
    sq->COM.DBL[0] = sq->COM.TAL;

    // Check completion
    NVME_COMPLETION_QUEUE *cq = sq->ICQ;
    while ((cq->CQE[cq->COM.HAD].STS & 1) != cq->COM.PHA)
    {
        pause();
    }

    // Consume CQE
    NVME_COMPLETION_QUEUE_ENTRY *cqe = cq->CQE + cq->COM.HAD;
    uint16_t cqNextHAD = (cq->COM.HAD + 1) % (cq->COM.MSK + 1ULL);
    if (cqNextHAD < cq->COM.HAD)
    {
        cq->COM.PHA ^= 1;
    }
    cq->COM.HAD = cqNextHAD;

    if (cqe->QHD != sq->COM.HAD)
    {
        sq->COM.HAD = cqe->QHD;
    }
    // Doorbell
    cq->COM.DBL[0] = cq->COM.HAD;
    return *cqe;
}
uint32_t NVMETransfer(NVME_NAMESPACE *ns, void *buf, uint64_t lba, uint32_t count, uint32_t write)
{
    if (!count)
        return 0;

    uint64_t bufAddr = (uint64_t)buf;
    uint32_t maxCount = (4096 / ns->BSZ) - ((bufAddr & 0xFFF) / ns->BSZ);
    if (count > maxCount)
        count = maxCount;
    if (count > ns->MXRS)
        count = ns->MXRS;

    NVME_SUBMISSION_QUEUE_ENTRY sqe;
    memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    sqe.CDW0 = write ? NVME_SQE_OPC_IO_WRITE : NVME_SQE_OPC_IO_READ;
    sqe.META = 0;
    sqe.DATA[0] = physical_mapping(bufAddr);
    sqe.DATA[1] = 0;
    sqe.NSID = ns->NSID;
    sqe.CDWA = lba;
    sqe.CDWB = lba >> 32;
    sqe.CDWC = (1UL << 31) | ((count - 1) & 0xFFFF);
    NVME_COMPLETION_QUEUE_ENTRY cqe = NVMEWaitingCMD(&ns->CTRL->ISQ, &sqe);
    if ((cqe.STS >> 1) & 0xFF)
    {
        kerror("NVME CANNOT READ\n");
        return -1;
    }
    return count;
}

int nvme_read(void *dev, void *buf, size_t count, idx_t idx, int flags)
{
    return (int)NVMETransfer(dev, buf, idx, count / 512, 0);
}

int nvme_write(void *dev, void *buf, size_t count, idx_t idx, int flags)
{
    return (int)NVMETransfer(dev, buf, idx, count / 512, 1);
}

struct pci_device_structure_header_t *nvme_dev[32];

void init_nvme()
{
    uint32_t nvme_count;
    pci_get_device_structure(0x01, 0x08, nvme_dev, &nvme_count);

    kinfo("Initializing NVME");

    NVME_CONTROLLER *ctrl;

    for (uint32_t i = 0; i < nvme_count; i++)
    {
        struct pci_device_structure_general_device_t *nvme = (struct pci_device_structure_general_device_t *)nvme_dev[i];
        uint32_t bar0 = nvme->BAR0;

        vmm_mmap((uint64_t)get_cr3(), true, (uint64_t)NVME_MAPPING_BASE, (bar0 & PAGE_2M_MASK), PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W, false, true);

        uint32_t cmd = pci_read_config(nvme->header.bus, nvme->header.device, nvme->header.func, 0x4);
        cmd |= (PCI_RCMD_MM_ACCESS | PCI_RCMD_DISABLE_INTR | PCI_RCMD_BUS_MASTER);
        pci_write_config(nvme->header.bus, nvme->header.device, nvme->header.func, 0x4, cmd);

        ctrl = (NVME_CONTROLLER *)kalloc(sizeof(NVME_CONTROLLER));
        memset(ctrl, 0, sizeof(NVME_CONTROLLER));
        ctrl->DVC = nvme;
        ctrl->CAP = (NVME_CAPABILITY *)(NVME_MAPPING_BASE + bar0 - (bar0 & PAGE_2M_MASK));
        ctrl->WTO = 500 * ((ctrl->CAP->CAP >> 24) & 0xFF);

        // RST controller
        ctrl->CAP->CC = 0;
        if (NVMEWaitingRDY(ctrl, 0))
        {
            kerror("NVME FATAL ERROR DURING CONTROLLER SHUTDOWN\n");
            goto FAILED_NVME;
        }
        ctrl->DST = 4ULL << ((ctrl->CAP->CAP >> 32) & 0xF);

        int rc = NVMEConfigureCQ(ctrl, &ctrl->ACQ, 1, 4096 / sizeof(NVME_COMPLETION_QUEUE_ENTRY));
        if (rc)
        {
            goto FAILED_NVME;
        }

        rc = NVMEConfigureSQ(ctrl, &ctrl->ASQ, 0, 4096 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
        if (rc)
        {
            goto FAILED_NVME;
        }
        ctrl->ASQ.ICQ = &ctrl->ACQ;

        ctrl->CAP->AQA = (ctrl->ACQ.COM.MSK << 16) | ctrl->ASQ.COM.MSK;
        ctrl->CAP->ASQ = physical_mapping((uint64_t)ctrl->ASQ.SQE);
        ctrl->CAP->ACQ = physical_mapping((uint64_t)ctrl->ACQ.CQE);

        ctrl->CAP->CC = 1 | (4 << 20) | (6 << 16);
        if (NVMEWaitingRDY(ctrl, 1))
        {
            kerror("NVME FATAL ERROR DURING CONTROLLER ENABLING\n");
            goto FAILED_NVME;
        }

        /* The admin queue is set up and the controller is ready. Let's figure out
           what namespaces we have. */
        // Identify Controller
        NVME_IDENTIFY_CONTROLLER *identify = (NVME_IDENTIFY_CONTROLLER *)phy_2_virt(allocate_frame());
        memset(identify, 0, 4096);

        NVME_SUBMISSION_QUEUE_ENTRY sqe;
        memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
        sqe.CDW0 = NVME_SQE_OPC_ADMIN_IDENTIFY;
        sqe.META = 0;
        sqe.DATA[0] = physical_mapping((uint64_t)identify);
        sqe.DATA[1] = 0;
        sqe.NSID = 0;
        sqe.CDWA = NVME_ADMIN_IDENTIFY_CNS_ID_CTRL;
        NVME_COMPLETION_QUEUE_ENTRY cqe = NVMEWaitingCMD(&ctrl->ASQ, &sqe);
        if ((cqe.STS >> 1) & 0xFF)
        {
            kerror("CANNOT IDENTIFY NVME CONTROLLER\n");
            goto FAILED_NVME;
        }

        char buf[41];
        memcpy(identify->SERN, buf, sizeof(identify->SERN));
        buf[sizeof(identify->SERN)] = 0;
        // OUTPUTTEXT(serialN);
        // LINEFEED();
        memcpy(identify->MODN, buf, sizeof(identify->MODN));
        buf[sizeof(identify->MODN)] = 0;
        // OUTPUTTEXT(serialN);
        // LINEFEED();

        ctrl->NSC = identify->NNAM;
        uint8_t mdts = identify->MDTS;
        deallocate_frame(physical_mapping((uint64_t)identify));

        if (ctrl->NSC == 0)
        {
            kerror("NO NAMESPACE\n");
            goto FAILED_NVME;
        }

        // Create I/O Queue
        // Create I/O CQ
        {
            uint32_t qidx = 3;
            uint32_t entryCount = 1 + (ctrl->CAP->CAP & 0xFFFF);
            if (entryCount > 4096 / sizeof(NVME_COMPLETION_QUEUE_ENTRY))
                entryCount = 4096 / sizeof(NVME_COMPLETION_QUEUE_ENTRY);
            if (NVMEConfigureCQ(ctrl, &ctrl->ICQ, qidx, entryCount))
            {
                kerror("CANNOT INIT I/O CQ\n");
                goto FAILED_NVME;
            }
            NVME_SUBMISSION_QUEUE_ENTRY ccq;
            memset(&ccq, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
            ccq.CDW0 = NVME_SQE_OPC_ADMIN_CREATE_IO_CQ;
            ccq.META = 0;
            ccq.DATA[0] = physical_mapping((uint64_t)ctrl->ICQ.CQE);
            ccq.DATA[1] = 0;
            ccq.CDWA = (ctrl->ICQ.COM.MSK << 16) | (qidx >> 1);
            ccq.CDWB = 1;

            cqe = NVMEWaitingCMD(&ctrl->ASQ, &ccq);
            if ((cqe.STS >> 1) & 0xFF)
            {
                kerror("CANNOT CREATE I/O CQ\n");
                goto FAILED_NVME;
            }
        }

        // Create I/O SQ
        {
            uint32_t qidx = 2;
            uint32_t entryCount = 1 + (ctrl->CAP->CAP & 0xFFFF);
            if (entryCount > 4096 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY))
                entryCount = 4096 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY);
            if (NVMEConfigureSQ(ctrl, &ctrl->ISQ, qidx, entryCount))
            {
                kerror("CANNOT INIT I/O SQ\n");
                goto FAILED_NVME;
            }
            NVME_SUBMISSION_QUEUE_ENTRY csq;
            memset(&csq, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
            csq.CDW0 = NVME_SQE_OPC_ADMIN_CREATE_IO_SQ;
            csq.META = 0;
            csq.DATA[0] = physical_mapping((uint64_t)ctrl->ISQ.SQE);
            csq.DATA[1] = 0;
            csq.CDWA = (ctrl->ICQ.COM.MSK << 16) | (qidx >> 1);
            csq.CDWB = ((qidx >> 1) << 16) | 1;

            cqe = NVMEWaitingCMD(&ctrl->ASQ, &csq);
            if ((cqe.STS >> 1) & 0xFF)
            {
                kerror("CANNOT CREATE I/O SQ\n");
                goto FAILED_NVME;
            }
            ctrl->ISQ.ICQ = &ctrl->ICQ;
        }

        /* Populate namespace IDs */
        for (uint32_t nsidx = 0; nsidx < ctrl->NSC; nsidx++)
        {
            // Probe Namespace
            uint32_t nsid = nsidx + 1;

            NVME_IDENTIFY_NAMESPACE *identifyNS = (NVME_IDENTIFY_NAMESPACE *)phy_2_virt(allocate_frame());
            identifyNS = (NVME_IDENTIFY_NAMESPACE *)(((uint64_t)identifyNS));
            memset(identifyNS, 0, 4096);

            memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
            sqe.CDW0 = NVME_SQE_OPC_ADMIN_IDENTIFY;
            sqe.META = 0;
            sqe.DATA[0] = physical_mapping((uint64_t)identifyNS);
            sqe.DATA[1] = 0;
            sqe.NSID = nsid;
            sqe.CDWA = NVME_ADMIN_IDENTIFY_CNS_ID_NS;
            cqe = NVMEWaitingCMD(&ctrl->ASQ, &sqe);
            if ((cqe.STS >> 1) & 0xFF)
            {
                kerror("CANNOT IDENTIFY NAMESPACE %d", nsid);
                goto FAILED_NAMESPACE;
            }

            uint8_t currentLBAFormat = identifyNS->FLBA & 0xF;
            if (currentLBAFormat > identifyNS->NLBA)
            {
                kerror("NVME NAMESPACE %d CURRENT LBA FORMAT %d IS BEYOND WHAT THE NAMESPACE SUPPORTS %d", nsid, currentLBAFormat, identifyNS->NLBA + 1);
                goto FAILED_NAMESPACE;
            }

            if (!identifyNS->SIZE)
            {
                goto FAILED_NAMESPACE;
            }

            if (!NVME_DMA_MEMORY)
            {
                NVME_DMA_MEMORY = phy_2_virt(allocate_frame());
            }

            NVME_NAMESPACE *ns = kalloc(sizeof(NVME_NAMESPACE));
            memset(ns, 0, sizeof(NVME_NAMESPACE));
            ns->CTRL = ctrl;
            ns->NSID = nsid;
            ns->NLBA = identifyNS->SIZE;

            NVME_LOGICAL_BLOCK_ADDRESS *fmt = identifyNS->LBAF + currentLBAFormat;

            ns->BSZ = 1ULL << fmt->DS;
            ns->META = fmt->MS;
            if (ns->BSZ > 4096)
            {
                kfree(ns);
                goto FAILED_NAMESPACE;
            }

            device_install(DEV_BLOCK, DEV_DISK, ns, "NVME", 0, 0, nvme_read, nvme_write);

            if (mdts)
            {
                ns->MXRS = ((1ULL << mdts) * 4096) / ns->BSZ;
            }
            else
            {
                ns->MXRS = -1;
            }

            // Try to read sector
            /*
            memset(identifyNS, 0, 4096);
            DISK_OPERATION dop;
            memset(&dop, 0, sizeof(DISK_OPERATION));
            dop.DRV = (DISK_DRIVER *) ns;
            dop.CMD = CMD_READ;
            dop.LBA = 0;
            dop.CNT = 8;
            dop.DAT = identifyNS;
            ExecuteDiskOperation(&dop);
            uint8_t *sector = (uint8_t *) identifyNS;
            PRINTRAX(*((uint64_t *) (sector + 512)), 16);
            LINEFEED();
            */

        FAILED_NAMESPACE:;
            deallocate_frame(physical_mapping((uint64_t)identifyNS));
        }
    }

    ksuccess("NVME initialized");
    return;
FAILED_NVME:;
    if (ctrl->ICQ.CQE)
    {
        deallocate_frame(physical_mapping((uint64_t)ctrl->ICQ.CQE));
    }
    if (ctrl->ISQ.SQE)
    {
        deallocate_frame(physical_mapping((uint64_t)ctrl->ISQ.SQE));
    }
    if (ctrl->ACQ.CQE)
    {
        deallocate_frame(physical_mapping((uint64_t)ctrl->ACQ.CQE));
    }
    if (ctrl->ASQ.SQE)
    {
        deallocate_frame(physical_mapping((uint64_t)ctrl->ASQ.SQE));
    }
    kfree(ctrl);
    kerror("Cannot init NVME");
}
