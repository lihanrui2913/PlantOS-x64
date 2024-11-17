#pragma once

#include "glib.h"
#include "driver/pci.h"
#include "driver/msi.h"

#define AHCI_IRQ_NUM 152

#define AHCI_MAPPING_BASE SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + AHCI_MAPPING_OFFSET

#define HBA_RCAP 0
#define HBA_RGHC 1
#define HBA_RIS 2
#define HBA_RPI 3
#define HBA_RVER 4

#define HBA_RPBASE (0x40)
#define HBA_RPSIZE (0x80 >> 2)
#define HBA_RPxCLB 0
#define HBA_RPxFB 2
#define HBA_RPxIS 4
#define HBA_RPxIE 5
#define HBA_RPxCMD 6
#define HBA_RPxTFD 8
#define HBA_RPxSIG 9
#define HBA_RPxSSTS 10
#define HBA_RPxSCTL 11
#define HBA_RPxSERR 12
#define HBA_RPxSACT 13
#define HBA_RPxCI 14
#define HBA_RPxSNTF 15
#define HBA_RPxFBS 16

#define HBA_PxCMD_FRE (1 << 4)
#define HBA_PxCMD_CR (1 << 15)
#define HBA_PxCMD_FR (1 << 14)
#define HBA_PxCMD_ST (1)
#define HBA_PxINTR_DMA (1 << 2)
#define HBA_PxINTR_D2HR (1)
#define HBA_PxTFD_ERR (1)
#define HBA_PxTFD_BSY (1 << 7)
#define HBA_PxTFD_DRQ (1 << 3)

#define HBA_RGHC_ahci_ENABLE (1 << 31)
#define HBA_RGHC_INTR_ENABLE (1 << 1)
#define HBA_RGHC_RESET 1

#define HBA_RPxSSTS_PWR(x) (((x) >> 8) & 0xf)
#define HBA_RPxSSTS_IF(x) (((x) >> 4) & 0xf)
#define HBA_RPxSSTS_PHYSTATE(x) ((x) & 0xf)

#define HBA_DEV_SIG_ATAPI 0xeb140101
#define HBA_DEV_SIG_ATA 0x00000101

#define __HBA_PACKED__ __attribute__((packed))

typedef unsigned int hba_reg_t;

#define HBA_CMDH_FIS_LEN(fis_bytes) (((fis_bytes) / 4) & 0x1f)
#define HBA_CMDH_ATAPI (1 << 5)
#define HBA_CMDH_WRITE (1 << 6)
#define HBA_CMDH_PREFETCH (1 << 7)
#define HBA_CMDH_R (1 << 8)
#define HBA_CMDH_CLR_BUSY (1 << 10)
#define HBA_CMDH_PRDT_LEN(entries) (((entries) & 0xffff) << 16)
struct hba_cmdh
{
    uint16_t options;
    uint16_t prdt_len;
    uint32_t transferred_size;
    uint32_t cmd_table_base;
    uint32_t reserved[5];
} __HBA_PACKED__;

#define HBA_PRDTE_BYTE_CNT(cnt) ((cnt & 0x3FFFFF) | 0x1)

struct hba_prdte
{
    uint32_t data_base;
    uint32_t reserved[2];
    uint32_t byte_count;
} __HBA_PACKED__;

struct hba_cmdt
{
    uint8_t command_fis[64];
    uint8_t atapi_cmd[16];
    uint8_t reserved[0x30];
    struct hba_prdte entries[3];
} __HBA_PACKED__;

#define HBA_DEV_FEXTLBA 1
#define HBA_DEV_FATAPI (1 << 1)

struct hba_port;

struct hba_device
{
    char serial_num[20];
    char model[40];
    uint32_t flags;
    uint64_t max_lba;
    uint32_t block_size;
    uint64_t wwn;
    uint8_t cbd_size;
    uint8_t last_error;
    uint8_t last_status;
    uint32_t alignment_offset;
    uint32_t block_per_sec;
    uint32_t capabilities;

    struct
    {
        int (*identify)(struct hba_port *port);
        int (*read_buffer)(struct hba_port *port,
                           uint64_t lba,
                           void *buffer,
                           uint32_t size);
        int (*write_buffer)(struct hba_port *port,
                            uint64_t lba,
                            void *buffer,
                            uint32_t size);
    } ops;
};

struct hba_port
{
    volatile hba_reg_t *regs;
    unsigned int ssts;
    struct hba_cmdh *cmdlst;
    void *fis;
    struct hba_device *device;
};

struct ahci_hba
{
    volatile hba_reg_t *base;
    unsigned int ports_num;
    unsigned int ports_bmp;
    unsigned int cmd_slots;
    unsigned int version;
    struct hba_port *ports[32];
};

int hba_prepare_cmd(struct hba_port *port,
                    struct hba_cmdt **cmdt,
                    struct hba_cmdh **cmdh,
                    void *buffer,
                    unsigned int size);

void init_ahci();

void ahci_register_ops(struct hba_port *port);

extern struct ahci_hba hba;

/* SCSI */

#define SCSI_FLIP(val)                                            \
    ((((val) & 0x000000ff) << 24) | (((val) & 0x0000ff00) << 8) | \
     (((val) & 0x00ff0000) >> 8) | (((val) & 0xff000000) >> 24))

#define SCSI_READ_CAPACITY_16 0x9e
#define SCSI_READ_CAPACITY_10 0x25
#define SCSI_READ_BLOCKS_16 0x88
#define SCSI_READ_BLOCKS_12 0xa8
#define SCSI_WRITE_BLOCKS_16 0x8a
#define SCSI_WRITE_BLOCKS_12 0xaa

struct scsi_cdb12
{
    uint8_t opcode;
    uint8_t misc1;
    uint32_t lba_be;
    uint32_t length;
    uint8_t misc2;
    uint8_t ctrl;
} __attribute__((packed));

struct scsi_cdb16
{
    uint8_t opcode;
    uint8_t misc1;
    uint32_t lba_be_hi;
    uint32_t lba_be_lo;
    uint32_t length;
    uint8_t misc2;
    uint8_t ctrl;
} __attribute__((packed));

void scsi_create_packet12(struct scsi_cdb12 *cdb,
                          uint8_t opcode,
                          uint32_t lba,
                          uint32_t alloc_size);

void scsi_create_packet16(struct scsi_cdb16 *cdb,
                          uint8_t opcode,
                          uint64_t lba,
                          uint32_t alloc_size);

int scsi_read_buffer(struct hba_port *port,
                     uint64_t lba,
                     void *buffer,
                     uint32_t size);

int scsi_write_buffer(struct hba_port *port,
                      uint64_t lba,
                      void *buffer,
                      uint32_t size);

/* SATA */
#define SATA_REG_FIS_D2H 0x34
#define SATA_REG_FIS_H2D 0x27
#define SATA_REG_FIS_COMMAND 0x80
#define SATA_LBA_COMPONENT(lba, offset) ((((lba) >> (offset)) & 0xff))

#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PAKCET_DEVICE 0xa1
#define ATA_PACKET 0xa0
#define ATA_READ_DMA_EXT 0x25
#define ATA_READ_DMA 0xc8
#define ATA_WRITE_DMA_EXT 0x35
#define ATA_WRITE_DMA 0xca

#define MAX_RETRY 2

struct sata_fis_head
{
    uint8_t type;
    uint8_t options;
    uint8_t status_cmd;
    uint8_t feat_err;
} __HBA_PACKED__;

struct sata_reg_fis
{
    struct sata_fis_head head;

    uint8_t lba0, lba8, lba16;
    uint8_t dev;
    uint8_t lba24, lba32, lba40;
    uint8_t feature;

    uint16_t count;

    uint8_t reserved[6];
} __HBA_PACKED__;

struct sata_data_fis
{
    struct sata_fis_head head;

    uint8_t data[0];
} __HBA_PACKED__;

void sata_create_fis(struct sata_reg_fis *cmd_fis,
                     uint8_t command,
                     uint64_t lba,
                     uint16_t sector_count);

int sata_read_buffer(struct hba_port *port,
                     uint64_t lba,
                     void *buffer,
                     uint32_t size);

int sata_write_buffer(struct hba_port *port,
                      uint64_t lba,
                      void *buffer,
                      uint32_t size);

// UTILS

void ahci_parse_dev_info(struct hba_device *dev_info, uint16_t *data);

void ahci_parsestr(char *str, uint16_t *reg_start, int size_word);

void scsi_parse_capacity(struct hba_device *device, uint32_t *parameter);

void sata_read_error(struct hba_port *port);
