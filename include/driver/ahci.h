#pragma once

#include <driver/pci.h>
#include <driver/dev.h>
#include <display/kprint.h>
#include <mm/memory.h>

#define AHCI_MAPPING_BASE SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + AHCI_MAPPING_OFFSET

typedef struct _AHCI_HBA_PORT
{
    uint64_t CLB; // Command List Base Address
    uint64_t FIS; // FIS Base Address
    uint32_t IST; // Interrupt Status
    uint32_t IEN; // Interrupt Enable
    uint32_t CMD; // Command and Status
    uint32_t RS0;
    uint32_t TFD; // Task File Data
    uint32_t SIG; // Signature
    uint32_t SAS; // Serial ATA Status
    uint32_t SAC; // Serial ATA Control
    uint32_t SAE; // Serial ATA Error
    uint32_t SAA; // Serial ATA Active
    uint32_t CIS; // Command Issue
    uint32_t SAN; // Serial ATA Notification
    uint32_t FBS; // FIS Based Switching Control
    uint32_t SLP; // Device Sleep
    uint32_t RS1[0x0A];
    uint32_t VEN[0x04];
} AHCI_HBA_PORT;
typedef struct _AHCI_HBA_MEMORY
{
    uint32_t CAP; // Capabilities
    uint32_t GHC; // Global Host Control
    uint32_t INT; // Interrupt Status
    uint32_t PTI; // Ports Implemented
    uint32_t VER; // Version
    uint32_t CCC; // Command Completion Coalescing Control
    uint32_t CCP; // Command Completion Coalescing Ports
    uint32_t EML; // Enclosure Management Location
    uint32_t EMC; // Enclosure Management Control
    uint32_t CAX; // Host Capabilities Extended
    uint32_t HCS; // BIOS/OS Handoff Control and Status
    uint8_t RSV[0x0074];
    uint8_t VSR[0x0060]; // Vendor Specific Registers
    AHCI_HBA_PORT PRT[];
} AHCI_HBA_MEMORY;

typedef struct _AHCI_COMMAND_HEAD
{
    uint32_t CFL : 0x05; // Command FIS Length
    uint32_t API : 0x01; // ATAPI
    uint32_t WRT : 0x01; // WRITE(1), READ(0)
    uint32_t PFT : 0x01; // Prefetchable
    uint32_t RST : 0x01; // Reset
    uint32_t TST : 0x01; // Built-In Self-Test(BIST)
    uint32_t BSY : 0x01; // Clear Busy upon R_OK
    uint32_t RV0 : 0x01;
    uint32_t PMP : 0x04; // Port Multiplier Port
    uint32_t DTL : 0x10; // Physical Region Descriptor Table Length

    uint32_t DBC; // Physical Region Descriptor uint8_t Count

    uint64_t TBL; // Command Table Descriptor Base Address

    uint32_t RV1[0x04];
} AHCI_COMMAND_HEAD;

typedef struct _AHCI_PRDT_ENTRY
{
    uint64_t DBA; // Data Base Address
    uint32_t RV0;
    uint32_t DBC : 0x16; // PRD uint8_t Count
    uint32_t RV1 : 0x09;
    uint32_t IOC : 0x01; // Interrupt On Completion
} AHCI_PRDT_ENTRY;

typedef struct _AHCI_FIS_H2D
{
    uint8_t TYP;        // FIS_TYPE_REG_H2D
    uint8_t PMP : 0x04; // Port Multiplier Port
    uint8_t RV0 : 0x03;
    uint8_t CCC : 0x01; // CMD(1), CTRL(0)
    uint8_t CMD;        // Command Register
    uint8_t FTL;        // Feature Register L

    uint8_t BA0; // LBA 0
    uint8_t BA1; // LBA 1
    uint8_t BA2; // LBA 2
    uint8_t DVC; // Device

    uint8_t BA3; // LBA 3
    uint8_t BA4; // LBA 4
    uint8_t BA5; // LBA 5
    uint8_t FTH; // Feature Register H

    uint16_t CNT; // Count
    uint8_t ICC;  // Isochronous Command Completion
    uint8_t CTR;  // Control

    uint8_t RV1[0x30];
} AHCI_FIS_H2D;

typedef struct _AHCI_COMMAND_TABLE
{
    AHCI_FIS_H2D FIS;
    uint8_t ATA[0x10];
    uint8_t RSV[0x30];
    AHCI_PRDT_ENTRY PRD[];
} AHCI_COMMAND_TABLE;

typedef struct _AHCI_CONTROLLER
{
    struct pci_device_structure_general_device_t *DVC;
    AHCI_HBA_MEMORY *HBA;
} AHCI_CONTROLLER;

typedef struct _AHCI_PORT
{
    AHCI_CONTROLLER *CTRL;
    AHCI_HBA_PORT *PRT;
    uint32_t PNR;
    uint8_t SER[0x14];
    uint8_t MOD[0x28];
} AHCI_PORT;

void init_ahci();
