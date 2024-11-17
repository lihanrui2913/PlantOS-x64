#pragma once

#include <glib.h>

/**
 * @brief MBR硬盘分区表项的结构
 *
 */
struct MBR_disk_partition_table_entry_t
{
    uint8_t flags;                // 引导标志符，标记此分区为活动分区
    uint8_t starting_head;        // 起始磁头号
    uint16_t starting_sector : 6, // 起始扇区号
        starting_cylinder : 10;   // 起始柱面号
    uint8_t type;                 // 分区类型ID
    uint8_t ending_head;          // 结束磁头号

    uint16_t ending_sector : 6, // 结束扇区号
        ending_cylinder : 10;   // 结束柱面号

    uint32_t starting_LBA;  // 起始逻辑扇区
    uint32_t total_sectors; // 分区占用的磁盘扇区数

} __attribute__((packed));

/**
 * @brief MBR磁盘分区表结构体
 *
 */
struct MBR_disk_partition_table_t
{
    uint8_t reserved[446];
    struct MBR_disk_partition_table_entry_t DPTE[4]; // 磁盘分区表项
    uint16_t BS_TrailSig;
} __attribute__((packed));

extern struct MBR_disk_partition_table_t MBR_partition_tables[4]; // 导出全局的MBR磁盘分区表

/**
 * @brief 读取磁盘的分区表
 *
 * @param ahci_ctrl_num ahci控制器编号
 * @param ahci_port_num ahci端口编号
 */
struct MBR_disk_partition_table_t *MBR_read_partition_table();
