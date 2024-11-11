#pragma once

#include <glib.h>
#include "stdint.h"
#include "process/wait_queue.h"

#define BLK_TYPE_AHCI 0
struct block_device_operation
{
    long (*open)();
    long (*close)();
    long (*ioctl)(long cmd, long arg);
    long (*transfer)(long cmd, uint64_t LBA_start, uint64_t count, uint64_t buffer, uint8_t arg0, uint8_t arg1);
};

/**
 * @brief 块设备请求队列内的packet
 *
 */
struct block_device_request_packet
{
    uint8_t cmd;
    uint64_t LBA_start;
    uint32_t count;
    uint64_t buffer_vaddr;

    uint8_t device_type; // 0: ahci 1: nvme 2: scsi
    void (*end_handler)(uint64_t num, uint64_t arg);

    wait_queue_node_t wait_queue;
};

/**
 * @brief 块设备的请求队列
 *
 */
struct block_device_request_queue
{
    wait_queue_node_t wait_queue_list;
    struct block_device_request_packet *in_service; // 正在请求的结点
    uint64_t request_count;
};