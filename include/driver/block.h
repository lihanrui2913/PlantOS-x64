#pragma once

#include "glib.h"
#include "process/wait_queue.h"

#define MAX_BLK_DEVS 512

struct block_device
{
    uint64_t read_cmd;
    uint64_t write_cmd;
    long (*transfer)(long cmd, uint64_t base_addr, uint64_t count, uint64_t buf, uint8_t arg1, uint8_t arg2);
};

extern struct block_device blk_dev_list[MAX_BLK_DEVS];

void init_block();

dev_t register_block_device(
    uint64_t read_cmd,
    uint64_t write_cmd,
    long (*transfer)(long cmd, uint64_t base_addr, uint64_t count, uint64_t buf, uint8_t arg1, uint8_t arg2));

long block_read(dev_t devid, uint64_t lba_start, uint64_t count, uint64_t buffer, uint8_t arg1, uint8_t arg2);
long write_read(dev_t devid, uint64_t lba_start, uint64_t count, uint64_t buffer, uint8_t arg1, uint8_t arg2);

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

    enum blk_dev_type
    {
        BLK_DEVICE_AHCI,
        BLK_DEVICE_NVME,
        BLK_DEVICE_USB,
    } device_type;
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
