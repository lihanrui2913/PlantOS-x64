#pragma once

#include <glib.h>
#include "process/wait_queue.h"
#include "errno.h"

#define DEVICE_NR 64 // 设备数量
#define NAMELEN 16

// 设备类型
enum device_type_t
{
    DEV_NULL,  // 空设备
    DEV_CHAR,  // 字符设备
    DEV_BLOCK, // 块设备
    DEV_NET,   // 网络设备
};

// 设备子类型
enum device_subtype_t
{
    DEV_CONSOLE = 1, // 控制台
    DEV_KEYBOARD,    // 键盘
    DEV_DISK,        // 磁盘
};

// 设备控制命令
enum device_cmd_t
{
    DEV_CMD_SECTOR_START = 1, // 获得设备扇区开始位置 lba
    DEV_CMD_SECTOR_COUNT,     // 获得设备扇区数量
    DEV_CMD_SECTOR_SIZE,      // 获得设备扇区大小
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

    uint8_t device_type; // 0: ahci
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

#define REQ_READ 0  // 块设备读
#define REQ_WRITE 1 // 块设备写

#define DIRECT_UP 0   // 上楼
#define DIRECT_DOWN 1 // 下楼

typedef struct device_t
{
    char name[NAMELEN]; // 设备名
    int type;           // 设备类型
    int subtype;        // 设备子类型
    dev_t dev;          // 设备号
    dev_t parent;       // 父设备号
    void *ptr;          // 设备指针
    bool direct;        // 磁盘寻道方向

    // 设备控制
    int (*ioctl)(dev_t self_dev_id, void *dev, int cmd, void *args, uint64_t flags);
    // 读设备
    int (*read)(dev_t self_dev_id, void *dev, void *buf, size_t count, uint64_t idx, int flags);
    // 写设备
    int (*write)(dev_t self_dev_id, void *dev, void *buf, size_t count, uint64_t idx, int flags);
} device_t;

// 安装设备
dev_t device_install(
    int type, int subtype,
    void *ptr, char *name, dev_t parent,
    void *ioctl, void *read, void *write);

// 根据子类型查找设备
device_t *device_find(int type, int idx);

// 根据设备号查找设备
device_t *device_get(dev_t dev);

// 控制设备
int device_ioctl(dev_t dev, int cmd, void *args, int flags);

// 读设备
int device_read(dev_t dev, void *buf, size_t count, uint64_t idx, int flags);

// 写设备
int device_write(dev_t dev, void *buf, size_t count, uint64_t idx, int flags);

void init_device();
