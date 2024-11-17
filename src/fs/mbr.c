#include "fs/mbr.h"
#include "fs/fs.h"
#include <mm/memory.h>
#include <display/kprint.h>
#include <driver/device.h>

struct MBR_disk_partition_table_t MBR_partition_tables[4] = {0};

/**
 * @brief 读取磁盘的分区表
 */
struct MBR_disk_partition_table_t *MBR_read_partition_table()
{
    uint8_t *buf = kalloc(512);
    memset(buf, 0, 512);
    device_read(root_dev, buf, 512, 0, 0);
    MBR_partition_tables[0] = *(struct MBR_disk_partition_table_t *)buf;
    return &MBR_partition_tables[0];
}
