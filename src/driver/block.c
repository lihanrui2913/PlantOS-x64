#include "driver/block.h"

long global_idx = 0;

struct block_device blk_dev_list[MAX_BLK_DEVS];

void init_block()
{
    memset(blk_dev_list, 0, sizeof(struct block_device) * MAX_BLK_DEVS);
}

dev_t register_block_device(
    uint64_t read_cmd,
    uint64_t write_cmd,
    long (*transfer)(long cmd, uint64_t base_addr, uint64_t count, uint64_t buf, uint8_t arg1, uint8_t arg2))
{
    struct block_device dev;
    dev.read_cmd = read_cmd;
    dev.write_cmd = write_cmd;
    dev.transfer = transfer;
    blk_dev_list[global_idx] = dev;

    return global_idx++;
}

long block_read(dev_t devid, uint64_t lba_start, uint64_t count, uint64_t buffer, uint8_t arg1, uint8_t arg2)
{
    return blk_dev_list[devid].transfer(blk_dev_list[devid].read_cmd, lba_start, count, buffer, arg1, arg2);
}

long write_read(dev_t devid, uint64_t lba_start, uint64_t count, uint64_t buffer, uint8_t arg1, uint8_t arg2)
{
    return blk_dev_list[devid].transfer(blk_dev_list[devid].write_cmd, lba_start, count, buffer, arg1, arg2);
}
