#pragma once

#include "glib.h"

/**
 * @brief 定义自旋锁结构体
 *
 */
typedef struct
{
    int8_t lock; // 1:unlocked 0:locked
} spinlock_t;

/**
 * @brief 自旋锁加锁
 *
 * @param lock
 */
static inline void spin_lock(spinlock_t *lock)
{
    __asm__ __volatile__("1:    \n\t"
                         "lock decb %0   \n\t" // 尝试-1
                         "jns 3f    \n\t"      // 加锁成功，跳转到步骤3
                         "2:    \n\t"          // 加锁失败，稍后再试
                         "pause \n\t"
                         "cmpb $0, %0   \n\t"
                         "jle   2b  \n\t" // 若锁被占用，则继续重试
                         "jmp 1b    \n\t" // 尝试加锁
                         "3:"
                         : "=m"(lock->lock)::"memory");
}

/**
 * @brief 自旋锁解锁
 *
 * @param lock
 */
static inline void spin_unlock(spinlock_t *lock)
{
    __asm__ __volatile__("movb $1, %0   \n\t"
                         : "=m"(lock->lock)::"memory");
}

/**
 * @brief 初始化自旋锁
 *
 * @param lock
 */
static inline void spin_init(spinlock_t *lock)
{
    lock->lock = 1;
}
