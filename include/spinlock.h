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
 * @brief 尝试加锁
 *
 * @param lock
 * @return long 锁变量的值（1为成功加锁，0为加锁失败）
 */
static inline long spin_trylock(spinlock_t *lock)
{
    uint64_t tmp_val = 0;
    // 交换tmp_val和lock的值，若tmp_val==1则证明加锁成功
    __asm__ __volatile__("lock xchg %%bx, %1  \n\t" // 确保只有1个进程能得到锁
                         : "=q"(tmp_val), "=m"(lock->lock)
                         : "b"(0)
                         : "memory");
    return tmp_val;
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
