#pragma once
#include "printk.h"
#include "spinlock.h"

#define ksuccess(...)                          \
    do                                         \
    {                                          \
        spin_lock(&global_printk_lock);        \
        printk("[");                           \
        color_printk(GREEN, BLACK, "SUCCESS"); \
        printk("] ");                          \
        printk(__VA_ARGS__);                   \
        printk("\n");                          \
        spin_unlock(&global_printk_lock);      \
    } while (0);

#define kinfo(...)                         \
    do                                     \
    {                                      \
        spin_lock(&global_printk_lock);    \
        printk("[");                       \
        color_printk(CYAN, BLACK, "INFO"); \
        printk("] ");                      \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
        spin_unlock(&global_printk_lock);  \
    } while (0);

#define kdebug(...)                                                     \
    do                                                                  \
    {                                                                   \
        spin_lock(&global_printk_lock);                                 \
        printk("[");                                                    \
        color_printk(BLUE, BLACK, "DEBUG (%s:%d)", __FILE__, __LINE__); \
        printk("] ");                                                   \
        printk(__VA_ARGS__);                                            \
        printk("\n");                                                   \
        spin_unlock(&global_printk_lock);                               \
    } while (0);

#define kwarn(...)                           \
    do                                       \
    {                                        \
        spin_lock(&global_printk_lock);      \
        printk("[");                         \
        color_printk(YELLOW, BLACK, "WARN"); \
        printk("] ");                        \
        printk(__VA_ARGS__);                 \
        printk("\n");                        \
        spin_unlock(&global_printk_lock);    \
    } while (0);

#define kerror(...)                        \
    do                                     \
    {                                      \
        spin_lock(&global_printk_lock);    \
        printk("[");                       \
        color_printk(RED, BLACK, "ERROR"); \
        printk("] ");                      \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
        spin_unlock(&global_printk_lock);  \
    } while (0);

#define kterminated(...)                        \
    do                                          \
    {                                           \
        spin_lock(&global_printk_lock);         \
        printk("[");                            \
        color_printk(RED, BLACK, "TERMINATED"); \
        printk("] ");                           \
        printk(__VA_ARGS__);                    \
        printk("\n");                           \
        spin_unlock(&global_printk_lock);       \
    } while (0);

#define kbug(...)                                                    \
    do                                                               \
    {                                                                \
        spin_lock(&global_printk_lock);                              \
        printk("[");                                                 \
        color_printk(RED, BLACK, "BUG (%s:%d)", __FILE__, __LINE__); \
        printk("] ");                                                \
        printk(__VA_ARGS__);                                         \
        printk("\n");                                                \
        spin_unlock(&global_printk_lock);                            \
    } while (0);
