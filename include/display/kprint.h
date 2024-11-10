#pragma once
#include "printk.h"

#define ksuccess(...)                          \
    do                                         \
    {                                          \
        printk("[ ");                          \
        color_printk(GREEN, BLACK, "SUCCESS"); \
        printk(" ] ");                         \
        printk(__VA_ARGS__);                   \
        printk("\n");                          \
    } while (0);

#define kinfo(...)           \
    do                       \
    {                        \
        printk("[ INFO ] "); \
        printk(__VA_ARGS__); \
        printk("\n");        \
    } while (0);

#define kdebug(...)                                        \
    do                                                     \
    {                                                      \
        printk("[ DEBUG ] (%s:%d)\t", __FILE__, __LINE__); \
        printk(__VA_ARGS__);                               \
        printk("\n");                                      \
    } while (0);

#define kwarn(...)                           \
    do                                       \
    {                                        \
        printk("[ ");                        \
        color_printk(YELLOW, BLACK, "WARN"); \
        printk(" ] ");                       \
        printk(__VA_ARGS__);                 \
        printk("\n");                        \
    } while (0);

#define kerror(...)                        \
    do                                     \
    {                                      \
        printk("[ ");                      \
        color_printk(RED, BLACK, "ERROR"); \
        printk(" ] ");                     \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
    } while (0);

#define kterminated(...)                        \
    do                                          \
    {                                           \
        printk("[ ");                           \
        color_printk(RED, BLACK, "TERMINATED"); \
        printk(" ] ");                          \
        printk(__VA_ARGS__);                    \
        printk("\n");                           \
    } while (0);

#define kBUG(...)                                   \
    do                                              \
    {                                               \
        printk("[ ");                               \
        color_printk(RED, BLACK, "BUG");            \
        printk(" ] (%s:%d)\t", __FILE__, __LINE__); \
        printk(__VA_ARGS__);                        \
        printk("\n");                               \
    } while (0);
