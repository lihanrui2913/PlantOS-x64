#pragma once
#include "printk.h"

#define ksuccess(...)                          \
    do                                         \
    {                                          \
        printk("[");                           \
        color_printk(GREEN, BLACK, "SUCCESS"); \
        printk("] ");                          \
        printk(__VA_ARGS__);                   \
        printk("\n");                          \
    } while (0);

#define kinfo(...)           \
    do                       \
    {                        \
        printk("[");                          \
        color_printk(CYAN, BLACK, "INFO");    \
        printk("] ");                         \
        printk(__VA_ARGS__); \
        printk("\n");        \
    } while (0);

#define kdebug(...)                                                         \
    do                                                                      \
    {                                                                       \
        printk("[");                                                        \
        color_printk(BLUE, BLACK, "DEBUG (%s:%d)", __FILE__, __LINE__);     \
        printk("] ");                                                       \
        printk(__VA_ARGS__);                                                \
        printk("\n");                                                       \
    } while (0);

#define kwarn(...)                           \
    do                                       \
    {                                        \
        printk("[");                         \
        color_printk(YELLOW, BLACK, "WARN"); \
        printk("] ");                        \
        printk(__VA_ARGS__);                 \
        printk("\n");                        \
    } while (0);

#define kerror(...)                        \
    do                                     \
    {                                      \
        printk("[");                       \
        color_printk(RED, BLACK, "ERROR"); \
        printk("] ");                      \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
    } while (0);

#define kterminated(...)                        \
    do                                          \
    {                                           \
        printk("[");                            \
        color_printk(RED, BLACK, "TERMINATED"); \
        printk("] ");                           \
        printk(__VA_ARGS__);                    \
        printk("\n");                           \
    } while (0);

#define kbug(...)                                                    \
    do                                                               \
    {                                                                \
        printk("[");                                                 \
        color_printk(RED, BLACK, "BUG (%s:%d)", __FILE__, __LINE__); \
        printk("] ");                                                \
        printk(__VA_ARGS__);                                         \
        printk("\n");                                                \
    } while (0);