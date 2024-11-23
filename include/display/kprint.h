#pragma once
#include "printk.h"
#include "spinlock.h"

#define ksuccess(...)                          \
    do                                         \
    {                                          \
        cli();                                 \
        printk("[");                           \
        color_printk(GREEN, BLACK, "SUCCESS"); \
        printk("] ");                          \
        printk(__VA_ARGS__);                   \
        printk("\n");                          \
        sti();                                 \
    } while (0);

#define kinfo(...)                         \
    do                                     \
    {                                      \
        cli();                             \
        printk("[");                       \
        color_printk(CYAN, BLACK, "INFO"); \
        printk("] ");                      \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
        sti();                             \
    } while (0);

#define kdebug(...)                                                     \
    do                                                                  \
    {                                                                   \
        cli();                                                          \
        printk("[");                                                    \
        color_printk(BLUE, BLACK, "DEBUG (%s:%d)", __FILE__, __LINE__); \
        printk("] ");                                                   \
        printk(__VA_ARGS__);                                            \
        printk("\n");                                                   \
        sti();                                                          \
    } while (0);

#define kwarn(...)                           \
    do                                       \
    {                                        \
        cli();                               \
        printk("[");                         \
        color_printk(YELLOW, BLACK, "WARN"); \
        printk("] ");                        \
        printk(__VA_ARGS__);                 \
        printk("\n");                        \
        sti();                               \
    } while (0);

#define kerror(...)                        \
    do                                     \
    {                                      \
        cli();                             \
        printk("[");                       \
        color_printk(RED, BLACK, "ERROR"); \
        printk("] ");                      \
        printk(__VA_ARGS__);               \
        printk("\n");                      \
        sti();                             \
    } while (0);

#define kterminated(...)                        \
    do                                          \
    {                                           \
        cli();                                  \
        printk("[");                            \
        color_printk(RED, BLACK, "TERMINATED"); \
        printk("] ");                           \
        printk(__VA_ARGS__);                    \
        printk("\n");                           \
        sti();                                  \
    } while (0);

#define kbug(...)                                                    \
    do                                                               \
    {                                                                \
        cli();                                                       \
        printk("[");                                                 \
        color_printk(RED, BLACK, "BUG (%s:%d)", __FILE__, __LINE__); \
        printk("] ");                                                \
        printk(__VA_ARGS__);                                         \
        printk("\n");                                                \
        sti();                                                       \
    } while (0);
