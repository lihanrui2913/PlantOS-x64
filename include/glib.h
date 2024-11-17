#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define container_of(ptr, type, member)                                     \
    ({                                                                      \
        typeof(((type *)0)->member) *p = (ptr);                             \
        (type *)((unsigned long)p - (unsigned long)&(((type *)0)->member)); \
    })

#define sti() __asm__ __volatile__("sti	\n\t" ::: "memory")
#define cli() __asm__ __volatile__("cli	\n\t" ::: "memory")
#define nop() __asm__ __volatile__("nop	\n\t")
#define io_mfence() __asm__ __volatile__("mfence	\n\t" ::: "memory")

#define hlt() __asm__ __volatile__("hlt	\n\t")
#define pause() __asm__ __volatile__("pause	\n\t")

#define wait_until(cond) \
    while (!(cond))      \
        pause();

#define loop_until(cond) \
    while (!(cond))      \
        pause();

#define wait_until_expire(cond, max)          \
    ({                                        \
        unsigned int __wcounter__ = (max);    \
        while (!(cond) && __wcounter__-- > 1) \
            ;                                 \
        __wcounter__;                         \
    });

#define CEIL(v, k) (((v) + (1 << (k)) - 1) >> (k))
#define ICEIL(x, y) ((x) / (y) + ((x) % (y) != 0))

#define ABS(x) ((x) > 0 ? (x) : -(x)) // 绝对值
// 最大最小值
#define max(x, y) ((x > y) ? (x) : (y))
#define min(x, y) ((x < y) ? (x) : (y))

typedef long dev_t;
typedef long idx_t;
typedef long ino_t;
typedef long err_t;
typedef long off_t;
typedef short mode_t;

// 链表数据结构
struct List
{
    struct List *prev, *next;
};

// 初始化循环链表
static inline void list_init(struct List *list)
{
    list->next = list;
    io_mfence();
    list->prev = list;
}

/**
 * @brief

 * @param entry 给定的节点
 * @param node 待插入的节点
 **/
static inline void list_add(struct List *entry, struct List *node)
{

    node->next = entry->next;
    io_mfence();
    node->prev = entry;
    io_mfence();
    node->next->prev = node;
    io_mfence();
    entry->next = node;
}

/**
 * @brief 将node添加到给定的list的结尾(也就是当前节点的前面)
 * @param entry 列表的入口
 * @param node 待添加的节点
 */
static inline void list_append(struct List *entry, struct List *node)
{

    struct List *tail = entry->prev;
    list_add(tail, node);
}

/**
 * @brief 从列表中删除节点
 * @param entry 待删除的节点
 */
static inline void list_del(struct List *entry)
{

    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
}

static inline bool list_empty(struct List *entry)
{
    /**
     * @brief 判断循环链表是否为空
     * @param entry 入口
     */

    if (entry == entry->next && entry->prev == entry)
        return true;
    else
        return false;
}

/**
 * @brief 获取链表的上一个元素
 *
 * @param entry
 * @return 链表的上一个元素
 */
static inline struct List *list_prev(struct List *entry)
{
    if (entry->prev != NULL)
        return entry->prev;
    else
        return NULL;
}

/**
 * @brief 获取链表的下一个元素
 *
 * @param entry
 * @return 链表的下一个元素
 */
static inline struct List *list_next(struct List *entry)
{
    if (entry->next != NULL)
        return entry->next;
    else
        return NULL;
}

/*
        From => To memory copy Num bytes
*/

static inline void *memcpy(void *From, void *To, long Num)
{
    int d0, d1, d2;
    __asm__ __volatile__("cld	\n\t"
                         "rep	\n\t"
                         "movsq	\n\t"
                         "testb	$4,%b4	\n\t"
                         "je	1f	\n\t"
                         "movsl	\n\t"
                         "1:\ttestb	$2,%b4	\n\t"
                         "je	2f	\n\t"
                         "movsw	\n\t"
                         "2:\ttestb	$1,%b4	\n\t"
                         "je	3f	\n\t"
                         "movsb	\n\t"
                         "3:	\n\t"
                         : "=&c"(d0), "=&D"(d1), "=&S"(d2)
                         : "0"(Num / 8), "q"(Num), "1"(To), "2"(From)
                         : "memory");
    return To;
}

/*
        FirstPart = SecondPart		=>	 0
        FirstPart > SecondPart		=>	 1
        FirstPart < SecondPart		=>	-1
*/

static inline int memcmp(void *FirstPart, void *SecondPart, long Count)
{
    register int __res;

    __asm__ __volatile__("cld	\n\t" // clean direct
                         "repe	\n\t" // repeat if equal
                         "cmpsb	\n\t"
                         "je	1f	\n\t"
                         "movl	$1,	%%eax	\n\t"
                         "jl	1f	\n\t"
                         "negl	%%eax	\n\t"
                         "1:	\n\t"
                         : "=a"(__res)
                         : "0"(0), "D"(FirstPart), "S"(SecondPart), "c"(Count)
                         :);
    return __res;
}

/*
        set memory at Address with C ,number is Count
*/

static inline void *memset(void *Address, unsigned char C, long Count)
{
    int d0, d1;
    unsigned long tmp = C * 0x0101010101010101UL;
    __asm__ __volatile__("cld	\n\t"
                         "rep	\n\t"
                         "stosq	\n\t"
                         "testb	$4, %b3	\n\t"
                         "je	1f	\n\t"
                         "stosl	\n\t"
                         "1:\ttestb	$2, %b3	\n\t"
                         "je	2f\n\t"
                         "stosw	\n\t"
                         "2:\ttestb	$1, %b3	\n\t"
                         "je	3f	\n\t"
                         "stosb	\n\t"
                         "3:	\n\t"
                         : "=&c"(d0), "=&D"(d1)
                         : "a"(tmp), "q"(Count), "0"(Count / 8), "1"(Address)
                         : "memory");
    return Address;
}

/*
        string copy
*/

static inline char *strcpy(char *Dest, char *Src)
{
    __asm__ __volatile__("cld	\n\t"
                         "1:	\n\t"
                         "lodsb	\n\t"
                         "stosb	\n\t"
                         "testb	%%al,	%%al	\n\t"
                         "jne	1b	\n\t"
                         :
                         : "S"(Src), "D"(Dest)
                         : "ax", "memory");
    return Dest;
}

/*
        string copy number bytes
*/

static inline char *strncpy(char *Dest, const char *Src, long Count)
{
    __asm__ __volatile__("cld	\n\t"
                         "1:	\n\t"
                         "decq	%2	\n\t"
                         "js	2f	\n\t"
                         "lodsb	\n\t"
                         "stosb	\n\t"
                         "testb	%%al,	%%al	\n\t"
                         "jne	1b	\n\t"
                         "rep	\n\t"
                         "stosb	\n\t"
                         "2:	\n\t"
                         :
                         : "S"(Src), "D"(Dest), "c"(Count)
                         : "ax", "memory");
    return Dest;
}

/*
        string cat Dest + Src
*/

static inline char *strcat(char *Dest, char *Src)
{
    __asm__ __volatile__("cld	\n\t"
                         "repne	\n\t"
                         "scasb	\n\t"
                         "decq	%1	\n\t"
                         "1:	\n\t"
                         "lodsb	\n\t"
                         "stosb	\n\r"
                         "testb	%%al,	%%al	\n\t"
                         "jne	1b	\n\t"
                         :
                         : "S"(Src), "D"(Dest), "a"(0), "c"(0xffffffff)
                         : "memory");
    return Dest;
}

/*
        string compare FirstPart and SecondPart
        FirstPart = SecondPart =>  0
        FirstPart > SecondPart =>  1
        FirstPart < SecondPart => -1
*/

static inline int strcmp(char *FirstPart, char *SecondPart)
{
    register int __res;
    __asm__ __volatile__("cld	\n\t"
                         "1:	\n\t"
                         "lodsb	\n\t"
                         "scasb	\n\t"
                         "jne	2f	\n\t"
                         "testb	%%al,	%%al	\n\t"
                         "jne	1b	\n\t"
                         "xorl	%%eax,	%%eax	\n\t"
                         "jmp	3f	\n\t"
                         "2:	\n\t"
                         "movl	$1,	%%eax	\n\t"
                         "jl	3f	\n\t"
                         "negl	%%eax	\n\t"
                         "3:	\n\t"
                         : "=a"(__res)
                         : "D"(FirstPart), "S"(SecondPart)
                         :);
    return __res;
}

/*
        string compare FirstPart and SecondPart with Count Bytes
        FirstPart = SecondPart =>  0
        FirstPart > SecondPart =>  1
        FirstPart < SecondPart => -1
*/

static inline int strncmp(char *FirstPart, char *SecondPart, long Count)
{
    register int __res;
    __asm__ __volatile__("cld	\n\t"
                         "1:	\n\t"
                         "decq	%3	\n\t"
                         "js	2f	\n\t"
                         "lodsb	\n\t"
                         "scasb	\n\t"
                         "jne	3f	\n\t"
                         "testb	%%al,	%%al	\n\t"
                         "jne	1b	\n\t"
                         "2:	\n\t"
                         "xorl	%%eax,	%%eax	\n\t"
                         "jmp	4f	\n\t"
                         "3:	\n\t"
                         "movl	$1,	%%eax	\n\t"
                         "jl	4f	\n\t"
                         "negl	%%eax	\n\t"
                         "4:	\n\t"
                         : "=a"(__res)
                         : "D"(FirstPart), "S"(SecondPart), "c"(Count)
                         :);
    return __res;
}

static inline int strlen(const char *String)
{
    register int __res;
    __asm__ __volatile__("cld	\n\t"
                         "repne	\n\t"
                         "scasb	\n\t"
                         "notl	%0	\n\t"
                         "decl	%0	\n\t"
                         : "=c"(__res)
                         : "D"(String), "a"(0), "0"(0xffffffff)
                         :);
    return __res;
}

static inline unsigned long bit_set(unsigned long *addr, unsigned long nr)
{
    return *addr | (1UL << nr);
}

static inline unsigned long bit_get(unsigned long *addr, unsigned long nr)
{
    return *addr & (1UL << nr);
}

static inline unsigned long bit_clean(unsigned long *addr, unsigned long nr)
{
    return *addr & (~(1UL << nr));
}

static inline unsigned char io_in8(unsigned short port)
{
    unsigned char ret = 0;
    __asm__ __volatile__("inb	%%dx,	%0	\n\t"
                         "mfence			\n\t"
                         : "=a"(ret)
                         : "d"(port)
                         : "memory");
    return ret;
}

static inline unsigned short io_in16(unsigned short port)
{
    unsigned short ret = 0;
    __asm__ __volatile__("inw	%%dx,	%0	\n\t"
                         "mfence			\n\t"
                         : "=a"(ret)
                         : "d"(port)
                         : "memory");
    return ret;
}

static inline unsigned int io_in32(unsigned short port)
{
    unsigned int ret = 0;
    __asm__ __volatile__("inl	%%dx,	%0	\n\t"
                         "mfence			\n\t"
                         : "=a"(ret)
                         : "d"(port)
                         : "memory");
    return ret;
}

static inline void io_out8(unsigned short port, unsigned char value)
{
    __asm__ __volatile__("outb	%0,	%%dx	\n\t"
                         "mfence			\n\t"
                         :
                         : "a"(value), "d"(port)
                         : "memory");
}

static inline void io_out16(unsigned short port, unsigned short value)
{
    __asm__ __volatile__("outw	%0,	%%dx	\n\t"
                         "mfence			\n\t"
                         :
                         : "a"(value), "d"(port)
                         : "memory");
}

static inline void io_out32(unsigned short port, unsigned int value)
{
    __asm__ __volatile__("outl	%0,	%%dx	\n\t"
                         "mfence			\n\t"
                         :
                         : "a"(value), "d"(port)
                         : "memory");
}

#define port_insw(port, buffer, nr) \
    __asm__ __volatile__("cld;rep;insw;mfence;" ::"d"(port), "D"(buffer), "c"(nr) : "memory")

#define port_outsw(port, buffer, nr) \
    __asm__ __volatile__("cld;rep;outsw;mfence;" ::"d"(port), "S"(buffer), "c"(nr) : "memory")

static inline unsigned long rdmsr(unsigned long address)
{
    unsigned int tmp0 = 0;
    unsigned int tmp1 = 0;
    __asm__ __volatile__("rdmsr	\n\t" : "=d"(tmp0), "=a"(tmp1) : "c"(address) : "memory");
    return (unsigned long)tmp0 << 32 | tmp1;
}

static inline void wrmsr(unsigned long address, unsigned long value)
{
    __asm__ __volatile__("wrmsr	\n\t" ::"d"(value >> 32), "a"(value & 0xffffffff), "c"(address) : "memory");
}

/**
 * @brief 验证地址空间是否为用户地址空间
 *
 * @param addr_start 地址起始值
 * @param length 地址长度
 * @return true
 * @return false
 */
static inline bool verify_area(uint64_t addr_start, uint64_t length)
{
    if ((addr_start + length) <= 0x00007fffffffffffUL) // 用户程序可用的的地址空间应<= 0x00007fffffffffffUL
        return true;
    else
        return false;
}

/**
 * @brief 从用户空间搬运数据到内核空间
 *
 * @param dst 目的地址
 * @param src 源地址
 * @param size 搬运的大小
 * @return uint64_t
 */
static inline uint64_t copy_from_user(void *dst, void *src, uint64_t size)
{
    uint64_t tmp0, tmp1;
    if (!verify_area((uint64_t)src, size))
        return 0;

    /**
     * @brief 先每次搬运8 bytes，剩余就直接一个个byte搬运
     *
     */
    __asm__ __volatile__("rep   \n\t"
                 "movsq  \n\t"
                 "movq %3, %0   \n\t"
                 "rep   \n\t"
                 "movsb \n\t"
                 : "=&c"(size), "=&D"(tmp0), "=&S"(tmp1)
                 : "r"(size & 7), "0"(size >> 3), "1"(dst), "2"(src)
                 : "memory");
    return size;
}

/**
 * @brief 从内核空间搬运数据到用户空间
 *
 * @param dst 目的地址
 * @param src 源地址
 * @param size 搬运的大小
 * @return uint64_t
 */
static inline uint64_t copy_to_user(void *dst, void *src, uint64_t size)
{
    uint64_t tmp0, tmp1;
    if (verify_area((uint64_t)src, size))
        return 0;

    /**
     * @brief 先每次搬运8 bytes，剩余就直接一个个byte搬运
     *
     */
    __asm__ __volatile__("rep   \n\t"
                 "movsq  \n\t"
                 "movq %3, %0   \n\t"
                 "rep   \n\t"
                 "movsb \n\t"
                 : "=&c"(size), "=&D"(tmp0), "=&S"(tmp1)
                 : "r"(size & 7), "0"(size >> 3), "1"(dst), "2"(src)
                 : "memory");
    return size;
}

static inline long strncpy_from_user(char *dst, const char *src, unsigned long size)
{
    if (!verify_area((uint64_t)src, size))
        return 0;

    strncpy(dst, src, size);
    return size;
}
