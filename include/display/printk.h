#ifndef __PRINTK_H__
#define __PRINTK_H__

#include <stdarg.h>
#include "glib.h"
#include "spinlock.h"

#define ZEROPAD 1  /* pad with zero */
#define SIGN 2     /* unsigned/signed long */
#define PLUS 4     /* show plus */
#define SPACE 8    /* space if plus */
#define LEFT 16    /* left justified */
#define SPECIAL 32 /* 0x */
#define SMALL 64   /* use 'abcdef' instead of 'ABCDEF' */

#define is_digit(c) ((c) >= '0' && (c) <= '9')

#define BLACK 0   // 黑
#define RED 1     // 红
#define GREEN 2   // 绿
#define YELLOW 3  // 黄
#define BLUE 4    // 蓝
#define MAGENTA 5 // 品红
#define CYAN 6    // 青
#define WHITE 7   // 白

extern unsigned char font_ascii[256][16];

extern spinlock_t global_printk_lock;

void init_printk();

void putchar(unsigned int *fb, int Xsize, int x, int y, unsigned int FRcolor, unsigned int BKcolor, unsigned char font);

int skip_atoi(const char **s);

#define do_div(n, base) ({ \
int __res; \
__asm__("divq %%rcx":"=a" (n),"=d" (__res):"0" (n),"1" (0),"c" (base)); \
__res; })

char *number(char *str, long num, int base, int size, int precision, int type);
int vsprintf(char *buf, const char *fmt, va_list args);
int color_printk(unsigned int FRcolor, unsigned int BKcolor, const char *fmt, ...);
int sprintk(char *buf, const char *fmt, ...);

#define printk(...) color_printk(WHITE, BLACK, __VA_ARGS__)

#endif
