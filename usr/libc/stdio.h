#pragma once

#include <sys/plant/types.h>
#include <stdarg.h>

// 字体颜色的宏定义
#define COLOR_BLACK   0  // 黑
#define COLOR_RED     1  // 红
#define COLOR_GREEN   2  // 绿
#define COLOR_YELLOW  3  // 黄
#define COLOR_BLUE    4  // 蓝
#define COLOR_MAGENTA 5  // 品红
#define COLOR_CYAN    6  // 青
#define COLOR_WHITE   7  // 白

#define SEEK_SET 0 /* Seek relative to start-of-file */
#define SEEK_CUR 1 /* Seek relative to current position */
#define SEEK_END 2 /* Seek relative to end-of-file */

#define SEEK_MAX 3

/**
 * @brief 往屏幕上输出字符串
 *
 * @param str 字符串指针
 * @param front_color 前景色
 * @param bg_color 背景色
 * @return int64_t
 */
int64_t put_string(char *str, uint64_t front_color, uint64_t bg_color);

int printf(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
int vsprintf(char *buf, const char *fmt, va_list args);
