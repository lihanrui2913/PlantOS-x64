#pragma once

typedef __builtin_va_list va_list;
#define va_arg(a, t) __builtin_va_arg(a, t)
#define va_start(a, f) __builtin_va_start(a, f)
#define va_end(a) __builtin_va_end(a)
