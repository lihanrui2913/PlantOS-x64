#include "display/printk.h"
#include "limine.h"
#include "spinlock.h"

__attribute__((used, section(".limine_requests"))) static volatile struct limine_framebuffer_request framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST,
    .revision = 0};

char buf[512] = {0};

struct position
{
    int XResolution;
    int YResolution;

    int Xposition;
    int Yposition;

    int XCharSize;
    int YCharSize;

    unsigned int *FB_addr;
    unsigned long FB_length;

    spinlock_t spinlock;
} pos;

void init_printk()
{
    if (framebuffer_request.response == NULL || framebuffer_request.response->framebuffer_count < 1)
    {
        for (;;)
            __asm__("hlt");
    }

    struct limine_framebuffer *framebuffer = framebuffer_request.response->framebuffers[0];

    pos.FB_addr = framebuffer->address;
    pos.FB_length = framebuffer->bpp * framebuffer->width * framebuffer->height;

    pos.XResolution = framebuffer->width;
    pos.YResolution = framebuffer->height;

    pos.Xposition = 0;
    pos.Yposition = 0;

    pos.XCharSize = 8;
    pos.YCharSize = 16;

    spin_init(&pos.spinlock);
}

void putchar(unsigned int *fb, int Xsize, int x, int y, unsigned int FRcolor, unsigned int BKcolor, unsigned char font)
{
    int i = 0, j = 0;
    unsigned int *addr = NULL;
    unsigned char *fontp = NULL;
    int testval = 0;
    fontp = font_ascii[font];

    for (i = 0; i < 16; i++)
    {
        addr = fb + Xsize * (y + i) + x;
        testval = 0x100;
        for (j = 0; j < 8; j++)
        {
            testval = testval >> 1;
            if (*fontp & testval)
                *addr = FRcolor;
            else
                *addr = BKcolor;
            addr++;
        }
        fontp++;
    }
}

int skip_atoi(const char **s)
{
    int i = 0;

    while (is_digit(**s))
        i = i * 10 + *((*s)++) - '0';
    return i;
}

char *number(char *str, long num, int base, int size, int precision, int type)
{
    char c, sign, tmp[50];
    const char *digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int i;

    if (type & SMALL)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (type & LEFT)
        type &= ~ZEROPAD;
    if (base < 2 || base > 36)
        return 0;
    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN && num < 0)
    {
        sign = '-';
        num = -num;
    }
    else
        sign = (type & PLUS) ? '+' : ((type & SPACE) ? ' ' : 0);
    if (sign)
        size--;
    if (type & SPECIAL)
    {
        if (base == 16)
        {
            size -= 2;
        }
        else if (base == 8)
        {
            size--;
        }
    }
    i = 0;
    if (num == 0)
        tmp[i++] = '0';
    else
        while (num != 0)
            tmp[i++] = digits[do_div(num, base)];
    if (i > precision)
        precision = i;
    size -= precision;
    if (!(type & (ZEROPAD + LEFT)))
        while (size-- > 0)
            *str++ = ' ';
    if (sign)
        *str++ = sign;
    if (type & SPECIAL)
    {
        if (base == 8)
        {
            *str++ = '0';
        }
        else if (base == 16)
        {
            *str++ = '0';
            *str++ = digits[33];
        }
    }
    if (!(type & LEFT))
        while (size-- > 0)
            *str++ = c;

    while (i < precision--)
        *str++ = '0';
    while (i-- > 0)
        *str++ = tmp[i];
    while (size-- > 0)
        *str++ = ' ';
    return str;
}

int vsprintf(char *buf, const char *fmt, va_list args)
{
    char *str, *s;
    int flags;
    int field_width;
    int precision;
    int len, i;

    int qualifier; /* 'h', 'l', 'L' or 'Z' for integer fields */

    for (str = buf; *fmt; fmt++)
    {

        if (*fmt != '%')
        {
            *str++ = *fmt;
            continue;
        }
        flags = 0;
    repeat:
        fmt++;
        switch (*fmt)
        {
        case '-':
            flags |= LEFT;
            goto repeat;
        case '+':
            flags |= PLUS;
            goto repeat;
        case ' ':
            flags |= SPACE;
            goto repeat;
        case '#':
            flags |= SPECIAL;
            goto repeat;
        case '0':
            flags |= ZEROPAD;
            goto repeat;
        }

        /* get field width */

        field_width = -1;
        if (is_digit(*fmt))
            field_width = skip_atoi(&fmt);
        else if (*fmt == '*')
        {
            fmt++;
            field_width = va_arg(args, int);
            if (field_width < 0)
            {
                field_width = -field_width;
                flags |= LEFT;
            }
        }

        /* get the precision */

        precision = -1;
        if (*fmt == '.')
        {
            fmt++;
            if (is_digit(*fmt))
                precision = skip_atoi(&fmt);
            else if (*fmt == '*')
            {
                fmt++;
                precision = va_arg(args, int);
            }
            if (precision < 0)
                precision = 0;
        }

        qualifier = -1;
        if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' || *fmt == 'Z')
        {
            qualifier = *fmt;
            fmt++;
        }

        switch (*fmt)
        {
        case 'c':

            if (!(flags & LEFT))
                while (--field_width > 0)
                    *str++ = ' ';
            *str++ = (unsigned char)va_arg(args, int);
            while (--field_width > 0)
                *str++ = ' ';
            break;

        case 's':
            s = va_arg(args, char *);
            if (!s)
                s = "\0";
            len = strlen(s);
            if (precision < 0)
                precision = len;
            else if (len > precision)
                len = precision;

            if (!(flags & LEFT))
                while (len < field_width--)
                    *str++ = ' ';
            for (i = 0; i < len; i++)
                *str++ = *s++;
            while (len < field_width--)
                *str++ = ' ';
            break;

        case 'o':

            if (qualifier == 'l')
                str = number(str, va_arg(args, unsigned long), 8, field_width, precision, flags);
            else
                str = number(str, va_arg(args, unsigned int), 8, field_width, precision, flags);
            break;

        case 'p':
        {
            if (field_width == -1)
            {
                field_width = 2 * sizeof(void *);
                flags |= ZEROPAD;
            }

            str = number(str, (unsigned long)va_arg(args, void *), 16, field_width, precision, flags);
            break;
        }
        case 'x':
        {
            flags |= SMALL;
        }
        case 'X':
        {
            if (qualifier == 'l')
                str = number(str, va_arg(args, unsigned long), 16, field_width, precision, flags);
            else
                str = number(str, va_arg(args, unsigned int), 16, field_width, precision, flags);
            break;
        }
        case 'd':
        case 'i':
        {
            flags |= SIGN;
        }
        case 'u':
        {
            if (qualifier == 'l')
                str = number(str, va_arg(args, long), 10, field_width, precision, flags);
            else
                str = number(str, va_arg(args, int), 10, field_width, precision, flags);
            break;
        }
        case 'n':

            if (qualifier == 'l')
            {
                long *ip = va_arg(args, long *);
                *ip = (str - buf);
            }
            else
            {
                int *ip = va_arg(args, int *);
                *ip = (str - buf);
            }
            break;

        case '%':

            *str++ = '%';
            break;

        default:

            *str++ = '%';
            if (*fmt)
                *str++ = *fmt;
            else
                fmt--;
            break;
        }
    }
    *str = '\0';
    return str - buf;
}

int do_scroll(bool direction, int pixels)
{
    if (direction == true) // 向上滚动
    {
        pixels = pixels;
        if (pixels > pos.YResolution)
            return -1;
        // 无需滚动
        if (pixels == 0)
            return 0;
        unsigned int src = pixels * pos.XResolution;
        unsigned int count = pos.FB_length - src;

        memcpy((pos.FB_addr + src), pos.FB_addr, sizeof(unsigned int) * (pos.FB_length - src));
        memset(pos.FB_addr + (pos.FB_length - src), 0, sizeof(unsigned int) * (src));

        return 0;
    }
    else
        return -1;
    return 0;
}
/**
 * @brief 滚动窗口（尚不支持向下滚动）
 *
 * @param direction  方向，向上滑动为true,否则为false
 * @param pixels 要滑动的像素数量
 * @param animation 是否包含滑动动画
 */
static int scroll(bool direction, int pixels, bool animation)
{
    // 暂时不支持反方向滚动
    if (direction == false)
        return -1;
    // 为了保证打印字符正确，需要对pixel按照字体高度对齐
    int md = pixels % pos.XCharSize;
    if (md)
        pixels = pixels + pos.YCharSize - md;

    if (animation == false)
        return do_scroll(direction, pixels);
    else
    {

        int steps;
        if (pixels > 10)
            steps = 5;
        else
            steps = pixels % 10;
        int half_steps = steps / 2;

        // 计算加速度
        double accelerate = 0.5 * pixels / (half_steps * half_steps);
        int current_pixels = 0;
        double delta_x;

        int trace[13] = {0};
        int js_trace = 0;
        // 加速阶段
        for (int i = 1; i <= half_steps; ++i)
        {
            trace[js_trace] = (int)(accelerate * i + 0.5);
            current_pixels += trace[js_trace];
            do_scroll(direction, trace[js_trace]);

            ++js_trace;
        }

        // 强制使得位置位于1/2*pixels
        if (current_pixels < pixels / 2)
        {
            delta_x = pixels / 2 - current_pixels;
            current_pixels += delta_x;
            do_scroll(direction, delta_x);
        }

        // 减速阶段，是加速阶段的重放
        for (int i = js_trace - 1; i >= 0; --i)
        {
            current_pixels += trace[i];
            do_scroll(direction, trace[i]);
        }

        if (current_pixels > pixels)
            color_printk(RED, BLACK, "During scrolling: scrolled pixels over bound!");

        // 强制使得位置位于pixels
        if (current_pixels < pixels)
        {
            delta_x = pixels - current_pixels;
            current_pixels += delta_x;
            do_scroll(direction, delta_x);
        }
    }

    return 0;
}

int color_printk(unsigned int FRcolor, unsigned int BKcolor, const char *fmt, ...)
{
    int i = 0;
    int count = 0;
    int line = 0;
    va_list args;

    va_start(args, fmt);
    i = vsprintf(buf, fmt, args);
    va_end(args);

    spin_lock(&pos.spinlock);

    for (count = 0; count < i || line; count++)
    {
        ////	add \n \b \t
        if (line > 0)
        {
            count--;
            goto Label_tab;
        }
        if ((unsigned char)*(buf + count) == '\n')
        {
            pos.Yposition++;
            pos.Xposition = 0;
        }
        else if ((unsigned char)*(buf + count) == '\b')
        {
            pos.Xposition--;
            if (pos.Xposition < 0)
            {
                pos.Xposition = (pos.XResolution / pos.XCharSize - 1) * pos.XCharSize;
                pos.Yposition--;
                if (pos.Yposition < 0)
                    pos.Yposition = (pos.YResolution / pos.YCharSize - 1) * pos.YCharSize;
            }
            putchar(pos.FB_addr, pos.XResolution, pos.Xposition * pos.XCharSize, pos.Yposition * pos.YCharSize, FRcolor, BKcolor, ' ');
        }
        else if ((unsigned char)*(buf + count) == '\t')
        {
            line = ((pos.Xposition + 8) & ~(8 - 1)) - pos.Xposition;

        Label_tab:
            line--;
            putchar(pos.FB_addr, pos.XResolution, pos.Xposition * pos.XCharSize, pos.Yposition * pos.YCharSize, FRcolor, BKcolor, ' ');
            pos.Xposition++;
        }
        else
        {
            putchar(pos.FB_addr, pos.XResolution, pos.Xposition * pos.XCharSize, pos.Yposition * pos.YCharSize, FRcolor, BKcolor, (unsigned char)*(buf + count));
            pos.Xposition++;
        }

        if (pos.Xposition >= (pos.XResolution / pos.XCharSize))
        {
            pos.Yposition++;
            pos.Xposition = 0;
        }
        if (pos.Yposition >= (pos.YResolution / pos.YCharSize))
        {
            scroll(true, pos.YCharSize, false);
            pos.Yposition--;
        }
    }

    spin_unlock(&pos.spinlock);

    return i;
}

int sprintk(char *buf, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
}
