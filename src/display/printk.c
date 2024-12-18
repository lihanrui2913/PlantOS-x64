#include "display/printk.h"
#include "display/terminal.h"
#include "limine.h"
#include "spinlock.h"

spinlock_t global_printk_lock;

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
} pos;

struct limine_framebuffer *framebuffer = NULL;

void init_printk()
{
    if (framebuffer_request.response == NULL || framebuffer_request.response->framebuffer_count < 1)
    {
        for (;;)
            __asm__("hlt");
    }

    framebuffer = framebuffer_request.response->framebuffers[0];

    pos.FB_addr = framebuffer->address;
    pos.FB_length = framebuffer->bpp * framebuffer->width * framebuffer->height;

    pos.XResolution = framebuffer->width;
    pos.YResolution = framebuffer->height;

    pos.Xposition = 0;
    pos.Yposition = 0;

    pos.XCharSize = 8;
    pos.YCharSize = 16;

    spin_init(&global_printk_lock);
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

static char *const color_codes[] = {
    [BLACK] = "0",
    [RED] = "1",
    [GREEN] = "2",
    [YELLOW] = "3",
    [BLUE] = "4",
    [MAGENTA] = "5",
    [CYAN] = "6",
    [WHITE] = "7"};

void add_color(char *dest, uint32_t color, int is_background)
{
    strcat(dest, "\033[");
    strcat(dest, is_background ? "4" : "3");
    strcat(dest, color_codes[color]);
    strcat(dest, "m");
}

int color_printk(unsigned int FRcolor, unsigned int BKcolor, const char *fmt, ...)
{
    int i = 0;
    int count = 0;
    int line = 0;
    va_list args;

    uint64_t rflags;
    spin_lock_irqsave(&global_printk_lock, rflags);

    if (use_terminal)
    {
        buf[0] = '\0';

        add_color(buf, FRcolor, false);
        add_color(buf, BKcolor, true);

        va_start(args, fmt);
        i = vsprintf(buf + 11, fmt, args);
        va_end(args);

        strcat(buf, buf + 11);
        strcat(buf, "\033[0m");

        terminal_print(buf);
        spin_unlock_irqrestore(&global_printk_lock, rflags);
        return i;
    }

    va_start(args, fmt);
    i = vsprintf(buf, fmt, args);
    va_end(args);

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
            pos.Xposition = 0;
            pos.Yposition = 0;
        }
    }

    spin_unlock_irqrestore(&global_printk_lock, rflags);

    return i;
}

int sprintk(char *buf, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    int n = vsprintf(buf, fmt, args);
    va_end(args);

    return n;
}
