#include "stdio.h"
#include "fcntl.h"
#include "unistd.h"
#include "keyboard.h"

int main()
{
    printf("Hello world!!!\n");

    int fd = open("/dev/kbd.dev", O_RDONLY);
    while (1)
    {
        int key = keyboard_analyze_keycode(fd);
        if (key != 0)
        {
            printf("key = %c", (char)key);
        }
    }
}
