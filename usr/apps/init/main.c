#include "stdio.h"

int main()
{
    printf("Hello world!!!");
    while (1)
        __asm__("pause");

    return 0;
}
