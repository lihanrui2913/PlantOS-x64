
#include <stdio.h>
#include <stdlib.h>

extern int main(int, char **);

void _start(int argc, char **argv)
{
    // printf("before main\n");
    int retval = main(argc, argv);
    // printf("before exit, code=%d\n", retval);
    exit(retval);
}
