#include "stat.h"
#include "sys/plant/call.h"

int mkdir(const char *path, mode_t mode)
{
    return syscall_invoke(SYS_MKDIR, (uint64_t)path, (uint64_t)mode, 0, 0, 0, 0);
}

int pipe(int *fd)
{
    return syscall_invoke(SYS_PIPE, (uint64_t)fd, 0, 0, 0, 0, 0);
}