#include "syscall/syscall.h"
#include "display/kprint.h"
#include "errno.h"
#include "gate.h"

syscall_handler_t system_call_table[MAX_SYSCALL_NUM] = {(syscall_handler_t)0};

extern void syscall_int();

uint64_t do_syscall_int(struct pt_regs *regs, unsigned long error_code)
{
    syscall_handler_t handler = system_call_table[regs->rax];
    if (handler == (syscall_handler_t)0)
    {
        kwarn("Unknown system call index: %d", regs->rax);
        return (uint64_t)-ENOSYS;
    }
    uint64_t ret = handler(regs);
    regs->rax = ret;
}

#include "process/process.h"

SYSCALL_DEFINER(sys_read)
{
    int fd_num = (int)regs->rdi;
    void *buf = (void *)regs->rsi;
    int64_t count = (int64_t)regs->rdx;

    // 校验文件描述符范围
    if (fd_num < 0 || fd_num > PROC_MAX_FD_NUM)
        return -EBADF;

    // 文件描述符不存在
    if (current_pcb->fds[fd_num] == NULL)
        return -EBADF;

    if (count < 0)
        return -EINVAL;

    struct vfs_file_t *file_ptr = current_pcb->fds[fd_num];
    uint64_t ret;
    if (file_ptr->file_ops && file_ptr->file_ops->read)
        ret = file_ptr->file_ops->read(file_ptr, (char *)buf, count, &(file_ptr->position));

    return ret;
}

SYSCALL_DEFINER(sys_write)
{
    int fd_num = (int)regs->rdi;
    void *buf = (void *)regs->rsi;
    int64_t count = (int64_t)regs->rdx;

    // 校验文件描述符范围
    if (fd_num < 0 || fd_num > PROC_MAX_FD_NUM)
        return -EBADF;

    // 文件描述符不存在
    if (current_pcb->fds[fd_num] == NULL)
        return -EBADF;

    if (count < 0)
        return -EINVAL;

    struct vfs_file_t *file_ptr = current_pcb->fds[fd_num];
    uint64_t ret;
    if (file_ptr->file_ops && file_ptr->file_ops->write)
        ret = file_ptr->file_ops->write(file_ptr, (char *)buf, count, &(file_ptr->position));

    return ret;
}

SYSCALL_DEFINER(sys_open)
{
    char *filename = (char *)(regs->rdi);
    int flags = (int)(regs->rsi);
    // kdebug("filename=%s", filename);

    long path_len = strlen(filename) + 1;

    if (path_len <= 0) // 地址空间错误
    {
        return -EFAULT;
    }
    else if (path_len >= PAGE_4K_SIZE) // 名称过长
    {
        return -ENAMETOOLONG;
    }

    // 为待拷贝文件路径字符串分配内存空间
    char *path = (char *)kalloc(path_len);
    if (path == NULL)
        return -ENOMEM;
    memset(path, 0, path_len);

    strncpy_from_user(path, filename, path_len);
    // 去除末尾的 '/'
    if (path_len >= 2 && path[path_len - 2] == '/')
    {
        path[path_len - 2] = '\0';
        --path_len;
    }

    // 寻找文件
    struct vfs_dir_entry_t *dentry = vfs_path_walk(path, 0);

    if (dentry == NULL && flags & O_CREAT)
    {
        // 先找到倒数第二级目录
        int tmp_index = -1;
        for (int i = path_len - 1; i >= 0; --i)
        {
            if (path[i] == '/')
            {
                tmp_index = i;
                break;
            }
        }

        struct vfs_dir_entry_t *parent_dentry = NULL;
        // kdebug("tmp_index=%d", tmp_index);
        if (tmp_index > 0)
        {

            path[tmp_index] = '\0';
            dentry = vfs_path_walk(path, 0);
            if (dentry == NULL)
            {
                kfree(path);
                return -ENOENT;
            }
            parent_dentry = dentry;
        }
        else
            parent_dentry = vfs_root_sb->root;

        // 创建新的文件
        dentry = (struct vfs_dir_entry_t *)kalloc(sizeof(struct vfs_dir_entry_t));
        memset(dentry, 0, sizeof(struct vfs_dir_entry_t));

        dentry->name_length = path_len - tmp_index - 1;
        dentry->name = (char *)kalloc(dentry->name_length);
        memset(dentry->name, 0, dentry->name_length);
        strncpy(dentry->name, path + tmp_index + 1, dentry->name_length);
        // kdebug("to create new file:%s   namelen=%d", dentry->name, dentry->name_length)
        dentry->parent = parent_dentry;
        uint64_t retval = parent_dentry->dir_inode->inode_ops->create(parent_dentry->dir_inode, dentry, 0);
        if (retval != 0)
        {
            kfree(dentry->name);
            kfree(dentry);
            kfree(path);
            return retval;
        }

        list_init(&dentry->child_node_list);
        list_init(&dentry->subdirs_list);
        list_add(&parent_dentry->subdirs_list, &dentry->child_node_list);
        // kdebug("created.");
    }
    kfree(path);
    if (dentry == NULL)
        return -ENOENT;

    // 要求打开文件夹而目标不是文件夹
    if ((flags & O_DIRECTORY) && (dentry->dir_inode->attribute != VFS_ATTR_DIR))
        return -ENOTDIR;

    // // 要找的目标是文件夹
    // if ((flags & O_DIRECTORY) && dentry->dir_inode->attribute == VFS_ATTR_DIR)
    //     return -EISDIR;

    // 创建文件描述符
    struct vfs_file_t *file_ptr = (struct vfs_file_t *)kalloc(sizeof(struct vfs_file_t));
    memset(file_ptr, 0, sizeof(struct vfs_file_t));

    int errcode = -1;

    file_ptr->dEntry = dentry;
    file_ptr->mode = flags;

    // todo: 接入devfs
    // 特判一下是否为键盘文件
    file_ptr->file_ops = dentry->dir_inode->file_ops;

    // 如果文件系统实现了打开文件的函数
    if (file_ptr->file_ops && file_ptr->file_ops->open)
        errcode = file_ptr->file_ops->open(dentry->dir_inode, file_ptr);

    if (errcode != VFS_SUCCESS)
    {
        kfree(file_ptr);
        return -EFAULT;
    }

    if (file_ptr->mode & O_TRUNC) // 清空文件
        file_ptr->dEntry->dir_inode->file_size = 0;

    if (file_ptr->mode & O_APPEND)
        file_ptr->position = file_ptr->dEntry->dir_inode->file_size;
    else
        file_ptr->position = 0;

    struct vfs_file_t **f = current_pcb->fds;

    int fd_num = -1;

    // 在指针数组中寻找空位
    // todo: 当pcb中的指针数组改为动态指针数组之后，需要更改这里（目前还是静态指针数组）
    for (int i = 0; i < PROC_MAX_FD_NUM; ++i)
    {
        if (f[i] == NULL) // 找到指针数组中的空位
        {
            fd_num = i;
            break;
        }
    }

    // 指针数组没有空位了
    if (fd_num == -1)
    {
        kfree(file_ptr);
        return -EMFILE;
    }
    // 保存文件描述符
    f[fd_num] = file_ptr;

    return fd_num;
}

SYSCALL_DEFINER(sys_close)
{
    int fd_num = (int)regs->rdi;

    // kdebug("sys close: fd=%d", fd_num);
    // 校验文件描述符范围
    if (fd_num < 0 || fd_num > PROC_MAX_FD_NUM)
        return -EBADF;
    // 文件描述符不存在
    if (current_pcb->fds[fd_num] == NULL)
        return -EBADF;
    struct vfs_file_t *file_ptr = current_pcb->fds[fd_num];
    uint64_t ret;
    // If there is a valid close function
    if (file_ptr->file_ops && file_ptr->file_ops->close)
        ret = file_ptr->file_ops->close(file_ptr->dEntry->dir_inode, file_ptr);

    kfree(file_ptr);
    current_pcb->fds[fd_num] = NULL;
    return 0;
}

#include "mm/memory.h"

SYSCALL_DEFINER(sys_brk)
{
    uint64_t new_brk = PAGE_4K_ALIGN(regs->rdi);

    // kdebug("sys_brk input= %#010lx ,  new_brk= %#010lx bytes current_pcb->mm->brk_start=%#018lx current->end_brk=%#018lx", regs->r8, new_brk, current_pcb->mm->brk_start, current_pcb->mm->brk_end);

    if ((int64_t)regs->rdi == -1)
    {
        // kdebug("get brk_start=%#018lx", current_pcb->mm->brk_start);
        return current_pcb->mm->brk_start;
    }
    if ((int64_t)regs->rdi == -2)
    {
        // kdebug("get brk_end=%#018lx", current_pcb->mm->brk_end);
        return current_pcb->mm->brk_end;
    }
    if (new_brk > current_pcb->addr_limit) // 堆地址空间超过限制
        return -ENOMEM;

    int64_t offset;
    if (new_brk >= current_pcb->mm->brk_end)
        offset = (int64_t)(new_brk - current_pcb->mm->brk_end);
    else
        offset = -(int64_t)(current_pcb->mm->brk_end - new_brk);

    new_brk = mm_do_brk(current_pcb->mm->brk_end, offset); // 扩展堆内存空间

    current_pcb->mm->brk_end = new_brk;
    return 0;
}

/**
 * @brief 将堆内存空间加上offset（注意，该系统调用只应在普通进程中调用，而不能是内核线程）
 *
 * @param arg0 offset偏移量
 * @return uint64_t the previous program break
 */
SYSCALL_DEFINER(sys_sbrk)
{
    uint64_t retval = current_pcb->mm->brk_end;
    if ((int64_t)regs->r8 > 0)
    {

        uint64_t new_brk = PAGE_2M_ALIGN(retval + regs->rdi);
        if (new_brk > current_pcb->addr_limit) // 堆地址空间超过限制
        {
            kdebug("exceed mem limit, new_brk = %#018lx", new_brk);
            return -ENOMEM;
        }
    }
    else
    {
        if ((__int128_t)current_pcb->mm->brk_end + (__int128_t)regs->rdi < current_pcb->mm->brk_start)
            return retval;
    }
    // kdebug("do brk");
    uint64_t new_brk = mm_do_brk(current_pcb->mm->brk_end, (int64_t)regs->rdi); // 调整堆内存空间
    // kdebug("do brk done, new_brk = %#018lx", new_brk);
    current_pcb->mm->brk_end = new_brk;
    return retval;
}

SYSCALL_DEFINER(sys_stat)
{
}

SYSCALL_DEFINER(sys_fstat)
{
}

SYSCALL_DEFINER(sys_lstat)
{
}

SYSCALL_DEFINER(sys_lseek)
{
    int fd_num = (int)regs->rdi;
    long offset = (long)regs->rsi;
    int whence = (int)regs->rdx;

    uint64_t retval = 0;

    // 校验文件描述符范围
    if (fd_num < 0 || fd_num > PROC_MAX_FD_NUM)
        return -EBADF;

    // 文件描述符不存在
    if (current_pcb->fds[fd_num] == NULL)
        return -EBADF;

    struct vfs_file_t *file_ptr = current_pcb->fds[fd_num];
    if (file_ptr->file_ops && file_ptr->file_ops->lseek)
        retval = file_ptr->file_ops->lseek(file_ptr, offset, whence);

    return retval;
}

SYSCALL_DEFINER(sys_mmap)
{
}

SYSCALL_DEFINER(sys_munmap)
{
}

SYSCALL_DEFINER(sys_fork)
{
    return do_fork(regs, 0, regs->rsp, 0);
}

SYSCALL_DEFINER(sys_vfork)
{
    return do_fork(regs, CLONE_VM | CLONE_FS | CLONE_SIGNAL, regs->rsp, 0);
}

#include "display/printk.h"

SYSCALL_DEFINER(sys_print)
{
    color_printk(WHITE, BLACK, (const char *)regs->rdi);
}

/**
 * @brief 获取目录中的数据
 *
 * @param fd 文件描述符号
 * @return uint64_t
 */
SYSCALL_DEFINER(sys_getdents)
{
    int fd = (int)regs->rdi;
    void *dirent = (void *)regs->rsi;
    long count = (long)regs->rdx;

    if (fd < 0 || fd > PROC_MAX_FD_NUM)
        return -EBADF;

    if (count < 0)
        return -EINVAL;

    struct vfs_file_t *filp = current_pcb->fds[fd];
    if (filp == NULL)
        return -EBADF;

    uint64_t retval = 0;
    if (filp->file_ops && filp->file_ops->readdir)
        retval = filp->file_ops->readdir(filp, dirent, &vfs_fill_dentry);

    return retval;
}

/**
 * @brief 执行新的程序
 *
 * @param user_path(r8寄存器) 文件路径
 * @param argv(r9寄存器) 参数列表
 * @return uint64_t
 */
SYSCALL_DEFINER(sys_execve)
{
    // kdebug("sys_execve");
    char *user_path = (char *)regs->rdi;
    char **argv = (char **)regs->rsi;

    int path_len = strlen(user_path);

    // kdebug("path_len=%d", path_len);
    if (path_len >= PAGE_4K_SIZE)
        return -ENAMETOOLONG;
    else if (path_len <= 0)
        return -EFAULT;

    char *path = (char *)kalloc(path_len + 1);
    if (path == NULL)
        return -ENOMEM;

    memset(path, 0, path_len + 1);

    // kdebug("before copy file path from user");
    // 拷贝文件路径
    strncpy_from_user(path, user_path, path_len);
    path[path_len] = '\0';

    // kdebug("before do_execve, path = %s", path);
    // 执行新的程序
    uint64_t retval = do_execve(regs, path, argv, NULL);

    kfree(path);
    return retval;
}

/**
 * @brief 等待进程退出
 *
 * @param pid 目标进程id
 * @param status 返回的状态信息
 * @param options 等待选项
 * @param rusage
 * @return uint64_t
 */
SYSCALL_DEFINER(sys_wait4)
{
    uint64_t pid = regs->rdi;
    int *status = (int *)regs->rsi;
    int options = regs->rdx;
    void *rusage = (void *)regs->r10;

    struct process_control_block *proc = NULL;
    struct process_control_block *child_proc = NULL;

    // 查找pid为指定值的进程
    // ps: 这里判断子进程的方法没有按照posix 2008来写。
    // todo: 根据进程树判断是否为当前进程的子进程
    for (proc = &initial_proc_union.pcb; proc->next_pcb != &initial_proc_union.pcb; proc = proc->next_pcb)
    {
        if (proc->next_pcb->pid == pid)
        {
            child_proc = proc->next_pcb;
            break;
        }
    }

    if (child_proc == NULL)
        return -ECHILD;

    // 暂时不支持options选项，该值目前必须为0
    if (options != 0)
        return -EINVAL;

    // 如果子进程没有退出，则等待其退出
    while (child_proc->state != PROC_ZOMBIE)
        wait_queue_sleep_on_interriptible(&current_pcb->wait_child_proc_exit);

    // 拷贝子进程的返回码
    if (status != NULL)
        *status = child_proc->exit_code;
    // copy_to_user(status, (void*)child_proc->exit_code, sizeof(int));
    proc->next_pcb = child_proc->next_pcb;

    // 释放子进程的页表
    process_exit_mm(child_proc);
    // 释放子进程的pcb
    kfree(child_proc);
    return 0;
}

/**
 * @brief 进程退出
 *
 * @param exit_code 退出返回码
 * @return uint64_t
 */
SYSCALL_DEFINER(sys_exit)
{
    return process_do_exit(regs->rdi);
}

/**
 * @brief nanosleep定时事件到期后，唤醒指定的进程
 *
 * @param pcb 待唤醒的进程的pcb
 */
void nanosleep_handler(void *pcb)
{
    process_wakeup((struct process_control_block *)pcb);
}

#include "timer.h"
#include "sched/sched.h"

struct timespec
{
    long int tv_sec;  // 秒
    long int tv_nsec; // 纳秒
};

/**
 * @brief 休眠指定时间
 *
 * @param rqtp 指定休眠的时间
 * @param rmtp 返回的剩余休眠时间
 * @return int
 */
int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
    int64_t total_ns = rqtp->tv_nsec;

    if (total_ns < 0 || total_ns >= 1000000000)
        return -EINVAL;

    // 增加定时任务
    struct timer_func_list_t *sleep_task = (struct timer_func_list_t *)kalloc(sizeof(struct timer_func_list_t));
    memset(sleep_task, 0, sizeof(struct timer_func_list_t));

    timer_func_init_us(sleep_task, &nanosleep_handler, (void *)current_pcb, total_ns / 1000);

    timer_func_add(sleep_task);

    current_pcb->state = PROC_INTERRUPTIBLE;
    current_pcb->flags |= PF_NEED_SCHED;
    sched();

    // todo: 增加信号唤醒的功能后，设置rmtp

    if (rmtp != NULL)
    {
        rmtp->tv_nsec = 0;
        rmtp->tv_sec = 0;
    }

    return 0;
}

SYSCALL_DEFINER(sys_nanosleep)
{
    const struct timespec *rqtp = (const struct timespec *)regs->rdi;
    struct timespec *rmtp = (struct timespec *)regs->rsi;

    return nanosleep(rqtp, rmtp);
}

void init_syscall()
{
    system_call_table[SYS_READ] = sys_read;
    system_call_table[SYS_WRITE] = sys_write;
    system_call_table[SYS_OPEN] = sys_open;
    system_call_table[SYS_CLOSE] = sys_close;
    system_call_table[SYS_BRK] = sys_brk;
    system_call_table[SYS_STAT] = sys_stat;
    system_call_table[SYS_FSTAT] = sys_fstat;
    system_call_table[SYS_LSTAT] = sys_lstat;
    system_call_table[SYS_LSEEK] = sys_lseek;
    system_call_table[SYS_MMAP] = sys_mmap;
    system_call_table[SYS_MUNMAP] = sys_munmap;
    system_call_table[SYS_FORK] = sys_fork;
    system_call_table[SYS_VFORK] = sys_vfork;
    system_call_table[SYS_PRINT] = sys_print;

    set_system_trap_gate(0x80, 0, syscall_int);
}

uint64_t enter_syscall_int(uint64_t rax, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    uint64_t ret;
    __asm__ __volatile__(
        "movq %%rdi, %%rax\n\t"
        "movq %%rsi, %%rdi\n\t"
        "movq %%rdx, %%rsi\n\t"
        "movq %%r10, %%rdx\n\t"
        "movq %%r8, %%r10\n\t"
        "movq %%r9, %%r8\n\t"
        "movq %1, %%r9\n\t"
        "int $0x80\n\t" : "=a"(ret) : "r"(arg6));
    return ret;
}
