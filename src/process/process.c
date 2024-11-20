#include "process/process.h"
#include "sched/sched.h"
#include <display/printk.h>
#include <display/kprint.h>
#include <gate.h>
#include <glib.h>
#include <mm/memory.h>
#include <syscall/syscall.h>

#include "elf.h"

#include "driver/device.h"
#include "driver/pci.h"
#include "driver/ahci.h"
#include "fs/fs.h"
#include "fs/fat32/fat32.h"
#include "driver/ps2_keyboard.h"

// #pragma GCC push_options
// #pragma GCC optimize("O0")

bool process_init_done = false;

spinlock_t process_global_pid_write_lock; // 增加pid的写锁
long process_global_pid = 1;              // 系统中最大的pid

extern void ret_from_system_call(void);
extern void kernel_thread_func(void);

struct mm_struct initial_mm = {0};
struct thread_struct initial_thread =
    {
        .rbp = (uint64_t)(initial_proc_union.stack + STACK_SIZE / sizeof(uint64_t)),
        .rsp = (uint64_t)(initial_proc_union.stack + STACK_SIZE / sizeof(uint64_t)),
        .fs = KERNEL_DS,
        .gs = KERNEL_DS,
        .cr2 = 0,
        .trap_num = 0,
        .err_code = 0};

union proc_union initial_proc_union __attribute__((used, section(".data.init_proc_union"))) = {INITIAL_PROC(initial_proc_union.pcb)};

struct process_control_block *initial_proc[MAX_CPU_NUM] = {&initial_proc_union.pcb, 0};

// 为每个核心初始化初始进程的tss
struct tss_struct initial_tss[MAX_CPU_NUM] = {[0 ... MAX_CPU_NUM - 1] = INITIAL_TSS};

/**
 * @brief 拷贝当前进程的标志位
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_flags(uint64_t clone_flags, struct process_control_block *pcb);

/**
 * @brief 拷贝当前进程的内存空间分布结构体信息
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_mm(uint64_t clone_flags, struct process_control_block *pcb);

/**
 * @brief 释放进程的页表
 *
 * @param pcb 要被释放页表的进程
 * @return uint64_t
 */
uint64_t process_exit_mm(struct process_control_block *pcb);

/**
 * @brief 拷贝当前进程的线程结构体
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_thread(uint64_t clone_flags, struct process_control_block *pcb, uint64_t stack_start, uint64_t stack_size, struct pt_regs *current_regs);

void process_exit_thread(struct process_control_block *pcb);

/**
 * @brief 切换进程
 *
 * @param prev 上一个进程的pcb
 * @param next 将要切换到的进程的pcb
 * 由于程序在进入内核的时候已经保存了寄存器，因此这里不需要保存寄存器。
 * 这里切换fs和gs寄存器
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
__attribute__((used)) void __switch_to(struct process_control_block *prev, struct process_control_block *next)
{
    initial_tss[proc_current_cpu_id].rsp0 = next->thread->rbp;
    // kdebug("next_rsp = %#018lx   ", next->thread->rsp);
    set_tss64((uint32_t *)&initial_tss[proc_current_cpu_id], initial_tss[0].rsp0, initial_tss[0].rsp1, initial_tss[0].rsp2, initial_tss[0].ist1,
              initial_tss[0].ist2, initial_tss[0].ist3, initial_tss[0].ist4, initial_tss[0].ist5, initial_tss[0].ist6, initial_tss[0].ist7);

    __asm__ __volatile__("movq	%%fs,	%0 \n\t"
                         : "=a"(prev->thread->fs));
    __asm__ __volatile__("movq	%%gs,	%0 \n\t"
                         : "=a"(prev->thread->gs));

    __asm__ __volatile__("movq	%0,	%%fs \n\t" ::"a"(next->thread->fs));
    __asm__ __volatile__("movq	%0,	%%gs \n\t" ::"a"(next->thread->gs));
}
#pragma GCC pop_options

/**
 * @brief 打开要执行的程序文件
 *
 * @param path
 * @return struct vfs_file_t*
 */
struct vfs_file_t *process_open_exec_file(char *path)
{
    struct vfs_dir_entry_t *dentry = NULL;
    struct vfs_file_t *filp = NULL;

    dentry = vfs_path_walk(path, 0);

    if (dentry == NULL)
        return (void *)-ENOENT;

    if (dentry->dir_inode->attribute == VFS_ATTR_DIR)
        return (void *)-ENOTDIR;

    filp = (struct vfs_file_t *)kalloc(sizeof(struct vfs_file_t));
    if (filp == NULL)
        return (void *)-ENOMEM;

    filp->position = 0;
    filp->mode = 0;
    filp->dEntry = dentry;
    filp->mode = ATTR_READ_ONLY;
    filp->file_ops = dentry->dir_inode->file_ops;

    return filp;
}

/**
 * @brief 加载elf格式的程序文件到内存中，并设置regs
 *
 * @param regs 寄存器
 * @param path 文件路径
 * @return int
 */
static int process_load_elf_file(struct pt_regs *regs, char *path)
{
    int retval = 0;
    struct vfs_file_t *filp = process_open_exec_file(path);

    if ((long)filp <= 0 && (long)filp >= -255)
    {
        return (unsigned long)filp;
    }

    void *buf = kalloc(PAGE_4K_SIZE);
    memset(buf, 0, PAGE_4K_SIZE);
    uint64_t pos = 0;
    pos = filp->file_ops->lseek(filp, 0, SEEK_SET);
    retval = filp->file_ops->read(filp, (char *)buf, sizeof(Elf64_Ehdr), &pos);
    retval = 0;
    if (!elf_check(buf))
    {
        kerror("Not an ELF file: %s", path);
        retval = -ENOTSUP;
        goto load_elf_failed;
    }
    // 暂时只支持64位的文件
    if (((Elf32_Ehdr *)buf)->e_ident[EI_CLASS] != ELFCLASS64)
    {
        kdebug("((Elf32_Ehdr *)buf)->e_ident[EI_CLASS]=%d", ((Elf32_Ehdr *)buf)->e_ident[EI_CLASS]);
        retval = -ENOTSUP;
        goto load_elf_failed;
    }
    Elf64_Ehdr ehdr = *(Elf64_Ehdr *)buf;
    // 暂时只支持AMD64架构
    if (ehdr.e_machine != EM_AMD64)
    {
        kerror("e_machine=%d", ehdr.e_machine);
        retval = -ENOTSUP;
        goto load_elf_failed;
    }

    if (ehdr.e_type != ET_EXEC)
    {
        kerror("Not executable file! filename=%s\tehdr->e_type=%d", path, ehdr.e_type);
        retval = -ENOTSUP;
        goto load_elf_failed;
    }
    // kdebug("filename=%s:\te_entry=%#018lx", path, ehdr.e_entry);
    regs->rip = ehdr.e_entry;

    // kdebug("ehdr.e_phoff=%#018lx\t ehdr.e_phentsize=%d, ehdr.e_phnum=%d", ehdr.e_phoff, ehdr.e_phentsize, ehdr.e_phnum);
    // 将指针移动到program header处
    pos = ehdr.e_phoff;
    // 读取所有的phdr
    pos = filp->file_ops->lseek(filp, pos, SEEK_SET);
    filp->file_ops->read(filp, (char *)buf, (uint64_t)ehdr.e_phentsize * (uint64_t)ehdr.e_phnum, &pos);
    if ((unsigned long)filp <= 0)
    {
        kdebug("(unsigned long)filp=%d", (long)filp);
        retval = -ENOEXEC;
        goto load_elf_failed;
    }
    Elf64_Phdr *phdr = buf;

    // 将程序加载到内存中
    for (int i = 0; i < ehdr.e_phnum; ++i, ++phdr)
    {
        // kdebug("phdr[%d] phdr->p_offset=%#018lx phdr->p_vaddr=%#018lx phdr->p_memsz=%ld phdr->p_filesz=%ld  phdr->p_type=%d", i, phdr->p_offset, phdr->p_vaddr, phdr->p_memsz, phdr->p_filesz, phdr->p_type);

        // 不是可加载的段
        if (phdr->p_type != PT_LOAD)
            continue;

        int64_t remain_mem_size = phdr->p_memsz;
        int64_t remain_file_size = phdr->p_filesz;
        pos = phdr->p_offset;

        uint64_t virt_base = phdr->p_vaddr;
        // kdebug("virt_base = %#018lx, &memory_management_struct=%#018lx", virt_base, &memory_management_struct);

        while (remain_mem_size > 0)
        {

            // todo: 改用slab分配4K大小内存块并映射到4K页
            if (!mm_check_mapped((uint64_t)current_pcb->mm->pgd, virt_base)) // 未映射，则新增物理页
            {
                vmm_mmap((uint64_t)current_pcb->mm->pgd, true, virt_base, allocate_frame(), PAGE_4K_SIZE, PAGE_U_S | PAGE_R_W | PAGE_PRESENT, true, true);
                memset((void *)virt_base, 0, PAGE_4K_SIZE);
            }
            pos = filp->file_ops->lseek(filp, pos, SEEK_SET);
            int64_t val = 0;
            if (remain_file_size != 0)
            {
                int64_t to_trans = (remain_file_size > PAGE_4K_SIZE) ? PAGE_4K_SIZE : remain_file_size;
                val = filp->file_ops->read(filp, (char *)virt_base, to_trans, &pos);
            }

            if (val < 0)
                goto load_elf_failed;

            remain_mem_size -= PAGE_4K_SIZE;
            remain_file_size -= val;
            virt_base += PAGE_4K_SIZE;
        }
    }

    // 分配2MB的栈内存空间
    regs->rsp = current_pcb->mm->stack_start;
    regs->rbp = current_pcb->mm->stack_start;

    vmm_mmap((uint64_t)current_pcb->mm->pgd, true, current_pcb->mm->stack_start - PAGE_4K_SIZE, allocate_frame(), PAGE_4K_SIZE, PAGE_U_S | PAGE_R_W | PAGE_PRESENT, true, true);
    // 清空栈空间
    memset((void *)(current_pcb->mm->stack_start - PAGE_4K_SIZE), 0, PAGE_4K_SIZE);

load_elf_failed:;
    if (buf != NULL)
        kfree(buf);
    return retval;
}

/**
 * @brief 使当前进程去执行新的代码
 *
 * @param regs 当前进程的寄存器
 * @param path 可执行程序的路径
 * @param argv 参数列表
 * @param envp 环境变量
 * @return uint64_t 错误码
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
__attribute__((used)) uint64_t do_execve(struct pt_regs *regs, char *path, char *argv[], char *envp[])
{
    // 当前进程正在与父进程共享地址空间，需要创建
    // 独立的地址空间才能使新程序正常运行
    if (current_pcb->flags & PF_VFORK)
    {
        // 分配新的内存空间分布结构体
        struct mm_struct *new_mms = (struct mm_struct *)kalloc(sizeof(struct mm_struct));
        memset(new_mms, 0, sizeof(struct mm_struct));
        current_pcb->mm = new_mms;

        // 分配顶层页表, 并设置顶层页表的物理地址
        new_mms->pgd = (pml4t_t *)allocate_frame();

        // 由于高2K部分为内核空间，在接下来需要覆盖其数据，因此不用清零
        memset(phy_2_virt(new_mms->pgd), 0, PAGE_4K_SIZE / 2);

        // 拷贝内核空间的页表指针
        memcpy(phy_2_virt(new_mms->pgd) + 256, phy_2_virt(initial_proc[proc_current_cpu_id]) + 256, PAGE_4K_SIZE / 2);
    }

    // 设置用户栈和用户堆的基地址
    unsigned long stack_start_addr = 0x6ffff0a00000UL;
    const uint64_t brk_start_addr = 0x700000000000UL;

    vmm_mmap((uint64_t)current_pcb->mm->pgd, true, stack_start_addr - PAGE_2M_SIZE, 0, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_U_S, true, true);
    vmm_mmap((uint64_t)current_pcb->mm->pgd, true, brk_start_addr, 0, PAGE_2M_SIZE, PAGE_PRESENT | PAGE_R_W | PAGE_U_S, true, true);

    process_switch_mm(current_pcb);

    // 为用户态程序设置地址边界
    if (!(current_pcb->flags & PF_KTHREAD))
        current_pcb->addr_limit = PAGE_OFFSET - 1;

    current_pcb->mm->brk_start = brk_start_addr;
    current_pcb->mm->brk_end = brk_start_addr;
    current_pcb->mm->stack_start = stack_start_addr;

    // 清除进程的vfork标志位
    current_pcb->flags &= ~PF_VFORK;

    // 拷贝参数列表
    if (argv != NULL)
    {
        int argc = 0;

        // 目标程序的argv基地址指针，最大8个参数
        char **dst_argv = (char **)(stack_start_addr - (sizeof(char **) << 3));
        uint64_t str_addr = (uint64_t)dst_argv;

        for (argc = 0; argc < 8 && argv[argc] != NULL; ++argc)
        {

            if (*argv[argc] == 0)
                break;

            // 测量参数的长度（最大1023）
            int argv_len = strlen(argv[argc]) + 1;
            strncpy((char *)(str_addr - argv_len), argv[argc], argv_len - 1);
            str_addr -= argv_len;
            dst_argv[argc] = (char *)str_addr;
            // 字符串加上结尾字符
            ((char *)str_addr)[argv_len] = '\0';
        }

        // 重新设定栈基址，并预留空间防止越界
        stack_start_addr = str_addr - 8;
        current_pcb->mm->stack_start = stack_start_addr;
        regs->rsp = regs->rbp = stack_start_addr;

        // 传递参数
        regs->rdi = argc;
        regs->rsi = (uint64_t)dst_argv;
    }

    int ret = process_load_elf_file(regs, path);
    if (ret < 0)
    {
        kerror("Cannot load elf file: %s", path);
        for (;;)
        {
            hlt();
        }
    }

    regs->cs = USER_CS | 0x3;
    regs->ds = USER_DS | 0x3;
    regs->ss = USER_DS | 0x3;
    regs->rflags = 0x200246;
    regs->rax = 1;
    regs->es = 0;
    regs->rbp = regs->rsp = current_pcb->mm->stack_start;

    return 0;
}
#pragma GCC pop_options

/**
 * @brief 内核init进程
 *
 * @param arg
 * @return uint64_t 参数
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
uint64_t initial_kernel_thread(uint64_t arg)
{
    color_printk(BLUE, BLACK, "initial kernel thread is running! arg = %#018lx, cpu_id = %d\n", arg, proc_current_cpu_id);

    init_device();
    init_pci();
    init_ahci();

    init_fs();
    init_fat32();

    init_ps2keyboard();

    // 准备切换到用户态
    struct pt_regs *regs;

    // 若在后面这段代码中触发中断，return时会导致段选择子错误，从而触发#GP，因此这里需要cli
    cli();
    current_pcb->thread->rip = (uint64_t)ret_from_system_call;
    current_pcb->thread->rsp = (uint64_t)current_pcb + STACK_SIZE - sizeof(struct pt_regs);
    current_pcb->thread->fs = USER_DS | 0x3;
    current_pcb->thread->gs = USER_DS | 0x3;

    // 主动放弃内核线程身份
    current_pcb->flags &= (~PF_KTHREAD);
    kdebug("in initial_kernel_thread: flags=%ld", current_pcb->flags);

    regs = (struct pt_regs *)current_pcb->thread->rsp;
    current_pcb->flags = 0;
    // 加载用户态程序: init.elf
    __asm__ __volatile__("movq %1, %%rsp   \n\t"
                         "pushq %2    \n\t"
                         "jmp do_execve  \n\t" ::"D"(current_pcb->thread->rsp),
                         "m"(current_pcb->thread->rsp), "m"(current_pcb->thread->rip), "S"("/init.elf"), "c"(NULL), "d"(NULL)
                         : "memory");

    return 1;
}
#pragma GCC pop_options

/**
 * @brief 当子进程退出后向父进程发送通知
 *
 */
void process_exit_notify()
{
    wait_queue_wakeup(&current_pcb->parent_pcb->wait_child_proc_exit, PROC_INTERRUPTIBLE);
}

/**
 * @brief 进程退出时执行的函数
 *
 * @param code 返回码
 * @return ul
 */
uint64_t process_do_exit(uint64_t code)
{
    cli();
    struct process_control_block *pcb = current_pcb;

    // 进程退出时释放资源
    process_exit_thread(pcb);
    // todo: 可否在这里释放内存结构体？（在判断共享页引用问题之后）

    pcb->state = PROC_ZOMBIE;
    pcb->exit_code = code;
    sti();

    process_exit_notify();
    sched();

    while (1)
        pause();
}

/**
 * @brief 初始化内核进程
 *
 * @param fn 目标程序的地址
 * @param arg 向目标程序传入的参数
 * @param flags
 * @return int
 */

int kernel_thread(unsigned long (*fn)(unsigned long), unsigned long arg, unsigned long flags)
{
    struct pt_regs regs;
    io_mfence();
    memset(&regs, 0, sizeof(regs));
    io_mfence();
    // 在rbx寄存器中保存进程的入口地址
    regs.rbx = (uint64_t)fn;
    // 在rdx寄存器中保存传入的参数
    regs.rdx = (uint64_t)arg;
    io_mfence();
    regs.cs = KERNEL_CS;
    io_mfence();
    regs.ds = KERNEL_DS;
    io_mfence();
    regs.es = KERNEL_DS;
    io_mfence();
    regs.ss = KERNEL_DS;
    io_mfence();

    // 置位中断使能标志位
    regs.rflags = (1 << 9);
    io_mfence();
    // rip寄存器指向内核线程的引导程序
    regs.rip = (uint64_t)kernel_thread_func;
    io_mfence();

    return do_fork(&regs, flags | CLONE_VM, 0, 0);
}

/**
 * @brief 初始化进程模块
 * ☆前置条件：已完成系统调用模块的初始化
 */
void init_process()
{
    kinfo("Initializing process...");
    initial_mm.pgd = (pml4t_t *)get_cr3();

    initial_mm.brk_end = current_pcb->addr_limit;

    initial_tss[proc_current_cpu_id].rsp0 = initial_thread.rbp;

    // 初始化pid的写锁
    spin_init(&process_global_pid_write_lock);
    // 初始化进程的循环链表
    list_init(&initial_proc_union.pcb.list);
    io_mfence();
    kernel_thread(initial_kernel_thread, 0x1103, CLONE_FS | CLONE_SIGNAL); // 初始化内核线程
    io_mfence();

    initial_proc_union.pcb.state = PROC_RUNNING;
    initial_proc_union.pcb.preempt_count = 0;
    initial_proc_union.pcb.cpu_id = 0;
    initial_proc_union.pcb.virtual_runtime = (1UL << 60);
    current_pcb->virtual_runtime = (1UL << 60);

    ksuccess("process initialized");
}

/**
 * @brief fork当前进程
 *
 * @param regs 新的寄存器值
 * @param clone_flags 克隆标志
 * @param stack_start 堆栈开始地址
 * @param stack_size 堆栈大小
 * @return unsigned long
 */
int do_fork(struct pt_regs *regs, unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size)
{
    int retval = 0;
    struct process_control_block *tsk = (struct process_control_block *)phy_2_virt(allocate_frame());

    io_mfence();
    if (tsk == NULL)
    {
        retval = -ENOMEM;
        return retval;
    }

    io_mfence();
    memset(tsk, 0, sizeof(struct process_control_block));
    io_mfence();
    // 将当前进程的pcb复制到新的pcb内
    memcpy(current_pcb, tsk, sizeof(struct process_control_block));
    io_mfence();

    // 初始化进程的循环链表结点
    list_init(&tsk->list);

    io_mfence();
    // 判断是否为内核态调用fork
    if (current_pcb->flags & PF_KTHREAD && stack_start != 0)
        tsk->flags |= PF_KFORK;

    tsk->priority = 2;
    tsk->preempt_count = 0;

    // 增加全局的pid并赋值给新进程的pid
    spin_lock(&process_global_pid_write_lock);
    tsk->pid = process_global_pid++;
    io_mfence();
    // 加入到进程链表中
    tsk->next_pcb = initial_proc_union.pcb.next_pcb;
    io_mfence();
    initial_proc_union.pcb.next_pcb = tsk;
    io_mfence();
    tsk->parent_pcb = current_pcb;
    io_mfence();

    spin_unlock(&process_global_pid_write_lock);

    tsk->cpu_id = proc_current_cpu_id;
    tsk->state = PROC_UNINTERRUPTIBLE;

    tsk->parent_pcb = current_pcb;
    wait_queue_init(&tsk->wait_child_proc_exit, NULL);
    io_mfence();
    list_init(&tsk->list);

    retval = -ENOMEM;

    // 拷贝标志位
    if (process_copy_flags(clone_flags, tsk))
        goto copy_flags_failed;

    // 拷贝内存空间分布结构体
    if (process_copy_mm(clone_flags, tsk))
        goto copy_mm_failed;

    // 拷贝线程结构体
    if (process_copy_thread(clone_flags, tsk, stack_start, stack_size, regs))
        goto copy_thread_failed;

    // 拷贝成功
    retval = tsk->pid;

    tsk->flags &= ~PF_KFORK;

    // 唤醒进程
    process_wakeup(tsk);

    return retval;

copy_thread_failed:;
    // 回收线程
    process_exit_thread(tsk);
copy_mm_failed:;
    // 回收内存空间分布结构体
    process_exit_mm(tsk);
copy_flags_failed:;
    kfree(tsk);
    return retval;

    return 0;
}

/**
 * @brief 根据pid获取进程的pcb
 *
 * @param pid
 * @return struct process_control_block*
 */
struct process_control_block *process_get_pcb(long pid)
{
    struct process_control_block *pcb = initial_proc_union.pcb.next_pcb;

    for (; pcb != &initial_proc_union.pcb; pcb = pcb->next_pcb)
    {
        if (pcb->pid == pid)
            return pcb;
    }
    return NULL;
}

/**
 * @brief 将进程加入到调度器的就绪队列中
 *
 * @param pcb 进程的pcb
 */
void process_wakeup(struct process_control_block *pcb)
{
    pcb->state = PROC_RUNNING;
    sched_enqueue(pcb);
}

/**
 * @brief 将进程加入到调度器的就绪队列中，并标志当前进程需要被调度
 *
 * @param pcb 进程的pcb
 */
void process_wakeup_immediately(struct process_control_block *pcb)
{
    pcb->state = PROC_RUNNING;
    sched_enqueue(pcb);
    // 将当前进程标志为需要调度，缩短新进程被wakeup的时间
    current_pcb->flags |= PF_NEED_SCHED;
}

/**
 * @brief 拷贝当前进程的标志位
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_flags(uint64_t clone_flags, struct process_control_block *pcb)
{
    if (clone_flags & CLONE_VM)
        pcb->flags |= PF_VFORK;
    return 0;
}

/**
 * @brief 拷贝当前进程的内存空间分布结构体信息
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_mm(uint64_t clone_flags, struct process_control_block *pcb)
{
    int retval = 0;
    // 与父进程共享内存空间
    if (clone_flags & CLONE_VM)
    {
        pcb->mm = current_pcb->mm;
        return retval;
    }

    // 分配新的内存空间分布结构体
    struct mm_struct *new_mms = (struct mm_struct *)kalloc(sizeof(struct mm_struct));
    memset(new_mms, 0, sizeof(struct mm_struct));
    new_mms->pgd = (pml4t_t *)allocate_frame();
    memcpy(current_pcb->mm->pgd, new_mms->pgd, PAGE_4K_SIZE);

    pcb->mm = new_mms;

    return retval;
}

/**
 * @brief 释放进程的页表
 *
 * @param pcb 要被释放页表的进程
 * @return uint64_t
 */
uint64_t process_exit_mm(struct process_control_block *pcb)
{
    if (pcb->flags & CLONE_VM)
        return 0;
    if (pcb->mm == NULL)
    {
        kdebug("pcb->mm==NULL");
        return 0;
    }
    if (pcb->mm->pgd == NULL)
    {
        kdebug("pcb->mm==NULL");
        return 0;
    }

    deallocate_frame((uint64_t)pcb->mm->pgd);
    // 释放内存空间分布结构体
    kfree(pcb->mm);

    return 0;
}

/**
 * @brief 拷贝当前进程的线程结构体
 *
 * @param clone_flags 克隆标志位
 * @param pcb 新的进程的pcb
 * @return uint64_t
 */
uint64_t process_copy_thread(uint64_t clone_flags, struct process_control_block *pcb, uint64_t stack_start, uint64_t stack_size, struct pt_regs *current_regs)
{
    // 将线程结构体放置在pcb后方
    struct thread_struct *thd = (struct thread_struct *)phy_2_virt(allocate_frame());
    memset(thd, 0, sizeof(struct thread_struct));
    pcb->thread = thd;

    // 拷贝栈空间
    struct pt_regs *child_regs = (struct pt_regs *)((uint64_t)pcb + STACK_SIZE - sizeof(struct pt_regs));
    memcpy(current_regs, child_regs, sizeof(struct pt_regs));

    // 设置子进程的返回值为0
    child_regs->rax = 0;
    child_regs->rsp = stack_start;

    thd->rbp = (uint64_t)pcb + STACK_SIZE;
    thd->rsp = (uint64_t)child_regs;
    thd->fs = current_pcb->thread->fs;
    thd->gs = current_pcb->thread->gs;

    // 根据是否为内核线程，设置进程的开始执行的地址
    if (pcb->flags & PF_KTHREAD)
        thd->rip = (uint64_t)kernel_thread_func;
    else
        thd->rip = (uint64_t)ret_from_system_call;
    return 0;
}

/**
 * @brief todo: 回收线程结构体
 *
 * @param pcb
 */
void process_exit_thread(struct process_control_block *pcb)
{
}
