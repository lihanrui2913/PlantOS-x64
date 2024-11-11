.section .data

.align 16
.global GDT_Table // 使得GDT可以被外部程序引用或者访问

GDT_Table:
    .quad 0x0000000000000000 // 0 空描述符 0x00
    .quad 0x0020980000000000 // 1 内核64位代码段描述符 0x08
    .quad 0x0000920000000000 // 2 内核64位数据段描述符 0x10
    .quad 0x0000000000000000 // 3 用户32位代码段描述符 0x18
    .quad 0x0000000000000000 // 4 用户32位数据段描述符 0x20
    .quad 0x0020f80000000000 // 5 用户64位代码段描述符 0x28
    .quad 0x0000f20000000000 // 6 用户64位数据段描述符 0x30
    .quad 0x00cf9a000000ffff // 7 内核32位代码段描述符 0x38
    .quad 0x00cf92000000ffff // 8 内核32位数据段描述符 0x40
    .fill 100, 8, 0          // 10-11 TSS(跳过了第9段)  重复十次填充8字节的空间，赋值为0   长模式下，每个TSS长度为128bit
GDT_END:

.global GDT_POINTER
GDT_POINTER:
GDT_LIMIT: .word GDT_END - GDT_Table - 1 // GDT的大小
GDT_BASE: .quad GDT_Table

.section .text
.global init_gdt
init_gdt:
    lgdt GDT_POINTER

    mov $0x10, %rax
    mov %rax, %ds
    mov %rax, %es
    mov %rax, %fs
    mov %rax, %gs
    mov %rax, %ss

    movq $flush_gdt, %rax
    pushq $0x08
    pushq %rax
    lretq

flush_gdt:
    jmp kstage2

.global init_ap_gdt
init_ap_gdt:
    lgdt GDT_POINTER

    mov $0x10, %rax
    mov %rax, %ds
    mov %rax, %es
    mov %rax, %fs
    mov %rax, %gs
    mov %rax, %ss

    movq $flush_ap_gdt, %rax
    pushq $0x08
    pushq %rax
    lretq

flush_ap_gdt:
    jmp kap_stage2
