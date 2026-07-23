/* Minimal BIOS boot sector for validating the QEMU plugin's CPUID marker
 * channel without waiting for Windows to boot. */
.code16
.section .text
.global _start
_start:
    cli

    /* Exact retained writes for the branchless memory-buffer smoke. */
    movw $0x7000, %di
    movw $0x1111, (%di)
    movw $0x2222, 2(%di)

    movl $0x5041434b, %eax
    movl $1234, %ebx
    movl $1, %ecx
    movl $7, %edx
    .byte 0x67, 0x0f, 0x1f, 0x84, 0x00, 0x4b, 0x43, 0x41, 0x50
    cpuid

    movl $0x5041434b, %eax
    movl $1234, %ebx
    movl $2, %ecx
    movl $7, %edx
    .byte 0x67, 0x0f, 0x1f, 0x84, 0x00, 0x4b, 0x43, 0x41, 0x50
    cpuid

    movl $0x5041434b, %eax
    movl $1234, %ebx
    movl $3, %ecx
    movl $0, %edx
    .byte 0x67, 0x0f, 0x1f, 0x84, 0x00, 0x4b, 0x43, 0x41, 0x50
    cpuid

    /* isa-debug-exit makes the test terminate without relying on firmware. */
    movw $0xf4, %dx
    movl $0x10, %eax
    outl %eax, %dx
1:
    hlt
    jmp 1b

.org 510
.word 0xaa55
