/* Boot sector that raises an exact x86 #UD for the discontinuity API smoke. */
.code16
.section .text
.global _start
_start:
    cli
    ud2
1:
    hlt
    jmp 1b

.org 510
.word 0xaa55
