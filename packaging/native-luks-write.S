/* Linux x86_64 syscall fixture: exercise the mounted encrypted root and fsync.
 * No host libraries, startup code, credentials, or NARF implementation helpers.
 */
.section .text
.global _start
_start:
    mov $257, %eax                 /* openat(AT_FDCWD, path, WRONLY|CREAT|TRUNC, 0600) */
    mov $-100, %rdi
    lea path(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js failed_open
    mov %rax, %r12
    mov %rax, %rdi
    mov $1, %eax                   /* write(fd, payload, length) */
    lea payload(%rip), %rsi
    mov $payload_len, %edx
    syscall
    cmp $payload_len, %rax
    jne failed_write
    mov $74, %eax                  /* fsync(fd) */
    mov %r12, %rdi
    syscall
    test %rax, %rax
    jnz failed_sync
    mov $3, %eax                   /* close(fd) */
    mov %r12, %rdi
    syscall
    lea success(%rip), %rsi
    mov $success_len, %edx
    jmp report
failed_open:
    lea failure_open(%rip), %rsi
    mov $failure_open_len, %edx
    jmp report
failed_write:
    lea failure_write(%rip), %rsi
    mov $failure_write_len, %edx
    jmp report
failed_sync:
    lea failure_sync(%rip), %rsi
    mov $failure_sync_len, %edx
report:
    mov %rax, %r8
    mov $1, %eax
    mov $1, %edi
    syscall
    lea result_hex(%rip), %rsi
    lea digits(%rip), %rdi
    mov $15, %ecx
1:
    mov %r8, %rax
    and $15, %eax
    mov (%rdi,%rax), %al
    mov %al, (%rsi,%rcx)
    shr $4, %r8
    dec %ecx
    jns 1b
    movb $10, 16(%rsi)
    mov $1, %eax
    mov $1, %edi
    mov $17, %edx
    syscall
    mov $231, %eax                 /* exit_group */
    xor %edi, %edi
    syscall
.section .rodata
digits: .ascii "0123456789abcdef"
path: .asciz "/luks-rw-proof"
payload: .ascii "NARF-LUKS-PERSISTED\n"
.set payload_len, . - payload
success: .ascii "NARF-LUKS-RW-SYNCED\n"
.set success_len, . - success
failure_open: .ascii "NARF-LUKS-RW-OPEN-FAILED\n"
.set failure_open_len, . - failure_open
failure_write: .ascii "NARF-LUKS-RW-WRITE-FAILED\n"
.set failure_write_len, . - failure_write
failure_sync: .ascii "NARF-LUKS-RW-FSYNC-FAILED\n"
.set failure_sync_len, . - failure_sync
.section .bss
result_hex: .skip 17
.section .note.GNU-stack,"",@progbits
