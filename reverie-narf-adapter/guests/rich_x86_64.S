// A richer libc-free x86_64 guest for the Narf/Reverie/Hermit parity cell.
//
// It adds a fixed-address anonymous mapping, error returns, a scheduler call
// and memory-protection changes to the canonical guest's write-then-exit.
// Every syscall result is host-independent by construction:
//
// - The mapping uses MAP_FIXED_NOREPLACE at RICH_ADDR, far above the guest
//   image (0x80_0000_1000) and far below the user stack, so its result is
//   RICH_ADDR on every kernel; an occupied range fails with -EEXIST instead
//   of silently replacing a mapping.
// - RICH_ADDR is 0x200_0000_0000 (PML4 slot 4), not 0x81_0000_0000. Narf
//   once left the range 0x80_4000_0000..0x100_0000_0000 covered by the
//   kernel's supervisor-only 1 GiB identity pages (PML4[1], shared into
//   every user address space), so mmap accepted it and the first user store
//   faulted. That kernel bug is fixed and the window guest pins it; this
//   guest keeps the address it was recorded with. Slot 4 is also
//   clear of Narf's brk arena (from 0x1000_0000_0000), its mmap window
//   (from 0x4080_0000_0000) and its vDSO (0x7fff_0000_0000).
// - BAD_FD is 0x7fffffff, above Linux's NR_OPEN ceiling (2147483584), so no
//   host can have it open and a write or close on it is -EBADF.
//
// The canonical trace Tool records arguments and results only for write, so
// the result R of every other call is reflected into the fd of the next
// write: write(BAD_FD + R, reflect, 1). Every such fd is still out of range,
// the write returns -EBADF, and R is visible in the write's a0. The guest
// does not branch on reflected results; the trace is the check.

    .intel_syntax noprefix
    .global _start
    .section .text

    .set RICH_ADDR, 0x20000000000
    .set PAGE, 4096
    .set BAD_FD, 0x7fffffff
    .set PROT_READ, 1
    .set PROT_READ_WRITE, 3
    .set MAP_PRIVATE_ANON_NOREPLACE, 0x100022

_start:
    // mmap(RICH_ADDR, PAGE, PROT_READ|PROT_WRITE,
    //      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0)
    mov     eax, 9
    mov     rdi, RICH_ADDR
    mov     esi, PAGE
    mov     edx, PROT_READ_WRITE
    mov     r10d, MAP_PRIVATE_ANON_NOREPLACE
    mov     r8, -1
    xor     r9d, r9d
    syscall
    mov     rbx, RICH_ADDR
    cmp     rax, rbx
    jne     mmap_failed

    // Store the first message into the fresh page.
    lea     rsi, [rip + mapped_message]
    mov     rdi, rbx
    mov     ecx, mapped_message_end - mapped_message
    rep movsb

    // write(1, mapping, len): the buffer is mmap's own result.
    mov     eax, 1
    mov     edi, 1
    mov     rsi, rbx
    mov     edx, mapped_message_end - mapped_message
    syscall
    cmp     rax, mapped_message_end - mapped_message
    jne     write_failed

    // write(BAD_FD, reflect, 1) = -EBADF
    mov     eax, 1
    mov     edi, BAD_FD
    lea     rsi, [rip + reflect]
    mov     edx, 1
    syscall

    // close(BAD_FD) = -EBADF, reflected.
    mov     eax, 3
    mov     edi, BAD_FD
    syscall
    call    reflect_rax

    // sched_yield() = 0, reflected.
    mov     eax, 24
    syscall
    call    reflect_rax

    // mprotect(mapping, PAGE, PROT_READ) = 0, reflected.
    mov     eax, 10
    mov     rdi, rbx
    mov     esi, PAGE
    mov     edx, PROT_READ
    syscall
    call    reflect_rax

    // write(1, mapping, len) from the now read-only page.
    mov     eax, 1
    mov     edi, 1
    mov     rsi, rbx
    mov     edx, mapped_message_end - mapped_message
    syscall
    cmp     rax, mapped_message_end - mapped_message
    jne     write_failed

    // munmap(mapping, PAGE) = 0, reflected.
    mov     eax, 11
    mov     rdi, rbx
    mov     esi, PAGE
    syscall
    call    reflect_rax

    // write(1, rodata, len)
    mov     eax, 1
    mov     edi, 1
    lea     rsi, [rip + final_message]
    mov     edx, final_message_end - final_message
    syscall
    cmp     rax, final_message_end - final_message
    jne     write_failed

    // exit(0)
    mov     eax, 60
    xor     edi, edi
    syscall
    ud2

// write(BAD_FD + rax, reflect, 1): makes a non-write result visible.
reflect_rax:
    lea     rdi, [rax + BAD_FD]
    mov     eax, 1
    lea     rsi, [rip + reflect]
    mov     edx, 1
    syscall
    ret

mmap_failed:
    mov     eax, 60
    mov     edi, 112
    syscall
    ud2

write_failed:
    mov     eax, 60
    mov     edi, 113
    syscall
    ud2

    .section .rodata
mapped_message:
    .ascii "narf-rich-mmap!\n"
mapped_message_end:
final_message:
    .ascii "narf-rich-done\n"
final_message_end:
reflect:
    .ascii "r"
