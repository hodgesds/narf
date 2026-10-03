// chaos guest: reads that chaos fails with EINTR or cuts to one byte, in a
// root process, a thread of it and a forked child, and a recvfrom that chaos
// cuts to one byte. Every read and the recvfrom ask for two bytes, and the
// guest requires of each thread's k-th read, counting the recvfrom as one of
// the root's, what chaos does to it with its default options: for odd k,
// EINTR (-4) without consuming anything; for even k, one byte. Any unexpected
// result exits with a distinct status in 80..=106.
//
// File descriptors are fixed so the test can find pipe T: pipe A is 3 (read)
// and 4 (write) and holds "ab", pipe C is 5 and 6 and holds "cd", and pipe T
// is 7 and 8 and starts empty. The root closes 4 and 6 once A and C are
// filled, so a read past their bytes ends with EOF instead of blocking.
//
// 1. The root makes the pipes, fills A and C, closes 4 and 6, and reads A:
//    EINTR.
// 2. It starts a thread (CLONE_CHILD_CLEARTID) and futex-waits for its exit.
//    The thread reads T four times: EINTR; "t"; EINTR; "u", and calls
//    exit(0). Its second read finds T empty and parks; the kernel test writes
//    "tu" into T through fd 8 once that read has parked, and the read is
//    re-executed, still for one byte.
// 3. The root forks a child, which reads C twice: EINTR; "c", and calls
//    exit_group(0). The root reaps it and requires wait status 0.
// 4. The root reads A three more times: "a"; EINTR; "b".
// 5. It makes a socket pair, which takes descriptors 4 and 6, writes "xy"
//    into 6 and reads 4: EINTR. It then calls recvfrom(4, buf, 2, MSG_PEEK,
//    NULL, NULL): "x", left in the socket. It reads 4 four more times:
//    EINTR, as after a cut read; "x" again, so the recvfrom chaos ran kept
//    the guest's MSG_PEEK; EINTR; "y", and calls exit_group(0).
//
// When the root starts the thread and forks the child, chaos would cut the
// root's next read, so the thread's and the child's first reads fail with
// EINTR only if each starts with state of its own.

    .intel_syntax noprefix
    .global _start

    .equ SYS_READ, 0
    .equ SYS_WRITE, 1
    .equ SYS_CLOSE, 3
    .equ SYS_CLONE, 56
    .equ SYS_FORK, 57
    .equ SYS_EXIT, 60
    .equ SYS_WAIT4, 61
    .equ SYS_FUTEX, 202
    .equ SYS_RECVFROM, 45
    .equ SYS_SOCKETPAIR, 53
    .equ SYS_EXIT_GROUP, 231
    .equ SYS_PIPE2, 293
    .equ AF_UNIX, 1
    .equ SOCK_STREAM, 1
    .equ MSG_PEEK, 2
    // CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|CHILD_CLEARTID
    .equ THREAD_FLAGS_CLEARTID, 0x350f00

// read(fd, buf, 2) must return `want`, and a one-byte read must have read
// `byte`; otherwise exit with `code`. Clobbers rax, rdi, rsi, rdx, rcx, r11.
    .macro read_expect fd, buf, want, byte, code
    mov     byte ptr [rip + \buf], 0
    mov     eax, SYS_READ
    mov     edi, \fd
    lea     rsi, [rip + \buf]
    mov     edx, 2
    syscall
    mov     edi, \code
    cmp     rax, \want
    jne     die
    .if \want == 1
    cmp     byte ptr [rip + \buf], \byte
    jne     die
    .endif
    .endm

    .section .rodata
a_bytes:    .ascii "ab"
c_bytes:    .ascii "cd"
s_bytes:    .ascii "xy"

    .section .bss
    .balign 16
fds:          .skip 24
pair:         .skip 8
thread_word:  .quad 0
status_word:  .quad 0
root_buf:     .quad 0
thread_buf:   .quad 0
child_buf:    .quad 0
    .balign 16
    .skip 4096
thread_stack_top:

    .section .text
_start:
    lea     rbx, [rip + fds]
    mov     eax, SYS_PIPE2      # pipe2(&fds[0], 0): A
    mov     rdi, rbx
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed
    mov     eax, SYS_PIPE2      # pipe2(&fds[2], 0): C
    lea     rdi, [rbx + 8]
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed
    mov     eax, SYS_PIPE2      # pipe2(&fds[4], 0): T
    lea     rdi, [rbx + 16]
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed
    xor     ecx, ecx            # the descriptors are 3..=8 in order
1:
    lea     edx, [rcx + 3]
    cmp     dword ptr [rbx + rcx * 4], edx
    jne     fds_unexpected
    inc     ecx
    cmp     ecx, 6
    jb      1b

    mov     eax, SYS_WRITE      # write(4, "ab", 2)
    mov     edi, 4
    lea     rsi, [rip + a_bytes]
    mov     edx, 2
    syscall
    cmp     rax, 2
    jne     write_failed
    mov     eax, SYS_WRITE      # write(6, "cd", 2)
    mov     edi, 6
    lea     rsi, [rip + c_bytes]
    mov     edx, 2
    syscall
    cmp     rax, 2
    jne     write_failed
    mov     eax, SYS_CLOSE      # close(4)
    mov     edi, 4
    syscall
    test    rax, rax
    jnz     close_failed
    mov     eax, SYS_CLOSE      # close(6)
    mov     edi, 6
    syscall
    test    rax, rax
    jnz     close_failed

    read_expect 3, root_buf, -4, 0, 84

    mov     edi, THREAD_FLAGS_CLEARTID
    lea     rsi, [rip + thread_stack_top]
    lea     rdx, [rip + thread_word]    # parent_tid: nonzero before the thread runs
    lea     r10, [rip + thread_word]    # child_tid: cleared at the thread's exit
    xor     r8d, r8d
    mov     eax, SYS_CLONE
    syscall
    test    rax, rax
    js      clone_failed
    jz      thread
    lea     rdi, [rip + thread_word]
    call    wait_cleared

    mov     eax, SYS_FORK
    syscall
    test    rax, rax
    js      fork_failed
    jz      child
    mov     rdi, rax            # wait4(child, &status, 0, NULL)
    lea     rsi, [rip + status_word]
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, SYS_WAIT4
    syscall
    test    rax, rax
    js      wait_failed
    cmp     dword ptr [rip + status_word], 0
    jne     child_status_bad

    read_expect 3, root_buf, 1, 0x61, 95    # "a"
    read_expect 3, root_buf, -4, 0, 96
    read_expect 3, root_buf, 1, 0x62, 97    # "b"

    mov     eax, SYS_SOCKETPAIR # socketpair(AF_UNIX, SOCK_STREAM, 0, &pair)
    mov     edi, AF_UNIX
    mov     esi, SOCK_STREAM
    xor     edx, edx
    lea     r10, [rip + pair]
    syscall
    test    rax, rax
    jnz     socketpair_failed
    cmp     dword ptr [rip + pair], 4       # the descriptors closed above
    jne     pair_unexpected
    cmp     dword ptr [rip + pair + 4], 6
    jne     pair_unexpected
    mov     eax, SYS_WRITE      # write(6, "xy", 2)
    mov     edi, 6
    lea     rsi, [rip + s_bytes]
    mov     edx, 2
    syscall
    cmp     rax, 2
    jne     pair_write_failed

    read_expect 4, root_buf, -4, 0, 101
    mov     byte ptr [rip + root_buf], 0
    mov     eax, SYS_RECVFROM   # recvfrom(4, buf, 2, MSG_PEEK, NULL, NULL)
    mov     edi, 4
    lea     rsi, [rip + root_buf]
    mov     edx, 2
    mov     r10d, MSG_PEEK
    xor     r8d, r8d
    xor     r9d, r9d
    syscall
    mov     edi, 102
    cmp     rax, 1
    jne     die
    cmp     byte ptr [rip + root_buf], 0x78 # "x"
    jne     die
    read_expect 4, root_buf, -4, 0, 103
    read_expect 4, root_buf, 1, 0x78, 104   # "x", which the recvfrom left
    read_expect 4, root_buf, -4, 0, 105
    read_expect 4, root_buf, 1, 0x79, 106   # "y"
    mov     eax, SYS_EXIT_GROUP # exit_group(0)
    xor     edi, edi
    syscall
    ud2

// ── the root's thread ──
thread:
    read_expect 7, thread_buf, -4, 0, 86
    read_expect 7, thread_buf, 1, 0x74, 87  # "t", after parking on empty T
    read_expect 7, thread_buf, -4, 0, 88
    read_expect 7, thread_buf, 1, 0x75, 89  # "u"
    mov     eax, SYS_EXIT       # exit(0)
    xor     edi, edi
    syscall
    ud2

// ── the forked child ──
child:
    read_expect 5, child_buf, -4, 0, 91
    read_expect 5, child_buf, 1, 0x63, 92   # "c"
    mov     eax, SYS_EXIT_GROUP # exit_group(0)
    xor     edi, edi
    syscall
    ud2

// Futex-waits until the 32-bit word at rdi is zero. Clobbers rax, rsi, rdx,
// r10, r8, r9, rcx, r11, r12.
wait_cleared:
    mov     r12, rdi
1:
    mov     edx, dword ptr [r12]
    test    edx, edx
    jz      2f
    mov     rdi, r12            # futex(word, FUTEX_WAIT, seen, NULL)
    xor     esi, esi
    xor     r10d, r10d
    mov     eax, SYS_FUTEX
    syscall
    jmp     1b
2:
    ret

pipe_failed:
    mov     edi, 80
    jmp     die
fds_unexpected:
    mov     edi, 81
    jmp     die
write_failed:
    mov     edi, 82
    jmp     die
close_failed:
    mov     edi, 83
    jmp     die
clone_failed:
    mov     edi, 85
    jmp     die
fork_failed:
    mov     edi, 90
    jmp     die
wait_failed:
    mov     edi, 93
    jmp     die
child_status_bad:
    mov     edi, 94
    jmp     die
socketpair_failed:
    mov     edi, 98
    jmp     die
pair_unexpected:
    mov     edi, 99
    jmp     die
pair_write_failed:
    mov     edi, 100
die:
    mov     eax, SYS_EXIT_GROUP
    syscall
    ud2
