/*
 * Per-vector trap stubs and common Rust dispatch.
 *
 * One stub per CPU exception vector (0..=31). Each stub:
 *   - For vectors that do NOT push an error code (CPU won't), push 0 first.
 *   - Push the vector number.
 *   - Jump to `common_trap`.
 *
 * `common_trap`:
 *   - Push all general-purpose registers in TrapFrame order.
 *   - Load RDI with the trap-frame pointer (RSP).
 *   - Call `rust_trap_handler` (does not return in Stage 1).
 *
 * Vector-to-error-code table (from Intel SDM Vol 3, §6.5):
 *   error-pushing: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30.
 *   All others: no error code; we push a zero placeholder.
 */

.section .text
.code64

/* Generate a no-error-code stub: push 0, push vec, jmp common. */
.macro TRAP_STUB_NOERR, vec
    .global int_\vec
    .type   int_\vec, @function
int_\vec:
    push 0
    push \vec
    jmp common_trap
    .size   int_\vec, . - int_\vec
.endm

/* Generate a with-error-code stub: CPU already pushed the error, so we
 * only push the vector. */
.macro TRAP_STUB_ERR, vec
    .global int_\vec
    .type   int_\vec, @function
int_\vec:
    push \vec
    jmp common_trap
    .size   int_\vec, . - int_\vec
.endm

TRAP_STUB_NOERR 0
TRAP_STUB_NOERR 1
TRAP_STUB_NOERR 2
TRAP_STUB_NOERR 3
TRAP_STUB_NOERR 4
TRAP_STUB_NOERR 5
TRAP_STUB_NOERR 6
TRAP_STUB_NOERR 7
TRAP_STUB_ERR   8
TRAP_STUB_NOERR 9
TRAP_STUB_ERR   10
TRAP_STUB_ERR   11
TRAP_STUB_ERR   12
TRAP_STUB_ERR   13
TRAP_STUB_ERR   14
TRAP_STUB_NOERR 15
TRAP_STUB_NOERR 16
TRAP_STUB_ERR   17
TRAP_STUB_NOERR 18
TRAP_STUB_NOERR 19
TRAP_STUB_NOERR 20
TRAP_STUB_ERR   21
TRAP_STUB_NOERR 22
TRAP_STUB_NOERR 23
TRAP_STUB_NOERR 24
TRAP_STUB_NOERR 25
TRAP_STUB_NOERR 26
TRAP_STUB_NOERR 27
TRAP_STUB_NOERR 28
TRAP_STUB_ERR   29
TRAP_STUB_ERR   30
TRAP_STUB_NOERR 31

/* External IRQ vectors — no CPU-pushed error code. */
TRAP_STUB_NOERR 32
TRAP_STUB_NOERR 33
TRAP_STUB_NOERR 34
TRAP_STUB_NOERR 35
TRAP_STUB_NOERR 36
TRAP_STUB_NOERR 37
TRAP_STUB_NOERR 38
TRAP_STUB_NOERR 39
TRAP_STUB_NOERR 40
TRAP_STUB_NOERR 41
TRAP_STUB_NOERR 42
TRAP_STUB_NOERR 43
TRAP_STUB_NOERR 44
TRAP_STUB_NOERR 45
TRAP_STUB_NOERR 46
TRAP_STUB_NOERR 47
TRAP_STUB_NOERR 255

.global common_trap
.type   common_trap, @function
common_trap:
    /* At entry: RSP points at [error_code, vector] followed upward by
     * [rip, cs, rflags, rsp, ss] that the CPU pushed.
     *
     * Push general-purpose registers in the order the Rust TrapFrame
     * struct expects them — last-pushed first in the struct, because
     * `push` grows the stack downward.
     */
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    /* RDI = pointer to the trap frame (the current RSP). */
    mov rdi, rsp

    /* Call the Rust dispatcher. It may either:
     *   - return normally → we pop regs and iretq, resuming at the
     *     (possibly rewritten) RIP in the trap frame. This is how the
     *     recoverable-probe path works: the handler modifies frame.rip
     *     to a recovery address and returns.
     *   - call exit_kernel internally → never returns here.
     */
    call rust_trap_handler

    /* Restore general-purpose registers in reverse push order. */
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    /* Discard the vector + error_code we pushed. */
    add rsp, 16

    /* Return from interrupt. Reads the CPU-pushed [rip, cs, rflags,
     * rsp, ss] from the top of the stack — the same 40 bytes the
     * processor pushed on entry, possibly with RIP rewritten by the
     * Rust handler.
     */
    iretq
.size common_trap, . - common_trap
