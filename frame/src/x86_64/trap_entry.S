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

    /* Call the Rust dispatcher — it is marked `-> !`, so we never
     * unwind this far. The hlt/jmp tail is a belt-and-braces fallback
     * in case the Rust signature changes.
     */
    call rust_trap_handler

1:  hlt
    jmp 1b
.size common_trap, . - common_trap
