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

/* External IRQ vectors 48..=254 (skipping 128, which is the user-
 * mode syscall gate and gets its own DPL=3 stub below). The
 * MSI/MSI-X allocator (`narf_interrupts::vector::alloc`) hands out
 * vectors in this range; without an IDT entry any MSI delivery
 * would #GP at the IDT lookup. The .rept loops emit one
 * TRAP_STUB_NOERR per vector. */
.altmacro
.set vec_n, 48
.rept (128 - 48)
    TRAP_STUB_NOERR %vec_n
    .set vec_n, vec_n + 1
.endr
TRAP_STUB_NOERR 128
.set vec_n, 129
.rept (255 - 129)
    TRAP_STUB_NOERR %vec_n
    .set vec_n, vec_n + 1
.endr
.noaltmacro
TRAP_STUB_NOERR 255

.global common_trap
.type   common_trap, @function
common_trap:
    /* At entry: RSP points at [error_code, vector] followed upward by
     * [rip, cs, rflags, rsp, ss] that the CPU pushed.
     *
     * If the trap came from user mode (CS.RPL != 0) we need to
     * swapgs into the kernel's per-CPU area so any kernel code
     * that reads `gs:offset` finds kernel data, not user-controlled
     * state. The CPU-pushed CS is at rsp + 24 (after error + vec +
     * rip). RPL lives in the low 2 bits of the selector.
     */
    test qword ptr [rsp + 24], 0x3
    jz 1f
    swapgs
1:
    /* Interrupt/trap entry preserves the live DF bit. Userspace may be
     * interrupted between STD and CLD, but Rust and the SysV kernel ABI
     * require forward string operations. The user's original RFLAGS is
     * already in the CPU-pushed frame below and IRETQ restores it, so this
     * sanitizes only the kernel execution context.
     */
    cld

    /* Push general-purpose registers in the order the Rust TrapFrame
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

    /* Reserve the architecture-owned domain prefix. No Rust may execute
     * until the live task rights have been captured and FRAME is active.
     * kind: 0 = inactive, 1 = PKRS, 2 = CR3/PCID. */
    sub rsp, 16
    mov qword ptr [rsp], 0
    mov qword ptr [rsp + 8], 0

    /* Read CR4 from its cached copy (write_cr4 maintains it): a live
     * `mov rax, cr4` VMEXITs under KVM/SVM on every trap, and this only needs
     * the boot-stable PKS(24)/PCIDE(17) bits. */
    mov rax, qword ptr [rip + NARF_X86_CACHED_CR4]
    bt rax, 24                         /* CR4.PKS */
    jc .Ldomain_enter_pks
    bt rax, 17                         /* CR4.PCIDE */
    jnc .Ldomain_enter_done
    mov rax, qword ptr [rip + NARF_X86_FRAME_PML4]
    test rax, rax                      /* PCID enforcer not initialised yet */
    jz .Ldomain_enter_done
    mov rcx, cr3
    mov qword ptr [rsp], rcx
    mov qword ptr [rsp + 8], 2
    or rax, 1                          /* FRAME uses PCID 1 */
    bts rax, 63                        /* preserve tagged translations */
    mov cr3, rax
    jmp .Ldomain_enter_done

.Ldomain_enter_pks:
    mov ecx, 0x6e1                     /* IA32_PKRS */
    rdmsr
    mov qword ptr [rsp], rax
    mov qword ptr [rsp + 8], 1
    xor eax, eax                       /* neutral FRAME: all domains allowed */
    xor edx, edx
    wrmsr
.Ldomain_enter_done:

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

    /* Restore the exact state captured on entry. Nested traps naturally save
     * and restore the neutral state established by their outer trap. */
    mov rcx, qword ptr [rsp + 8]
    cmp rcx, 1
    je .Ldomain_exit_pks
    cmp rcx, 2
    je .Ldomain_exit_pcid
    jmp .Ldomain_exit_done
.Ldomain_exit_pks:
    mov rax, qword ptr [rsp]
    xor edx, edx
    mov ecx, 0x6e1                     /* IA32_PKRS */
    wrmsr
    jmp .Ldomain_exit_done
.Ldomain_exit_pcid:
    mov rax, qword ptr [rsp]
    bts rax, 63
    mov cr3, rax
.Ldomain_exit_done:
    add rsp, 16

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

    /* If we're about to iretq to user mode, swapgs to restore the
     * user's GS.base — the inverse of the entry-side swapgs.
     * Rust handlers can rewrite frame.cs, so we re-check against
     * the CPU-pushed CS at rsp + 8 (after rip, since rip is at
     * rsp + 0 post add-rsp-16).
     */
    test qword ptr [rsp + 8], 0x3
    jz 2f
    swapgs
2:

    /* Return from interrupt. Reads the CPU-pushed [rip, cs, rflags,
     * rsp, ss] from the top of the stack — the same 40 bytes the
     * processor pushed on entry, possibly with RIP rewritten by the
     * Rust handler.
     */
    iretq
.size common_trap, . - common_trap

/*
 * run_irq_dispatch_on_stack(TrapFrame *frame in rdi)
 *
 * Run `irq_dispatch_body(frame)` on this CPU's dedicated per-CPU hardirq
 * stack (Linux `call_on_irqstack`), so the IRQ-dispatch body (on_irq + EOI,
 * incl. the timer-wheel drain) never consumes the interrupted task's own
 * kernel stack. A faithful port of Linux's `call_on_stack`:
 *   - save the caller's RSP into the irq stack's top-8 slot,
 *   - switch RSP to the irq stack,
 *   - call the body (frame stays in RDI across the swap),
 *   - pop the saved RSP back, restoring the caller's stack.
 *
 * Nesting guard (gs:[32], hardirq_inuse): if already on the irq stack, run
 * directly on the current stack instead of re-switching (which would clobber
 * the saved-RSP slot). NARF IRQ gates enter IF=0 and the body never `sti`s,
 * so genuine nesting does not occur here; the guard is defensive.
 *
 * Preconditions: kernel GS is live (common_trap swapgs'd on user entry),
 * IF=0. gs:[24] = irq_stack_top (already top-8), gs:[32] = hardirq_inuse.
 * Clobbers rax, r11 (caller-saved scratch).
 */
.global run_irq_dispatch_on_stack
.type   run_irq_dispatch_on_stack, @function
run_irq_dispatch_on_stack:
    mov rax, gs:[32]                 /* hardirq_inuse */
    test rax, rax
    jnz 1f                           /* already on irq stack: run directly */

    mov rax, 1
    mov gs:[32], rax                 /* inuse = 1 (store via reg — gs:[] takes no imm) */
    mov r11, gs:[24]                 /* r11 = irq_stack_top (top - 8) */
    mov [r11], rsp                   /* save caller rsp into the top-8 slot */
    mov rsp, r11                     /* switch to the hardirq stack */
    call irq_dispatch_body           /* rdi (frame) preserved across the swap */
    pop rsp                          /* restore caller rsp from [old top-8] */
    xor eax, eax
    mov gs:[32], rax                 /* inuse = 0 */
    ret

1:
    jmp irq_dispatch_body            /* tail-call on the current stack; rdi intact */
.size run_irq_dispatch_on_stack, . - run_irq_dispatch_on_stack
