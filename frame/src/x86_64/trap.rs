//! x86_64 trap frame + Rust-side dispatch.
//!
//! Each CPU exception has an asm stub (`trap_entry.S`) that:
//!
//!   1. Optionally pushes a zero error code for vectors that don't push one.
//!   2. Pushes the vector number.
//!   3. Pushes all general-purpose registers.
//!   4. Calls `rust_trap_handler(&TrapFrame)`.
//!   5. Does NOT return (Stage 1 turns every exception into a panic).
//!
//! Full trap-prologue PKRS save / restore discipline (frame/ §4) comes
//! with the Stage-2 domain-switch work. Stage 1 has a single domain so
//! PKRS is always the open mask.

use core::fmt::Write;

use narf_console::TrapWriter;

/// The on-stack layout that `common_trap` builds before calling here.
///
/// Order follows the asm's reverse pushes + CPU-pushed frame at the end.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TrapFrame {
    // General-purpose registers, in the order `common_trap` pushes them.
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,

    // Pushed by `common_trap` before the GP saves.
    pub vector: u64,
    pub error_code: u64,

    // Pushed by the CPU on exception. In long mode these are always
    // 64-bit and the SS/RSP pair is always present.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl core::fmt::Debug for TrapFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TrapFrame {{ vec={}, err={:#x}, rip={:#018x}, cs={:#x}, rflags={:#x} }}",
            self.vector, self.error_code, self.rip, self.cs, self.rflags
        )
    }
}

/// Render a u64 as 16 ASCII hex digits, MS→LS, on the FB at
/// pixel-row `px_y`. Each digit takes 18 px (16 px char at 2×
/// scale + 2 px gap). Uses `narf_graphics::font8x8` via
/// `beacon::paint_glyph_2x_at` so this works the same on real
/// silicon as on QEMU — the trap-handler hex dump no longer
/// requires the operator to count bar heights.
fn paint_hex_u64_text(px_y: u32, value: u64, fg: u32, bg: u32) {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for i in 0..16u32 {
        let shift = 60 - (i * 4);
        let nibble = ((value >> shift) & 0xF) as usize;
        let glyph = narf_graphics::font8x8::lookup(HEX_DIGITS[nibble]);
        let px_x = i * 18;
        narf_memory::beacon::paint_glyph_2x_at(px_x, px_y, &glyph, fg, bg);
    }
}

fn vector_name(v: u64) -> &'static str {
    match v {
        0 => "#DE  divide-by-zero",
        1 => "#DB  debug",
        2 => "NMI",
        3 => "#BP  breakpoint",
        4 => "#OF  overflow",
        5 => "#BR  bound-range",
        6 => "#UD  invalid-opcode",
        7 => "#NM  device-not-available",
        8 => "#DF  double-fault",
        10 => "#TS  invalid-TSS",
        11 => "#NP  segment-not-present",
        12 => "#SS  stack-segment",
        13 => "#GP  general-protection",
        14 => "#PF  page-fault",
        16 => "#MF  x87-float",
        17 => "#AC  alignment-check",
        18 => "#MC  machine-check",
        19 => "#XM  SIMD-float",
        20 => "#VE  virtualisation",
        21 => "#CP  control-protection",
        _ => "reserved / unknown",
    }
}

/// Rust-side trap dispatch. Called from `common_trap` in `trap_entry.S`
/// with a mutable pointer to the `TrapFrame` on the trap stack.
///
/// Contract:
///   - If a probe is armed (`narf_arch::x86_64::probe` globals), consume
///     it: record the vector, rewrite `frame.rip` to the probe's
///     recovery RIP, and return. The asm tail restores GPRs and
///     `iretq`s to the rewritten RIP.
///   - Otherwise print the frame and call `exit_kernel(42)`, which
///     does not return.
#[unsafe(no_mangle)]
pub extern "C" fn rust_trap_handler(frame: &mut TrapFrame) {
    // Software-interrupt syscall gate. `int 0x80` arrives here; the
    // caller's registers have been saved into `frame` already.
    // Convention: rax = syscall number, rdi/rsi/rdx/r10/r8/r9 =
    // args 0..5. Return value in rax, status in rdx.
    //
    // Raw handlers can `redirect_to_kernel` to rewrite the frame
    // instead of returning to the caller's context — the iretq at
    // the tail of common_trap then lands at the kernel RIP we set
    // here, with kernel CS/SS and the supplied RSP. swapgs on exit
    // is gated on the (possibly rewritten) frame.cs, so a redirect
    // to KCODE correctly skips the user-side swapgs.
    if frame.vector == 128 {
        let num = frame.rax as u32;
        let mut ctx = X86TrapContext::from_int80(frame);
        narf_userspace::kernel_syscall_entry(num, &mut ctx);
        // Signal-delivery hook: if a `narf_userspace`-side hook
        // is installed and we're heading back to user (CS RPL=3,
        // i.e. the syscall handler didn't redirect to kernel),
        // give it a chance to rewrite the frame to land at a
        // pending signal handler. The hook self-checks
        // `returning_to_user` so a redirect-to-kernel handler
        // (exit, longjmp) bypasses delivery cleanly.
        if let Some(hook) = narf_userspace::signal_delivery_hook() {
            hook(&mut ctx);
        }
        return;
    }

    // External IRQ path (vectors 32..=255). Dispatch through the
    // generic dispatch table (driver-registered IRQ wakers) and then
    // EOI. Vector 32 still hits the timer-tick counter directly so
    // boot-time stats remain stable; everything else lands in the
    // dispatch table where waiters are tracked.
    //
    // Bypasses the probe-catch path — probes are for catching CPU
    // *exceptions* (vectors 0..=31), not asynchronous IRQs.
    if frame.vector >= 32 {
        if frame.vector == 32 {
            narf_interrupts::x86_64::apic::on_timer_tick();
        }
        narf_interrupts::on_irq(frame.vector as u8);
        // SAFETY: APIC is initialised before interrupts are enabled.
        unsafe {
            narf_interrupts::eoi();
        }
        return;
    }

    // Synchronous-signal delivery for user-mode CPU exceptions.
    // Strict gate on CS RPL == 3 so kernel-mode exceptions stay
    // on the existing probe-catch / panic path: the probe-catch
    // surface below is for kernel-issued recovery (test
    // infrastructure), and a kernel-mode crash is unambiguously
    // a kernel bug we want to panic on.
    //
    // The hook returns true when it rewrote the trap frame to
    // land at a user signal handler — fall through to the asm
    // tail's iretq, which carries the rewritten RIP back to user
    // mode where the handler runs. Returning false (no handler
    // installed, or an unmappable vector like #DF) means the user
    // genuinely deserves the panic surface below.
    if (frame.cs & 3) == 3 {
        if let Some(hook) = narf_userspace::sync_signal_hook() {
            // Snapshot the vector before the mutable borrow of
            // `frame` lands inside `from_int80`. The hook may
            // rewrite RIP/RSP on the trap frame to deliver, so
            // `frame` must be mutably borrowed for the duration
            // of the call.
            let vector = frame.vector;
            let mut ctx = X86TrapContext::from_int80(frame);
            if hook(&mut ctx, vector) {
                return;
            }
        }
    }

    // COW write-fault recovery (user-mode only). When a fork()'d
    // process writes a shared, write-protected page for the first
    // time, #PF lands here with the present + write + user bits
    // set in the error code. We resolve via the active user AS:
    //   - cow_split_on_write allocates a private frame, memcpys
    //     the shared bytes, dec_refs the old frame, restores
    //     WRITE on the region.
    //   - remap_page rewrites the live PTE so the next user-mode
    //     instruction succeeds.
    // On any failure we fall through to the panic path so the
    // existing diagnostic still fires on genuine bugs.
    if frame.vector == 14 {
        // PF error code (Intel SDM Vol. 3 §4.7):
        //   bit 0 (P): set if fault was a present-page violation
        //   bit 1 (W): set if write
        //   bit 2 (U): set if CPL=3
        const PF_P: u64 = 1 << 0;
        const PF_W: u64 = 1 << 1;
        const PF_U: u64 = 1 << 2;
        let ec = frame.error_code;
        let cr2: u64;
        // SAFETY: reading CR2 at CPL=0 is always defined.
        unsafe {
            core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
                options(nostack, preserves_flags));
        }
        // Canonical lower-half (user) addresses: bit 47 clear.
        // 0x0000_8000_0000_0000 is the first non-canonical lower
        // address; anything strictly below is in the user half.
        let cr2_in_user_half = cr2 < 0x0000_8000_0000_0000;
        let from_user = (frame.cs & 3) == 3;

        // Demand paging: P=0 means the page wasn't mapped at fault
        // time. Two cases get serviced through the active user AS's
        // lazy region table:
        //   (a) CPL=3 fault on any vaddr — `mmap`'s deferred-alloc
        //       path: the syscall installs `phys[i] == 0` and the
        //       first user touch lands here.
        //   (b) CPL=0 fault on a USER vaddr — the kernel writing
        //       through to a user buffer that hasn't been touched
        //       yet (e.g. a syscall handler reading/writing a
        //       caller-supplied buffer that came from a fresh mmap
        //       grow). Same backing path; the supervisor bit on the
        //       error code just means we got there from kernel mode.
        // Falls through to stack-grow / COW / panic on any error so
        // the existing diagnostic still fires for genuine bugs.
        let p_clear = (ec & PF_P) == 0;
        if p_clear && (from_user || cr2_in_user_half) {
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(cr2);
                // SAFETY: identity map live, AS belongs to the
                // task whose CR3 is currently active.
                if unsafe { as_arc.demand_alloc_page(v) }.is_ok() {
                    return;
                }
                // Demand-alloc surfaced Unmapped: vaddr might land
                // in a STACK_GUARD region. try_grow_stack promotes
                // the guard to a real stack page and installs a
                // fresh guard below; on success the user-mode
                // instruction retries and lands on the freshly
                // backed page. POSIX.1-2017 §2.2.2 — stack
                // auto-extension is implementation-defined.
                if from_user {
                    // SAFETY: same identity-map argument.
                    if unsafe { as_arc.try_grow_stack(v) }.is_ok() {
                        return;
                    }
                }
            }
        }
        // COW write-fault recovery: P+W+U → split on write.
        if (ec & (PF_P | PF_W | PF_U)) == (PF_P | PF_W | PF_U) {
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(cr2);
                // SAFETY: low-4-GiB identity map is live, frame
                // allocator + COW refcount table are
                // initialised at boot. AS is the active user AS
                // by construction (we just probed CPL=3).
                let split_ok = unsafe { as_arc.cow_split_on_write(v) }.is_ok();
                if split_ok {
                    // SAFETY: same identity-map argument; the
                    // region was just touched by cow_split_on_write
                    // so it definitely exists.
                    let remap_ok = unsafe { as_arc.remap_page(v) }.is_ok();
                    if remap_ok {
                        return;
                    }
                }
            }
        }
    }

    // Recoverable-probe path. `consume` is atomic: a second fault
    // inside the handler can't double-claim the recovery.
    let recovery = narf_arch::x86_64::probe::consume(frame.vector as u32, frame.error_code);
    if recovery != 0 {
        frame.rip = recovery;
        return;
    }

    // Paint a HUGE diagnostic block to FB so real-HW boots
    // without serial can see WHICH vector fired. Uses the
    // beacon facility — slot index = vector number, color
    // encodes vector range. Painted BEFORE writeln so even if
    // console writes don't reach FB, the beacon block does.
    {
        // Color: distinct per common vector for easy ID.
        let color: u32 = match frame.vector {
            6 => 0x00FF0000,  // #UD red
            13 => 0x00FF8000, // #GP orange
            14 => 0x00FFFF00, // #PF yellow
            8 => 0x00FF00FF,  // #DF magenta
            18 => 0x000000FF, // #MC blue
            _ => 0x00FFFFFF,  // anything else = white
        };
        // Paint slot = vector index in row 3 (y=60-76, well
        // below earlier diagnostic rows so it's visible
        // alongside any other beacons).
        narf_memory::beacon::paint_at(frame.vector as u32, 3, color);
        // Also paint a big bar across the whole top of row 4
        // (y=80-96) for visibility — color matches the vector
        // color so even if vector-slot is off-screen it's
        // obvious a fault happened.
        for slot in 0..16u32 {
            narf_memory::beacon::paint_at(slot, 4, color);
        }

        // Hex diagnostics — font-free bar-height encoding so they're
        // legible on any FB regardless of GTK scaling / panel font.
        // Each row is 16 slots × 4-bit nibble = one u64 value MS→LS:
        //   row 5: RIP                  (where it faulted)
        //   row 6: CR2 (only if #PF)    (what addr it touched)
        //   row 7: error_code           (selector / PF flags)
        // Even bytes = bright fg colour, odd bytes = darker variant
        // so you can group nibble-pairs into bytes visually.
        let bg = 0x00_10_10_10; // near-black grid background
        let (fg_e, fg_o) = match frame.vector {
            6  => (0x00_FF_60_60, 0x00_A0_30_30), // #UD reds
            13 => (0x00_FF_C0_60, 0x00_A0_70_30), // #GP oranges
            14 => (0x00_FF_FF_60, 0x00_A0_A0_30), // #PF yellows
            8  => (0x00_FF_60_FF, 0x00_A0_30_A0), // #DF magentas
            18 => (0x00_60_60_FF, 0x00_30_30_A0), // #MC blues
            _  => (0x00_FF_FF_FF, 0x00_80_80_80), // generic
        };
        narf_memory::beacon::paint_u64_hex(0, 5, frame.rip, fg_e, fg_o, bg);
        if frame.vector == 14 {
            let cr2: u64;
            // SAFETY: reading CR2 at CPL=0 is always defined.
            unsafe {
                core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
                options(nostack, preserves_flags));
            }
            narf_memory::beacon::paint_u64_hex(0, 6, cr2, fg_e, fg_o, bg);
        }
        narf_memory::beacon::paint_u64_hex(0, 7, frame.error_code, fg_e, fg_o, bg);

        // Hex-digit TEXT diagnostics — actual readable ASCII
        // characters rendered from font8x8 at 2x scale (16x16
        // per char). Bar-height encoding above is the visual
        // backup; this lets the operator just READ the values
        // off the panel.
        //
        // Layout: 16 chars per u64, 18 px per char (16 + 2 gap)
        // = 288 px wide. Three rows stacked starting at y=180
        // (well below the row-7 nibble band) with 20 px row gap.
        paint_hex_u64_text(180, frame.rip, fg_e, bg);
        if frame.vector == 14 {
            // CR2 — re-read since the asm! above is in a
            // different scope (and reading CR2 twice is cheap).
            let cr2: u64;
            // SAFETY: reading CR2 at CPL=0 is always defined.
            unsafe {
                core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
                options(nostack, preserves_flags));
            }
            paint_hex_u64_text(200, cr2, fg_e, bg);
        }
        paint_hex_u64_text(220, frame.error_code, fg_e, bg);
    }
    // Lock-free TrapWriter: the original faulting code may already
    // hold `CONSOLE.lock` (e.g. it faulted mid-`write_str`); a
    // blocking re-acquire from inside the trap handler would
    // deadlock against itself, which is why every line past the
    // first one used to vanish.
    let _ = writeln!(TrapWriter, "\n*** CPU EXCEPTION ***");
    let _ = writeln!(
        TrapWriter,
        "  vector: {:3} — {}",
        frame.vector,
        vector_name(frame.vector)
    );
    let _ = writeln!(TrapWriter, "  error:  {:#018x}", frame.error_code);
    if frame.vector == 14 {
        // #PF: CR2 holds the faulting linear address.
        let cr2: u64;
        // SAFETY: reading CR2 at CPL=0 is always defined.
        unsafe {
            core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
            options(nostack, preserves_flags));
        }
        let _ = writeln!(TrapWriter, "  cr2:    {:#018x}", cr2);
    }
    let _ = writeln!(
        TrapWriter,
        "  rip:    {:#018x}   cs:     {:#018x}",
        frame.rip, frame.cs
    );
    let _ = writeln!(
        TrapWriter,
        "  rflags: {:#018x}   rsp:    {:#018x}   ss: {:#018x}",
        frame.rflags, frame.rsp, frame.ss
    );
    let _ = writeln!(
        TrapWriter,
        "  rax:    {:#018x}   rbx:    {:#018x}",
        frame.rax, frame.rbx
    );
    let _ = writeln!(
        TrapWriter,
        "  rcx:    {:#018x}   rdx:    {:#018x}",
        frame.rcx, frame.rdx
    );
    let _ = writeln!(
        TrapWriter,
        "  rsi:    {:#018x}   rdi:    {:#018x}",
        frame.rsi, frame.rdi
    );
    let _ = writeln!(
        TrapWriter,
        "  rbp:    {:#018x}   r8:     {:#018x}",
        frame.rbp, frame.r8
    );
    let _ = writeln!(
        TrapWriter,
        "  r9:     {:#018x}   r10:    {:#018x}",
        frame.r9, frame.r10
    );
    let _ = writeln!(
        TrapWriter,
        "  r11:    {:#018x}   r12:    {:#018x}",
        frame.r11, frame.r12
    );
    let _ = writeln!(
        TrapWriter,
        "  r13:    {:#018x}   r14:    {:#018x}",
        frame.r13, frame.r14
    );
    let _ = writeln!(TrapWriter, "  r15:    {:#018x}", frame.r15);

    // SAFETY: after a fatal exception we have no policy to resume; exit with
    // a non-zero code so xtask / verification can see the failure.
    unsafe { narf_arch::exit_kernel(42) }
}

// ── TrapContext impl for the int-0x80 path ─────────────────────────

use narf_userspace::{SyscallArgs, SyscallReturn, TrapContext};

/// Arch-specific `TrapContext` wrapper around a live trap frame.
/// Constructed at int-0x80 dispatch time so raw handlers get
/// `set_return` + `redirect_to_kernel` bound to the real frame.
struct X86TrapContext<'a> {
    frame: &'a mut TrapFrame,
    args: SyscallArgs,
}

impl<'a> X86TrapContext<'a> {
    fn from_int80(frame: &'a mut TrapFrame) -> Self {
        let args = SyscallArgs {
            arg0: frame.rdi,
            arg1: frame.rsi,
            arg2: frame.rdx,
            arg3: frame.r10,
            arg4: frame.r8,
            arg5: frame.r9,
        };
        Self { frame, args }
    }
}

impl<'a> TrapContext for X86TrapContext<'a> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }

    fn set_return(&mut self, ret: SyscallReturn) {
        self.frame.rax = ret.value;
        self.frame.rdx = ret.status as u64;
    }

    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        // Rewrite the CPU-pushed fields so common_trap's iretq
        // lands in kernel mode at the supplied RIP/RSP. CS=KCODE,
        // SS=KDATA match the kernel's data-segment convention.
        // RFLAGS retains the caller's flags — kernel code is
        // prepared for any flag state.
        self.frame.rip = rip;
        self.frame.cs = super::gdt::KCODE_SEL as u64;
        self.frame.rsp = rsp;
        self.frame.ss = super::gdt::KDATA_SEL as u64;
        true
    }

    fn redirect_to_user(&mut self, entry_rip: u64, entry_rsp: u64) -> bool {
        // Rewrite the trap frame so the upcoming iretq lands in
        // user mode at the freshly-loaded program's entry. Used
        // by execve to discard the caller's post-syscall
        // continuation (the old image's text is about to be
        // unmapped) and resume execution in the new image.
        //
        // Selectors: UCODE/UDATA carry RPL=3 so iretq enters CPL=3.
        //
        // RFLAGS: 0x202 = IF (interrupts enabled) + reserved bit
        // 1 (always 1 per Intel SDM Vol 1 §3.4.3). Discards any
        // user-controllable flag state from the caller — the new
        // program starts with a clean flag word.
        //
        // GPRs: zeroed — POSIX execve says the new image observes
        // unspecified register values; zeroing is the most
        // defensible "no information leak from caller" choice.
        // The crt0 / _start prologue reads argv/envp from rsp,
        // not from registers, so no useful information is lost.
        self.frame.rip = entry_rip;
        self.frame.cs = super::gdt::UCODE_SEL as u64;
        self.frame.rsp = entry_rsp;
        self.frame.ss = super::gdt::UDATA_SEL as u64;
        self.frame.rflags = 0x202;
        // Zero GPRs.
        self.frame.rax = 0;
        self.frame.rbx = 0;
        self.frame.rcx = 0;
        self.frame.rdx = 0;
        self.frame.rsi = 0;
        self.frame.rdi = 0;
        self.frame.rbp = 0;
        self.frame.r8 = 0;
        self.frame.r9 = 0;
        self.frame.r10 = 0;
        self.frame.r11 = 0;
        self.frame.r12 = 0;
        self.frame.r13 = 0;
        self.frame.r14 = 0;
        self.frame.r15 = 0;
        true
    }

    unsafe fn save_user_state(&self, out: *mut u8) -> bool {
        use super::user::UserState;
        // SAFETY: caller declared `out` is writable for at least
        // `size_of::<UserState>()` bytes — the trait's contract.
        let s = unsafe { &mut *(out as *mut UserState) };
        let f = &self.frame;
        s.r15 = f.r15;
        s.r14 = f.r14;
        s.r13 = f.r13;
        s.r12 = f.r12;
        s.r11 = f.r11;
        s.r10 = f.r10;
        s.r9 = f.r9;
        s.r8 = f.r8;
        s.rbp = f.rbp;
        s.rdi = f.rdi;
        s.rsi = f.rsi;
        s.rdx = f.rdx;
        s.rcx = f.rcx;
        s.rbx = f.rbx;
        s.rax = f.rax;
        s.rip = f.rip;
        s.rflags = f.rflags;
        s.rsp = f.rsp;
        s.valid = 1;
        true
    }

    fn returning_to_user(&self) -> bool {
        // CS RPL = bits[1:0]. RPL=3 ⇒ user mode. A
        // `redirect_to_kernel`'d frame has CS=KCODE_SEL (RPL=0)
        // so this returns false and the hook short-circuits.
        (self.frame.cs & 3) == 3
    }

    fn deliver_signal(&mut self, handler_vaddr: u64, signum: u32) -> bool {
        // POSIX-compliant signal delivery. Saves the full pre-trap
        // user context as a SigContext on the user stack so the
        // handler can return through sys_sigreturn (sycall 187),
        // which restores every register exactly. Pre-fix the path
        // only saved RIP — handlers that clobbered callee-saved
        // regs (per SysV C ABI compliant handlers don't, but signal
        // handlers commonly do non-trivial work) corrupted the
        // resumed thread.
        //
        // Stack layout after delivery (low → high addresses):
        //
        //   [new_rsp + 0  ]  fallback_return (handler's `ret` pops
        //                    this if it doesn't go through
        //                    sigreturn; we point it at the saved
        //                    RIP so a degenerate handler that just
        //                    returns lands at the trapping
        //                    instruction without state restoration)
        //   [new_rsp + 8  ]  SigContext { ... }   (fits in 192 B)
        //
        // The handler `handler_vaddr` is what libc registered via
        // sigaction — typically a libc-provided trampoline that
        // dispatches to the user's actual handler then calls
        // sys_sigreturn (syscall 187), which restores the
        // SigContext frame. A user that registers a raw handler
        // (no libc) falls through to the fallback_return path.
        //
        // Handler signature: `extern "C" fn(c_int)` — signum in rdi.
        // sigcontext addr in rsi.
        let fallback_return = self.frame.rip;

        // Build the SigContext on the user stack. Total bytes:
        // 128 (SysV red zone — caller's data above RSP) +
        // size_of::<SigContext>() (176) + 8 (fallback_return slot).
        // Skipping the red zone means we'd clobber bytes the caller
        // legitimately stored above its declared RSP (e.g. the call
        // frame's return address that the function hasn't pushed
        // yet under SysV-amd64 §3.2.2).
        let ctx_size = core::mem::size_of::<SigContext>() as u64;
        const SYSV_RED_ZONE: u64 = 128;
        let raw_rsp = self.frame.rsp.wrapping_sub(SYSV_RED_ZONE + ctx_size + 8);
        // Align the new RSP to 16-byte boundary, then `| 0x8`. The
        // handler is reached via iretq (no implicit `call` push), so
        // it must see RSP at the position a `call` would have left
        // it: 16k + 8. The function prologue's `push rbp` then lands
        // at 16k.
        let new_rsp = (raw_rsp & !0xFu64) | 0x8;

        let ctx_vaddr = new_rsp + 8;
        let ctx = SigContext {
            r15: self.frame.r15,
            r14: self.frame.r14,
            r13: self.frame.r13,
            r12: self.frame.r12,
            r11: self.frame.r11,
            r10: self.frame.r10,
            r9: self.frame.r9,
            r8: self.frame.r8,
            rbp: self.frame.rbp,
            rdi: self.frame.rdi,
            rsi: self.frame.rsi,
            rdx: self.frame.rdx,
            rcx: self.frame.rcx,
            rbx: self.frame.rbx,
            rax: self.frame.rax,
            rip: self.frame.rip,
            rflags: self.frame.rflags,
            rsp: self.frame.rsp,
            signum: signum as u64,
            _pad: [0; 3],
        };

        // SAFETY: the user stack is mapped in the active CR3; the
        // CPU is at CPL=0 holding the trap; writes through the user
        // vaddr cross the demand-paging branch on the new bytes if
        // needed.
        unsafe {
            core::ptr::write_volatile(new_rsp as *mut u64, fallback_return);
            core::ptr::write_volatile(ctx_vaddr as *mut SigContext, ctx);
        }

        self.frame.rsp = new_rsp;
        self.frame.rdi = signum as u64;
        // The trampoline reads sigcontext via rsi (libc convention).
        self.frame.rsi = ctx_vaddr;
        self.frame.rip = handler_vaddr;
        true
    }

    fn perform_sigreturn(&mut self, sc_vaddr: u64) -> bool {
        // SAFETY: same conditions as deliver_signal — we're at CPL=0
        // holding the trap frame for the calling task; sc_vaddr is
        // the explicit sigcontext addr the trampoline forwarded
        // (originally set in RSI by deliver_signal).
        unsafe { perform_sigreturn(self, sc_vaddr) }
    }
}

/// Saved register state for a signal-delivery sigreturn round-trip.
/// Layout matches what `sys_sigreturn` reads back from user RSP+8.
/// Wire-stable: the libc-side trampoline / debugger walks the same
/// shape.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SigContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub signum: u64,
    pub _pad: [u64; 3],
}

/// Restore a SigContext frame at user RSP+8 into the live trap
/// frame. Called from `sys_sigreturn`. The user RSP at entry is
/// pointing at the trampoline-return slot; the SigContext sits 8
/// bytes above. After restore the trap path's iretq lands the user
/// back at the saved RIP with full register state.
///
/// # Safety
/// Must be called from the int-0x80 trap-handler context after
/// kernel_syscall_entry has run; `self.frame` is the live trap
/// frame about to be popped by iretq.
unsafe fn perform_sigreturn(ctx: &mut X86TrapContext<'_>, sc_vaddr: u64) -> bool {
    if (ctx.frame.cs & 3) != 3 {
        return false;
    }
    if sc_vaddr == 0 {
        return false;
    }
    // SAFETY: user-supplied vaddr; the read goes through the active
    // user AS. A bogus addr faults user-side.
    let sc = unsafe { core::ptr::read_volatile(sc_vaddr as *const SigContext) };
    use core::fmt::Write as _;
    ctx.frame.r15 = sc.r15;
    ctx.frame.r14 = sc.r14;
    ctx.frame.r13 = sc.r13;
    ctx.frame.r12 = sc.r12;
    ctx.frame.r11 = sc.r11;
    ctx.frame.r10 = sc.r10;
    ctx.frame.r9 = sc.r9;
    ctx.frame.r8 = sc.r8;
    ctx.frame.rbp = sc.rbp;
    ctx.frame.rdi = sc.rdi;
    ctx.frame.rsi = sc.rsi;
    ctx.frame.rdx = sc.rdx;
    ctx.frame.rcx = sc.rcx;
    ctx.frame.rbx = sc.rbx;
    ctx.frame.rax = sc.rax;
    ctx.frame.rip = sc.rip;
    // Preserve only IF (bit 9) + TF (bit 8) from the saved RFLAGS
    // (POSIX requires the trap context's flags to be restored
    // verbatim, but a malicious user setting NT/IOPL bits could
    // escape sandboxing on a future fork; mask to the safe set).
    const SAFE_RFLAGS: u64 = (1 << 9) | (1 << 8) | (1 << 0); // IF, TF, CF
    let preserved = sc.rflags & SAFE_RFLAGS;
    let kept_kernel = ctx.frame.rflags & !SAFE_RFLAGS;
    ctx.frame.rflags = preserved | kept_kernel;
    ctx.frame.rsp = sc.rsp;
    true
}
