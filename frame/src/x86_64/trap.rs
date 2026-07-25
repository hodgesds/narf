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

/// Ensure every page in the user range `[lo, hi)` is present and writable in
/// the active user address space, backing demand-paged / growable-stack pages
/// on the way (the same recovery the `#PF` handler would do on a real touch).
///
/// Returns `false` if any page cannot be backed — i.e. the range runs off the
/// end of a fixed mapping (a genuine stack overflow). This is the guard that
/// keeps `deliver_signal`'s CPL=0 frame writes from faulting *un-recoverably*
/// and panicking the whole kernel when a user task overflows its stack during
/// signal delivery (e.g. a SIGSEGV handler that itself faults, walking the
/// stack down one rt_sigframe at a time). On `false` the caller force-applies
/// the signal's default action (terminate) — Linux's `force_sigsegv` model —
/// so the offending task dies and the kernel survives.
#[cfg(target_arch = "x86_64")]
fn ensure_user_range_writable(lo: u64, hi: u64) -> bool {
    use narf_memory::AddressSpaceError;
    let Some(as_arc) = narf_userspace::active_user_as() else {
        // No active user AS — a kernel-internal delivery (or a unit test
        // driving a kernel-buffer "stack"). Nothing to back / can't check;
        // don't block. Only a delivery to a *real* user task (AS present) but
        // an unbacked target page is the overflow we must refuse.
        return true;
    };
    let mut p = lo & !0xFFFu64;
    while p < hi {
        let v = narf_memory::VirtAddr::new(p);
        // SAFETY: the active CR3 belongs to this AS (we're in its trap
        // context); the identity map is live. `demand_alloc_page` backs a
        // demand slot and reports `AlignmentMismatch` for an already-present
        // page (both mean "writable now"); `try_grow_stack` promotes a guard
        // page. Anything else means the page is unbacked and not growable.
        let backed = matches!(
            unsafe { as_arc.demand_alloc_page(v) },
            Ok(()) | Err(AddressSpaceError::AlignmentMismatch)
        ) || unsafe { as_arc.try_grow_stack(v) }.is_ok();
        if !backed {
            return false;
        }
        p = p.wrapping_add(0x1000);
    }
    true
}

/// Scheduler-stall watchdog. Detects a *global forward-progress stall*
/// (the kernel keeps taking timer ticks but USER SYSCALLS stop advancing —
/// the signature of the intermittent SMP wedge: workers parked/stuck while
/// the benchmark gets no responses) and dumps per-CPU scheduler state ONCE
/// so the wedge can be classified without a debugger:
///   - per CPU: ready-queue depth, # of awake (runnable) slots, the
///     published HALTED flag, whether the queue lock was held, and the
///     last-tick CPL/RIP (kernel RIP → addr2line offline).
/// Decision: `halted && awake>0` ⇒ lost wakeup; `!halted && awake>0` ⇒
/// spinning-not-polling (data-path/lock); `locked` ⇒ stuck in the queue
/// lock. Self-latches after one dump. Cheap (a few atomics per tick); the
/// dump only ever runs once, from IRQ context, via the same TrapWriter the
/// perf dump uses, then panics so CI cannot silently time out after a
/// diagnosed stall.
///
/// Off by default — build with `--features stall-watchdog` to arm it for
/// an SMP-wedge investigation (a few atomics per tick; dumps once).
#[cfg(feature = "stall-watchdog")]
mod stall_wd {
    use core::fmt::Write as _;
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
    use narf_console::TrapWriter;

    const MAXC: usize = 16;
    // Last interrupted RIP / CPL per CPU, recorded every tick.
    static LAST_RIP: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];
    static LAST_CPL: [AtomicU8; MAXC] = [const { AtomicU8::new(0) }; MAXC];
    static LAST_TASK: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];
    static LAST_STAGE: [AtomicU8; MAXC] = [const { AtomicU8::new(0) }; MAXC];
    // Stall detector state (checked on whichever CPU happens to tick).
    static LAST_CHECK_CYCLES: AtomicU64 = AtomicU64::new(0);
    static LAST_SYSCALLS: AtomicU64 = AtomicU64::new(0);
    static HIGH_WATER: AtomicU64 = AtomicU64::new(0);
    static FLAT_WINDOWS: AtomicU64 = AtomicU64::new(0);
    static DUMPED: AtomicBool = AtomicBool::new(false);

    /// Called from the timer-tick path with the interrupted CPL3-or-not
    /// `cs` and `rip`. Records this CPU's last RIP/CPL, then (rate-limited
    /// to ~once/second, on whatever CPU ticks) checks for a syscall-count
    /// stall and dumps once.
    pub fn tick(cs: u64, rip: u64) {
        let cpu = narf_lib::percpu::current_cpu();
        if cpu < MAXC {
            LAST_STAGE[cpu].store(1, Ordering::Relaxed);
            LAST_RIP[cpu].store(rip, Ordering::Relaxed);
            LAST_CPL[cpu].store((cs & 3) as u8, Ordering::Relaxed);
            LAST_TASK[cpu].store(narf_scheduler::current_task_id().raw(), Ordering::Relaxed);
        }
        if DUMPED.load(Ordering::Relaxed) {
            return;
        }
        // The per-CPU `narf_lib::perf` software counters (incl. `syscalls`,
        // our forward-progress signal) only increment while perf is
        // ENABLED — otherwise the bump is a no-op and the count stays 0.
        // The perf-dump tick enables it, but that's a separate feature; the
        // watchdog must enable it itself or its syscall signal is always 0.
        if !narf_lib::perf::enabled() {
            narf_lib::perf::set_enabled(true);
        }
        let cpns = narf_scheduler::narf_time::cycles_per_ns().max(1) as u64;
        let now = narf_scheduler::narf_time::now_cycles();
        // ~1 s cadence.
        let window = cpns.saturating_mul(1_000_000_000);
        let last = LAST_CHECK_CYCLES.load(Ordering::Relaxed);
        if now.wrapping_sub(last) < window {
            return;
        }
        // Only one CPU advances the check per window (CAS the timestamp).
        if LAST_CHECK_CYCLES
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let sc = narf_lib::perf::snapshot().syscalls;
        let prev = LAST_SYSCALLS.swap(sc, Ordering::Relaxed);
        // `HIGH_WATER` reused as a monotonic WINDOW COUNTER here.
        let wc = HIGH_WATER.fetch_add(1, Ordering::Relaxed) + 1;
        let delta = sc.wrapping_sub(prev);
        const RCU_CRITICAL_NS: u64 = 1_000_000_000;
        let rcu_stalled =
            narf_rcu::stalled_cpu_mask(narf_scheduler::narf_time::monotonic_ns(), RCU_CRITICAL_NS);
        if rcu_stalled != 0 && !DUMPED.swap(true, Ordering::Relaxed) {
            let _ = writeln!(
                TrapWriter,
                "STALL-WD: RCU quiescent-state timeout mask={rcu_stalled:#x}"
            );
            dump(sc);
            panic!("STALL-WD: RCU quiescent-state timeout");
        }
        // Wedge signature: past boot (window 20 ≈ 20 s uptime) and the
        // syscall RATE collapses far below healthy. A healthy 200-conn run
        // does ~150-200k syscalls/window; the partial wedge limps at ~2k
        // (most workers stuck, a few connections trickling). A healthy
        // 200-conn run does >100k syscalls/window; a wedged/degraded run
        // limps far below. Trigger on delta < 50k for 3 consecutive windows
        // — catches the full stall (delta 0) AND the degraded "limping"
        // wedge whose exact rate varies (2k-30k). A healthy run completes
        // (and qemu exits) well before the window count matters, so this
        // only ever fires on a genuine wedge.
        if wc > 20 && delta < 50_000 {
            let flats = FLAT_WINDOWS.fetch_add(1, Ordering::Relaxed) + 1;
            if flats >= 3 && !DUMPED.swap(true, Ordering::Relaxed) {
                dump(sc);
                panic!("STALL-WD: scheduler forward progress stopped");
            }
        } else {
            FLAT_WINDOWS.store(0, Ordering::Relaxed);
        }
    }

    pub fn stage(value: u8) {
        let cpu = narf_lib::percpu::current_cpu();
        if cpu < MAXC {
            LAST_STAGE[cpu].store(value, Ordering::Relaxed);
        }
    }

    fn dump(sc: u64) {
        let reporter = narf_lib::percpu::current_cpu();
        let (ipi_sent, ipi_skip) = narf_scheduler::dbg_resched_counts();
        let _ = writeln!(
            TrapWriter,
            "STALL-WD: scheduler stalled (syscalls flat at {sc}); reporter_cpu={reporter}; resched_ipi_sent={ipi_sent} resched_skip_not_halted={ipi_skip}; per-CPU state:"
        );
        for cpu in 0..MAXC {
            if cpu != 0 && !narf_lib::smp::is_online(cpu as u32) {
                continue;
            }
            let (depth, awake, halted, locked) = narf_scheduler::dbg_cpu_stall(cpu);
            let rip = LAST_RIP[cpu].load(Ordering::Relaxed);
            let cpl = LAST_CPL[cpu].load(Ordering::Relaxed);
            let task = LAST_TASK[cpu].load(Ordering::Relaxed);
            let stage = LAST_STAGE[cpu].load(Ordering::Relaxed);
            let verdict = if cpu == reporter {
                "REPORTING"
            } else if locked {
                "LOCK-HELD"
            } else if halted && awake > 0 {
                "LOST-WAKEUP"
            } else if !halted && awake > 0 {
                "SPIN-NOT-POLLING"
            } else if halted {
                "idle-halted"
            } else {
                "running"
            };
            let _ = writeln!(
                TrapWriter,
                "STALL-WD cpu={cpu} depth={depth} awake={awake} halted={halted} locked={locked} task={task} stage={stage} cpl={cpl} rip={rip:#x} -> {verdict}"
            );
        }
        // Wheel + per-task park states: shows a task parked with an expired
        // (or absurdly far) deadline and whether a deliverable signal is
        // pending — the signature that root-caused the stress-ng --futex
        // SMP strand (finite futex park deaf to the parent's SIGALRM).
        let now_ns = narf_scheduler::narf_time::monotonic_ns();
        let now_cyc = narf_scheduler::narf_time::now_cycles();
        let nd = narf_scheduler::narf_time::timer_wheel::next_deadline_cycles();
        let _ = writeln!(
            TrapWriter,
            "STALL-WD wheel: occ={} next={:?} now_cyc={now_cyc} now_ns={now_ns}",
            narf_scheduler::narf_time::timer_wheel::occupied(),
            nd
        );
        for (tid, pid, st, dl, fu, parked) in narf_userspace::task::dbg_park_snapshot() {
            let sig = narf_userspace::handlers::signal_pending_bits(tid);
            let _ = writeln!(
                TrapWriter,
                "STALL-WD task tid={tid} pid={pid} st={st} dl={dl} dl_expired={} futex={fu:#x} parked={parked} sigpend={sig:#x}",
                dl != 0 && dl != u64::MAX && now_ns > dl
            );
        }
    }
}

/// Feature-gated perf-stat dump: reads the per-CPU `narf_lib::perf` software
/// counters (summed) + the hardware PMU and prints a `perf stat`-style line
/// every ~3000 timer ticks. Off by default; build with `--features
/// perf-dump` for a profiling run. The counters themselves are always on.
#[cfg(feature = "perf-dump")]
mod perf_dump {
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_arch::x86_64::pmu;

    static PMUC: narf_lib::sync::IrqSafeSpinLock<Option<[pmu::PmuCounter; 4]>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    static LAST: AtomicU64 = AtomicU64::new(u64::MAX);
    // Last interrupted RIP / CPL per CPU, recorded every tick — shows WHERE a
    // busy core is spinning (addr2line the printed rip against narf-frame).
    const MAXC: usize = 16;
    static LAST_RIP: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];
    static LAST_CPL: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];

    pub fn on_tick(rip: u64, cs: u64) {
        let cpu = narf_lib::percpu::current_cpu();
        if cpu < MAXC {
            LAST_RIP[cpu].store(rip, Ordering::Relaxed);
            LAST_CPL[cpu].store(cs & 3, Ordering::Relaxed);
        }
        // Attach the profiler (enables the per-CPU tracepoints). Cheap guard
        // so we don't re-store the shared `enabled` flag every tick.
        if !narf_lib::perf::enabled() {
            narf_lib::perf::set_enabled(true);
        }
        let t = narf_lib::perf::total_ticks();
        if t == 0 || t % 3000 != 0 || LAST.swap(t, Ordering::Relaxed) == t {
            return;
        }
        let mut g = PMUC.lock();
        if g.is_none() {
            // SAFETY: tick handler runs at CPL=0; single-CPU init.
            unsafe {
                if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                    pmu::alloc_counter(pmu::PmuEvent::Instructions),
                    pmu::alloc_counter(pmu::PmuEvent::Cycles),
                    pmu::alloc_counter(pmu::PmuEvent::LlcMisses),
                    pmu::alloc_counter(pmu::PmuEvent::BranchMisses),
                ) {
                    *g = Some([a, b, c, d]);
                }
            }
        }
        let (i, c, l, b) = match g.as_ref() {
            // SAFETY: live counters from alloc_counter; CPL=0.
            Some(c) => unsafe {
                (
                    pmu::read(&c[0]),
                    pmu::read(&c[1]),
                    pmu::read(&c[2]),
                    pmu::read(&c[3]),
                )
            },
            None => (0, 0, 0, 0),
        };
        drop(g);
        let s = narf_lib::perf::snapshot();
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::TrapWriter,
            "PERF ctx={} sc={} pf={} | uTk={} kTk={} | instr={} cyc={} llc={} br={}",
            s.ctx,
            s.syscalls,
            s.page_faults,
            s.user_ticks,
            s.kernel_ticks,
            i,
            c,
            l,
            b
        );
        // Per-core breakdown: where is the work landing, and in what mode?
        // A serialization bottleneck shows as ticks/syscalls concentrated
        // on one or two cores with the rest idle. Cheap (a few reads +
        // one writeln per online CPU, only every 3000 ticks).
        for cpu in 0..narf_lib::percpu::MAX_CPUS.min(16) {
            if cpu != 0 && !narf_lib::smp::is_online(cpu as u32) {
                continue;
            }
            let pc = narf_lib::perf::snapshot_cpu(cpu);
            if pc.user_ticks == 0 && pc.kernel_ticks == 0 && pc.syscalls == 0 {
                continue;
            }
            let rip = LAST_RIP[cpu].load(Ordering::Relaxed);
            let cpl = LAST_CPL[cpu].load(Ordering::Relaxed);
            let _ = writeln!(
                narf_console::TrapWriter,
                "PCORE cpu={} uTk={} kTk={} sc={} ctx={} pf={} cpl={} rip={:#x}",
                cpu,
                pc.user_ticks,
                pc.kernel_ticks,
                pc.syscalls,
                pc.ctx,
                pc.page_faults,
                cpl,
                rip
            );
        }
    }
}

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

/// Kernel core-dump: on a fatal exception, stream a minimal ELF core
/// (`NT_PRSTATUS` registers + a `PT_LOAD` of the live kernel stack) out COM2
/// (0x2F8). Route COM2 to a host file with QEMU `-serial file:<path>` (it is
/// the kernel's 2nd serial; the console stays on COM1), then analyze with
/// `gdb target/x86_64-unknown-none/debug/narf-frame <path>` for a real
/// backtrace of a kernel crash (e.g. the SMP rip=0x3 #UD). A user-process
/// coredump can't capture this — the smash is on the kernel stack.
#[cfg(target_arch = "x86_64")]
mod kcore {
    use super::TrapFrame;
    use core::arch::asm;

    const COM2: u16 = 0x2F8;

    #[inline]
    unsafe fn outb(port: u16, val: u8) {
        // SAFETY: `out` to a fixed legacy ISA I/O port; no memory access.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
        }
    }
    #[inline]
    unsafe fn inb(port: u16) -> u8 {
        let v: u8;
        // SAFETY: `in` from a fixed legacy ISA I/O port; no memory access.
        unsafe {
            asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        v
    }
    unsafe fn init() {
        // SAFETY: programs the COM2 UART via legacy ISA port I/O.
        unsafe {
            outb(COM2 + 1, 0x00); // no IRQs
            outb(COM2 + 3, 0x80); // DLAB
            outb(COM2, 0x01); // 115200 lo
            outb(COM2 + 1, 0x00); // hi
            outb(COM2 + 3, 0x03); // 8N1
            outb(COM2 + 2, 0xC7); // FIFO
            outb(COM2 + 4, 0x0B); // DTR/RTS/OUT2
        }
    }
    unsafe fn put(b: u8) {
        // SAFETY: polls the COM2 LSR then writes its data port (port I/O only).
        unsafe {
            let mut spin = 0u32;
            while inb(COM2 + 5) & 0x20 == 0 {
                spin += 1;
                if spin > 2_000_000 {
                    break;
                }
            }
            outb(COM2, b);
        }
    }
    unsafe fn put_bytes(s: &[u8]) {
        for &b in s {
            // SAFETY: `put` writes the COM2 data port.
            unsafe { put(b) };
        }
    }
    unsafe fn u16le(v: u16) {
        // SAFETY: `put_bytes` writes the COM2 data port.
        unsafe { put_bytes(&v.to_le_bytes()) };
    }
    unsafe fn u32le(v: u32) {
        // SAFETY: `put_bytes` writes the COM2 data port.
        unsafe { put_bytes(&v.to_le_bytes()) };
    }
    unsafe fn u64le(v: u64) {
        // SAFETY: `put_bytes` writes the COM2 data port.
        unsafe { put_bytes(&v.to_le_bytes()) };
    }

    /// Stream the ELF core for `frame` out COM2.
    pub unsafe fn dump(frame: &TrapFrame) {
        // SAFETY: fatal-path COM2 port I/O plus read_volatile of the live
        // kernel stack window (guarded canonical range below).
        unsafe {
            init();
            // 4 pages from rsp's page upward (the kernel stack grows down,
            // so the live caller frames sit at/above rsp — capture enough to
            // walk a deep call chain).
            let stack_lo = frame.rsp & !0xFFFu64;
            let stack_len: u64 = 0x4000;

            let phoff: u64 = 64;
            let note_off: u64 = phoff + 2 * 56; // 176
            let note_sz: u64 = 12 + 8 + 336; // Nhdr + "CORE\0\0\0\0" + prstatus = 356
            let load_off: u64 = note_off + note_sz; // 532

            // ── ELF header (ET_CORE, EM_X86_64) ──
            put_bytes(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            u16le(4);
            u16le(62);
            u32le(1);
            u64le(0);
            u64le(phoff);
            u64le(0);
            u32le(0);
            u16le(64);
            u16le(56);
            u16le(2);
            u16le(0);
            u16le(0);
            u16le(0);
            // ── Phdr PT_NOTE ──
            u32le(4);
            u32le(0);
            u64le(note_off);
            u64le(0);
            u64le(0);
            u64le(note_sz);
            u64le(0);
            u64le(0);
            // ── Phdr PT_LOAD (kernel stack) ──
            u32le(1);
            u32le(6);
            u64le(load_off);
            u64le(stack_lo);
            u64le(stack_lo);
            u64le(stack_len);
            u64le(stack_len);
            u64le(0x1000);
            // ── PT_NOTE: NT_PRSTATUS ──
            u32le(5);
            u32le(336);
            u32le(1);
            put_bytes(b"CORE\0\0\0\0");
            // prstatus head (112 bytes), pr_cursig (offset 12) = SIGILL(4)
            let mut head = [0u8; 112];
            head[12] = 4;
            put_bytes(&head);
            // pr_reg: 27 u64s in user_regs_struct order
            let regs: [u64; 27] = [
                frame.r15,
                frame.r14,
                frame.r13,
                frame.r12,
                frame.rbp,
                frame.rbx,
                frame.r11,
                frame.r10,
                frame.r9,
                frame.r8,
                frame.rax,
                frame.rcx,
                frame.rdx,
                frame.rsi,
                frame.rdi,
                frame.rax, // orig_rax
                frame.rip,
                frame.cs,
                frame.rflags,
                frame.rsp,
                frame.ss,
                0,
                0,
                0,
                0,
                0,
                0, // fs_base, gs_base, ds, es, fs, gs
            ];
            for r in regs {
                u64le(r);
            }
            u32le(0); // pr_fpvalid
            u32le(0); // pad
                      // ── PT_LOAD data: the kernel stack window ──
            let mut a = stack_lo;
            let end = stack_lo + stack_len;
            while a < end {
                let b = core::ptr::read_volatile(a as *const u8);
                put(b);
                a += 1;
            }
        }
    }
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

// Layout assertion: `narf_scheduler::stackful::TrapFrame` is a
// re-declaration of this struct (scheduler can't depend on frame,
// so the two are kept in sync by this assertion). Drift on
// either side fails the build.
const _: () = {
    assert!(
        core::mem::size_of::<TrapFrame>()
            == core::mem::size_of::<narf_scheduler::stackful::TrapFrame>(),
        "TrapFrame size must match scheduler::stackful::TrapFrame",
    );
};

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

unsafe extern "C" {
    /// Asm shim (`trap_entry.S`): runs `irq_dispatch_body(frame)` on this CPU's
    /// dedicated hardirq stack (`gs:[24]`), unless already nested on it
    /// (`gs:[32]`), in which case it runs on the current stack. Kernel GS must
    /// be live (it is — `common_trap` swapgs'd on user entry).
    fn run_irq_dispatch_on_stack(frame: *mut TrapFrame);
}

/// The external-interrupt dispatch body, run on the per-CPU hardirq stack by
/// [`run_irq_dispatch_on_stack`]. Contains `on_irq` (and thus the timer-wheel
/// drain + every device handler) + EOI, bracketed by the trap-handler-depth
/// marker. Kept OFF the interrupted task's kernel stack so a deep dispatch
/// cannot smash it (Linux runs hardirq + softirq handlers on the irq stack).
/// `frame` is accessed only through the pointer, so it stays valid on the
/// original (task) stack.
#[unsafe(no_mangle)]
extern "C" fn irq_dispatch_body(frame: *mut TrapFrame) {
    // SAFETY: `frame` is the live trap frame on the entry stack (shim contract).
    let frame = unsafe { &mut *frame };
    narf_lib::context::enter_trap_handler();
    narf_interrupts::on_irq_with_context(frame.vector as u8, frame.rip);
    // SAFETY: APIC is initialised before interrupts are enabled.
    unsafe {
        narf_interrupts::eoi();
    }
    narf_lib::context::exit_trap_handler();
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
        //
        // `num` is forwarded so the hook can ask the restartable-
        // syscall table whether the syscall the trap is returning
        // from should be re-executed when SA_RESTART is set on
        // the handler (in which case the arch's `deliver_signal`
        // rewinds RIP - 2 to land on the `int 0x80` opcode).
        if let Some(hook) = narf_userspace::handlers::signal_delivery_hook() {
            hook(&mut ctx, num);
        }
        return;
    }

    // NMI (vector 2). Dispatch through the lock-free NMI handler
    // chain (perf, watchdog, crash-trigger consumers register
    // there). Return without falling through to the exception /
    // panic path — unhandled NMIs should be diagnostic, not fatal.
    // The NMI hardware contract is: edge-only, IF=0 throughout.
    if frame.vector == 2 {
        narf_interrupts::on_nmi();
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
        // Tick-source dispatch. The clockevent registry publishes
        // `TICK_VECTOR` when `select_primary` succeeds — that's
        // the IRQ vector the selected backend delivers on.
        // LAPIC: vector 32. HPET: dynamically-allocated, typically
        // ≥48. Both flow through `on_tick` which increments the
        // selected device's tick_count AND fires the wheel.
        //
        // Backward compat: if TICK_VECTOR is 0 (no backend
        // selected — degraded mode), still treat vector 32 as the
        // LAPIC tick on the assumption the legacy direct
        // start_timer path is in use.
        let tick_vector =
            narf_time::clockevent::TICK_VECTOR.load(core::sync::atomic::Ordering::Acquire);
        let is_tick = if tick_vector != 0 {
            frame.vector as u8 == tick_vector
        } else {
            frame.vector == 32
        };
        if is_tick {
            // LAPIC backend still wants its own TIMER_TICKS bump
            // — keep the on_timer_tick call so existing
            // diagnostics (`apic::timer_ticks()`) still work.
            // For HPET the backend ISR handles its own counter
            // already; double-counting LAPIC isn't a concern
            // because tick_vector == 32 only when LAPIC is the
            // selected backend.
            if tick_vector == 32 || (tick_vector == 0 && frame.vector == 32) {
                narf_interrupts::x86_64::apic::on_timer_tick();
            }
            // Per-CPU perf counters: tag this tick by interrupted CPL.
            narf_lib::perf::tick((frame.cs & 3) != 3);
            // Scheduler-stall watchdog: record this CPU's RIP/CPL and, on a
            // global syscall-progress stall, dump per-CPU state once.
            #[cfg(feature = "stall-watchdog")]
            stall_wd::tick(frame.cs, frame.rip);
            #[cfg(feature = "perf-dump")]
            perf_dump::on_tick(frame.rip, frame.cs);
        }
        // Note: we don't call timer_wheel::fire_due from this trap
        // context. fire_due drops Wakers, which deallocate via the
        // global Sleepable allocator — that's a panic in IRQ
        // context (IF=0). The wheel is advanced by:
        //   (a) the selected clockevent's ISR (LAPIC/HPET) via
        //       its own backend-specific tick handler, which calls
        //       clockevent::on_tick (safe — handlers are
        //       carefully written to avoid alloc), AND
        //   (b) run_until_empty's idle path's TSC-driven busy-
        //       poll, with IRQs enabled, where Waker drops are
        //       allowed to free.
        // Mark this CPU as inside a real trap-handler frame
        // around the on_irq + EOI window. `dispatch::on_irq` uses
        // this to gate "defer wake() vs wake-direct" — defer is
        // required from a real trap (Sleepable alloc would
        // panic), but synchronous on_irq calls from smoke tests
        // need direct wakes (the test driver doesn't run the
        // executor that drains the deferred queue).
        // Run the IRQ-dispatch body (on_irq + EOI — which contains the
        // timer-wheel drain and every device handler) on this CPU's
        // dedicated hardirq stack, NOT the interrupted task's own kernel
        // stack (Linux `call_on_irqstack`). `frame` is passed by pointer
        // and read through it regardless of which stack the body runs on.
        // The preempt/signal tail below stays on the task stack so a
        // `kernel_switch` continuation is never stranded on the shared
        // IRQ stack (Linux reschedules on the thread stack).
        // SAFETY: kernel GS is live (common_trap swapgs'd on user entry);
        // gs:[24]/gs:[32] are set up per-CPU by percpu::init_bsp/init_ap.
        unsafe {
            run_irq_dispatch_on_stack(frame as *mut TrapFrame);
        }
        #[cfg(feature = "stall-watchdog")]
        if is_tick {
            stall_wd::stage(2);
        }
        if is_tick {
            // Preemption hook for stackful kernel tasks. Runs AFTER
            // EOI so that yielding to the executor doesn't leave
            // the LAPIC's in-service bit set; subsequent timer
            // ticks can still fire while we're switched out.
            //
            // try_preempt may NOT return: if a stackful task is
            // CPU-bound past its slice, it calls kernel_switch to
            // the executor right here. When the executor later
            // switches back in, we resume just past the
            // kernel_switch call, return through this fn, and
            // common_trap's iretq restores the task at its pre-
            // trap RIP. The trap frame on the task's kernel stack
            // is left untouched throughout — that's the
            // persistence mechanism.
            //
            // SAFETY: TrapFrame layout matches narf-scheduler's
            // re-declared TrapFrame (asserted below).
            // SAFETY: Valid memory or trusted environment
            unsafe {
                #[cfg(feature = "stall-watchdog")]
                stall_wd::stage(3);
                let sched_frame_ptr =
                    frame as *mut TrapFrame as *mut narf_scheduler::stackful::TrapFrame;
                narf_scheduler::stackful::try_preempt(&mut *sched_frame_ptr);
                #[cfg(feature = "stall-watchdog")]
                stall_wd::stage(4);
            }
            // (a) Raise any timer-driven signal whose deadline has passed
            // for the currently-running task (e.g. SIGALRM from
            // alarm()/setitimer(ITIMER_REAL)). A CPU-bound task never
            // parks, so the sleep-pump that normally fires interval timers
            // never runs for it — this alloc-free ISR check is what makes
            // its alarm fire. Done before the delivery hook below so the
            // freshly-raised signal lands on this same return-to-user.
            //
            // Gated on CPL=3 (returning to a running user task): a PARKED
            // itimer owner must be left to the sleep-pump, which both
            // raises AND wakes it. Firing here (the alloc-free raise
            // deliberately skips the wake) would advance the deadline and
            // starve the pump's wake, hanging the sleeper.
            if (frame.cs & 3) == 3 {
                narf_userspace::handlers::timer_tick_raise_due_signals();
                narf_userspace::handlers::numa_balance_tick();
            }
        }
        // Full Linux-style signal delivery on the timer-IRQ return to user.
        // Linux takes any pending, unblocked signal at EVERY kernel→user
        // return — including interrupt returns — so a task spinning in a
        // tight loop with no syscalls still receives signals (a fired
        // SIGALRM, a cross-task kill, SIGTERM/SIGKILL). This is the same
        // `default_signal_delivery` hook the int 0x80 + syscall-instruction
        // return paths run; SYSCALL_NUM_NONE because the interrupted
        // instruction isn't a syscall (no SA_RESTART rewind). Now that the
        // deferred-handled-signal model is gone (signal_smoke uses
        // sigsuspend) this can be the full hook, not the old eager/fatal
        // subset. Self-gates on returning_to_user (CS RPL=3) internally;
        // IRQ vectors run on RSP0 (not an IST) so a default-action
        // terminate that longjmps to the executor is on the same stack as
        // the syscall path's.
        if (frame.cs & 3) == 3 {
            let mut ctx = X86TrapContext::from_int80(frame);
            if let Some(hook) = narf_userspace::handlers::signal_delivery_hook() {
                hook(&mut ctx, narf_userspace::handlers::SYSCALL_NUM_NONE);
            }
        }
        // (b) Preemptive time-slice. On a timer tick that interrupted user
        // mode, hand the running task back to the cooperative executor so
        // a CPU-bound task can't monopolize the CPU and starve siblings
        // (and their self-driven sleep deadlines). Gated on is_tick so
        // only the scheduler tick slices (not every device IRQ), and on
        // CPL=3 so a task interrupted mid-syscall (CPL=0) is never yanked.
        // Runs AFTER signal delivery so a pending/just-raised signal is
        // taken before we yield. timer_preempt_user_task does what
        // sys_yield does — it longjmps to the executor and does NOT return
        // when it preempts; the task resumes later via
        // enter_user_mode_resume. It's a no-op (returns) when no polling
        // executor is wired (kernel-test contexts).
        if is_tick && (frame.cs & 3) == 3 {
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // Per-task-own-stack model: the user task ran on its own kernel
                // stack, so this timer trap's frame is on that stack — preempt
                // with a clean kernel_switch (no longjmp). On resume, the asm
                // tail below pops GPRs + iretq's the (signal-adjusted) frame
                // back to the interrupted user instruction.
                // SAFETY: TrapFrame layout matches narf-scheduler's mirror
                // (asserted in stackful.rs); `frame` is the live trap frame.
                unsafe {
                    let sched_frame_ptr =
                        frame as *mut TrapFrame as *mut narf_scheduler::stackful::TrapFrame;
                    narf_scheduler::stackful::try_preempt_user(&mut *sched_frame_ptr);
                }
            } else {
                let mut ctx = X86TrapContext::from_int80(frame);
                narf_userspace::handlers::timer_preempt_user_task(&mut ctx);
            }
        }
        return;
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
        narf_lib::perf::page_fault();
        // PF error code (Intel SDM Vol. 3 §4.7):
        //   bit 0 (P): set if fault was a present-page violation
        //   bit 1 (W): set if write
        //   bit 2 (U): set if CPL=3
        const PF_P: u64 = 1 << 0;
        const PF_W: u64 = 1 << 1;
        #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
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
            if from_user && narf_userspace::handlers::handle_numa_hint_fault(cr2) {
                return;
            }
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(cr2);
                // Publish the faulting task's NUMA mempolicy for `cr2`
                // so the demand-paging allocator steers the fresh frame
                // (set_mempolicy/mbind enforcement). Cleared right after.
                narf_userspace::publish_mempolicy_for_fault(cr2);
                // SAFETY: identity map live, AS belongs to the
                // task whose CR3 is currently active.
                // SAFETY: Valid memory or trusted environment
                let r = unsafe { as_arc.demand_alloc_page(v) };
                narf_userspace::clear_mempolicy_for_fault();
                if r.is_ok() {
                    return;
                }
                // Demand-alloc surfaced Unmapped: vaddr might land
                // in a STACK_GUARD region. try_grow_stack promotes
                // the guard to a real stack page and installs a
                // fresh guard below; on success the faulting
                // instruction retries and lands on the freshly
                // backed page. POSIX.1-2017 §2.2.2 — stack
                // auto-extension is implementation-defined.
                //
                // Also grow on a CPL=0 (supervisor) fault when cr2 is
                // in the user half: `deliver_signal` writes the signal
                // frame onto the user stack from kernel mode, and a
                // large frame (rt_sigframe ≈ a few hundred bytes) below
                // a near-page-boundary RSP lands in the guard page — a
                // not-present write fault with U=0. Without this the
                // kernel-mode write panics instead of growing the stack
                // (hit by stress-ng under heavy SMP churn, where signals
                // are delivered far more often near a stack boundary).
                // try_grow_stack only ever promotes a real STACK_GUARD
                // region, so a non-stack user vaddr still falls through
                // to the SEGV/panic surface.
                if from_user || cr2_in_user_half {
                    // SAFETY: same identity-map argument.
                    if unsafe { as_arc.try_grow_stack(v) }.is_ok() {
                        return;
                    }
                }
            }
        }
        // COW write-fault recovery: P+W on a present-RO user page.
        // The U/S bit distinguishes user-mode vs supervisor-mode
        // writes — both need recovery. User-mode writes happen when
        // the user task itself stores into a CoW-shared page;
        // supervisor-mode writes happen when the kernel is acting on
        // behalf of a user task (deliver_signal pushing a frame onto
        // the user stack, copy_to_user, etc.). We require cr2 to lie
        // in the user canonical-low half so the kernel can't
        // accidentally COW-resolve a fault on its own pages.
        const USER_CANONICAL_END: u64 = 0x0000_8000_0000_0000;
        let cr2_is_user = cr2 < USER_CANONICAL_END;
        if (ec & (PF_P | PF_W)) == (PF_P | PF_W) && cr2_is_user {
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(cr2);
                // SAFETY: low-4-GiB identity map is live, frame
                // allocator + COW refcount table are
                // initialised at boot. AS is the active user AS by
                // construction (cr2 in user half + active_user_as).
                // SAFETY: Valid memory or trusted environment
                let split_ok = unsafe { as_arc.cow_split_on_write(v) }.is_ok();
                if split_ok {
                    // SAFETY: same identity-map argument; the
                    // region was just touched by cow_split_on_write
                    // so it definitely exists.
                    // SAFETY: Valid memory or trusted environment
                    let remap_ok = unsafe { as_arc.remap_page(v) }.is_ok();
                    if remap_ok {
                        return;
                    }
                }
            }
        }
    }

    // Synchronous-signal delivery for user-mode CPU exceptions.
    // Runs AFTER demand-paging / stack-grow / COW so a legitimate
    // fault that has a normal recovery path doesn't get stolen by
    // an installed SIGSEGV handler. Only genuine user crashes —
    // dereferencing NULL, writing to a non-mapped page, divide by
    // zero — reach this. Strict CS RPL == 3 gate keeps kernel-mode
    // exceptions on the existing probe-catch / panic path.
    //
    // The hook returns true when it rewrote the trap frame to land
    // at a user signal handler — fall through to the asm tail's
    // iretq, which carries the rewritten RIP back to user mode where
    // the handler runs. Returning false (no handler installed, or an
    // unmappable vector like #DF) means the user genuinely deserves
    // the panic surface below.
    if (frame.cs & 3) == 3 {
        if let Some(hook) = narf_userspace::sync_signal_hook() {
            let vector = frame.vector;
            // Wave-58: forward the faulting address. #PF → CR2;
            // RIP-flavoured vectors (#UD/#DE/#OF/#BP/#AC/#GP) → trapping RIP.
            let addr = if vector == 14 {
                let cr2: u64;
                // SAFETY: reading CR2 at CPL=0 is always defined.
                unsafe {
                    core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
                        options(nostack, preserves_flags));
                }
                cr2
            } else {
                frame.rip
            };
            let info = narf_userspace::SyncFaultInfo { addr };
            let mut ctx = X86TrapContext::from_int80(frame);
            if hook(&mut ctx, vector, info) {
                return;
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

    // Status-panel diag: capture the UNRECOVERED #PF's CR2/RIP into
    // the diag latch. By placing the call after every recovery
    // surface (demand-paging, stack-grow, COW split, probe-catch)
    // and before the panic block, the diag latch holds the
    // earliest fault that actually killed the kernel — exactly
    // what the operator wants to read off the status panel on a
    // bare-metal boot that dies in #PF. First-fault-wins inside
    // diag::note_pf means cascading panics don't overwrite.
    if frame.vector == 14 {
        let cr2: u64;
        // SAFETY: reading CR2 at CPL=0 is always defined.
        unsafe {
            core::arch::asm!("mov {v}, cr2", v = out(reg) cr2,
                options(nostack, preserves_flags));
        }
        narf_memory::diag::note_pf(cr2, frame.rip);
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
    {
        let cr3: u64;
        // SAFETY: reading CR3 at CPL=0 is always defined.
        unsafe {
            core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                options(nostack, preserves_flags));
        }
        let _ = writeln!(TrapWriter, "  cr3:    {:#018x}", cr3);
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

    // Stack dump: for a control-flow corruption (e.g. RIP at a near-null
    // address) the faulting RIP is useless — the call chain and the
    // corrupted return address live on the stack. Dump raw words from RSP
    // so they can be resolved offline against the kernel ELF
    // (`addr2line -e <elf>`). ALIGN RSP DOWN to 8 rather than requiring
    // 8-alignment: a control-flow corruption often leaves RSP itself
    // misaligned (e.g. the observed wild-`rip` #UD had `rsp` ending in 0xC),
    // and skipping the dump there loses exactly the crash we most need it for.
    // Still guard canonical + non-null so a wild RSP can't cascade to a double
    // fault.
    let sp = frame.rsp & !0x7u64;
    let canonical = sp >= 0x1000 && !(0x0000_8000_0000_0000..0xFFFF_8000_0000_0000).contains(&sp);
    if canonical {
        let _ = writeln!(TrapWriter, "  stack @ rsp {:#018x}:", sp);
        for row in 0..10u64 {
            let base = sp + row * 32;
            let mut w = [0u64; 4];
            for (i, slot) in w.iter_mut().enumerate() {
                // SAFETY: `base` is canonical + 8-aligned; the kernel stack
                // is mapped. A torn RSP is the only risk and is bounded by
                // the canonical guard above (worst case a single nested #PF,
                // which re-enters this handler with the registers already
                // printed).
                *slot = unsafe { core::ptr::read_volatile((base + (i as u64) * 8) as *const u64) };
            }
            let _ = writeln!(
                TrapWriter,
                "    {:#018x}: {:016x} {:016x} {:016x} {:016x}",
                base, w[0], w[1], w[2], w[3]
            );
        }

        // Filtered backtrace: for a control-flow corruption the faulting RIP is
        // garbage, but the stack still holds the return addresses of the frames
        // that led here. Scan a window of stack words for values inside the
        // kernel .text range and print them (with their offset from
        // __text_start, so `addr2line -e <elf> <off>` names each frame) — the
        // approximate call chain, no offline stack-word triage needed.
        // SAFETY: __text_start/__text_end are linker-provided kernel-VA symbols.
        extern "C" {
            static __text_start: u8;
            static __text_end: u8;
        }
        let tstart = core::ptr::addr_of!(__text_start) as u64;
        let tend = core::ptr::addr_of!(__text_end) as u64;
        if tend > tstart {
            let _ = writeln!(
                TrapWriter,
                "  backtrace (stack words in kernel .text [{:#x}..{:#x}], +off = addr2line):",
                tstart, tend
            );
            let mut printed = 0u32;
            for i in 0..128u64 {
                if printed >= 16 {
                    break;
                }
                // SAFETY: same canonical/aligned RSP guard as the dump above.
                let v = unsafe { core::ptr::read_volatile((sp + i * 8) as *const u64) };
                if v >= tstart && v < tend {
                    let _ = writeln!(
                        TrapWriter,
                        "    [{:#06x}] {:#018x}  (+{:#x})",
                        i * 8,
                        v,
                        v - tstart
                    );
                    printed += 1;
                }
            }
            if printed == 0 {
                let _ = writeln!(
                    TrapWriter,
                    "    (no .text return addresses found in window)"
                );
            }
        }
    }

    // Kernel core dump out COM2 (captured by QEMU `-serial file:<path>`), so a
    // kernel crash can be analyzed offline in gdb. Harmless if COM2 isn't routed.
    let _ = writeln!(
        TrapWriter,
        "*** writing kernel core to COM2 (capture with QEMU -serial file:) ***"
    );
    // SAFETY: fatal path, single-threaded-enough; COM2 is the standard 2nd ISA
    // serial and `frame` is the live trap frame.
    unsafe {
        kcore::dump(frame);
    }
    let _ = writeln!(TrapWriter, "*** kernel core written ***");

    // SAFETY: after a fatal exception we have no policy to resume; exit with
    // a non-zero code so xtask / verification can see the failure.
    // SAFETY: Valid memory or trusted environment
    unsafe { narf_arch::exit_kernel(42) }
}

// ── TrapContext impl for the int-0x80 path ─────────────────────────

use narf_userspace::{
    SigDeliveryParams, SyscallArgs, SyscallReturn, TrapContext, SA_ONSTACK, SA_RESTART, SA_SIGINFO,
};

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

    fn user_rsp(&self) -> u64 {
        self.frame.rsp
    }

    fn rip(&self) -> u64 {
        self.frame.rip
    }

    fn set_rip(&mut self, rip: u64) {
        self.frame.rip = rip;
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
        // SAFETY: Valid memory or trusted environment
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

    fn deliver_signal(&mut self, params: &SigDeliveryParams) -> bool {
        // POSIX-compliant signal delivery. Honours three sa_flags:
        //
        //   * SA_RESTART: when set + the outer trap is a restartable
        //     syscall trap, rewinds the SAVED RIP (the one sigreturn
        //     restores) by 2 — both `int 0x80` (CD 80) and `syscall`
        //     (0F 05) are 2-byte instructions, so the next iretq
        //     after the handler lands ON the syscall instruction,
        //     not just after it. Re-executing the trap instruction
        //     is how Linux implements "restartable interrupted
        //     syscalls" — see arch/x86/kernel/signal_64.c
        //     `setup_rt_frame` + arch/x86/kernel/signal.c
        //     `handle_signal`.
        //
        //   * SA_ONSTACK: when set + a non-disabled altstack is
        //     supplied via `params.altstack_sp`/`altstack_size`,
        //     builds the sigframe at the top of the altstack
        //     instead of the user RSP. Matches Linux's
        //     `sas_ss_sp + sas_ss_size` (`sigsp` in
        //     arch/x86/kernel/signal.c).
        //
        //   * SA_SIGINFO: when set, lays out a full
        //     `struct rt_sigframe` (siginfo_t + ucontext_t per
        //     arch/x86/include/uapi/asm/ucontext.h) on the
        //     selected stack and sets the handler's RSI = &info,
        //     RDX = &ucontext so the 3-arg
        //     `void(int, siginfo_t *, void *)` shape is observed.
        //
        // Stack layout after delivery (low → high addresses):
        //
        //   Classic (no SA_SIGINFO):
        //     [new_rsp + 0  ]  fallback_return       (8 B)
        //     [new_rsp + 8  ]  SigContext            (176 B)
        //
        //   SA_SIGINFO (rt_sigframe):
        //     [new_rsp + 0   ]  fallback_return      (8 B)
        //     [new_rsp + 8   ]  siginfo_t            (128 B)
        //     [new_rsp + 136 ]  ucontext_t           (per Linux
        //                                             arch/x86/include/uapi/asm/ucontext.h
        //                                             — uc_flags +
        //                                             uc_link +
        //                                             uc_stack +
        //                                             mcontext_t +
        //                                             sigmask)
        //
        // `params.handler` is what libc registered via sigaction.
        // For a classic handler this is a trampoline that calls
        // sys_sigreturn (Linux x86_64 numbers it 15 for sigreturn;
        // NARF uses 187) at the end. For an SA_SIGINFO handler the
        // trampoline reads ucontext.uc_mcontext when restoring.
        let fallback_return = if params.restorer != 0 {
            params.restorer
        } else {
            self.frame.rip
        };
        let want_siginfo = (params.flags & SA_SIGINFO) != 0;
        let want_altstack = (params.flags & SA_ONSTACK) != 0 && params.altstack_sp != 0;
        // Naive handlers (no SA_SIGINFO, no SA_ONSTACK, no restorer)
        // don't have a libc trampoline to call sigreturn — they `ret`
        // directly and the kernel must arrange for that `ret` to land
        // at the resumption RIP with RSP within the SysV red zone of
        // the original user RSP. Use a minimal 16-byte `[saved_rip,
        // signum]` push; handler ret pops saved_rip, RSP ends at
        // orig_rsp - 8 (red-zone safe). Wave-79: full SigContext
        // layout shifted RSP by ~300 B which broke any post-handler
        // stack-relative access in the trapped code.
        let minimal_push = !want_siginfo && !want_altstack && params.restorer == 0;

        // Modern Linux (rt_sigaction) always uses the rt_sigframe
        // layout if a restorer is present, because the restorer
        // will call rt_sigreturn which expects that layout.
        let force_rt = params.restorer != 0;

        // Frame size depends on layout choice.
        let frame_size = if want_siginfo || force_rt {
            // 8 (fallback) + 128 (siginfo) + size_of::<UContext>().
            8 + 128 + (core::mem::size_of::<UContext>() as u64)
        } else if minimal_push {
            // [saved_rip, signum] only — naive-handler-safe.
            16
        } else {
            // SA_ONSTACK w/o SA_SIGINFO — libc trampoline reads
            // SigContext via RSI and calls sigreturn at end.
            8 + (core::mem::size_of::<SigContext>() as u64)
        };

        // ... (red zone and alignment logic)
        const SYSV_RED_ZONE: u64 = 128;
        let stack_top = if want_altstack {
            params.altstack_sp.wrapping_add(params.altstack_size)
        } else {
            self.frame.rsp.wrapping_sub(SYSV_RED_ZONE)
        };
        let raw_rsp = stack_top.wrapping_sub(frame_size);
        let new_rsp = (raw_rsp & !0xFu64) | 0x8;

        // Back the frame's target pages first. The writes below run at CPL=0
        // through the SMAP window, so a not-present page they touch faults in
        // KERNEL mode; if that page is a genuine stack overflow (not growable),
        // the `#PF` is unrecoverable and panics the whole kernel. Pre-faulting
        // here turns "can't place the signal frame" into a clean `false`
        // return → the caller applies the default action (terminate the task),
        // matching Linux's `force_sigsegv`. Growable / demand pages get backed
        // as a side effect, so legitimate deliveries proceed unchanged.
        if !ensure_user_range_writable(new_rsp, new_rsp.wrapping_add(frame_size)) {
            return false;
        }

        let saved_rip = if (params.flags & SA_RESTART) != 0 && params.restartable_syscall {
            self.frame.rip.wrapping_sub(2)
        } else {
            self.frame.rip
        };

        if want_siginfo || force_rt {
            // rt_sigframe path: lay out [fallback_return][siginfo_t][ucontext_t].
            let siginfo_vaddr = new_rsp + 8;
            let uctx_vaddr = siginfo_vaddr + 128;

            let uctx = UContext {
                uc_flags: 0,
                uc_link: 0,
                uc_stack_sp: params.altstack_sp,
                uc_stack_flags: if want_altstack {
                    1 /* SS_ONSTACK */
                } else {
                    0
                },
                uc_stack_size: params.altstack_size,
                uc_mcontext: McContext {
                    r8: self.frame.r8,
                    r9: self.frame.r9,
                    r10: self.frame.r10,
                    r11: self.frame.r11,
                    r12: self.frame.r12,
                    r13: self.frame.r13,
                    r14: self.frame.r14,
                    r15: self.frame.r15,
                    rdi: self.frame.rdi,
                    rsi: self.frame.rsi,
                    rbp: self.frame.rbp,
                    rbx: self.frame.rbx,
                    rdx: self.frame.rdx,
                    rax: self.frame.rax,
                    rcx: self.frame.rcx,
                    rsp: self.frame.rsp,
                    rip: saved_rip,
                    rflags: self.frame.rflags,
                    cs: self.frame.cs as u16,
                    gs: 0,
                    fs: 0,
                    ss: self.frame.ss as u16,
                    err: 0,
                    trapno: self.frame.vector,
                    oldmask: 0,
                    cr2: params.si_addr,
                    fpstate: 0,
                    reserved: [0; 8],
                },
                uc_sigmask: 0,
            };

            // SAFETY: `new_rsp` is the 16-byte-aligned user stack pointer
            // derived from the task's own RSP/altstack minus `frame_size`,
            // and `siginfo_vaddr`/`uctx_vaddr` are the layout offsets within
            // that same `frame_size` reservation, so all writes stay inside
            // the user stack we just allocated. `with_user_access` opens the
            // SMAP window so these CPL=0 writes to user PTEs don't fault; the
            // `write_unaligned`/`write_bytes` tolerate the unaligned siginfo
            // fields.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_arch::x86_64::smap::with_user_access(|| {
                    core::ptr::write_volatile(new_rsp as *mut u64, fallback_return);
                    let info_p = siginfo_vaddr as *mut u8;
                    core::ptr::write_bytes(info_p, 0, 128);
                    (info_p as *mut i32).write_unaligned(params.signum as i32);
                    (info_p.add(4) as *mut i32).write_unaligned(0);
                    (info_p.add(8) as *mut i32).write_unaligned(params.si_code);
                    (info_p.add(16) as *mut u64).write_unaligned(params.si_addr);
                    // _sifields._rt.si_sigval (sigqueue payload). Unused by
                    // non-queued signals, so writing 0 there is harmless.
                    (info_p.add(24) as *mut u64).write_unaligned(params.si_value);
                    core::ptr::write_volatile(uctx_vaddr as *mut UContext, uctx);
                });
            }

            self.frame.rsp = new_rsp;
            self.frame.rdi = params.signum as u64;
            self.frame.rsi = siginfo_vaddr;
            self.frame.rdx = uctx_vaddr;
            self.frame.rip = params.handler;
            true
        } else if minimal_push {
            // Naive-handler path: [saved_rip, signum] only. Handler
            // ret pops saved_rip, RSP lands within the SysV red zone
            // of orig_rsp so the trapped code resumes cleanly without
            // calling sigreturn.
            //
            // SAFETY: user stack is mapped under the active CR3 and
            // we hold the trap frame for the calling task. SMAP
            // bracket required for supervisor-mode write to USER pages.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_arch::x86_64::smap::with_user_access(|| {
                    core::ptr::write_volatile(new_rsp as *mut u64, saved_rip);
                    core::ptr::write_volatile((new_rsp + 8) as *mut u64, params.signum as u64);
                });
            }
            self.frame.rsp = new_rsp;
            self.frame.rdi = params.signum as u64;
            // No SigContext laid down — RSI is set to new_rsp+8
            // (the signum slot) only so a future trampoline-aware
            // handler that inspects RSI sees a defined value rather
            // than a stale register.
            self.frame.rsi = new_rsp + 8;
            self.frame.rip = params.handler;
            true
        } else {
            // SA_ONSTACK trampoline path: [fallback_return][SigContext].
            // The libc trampoline reads SigContext via RSI and calls
            // sigreturn to restore the trapped register state.
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
                rip: saved_rip,
                rflags: self.frame.rflags,
                rsp: self.frame.rsp,
                signum: params.signum as u64,
                _pad: [0; 3],
            };

            // SAFETY: see SA_SIGINFO branch.
            unsafe {
                narf_arch::x86_64::smap::with_user_access(|| {
                    core::ptr::write_volatile(new_rsp as *mut u64, fallback_return);
                    core::ptr::write_volatile(ctx_vaddr as *mut SigContext, ctx);
                });
            }

            self.frame.rsp = new_rsp;
            self.frame.rdi = params.signum as u64;
            // The trampoline reads sigcontext via rsi (libc convention).
            self.frame.rsi = ctx_vaddr;
            self.frame.rip = params.handler;
            true
        }
    }

    fn perform_sigreturn(&mut self, sc_vaddr: u64, is_rt: bool) -> bool {
        // SAFETY: same conditions as deliver_signal — we're at CPL=0
        // holding the trap frame for the calling task; sc_vaddr is
        // the explicit sigcontext addr the trampoline forwarded
        // (originally set in RSI by deliver_signal).
        // SAFETY: Valid memory or trusted environment
        unsafe { perform_sigreturn(self, sc_vaddr, is_rt) }
    }

    fn dump_gprs(&self) {
        use core::fmt::Write;
        let f = &self.frame;
        // #PF error code bits: P(0)=1 protection vs 0 not-present,
        // W(1)=write, U(2)=user, RSVD(3), I(4)=instr-fetch.
        let ec = f.error_code;
        let _ = writeln!(
            narf_console::Writer,
            "  pf-errcode={:#x} [P={} W={} U={}]",
            ec,
            ec & 1,
            (ec >> 1) & 1,
            (ec >> 2) & 1
        );
        let _ = writeln!(
            narf_console::Writer,
            "  gpr: rax={:x} rbx={:x} rcx={:x} rdx={:x} rsi={:x} rdi={:x} rbp={:x}",
            f.rax,
            f.rbx,
            f.rcx,
            f.rdx,
            f.rsi,
            f.rdi,
            f.rbp
        );
        let _ = writeln!(
            narf_console::Writer,
            "  gpr: r8={:x} r9={:x} r10={:x} r11={:x} r12={:x} r13={:x} r14={:x} r15={:x}",
            f.r8,
            f.r9,
            f.r10,
            f.r11,
            f.r12,
            f.r13,
            f.r14,
            f.r15
        );
    }
}

/// Linux-compatible `struct sigcontext` / `struct mcontext_t` on
/// x86_64. Layout exactly matches
/// `arch/x86/include/uapi/asm/sigcontext.h` so the libc shim's
/// `getcontext` / `swapcontext` / debugger-side unwinders can walk
/// it. Embedded inside `UContext` below.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct McContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    /// User-mode FP state pointer (0 = none). NARF doesn't yet save
    /// FPU state through delivery (the FP register file isn't
    /// touched by syscalls today — the user's FP state survives
    /// untouched through the trap, and the handler is expected to
    /// preserve it itself per the SysV ABI). Wire-stable so future
    /// FP-save work can fill this in without an ABI bump.
    pub fpstate: u64,
    pub reserved: [u64; 8],
}

/// Linux-compatible `struct ucontext` on x86_64. Layout per
/// `arch/x86/include/uapi/asm/ucontext.h`:
///   uc_flags, uc_link, uc_stack (sigaltstack), uc_mcontext,
///   uc_sigmask.
/// Pushed onto the user stack alongside `siginfo_t` when SA_SIGINFO
/// is set. The 3-arg handler receives `&ucontext` in RDX.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UContext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack_sp: u64,
    pub uc_stack_flags: i32,
    // 4 bytes pad to align uc_stack_size to 8 bytes — matches the
    // Linux `stack_t` layout (`ss_size` is `size_t` after a 4-byte
    // hole on 64-bit).
    pub uc_stack_size: u64,
    pub uc_mcontext: McContext,
    pub uc_sigmask: u64,
}

/// Saved register state for a signal-delivery sigreturn round-trip
/// (the classic non-SA_SIGINFO frame).
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
unsafe fn perform_sigreturn(ctx: &mut X86TrapContext<'_>, sc_vaddr: u64, is_rt: bool) -> bool {
    if (ctx.frame.cs & 3) != 3 {
        return false;
    }
    if sc_vaddr == 0 {
        return false;
    }

    // `is_rt` is the layout the kernel RECORDED when it delivered this signal
    // (deliver_signal's `want_siginfo || force_rt`), threaded down from
    // sys_sigreturn. We must NOT re-derive it from user memory: the previous
    // code sniffed `si_signo` at sc_vaddr+0 and treated 0<n<64 as rt, but that
    // word is user-controlled / layout-dependent, and a wrong guess read RIP
    // from the rt mcontext offset (sc_vaddr+168) over a legacy frame — landing
    // on the frame's `cs`/`ss` selector fields, so the restored RIP became a
    // tiny RPL-3 selector value and the iretq #UD'd. rt_sigframe (Linux x86_64):
    //   off 0 pretcode, off 8 siginfo, off 136 ucontext, off 176 mcontext.

    let (
        sc_rip,
        sc_rsp,
        sc_rax,
        sc_rbx,
        sc_rcx,
        sc_rdx,
        sc_rsi,
        sc_rdi,
        sc_rbp,
        sc_r8,
        sc_r9,
        sc_r10,
        sc_r11,
        sc_r12,
        sc_r13,
        sc_r14,
        sc_r15,
        sc_rflags,
    );

    if is_rt {
        // RT frame. RSP at rt_sigreturn entry points at siginfo
        // (restorer popped pretcode).
        // ucontext is at sc_vaddr + 128.
        // mcontext is at sc_vaddr + 128 + 40 = sc_vaddr + 168.
        let mc_vaddr = sc_vaddr + 168;
        // SAFETY: rt_sigframe path — `mc_vaddr = sc_vaddr + 168` is the
        // mcontext offset within the user `rt_sigframe` whose base
        // (`sc_vaddr`) was validated above; the frame the kernel itself laid
        // out reserves a full `McContext` there. `read_volatile` reads it as
        // a plain POD copy and `with_user_access` opens the SMAP window for
        // this read of a user PTE.
        // SAFETY: Valid memory or trusted environment
        let mc = unsafe {
            narf_arch::x86_64::smap::with_user_access(|| {
                core::ptr::read_volatile(mc_vaddr as *const McContext)
            })
        };
        sc_rip = mc.rip;
        sc_rsp = mc.rsp;
        sc_rax = mc.rax;
        sc_rbx = mc.rbx;
        sc_rcx = mc.rcx;
        sc_rdx = mc.rdx;
        sc_rsi = mc.rsi;
        sc_rdi = mc.rdi;
        sc_rbp = mc.rbp;
        sc_r8 = mc.r8;
        sc_r9 = mc.r9;
        sc_r10 = mc.r10;
        sc_r11 = mc.r11;
        sc_r12 = mc.r12;
        sc_r13 = mc.r13;
        sc_r14 = mc.r14;
        sc_r15 = mc.r15;
        sc_rflags = mc.rflags;
    } else {
        // Legacy SigContext.
        // SAFETY: legacy-frame path — `sc_vaddr` points at the `SigContext`
        // the kernel pushed onto the user stack, validated non-zero and
        // CPL=3 above, so a full `SigContext` is readable there.
        // `read_volatile` takes a plain POD copy and `with_user_access`
        // opens the SMAP window for this read of a user PTE.
        // SAFETY: Valid memory or trusted environment
        let sc = unsafe {
            narf_arch::x86_64::smap::with_user_access(|| {
                core::ptr::read_volatile(sc_vaddr as *const SigContext)
            })
        };
        sc_rip = sc.rip;
        sc_rsp = sc.rsp;
        sc_rax = sc.rax;
        sc_rbx = sc.rbx;
        sc_rcx = sc.rcx;
        sc_rdx = sc.rdx;
        sc_rsi = sc.rsi;
        sc_rdi = sc.rdi;
        sc_rbp = sc.rbp;
        sc_r8 = sc.r8;
        sc_r9 = sc.r9;
        sc_r10 = sc.r10;
        sc_r11 = sc.r11;
        sc_r12 = sc.r12;
        sc_r13 = sc.r13;
        sc_r14 = sc.r14;
        sc_r15 = sc.r15;
        sc_rflags = sc.rflags;
    }

    ctx.frame.r15 = sc_r15;
    ctx.frame.r14 = sc_r14;
    ctx.frame.r13 = sc_r13;
    ctx.frame.r12 = sc_r12;
    ctx.frame.r11 = sc_r11;
    ctx.frame.r10 = sc_r10;
    ctx.frame.r9 = sc_r9;
    ctx.frame.r8 = sc_r8;
    ctx.frame.rbp = sc_rbp;
    ctx.frame.rdi = sc_rdi;
    ctx.frame.rsi = sc_rsi;
    ctx.frame.rdx = sc_rdx;
    ctx.frame.rcx = sc_rcx;
    ctx.frame.rbx = sc_rbx;
    ctx.frame.rax = sc_rax;
    ctx.frame.rip = sc_rip;

    const SAFE_RFLAGS: u64 = (1 << 9) | (1 << 8) | (1 << 0); // IF, TF, CF
    let preserved = sc_rflags & SAFE_RFLAGS;
    let kept_kernel = ctx.frame.rflags & !SAFE_RFLAGS;
    ctx.frame.rflags = preserved | kept_kernel;
    ctx.frame.rsp = sc_rsp;
    true
}

// ── Smokes for the SA_* delivery flags ─────────────────────────────
//
// Synthetic-frame tests for the three sa_flags the arch
// `deliver_signal` honours: SA_RESTART (RIP rewind), SA_ONSTACK
// (altstack frame placement), and SA_SIGINFO (3-arg ucontext push).
// Each smoke builds a fresh `TrapFrame` with deterministic register
// sentinels, wraps it in `X86TrapContext`, calls `deliver_signal`
// with a tailored `SigDeliveryParams`, and then asserts the
// outputs — the rewritten trap-frame fields and the bytes the
// arch wrote into the in-memory "user stack" buffer.
//
// The "user stack" is a kernel-resident `[u64; N]` aligned to 16
// bytes. The arch's `deliver_signal` writes to it via
// `write_volatile` through a raw vaddr — which is perfectly
// well-defined when the vaddr is a kernel-mapped pointer.

use narf_kernel_test::{kernel_test_in, TestResult};

/// Aligned scratch region used as a synthetic user stack for the
/// SA_* smokes. 4 KiB is well over the largest sigframe NARF lays
/// (~432 B for SA_SIGINFO + the SysV red-zone reserve), so the
/// alignment-rounded base + frame_size never escapes the buffer.
#[repr(C, align(16))]
struct SmokeStack {
    bytes: [u8; 4096],
}

impl SmokeStack {
    const fn new() -> Self {
        Self { bytes: [0; 4096] }
    }

    /// Top-of-stack vaddr — what the test plants in `frame.rsp` so
    /// the arch's `sigsp(rsp - 128 - frame_size)` arithmetic lands
    /// at a valid offset inside `bytes`.
    fn top(&self) -> u64 {
        self.bytes.as_ptr() as u64 + self.bytes.len() as u64
    }

    /// Base of the buffer — what the test passes as
    /// `altstack_sp` for SA_ONSTACK smokes. `altstack_size` is the
    /// buffer length.
    fn base(&self) -> u64 {
        self.bytes.as_ptr() as u64
    }
}

/// Build a TrapFrame with each GP register set to a unique
/// sentinel so the arch's sigcontext write is easy to verify.
fn smoke_signal_trap_frame(rip: u64, rsp: u64) -> TrapFrame {
    TrapFrame {
        r15: 0xF1F1_F1F1_F1F1_F1F1,
        r14: 0xE2E2_E2E2_E2E2_E2E2,
        r13: 0xD3D3_D3D3_D3D3_D3D3,
        r12: 0xC4C4_C4C4_C4C4_C4C4,
        r11: 0xB5B5_B5B5_B5B5_B5B5,
        r10: 0xA6A6_A6A6_A6A6_A6A6,
        r9: 0x9797_9797_9797_9797,
        r8: 0x8888_8888_8888_8888,
        rbp: 0x7979_7979_7979_7979,
        rdi: 0x6A6A_6A6A_6A6A_6A6A,
        rsi: 0x5B5B_5B5B_5B5B_5B5B,
        rdx: 0x4C4C_4C4C_4C4C_4C4C,
        rcx: 0x3D3D_3D3D_3D3D_3D3D,
        rbx: 0x2E2E_2E2E_2E2E_2E2E,
        rax: 0x1F1F_1F1F_1F1F_1F1F,
        vector: 128,
        error_code: 0,
        rip,
        cs: 0x33, // UCODE_SEL with RPL=3
        rflags: 0x202,
        rsp,
        ss: 0x2B, // UDATA_SEL with RPL=3
    }
}

/// SA_RESTART: when a restartable syscall is interrupted by a
/// signal whose handler has `SA_RESTART`, the SAVED RIP (the one
/// sigreturn will restore on handler return) must be rewound by
/// 2 bytes so the user re-executes `int 0x80`.
fn smoke_x86_64_sa_restart_rewinds_saved_rip() -> TestResult {
    let stack = SmokeStack::new();
    // Post-trap RIP (the instruction AFTER int 0x80). Saved RIP
    // for SA_RESTART must land 2 bytes earlier — the int 0x80
    // opcode itself.
    const POST_TRAP_RIP: u64 = 0xC0FF_EE00_C0FF_EE12;
    let mut frame = smoke_signal_trap_frame(POST_TRAP_RIP, stack.top());
    let _ = stack.base(); // silence dead-store warning in builds w/o assertions

    let params = SigDeliveryParams {
        handler: 0xDEAD_BEEF_F00D_F00D,
        restorer: 0,
        signum: 10,
        flags: SA_RESTART,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: true,
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let ok = ctx.deliver_signal(&params);
    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    // Wave-79: naive-handler-safe minimal push. The saved RIP the
    // handler's `ret` will pop sits at [frame.rsp + 0]; no
    // SigContext is laid down (SA_RESTART without SA_SIGINFO /
    // SA_ONSTACK).
    let new_rsp = frame.rsp;
    // SAFETY: arch wrote a u64 saved_rip to this aligned vaddr just
    // above; reading it back from the same process is sound.
    // SAFETY: Valid memory or trusted environment
    let saved_rip = unsafe { core::ptr::read_volatile(new_rsp as *const u64) };
    if saved_rip != POST_TRAP_RIP.wrapping_sub(2) {
        return TestResult::Fail("SA_RESTART did not rewind saved RIP by 2");
    }
    // RDI must carry the signum for the 1-arg handler call.
    if frame.rdi != 10 {
        return TestResult::Fail("RDI not set to signum");
    }
    if frame.rip != 0xDEAD_BEEF_F00D_F00D {
        return TestResult::Fail("RIP not set to handler entry");
    }
    TestResult::Pass
}
kernel_test_in!("frame/x86_64", smoke_x86_64_sa_restart_rewinds_saved_rip);

/// Robustness: when a signal is delivered to a *real* user task (an active
/// address space is present) but the target stack range can't be backed —
/// a stack overflow during delivery, e.g. a SIGSEGV handler that itself
/// faults and walks the stack down one rt_sigframe at a time —
/// `deliver_signal` must REFUSE (return false) so the caller force-applies
/// the default action (terminate). Letting the CPL=0 frame write fault
/// unrecoverably instead panics the whole kernel for one runaway task; this
/// is the SMP `chroot_run` #PF that the pre-fault guard closes (Linux's
/// `force_sigsegv` model).
fn smoke_x86_64_deliver_signal_refuses_unbacked_user_stack() -> TestResult {
    use alloc::sync::Arc;
    use narf_memory::AddressSpace;

    // Present an EMPTY address space: every user vaddr is unbacked and not
    // growable (no STACK_GUARD region), so the pre-fault can't back the
    // frame. `AddressSpace::empty()` has root=0, but the unbacked path never
    // dereferences the root (no region matches → Unmapped before any walk).
    fn empty_as_lookup() -> Option<Arc<AddressSpace>> {
        Some(Arc::new(AddressSpace::empty()))
    }

    let saved = narf_userspace::address_space_lookup();
    narf_userspace::install_address_space_lookup(empty_as_lookup);

    // A canonical user-half RSP with nothing mapped beneath it. SA_SIGINFO
    // selects the largest (rt_sigframe) layout — the case most prone to
    // straddle an unmapped page.
    let user_rsp = 0x0000_7fff_0000_0000u64;
    let mut frame = smoke_signal_trap_frame(0xC0FF_EE00_1234_5678, user_rsp);
    let params = SigDeliveryParams {
        handler: 0xDEAD_BEEF_F00D_F00D,
        restorer: 0,
        signum: 11,
        flags: SA_SIGINFO,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: false,
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };
    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let refused = !ctx.deliver_signal(&params);

    // Restore the original lookup BEFORE returning so the live kernel /
    // other tests see their real per-task AS resolver again.
    narf_userspace::restore_address_space_lookup(saved);

    if !refused {
        return TestResult::Fail(
            "deliver_signal placed a frame on an unbacked user stack (would #PF-panic the kernel)",
        );
    }
    // A refused delivery must not have mutated the trap frame (no partial
    // write / RIP redirect to the handler).
    if frame.rip != 0xC0FF_EE00_1234_5678 {
        return TestResult::Fail("deliver_signal mutated RIP despite refusing delivery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_deliver_signal_refuses_unbacked_user_stack
);

/// SA_RESTART cleared: even on a restartable syscall, the saved
/// RIP must NOT be rewound — the syscall returns EINTR and the
/// next instruction after `int 0x80` runs on handler return.
fn smoke_x86_64_sa_restart_clear_does_not_rewind() -> TestResult {
    let stack = SmokeStack::new();
    const POST_TRAP_RIP: u64 = 0x1234_5678_9ABC_DE56;
    let mut frame = smoke_signal_trap_frame(POST_TRAP_RIP, stack.top());

    let params = SigDeliveryParams {
        handler: 0xABCD,
        restorer: 0,
        signum: 11,
        flags: 0, // no SA_RESTART
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: true,
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let _ = ctx.deliver_signal(&params);
    let new_rsp = frame.rsp;
    // Wave-79: minimal-push layout — saved RIP at new_rsp + 0.
    // SAFETY: see SA_RESTART smoke.
    let saved_rip = unsafe { core::ptr::read_volatile(new_rsp as *const u64) };
    if saved_rip != POST_TRAP_RIP {
        return TestResult::Fail("saved RIP rewound despite SA_RESTART clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_sa_restart_clear_does_not_rewind
);

/// SA_RESTART set but restartable_syscall false (non-restartable
/// syscall like nanosleep/poll/sigtimedwait): the arch must NOT
/// rewind RIP regardless of the flag — POSIX-2017 §2.4 says the
/// timeout family observes the abbreviated wait, not auto-restart.
fn smoke_x86_64_sa_restart_non_restartable_syscall() -> TestResult {
    let stack = SmokeStack::new();
    const POST_TRAP_RIP: u64 = 0xFEEDFACE_C0DEBABE;
    let mut frame = smoke_signal_trap_frame(POST_TRAP_RIP, stack.top());

    let params = SigDeliveryParams {
        handler: 0xABCD,
        restorer: 0,
        signum: 14,
        flags: SA_RESTART,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: false, // e.g. nanosleep — never restarts
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let _ = ctx.deliver_signal(&params);
    let new_rsp = frame.rsp;
    // Wave-79: minimal-push layout — saved RIP at new_rsp + 0.
    // SAFETY: see SA_RESTART smoke.
    let saved_rip = unsafe { core::ptr::read_volatile(new_rsp as *const u64) };
    if saved_rip != POST_TRAP_RIP {
        return TestResult::Fail("saved RIP rewound for a non-restartable syscall");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_sa_restart_non_restartable_syscall
);

/// SA_ONSTACK with a valid altstack: the arch must lay the
/// sigframe at the TOP of the altstack (`sp + size - frame_size`),
/// not at the user RSP.
fn smoke_x86_64_sa_onstack_uses_altstack_top() -> TestResult {
    // Two separate scratch regions so we can prove the frame
    // landed in the altstack, not the user stack.
    let user_stack = SmokeStack::new();
    let altstack = SmokeStack::new();
    let mut frame = smoke_signal_trap_frame(0xDEAD_F00D, user_stack.top());

    let params = SigDeliveryParams {
        handler: 0xBABEFACE,
        restorer: 0,
        signum: 12,
        flags: SA_ONSTACK,
        altstack_sp: altstack.base(),
        altstack_size: altstack.bytes.len() as u64,
        restartable_syscall: false,
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let ok = ctx.deliver_signal(&params);
    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    // frame.rsp must point inside the altstack region.
    let alt_lo = altstack.base();
    let alt_hi = altstack.base() + altstack.bytes.len() as u64;
    if frame.rsp < alt_lo || frame.rsp >= alt_hi {
        return TestResult::Fail("sigframe rsp not within altstack range");
    }
    // It also must NOT be inside the user stack.
    let user_lo = user_stack.base();
    let user_hi = user_stack.base() + user_stack.bytes.len() as u64;
    if frame.rsp >= user_lo && frame.rsp < user_hi {
        return TestResult::Fail("sigframe leaked onto user stack");
    }
    TestResult::Pass
}
kernel_test_in!("frame/x86_64", smoke_x86_64_sa_onstack_uses_altstack_top);

/// SA_ONSTACK set but no altstack installed (`altstack_sp = 0`):
/// the arch must fall back to the user RSP path — Linux spec
/// behaviour (`sigsp` returns the regular sp when no altstack
/// is configured).
fn smoke_x86_64_sa_onstack_no_altstack_falls_back() -> TestResult {
    let user_stack = SmokeStack::new();
    let mut frame = smoke_signal_trap_frame(0xDEAD_F00D, user_stack.top());

    let params = SigDeliveryParams {
        handler: 0xBABEFACE,
        restorer: 0,
        signum: 12,
        flags: SA_ONSTACK,
        altstack_sp: 0, // no altstack
        altstack_size: 0,
        restartable_syscall: false,
        si_code: 0,
        si_addr: 0,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let _ = ctx.deliver_signal(&params);

    // frame.rsp must land inside the user-stack buffer (below the
    // top, above the bottom — the arch lays the frame at
    // top - SYSV_RED_ZONE - frame_size).
    let user_lo = user_stack.base();
    let user_hi = user_stack.base() + user_stack.bytes.len() as u64;
    if frame.rsp < user_lo || frame.rsp >= user_hi {
        return TestResult::Fail("frame rsp did not fall back to user stack");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_sa_onstack_no_altstack_falls_back
);

/// SA_SIGINFO: the 3-arg handler observes RDI = signum,
/// RSI = &siginfo, RDX = &ucontext. The siginfo and ucontext are
/// laid out at known offsets relative to the frame base so the
/// trampoline (which is libc-side) can walk them.
fn smoke_x86_64_sa_siginfo_sets_three_args() -> TestResult {
    let stack = SmokeStack::new();
    let mut frame = smoke_signal_trap_frame(0xDEAD_F00D, stack.top());

    let params = SigDeliveryParams {
        handler: 0xCAFE_F00D,
        restorer: 0,
        signum: 11, // SIGSEGV
        flags: SA_SIGINFO,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: false,
        si_code: 2, // SEGV_ACCERR
        si_addr: 0xBAD_AAAA,
        si_value: 0,
        si_pid: 0,
    };

    let mut ctx = X86TrapContext::from_int80(&mut frame);
    let ok = ctx.deliver_signal(&params);
    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    // RDI = signum.
    if frame.rdi != 11 {
        return TestResult::Fail("RDI != signum");
    }
    // RSI = &siginfo. The arch lays siginfo at frame.rsp + 8.
    let siginfo_vaddr = frame.rsp + 8;
    if frame.rsi != siginfo_vaddr {
        return TestResult::Fail("RSI != &siginfo (rsp + 8)");
    }
    // RDX = &ucontext. The arch lays ucontext at frame.rsp + 8 + 128.
    let ucontext_vaddr = siginfo_vaddr + 128;
    if frame.rdx != ucontext_vaddr {
        return TestResult::Fail("RDX != &ucontext (rsp + 136)");
    }
    if frame.rip != 0xCAFE_F00D {
        return TestResult::Fail("RIP != handler");
    }

    // siginfo prefix bytes should be readable + match.
    // SAFETY: the arch just wrote a 128-B siginfo there; reading
    // back from a kernel-resident buffer is sound.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let signo = (siginfo_vaddr as *const i32).read_unaligned();
        let errno = ((siginfo_vaddr + 4) as *const i32).read_unaligned();
        let code = ((siginfo_vaddr + 8) as *const i32).read_unaligned();
        let addr = ((siginfo_vaddr + 16) as *const u64).read_unaligned();
        if signo != 11 {
            return TestResult::Fail("siginfo.si_signo mismatch");
        }
        if errno != 0 {
            return TestResult::Fail("siginfo.si_errno != 0");
        }
        if code != 2 {
            return TestResult::Fail("siginfo.si_code mismatch");
        }
        if addr != 0xBAD_AAAA {
            return TestResult::Fail("siginfo.si_addr mismatch");
        }
    }

    // ucontext.uc_mcontext.rip must hold the saved post-trap RIP
    // (no SA_RESTART rewind for this smoke). Offset from
    // ucontext_vaddr is offset_of!(UContext, uc_mcontext) +
    // offset_of!(McContext, rip).
    let mcontext_rip_offset =
        core::mem::offset_of!(UContext, uc_mcontext) + core::mem::offset_of!(McContext, rip);
    let saved_rip =
        // SAFETY: same justification as siginfo read.
        unsafe { ((ucontext_vaddr + mcontext_rip_offset as u64) as *const u64).read_unaligned() };
    if saved_rip != 0xDEAD_F00D {
        return TestResult::Fail("ucontext.uc_mcontext.rip != saved post-trap RIP");
    }
    TestResult::Pass
}
kernel_test_in!("frame/x86_64", smoke_x86_64_sa_siginfo_sets_three_args);
