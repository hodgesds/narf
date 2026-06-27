//! narf-console — early boot serial, panic sink, MMU-enable handoff.
//!
//! Spec: `console/specification/spec.md` §3 + §3.1. Stage-1 scope: 16550A
//! on x86_64, PL011 on aarch64, plus `remap_to_virtual` so `memory/`'s
//! MMU bring-up doesn't silently kill the UART.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use narf_lib::sync::{IrqSafeSpinLock, OnceLock};
use narf_memory::{PhysAddr, VirtAddr};

pub mod klog;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as backend;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as backend;

/// UART hardware variant. `boot/` picks this from platform detection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum UartKind {
    /// 16550A UART on x86_64. `base` is treated as an I/O port number
    /// (typically 0x3F8) rather than an MMIO address.
    Uart16550,
    /// PL011 UART on aarch64. `base` is an MMIO address.
    Pl011,
}

/// Handoff flag state. The console stores this as an `AtomicUsize` so the
/// (base pointer, selection) pair is observable coherently across a single
/// `Acquire` load inside `write_str`.
const HANDOFF_PHYS: usize = 0;
const HANDOFF_VIRT: usize = 1;

/// Static console state. A single global is fine — Stage 1 is BSP-only and
/// we hold the write lock for the whole `write_str`.
struct Console {
    kind: OnceLock<UartKind>,
    handoff: AtomicUsize,
    base: AtomicPtr<u8>,
    lock: IrqSafeSpinLock<()>,
}

impl core::fmt::Debug for Console {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Console")
            .field("kind", &self.kind.get())
            .field("handoff", &self.handoff.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

static CONSOLE: Console = Console {
    kind: OnceLock::new(),
    handoff: AtomicUsize::new(HANDOFF_PHYS),
    base: AtomicPtr::new(core::ptr::null_mut()),
    lock: IrqSafeSpinLock::new(()),
};

/// Called by `boot/` before the MMU is on.
///
/// - `base` is physical: on x86_64 this is *actually* the I/O port number
///   (the `Uart16550` backend ignores the MMIO interpretation and reads
///   `base.raw() as u16`); on aarch64 it's the MMIO address of the PL011
///   register block.
/// - `kind` selects the backend.
///
/// Idempotent against repeated `early_init` calls with the same args
/// (re-initialising the FIFO / line control); calling with a different
/// `kind` panics because the whole console already committed to one UART.
pub fn early_init(base: PhysAddr, kind: UartKind) {
    // First caller records the kind; subsequent callers just re-init the
    // hardware. Kind mismatch panics (no valid reason to switch UARTs
    // mid-boot).
    if let Some(existing) = CONSOLE.kind.get() {
        assert_eq!(
            *existing, kind,
            "console::early_init: cannot switch UART kind mid-boot"
        );
    } else {
        let _ = CONSOLE.kind.set(kind);
    }
    CONSOLE
        .base
        .store(base.as_mut_ptr::<u8>(), Ordering::Release);
    CONSOLE.handoff.store(HANDOFF_PHYS, Ordering::Release);

    // SAFETY: the caller has supplied a real UART base; hardware
    // programming is idempotent on the 16550A / PL011.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        backend::init(base.raw() as usize, kind);
    }
}

/// Called by `memory/` inside the MMU-bring-up critical section. See
/// `console/` §3.1. Atomically swaps the base pointer from phys to virt
/// and flips the handoff flag.
///
/// Precondition: interrupts are disabled; the kernel has exactly one CPU
/// online; `virt` maps the same UART region as the original phys base.
pub fn remap_to_virtual(virt: VirtAddr) {
    // §4 invariant: remap_to_virtual MUST NOT be called twice.
    let prev = CONSOLE.handoff.swap(HANDOFF_VIRT, Ordering::AcqRel);
    assert_eq!(
        prev, HANDOFF_PHYS,
        "console::remap_to_virtual called more than once"
    );
    CONSOLE
        .base
        .store(virt.as_mut_ptr::<u8>(), Ordering::Release);
}

/// Write a string through the active backend. Blocks on a coarse lock to
/// prevent interleaved output across CPUs (harmless on Stage 1's single CPU,
/// correct when AP bring-up lands in Stage 2).
pub fn write_str(s: &str) {
    // Mirror to the kernel log ring *first*, before taking the
    // console lock. klog uses its own IrqSafe lock so panic-time
    // writes (which may already hold the console lock via the
    // panic_sink path) still capture without a deadlock risk.
    klog::record(s);

    let _g = CONSOLE.lock.lock();
    let kind = match CONSOLE.kind.get() {
        Some(k) => *k,
        None => return, // pre-init; silently drop
    };
    let base = CONSOLE.base.load(Ordering::Acquire) as usize;
    // SAFETY: `kind` + `base` were published via Release by `early_init`
    // or `remap_to_virtual`, and we hold the coarse lock; the backend
    // methods themselves uphold the compiler_fence discipline.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        backend::write_bytes(base, kind, s.as_bytes());
    }

    // Fan out to the framebuffer-console hook when installed.
    let h = FB_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: stored as `FbHook as usize` in `set_fb_hook`.
        let f: FbHook = unsafe { core::mem::transmute(h) };
        f(s.as_bytes());
    }
}

/// Enable RX-data-available IRQ on the active UART. After this
/// call, the chipset asserts the platform's UART IRQ line
/// (typically ISA IRQ 4 for COM1) when bytes arrive — caller
/// is responsible for routing that IRQ through the IOAPIC and
/// installing a handler that drains via `try_read_byte` before
/// turning this on.
///
/// No-op when the console isn't initialised yet.
#[cfg(target_arch = "x86_64")]
pub fn enable_rx_irq() {
    let _g = CONSOLE.lock.lock();
    let kind = match CONSOLE.kind.get() {
        Some(k) => *k,
        None => return,
    };
    let base = CONSOLE.base.load(Ordering::Acquire) as usize;
    if base == 0 {
        return;
    }
    // SAFETY: kind + base published Release; lock held; backend
    // call is a single port write.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        backend::enable_rx_irq(base, kind);
    }
}

/// Non-blocking single-byte read from the active UART, or `None` if
/// nothing is queued (RX FIFO empty / pre-init / unknown kind). Used
/// by the kernel's serial-input pump (registered as a sleep_pump
/// from `frame/bare_main.rs`) to drain typed bytes from `qemu -serial
/// stdio` and from the platform serial port on real hardware, then
/// push them onto `narf_input::GLOBAL_RING` as `InputEvent::AsciiByte`.
///
/// Holds the same coarse `CONSOLE.lock` as `write_str` so the RX read
/// doesn't tear against a concurrent TX (only matters when the pump
/// runs alongside another CPU writing — single-CPU today).
pub fn try_read_byte() -> Option<u8> {
    let _g = CONSOLE.lock.lock();
    let kind = *CONSOLE.kind.get()?;
    let base = CONSOLE.base.load(Ordering::Acquire) as usize;
    if base == 0 {
        return None;
    }
    // SAFETY: kind + base were published via Release by `early_init`
    // / `remap_to_virtual`; we hold the coarse lock; the backend's
    // `try_read_byte` is a one-shot LSR/FR + RBR/DR read with no TX
    // side effects.
    // SAFETY: Valid memory or trusted environment
    unsafe { backend::try_read_byte(base, kind) }
}

/// Type of the optional framebuffer fan-out callback. Boot-time
/// install only; no per-call allocation.
pub type FbHook = fn(&[u8]);

/// Stored as `FbHook as usize` so the static can sit alongside the
/// other AtomicUsize hooks without a Mutex.
static FB_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the FB-console fan-out. Frame's boot path calls this
/// after `graphics::install_fb_console` succeeds.
pub fn set_fb_hook(hook: FbHook) {
    FB_HOOK.store(hook as usize, Ordering::Release);
}

/// Atomically detach the current FB-console fan-out and return its
/// prior value as an opaque token. Subsequent kernel prints stay on
/// the serial / UART backend until [`restore_fb_hook`] is called
/// with the returned token.
///
/// Used by FB-handle owners (e.g. a userspace process that opened a
/// scanout via `Syscall::FbConnect`) to take exclusive ownership of
/// the framebuffer for the lifetime of the handle, so kernel
/// console glyphs don't paint over the user's pixels.
#[must_use = "the returned token must be passed to restore_fb_hook on disconnect"]
pub fn take_fb_hook() -> usize {
    FB_HOOK.swap(0, Ordering::AcqRel)
}

/// Re-install a previously-detached FB hook. Pass the value returned
/// by [`take_fb_hook`]; passing 0 leaves the hook unset (e.g. if no
/// FB console was ever installed).
pub fn restore_fb_hook(prior: usize) {
    FB_HOOK.store(prior, Ordering::Release);
}

/// True while a userspace scanout owner (a DRM master compositor, or a
/// `Syscall::FbConnect` handle holder) has taken the framebuffer. The FB
/// status-panel / cursor painters in `narf_fb` consult this and suppress
/// themselves so they don't paint kernel chrome over the user's pixels.
static FB_USER_OWNED: AtomicBool = AtomicBool::new(false);
/// Token saved by [`fb_take_for_user`] so [`fb_release_from_user`] can put
/// the console FB hook back exactly as it was.
static FB_USER_SAVED_HOOK: AtomicUsize = AtomicUsize::new(0);

/// A userspace scanout owner takes the framebuffer: detach the console FB
/// hook (kernel glyphs stop painting) and flag ownership so `narf_fb`'s
/// status-panel + cursor painters suppress themselves. Idempotent — a
/// second take while already owned is a no-op, so the DRM blit path may
/// call it on every page flip.
pub fn fb_take_for_user() {
    if FB_USER_OWNED.swap(true, Ordering::AcqRel) {
        return; // already owned
    }
    let prior = take_fb_hook();
    FB_USER_SAVED_HOOK.store(prior, Ordering::Release);
}

/// Hand the framebuffer back to the kernel console: re-attach the FB hook
/// and clear the ownership flag. Idempotent — releasing when not owned is
/// a no-op. Called when the last DRM master node closes.
pub fn fb_release_from_user() {
    if !FB_USER_OWNED.swap(false, Ordering::AcqRel) {
        return; // wasn't owned
    }
    let prior = FB_USER_SAVED_HOOK.swap(0, Ordering::AcqRel);
    restore_fb_hook(prior);
}

/// Whether a userspace scanout owner currently holds the framebuffer.
pub fn fb_user_owned() -> bool {
    FB_USER_OWNED.load(Ordering::Acquire)
}

/// Panic sink — no allocation, no re-entry, lock-free.
///
/// Bypasses the regular `CONSOLE.lock` because the panicking
/// CPU may already hold it (e.g. panicked mid-`write_str`); a
/// blocking lock attempt would deadlock against itself. Writes
/// directly to the UART backend AND to the framebuffer hook
/// (when installed) so the message reaches both serial and the
/// laptop screen.
///
/// Re-entrance guard: `IN_PANIC` short-circuits a recursive
/// panic (e.g. if the FB hook panics during its own write) so
/// we don't loop forever.
pub fn panic_sink(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::sync::atomic::AtomicBool;

    static IN_PANIC: AtomicBool = AtomicBool::new(false);
    if IN_PANIC.swap(true, Ordering::AcqRel) {
        // Recursive panic — just halt without trying to log
        // anything new.
        narf_arch::halt_forever();
    }

    // Status-panel diag: latch the panic location into the shared
    // diag state so the FB status panel turns red and shows a
    // compact marker (file/line hashed into a u64). First-only
    // semantics inside latch_panic mean the panic that caused us
    // is preserved even if the FB hook or RBP walk below tries to
    // re-panic. Atomic-only — no allocation, no lock acquisition.
    {
        let mut marker: u64 = 0;
        if let Some(loc) = info.location() {
            // Cheap FNV-1a 64 of file path + line. Compact enough
            // for the panel; the operator can grep the kernel for
            // the matching file/line later.
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in loc.file().as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
            h ^= loc.line() as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
            marker = h;
        }
        narf_memory::diag::latch_panic(marker);
    }

    // Format into a small fixed-size buffer + emit to both
    // sinks. Using `core::fmt::Write` against a stack buffer
    // avoids allocation and avoids the CONSOLE.lock path.
    struct StackBuf {
        bytes: [u8; 1024],
        len: usize,
    }
    impl fmt::Write for StackBuf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for &b in s.as_bytes() {
                if self.len < self.bytes.len() {
                    self.bytes[self.len] = b;
                    self.len += 1;
                }
            }
            Ok(())
        }
    }

    let mut buf = StackBuf {
        bytes: [0; 1024],
        len: 0,
    };
    let _ = writeln!(buf, "\n*** KERNEL PANIC ***");
    let _ = writeln!(buf, "{info}");
    // Best-effort RBP-chain walk. Rust kernels keep frame pointers
    // by default; each frame is `[saved_rbp, return_addr]`. Stop at
    // null / unaligned / outside [0xffff_8000_0000_0000, 0xffff_ffff_ffff_ffff]
    // to avoid a fault during panic.
    #[cfg(target_arch = "x86_64")]
    {
        let _ = writeln!(buf, "  backtrace (return addresses):");
        let mut rbp: u64;
        let mut rsp: u64;
        // SAFETY: reading rbp is always legal at CPL=0.
        unsafe {
            core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack, preserves_flags));
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        }
        let _ = writeln!(buf, "    rbp={:#x} rsp={:#x}", rbp, rsp);
        for depth in 0..16 {
            // Accept either kernel high-half (post-stack-switch) or
            // boot low-half (pre-Wave-2 stack swap) RBP values.
            // Reject only the bogus ones: null, unaligned, or
            // canonical-hole [0x0001_0000_0000_0000 .. 0xffff_0000_0000_0000].
            if rbp == 0
                || rbp & 0x7 != 0
                || (0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&rbp)
            {
                break;
            }
            // SAFETY: rbp validated above; reading [rbp + 8] is the
            // return address of the current frame, [rbp] is the
            // saved rbp.
            // SAFETY: Valid memory or trusted environment
            let (next_rbp, ret_addr): (u64, u64) = unsafe {
                let frame = rbp as *const u64;
                (frame.read_volatile(), frame.add(1).read_volatile())
            };
            let _ = writeln!(buf, "    #{depth} {ret_addr:#018x}");
            if next_rbp <= rbp {
                // Walk only goes deeper; loop detection.
                break;
            }
            rbp = next_rbp;
        }
    }
    let msg = &buf.bytes[..buf.len];

    // Direct write to UART backend, no lock acquisition.
    if let Some(kind) = CONSOLE.kind.get() {
        let base = CONSOLE.base.load(Ordering::Acquire) as usize;
        if base != 0 {
            // SAFETY: kind + base published Release; we accept
            // the risk of interleaving with another CPU's
            // mid-write — better than deadlocking on the lock.
            // Real panics are single-CPU events most of the
            // time anyway.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                backend::write_bytes(base, *kind, msg);
            }
        }
    }

    // Direct call into the FB hook, also lock-free.
    let h = FB_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: stored as `FbHook as usize` in `set_fb_hook`.
        let f: FbHook = unsafe { core::mem::transmute(h) };
        f(msg);
    }

    narf_arch::halt_forever();
}

/// Lock-free string emit used by the CPU trap path. The trap may
/// have fired while the original code was holding `CONSOLE.lock`
/// (mid-`write_str`); a blocking re-acquire from the trap handler
/// would deadlock against itself, which is why every line past
/// the first one in the exception printer used to vanish. Same
/// shape as `panic_sink` minus the format-into-stack-buf step
/// since callers usually want raw writes interleaved with their
/// own register dumps.
pub fn trap_sink(s: &str) {
    // Skip `klog::record` deliberately — it takes an
    // `IrqSafeSpinLock` (`RING.lock()`) and the original faulting
    // code may already hold it; deadlock there manifests as the
    // trap printer dying after one line. The FB hook is also
    // skipped for the same reason — the FB-console writer's path
    // takes its own locks.
    if let Some(kind) = CONSOLE.kind.get() {
        let base = CONSOLE.base.load(Ordering::Acquire) as usize;
        if base != 0 {
            // SAFETY: kind + base were published Release; we accept
            // the interleave risk versus deadlocking on the lock.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                backend::write_bytes(base, *kind, s.as_bytes());
            }
        }
    }
}

/// Lock-free `fmt::Write` adapter for the trap printer.
pub struct TrapWriter;

impl fmt::Debug for TrapWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrapWriter").finish()
    }
}

impl fmt::Write for TrapWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        trap_sink(s);
        Ok(())
    }
}

/// Formatter adapter for `write!` / `writeln!`.
pub struct Writer;

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer").finish()
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Kernel log macro. Minimal Stage 1 form — no levels, no structured
/// records yet. Those land when `tracing/` is online (Wave 4).
#[macro_export]
macro_rules! klog {
    ($($arg:tt)*) => {
        {
            use core::fmt::Write as _;
            let _ = writeln!($crate::Writer, $($arg)*);
        }
    };
}
