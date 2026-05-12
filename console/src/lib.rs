//! narf-console — early boot serial, panic sink, MMU-enable handoff.
//!
//! Spec: `console/specification/spec.md` §3 + §3.1. Stage-1 scope: 16550A
//! on x86_64, PL011 on aarch64, plus `remap_to_virtual` so `memory/`'s
//! MMU bring-up doesn't silently kill the UART.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

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
