//! What rtw88 needs from the kernel, in the module build.
//!
//! Built in, the driver names the kernel's crates directly (`narf_time`,
//! `narf_scheduler`, `narf_wireless`, ...). A loadable `.ko` can cross only
//! the primitive C KABI, so this module provides **the same names** —
//! `platform::narf_time`, `platform::narf_scheduler`, ... — over
//! `narf-module-rt`, the kernel-free protocol crates and KABI exports. Each
//! driver file that names a kernel crate imports those names in the module
//! build only:
//!
//! ```ignore
//! #[cfg(feature = "module")]
//! #[allow(unused_imports)]
//! use crate::rtw88::platform::{narf_time, narf_wireless};
//! ```
//!
//! so the ~55k lines of driver source build both ways without edits to
//! their bodies, and the built-in build is unchanged. ath11k does the same
//! with `platform::` names of its own (`drivers/wireless/ath11k`); rtw88
//! names the kernel crates because it uses far more of them.
//!
//! Each shim carries only what the module-compiled files use, with the
//! kernel's semantics where the KABI can provide them:
//!
//! - **Runtime** ([`narf_scheduler`], [`narf_time`], [`narf_lib`]): the
//!   module's [`EXEC`]utor, the module-rt clock, sleeps and locks. Sleeps
//!   complete on the executor's heartbeat (`narf_usb_spawn_poller`, 1 ms).
//! - **Firmware** ([`narf_firmware`], [`narf_capabilities`]): files come
//!   through `narf_firmware_open`/`_read`/`_signed`; the module's
//!   `Firmware:Read` manifest grant is the authority, so the capability
//!   types are plain tokens that never revoke.
//! - **USB** ([`narf_drivers_usb`], [`narf_drivers_wireless_rtl_usb`]): the
//!   `ControlIo`/`Io` transport traits the driver is written against, with
//!   the KABI implementation in `usb_kabi.rs`.
//! - **Stack** ([`narf_net`], [`narf_ipc`], [`narf_wireless`]): the
//!   station's netdev hooks (link, RX delivery, disconnect reports) route to
//!   `iface_module.rs`, which crosses to the kernel through the netif bridge
//!   and the `WIFI` family host. The regulatory database is the world
//!   domain: a module cannot read the kernel's regdb.
//! - **PCI-only types** ([`narf_bus`], [`narf_power`]): uninhabited. The
//!   module build carries no PCI function, so every path that would need one
//!   is statically unreachable, which the compiler checks.

#![allow(missing_debug_implementations)]

use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_module_rt::exec::Executor;

#[path = "bus.rs"]
pub mod narf_bus;
#[path = "capabilities.rs"]
pub mod narf_capabilities;
#[path = "console.rs"]
pub mod narf_console;
#[path = "usb.rs"]
pub mod narf_drivers_usb;
#[path = "rtl_usb.rs"]
pub mod narf_drivers_wireless_rtl_usb;
#[path = "firmware.rs"]
pub mod narf_firmware;
#[path = "io.rs"]
pub mod narf_io;
#[path = "ipc.rs"]
pub mod narf_ipc;
#[path = "lib_sync.rs"]
pub mod narf_lib;
#[path = "net.rs"]
pub mod narf_net;
#[path = "power.rs"]
pub mod narf_power;
#[path = "scheduler.rs"]
pub mod narf_scheduler;
#[path = "time.rs"]
pub mod narf_time;
#[path = "wireless.rs"]
pub mod narf_wireless;

/// KABI exports the platform itself calls.
pub(crate) mod ffi {
    unsafe extern "C" {
        pub fn narf_random_bytes(buf: *mut u8, len: usize) -> i32;
        pub fn narf_udelay(ns: u64) -> i32;
        pub fn narf_firmware_open(
            name: *const u8,
            name_len: usize,
            out_handle: *mut u64,
            out_size: *mut usize,
        ) -> i32;
        pub fn narf_firmware_read(
            handle: u64,
            offset: u64,
            buf: *mut u8,
            len: usize,
            out_read: *mut usize,
        ) -> i32;
        pub fn narf_firmware_signed(handle: u64) -> i32;
        pub fn narf_firmware_close(handle: u64) -> i32;
    }
}

/// The module's executor: every driver future runs here, from the USB
/// completion upcalls and the 1 ms device poller.
pub static EXEC: Executor = Executor::new();

/// The probed USB function's token; 0 until probe.
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// Record the probed device (the token every device export takes).
pub fn set_device(dev: u64) {
    DEVICE.store(dev, Ordering::Release);
}

/// The probed device's token.
pub fn device() -> u64 {
    DEVICE.load(Ordering::Acquire)
}

/// Spawn a driver task on the module's executor. Refused only after module
/// exit has stopped the executor, when nothing may run any more.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    let _ = EXEC.spawn(future);
}

/// Busy-wait `ns` nanoseconds (`narf_udelay`, at most 1 s per call), during
/// which the kernel's sleep pumps keep ticking.
pub fn delay_ns(ns: u64) {
    let mut left = ns;
    while left > 0 {
        let step = left.min(1_000_000_000);
        // SAFETY: argument-only call, 1 ns ..= 1 s.
        let _ = unsafe { ffi::narf_udelay(step) };
        left -= step;
    }
}

/// The kernel's DRBG, installed as the entropy source the kernel-free
/// `narf-crypto` draws from (CCMP packet numbers, EAPOL nonces).
pub fn install_entropy() {
    fn kernel_random(out: &mut [u8]) -> bool {
        out.chunks_mut(4096).all(|chunk| {
            // SAFETY: `chunk` names `chunk.len()` (≤ 4096) writable bytes.
            unsafe { ffi::narf_random_bytes(chunk.as_mut_ptr(), chunk.len()) == 0 }
        })
    }
    narf_crypto::install_entropy_source(kernel_random);
}

/// `narf_drivers_wireless_core::watchdog_work`: the device's periodic
/// watchdog. Built in this is kernel delayed work; here it is a task on the
/// module executor that sleeps one period between steps.
pub mod watchdog_work {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;

    /// A device whose watchdog step runs every period.
    pub trait Watchdog: Send + Sync + 'static {
        /// The device has been withdrawn: the work stops.
        fn watchdog_stopped(&self) -> bool;
        /// One watchdog period's step.
        fn watchdog_step(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
    }

    /// Run `device`'s watchdog every `period_ms`, the first run one period
    /// from now, until a run finds the device stopped.
    pub fn start<D: Watchdog>(device: &Arc<D>, period_ms: u64) {
        let weak = Arc::downgrade(device);
        super::spawn(async move {
            loop {
                narf_module_rt::time::sleep_ms(period_ms).await;
                match weak.upgrade() {
                    Some(device) if !device.watchdog_stopped() => device.watchdog_step().await,
                    _ => return,
                }
            }
        });
    }
}
