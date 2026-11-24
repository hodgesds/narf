//! Built-in platform: the kernel's own crates, re-exported unchanged.

pub use narf_console::Writer as Console;
pub use narf_lib::mutex::{Mutex, MutexGuard};
pub use narf_lib::sync::IrqSafeSpinLock;
pub use narf_scheduler::block_on_spin;

/// Synchronous hardware delay that keeps the kernel's sleep pumps (console,
/// framebuffer, cursor) ticking.
pub fn delay_ms(ms: u32) {
    let deadline = narf_time::Deadline::after_ms(ms as u64);
    narf_scheduler::responsive_spin_until(
        || deadline.expired(),
        narf_time::Deadline::after_ms(ms as u64 + 1),
    );
}

/// The CPU running the caller, for spreading TX rings.
pub fn current_cpu() -> u32 {
    narf_lib::percpu::current_cpu() as u32
}

/// Spawn a driver task on the kernel executor.
pub fn spawn<F: core::future::Future<Output = ()> + Send + 'static>(future: F) {
    let _ = narf_scheduler::spawn(future);
}

/// Framebuffer status-panel counters (`wifi: <stage>`).
pub mod diag {
    pub use narf_memory::diag::{
        latch_wifi_error, note_wifi_crash, note_wifi_recovered, set_wifi_stage, WifiStage,
    };
}

/// Monotonic clock, deadlines and sleeps.
pub mod time {
    pub use narf_time::{Deadline, Instant, SleepUntil};

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_time::wall::monotonic_ns()
    }
}

/// Coherent DMA memory.
pub mod dma {
    pub use narf_io::{alloc_coherent, alloc_coherent_masked, DmaBuffer};
    pub use narf_lib::id::DomainId;
}

/// Interrupt handlers (hard-IRQ context, built in).
pub mod irq {
    pub use narf_interrupts::{install_handler_named, remove_handler, IrqStatus};
}

/// Firmware lookup through the trusted loader authority.
pub mod firmware {
    use alloc::vec::Vec;

    /// Why a firmware file could not be had.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FwError {
        /// No such file (yet: probe can run before the rootfs scan).
        NotFound,
        NoMemory,
        /// Unsigned where a signer is required, or failed validation.
        Invalid,
        /// No trusted loader authority exists yet.
        NoAuthority,
        /// The authority was revoked.
        Revoked,
    }

    /// `request_firmware` against the kernel firmware registry.
    #[derive(Debug)]
    pub struct Loader {
        auth: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    }

    impl Loader {
        pub fn new() -> Result<Self, FwError> {
            let root = narf_firmware::trusted_loader_authority().ok_or(FwError::NoAuthority)?;
            let auth = root.derive().map_err(|_| FwError::Revoked)?;
            Ok(Self { auth })
        }

        /// A loader over a given authority (tests stage a bootstrap
        /// registry instead of the trusted loader's).
        #[cfg(feature = "kernel-test")]
        pub fn from_cap(
            auth: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
        ) -> Self {
            Self { auth }
        }

        /// The whole file, at most `max` bytes; `signed` requires a verified
        /// signer (board, regulatory and calibration data).
        pub fn load(&self, name: &str, max: usize, signed: bool) -> Result<Vec<u8>, FwError> {
            crate::firmware_asset::load(&self.auth, name, max, signed)
                .map(|asset| asset.bytes)
                .map_err(|error| match error {
                    narf_firmware::FirmwareError::NotFound => FwError::NotFound,
                    narf_firmware::FirmwareError::OutOfMemory => FwError::NoMemory,
                    _ => FwError::Invalid,
                })
        }
    }
}
