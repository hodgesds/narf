//! Built-in platform: the kernel's own crates, re-exported unchanged.

pub use narf_io::iommu::DmaBlock;
pub use narf_lib::mutex::{Mutex, MutexGuard};
pub use narf_lib::sync::IrqSafeSpinLock;
pub use narf_scheduler::{block_on, block_on_spin, responsive_spin_until};

/// Monotonic clock, deadlines and sleeps (`narf_time`).
pub mod time {
    pub use narf_time::{sleep_cycles, Deadline, SleepUntil};

    /// Cycle/nanosecond conversion and the monotonic clock.
    pub mod wall {
        pub use narf_time::wall::{monotonic_ns, ns_to_cycles};
    }
}

/// Bus identity types the provisioning records bind to.
pub mod bus {
    pub use narf_bus::{BusAddr, DeviceId, PcieAddr};
    pub use narf_drivers_sdio::pio::HostIdentity;
    pub use narf_memory::PhysAddr;
}
