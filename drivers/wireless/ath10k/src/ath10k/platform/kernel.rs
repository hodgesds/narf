//! Built-in platform: the kernel's own crates, re-exported unchanged.

pub use narf_console::Writer as Console;
pub use narf_lib::mutex::{Mutex, MutexGuard};
pub use narf_lib::sync::IrqSafeSpinLock;
pub use narf_scheduler::{block_on_spin, responsive_spin_until, yield_now};

/// `ath10k_core_check_smbios` over the boot-time DMI table.
pub use narf_drivers_wireless_ath_core::board::check_smbios;

/// Spawn a driver task on the kernel executor.
pub fn spawn<F: core::future::Future<Output = ()> + Send + 'static>(future: F) {
    let _ = narf_scheduler::spawn(future);
}

/// Monotonic clock, deadlines and sleeps.
pub mod time {
    pub use narf_time::Deadline;

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_time::wall::monotonic_ns()
    }

    /// Sleep `ns` nanoseconds on the kernel's timers.
    pub fn sleep_ns(ns: u64) -> narf_time::SleepUntil {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ns))
    }
}

/// Coherent DMA memory.
pub mod dma {
    pub use narf_io::{alloc_coherent, alloc_coherent_masked, DmaBuffer};
    pub use narf_lib::id::DomainId;
}

/// The bound PCI function: its identity, its device capability and the
/// config-space operations the transport performs through it.
pub mod pci {
    pub use narf_bus::pci::{
        clear_command, cmd, read_command, read_config32, set_command, write_config32,
    };
    pub use narf_bus::pci_express::{clear_and_set_link_control, read_status, LNKCTL_ASPMC};
    pub use narf_bus::{BusAddr, BusDevice, BusDeviceCap, MmioRegion, PcieAddr};
    pub use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read, Write};
    /// Run `operation` inside one invocation of the function's current cap.
    pub use narf_drivers_wireless_ath_core::qualcomm_pci::invoke;
}

/// The installed regulatory domain (`narf_wireless::reg::db`).
pub mod reg {
    pub use narf_wireless::reg::db::{ensure_domain, get_domain, snapshot};
}

/// Emission/receive authorities of the AP and off-channel owners.
pub use narf_wireless::ap_control;
pub use narf_wireless::WirelessNetIface;
