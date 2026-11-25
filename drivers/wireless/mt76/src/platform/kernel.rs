//! Built-in platform: the kernel's own crates, re-exported unchanged.
//!
//! The few helpers defined here (PCI command updates, IOMMU stop/restore,
//! `sleep_ns`) are the exact sequences the driver files used to spell out
//! inline, moved behind one name so the module build can supply its own.

pub use narf_console::{PriorityWriter as PriorityConsole, Writer as Console};
pub use narf_lib::mutex::{LockFuture, Mutex, MutexGuard};
pub use narf_lib::sync::IrqSafeSpinLock;
pub use narf_scheduler::{responsive_spin_until, yield_now};

/// Spawn a driver task on the kernel executor.
pub fn spawn<F: core::future::Future<Output = ()> + Send + 'static>(future: F) {
    let _ = narf_scheduler::spawn(future);
}

/// Monotonic clock, deadlines and sleeps.
pub mod time {
    pub use narf_time::{sleep_until, Deadline, SleepUntil};

    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        narf_time::wall::monotonic_ns()
    }

    /// Sleep `ns` nanoseconds on the kernel timer.
    pub fn sleep_ns(ns: u64) -> SleepUntil {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ns))
    }
}

/// Coherent DMA memory.
pub mod dma {
    pub use narf_io::{alloc_coherent, alloc_coherent_for, DmaBuffer, DmaDevice};
    pub use narf_lib::id::DomainId;
}

/// The bound PCI function: its identity, its current probe capability and
/// configuration-space access under that capability.
pub mod bus {
    pub use narf_bus::pci::{cmd, PM_D3HOT_DELAY_MS};
    pub use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
    pub use narf_capabilities::CapError;
    use narf_capabilities::{Cap, CapOp, Write};

    /// The bus probe capability the driver retains for its function.
    pub type DeviceCap = Cap<BusDeviceCap, Write>;

    /// Run `operation` under the current invocation of `cap` (fails once
    /// the binding was revoked).
    pub fn invoke<T>(cap: &DeviceCap, operation: impl FnOnce() -> T) -> Result<T, CapError> {
        struct Registers<F>(F);
        impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Registers<F> {
            type Output = T;
            fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
                Ok(self.0())
            }
        }
        cap.invoke(Registers(operation))
    }

    /// Clear, then set, PCI command bits and read the register back
    /// (`clear = set = 0` only reads it). Caller holds the invocation.
    pub fn command(cap: &DeviceCap, device: &BusDevice, clear: u16, set: u16) -> Result<u16, ()> {
        if clear != 0 {
            narf_bus::pci::clear_command(cap, device, clear).map_err(|_| ())?;
        }
        if set != 0 {
            narf_bus::pci::set_command(cap, device, set).map_err(|_| ())?;
        }
        narf_bus::pci::read_command(cap, device).map_err(|_| ())
    }

    /// The function's firmware DMA configuration (Linux
    /// `dma_alloc_coherent`'s `struct device` facts).
    pub fn dma_device(device: &BusDevice) -> Result<narf_io::DmaDevice, ()> {
        narf_bus::dma::configure(device).map_err(|_| ())
    }
}

/// The function's IOMMU stop proof (Linux `pci_dev_reset_iommu_*`).
pub mod iommu {
    use narf_bus::BusDevice;
    pub use narf_io::iommu::DmaBlock;

    /// IOMMU requester ID of `device`; `narf_bus::dma::configure` attaches
    /// only PCI segment 0 functions to a default domain.
    fn bdf(device: &BusDevice) -> Option<narf_io::iommu::Bdf> {
        match device.kind {
            narf_bus::BusKind::Pcie { addr, .. } if addr.segment == 0 => Some(
                narf_io::iommu::Bdf::new(addr.bus, addr.device, addr.function),
            ),
            _ => None,
        }
    }

    fn per_domain() -> bool {
        narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain
    }

    /// Block the function's DMA at its IOMMU. Outside `PerDomain` this is
    /// `Untranslated` and touches no hardware. `Err(true)`: the function has
    /// no requester ID; `Err(false)`: the detach timed out.
    pub fn block(device: &BusDevice) -> Result<DmaBlock, bool> {
        if !per_domain() {
            return Ok(DmaBlock::Untranslated);
        }
        let bdf = bdf(device).ok_or(true)?;
        narf_io::iommu::block_device_dma(bdf).map_err(|_| false)
    }

    /// Re-attach a function blocked by an earlier stop to its retained
    /// default domain. A no-op outside `PerDomain` and when not blocked.
    /// `Err(true)`: no requester ID; `Err(false)`: the attach was refused.
    pub fn restore(device: &BusDevice) -> Result<(), bool> {
        if !per_domain() {
            return Ok(());
        }
        let bdf = bdf(device).ok_or(true)?;
        if !narf_io::iommu::device_dma_blocked(bdf) {
            return Ok(());
        }
        narf_io::iommu::restore_device_dma(bdf).map_err(|_| false)
    }

    /// Whether the function's DMA is currently blocked.
    pub fn blocked(device: &BusDevice) -> bool {
        bdf(device).is_some_and(narf_io::iommu::device_dma_blocked)
    }
}

/// System sleep states.
pub mod power {
    pub use narf_power::system_pm::SystemSleepState;
}

/// The regulatory policy the radio is programmed from.
pub mod reg_db {
    pub use narf_wireless::reg::db::{ensure_domain, get_domain, snapshot};
}

/// Native AP / radio control authorities.
pub mod ap_control {
    pub use narf_wireless::ap_control::*;
}
