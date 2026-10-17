//! ath11k PCI probe.
//!
//! Stage-0/1 scope:
//!   - PCI device-id match table (one entry per chip family).
//!   - BAR0 MMIO mapping (ath11k uses BAR0 only — 2 MiB on
//!     QCA6390, 4 MiB on QCN9074 / WCN6855).
//!   - SoC global reset prologue (per Linux's
//!     `ath11k_pci_soc_global_reset`).
//!   - LTSSM enable + PCIe hot-reset clear (per
//!     `ath11k_pci_enable_ltssm`).
//!   - hw_rev resolution (TCSR major/minor + WCN6855 sub-version).
//!
//! Then power-up (Linux `ath11k_pci_power_up` short of MHI start):
//! MSI vectors (32, else 1), `sw_reset(power_on)`, ASPM off, MSI on.
//!
//! Not yet: MHI host + firmware boot, QMI, CE/HTC/WMI, DP. Until
//! those land the device registers no network interface — a
//! `wlan%d` with a made-up MAC that "associates" without touching
//! the radio would only mislead userspace.
//!
//! Linux references (BSD-3 / dual GPL):
//! - `drivers/net/wireless/ath/ath11k/pci.c::ath11k_pci_probe`
//!   (v6.6 ~L985..L1180).
//! - `drivers/net/wireless/ath/ath11k/pci.c::ath11k_pci_soc_global_reset`,
//!   `ath11k_pci_enable_ltssm` (~L193..L350).
//! - `drivers/net/wireless/ath/ath11k/pcic.h`,
//!   `drivers/net/wireless/ath/ath11k/pci.h` — register offsets.

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::diag::{self, WifiStage};

use super::hw::{
    self, name_for, refine_hw_rev, ChipInfo, HwParams, HwRev, ALL_DEV_IDS, MSI_CONFIG_ONE,
    QCOM_VENDOR,
};
use super::power::{self, ChipIo, PowerUpReport};

/// Failing-step codes latched into `narf_memory::diag` (shown on the
/// framebuffer status panel as `wifi: <stage> FAILED step=N`).
pub mod step {
    pub const BAR0_MAP: u32 = 1;
    pub const LINK_DOWN: u32 = 2;
    pub const UNSUPPORTED_SOC: u32 = 3;
    pub const NO_HW_PARAMS: u32 = 4;
    pub const MSI_UNAVAILABLE: u32 = 5;
}

/// Errors raised by the baseline probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed.
    Bar0MapFailed,
    /// SoC version register read back 0xFFFFFFFF — the chip is gone
    /// or the link is down.
    LinkDown,
    /// The TCSR version names a stepping Linux's `ath11k_pci_probe`
    /// rejects (`unsupported_*_soc`).
    UnsupportedSoc { major: u32, minor: u32 },
    /// Neither the per-chip vector count nor a single MSI vector
    /// could be set up (Linux `ath11k_pci_alloc_msi` -EINVAL).
    MsiUnavailable,
}

impl ProbeError {
    /// `(step, detail)` for `diag::latch_wifi_error`.
    fn diag_code(self) -> (u32, u32) {
        match self {
            ProbeError::Bar0MapFailed => (step::BAR0_MAP, 0),
            ProbeError::LinkDown => (step::LINK_DOWN, 0xffff_ffff),
            ProbeError::UnsupportedSoc { major, minor } => {
                (step::UNSUPPORTED_SOC, (major << 8) | minor)
            }
            ProbeError::MsiUnavailable => (step::MSI_UNAVAILABLE, 0),
        }
    }
}

/// MSI vectors granted to the chip. The chip itself is told
/// `addr` + `ep_base_data + base_vector` per user (MHI, CE, DP) in
/// later bring-up phases, so these must match what was programmed.
#[derive(Debug)]
pub struct MsiState {
    pub bus_cfg: narf_bus::msi::MsiConfig,
    /// Per-user layout — the chip's table, or `MSI_CONFIG_ONE`.
    pub config: &'static hw::MsiConfig,
    /// First IDT vector; vectors are `base_irq..base_irq + n_vectors`.
    pub base_irq: u8,
    pub n_vectors: u8,
    /// Programmed Message Address.
    pub addr: u64,
    /// Programmed Message Data (Linux `msi.ep_base_data`).
    pub ep_base_data: u32,
}

/// One bound ath11k device. Holds the BAR0 mapping + the hw_rev
/// derived from the TCSR version registers.
pub struct Ath11kDevice {
    pub mmio_bar0: MmioRegion,
    pub chip: ChipInfo,
    pub hw_rev: HwRev,
    /// PCI device id we matched on.
    pub device_id: u16,
    pub params: HwParams,
    pub msi: MsiState,
    /// Link Control before ASPM was disabled for firmware download
    /// (Linux `ab_pci->link_ctl`); restored once firmware is up.
    pub saved_link_ctl: Option<u16>,
    pub power: PowerUpReport,
}

/// The device's BAR0 as a [`ChipIo`].
#[derive(Debug)]
pub struct Bar0Io<'a>(pub &'a MmioRegion);

impl ChipIo for Bar0Io<'_> {
    fn read32(&self, offset: u32) -> u32 {
        // SAFETY: Bar0Io wraps the driver-owned live BAR0 mapping;
        // offsets come from Linux's register tables.
        unsafe { read32(self.0, offset) }
    }
    fn write32(&self, offset: u32, value: u32) {
        // SAFETY: as `read32`.
        unsafe { write32(self.0, offset, value) }
    }
    fn delay_ms(&self, ms: u32) {
        let deadline = narf_time::Deadline::after_ms(ms as u64);
        narf_scheduler::responsive_spin_until(
            || deadline.expired(),
            narf_time::Deadline::after_ms(ms as u64 + 1),
        );
    }
    fn restore_window(&self) {
        // SAFETY: as `read32`.
        unsafe { restore_window(self.0) }
    }
}

/// MSI deliveries seen, any vector. Nothing consumes them until the
/// MHI host lands; the count shows the chip can reach the host.
pub static MSI_FIRES: AtomicU64 = AtomicU64::new(0);

fn msi_irq(_cookie: u64) -> narf_interrupts::IrqStatus {
    MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    narf_interrupts::IrqStatus::Handled
}

impl core::fmt::Debug for Ath11kDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath11kDevice")
            .field("display_name", &self.chip.display_name)
            .field("device_id", &self.device_id)
            .field("hw_rev", &self.hw_rev)
            .finish_non_exhaustive()
    }
}

/// Single-instance live device — most laptops ship one ath11k
/// part.
static CONTROLLER: IrqSafeSpinLock<Option<Ath11kDevice>> = IrqSafeSpinLock::new(None);

/// Register every supported PCI device id with the bus driver
/// match table. Mirrors the shape of Linux's
/// `ath11k_pci_id_table`.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: QCOM_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Probe entry called by `narf-bus::driver_match` when one of our
/// vendor/device pairs surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use core::fmt::Write as _;

    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    let chip = match hw::chip_for_pci_id(device.id.vendor, device.id.device) {
        Some(c) => c,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Enable MEM_SPACE + BUS_MASTER. The MHI controller will issue
    // DMA from inside the chip once running, so BUS_MASTER must be
    // set before BAR mapping completes.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    let result = unsafe { bring_up(&device, &cap, chip) };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            let (code, detail) = e.diag_code();
            diag::latch_wifi_error(code, detail);
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {} ({:04x}:{:04x}) bring-up failed: {:?}",
                chip.display_name,
                chip.vid,
                chip.did,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: probed {} ({:04x}:{:04x}) hw_rev={} fw=ath11k/{}",
        chip.display_name,
        chip.vid,
        chip.did,
        dev.hw_rev.name(),
        dev.params.fw_dir,
    );
    let p = &dev.power;
    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: powered up: msi {}x@{} data={:#x} ltssm={:#x} hot_rst={:#x} \
         reset_cause={:#x} mhistatus={:#x} aspm_saved={:?}",
        dev.msi.n_vectors,
        dev.msi.base_irq,
        dev.msi.ep_base_data,
        p.ltssm,
        p.hot_rst,
        p.reset_cause,
        p.mhistatus,
        dev.saved_link_ctl,
    );
    // Linux only warns on these and carries on.
    if p.ltssm != power::PARM_LTSSM_VALUE {
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: warning: LTSSM did not settle ({:#x})",
            p.ltssm
        );
    }
    if p.link_down_after_reset {
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: warning: link down error during global reset"
        );
    }
    if let Some(reg) = p.l1ss_failed_reg {
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: warning: failed to set pcie link register {:#010x}",
            reg
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(dev.device_id)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(QCOM_VENDOR),
        pci_did: Some(dev.device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

/// Bring the chip up: map BAR0, resolve `hw_rev` from the TCSR
/// version registers, allocate MSI, then run Linux's power-up
/// sequence short of starting MHI.
///
/// # Safety
/// Caller owns the device's BARs and cfg space exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    chip: ChipInfo,
) -> Result<Ath11kDevice, ProbeError> {
    // SAFETY: `bring_up`'s contract is that the caller owns the device's BARs
    // exclusively — exactly the precondition `map_bar` requires.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // SAFETY: BAR0 mapped + owned; TCSR_SOC_HW_VERSION is a readable
    // chip register.
    let version = unsafe { read32(&mmio_bar0, hw::TCSR_SOC_HW_VERSION) };
    if version == 0xFFFF_FFFF {
        return Err(ProbeError::LinkDown);
    }

    let major =
        (version & hw::TCSR_SOC_HW_VERSION_MAJOR_MASK) >> hw::TCSR_SOC_HW_VERSION_MAJOR_SHIFT;
    let minor = version & hw::TCSR_SOC_HW_VERSION_MINOR_MASK;
    let sub_version = if hw::needs_sub_version(chip.did, major, minor) {
        // SAFETY: BAR0 mapped + owned; TCSR_SOC_HW_SUB_VER is readable
        // (Linux reads it at the same point in `ath11k_pci_probe`).
        unsafe { read32(&mmio_bar0, hw::TCSR_SOC_HW_SUB_VER) }
    } else {
        0
    };
    let hw_rev = refine_hw_rev(chip.did, major, minor, sub_version);
    let params = hw_rev
        .params()
        .ok_or(ProbeError::UnsupportedSoc { major, minor })?;
    diag::set_wifi_stage(WifiStage::Probe);

    // SAFETY: caller owns cfg space exclusively.
    let msi = unsafe { alloc_msi(device, cap, params.msi) }?;

    // ── Linux `ath11k_pci_power_up`, minus `ath11k_mhi_start` ──
    *WINDOW.lock() = 0; // `ab_pci->register_window = 0`
    let report = power::sw_reset(&Bar0Io(&mmio_bar0), true, params.fix_l1ss.as_ref());
    // "Disable ASPM during firmware download due to problems
    // switching to AMSS state."
    let saved_link_ctl = narf_bus::pci_express::clear_and_set_link_control(
        cap,
        device,
        narf_bus::pci_express::LNKCTL_ASPMC,
        0,
    )
    .ok();
    // SAFETY: caller owns cfg space exclusively.
    unsafe { narf_bus::msi::enable(&msi.bus_cfg) }.map_err(|_| ProbeError::MsiUnavailable)?;
    diag::set_wifi_stage(WifiStage::PowerUp);

    Ok(Ath11kDevice {
        mmio_bar0,
        chip,
        hw_rev,
        device_id: chip.did,
        params,
        msi,
        saved_link_ctl,
        power: report,
    })
}

/// Linux `ath11k_pci_alloc_msi`: the chip's full vector count, else
/// one shared vector with `MSI_CONFIG_ONE`. Programs the message and
/// installs the handler, then leaves MSI *disabled* — power-up
/// enables it.
///
/// # Safety
/// Caller owns `device`'s cfg space exclusively.
unsafe fn alloc_msi(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    want: &'static hw::MsiConfig,
) -> Result<MsiState, ProbeError> {
    // Multi-message MSI needs a block aligned to its size.
    let attempt = |config: &'static hw::MsiConfig| -> Option<MsiState> {
        let n = config.total_vectors as u8;
        let mut bus_cfg = narf_bus::msi::enable_msi(cap, device, n as u16).ok()?;
        if bus_cfg.vectors_enabled() != n as u16 {
            return None;
        }
        let base_irq = narf_interrupts::vector::alloc_block_aligned(n, n).ok()?;
        // SAFETY: caller owns cfg space exclusively; `base_irq..+n`
        // was just reserved for this device.
        let addr = match unsafe { narf_bus::msi::program_msi(&mut bus_cfg, 0, base_irq) } {
            Ok(a) => a,
            Err(_) => {
                for i in 0..n {
                    let _ = narf_interrupts::vector::free(base_irq + i);
                }
                return None;
            }
        };
        Some(MsiState {
            bus_cfg,
            config,
            base_irq,
            n_vectors: n,
            addr,
            ep_base_data: base_irq as u32,
        })
    };
    let state = attempt(want)
        .or_else(|| attempt(&MSI_CONFIG_ONE))
        .ok_or(ProbeError::MsiUnavailable)?;
    for i in 0..state.n_vectors {
        narf_interrupts::install_handler_named(state.base_irq + i, "ath11k", i as u64, msi_irq);
    }
    // SAFETY: caller owns cfg space exclusively.
    unsafe { narf_bus::msi::disable(&state.bus_cfg) }.map_err(|_| ProbeError::MsiUnavailable)?;
    Ok(state)
}

/// Read a chip register. Offsets below `ATH11K_PCI_WINDOW_START`
/// sit directly in BAR0; higher ones go through the sliding window.
/// Mirrors Linux `pcic.c::__ath11k_pcic_read32` (dynamic-window
/// chips: QCA6390 / WCN6855).
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// readable chip register.
pub unsafe fn read32(mmio: &MmioRegion, offset: u32) -> u32 {
    if offset < hw::ATH11K_PCI_WINDOW_START {
        // SAFETY: caller-asserted BAR0 mapping; offset is inside BAR0.
        unsafe { mmio.read32(offset as u64) }
    } else {
        // SAFETY: caller-asserted BAR0 mapping + register.
        unsafe { read_via_window(mmio, offset) }
    }
}

/// Write a chip register; direct/window split as in [`read32`].
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// writable chip register.
pub unsafe fn write32(mmio: &MmioRegion, offset: u32, value: u32) {
    if offset < hw::ATH11K_PCI_WINDOW_START {
        // SAFETY: caller-asserted BAR0 mapping; offset is inside BAR0.
        unsafe { mmio.write32(offset as u64, value) }
    } else {
        // SAFETY: caller-asserted BAR0 mapping + register.
        unsafe { write_via_window(mmio, offset, value) }
    }
}

/// Serialises window-select + access, and caches the selected
/// window (Linux `ath11k_pci::window_lock` / `register_window`).
/// `u32::MAX` = nothing selected yet.
static WINDOW: IrqSafeSpinLock<u32> = IrqSafeSpinLock::new(u32::MAX);

/// Window number for a chip-register offset —
/// `FIELD_GET(ATH11K_PCI_WINDOW_VALUE_MASK, offset)`.
pub const fn window_of(offset: u32) -> u32 {
    (offset & hw::ATH11K_PCI_WINDOW_VALUE_MASK) >> 19
}

/// Value written to `ATH11K_PCI_WINDOW_REG_ADDRESS` to select the
/// window holding `offset` (Linux `ath11k_pci_select_window`: the
/// window *number*, not the shifted field).
pub const fn window_select_value(offset: u32) -> u32 {
    hw::ATH11K_PCI_WINDOW_ENABLE_BIT | window_of(offset)
}

/// BAR0 byte offset at which `offset` is visible once its window is
/// selected (dynamic-window chips).
pub const fn windowed_bar_offset(offset: u32) -> u32 {
    hw::ATH11K_PCI_WINDOW_START + (offset & hw::ATH11K_PCI_WINDOW_RANGE_MASK)
}

/// # Safety
/// `mmio` must be a valid BAR0 mapping; caller holds `WINDOW`.
unsafe fn select_window(mmio: &MmioRegion, cur: &mut u32, offset: u32) {
    let window = window_of(offset);
    if *cur != window {
        // SAFETY: caller-asserted BAR0 mapping.
        unsafe {
            mmio.write32(
                hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64,
                window_select_value(offset),
            );
            // Posted-write flush, as Linux does, so the select lands
            // before the data access.
            let _ = mmio.read32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64);
        }
        *cur = window;
    }
}

/// Read a register at or above `ATH11K_PCI_WINDOW_START` through the
/// sliding window. Mirrors Linux `ath11k_pci_window_read32`.
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// readable chip register.
pub unsafe fn read_via_window(mmio: &MmioRegion, offset: u32) -> u32 {
    let mut cur = WINDOW.lock();
    // SAFETY: caller-asserted BAR0 mapping; WINDOW held.
    unsafe {
        select_window(mmio, &mut cur, offset);
        mmio.read32(windowed_bar_offset(offset) as u64)
    }
}

/// Write counterpart of [`read_via_window`].
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// writable chip register.
pub unsafe fn write_via_window(mmio: &MmioRegion, offset: u32, value: u32) {
    let mut cur = WINDOW.lock();
    // SAFETY: caller-asserted BAR0 mapping; WINDOW held.
    unsafe {
        select_window(mmio, &mut cur, offset);
        mmio.write32(windowed_bar_offset(offset) as u64, value);
    }
}

/// Re-select the cached window after a global reset cleared the
/// hardware register (Linux `ath11k_pci_restore_window`).
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping.
pub unsafe fn restore_window(mmio: &MmioRegion) {
    let cur = WINDOW.lock();
    let window = if *cur == u32::MAX { 0 } else { *cur };
    // SAFETY: caller-asserted BAR0 mapping.
    unsafe {
        mmio.write32(
            hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64,
            hw::ATH11K_PCI_WINDOW_ENABLE_BIT | window,
        );
        let _ = mmio.read32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64);
    }
}

/// Test helper: `true` if any device is bound.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller (None if unbound).
pub fn with_controller<R>(f: impl FnOnce(&Ath11kDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
    *WINDOW.lock() = u32::MAX;
}
