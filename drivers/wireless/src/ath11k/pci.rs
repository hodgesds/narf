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
//! Then power-up (Linux `ath11k_pci_power_up`): MSI vectors (32,
//! else 1), `sw_reset(power_on)`, ASPM off, MSI on, and
//! `ath11k_mhi_start` — run by a spawned task ([`mhi_task`]) because
//! the firmware download and MHI state machine take seconds: the MHI
//! host ([`super::mhi_host`]) loads `amss.bin` over BHI/BHIe, follows
//! the device to mission mode and starts the IPCR channels 20/21.
//!
//! The same task then runs the WLFW QMI handshake over QRTR
//! ([`super::wlfw`]) to FW_READY and hands the session to
//! [`super::core::pci_start`] (QMI firmware start, CE, HTC, WMI to
//! READY, the data path), which hands the running device to
//! [`super::runtime::start_pci`] (mac layer → `wlan%d`,
//! [`super::iface`]). Everything after probe runs in that spawned task;
//! a failure latches its step and leaves the rest of the kernel booting.
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

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::diag::{self, WifiStage};

use super::fw::{FwApi, ATH11K_FW_API2_FILE};
use super::hw::{
    self, name_for, refine_hw_rev, ChipInfo, HwParams, HwRev, ALL_DEV_IDS, MSI_CONFIG_ONE,
    QCOM_VENDOR,
};
use super::mhi::{self, ATH11K_AMSS_FILE};
use super::mhi_host::{
    self, ControllerParams, HifPower, MhiBus, MhiController, MhiError, MhiNotify,
};
use super::power::{self, ChipIo, PowerUpReport};
use super::wlfw::{self, WlfwConfig};

/// Failing-step codes latched into `narf_memory::diag` (shown on the
/// framebuffer status panel as `wifi: <stage> FAILED step=N`).
pub mod step {
    pub const BAR0_MAP: u32 = 1;
    pub const LINK_DOWN: u32 = 2;
    pub const UNSUPPORTED_SOC: u32 = 3;
    pub const NO_HW_PARAMS: u32 = 4;
    pub const MSI_UNAVAILABLE: u32 = 5;
    pub const SOFTWARE_UNSUPPORTED: u32 = 6;
    pub const PCI_CONFIG: u32 = 7;
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
    /// Silicon is recognized, but its complete HAL/core/DP profile has
    /// not been implemented. It must never reach MHI firmware activation.
    UnsupportedRuntime { hw_rev: HwRev },
    /// PCI command access failed while preparing the owned function.
    PciConfiguration,
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
            ProbeError::UnsupportedRuntime { hw_rev } => {
                (step::SOFTWARE_UNSUPPORTED, hw_rev as u32)
            }
            ProbeError::PciConfiguration => (step::PCI_CONFIG, 0),
        }
    }
}

/// A PCI ID and firmware directory alone are not a runtime implementation.
/// Keep probe admission tied to the profiles the live core and RX/TX path
/// actually use, before any MSI allocation, reset or DMA activation.
pub(super) fn validate_runtime_profile(hw_rev: HwRev) -> Result<(), ProbeError> {
    let complete = hw_rev.params().is_some_and(|params| {
        params.regs.is_some()
            && super::core::CoreConfig::for_hw(&params).is_some()
            && super::dp_ring::DpHwParams::for_rev(hw_rev).is_some()
            && mhi::config_for(hw_rev).is_some()
    });
    if complete {
        Ok(())
    } else {
        Err(ProbeError::UnsupportedRuntime { hw_rev })
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

/// MSI deliveries seen, any vector — the count shows the chip can
/// reach the host.
pub static MSI_FIRES: AtomicU64 = AtomicU64::new(0);

/// Vectors not yet claimed by a subsystem (CE / WAKE / DP until those
/// phases land).
fn msi_irq(_cookie: u64) -> narf_interrupts::IrqStatus {
    MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    narf_interrupts::IrqStatus::Handled
}

/// `mhi_cntrl->irq[]` indexes that fired and the MHI task has not
/// consumed yet (bit `i` = `irq[i]`: 0 = BHI / intvec, 1–2 = event
/// rings).
static MHI_IRQ_PENDING: AtomicU32 = AtomicU32::new(0);
/// The MHI task parked in [`MhiIrqWait`].
static MHI_WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);

/// Handler on the MHI vectors (Linux `mhi_intvec_handler` /
/// `mhi_irq_handler` top halves): note which `irq[]` entries fired and
/// wake the MHI task, which does the work. `cookie` is the bitmask of
/// `irq[]` indexes this vector carries (all three when MSI fell back
/// to one shared vector).
fn mhi_msi_irq(cookie: u64) -> narf_interrupts::IrqStatus {
    MSI_FIRES.fetch_add(1, Ordering::Relaxed);
    MHI_IRQ_PENDING.fetch_or(cookie as u32, Ordering::AcqRel);
    if let Some(w) = MHI_WAKER.lock().take() {
        w.wake();
    }
    narf_interrupts::IrqStatus::Handled
}

/// `ath11k_mhi_get_msi`: `(irq[] count, IDT vector of irq[0], one
/// vector per entry?)` from the "MHI" user assignment.
fn mhi_vectors(msi: &MsiState) -> Option<(u32, u8, bool)> {
    let (num, _user_base_data, base_vector) =
        msi.config.user_assignment("MHI", msi.ep_base_data)?;
    let multi = msi.n_vectors > 1;
    Some((num, msi.base_irq + base_vector as u8, multi))
}

/// Handler cookie for IDT vector `base_irq + i`: the bitmask of MHI
/// `irq[]` entries it carries, or `None` for a non-MHI vector. With one
/// vector per entry `irq[k]` = `base_vector + k`; with the shared
/// single-MSI fallback every entry is `base_vector`.
pub fn mhi_vector_cookie(
    config: &hw::MsiConfig,
    ep_base_data: u32,
    n_vectors: u8,
    i: u8,
) -> Option<u64> {
    let (num, _, base_vector) = config.user_assignment("MHI", ep_base_data)?;
    if n_vectors > 1 {
        let k = (i as u32).checked_sub(base_vector)?;
        (k < num).then_some(1u64 << k)
    } else {
        (i as u32 == base_vector).then_some((1u64 << num) - 1)
    }
}

/// Tear down the CPU-vector half of a partially constructed MSI setup.
///
/// `enable_msi` only discovers the capability and `program_msi` writes an
/// address/data pair; delivery stays disabled until power-up.  The IDT
/// vectors and their dispatch entries are nevertheless live as soon as
/// [`alloc_msi`] installs them, so every later probe error must reclaim them
/// before another driver can bind the function.
pub(super) fn teardown_msi_vectors(
    config: &hw::MsiConfig,
    ep_base_data: u32,
    n_vectors: u8,
    base_irq: u8,
) {
    for i in 0..n_vectors {
        let vector = base_irq + i;
        // Stop delivery before touching the handler chain.  An interrupt
        // already in flight is then drained before this vector is returned
        // to the allocator.
        narf_interrupts::disable_irq(vector);
        match mhi_vector_cookie(config, ep_base_data, n_vectors, i) {
            Some(cookie) => {
                let _ = narf_interrupts::remove_handler(vector, "ath11k-mhi", cookie);
            }
            None => {
                let _ = narf_interrupts::remove_handler(vector, "ath11k", i as u64);
            }
        }
        narf_interrupts::dispatch::clear_all_wakers(vector);
        narf_interrupts::synchronize_irq(vector);
        let _ = narf_interrupts::vector::free(vector);
    }
}

/// Keep a vector reserved when MSI delivery cannot be proven disabled.
///
/// Reusing a vector that a still-live PCI function can target is worse than
/// leaking it: a later driver could receive the old device's interrupt.  The
/// dispatch mask prevents it from running any handler while this function is
/// left quarantined for the rest of the boot.
fn quarantine_msi_vectors(n_vectors: u8, base_irq: u8) {
    for i in 0..n_vectors {
        let vector = base_irq + i;
        narf_interrupts::disable_irq(vector);
        narf_interrupts::dispatch::clear_all_wakers(vector);
        narf_interrupts::synchronize_irq(vector);
    }
}

/// Disable MSI delivery and return the interrupt resources owned by a failed
/// ath11k probe.  This is deliberately usable before the controller has been
/// published: no MHI DMA buffers exist yet, but the IRQ plumbing does.
fn teardown_msi(state: &MsiState) {
    // SAFETY: the caller still owns this function's cfg space.  If the cfg
    // write fails (for example, a surprise-removed function), do not recycle
    // its vector: its MSI source cannot be proven quiesced.
    if unsafe { narf_bus::msi::disable(&state.bus_cfg) }.is_ok() {
        teardown_msi_vectors(
            state.config,
            state.ep_base_data,
            state.n_vectors,
            state.base_irq,
        );
    } else {
        quarantine_msi_vectors(state.n_vectors, state.base_irq);
    }
}

/// Resolves when an MHI vector fires or the slice ends.
struct MhiIrqWait {
    sleep: narf_time::SleepUntil,
}

impl Future for MhiIrqWait {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if MHI_IRQ_PENDING.load(Ordering::Acquire) != 0 {
            return Poll::Ready(());
        }
        *MHI_WAKER.lock() = Some(cx.waker().clone());
        // Re-check after publishing the waker: an IRQ between the two
        // loads either sees the waker or left the bit for us.
        if MHI_IRQ_PENDING.load(Ordering::Acquire) != 0 {
            return Poll::Ready(());
        }
        Pin::new(&mut self.sleep).poll(cx)
    }
}

/// The MHI host's view of the chip: direct BAR0 (Linux
/// `ath11k_mhi_op_read_reg` is a plain `readl(regs + offset)`, no
/// window), the MHI vectors, time and entropy.
#[derive(Debug)]
pub struct Bar0Mhi {
    mmio: MmioRegion,
}

impl Bar0Mhi {
    fn in_bar(&self, offset: u32) -> bool {
        offset as u64 + 4 <= self.mmio.len && offset % 4 == 0
    }
}

impl MhiBus for Bar0Mhi {
    fn read32(&self, offset: u32) -> u32 {
        if !self.in_bar(offset) {
            return u32::MAX;
        }
        // SAFETY: `mmio` is the driver-owned live BAR0 mapping and the
        // access is inside it (checked above).
        unsafe { self.mmio.read32(offset as u64) }
    }
    fn write32(&self, offset: u32, value: u32) {
        if !self.in_bar(offset) {
            return;
        }
        // SAFETY: as `read32`.
        unsafe { self.mmio.write32(offset as u64, value) }
    }
    fn take_irqs(&self) -> u32 {
        MHI_IRQ_PENDING.swap(0, Ordering::AcqRel)
    }
    fn irqs_pending(&self) -> bool {
        MHI_IRQ_PENDING.load(Ordering::Acquire) != 0
    }
    fn hif_power(&self, step: HifPower) {
        use core::fmt::Write as _;
        let io = Bar0Io(&self.mmio);
        match step {
            // ath11k_pci_power_down: "restore aspm in case firmware
            // bootup fails", force wake, MSI off (then ath11k_mhi_stop).
            HifPower::Down => {
                pci_aspm_restore();
                power::force_wake(&io);
                msi_set(false);
            }
            // clear_bit(DEVICE_INIT_DONE) + ath11k_pci_sw_reset(ab, false).
            HifPower::Reset => {
                let _ = power::sw_reset(&io, false, None);
            }
            // ath11k_pci_power_up up to ath11k_mhi_start.
            HifPower::Up => {
                *WINDOW.lock() = 0;
                let l1ss = with_controller(|d| d.params.fix_l1ss).flatten();
                let report = power::sw_reset(&io, true, l1ss.as_ref());
                if let Some(reg) = report.l1ss_failed_reg {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  ath11k: warning: failed to set pcie link register {:#010x}",
                        reg
                    );
                }
                pci_aspm_disable();
                msi_set(true);
            }
        }
    }
    fn wait_irq(&self, ms: u32) -> impl Future<Output = ()> + Send {
        MhiIrqWait {
            sleep: narf_time::SleepUntil::new(
                narf_time::Deadline::after_ms(ms as u64).as_instant(),
            ),
        }
    }
    fn sleep(&self, ms: u32) -> impl Future<Output = ()> + Send {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms as u64).as_instant())
    }
    fn now_ms(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
    fn random_nonzero(&self, max: u32) -> u32 {
        let mut b = [0u8; 4];
        narf_crypto::fill_random_bytes(&mut b);
        let v = u32::from_le_bytes(b) & max;
        if v == 0 {
            1
        } else {
            v
        }
    }
    fn notify(&self, ev: MhiNotify) {
        use core::fmt::Write as _;
        match ev {
            MhiNotify::FirstM0 => diag::set_wifi_stage(WifiStage::Transport),
            MhiNotify::EeMissionMode => diag::set_wifi_stage(WifiStage::FwBoot),
            _ => {}
        }
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: notify status reason {:?}",
            ev
        );
    }
    fn log(&self, args: core::fmt::Arguments<'_>) {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "  ath11k: {}", args);
    }
}

/// `true` once MHI reached mission mode and IPCR is running.
static MHI_UP: AtomicBool = AtomicBool::new(false);

/// `true` once MHI reached mission mode and IPCR is running.
pub fn mhi_ready() -> bool {
    MHI_UP.load(Ordering::Acquire)
}

/// The WLFW session over the running MHI controller.
pub type Wlfw = wlfw::Wlfw<MhiController<Bar0Mhi>, wlfw::NarfFirmware, wlfw::Dma32>;

/// What `ath11k_pci_aspm_disable` / `_restore` need: the function, the
/// Link Control saved when ASPM was disabled (`ab_pci->link_ctl`),
/// `ATH11K_PCI_ASPM_RESTORE`, and whether more than one MSI vector was
/// granted (`ATH11K_FLAG_MULTI_MSI_VECTORS`).
struct AspmRestore {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    link_ctl: u16,
    multi_msi: bool,
    /// `ATH11K_PCI_ASPM_RESTORE`.
    restore: bool,
}

static ASPM_RESTORE: IrqSafeSpinLock<Option<AspmRestore>> = IrqSafeSpinLock::new(None);

/// `ath11k_pci_aspm_restore`: if `ATH11K_PCI_ASPM_RESTORE` was set
/// (`test_and_clear_bit`), put the saved ASPM bits back.
fn pci_aspm_restore() {
    use core::fmt::Write as _;
    let Some(mut a) = ASPM_RESTORE.lock().take() else {
        return;
    };
    if a.restore {
        a.restore = false;
        let lnkctl = narf_bus::pci_express::LNKCTL_ASPMC;
        let r = narf_bus::pci_express::clear_and_set_link_control(
            &a.cap,
            &a.device,
            lnkctl,
            a.link_ctl & lnkctl,
        );
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: ASPM restored (link_ctl {:#06x}): {}",
            a.link_ctl,
            if r.is_ok() { "ok" } else { "failed" }
        );
    }
    *ASPM_RESTORE.lock() = Some(a);
}

/// `ath11k_pci_aspm_disable`: save Link Control, clear L0s / L1, set
/// `ATH11K_PCI_ASPM_RESTORE`.
fn pci_aspm_disable() {
    let Some(mut a) = ASPM_RESTORE.lock().take() else {
        return;
    };
    if let Ok(cur) = narf_bus::pci_express::clear_and_set_link_control(
        &a.cap,
        &a.device,
        narf_bus::pci_express::LNKCTL_ASPMC,
        0,
    ) {
        a.link_ctl = cur;
        a.restore = true;
    }
    *ASPM_RESTORE.lock() = Some(a);
}

/// `ath11k_pci_msi_enable` / `_disable` (`ath11k_pci_msi_config`).
fn msi_set(enable: bool) {
    with_controller(|d| {
        // SAFETY: the bound device's cfg space belongs to this driver
        // (probe claimed it); the MSI capability was set up by
        // `alloc_msi` and is only toggled here and at power-up.
        let r = unsafe {
            if enable {
                narf_bus::msi::enable(&d.msi.bus_cfg)
            } else {
                narf_bus::msi::disable(&d.msi.bus_cfg)
            }
        };
        let _ = r;
    });
}

/// `ath11k_pci_start`'s ASPM half: `ath11k_pci_aspm_restore`, except
/// with a single MSI vector, where Linux leaves ASPM off ("MHI register
/// reading in M2 causes system hang").
pub fn aspm_restore() {
    use core::fmt::Write as _;
    let multi = ASPM_RESTORE.lock().as_ref().map(|a| a.multi_msi);
    match multi {
        None => {}
        Some(false) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: leaving PCI ASPM disabled to avoid MHI M2 problems"
            );
        }
        Some(true) => pci_aspm_restore(),
    }
}

/// Firmware lookup retries: probe can run before the rootfs firmware
/// scan registers the ath11k blobs (spec §8), so keep looking for a
/// while instead of failing like `request_firmware`.
const FW_WAIT_MS: u64 = 60_000;
const FW_RETRY_MS: u64 = 500;

/// One `firmware_request_nowarn(ath11k/<fw_dir>/<file>)` (`Err` =
/// positive errno).
fn request_fw(
    auth: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    fw_dir: &str,
    file: &str,
) -> Result<alloc::vec::Vec<u8>, i32> {
    let name = alloc::format!("ath11k/{}/{}", fw_dir, file);
    let cap = narf_firmware::open(&name, auth).map_err(|e| match e {
        narf_firmware::FirmwareError::NotFound => wlfw::ENOENT,
        narf_firmware::FirmwareError::OutOfMemory => wlfw::ENOMEM,
        _ => wlfw::EINVAL,
    })?;
    let view = narf_firmware::view_of(&cap).map_err(|_| wlfw::EINVAL)?;
    Ok(view.bytes.to_vec())
}

/// The MHI image and `ab->fw`: `ath11k_fw_pre_init` (`firmware-2.bin`;
/// `ath11k_core_pre_init` runs it before `ath11k_mhi_register`), then the
/// image `ath11k_mhi_register` picks — the container's AMSS IE when it is
/// non-empty, else `request_firmware(ath11k/<fw_dir>/amss.bin)`. Both are
/// retried together while the store fills (spec §8).
async fn load_firmware(fw_dir: &str) -> Result<(alloc::vec::Vec<u8>, FwApi), MhiError> {
    use core::fmt::Write as _;
    let auth = match narf_firmware::trusted_loader_authority().and_then(|a| a.derive().ok()) {
        Some(a) => a,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: no firmware authority for ath11k/{}",
                fw_dir
            );
            return Err(MhiError::new(
                mhi_host::step::FW_NOT_FOUND,
                1,
                mhi_host::errno::EIO,
            ));
        }
    };
    let start = narf_time::wall::monotonic_ns() / 1_000_000;
    let mut reported = false;
    loop {
        let (api, refused) = FwApi::pre_init(|file| request_fw(&auth, fw_dir, file));
        if let (Some(e), false) = (refused, reported) {
            // ath11k_fw_request_firmware_api_n's ath11k_err; pre_init
            // still succeeds, with api 1.
            reported = true;
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: ath11k/{}/{}: {:?} (-{}), using fw api 1",
                fw_dir,
                ATH11K_FW_API2_FILE,
                e,
                e.errno()
            );
        }
        if let Some(img) = api.amss() {
            // "use MHI firmware file from firmware-N.bin"
            let img = img.to_vec();
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: firmware ath11k/{}/{} (fw api 2: amss {} bytes, m3 {} bytes)",
                fw_dir,
                ATH11K_FW_API2_FILE,
                img.len(),
                api.m3().map_or(0, |m| m.len())
            );
            return Ok((img, api));
        }
        // "use the old separate mhi.bin MHI firmware file"
        match request_fw(&auth, fw_dir, ATH11K_AMSS_FILE) {
            Ok(bytes) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  ath11k: firmware ath11k/{}/{} ({} bytes, fw api {})",
                    fw_dir,
                    ATH11K_AMSS_FILE,
                    bytes.len(),
                    api.api_version
                );
                return Ok((bytes, api));
            }
            Err(e) => {
                let now = narf_time::wall::monotonic_ns() / 1_000_000;
                if now.saturating_sub(start) >= FW_WAIT_MS {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  ath11k: firmware ath11k/{}/{} not found (-{})",
                        fw_dir,
                        ATH11K_AMSS_FILE,
                        e
                    );
                    return Err(MhiError::new(
                        mhi_host::step::FW_NOT_FOUND,
                        3,
                        mhi_host::errno::EIO,
                    ));
                }
            }
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(FW_RETRY_MS).as_instant()).await;
    }
}

/// What [`mhi_task`] needs from the bound device.
#[derive(Copy, Clone, Debug)]
pub struct MhiStart {
    pub mmio: MmioRegion,
    pub hw_rev: HwRev,
    pub fw_dir: &'static str,
    /// `nr_irqs` (the "MHI" MSI user's vector count).
    pub nr_irqs: u32,
    /// `ab->id`: PCI vendor / device / subsystem ids (board names).
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    /// `(domain, bus, slot, function)` — `dev_name()` for caldata.
    pub pci_addr: (u16, u8, u8, u8),
}

/// Linux `ath11k_mhi_register` + `ath11k_mhi_start`
/// (`mhi_prepare_for_power_up` + `mhi_sync_power_up`), then the QRTR
/// MHI client's `mhi_prepare_for_transfer` on IPCR.
async fn mhi_bring_up(s: MhiStart) -> Result<(MhiController<Bar0Mhi>, FwApi), MhiError> {
    use core::fmt::Write as _;
    let cfg = mhi::config_for(s.hw_rev).ok_or(MhiError::new(
        mhi_host::step::BAD_CONFIG,
        0,
        mhi_host::errno::EINVAL,
    ))?;
    let (fw, api) = load_firmware(s.fw_dir).await?;
    let params = ControllerParams::ath11k(s.mmio.len.min(u32::MAX as u64) as u32, s.nr_irqs);
    let mut ctrl = MhiController::new(Bar0Mhi { mmio: s.mmio }, cfg, params)?;
    let result: Result<(), MhiError> = async {
        ctrl.prepare_for_power_up()?;
        let (bhi, bhie) = ctrl.bhi_offsets();
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: mhi: BHI at {:#x}, BHIe at {:#x}, timeout {} ms",
            bhi,
            bhie,
            params.timeout_ms
        );
        ctrl.set_firmware(fw);
        ctrl.sync_power_up().await?;
        ctrl.prepare_for_transfer("IPCR").await
    }
    .await;
    if let Err(e) = result {
        // A failed MHI start can still have live BHIe/context DMA.  Reset the
        // function before this owner drops those allocations.
        abort_mhi_bring_up(&mut ctrl).await;
        return Err(e);
    }
    let st = ctrl.stats;
    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: mhi: mission mode, IPCR ch20/21 started; irqs {:?} events {:?} \
         events-without-msi {} serial {:#x}",
        st.irqs,
        st.events,
        st.events_without_irq,
        ctrl.serial_number()
    );
    if st.events_without_irq != 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: warning: MHI events arrived without MSI; running on polling"
        );
    }
    Ok((ctrl, api))
}

/// Quiesce a failed MHI/WLFW initialisation before its owner is dropped.
///
/// The single physical radio has one MHI task, so an old IRQ bit or waker is
/// never meaningful after that task gives up.  Clear both along with the
/// public readiness state after the controller has reset the device.
async fn abort_mhi_bring_up(ctrl: &mut MhiController<Bar0Mhi>) {
    ctrl.abort_bring_up().await;
    reset_mhi_task_state();
}

/// The firmware lookup and controller construction happen before an
/// [`MhiController`] exists.  They can still fail after PCI power-up enabled
/// MSI and disabled ASPM, so quiesce that PCI half here as well.
fn abort_unowned_mhi_bring_up(s: MhiStart) {
    Bar0Mhi { mmio: s.mmio }.hif_power(HifPower::Down);
    reset_mhi_task_state();
}

fn reset_mhi_task_state() {
    MHI_UP.store(false, Ordering::Release);
    MHI_IRQ_PENDING.store(0, Ordering::Release);
    *MHI_WAKER.lock() = None;
}

/// The MHI bring-up task spawned by probe: MHI to mission mode, then
/// the WLFW handshake to FW_READY.
pub async fn mhi_task(s: MhiStart) {
    use core::fmt::Write as _;
    MHI_UP.store(false, Ordering::Release);
    match mhi_bring_up(s).await {
        Ok((ctrl, api)) => {
            MHI_UP.store(true, Ordering::Release);
            wlfw_bring_up(ctrl, s, api).await;
        }
        Err(e) => {
            // `load_firmware` and `MhiController::new` can fail before an
            // MHI owner exists, while PCI is already powered up.  Repeating
            // this after a controller-owned failure is harmless and keeps
            // the no-owner path equally safe.
            abort_unowned_mhi_bring_up(s);
            diag::latch_wifi_error(e.step, e.detail);
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: MHI bring-up failed: step {} detail {:#x} (-{})",
                e.step,
                e.detail,
                e.errno
            );
        }
    }
}

/// `dev_name()` of a PCI function: `"%04x:%02x:%02x.%d"`.
pub fn pci_dev_name(addr: (u16, u8, u8, u8)) -> alloc::string::String {
    alloc::format!("{:04x}:{:02x}:{:02x}.{}", addr.0, addr.1, addr.2, addr.3)
}

fn wlfw_fail(e: wlfw::WlfwError) {
    use core::fmt::Write as _;
    diag::latch_wifi_error(e.step, e.detail);
    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: QMI handshake failed: step {} detail {:#x} (-{})",
        e.step,
        e.detail,
        e.errno
    );
}

/// QRTR + QMI over the running controller: Linux's
/// `ath11k_qmi_init_service` → driver events → FW_READY.
async fn wlfw_bring_up(ctrl: MhiController<Bar0Mhi>, s: MhiStart, api: FwApi) {
    use core::fmt::Write as _;
    diag::set_wifi_stage(WifiStage::Control);
    let Some(fw) = wlfw::NarfFirmware::new() else {
        let mut ctrl = ctrl;
        abort_mhi_bring_up(&mut ctrl).await;
        return wlfw_fail(wlfw::WlfwError::new(
            wlfw::step::NO_FW_AUTHORITY,
            0,
            wlfw::ENOENT,
        ));
    };
    // `ath11k_core_check_smbios`: the type-0xF8 `BDF_<variant>` string
    // from the table the boot-time DMI scan kept (empty = no variant).
    let Some(cfg) = WlfwConfig::pci(
        s.hw_rev,
        s.vendor,
        s.device,
        s.subsystem_vendor,
        s.subsystem_device,
        pci_dev_name(s.pci_addr),
        super::board::check_smbios().bdf_ext,
    ) else {
        let mut ctrl = ctrl;
        abort_mhi_bring_up(&mut ctrl).await;
        return wlfw_fail(wlfw::WlfwError::new(
            wlfw::step::UNSUPPORTED,
            0,
            wlfw::EOPNOTSUPP,
        ));
    };
    let mut w = match wlfw::Wlfw::new(ctrl, fw, wlfw::Dma32, cfg) {
        Ok(w) => w,
        Err(e) => return wlfw_fail(e),
    };
    // ab->fw (ath11k_qmi_m3_load takes the M3 IE from it).
    w.fw_api = api;
    match w.run_to_fw_ready().await {
        Ok(info) => {
            let st = w.client.stats;
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: qmi: FW_READY chip_id {:#x} board_id {:#x} soc_id {:#x} \
                 board {:?} regdb {:?} m3 {:#x}+{} target_mem {} seg (delayed {}) \
                 qrtr rx {} tx {} bad {}",
                info.target.chip_id,
                info.target.board_id,
                info.target.soc_id,
                info.board
                    .as_ref()
                    .map(|b| (&b.name, b.api, b.bdf_type, b.sent)),
                info.regdb_sent,
                info.m3_addr,
                info.m3_size,
                info.target_mem.len(),
                info.mem_delayed_rounds,
                st.frames_rx,
                st.frames_tx,
                st.bad_frames
            );
            // Linux: ath11k_core_qmi_firmware_ready.
            super::core::pci_start(w).await;
        }
        Err(e) => {
            // The QMI owner has handed target-memory DMA to firmware by this
            // point on several failure paths.  Stop MHI before `w` drops it.
            abort_mhi_bring_up(&mut w.client.pipe).await;
            wlfw_fail(e);
        }
    }
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

    let chip = match hw::chip_for_pci_id(device.id.vendor, device.id.device) {
        Some(c) => c,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Quiesce an inherited function before identifying or resetting it.
    // Recognized QCA6390/QCN9074 IDs currently lack a complete runtime
    // profile; reject them before MMIO/MSI setup and never enable DMA.
    let occupied = CONTROLLER.lock().is_some();
    let profile = validate_runtime_profile(chip.default_hw_rev);
    crate::qualcomm_pci::park(&device, &cap, !occupied && profile.is_ok())?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath11k singleton already owns another radio",
        ));
    }
    if let Err(error) = profile {
        let (code, detail) = error.diag_code();
        diag::latch_wifi_error(code, detail);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {}: {:?}",
            chip.display_name,
            error
        );
        return Err(narf_bus::ProbeError::Other(
            "ath11k family runtime is not implemented",
        ));
    }
    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    let result = unsafe { bring_up(&device, &cap, chip) }.and_then(|dev| {
        // The silicon and all software profiles have now been accepted;
        // no firmware DMA was enabled during identification or reset.
        if narf_bus::pci::set_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER).is_err() {
            teardown_msi(&dev.msi);
            if let Some(link_ctl) = dev.saved_link_ctl {
                let _ = narf_bus::pci_express::clear_and_set_link_control(
                    &cap,
                    &device,
                    narf_bus::pci_express::LNKCTL_ASPMC,
                    link_ctl & narf_bus::pci_express::LNKCTL_ASPMC,
                );
            }
            return Err(ProbeError::PciConfiguration);
        }
        Ok(dev)
    });
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            // No controller was published, so no later lifecycle path will
            // revoke the command bits.  In particular, leaving BUS_MASTER
            // set after a rejected probe would let an unbound function DMA.
            let _ = narf_bus::pci::clear_command(
                &cap,
                &device,
                narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
            );
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

    let pci_addr = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => {
            (addr.segment, addr.bus, addr.device, addr.function)
        }
        _ => (0, 0, 0, 0),
    };
    let start = mhi_vectors(&dev.msi).map(|(nr_irqs, _, _)| MhiStart {
        mmio: dev.mmio_bar0,
        hw_rev: dev.hw_rev,
        fw_dir: dev.params.fw_dir,
        nr_irqs,
        vendor: device.id.vendor,
        device: device.id.device,
        subsystem_vendor: device.id.subsystem_vendor,
        subsystem_device: device.id.subsystem_id,
        pci_addr,
    });
    if let Some(link_ctl) = dev.saved_link_ctl {
        *ASPM_RESTORE.lock() = Some(AspmRestore {
            device,
            cap,
            link_ctl,
            multi_msi: dev.msi.n_vectors > 1,
            restore: true,
        });
    }
    *CONTROLLER.lock() = Some(dev);
    match start {
        Some(s) => {
            narf_scheduler::spawn(mhi_task(s));
        }
        None => diag::latch_wifi_error(mhi_host::step::BAD_CONFIG, 0),
    }
    Ok(())
}

/// Bring the chip up: map BAR0, resolve `hw_rev` from the TCSR
/// version registers, allocate MSI, then run Linux's power-up
/// sequence short of starting MHI.
///
/// # Safety
/// Caller owns the device's BARs and cfg space exclusively and has
/// disabled inherited bus mastering before calling.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    chip: ChipInfo,
) -> Result<Ath11kDevice, ProbeError> {
    // SAFETY: `bring_up`'s contract is that the caller owns the device's BARs
    // exclusively — exactly the precondition `map_bar_control` requires.
    let mmio_bar0 = unsafe { map_bar_control(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;
    if mmio_bar0.len < 0x100000 {
        return Err(ProbeError::Bar0MapFailed);
    }

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
    validate_runtime_profile(hw_rev)?;
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
    if unsafe { narf_bus::msi::enable(&msi.bus_cfg) }.is_err() {
        // Keep the PCIe link as we found it before returning an error.  The
        // probe caller clears MEM_SPACE/BUS_MASTER; this path owns the MSI
        // vectors and dispatch handlers created above.
        if let Some(link_ctl) = saved_link_ctl {
            let _ = narf_bus::pci_express::clear_and_set_link_control(
                cap,
                device,
                narf_bus::pci_express::LNKCTL_ASPMC,
                link_ctl & narf_bus::pci_express::LNKCTL_ASPMC,
            );
        }
        teardown_msi(&msi);
        return Err(ProbeError::MsiUnavailable);
    }
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
    // `ath11k_mhi_get_msi`: irq[i] = base_vector (+ i with one vector
    // per entry); everything else keeps the counting handler until its
    // subsystem lands.
    for i in 0..state.n_vectors {
        let v = state.base_irq + i;
        match mhi_vector_cookie(state.config, state.ep_base_data, state.n_vectors, i) {
            Some(cookie) => {
                narf_interrupts::install_handler_named(v, "ath11k-mhi", cookie, mhi_msi_irq)
            }
            None => narf_interrupts::install_handler_named(v, "ath11k", i as u64, msi_irq),
        }
    }
    // SAFETY: caller owns cfg space exclusively.
    if unsafe { narf_bus::msi::disable(&state.bus_cfg) }.is_err() {
        teardown_msi(&state);
        return Err(ProbeError::MsiUnavailable);
    }
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
