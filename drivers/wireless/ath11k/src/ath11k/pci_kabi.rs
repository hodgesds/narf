//! The module build's PCI binding (`ath11k.ko`): the names the shared PCI
//! code in `pci.rs` uses — `MmioRegion`, `NativeIo`, `MsiState`,
//! `Ath11kDevice`, probe and registration, MSI and ASPM control — over the
//! KABI instead of `narf-bus` / `narf-interrupts`.
//!
//! The sequence is the built-in `probe` + `bring_up_current` step for step
//! (Linux `ath11k_pci_probe` up to `ath11k_pci_power_up`): identify, park
//! inherited decode/mastering, map BAR0, read TCSR, resolve `hw_rev`, refuse
//! an unimplemented runtime profile before any MSI or DMA, allocate MSI (the
//! chip's 32-vector block, else one shared vector), `sw_reset(power_on)`,
//! ASPM off, MSI on, then bus mastering — and the MHI task. WCN6855 only:
//! QCA6390 shares the profile but is not registered until it has run.

use super::*;

/// KABI exports the PCI binding calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_register_pci_driver(
            name: *const u8,
            len: usize,
            vendor: u16,
            device: u16,
            probe: usize,
        ) -> i32;
        pub fn narf_pci_prepare_probe(dev: u64) -> i32;
        pub fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
        pub fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
        pub fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32;
        pub fn narf_msi_enable(
            dev: u64,
            want: u16,
            out_count: *mut u16,
            out_base_vector: *mut u16,
            out_addr: *mut u64,
            out_data: *mut u32,
        ) -> i32;
        pub fn narf_msi_set_enabled(dev: u64, enabled: u32) -> i32;
        pub fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

/// PCI command register bits (`PCI_COMMAND_MEMORY` / `_MASTER`).
const CMD_MEM_SPACE: u16 = 0x2;
const CMD_BUS_MASTER: u16 = 0x4;
/// `PCI_EXP_LNKCTL_ASPMC`.
const LNKCTL_ASPMC: u16 = 0x3;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;

/// BAR0 as the shared window helpers see it: a length and 32-bit accessors.
/// The mapping stays in the kernel; every access is a bounds-checked export.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub len: u64,
    bar: u64,
}

impl MmioRegion {
    /// # Safety
    /// `off` names a readable register inside the BAR (the kernel
    /// bounds-checks it as well; an out-of-range read returns all-ones).
    pub unsafe fn read32(&self, off: u64) -> u32 {
        let mut value = u32::MAX;
        // SAFETY: `value` is a live local.
        let _ = unsafe {
            ffi::narf_mmio_read32(crate::ath11k::platform::device(), self.bar, off, &mut value)
        };
        value
    }

    /// # Safety
    /// `off` names a writable register inside the BAR.
    pub unsafe fn write32(&self, off: u64, value: u32) {
        // SAFETY: argument-only call; the kernel bounds-checks `off`.
        let _ = unsafe {
            ffi::narf_mmio_write32(crate::ath11k::platform::device(), self.bar, off, value)
        };
    }
}

/// The bound BAR0 and its window mode (see the built-in `NativeIo`).
#[derive(Copy, Clone, Debug)]
pub struct NativeIo {
    pub(crate) mmio: MmioRegion,
    /// `static_window_map` parts (QCN9074): the register map whose CE range
    /// takes window 2 (UMAC/DP: window 3).
    pub(crate) static_window: Option<&'static super::hw::HalRegs>,
}

impl NativeIo {
    fn static_at(&self, offset: u32, direct: bool) -> Option<u32> {
        if direct || offset < hw::ATH11K_PCI_WINDOW_START {
            return None;
        }
        self.static_window
            .and_then(|r| super::super::qcn9074::static_bar_offset(r, offset))
    }
    fn valid(&self, offset: u32, direct: bool) -> bool {
        let at = if direct || offset < hw::ATH11K_PCI_WINDOW_START {
            offset
        } else if let Some(at) = self.static_at(offset, direct) {
            at
        } else {
            windowed_bar_offset(offset)
        };
        offset & 3 == 0
            && u64::from(at) + 4 <= self.mmio.len
            && (direct || u64::from(hw::ATH11K_PCI_WINDOW_REG_ADDRESS) + 4 <= self.mmio.len)
    }
    pub(crate) fn read(&self, offset: u32, direct: bool) -> u32 {
        if !self.valid(offset, direct) {
            return u32::MAX;
        }
        if let Some(at) = self.static_at(offset, direct) {
            // SAFETY: bound-checked by `valid`.
            return unsafe { self.mmio.read32(u64::from(at)) };
        }
        // SAFETY: full exact-width bound; the windowed helper serialises
        // select/read as one transaction.
        unsafe {
            if direct {
                self.mmio.read32(u64::from(offset))
            } else {
                read32(&self.mmio, offset)
            }
        }
    }
    pub(crate) fn write(&self, offset: u32, value: u32, direct: bool) {
        if !self.valid(offset, direct) {
            return;
        }
        if let Some(at) = self.static_at(offset, direct) {
            // SAFETY: as `read`.
            unsafe { self.mmio.write32(u64::from(at), value) };
            return;
        }
        // SAFETY: as `read`.
        unsafe {
            if direct {
                self.mmio.write32(u64::from(offset), value)
            } else {
                write32(&self.mmio, offset, value)
            }
        }
    }
    pub(crate) fn restore(&self) {
        if !self.valid(hw::ATH11K_PCI_WINDOW_REG_ADDRESS, true) {
            return;
        }
        // SAFETY: selector extent checked; the helper serialises WINDOW.
        unsafe { restore_window(&self.mmio) }
    }
}

/// MSI vectors granted to the chip (see the built-in `MsiState`).
#[derive(Debug)]
pub struct MsiState {
    pub config: &'static hw::MsiConfig,
    pub base_irq: u8,
    pub n_vectors: u8,
    pub addr: u64,
    pub ep_base_data: u32,
}

/// One bound ath11k device (module build).
pub struct Ath11kDevice {
    pub mmio_bar0: MmioRegion,
    pub(crate) native: NativeIo,
    pub chip: ChipInfo,
    pub hw_rev: HwRev,
    pub device_id: u16,
    pub params: HwParams,
    pub msi: MsiState,
    pub saved_link_ctl: Option<u16>,
    pub power: PowerUpReport,
}

/// `ath11k_pci_aspm_*` state: the ASPM field saved when it was cleared.
pub(super) struct AspmRestore {
    pub(super) link_ctl: u16,
    pub(super) multi_msi: bool,
    pub(super) restore: bool,
}

pub(super) static ASPM_RESTORE: IrqSafeSpinLock<Option<AspmRestore>> = IrqSafeSpinLock::new(None);

fn aspm_write(aspmc: u16) -> Option<u16> {
    let mut previous = 0u16;
    // SAFETY: `previous` is a live local.
    (unsafe { ffi::narf_pcie_aspm(crate::ath11k::platform::device(), aspmc, &mut previous) } == 0)
        .then_some(previous)
}

/// `ath11k_pci_aspm_restore`.
pub(super) fn pci_aspm_restore() {
    use core::fmt::Write as _;
    let Some(mut a) = ASPM_RESTORE.lock().take() else {
        return;
    };
    if a.restore {
        a.restore = false;
        let ok = aspm_write(a.link_ctl & LNKCTL_ASPMC).is_some();
        let _ = writeln!(
            crate::ath11k::platform::Console,
            "  ath11k: ASPM restored (link_ctl {:#06x}): {}",
            a.link_ctl,
            if ok { "ok" } else { "failed" }
        );
    }
    *ASPM_RESTORE.lock() = Some(a);
}

/// `ath11k_pci_aspm_disable`.
pub(super) fn pci_aspm_disable() {
    let Some(mut a) = ASPM_RESTORE.lock().take() else {
        return;
    };
    if let Some(previous) = aspm_write(0) {
        a.link_ctl = previous;
        a.restore = true;
    }
    *ASPM_RESTORE.lock() = Some(a);
}

/// `ath11k_pci_msi_enable` / `_disable`.
pub(super) fn msi_set(enable: bool) {
    // SAFETY: argument-only call on the probed device.
    let _ =
        unsafe { ffi::narf_msi_set_enabled(crate::ath11k::platform::device(), u32::from(enable)) };
}

/// Register the WCN6855 PCI id; the kernel calls [`probe_c`] for a match.
pub fn register_pci_driver() {
    use core::fmt::Write as _;
    const NAME: &[u8] = b"ath11k";
    // SAFETY: `NAME` is 'static and `probe_c` is a valid extern "C" fn; the
    // loader unregisters the match before this image is unmapped.
    let rc = unsafe {
        ffi::narf_register_pci_driver(
            NAME.as_ptr(),
            NAME.len(),
            QCOM_VENDOR,
            hw::ATH11K_DEV_WCN6855,
            probe_c as usize,
        )
    };
    if rc != 0 {
        let _ = writeln!(
            crate::ath11k::platform::Console,
            "  ath11k.ko: PCI registration failed ({rc})"
        );
    }
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    let _ = crate::ath11k::platform::EXEC.run();
    0
}

/// The function's identity (`narf_pci_identity`).
struct Identity {
    vendor: u16,
    device: u16,
    subsystem_vendor: u16,
    subsystem_device: u16,
    /// `(segment, bus, slot, function)`.
    pci_addr: (u16, u8, u8, u8),
}

fn identity(dev: u64) -> Option<Identity> {
    let mut record = [0u8; 16];
    // SAFETY: `record` names 16 writable bytes.
    if unsafe { ffi::narf_pci_identity(dev, record.as_mut_ptr(), record.len()) } != 0 {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([record[i], record[i + 1]]);
    let devfn = record[15];
    Some(Identity {
        vendor: u16_at(0),
        device: u16_at(2),
        subsystem_vendor: u16_at(4),
        subsystem_device: u16_at(6),
        pci_addr: (u16_at(12), record[14], devfn >> 3, devfn & 7),
    })
}

/// Linux `ath11k_pci_alloc_msi`: the chip's full vector count, else one
/// shared vector with `MSI_CONFIG_ONE`. The kernel programs the message and
/// leaves delivery off; each vector's task-context callback runs the
/// handlers this installs (and the executor).
fn alloc_msi(dev: u64, want: &'static hw::MsiConfig) -> Result<MsiState, ProbeError> {
    let attempt = |config: &'static hw::MsiConfig| -> Option<MsiState> {
        let n = config.total_vectors as u16;
        let (mut count, mut base, mut addr, mut data) = (0u16, 0u16, 0u64, 0u32);
        // SAFETY: the four outputs are live locals.
        let rc =
            unsafe { ffi::narf_msi_enable(dev, n, &mut count, &mut base, &mut addr, &mut data) };
        // The shared MSI code (and the handler table) keys vectors as `u8`;
        // a block past 255 (possible on aarch64 GICs) is refused, not
        // truncated onto another device's vectors.
        let base_irq = u8::try_from(base).ok()?;
        u8::try_from(u32::from(base) + u32::from(n) - 1).ok()?;
        (rc == 0 && count == n).then_some(MsiState {
            config,
            base_irq,
            n_vectors: n as u8,
            addr,
            ep_base_data: data,
        })
    };
    let state = attempt(want)
        .or_else(|| attempt(&MSI_CONFIG_ONE))
        .ok_or(ProbeError::MsiUnavailable)?;
    for i in 0..state.n_vectors {
        let vector = state.base_irq + i;
        if crate::ath11k::platform::irq::bind_vector(u16::from(vector)) != 0 {
            return Err(ProbeError::MsiUnavailable);
        }
        match mhi_vector_cookie(state.config, state.ep_base_data, state.n_vectors, i) {
            Some(cookie) => crate::ath11k::platform::irq::install_handler_named(
                vector,
                "ath11k-mhi",
                cookie,
                mhi_msi_irq,
            ),
            None => crate::ath11k::platform::irq::install_handler_named(
                vector, "ath11k", i as u64, msi_irq,
            ),
        }
    }
    Ok(state)
}

/// Bring the chip up to the point the MHI task takes over (the built-in
/// `bring_up_current`). Resources it creates are the device context's: a
/// failed probe's teardown releases the BAR, MSI block and DMA.
fn bring_up(dev: u64, chip: ChipInfo) -> Result<Ath11kDevice, ProbeError> {
    // SAFETY: argument-only calls on our probe token.
    let bar = unsafe {
        if ffi::narf_pci_prepare_probe(dev) != 0 || ffi::narf_pci_enable(dev, CMD_MEM_SPACE) != 0 {
            return Err(ProbeError::PciConfiguration);
        }
        ffi::narf_bar_map(dev, 0)
    };
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if bar == 0 || unsafe { ffi::narf_bar_len(dev, bar, &mut len) } != 0 || len < 0x100000 {
        return Err(ProbeError::Bar0MapFailed);
    }
    let mmio_bar0 = MmioRegion { len, bar };
    let mut native = NativeIo {
        mmio: mmio_bar0,
        static_window: None,
    };
    let version = native.read(hw::TCSR_SOC_HW_VERSION, false);
    if version == 0xFFFF_FFFF {
        return Err(ProbeError::LinkDown);
    }
    let major =
        (version & hw::TCSR_SOC_HW_VERSION_MAJOR_MASK) >> hw::TCSR_SOC_HW_VERSION_MAJOR_SHIFT;
    let minor = version & hw::TCSR_SOC_HW_VERSION_MINOR_MASK;
    let sub_version = if hw::needs_sub_version(chip.did, major, minor) {
        native.read(hw::TCSR_SOC_HW_SUB_VER, false)
    } else {
        0
    };
    let hw_rev = refine_hw_rev(chip.did, major, minor, sub_version);
    let params = hw_rev
        .params()
        .ok_or(ProbeError::UnsupportedSoc { major, minor })?;
    validate_runtime_profile(hw_rev)?;
    if params.static_window_map {
        native.static_window = params.regs;
    }
    diag::set_wifi_stage(WifiStage::Probe);

    let msi = alloc_msi(dev, params.msi)?;

    // ── Linux `ath11k_pci_power_up`, minus `ath11k_mhi_start` ──
    *WINDOW.lock() = 0;
    let report = power::sw_reset(&Bar0Io(&native), true, params.fix_l1ss.as_ref());
    // "Disable ASPM during firmware download due to problems switching to
    // AMSS state."
    let saved_link_ctl = aspm_write(0);
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_msi_set_enabled(dev, 1) } != 0 {
        if let Some(link_ctl) = saved_link_ctl {
            let _ = aspm_write(link_ctl & LNKCTL_ASPMC);
        }
        return Err(ProbeError::MsiUnavailable);
    }
    diag::set_wifi_stage(WifiStage::PowerUp);
    Ok(Ath11kDevice {
        mmio_bar0,
        native,
        chip,
        hw_rev,
        device_id: chip.did,
        params,
        msi,
        saved_link_ctl,
        power: report,
    })
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // Every device export after this point takes the bound token
    // (`platform::device`): a second function must not replace it.
    if CONTROLLER.lock().is_some() {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 && CONTROLLER.lock().is_none() {
        crate::ath11k::platform::set_device(0);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    use core::fmt::Write as _;
    crate::ath11k::platform::set_device(dev);
    let Some(Identity {
        vendor,
        device,
        subsystem_vendor,
        subsystem_device,
        pci_addr,
    }) = identity(dev)
    else {
        return ENODEV;
    };
    let Some(chip) = hw::chip_for_pci_id(vendor, device) else {
        return ENODEV;
    };
    if let Err(error) = validate_runtime_profile(chip.default_hw_rev) {
        let (code, detail) = error.diag_code();
        diag::latch_wifi_error(code, detail);
        return ENODEV;
    }
    // Firmware owns target memory and rings from MHI start on; a teardown
    // that cannot prove the device stopped must not free them.
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    let dev_state = match bring_up(dev, chip) {
        Ok(d) => d,
        Err(e) => {
            let (code, detail) = e.diag_code();
            diag::latch_wifi_error(code, detail);
            let _ = writeln!(
                crate::ath11k::platform::Console,
                "  ath11k.ko: {} ({:04x}:{:04x}) bring-up failed: {:?}",
                chip.display_name,
                chip.vid,
                chip.did,
                e
            );
            return EIO;
        }
    };
    // The silicon and all software profiles are accepted; no firmware DMA
    // was enabled during identification or reset.
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_enable(dev, CMD_BUS_MASTER) } != 0 {
        return EIO;
    }
    let _ = writeln!(
        crate::ath11k::platform::Console,
        "  ath11k.ko: probed {} ({:04x}:{:04x} subsys {:04x}:{:04x}) hw_rev={} fw=ath11k/{} \
         msi {}x@{} data={:#x} ltssm={:#x}",
        chip.display_name,
        vendor,
        device,
        subsystem_vendor,
        subsystem_device,
        dev_state.hw_rev.name(),
        dev_state.params.fw_dir,
        dev_state.msi.n_vectors,
        dev_state.msi.base_irq,
        dev_state.msi.ep_base_data,
        dev_state.power.ltssm,
    );
    let start = mhi_vectors(&dev_state.msi).map(|(nr_irqs, _, _)| MhiStart {
        io: dev_state.native,
        hw_rev: dev_state.hw_rev,
        fw_dir: dev_state.params.fw_dir,
        nr_irqs,
        vendor,
        device,
        subsystem_vendor,
        subsystem_device,
        pci_addr,
    });
    if let Some(link_ctl) = dev_state.saved_link_ctl {
        *ASPM_RESTORE.lock() = Some(AspmRestore {
            link_ctl,
            multi_msi: dev_state.msi.n_vectors > 1,
            restore: true,
        });
    }
    *CONTROLLER.lock() = Some(dev_state);
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller before unmapping it.
    if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
        return EIO;
    }
    match start {
        Some(s) => crate::ath11k::platform::spawn(mhi_task(s)),
        None => diag::latch_wifi_error(mhi_host::step::BAD_CONFIG, 0),
    }
    let _ = crate::ath11k::platform::EXEC.run();
    0
}
