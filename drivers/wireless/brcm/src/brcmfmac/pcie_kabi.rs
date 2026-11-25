// SPDX-License-Identifier: GPL-2.0-or-later
//! The module build's PCI binding (`brcmfmac.ko`): the built-in `pcie.rs`
//! probe and `native_runtime.rs` provisioning, step for step, over the KABI
//! instead of `narf-bus` / `narf-interrupts` / `narf-io`.
//!
//! [`KabiBackplane`] implements the same three bus seams the built-in
//! `PcieBackplane` does — `chip::Backplane` (BAR0 through the config-space
//! window), `boot::Bus` (BAR2 TCM) and `runtime::Bus` (mapped DMA, the
//! doorbells, the SBMBX mailbox, one plain MSI vector) — so chip discovery,
//! the CR4/CA7 firmware download, the msgbuf common rings and the FullMAC
//! station are the driver's own code. The probe order is Linux
//! `brcmf_pcie_probe` as the built-in follows it:
//!
//! 1. `narf_pci_identity`; the id must be in [`ALL_DEV_IDS`].
//! 2. `narf_pci_prepare_probe` parks decode and bus mastering (D0, INTx
//!    off); the readback must show both off.
//! 3. BAR0 (≥ 4 KiB) and, for the ids the built-in boots, BAR2 are mapped;
//!    memory decode is enabled with INTx disable kept.
//! 4. `Chip::discover` over the BAR0 window, then `park_pcie` masks the
//!    PCIe core's mailbox interrupts.
//! 5. A device the built-in would only park is left parked (bound, no
//!    netdev). Otherwise the provisioning task runs on the module's
//!    executor: signed NBSP board selection, the kernel's regulatory domain
//!    (`narf_wireless_regdomain`), CR4/CA7 boot, ring attach, the station
//!    transport and the station itself, then the netdev/wiphy
//!    ([`crate::cyw43439::interface_module`]).
//!
//! The 1 ms device poller and the MSI upcall drive the executor.

pub use super::pcie_ids::*;
use super::{
    boot,
    chip::{self, Backplane, Chip},
    provision::{self, Family},
    runtime::{self, Memory},
};
use crate::platform::{self, bus as pbus, time, IrqSafeSpinLock};
use alloc::sync::Arc;
use core::fmt::Write as _;
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

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
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_pci_config_read32(dev: u64, offset: u16, out: *mut u32) -> i32;
        pub fn narf_pci_config_write32(dev: u64, offset: u16, value: u32) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_command: *mut u16) -> i32;
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
        pub fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
        pub fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

/// PCI command register bits (`PCI_COMMAND_MEMORY` / `_MASTER` /
/// `_INTX_DISABLE`).
const CMD_MEM_SPACE: u16 = 0x0002;
const CMD_BUS_MASTER: u16 = 0x0004;
const CMD_INTX_DISABLE: u16 = 0x0400;
/// `BRCMF_PCIE_BAR0_WINDOW` (config space).
const BAR0_WINDOW: u16 = 0x80;
/// `BRCMF_PCIE_REG_SBMBX` (config space).
const SBMBX: u16 = 0x98;
/// `BRCMF_PCIE_REG_LINK_STATUS_CTRL` (config space).
const LINK_STATUS_CTRL: u16 = 0xBC;
/// `PCI_EXP_LNKCTL_ASPMC`.
const LNKCTL_ASPMC: u32 = 0x3;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;

/// The PCIe function as the driver's bus seams see it. Every access is a
/// bounds-checked KABI call on the probed device's token; the BAR mappings
/// stay in the kernel.
pub struct KabiBackplane {
    dev: u64,
    bar0: u64,
    bar0_len: u64,
    /// BAR2 (dongle TCM) handle and length.
    bar2: Option<(u64, u64)>,
    pub(super) pcie_core: Option<chip::Core>,
    /// The bound MSI vector, once [`runtime::Bus::arm_interrupts`] ran.
    msi: Option<u16>,
}

impl core::fmt::Debug for KabiBackplane {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfKabiBackplane")
            .field("bar0_len", &self.bar0_len)
            .field("bar2", &self.bar2.map(|(_, len)| len))
            .field("msi", &self.msi)
            .finish_non_exhaustive()
    }
}

/// Order device-visible memory against the doorbell/index writes.
fn barrier() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: order peripheral ownership across the outer-shareable domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

impl KabiBackplane {
    fn cfg_read(&self, offset: u16) -> Result<u32, chip::Error> {
        let mut value = u32::MAX;
        // SAFETY: `value` is a live local.
        match unsafe { ffi::narf_pci_config_read32(self.dev, offset, &mut value) } {
            0 => Ok(value),
            _ => Err(chip::Error::Access),
        }
    }
    fn cfg_write(&self, offset: u16, value: u32) -> Result<(), chip::Error> {
        // SAFETY: argument-only call; the kernel bounds the window.
        match unsafe { ffi::narf_pci_config_write32(self.dev, offset, value) } {
            0 => Ok(()),
            _ => Err(chip::Error::Access),
        }
    }
    /// Command register after clearing `clear` and setting `set`.
    fn command(&self, clear: u16, set: u16) -> Result<u16, ()> {
        let mut command = u16::MAX;
        // SAFETY: `command` is a live local.
        match unsafe { ffi::narf_pci_command(self.dev, clear, set, &mut command) } {
            0 if command != u16::MAX => Ok(command),
            _ => Err(()),
        }
    }
    fn mmio_read(&self, bar: u64, offset: u64) -> u32 {
        let mut value = u32::MAX;
        // SAFETY: `value` is a live local; the kernel bounds-checks `offset`.
        let _ = unsafe { ffi::narf_mmio_read32(self.dev, bar, offset, &mut value) };
        value
    }
    fn mmio_write(&self, bar: u64, offset: u64, value: u32) {
        // SAFETY: argument-only call; the kernel bounds-checks `offset`.
        let _ = unsafe { ffi::narf_mmio_write32(self.dev, bar, offset, value) };
    }
    /// `brcmf_pcie_select_core`'s window write, retried once and verified,
    /// as built in. Returns the offset inside the 4 KiB window.
    fn select(&mut self, address: u32) -> Result<u64, chip::Error> {
        if !chip::valid_address(address) {
            return Err(chip::Error::Address);
        }
        let window = address & !0xfff;
        for _ in 0..2 {
            self.cfg_write(BAR0_WINDOW, window)?;
            let selected = self.cfg_read(BAR0_WINDOW)?;
            if selected == window {
                return Ok(u64::from(address & 0xfff));
            }
            if selected == u32::MAX {
                return Err(chip::Error::Gone);
            }
        }
        Err(chip::Error::Access)
    }
    /// The TCM aperture for `[address, address + length)`, with memory
    /// decode and INTx disable verified on (the built-in `aperture`).
    fn aperture(&self, address: u32, length: usize) -> Result<u64, boot::Error> {
        let command = self.command(0, 0).map_err(|_| boot::Error::Access)?;
        if command & (CMD_MEM_SPACE | CMD_INTX_DISABLE) != CMD_MEM_SPACE | CMD_INTX_DISABLE {
            return Err(boot::Error::Access);
        }
        let (bar, len) = self.bar2.ok_or(boot::Error::Extent)?;
        if u64::from(address)
            .checked_add(length as u64)
            .is_none_or(|end| end > len)
        {
            return Err(boot::Error::Extent);
        }
        Ok(bar)
    }
}

impl Backplane for KabiBackplane {
    fn read32(&mut self, address: u32) -> Result<u32, chip::Error> {
        let offset = self.select(address)?;
        Ok(self.mmio_read(self.bar0, offset))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), chip::Error> {
        let offset = self.select(address)?;
        self.mmio_write(self.bar0, offset, value);
        Ok(())
    }
    /// `brcmf_pcie_read_reg16`. The KABI has no 16-bit MMIO read, so this
    /// is the containing dword's half; backplane register reads have no
    /// side effects on the neighbouring half.
    fn read16(&mut self, address: u32) -> Result<u16, chip::Error> {
        if address & 1 != 0 {
            return Err(chip::Error::Address);
        }
        let dword = self.read32(address & !3)?;
        Ok((dword >> (8 * (address & 2))) as u16)
    }
}

impl boot::Bus for KabiBackplane {
    fn tcm_extent(&self) -> u32 {
        self.bar2
            .map_or(0, |(_, len)| len.min(u64::from(u32::MAX)) as u32)
    }
    fn dma_enabled(&mut self) -> Result<bool, boot::Error> {
        self.command(0, 0)
            .map(|command| command & CMD_BUS_MASTER != 0)
            .map_err(|_| boot::Error::Access)
    }
    /// Dword reads; a partial dword is the matching bytes of its aligned
    /// read (TCM is RAM: reads have no side effects).
    fn read_tcm(&mut self, address: u32, out: &mut [u8]) -> Result<(), boot::Error> {
        let bar = self.aperture(address, out.len())?;
        let mut at = 0usize;
        while at < out.len() {
            let offset = u64::from(address) + at as u64;
            let aligned = offset & !3;
            let skip = (offset - aligned) as usize;
            let take = (4 - skip).min(out.len() - at);
            let word = self.mmio_read(bar, aligned).to_le_bytes();
            out[at..at + take].copy_from_slice(&word[skip..skip + take]);
            at += take;
        }
        Ok(())
    }
    /// Dword writes; a partial dword is read, merged and written back.
    /// The dongle CPU is halted for every TCM write the loader issues, so
    /// nothing else writes the merged bytes meanwhile.
    fn write_tcm(&mut self, address: u32, bytes: &[u8]) -> Result<(), boot::Error> {
        let bar = self.aperture(address, bytes.len())?;
        let mut at = 0usize;
        while at < bytes.len() {
            let offset = u64::from(address) + at as u64;
            let aligned = offset & !3;
            let skip = (offset - aligned) as usize;
            let take = (4 - skip).min(bytes.len() - at);
            let mut word = if skip == 0 && take == 4 {
                [0; 4]
            } else {
                self.mmio_read(bar, aligned).to_le_bytes()
            };
            word[skip..skip + take].copy_from_slice(&bytes[at..at + take]);
            self.mmio_write(bar, aligned, u32::from_le_bytes(word));
            at += take;
        }
        Ok(())
    }
}

/// One coherent buffer of the module DMA pool, as the msgbuf runtime's
/// [`Memory`]. The mapping is coherent, so the sync points are barriers.
pub struct KabiMemory(platform::dma::DmaBuffer);

impl core::fmt::Debug for KabiMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl Memory for KabiMemory {
    fn address(&self) -> u64 {
        self.0.bus()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), runtime::Error> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.0.len())
        {
            return Err(runtime::Error::Bounds);
        }
        // SAFETY: checked extent of this buffer's live CPU mapping.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.0.cpu_ptr().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), runtime::Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.0.len())
        {
            return Err(runtime::Error::Bounds);
        }
        // SAFETY: checked extent; the caller holds exclusive CPU ownership.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.0.cpu_ptr().add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }
    fn to_device(&mut self, _offset: usize, _length: usize) {
        barrier();
    }
    fn release(&mut self) {
        barrier();
    }
    fn sync_from_device(&mut self, _offset: usize, _length: usize) {
        barrier();
    }
}

/// The MSI vector's signal; the upcall raises it.
static SIGNAL: IrqSafeSpinLock<Option<Arc<super::irq::Signal>>> = IrqSafeSpinLock::new(None);

/// Task-context upcall for the bound vector: raise the owner's signal (the
/// built-in `vector_irq`), then run the executor so the woken service
/// makes progress on this CPU now.
extern "C" fn msi_upcall(_cookie: u64) -> i32 {
    let signal = SIGNAL.lock().clone();
    if let Some(signal) = signal {
        signal.raise();
    }
    let _ = platform::EXEC.run();
    0
}

impl runtime::Bus for KabiBackplane {
    type Memory = KabiMemory;
    fn allocate(&mut self, length: usize) -> Result<KabiMemory, runtime::Error> {
        let command = self.command(0, 0).map_err(|_| runtime::Error::Access)?;
        if command & (CMD_MEM_SPACE | CMD_INTX_DISABLE) != CMD_MEM_SPACE | CMD_INTX_DISABLE {
            return Err(runtime::Error::Access);
        }
        platform::dma::alloc(length)
            .map(KabiMemory)
            .map_err(|_| runtime::Error::Access)
    }
    fn enable_dma(&mut self) -> Result<(), runtime::Error> {
        let command = self
            .command(0, CMD_BUS_MASTER)
            .map_err(|_| runtime::Error::Access)?;
        let all = CMD_BUS_MASTER | CMD_MEM_SPACE | CMD_INTX_DISABLE;
        if command & all != all {
            return Err(runtime::Error::Access);
        }
        Ok(())
    }
    fn park_dma(&mut self) -> Result<(), runtime::Error> {
        let command = self
            .command(CMD_BUS_MASTER, 0)
            .map_err(|_| runtime::Error::Access)?;
        if command & CMD_BUS_MASTER != 0 {
            return Err(runtime::Error::Access);
        }
        Ok(())
    }
    fn doorbell(&mut self) -> Result<(), runtime::Error> {
        let core = self.pcie_core.ok_or(runtime::Error::Protocol)?;
        barrier();
        self.write32(
            core.base + if core.revision >= 64 { 0xa20 } else { 0x140 },
            1,
        )
        .map_err(|_| runtime::Error::Access)
    }
    fn host_ready(&mut self, db1: bool) -> Result<(), runtime::Error> {
        if db1 {
            let core = self.pcie_core.ok_or(runtime::Error::Protocol)?;
            barrier();
            self.write32(
                core.base + if core.revision >= 64 { 0xa24 } else { 0x144 },
                1,
            )
            .map_err(|_| runtime::Error::Access)?;
        }
        Ok(())
    }
    fn mailbox(&self) -> Option<runtime::mailbox::Reginfo> {
        let core = self.pcie_core?;
        Some(runtime::mailbox::Reginfo::for_core(
            core.base,
            core.revision,
        ))
    }
    /// `brcmf_pcie_send_mb_data`: SBMBX, written twice on PCIe2 core
    /// revisions <= 13.
    fn ring_mailbox(&mut self) -> Result<(), runtime::Error> {
        let core = self.pcie_core.ok_or(runtime::Error::Protocol)?;
        barrier();
        let writes = if core.revision <= 13 { 2 } else { 1 };
        for _ in 0..writes {
            self.cfg_write(SBMBX, 1)
                .map_err(|_| runtime::Error::Access)?;
        }
        Ok(())
    }
    /// One plain MSI vector (`pci_enable_msi`), the handler bound before
    /// delivery is enabled. Any failure keeps polled service.
    fn arm_interrupts(&mut self, signal: &Arc<super::irq::Signal>) -> bool {
        if self.msi.is_some() {
            *SIGNAL.lock() = Some(signal.clone());
            // SAFETY: argument-only call on our probe token.
            return unsafe { ffi::narf_msi_set_enabled(self.dev, 1) } == 0;
        }
        let (mut count, mut base, mut addr, mut data) = (0u16, 0u16, 0u64, 0u32);
        // SAFETY: the four outputs are live locals.
        let rc = unsafe {
            ffi::narf_msi_enable(self.dev, 1, &mut count, &mut base, &mut addr, &mut data)
        };
        if rc != 0 || count != 1 {
            return false;
        }
        *SIGNAL.lock() = Some(signal.clone());
        // SAFETY: `msi_upcall` is a valid extern "C" fn in this image, which
        // the kernel unbinds before unmapping it.
        if unsafe { ffi::narf_irq_set_handler(self.dev, base, msi_upcall as usize, 0) } != 0 {
            *SIGNAL.lock() = None;
            return false;
        }
        self.msi = Some(base);
        // SAFETY: argument-only call on our probe token.
        unsafe { ffi::narf_msi_set_enabled(self.dev, 1) == 0 }
    }
    /// `pci_disable_msi`: delivery off. The vector stays bound to this
    /// device until teardown (the KABI never reuses it).
    fn disarm_interrupts(&mut self) {
        if self.msi.is_some() {
            // SAFETY: argument-only call on our probe token.
            let _ = unsafe { ffi::narf_msi_set_enabled(self.dev, 0) };
        }
        *SIGNAL.lock() = None;
    }
    /// Linux `pci_pme_capable(pdev, PCI_D3hot)`: the module carries no
    /// system PM or WoWL, so it reports no D3hot wake.
    fn pme_d3hot(&mut self) -> bool {
        false
    }
    fn link_control(&mut self) -> Result<u32, runtime::Error> {
        self.cfg_read(LINK_STATUS_CTRL)
            .map_err(|_| runtime::Error::Access)
    }
    /// The reset path only toggles ASPM in Link Control; a module reaches
    /// that field through `narf_pcie_aspm` (the PCI Express capability is
    /// the kernel's), which locates Link Control itself.
    fn set_link_control(&mut self, value: u32) -> Result<(), runtime::Error> {
        let mut previous = 0u16;
        // SAFETY: `previous` is a live local.
        match unsafe { ffi::narf_pcie_aspm(self.dev, (value & LNKCTL_ASPMC) as u16, &mut previous) }
        {
            0 => Ok(()),
            _ => Err(runtime::Error::Access),
        }
    }
}

/// The function's identity (`narf_pci_identity`).
#[derive(Clone, Copy, Debug)]
pub(super) struct Identity {
    pub(super) pci: boot::PciIdentity,
    pub(super) host: pbus::HostIdentity,
}

fn identity(dev: u64) -> Option<Identity> {
    let mut r = [0u8; 16];
    // SAFETY: `r` names 16 writable bytes.
    if unsafe { ffi::narf_pci_identity(dev, r.as_mut_ptr(), r.len()) } != 0 {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([r[i], r[i + 1]]);
    let pci = boot::PciIdentity {
        vendor: u16_at(0),
        device: u16_at(2),
        subsystem_vendor: u16_at(4),
        subsystem_device: u16_at(6),
    };
    let host = pbus::HostIdentity {
        address: pbus::BusAddr::Pcie(pbus::PcieAddr::new(
            u16_at(12),
            r[14],
            r[15] >> 3,
            r[15] & 7,
        )),
        id: pbus::DeviceId {
            vendor: pci.vendor,
            device: pci.device,
            class: u32::from_le_bytes([r[9], r[10], r[11], 0]),
            subsystem_vendor: pci.subsystem_vendor,
            subsystem_id: pci.subsystem_device,
        },
    };
    Some(Identity { pci, host })
}

/// The bound function: one per module, as built in (`pcie.rs::OWNED`).
static BOUND: AtomicBool = AtomicBool::new(false);

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(platform::Console, "  brcmfmac.ko: {}", args);
}

/// The module's match name. Distinct from the built-in per-id names
/// (`name_for`): the PCI match table is keyed on (name, id), so reusing a
/// built-in name would replace the built-in entry and take it away again at
/// unload.
pub const MODULE_MATCH_NAME: &str = "brcmfmac-module";

/// Register every Broadcom FullMAC PCIe id (the built-in
/// `register_pci_driver`'s table); the kernel calls [`probe_c`] for a match.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        // SAFETY: the name is 'static and `probe_c` is a valid extern "C"
        // fn; the loader unregisters every match before this image is
        // unmapped.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                MODULE_MATCH_NAME.as_ptr(),
                MODULE_MATCH_NAME.len(),
                BROADCOM_VENDOR,
                did,
                probe_c as usize,
            )
        };
        if rc != 0 {
            log(format_args!(
                "PCI registration of {} failed ({rc})",
                name_for(did)
            ));
        }
    }
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    let _ = platform::EXEC.run();
    0
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // Every device export after this point takes the bound token
    // (`platform::device`): a second function must not replace it.
    if BOUND.swap(true, Ordering::AcqRel) {
        return EBUSY;
    }
    platform::set_device(dev);
    let rc = probe_device(dev);
    if rc != 0 {
        platform::set_device(0);
        BOUND.store(false, Ordering::Release);
    }
    rc
}

/// The built-in `bring_up`: parked identification, BAR mapping, AI core
/// discovery and PCIe interrupt parking. No DMA, no firmware.
fn bring_up(dev: u64, device: u16) -> Result<(KabiBackplane, Chip), &'static str> {
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_prepare_probe(dev) } != 0 {
        return Err("PCI preparation failed");
    }
    let mut bus = KabiBackplane {
        dev,
        bar0: 0,
        bar0_len: 0,
        bar2: None,
        pcie_core: None,
        msi: None,
    };
    let parked = bus.command(0, 0).map_err(|_| "command read failed")?;
    if parked & (CMD_BUS_MASTER | CMD_MEM_SPACE | CMD_INTX_DISABLE) != CMD_INTX_DISABLE {
        return Err("decode/bus mastering not parked");
    }
    let map = |index: u8| -> Option<(u64, u64)> {
        // SAFETY: argument-only call on our probe token.
        let handle = unsafe { ffi::narf_bar_map(dev, index) };
        let mut len = 0u64;
        // SAFETY: `len` is a live local.
        (handle != 0 && unsafe { ffi::narf_bar_len(dev, handle, &mut len) } == 0)
            .then_some((handle, len))
    };
    let (bar0, bar0_len) = map(0).ok_or("BAR0 map failed")?;
    if bar0_len < 4096 {
        return Err("BAR0 too small");
    }
    bus.bar0 = bar0;
    bus.bar0_len = bar0_len;
    // BAR2 for the ids the built-in boots: BCM43602, or a PCI row a chip
    // profile implements.
    let pci = pbus::DeviceId {
        vendor: BROADCOM_VENDOR,
        device,
        class: 0,
        subsystem_vendor: 0,
        subsystem_id: 0,
    };
    let bootable = matches!(
        device,
        BRCM_PCIE_43602_DEVICE_ID | BRCM_PCIE_43602_2G_DEVICE_ID | BRCM_PCIE_43602_5G_DEVICE_ID
    ) || super::chip_profile::pci_match(&pci)
        .is_some_and(super::chip_profile::implemented);
    if bootable {
        bus.bar2 = Some(map(2).ok_or("BAR2 map failed")?);
    }
    let command = bus
        .command(0, CMD_MEM_SPACE | CMD_INTX_DISABLE)
        .map_err(|_| "memory decode enable failed")?;
    if command & (CMD_BUS_MASTER | CMD_MEM_SPACE | CMD_INTX_DISABLE)
        != CMD_MEM_SPACE | CMD_INTX_DISABLE
    {
        return Err("memory decode readback mismatch");
    }
    let chip = Chip::discover(&mut bus).map_err(|_| "AI core discovery failed")?;
    bus.pcie_core = chip.core(chip::CORE_PCIE2);
    chip.park_pcie(&mut bus)
        .map_err(|_| "PCIe interrupt parking failed")?;
    Ok((bus, chip))
}

fn probe_device(dev: u64) -> i32 {
    let Some(id) = identity(dev) else {
        return ENODEV;
    };
    if id.pci.vendor != BROADCOM_VENDOR || !ALL_DEV_IDS.contains(&id.pci.device) {
        return ENODEV;
    }
    let (bus, chip) = match bring_up(dev, id.pci.device) {
        Ok(found) => found,
        Err(why) => {
            log(format_args!(
                "{} ({:04x}:{:04x}) bring-up failed: {why}",
                name_for(id.pci.device),
                id.pci.vendor,
                id.pci.device
            ));
            return EIO;
        }
    };
    log(format_args!(
        "probed {} ({:04x}:{:04x} subsys {:04x}:{:04x}) chip {} rev {} ({} cores)",
        name_for(id.pci.device),
        id.pci.vendor,
        id.pci.device,
        id.pci.subsystem_vendor,
        id.pci.subsystem_device,
        chip.id,
        chip.revision,
        chip.cores.len()
    ));
    // Firmware owns rings and buffers from boot on; a teardown that cannot
    // prove the dongle stopped must not free them (the built-in quarantine).
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller before unmapping it.
    if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
        return EIO;
    }
    // The built-in `native_runtime::start`: only a covered chip with its
    // TCM aperture is provisioned; any other stays parked and bound.
    if super::chip_profile::covered(chip.id).is_none() || bus.bar2.is_none() {
        log(format_args!(
            "chip {} parked: no implemented boot profile",
            chip.id
        ));
        return 0;
    }
    platform::spawn(provision_task(bus, chip, id));
    let _ = platform::EXEC.run();
    0
}

/// The built-in `drive_scheduled(120, ...)` retry: signed provisioning
/// staged late (a firmware pack loaded after the module) or a regulatory
/// country set late is retried every 500 ms for a minute, only while no
/// hardware attempt has started.
async fn provision_task(bus: KabiBackplane, chip: Chip, id: Identity) {
    let mut parked = Some(bus);
    let mut last = "signed board selection unavailable or mismatched";
    for attempt in 0..120 {
        if attempt > 0 {
            time::sleep_cycles(time::wall::ns_to_cycles(500_000_000)).await;
        }
        let Some(bus) = parked.take() else {
            break;
        };
        match provision(bus, &chip, id).await {
            Ok(()) => return,
            Err(Refusal::Parked(bus, why)) => {
                parked = Some(bus);
                last = why;
            }
            Err(Refusal::Started(why)) => {
                last = why;
                break;
            }
        }
    }
    log(format_args!("{last}"));
}

/// A provisioning failure: before any hardware attempt the parked bus is
/// returned for a retry; after one, the attempt is final (as built in).
enum Refusal {
    Parked(KabiBackplane, &'static str),
    Started(&'static str),
}

/// The built-in provisioning gate (`narf_wireless::reg::db::ensure_domain`)
/// over the KABI: the kernel's installed domain ([`platform::reg`]) must
/// exist before any hardware attempt; none parks the bus for a retry.
///
/// It must also name a country. The shared station refuses any other
/// (`Station::initialize_inner` requires an uppercase alpha2 for the
/// firmware `country` iovar), so world `00` never brings brcmfmac up, built
/// in or module. Built in that refusal comes after the CR4 boot and is
/// final; here it comes before the firmware runs, so a country set within
/// the retry window (`iw reg set`, a staged signed policy) still provisions
/// the device.
fn regulatory_policy() -> Result<(), &'static str> {
    let domain = platform::reg::snapshot().ok_or("kernel regulatory domain unavailable")?;
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err("kernel regulatory domain names no country (world 00)");
    }
    Ok(())
}

/// The built-in `provision_checked` + `attach_runtime` for the module:
/// select and load the signed assets, require the kernel's regulatory
/// domain, then boot, attach the rings, build the station on that live
/// domain and publish it.
async fn provision(bus: KabiBackplane, chip: &Chip, id: Identity) -> Result<(), Refusal> {
    let reprovision = Reprovision {
        id,
        chip: chip.id,
        revision: chip.revision,
    };
    let (selection, assets, nvram) = match reprovision.load() {
        Ok(loaded) => loaded,
        Err(why) => return Err(Refusal::Parked(bus, why)),
    };
    if let Err(why) = regulatory_policy() {
        return Err(Refusal::Parked(bus, why));
    }
    if assets.proof.validate().is_err() {
        return Err(Refusal::Parked(bus, "provisioning replaced before boot"));
    }
    // From here an error is final: the dongle may have run.
    let cr4 = boot::Cr4::claim_selected(bus, id.pci, &selection)
        .map_err(|_| Refusal::Started("CR4 passive/RAM/identity discovery failed"))?;
    let booted = cr4
        .boot(&assets.firmware, &nvram)
        .map_err(|_| Refusal::Started("CR4 firmware bootstrap failed"))?;
    let mut runtime = runtime::Runtime::attach(booted)
        .map_err(|_| Refusal::Started("common-ring/DMA attachment failed"))?;
    runtime
        .enable_data()
        .map_err(|_| Refusal::Started("RX buffer posting failed"))?;
    let adapter = super::station_transport::Adapter::new(runtime)
        .map_err(|_| Refusal::Started("station transport setup failed"))?
        .with_reboot(alloc::boxed::Box::new(reprovision));
    log(format_args!(
        "firmware up ({} bytes, board {}); attaching the station",
        assets.firmware.len(),
        selection.board()
    ));
    crate::cyw43439::interface_module::attach(adapter)
        .await
        .map_err(Refusal::Started)
}

/// The retained firmware selection of the bound function (the built-in
/// `native_runtime::Reprovision`, signed-manifest path): every (re)boot
/// re-runs the selection and the asset reads, so a replaced or removed
/// asset refuses the reboot instead of reusing stale bytes.
#[derive(Clone, Copy, Debug)]
struct Reprovision {
    id: Identity,
    chip: u16,
    revision: u8,
}

impl Reprovision {
    fn load(
        &self,
    ) -> Result<(provision::Selection, provision::Assets, alloc::vec::Vec<u8>), &'static str> {
        let family = if self.chip == super::chip_profile::BRCM_CC_43602 {
            Family::Pcie43602
        } else {
            Family::PcieFullmac
        };
        let selection = provision::select_kabi(family, self.id.host)
            .map_err(|_| "signed board selection unavailable or mismatched")?;
        if !selection.admits_chip(self.chip, self.revision) {
            return Err("discovered chip/revision mismatch");
        }
        let assets = selection
            .load_kabi()
            .map_err(|_| "selected asset signature/key/length/hash mismatch")?;
        let nvram = boot::pack_nvram(&assets.nvram).map_err(|_| "invalid selected NVRAM")?;
        Ok((selection, assets, nvram))
    }
}

/// Linux `brcmf_pcie_reset`'s fresh download (`brcmf_pcie_setup`) on the
/// reset, halted bus, as the built-in `Reprovision::boot`: a refused
/// download before the claim returns the bus for a retry.
impl super::station_transport::Reboot<KabiBackplane> for Reprovision {
    fn boot(
        &mut self,
        bus: KabiBackplane,
    ) -> Result<runtime::Runtime<KabiBackplane>, (runtime::Error, Option<KabiBackplane>)> {
        let (selection, assets, nvram) = match self.load() {
            Ok(loaded) => loaded,
            Err(why) => {
                log(format_args!("reboot refused: {why}"));
                return Err((runtime::Error::Access, Some(bus)));
            }
        };
        if assets.proof.validate().is_err() {
            return Err((runtime::Error::Access, Some(bus)));
        }
        let booted = boot::Cr4::claim_selected(bus, self.id.pci, &selection)
            .and_then(|cr4| cr4.boot(&assets.firmware, &nvram))
            .map_err(|refused| (refused.error.into(), Some(refused.bus)))?;
        runtime::Runtime::attach(booted).map_err(|error| (error, None))
    }
}
