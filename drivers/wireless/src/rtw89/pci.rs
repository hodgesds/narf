//! RTW89 PCI probe.
//!
//! Driver-match registration + **BAR2** mapping. Notable difference
//! from the sibling rtw88: the AX-generation 8852/8851 parts use BAR2.
//! Device-specific extents must cover each access; indirect CPU-local
//! accesses on A/C require the larger aperture at0x40000.
//!
//! Linux's `rtw89/pci.c::rtw89_pci_claim_device` (~L3340..L3420) hard-
//! codes `u8 bar_id = 2;` before the `pci_iomap` call. We mirror that
//! exactly.
//!
//! ## What this file does *not* do at Stage 0/1 (deferred)
//!
//! - MSI/MSI-X vector setup. Lands with Stage-2 TX/RX rings.
//! - Complete firmware load. Checked secure plans, power/DLE/HFC and native
//!   CH12 primitives exist; full PCIe/BDRAM/WCPU still need composition.
//! - PHY parameter table load. Stubbed in `phy.rs`.
//! - DMA channel activation. The diagnostic retains13 TX +2 RX allocations;
//!   they remain unpublished until the complete native startup owner exists.

#![allow(dead_code)]

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::efuse;
use super::mac::{self, ChipId};
use super::*;

use super::tx_transport::{self, Ticket, TxQueue};
use crate::rtw89::datapath::{RxChannelState, TxChannelState};
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_io::{alloc_coherent, alloc_coherent_masked, DmaBuffer};
use narf_lib::id::DomainId;

/// One bound RTW89 device.
pub struct Rtw89Device {
    /// Retained bus identity; a repeat probe must not park the active owner.
    pub(crate) bus_addr: narf_bus::BusAddr,
    /// Retained PCI function identity for MSI binding (irq_be step 6).
    /// `BusDevice` is `Copy`; the MSI enable path needs the function,
    /// not just its address.
    pub(crate) device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    /// BAR2 MMIO mapping — the only BAR rtw89 silicon exposes.
    pub mmio_bar2: MmioRegion,
    /// Factory MAC decoded from the chip-specific logical EFUSE map.
    pub mac: [u8; efuse::MAC_ADDR_LEN],
    /// PCI device id we matched on.
    pub device_id: u16,
    /// Chip family decoded from the PCI device id.
    pub chip_id: Option<ChipId>,
    /// Chip-version field from `R_AX_SYS_CFG1`.
    pub chip_version: u8,

    // ── Stage-2 Data Path ──
    pub tx_rings: Vec<IrqSafeSpinLock<TxChannelState>>,
    // Native packets and their header mappings remain owned until both a
    // TXBD read-pointer update and the matching firmware RPQ release.
    native_tx: Vec<IrqSafeSpinLock<TxQueue<NativePacket>>>,
    pub rx_rings: Vec<IrqSafeSpinLock<RxChannelState>>,
    pub tx_ring_dma: Vec<DmaBuffer>,
    pub rx_ring_dma: Vec<DmaBuffer>,
    pub rx_buffers: Vec<Vec<DmaBuffer>>,
    /// Prepared 8922A transport owner (chip-row step 5): factory
    /// identity, station pool, BE data + H2C transport, ring state.
    /// `None` for AX chips, whose transport stays with `native_tx`.
    pub(crate) be_8922a: Option<IrqSafeSpinLock<super::prepared_8922a::Prepared8922a>>,
    pub irq_vector: Option<u8>,
}

impl core::fmt::Debug for Rtw89Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89Device")
            .field("mac", &self.mac)
            .field("device_id", &self.device_id)
            .field("chip_id", &self.chip_id)
            .field("chip_version", &self.chip_version)
            .finish_non_exhaustive()
    }
}

struct NativePacket {
    header: DmaBuffer,
    frame: DmaBuffer,
}

/// Errors raised by the Stage-0/1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// PCI access failed or bus mastering could not be verifiably parked.
    PciAccess,
    /// `map_bar(device, 2)` failed.
    Bar2MapFailed,
    /// Power-on prologue failed.
    PowerOn(mac::MacError),
    /// EFUSE read failed.
    Efuse(efuse::EfuseError),
    /// PCI device ID didn't match a known chip family.
    UnknownChip,
    /// Out of DMA-coherent memory during ring allocation.
    NoMemory,
}

/// Single-instance live device.
static CONTROLLER: IrqSafeSpinLock<Option<Arc<Rtw89Device>>> = IrqSafeSpinLock::new(None);

/// Attach the initial B station after a trusted platform reset handoff.
/// Generic PCI matching always requires actual advertised and completed FLR.
///
/// # Safety
/// Caller independently proved actual function/slot power reset, posted DMA
/// drainage, and no firmware/driver DMA since, and holds this exact function
/// and capability exclusively before generic binding. A board flag or PCI
/// bus-master-off readback does not establish this temporal contract.
pub unsafe fn attach_cold(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: delegated qualified platform temporal-reset/exclusivity proof.
    unsafe { super::bootstrap::attach_cold(device, cap) }
}

/// Probe entry called by `narf-bus::driver_match`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // RTL8852BE (b852/b85b), RTL8852CE (c852, rtw8852ce.c
    // `rtw89_8852ce_id_table`) and RTL8851BE (b851, rtw8851be.c
    // `rtw89_8851be_id_table`) run the retained reset/firmware/radio/
    // station bootstrap; C and 8851B station admission need their signed
    // records.
    if device.id.vendor == 0x10ec && super::bootstrap_did(device.id.device) {
        return super::bootstrap::probe(device, cap);
    }
    let bound = CONTROLLER.lock().as_ref().map(|owner| owner.bus_addr);
    match crate::rtw88::pci_park::admission(bound, device.addr) {
        crate::rtw88::pci_park::Admission::Bound => return Ok(()),
        crate::rtw88::pci_park::Admission::ParkExtra => {
            crate::rtw88::pci_park::invoke(&cap, || crate::rtw88::pci_park::park(&device, &cap))
                .map_err(|_| narf_bus::ProbeError::BadDevice)?
                .map_err(|_| narf_bus::ProbeError::BadDevice)?;
            return Ok(());
        }
        crate::rtw88::pci_park::Admission::Initialize => {}
    }

    // SAFETY: caller-authority.
    let result = unsafe { bring_up(&device, &cap) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let did = dev.device_id;
    let arc_dev = Arc::new(dev);
    *CONTROLLER.lock() = Some(arc_dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    Ok(())
}

/// Bring the chip up: map BAR2, run baseline power-on, detect chip
/// version and factory MAC, and retain unpublished ring storage.
///
/// # Safety
/// Caller owns the device's PCI configuration and BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Rtw89Device, ProbeError> {
    crate::rtw88::pci_park::invoke(cap, || {
        // SAFETY: caller's exclusive function/BAR contract; complete diagnostic
        // accesses stay inside the real capability operation.
        unsafe { bring_up_registers(device, cap) }
    })
    .map_err(|_| ProbeError::PciAccess)?
}

unsafe fn bring_up_registers(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Rtw89Device, ProbeError> {
    let mmio_bar2 = crate::rtw88::pci_park::map_bar_control(device, cap, 2)
        .map_err(|_| ProbeError::Bar2MapFailed)?;
    if mmio_bar2.len < 0x10000 {
        return Err(ProbeError::Bar2MapFailed);
    }

    let chip_id = ChipId::from_pci_did(device.id.device).ok_or(ProbeError::UnknownChip)?;
    // RTL8922A is admitted here (chip-row step 5): its power-on
    // prologue, factory read, and transport owner are the BE
    // variants below. Ring programming itself stays with the future
    // mac_pre_init owner (`Prepared8922a::program_rings`).
    let is_8922a = chip_id == ChipId::Rtl8922A;

    // SAFETY: BAR2 mapped + owned.
    unsafe {
        if is_8922a {
            mac::baseline_power_on_be(&mmio_bar2).map_err(ProbeError::PowerOn)?;
        } else {
            mac::baseline_power_on(&mmio_bar2).map_err(ProbeError::PowerOn)?;
        }
    }

    // SAFETY: `mmio_bar2` is the just-mapped, caller-owned BAR2 region; reading
    // the chip-version field (`R_AX_SYS_CFG1`) is an MMIO read of a valid,
    // in-range device register on this owned window. Linux reads `cv`
    // from this register for every generation (`core.c:7134`).
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let chip_version = unsafe { mac::read_chip_version(&mmio_bar2) };
    // 8922A MAC pre-init (chip-row remainder): the MAC
    // power-state reset + full `pwr_on_func` tail, in Linux
    // `rtw89_chip_info_setup` order (`core.c:7388..7409`:
    // chip-ver read, `rtw89_mac_pwr_on`, then the EFUSE read
    // below). The core chip version is read here too and retained
    // on the owner once constructed (`record_chip_ver`). A
    // refused pre-init aborts the probe — Linux behaves the same
    // (a failed power-on aborts the probe; no blind retry).
    let mut chip_ver_8922a = None;
    if is_8922a {
        let mut pre_init_regs = super::prepared_8922a::MmioRegs(&mmio_bar2);
        super::mac_pre_init_8922a::reset_pwr_state(&mut pre_init_regs)
            .map_err(|_| ProbeError::PowerOn(mac::MacError::Timeout))?;
        super::mac_pre_init_8922a::power_on_tail(&mut pre_init_regs, true, chip_version)
            .map_err(|_| ProbeError::PowerOn(mac::MacError::Timeout))?;
        chip_ver_8922a = Some(
            super::mac_pre_init_8922a::read_chip_ver(&mut pre_init_regs, chip_version)
                .map_err(|_| ProbeError::PowerOn(mac::MacError::Timeout))?,
        );
    }
    // 8922A reads its factory identity (MAC + RFE + PHY-cap + cut +
    // thermal) through the BE EFUSE protocol; AX chips use the AX map.
    // The factory is retained for the Prepared owner below.
    let mut factory_8922a = None;
    // SAFETY: `mmio_bar2` is the caller-owned BAR2 region; the EFUSE
    // readers only touch in-range EFUSE registers on this owned window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mac = if is_8922a {
        // SAFETY: Caller owns powered BAR2 exclusively (just-mapped,
        // baseline power-on done above); the BE EFUSE reader only
        // touches in-range EFUSE registers on this owned window.
        let factory = unsafe { super::efuse_be::read_factory(&mmio_bar2, chip_version) }
            .map_err(|error| ProbeError::Efuse(error.as_efuse_error()))?;
        if !efuse::mac_is_valid(factory.mac) {
            return Err(ProbeError::Efuse(efuse::EfuseError::MacUninitialized));
        }
        let mac = factory.mac;
        factory_8922a = Some(factory);
        mac
    } else {
        // SAFETY: Caller owns powered BAR2 exclusively (just-mapped,
        // baseline power-on done above); the AX EFUSE reader only
        // touches in-range EFUSE registers on this owned window.
        unsafe { efuse::read_mac(&mmio_bar2, chip_id, chip_version) }.map_err(ProbeError::Efuse)?
    };

    // No interrupt delivery is enabled until a complete firmware/ring owner
    // installs and owns its actual completion path.
    let irq_vector = None;

    // ── DMA Ring Allocation ──
    use crate::rtw89::dma::*;

    let mut tx_rings = Vec::new();
    let mut tx_ring_dma = Vec::new();
    // AX chips keep the native (AX-header) TX queues; 8922A owns
    // its queues inside the Prepared owner (`DataTx`: 12 data
    // channels + CH12 H2C) instead, so no AX queue is built for it.
    let mut native_tx = Vec::new();
    if !is_8922a {
        for ch in 0..12 {
            native_tx.push(IrqSafeSpinLock::new(
                TxQueue::new(ch, DEFAULT_TXBD_NUM).map_err(|_| ProbeError::NoMemory)?,
            ));
        }
    }
    for ch in 0..TXCH_NUM as u8 {
        let buf = alloc_coherent(tx_ring_bytes(DEFAULT_TXBD_NUM), DomainId::DRIVER_0)
            .map_err(|_| ProbeError::NoMemory)?;
        // SAFETY: `buf` is a fresh DMA-coherent allocation of exactly
        // `tx_ring_bytes(DEFAULT_TXBD_NUM)` bytes, so `as_mut_ptr()` is valid and
        // writable for that length; zeroing the whole region stays in bounds.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_bytes(buf.as_mut_ptr(), 0, tx_ring_bytes(DEFAULT_TXBD_NUM));
        }
        tx_ring_dma.push(buf);
        tx_rings.push(IrqSafeSpinLock::new(TxChannelState::new(
            chip_id,
            ch,
            DEFAULT_TXBD_NUM,
        )));
    }

    let mut rx_rings = Vec::new();
    let mut rx_ring_dma = Vec::new();
    let mut rx_buffers = Vec::new();
    for ch in 0..RXCH_NUM as u8 {
        let buf = alloc_coherent(rx_ring_bytes(DEFAULT_RXBD_NUM), DomainId::DRIVER_0)
            .map_err(|_| ProbeError::NoMemory)?;
        // SAFETY: `buf` is a fresh DMA-coherent allocation of exactly
        // `rx_ring_bytes(DEFAULT_RXBD_NUM)` bytes, so `as_mut_ptr()` is valid and
        // writable for that length; zeroing the whole region stays in bounds.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_bytes(buf.as_mut_ptr(), 0, rx_ring_bytes(DEFAULT_RXBD_NUM));
        }
        let mut bufs = Vec::with_capacity(DEFAULT_RXBD_NUM as usize);
        let ring_ptr = buf.as_mut_ptr() as *mut RxBd;
        for i in 0..DEFAULT_RXBD_NUM {
            let pkt_buf =
                alloc_coherent(2048, DomainId::DRIVER_0).map_err(|_| ProbeError::NoMemory)?;
            // SAFETY: `ring_ptr` points into the `DEFAULT_RXBD_NUM`-entry RX ring
            // buffer just allocated and zeroed above; `i < DEFAULT_RXBD_NUM`, so
            // `ring_ptr.add(i)` is an in-bounds, properly aligned `RxBd` slot, and
            // `set_phys` records the physical address of `pkt_buf`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                let mut bd = RxBd {
                    buf_size: 2048,
                    ..Default::default()
                };
                bd.set_phys(pkt_buf.dma_addr().raw());
                core::ptr::write_volatile(ring_ptr.add(i as usize), bd);
            }
            bufs.push(pkt_buf);
        }
        rx_ring_dma.push(buf);
        rx_buffers.push(bufs);
        rx_rings.push(IrqSafeSpinLock::new(RxChannelState::new(
            chip_id,
            ch,
            DEFAULT_RXBD_NUM,
        )));
    }

    // The diagnostic owns unpublished storage only. Ring base/index/BDRAM
    // writes belong to the future verified firmware/DLE/HFC/reset owner.
    // 8922A: retain the Prepared transport owner (station pool, BE
    // data + H2C transport, ring state) for that owner to drive;
    // ring programming itself is NOT done here — Linux programs the
    // rings in `rtw89_pci_ops_mac_pre_init_be` /
    // `rtw89_pci_ops_reset`, after the DMA pre-init halves and the
    // MAC reset (`Prepared8922a::program_rings`).
    let be_8922a = match factory_8922a {
        Some(factory) => {
            let mut owner = super::prepared_8922a::Prepared8922a::new(factory, chip_version)
                .map_err(|_| ProbeError::NoMemory)?;
            if let Some(ver) = chip_ver_8922a {
                owner.record_chip_ver(ver);
            }
            Some(IrqSafeSpinLock::new(owner))
        }
        None => None,
    };
    let device = Rtw89Device {
        bus_addr: device.addr,
        device: *device,
        cap: *cap,
        mmio_bar2,
        mac,
        device_id: device.id.device,
        chip_id: Some(chip_id),
        chip_version,
        tx_rings,
        native_tx,
        rx_rings,
        tx_ring_dma,
        rx_ring_dma,
        rx_buffers,
        be_8922a,
        irq_vector,
    };
    // 8922A: run the `rtw89_core_start` prefix through the firmware
    // download now that the rings and the Prepared owner exist. The
    // outcome is recorded on the owner (`firmware_ready`), never
    // fatal to the probe: nothing past the download is wired yet,
    // so a failed download leaves an inert, inspectable device.
    if is_8922a {
        // SAFETY: caller's exclusive BAR/function contract; the rings
        // were just allocated, nothing else uses them yet.
        let outcome = unsafe { device.boot_8922a() };
        if let Some(owner) = device.be_8922a.as_ref() {
            owner.lock().record_firmware(outcome);
        }
    }
    Ok(device)
}

/// Why the 8922A boot (`Rtw89Device::boot_8922a`) stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boot8922aError {
    /// Not an 8922A probe.
    NoOwner,
    /// `partial_init` / download sequence failure.
    Fwdl(super::fwdl_be::Error),
    /// DMA pre-init / ring programming failure.
    Dma(super::prepared_8922a::Error),
    /// BDRAM reset poll failure.
    Bdram(super::dma_8922a::Error),
    /// Firmware file / BBMCU0 element.
    Firmware(super::fw::FwError),
    /// Download plan (security, geometry).
    Plan(super::download_plan::Error),
}

impl Rtw89Device {
    /// RTL8922A `rtw89_core_start` prefix through the firmware
    /// download, in Linux order:
    ///
    /// 1. `rtw89_mac_preinit` tail: `mac_func_en_be` (power-on
    ///    already ran in `bring_up_registers`).
    /// 2. `rtw89_mac_partial_init(include_bb = true)`
    ///    (`mac.c:4307`): `fwdl_be::partial_init` (HCI DMA TRX, BB
    ///    preinit, DMAC pre-init, DLFW DLE/HFC).
    /// 3. hci `mac_pre_init` (`pci_be.c:484`): IO recovery, power
    ///    wake, DMA pre-init first half, `rtw89_pci_ops_reset`
    ///    (`program_rings`, CH12 reset), BDRAM reset, the
    ///    debounce/LDO/PCIe/SER settings, then only CH12 TX DMA on.
    /// 4. `rtw89_mac_fwdl_preconfig`.
    /// 5. `rtw89_fw_download(NORMAL, include_bb)`: the NORMAL suit
    ///    from the trusted firmware registry and its BBMCU0 element,
    ///    each through the fuse-selected `DownloadPlan`, over CH12.
    ///
    /// # Safety
    /// Caller owns BAR2, the PCI function and the probe-allocated
    /// rings exclusively; no reset/removal races.
    pub(super) unsafe fn boot_8922a(&self) -> Result<(), Boot8922aError> {
        use super::dma::{DEFAULT_RXBD_NUM, DEFAULT_TXBD_NUM, TXCH_NUM};
        use super::fwdl_be::{self, CheckType, Suit};
        let owner_lock = self.be_8922a.as_ref().ok_or(Boot8922aError::NoOwner)?;
        let cv = self.chip_version;
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        fwdl_be::mac_func_en(regs);
        fwdl_be::partial_init(regs).map_err(Boot8922aError::Fwdl)?;
        super::pci_pre_init_8922a::io_rcy(regs);
        super::pci_pre_init_8922a::power_wake(regs, true);
        let tx_phys: [u64; TXCH_NUM] =
            core::array::from_fn(|ch| self.tx_ring_dma[ch].dma_addr().raw());
        let rx_phys = [
            self.rx_ring_dma[0].dma_addr().raw(),
            self.rx_ring_dma[1].dma_addr().raw(),
        ];
        let fuses = {
            let mut owner = owner_lock.lock();
            owner
                .pre_init_dma_before_reset(regs, DEFAULT_RXBD_NUM, DEFAULT_RXBD_NUM)
                .map_err(Boot8922aError::Dma)?;
            owner
                .program_rings(regs, &tx_phys, &rx_phys, DEFAULT_TXBD_NUM, DEFAULT_RXBD_NUM)
                .map_err(Boot8922aError::Dma)?;
            owner.secure_fuses()
        };
        super::dma_8922a::rst_bdram(regs).map_err(Boot8922aError::Bdram)?;
        // A SER-clear timeout only warns in Linux (`pci_be.c:385`).
        let _ = super::pci_pre_init_8922a::settings(regs, cv);
        super::dma_8922a::pre_init_dma_enable(regs);
        fwdl_be::fwdl_preconfig(regs);

        let image = super::firmware_registry::load(ChipId::Rtl8922A, cv)
            .map_err(Boot8922aError::Firmware)?;
        let bb_image = image.bbmcu(cv, 0).map_err(Boot8922aError::Firmware)?;
        let blacklist = super::secure::Blacklist::upstream(ChipId::Rtl8922A);
        let normal = super::download_plan::DownloadPlan::new(image, fuses, blacklist)
            .map_err(Boot8922aError::Plan)?;
        let bb = super::download_plan::DownloadPlan::new(bb_image, fuses, blacklist)
            .map_err(Boot8922aError::Plan)?;
        // SAFETY: rings programmed above; caller's exclusivity contract.
        let mut port = unsafe { FwdlPort::new(self) };
        fwdl_be::download(
            &mut port,
            &Suit {
                plan: &normal,
                check: CheckType::Wcpu,
                malloc_info: true,
            },
            &[Suit {
                plan: &bb,
                check: CheckType::Bb0,
                malloc_info: false,
            }],
        )
        .map(|_| ())
        .map_err(Boot8922aError::Fwdl)
    }
}

/// Production [`super::fwdl_be::Port`] for a probed 8922A device:
/// BAR2 for the register program and `Rtw89Device::submit_be_fwdl`
/// for CH12 packets.
pub(super) struct FwdlPort<'a> {
    device: &'a Rtw89Device,
    regs: super::prepared_8922a::MmioRegs<'a>,
}

impl<'a> FwdlPort<'a> {
    /// # Safety
    /// Same contract as [`Rtw89Device::submit_be_fwdl`] for the
    /// port's whole lifetime: rings programmed through the Prepared
    /// owner, no reset/removal racing, caller owns BAR2.
    pub(super) unsafe fn new(device: &'a Rtw89Device) -> Self {
        Self {
            device,
            regs: super::prepared_8922a::MmioRegs(&device.mmio_bar2),
        }
    }
}

impl super::fwdl_be::Regs for FwdlPort<'_> {
    fn read16(&mut self, address: u32) -> u16 {
        super::fwdl_be::Regs::read16(&mut self.regs, address)
    }
    fn read32(&mut self, address: u32) -> u32 {
        super::fwdl_be::Regs::read32(&mut self.regs, address)
    }
    fn write16(&mut self, address: u32, value: u16) {
        super::fwdl_be::Regs::write16(&mut self.regs, address, value)
    }
    fn write32(&mut self, address: u32, value: u32) {
        super::fwdl_be::Regs::write32(&mut self.regs, address, value)
    }
}

impl super::fwdl_be::Port for FwdlPort<'_> {
    fn submit(&mut self, buf: &[u8], fwdl: bool) -> Result<(), super::fwdl_be::Error> {
        // SAFETY: `FwdlPort::new`'s contract covers this submit.
        unsafe { self.device.submit_be_fwdl(buf, fwdl) }
            .map(|_| ())
            .map_err(|_| super::fwdl_be::Error::Transport)
    }
}

/// What frees a CH12 buffer: an H2C with an ack identity is held
/// until its C2H ack; FWDL header / section packets have no ack and
/// are freed on TXBD consumption (`fwdl` picks the RPKT type).
enum FwcmdHold {
    Ack(super::fwcmd_8922a::FramedH2c),
    Consumed { fwdl: bool },
}

fn rtw89_isr() {
    // Completion handling deferred to pumps.
}

/// Ethernet SendFn. Station association, controlled-port handling and native
/// encapsulation are not wired; accepting this input as an MPDU would corrupt
/// both the on-air frame and the PCI descriptor layout. Reject before DMA/MMIO.
pub fn send_frame(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}

/// Device ownership is outside ARM's inner-shareable CPU ordering domain.
fn native_dma_barrier() {
    use core::sync::atomic::{compiler_fence, Ordering};
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: orders normal-memory DMA ownership against device MMIO.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

impl Rtw89Device {
    /// Retained native PCI TX backend for a future station producer. No current
    /// probe/network callback invokes it: firmware, RF and RPQ startup still
    /// need a single runtime owner.
    ///
    /// # Safety
    /// Caller has initialized firmware/station rate state and enabled the
    /// selected AX channel with explicitly programmed and retained ring geometry;
    /// no reset/removal can race. The RPQ consumer must pass release records to
    /// complete_native_report. `frame` is an unprotected, non-QoS native MPDU.
    pub(super) unsafe fn submit_native(
        &self,
        info: super::txrx::TxwdInfo,
        frame: &[u8],
    ) -> Result<Ticket, tx_transport::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.submit_native_authorized(info, frame) }
        })
        .map_err(|_| tx_transport::Error::Authority)?
    }

    unsafe fn submit_native_authorized(
        &self,
        info: super::txrx::TxwdInfo,
        frame: &[u8],
    ) -> Result<Ticket, tx_transport::Error> {
        use super::datapath::{read_tx_ring_idx, ring_doorbell_tx};
        use super::dma::{split_idx, TxBd, TXBD_OPT_LS};
        let chip = self.chip_id.ok_or(tx_transport::Error::BadQueue)?;
        let queue = self
            .native_tx
            .get(info.channel as usize)
            .ok_or(tx_transport::Error::BadQueue)?;
        // Validate the native profile and extent before allocating anything.
        tx_transport::prepare_header(chip, info, 0, 0, frame)?;
        let mut owner = queue.lock();
        let ring = self.tx_rings[info.channel as usize].lock();
        // SAFETY: caller guarantees a live initialized owned AX channel.
        let (rp, _) = split_idx(unsafe { read_tx_ring_idx(&self.mmio_bar2, &ring.regs) });
        native_dma_barrier();
        // A read-pointer update alone deliberately cannot release a packet.
        drop(owner.observe_read_pointer(rp)?);
        if owner.is_full() {
            return Err(tx_transport::Error::Full);
        }
        let mask = if chip == ChipId::Rtl8852C {
            0xf_ffff_ffff
        } else {
            0xff_ffff_ffff
        };
        let payload = alloc_coherent_masked(frame.len(), DomainId::DRIVER_0, mask)
            .map_err(|_| tx_transport::Error::NoMemory)?;
        let header = tx_transport::prepare_header(chip, info, 0, payload.dma_addr().raw(), frame)?;
        let header_dma = alloc_coherent_masked(header.len(), DomainId::DRIVER_0, 0xff_ffff_ffff)
            .map_err(|_| tx_transport::Error::NoMemory)?;
        let ticket = owner
            .reserve(
                NativePacket {
                    header: header_dma,
                    frame: payload,
                },
                info.mac_id,
                info.qsel,
            )
            .map_err(|(error, _resource)| error)?;
        // No fallible preparation remains after publication. Until then abort
        // returns ordinary ownership and both mappings can be safely freed.
        let packet = owner.reserved_mut(ticket)?;
        let mut header = header;
        let body = if chip == ChipId::Rtl8852C { 32 } else { 24 };
        header[body..body + 2].copy_from_slice(&(ticket.sequence | 0x8000).to_le_bytes());
        // SAFETY: fresh owned allocations cover the exact source lengths.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), packet.frame.as_mut_ptr(), frame.len());
            core::ptr::copy_nonoverlapping(
                header.as_ptr(),
                packet.header.as_mut_ptr(),
                header.len(),
            );
        }
        packet.frame.sync(0, frame.len());
        packet.header.sync(0, header.len());
        let mut bd = TxBd {
            length: header.len() as u16,
            opt: TXBD_OPT_LS,
            ..Default::default()
        };
        bd.set_phys(packet.header.dma_addr().raw());
        let ring_dma = &self.tx_ring_dma[info.channel as usize];
        // SAFETY: owner validates slot < configured ring depth and reserves it
        // exclusively until TXBD consumption plus RPQ release.
        unsafe {
            core::ptr::write_volatile(
                (ring_dma.as_mut_ptr() as *mut TxBd).add(ticket.slot as usize),
                bd,
            );
        }
        ring_dma.sync(
            ticket.slot as usize * core::mem::size_of::<TxBd>(),
            core::mem::size_of::<TxBd>(),
        );
        owner.publish(ticket)?;
        native_dma_barrier();
        // SAFETY: same live channel; packet retention was committed above.
        unsafe {
            ring_doorbell_tx(&self.mmio_bar2, &ring.regs, owner.write_pointer());
        }
        Ok(ticket)
    }

    /// Apply one validated AX RPQ release together with the current DMA read
    /// pointer. Either arrival order is allowed; resources retire only once.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as submit_native. `bytes` must come
    /// from this device's coherently acquired RPQ (not untrusted network data).
    pub(super) unsafe fn complete_native_report(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, tx_transport::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller guarantees an acquired native RPQ/live ring.
            unsafe { self.complete_native_report_authorized(bytes) }
        })
        .map_err(|_| tx_transport::Error::Authority)?
    }

    unsafe fn complete_native_report_authorized(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, tx_transport::Error> {
        use super::datapath::read_tx_ring_idx;
        use super::dma::split_idx;
        let report = tx_transport::parse_report(bytes)?;
        let mut owner = self.native_tx[report.channel as usize].lock();
        let ring = self.tx_rings[report.channel as usize].lock();
        // SAFETY: caller guarantees a coherently acquired live AX RPQ/ring.
        let (rp, _) = split_idx(unsafe { read_tx_ring_idx(&self.mmio_bar2, &ring.regs) });
        native_dma_barrier();
        let completed = owner.observe_read_pointer(rp)?;
        let mut statuses: Vec<u8> = completed.into_iter().map(|done| done.status).collect();
        if let Some(done) = owner.observe_report(report)? {
            statuses.push(done.status);
        }
        Ok(statuses)
    }

    /// BE data submit for a probed 8922A device: build the 32-byte
    /// v2 TXWD body, reserve a slot + fill the TXBD through the
    /// Prepared owner, then publish + ring the doorbell. No current
    /// probe/network callback invokes it: firmware, RF and the
    /// mac_pre_init ring programming still need a single runtime
    /// owner. The header + frame DMA buffers are retained by the
    /// owner until the matching RPQ release retires them
    /// (`complete_be_report`).
    ///
    /// # Safety
    /// Caller has initialized firmware/station rate state, admitted
    /// the `info.mac_id` station, and programmed the rings through
    /// the Prepared owner; no reset/removal can race. `frame` is an
    /// unprotected, non-QoS native MPDU.
    pub(super) unsafe fn submit_be_data(
        &self,
        info: super::txrx_be::TxwdBeInfo,
        frame: &[u8],
    ) -> Result<Ticket, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.submit_be_data_authorized(info, frame) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn submit_be_data_authorized(
        &self,
        info: super::txrx_be::TxwdBeInfo,
        frame: &[u8],
    ) -> Result<Ticket, super::prepared_8922a::Error> {
        use super::dma::{TxBd, DEFAULT_TXBD_NUM};
        use super::prepared_8922a::{Error, MAX_HEADER_BYTES};
        use super::tx_8922a::{PrepareArgs, BUFFER_DMA_MASK, FRAME_DMA_MASK, MAX_FRAME_LEN};
        if info.channel >= 12 {
            return Err(Error::Transport(super::tx_8922a::Error::BadChannel));
        }
        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
            return Err(Error::Transport(super::tx_8922a::Error::BadFrame));
        }
        let mac_id: u8 = info
            .mac_id
            .try_into()
            .map_err(|_| Error::Transport(super::tx_8922a::Error::BadMacId))?;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let frame_dma_buf = alloc_coherent_masked(frame.len(), DomainId::DRIVER_0, FRAME_DMA_MASK)
            .map_err(|_| Error::NoMemory)?;
        // SAFETY: fresh owned allocation covers exactly the frame length.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), frame_dma_buf.as_mut_ptr(), frame.len());
        }
        frame_dma_buf.sync(0, frame.len());
        let header_dma_buf =
            alloc_coherent_masked(MAX_HEADER_BYTES, DomainId::DRIVER_0, BUFFER_DMA_MASK)
                .map_err(|_| Error::NoMemory)?;
        let mut body = [0u8; super::txrx_be::TXWD_BODY_V2_SIZE];
        super::txrx_be::encode_txwd_be(&info, &mut body)
            .ok_or(Error::Transport(super::tx_8922a::Error::BadFrame))?;
        let mut owner = owner_lock.lock();
        let ring_dma = &self.tx_ring_dma[info.channel as usize];
        // SAFETY: `ring_dma` is a fresh DMA-coherent allocation of
        // exactly `tx_ring_bytes(DEFAULT_TXBD_NUM)` bytes, so the
        // TxBd slice covers exactly the ring; the owner validates
        // slot < depth before writing.
        let bd = unsafe {
            core::slice::from_raw_parts_mut(
                ring_dma.as_mut_ptr() as *mut TxBd,
                DEFAULT_TXBD_NUM as usize,
            )
        };
        let prepared = owner.prepare_data(PrepareArgs {
            channel: info.channel,
            mac_id,
            qsel: info.qsel,
            body: &body,
            header_dma: header_dma_buf.dma_addr().raw(),
            frame_dma: frame_dma_buf.dma_addr().raw(),
            frame_len: frame.len(),
            bd,
        })?;
        let ticket = prepared.ticket;
        if prepared.header.len() > MAX_HEADER_BYTES {
            return Err(Error::Transport(super::tx_8922a::Error::BadFrame));
        }
        // SAFETY: header_dma_buf is a fresh MAX_HEADER_BYTES
        // allocation and the length check above bounds the copy.
        unsafe {
            core::ptr::copy_nonoverlapping(
                prepared.header.as_ptr(),
                header_dma_buf.as_mut_ptr(),
                prepared.header.len(),
            );
        }
        header_dma_buf.sync(0, prepared.header.len());
        // Retain both buffers until RPQ release; the queue keeps
        // only their addresses. A failed kick below keeps them
        // retained with the (unpublished) reservation.
        owner.retain_data(header_dma_buf, frame_dma_buf);
        ring_dma.sync(
            ticket.slot as usize * core::mem::size_of::<TxBd>(),
            core::mem::size_of::<TxBd>(),
        );
        native_dma_barrier();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        owner.kick_data(regs, &prepared)?;
        Ok(ticket)
    }

    /// BE H2C submit for a probed 8922A device: move one
    /// caller-framed buffer across CH12. The buffer's DMA is
    /// retained by the owner, keyed by `framed` (the identity
    /// `Prepared8922a::frame_h2c` returned when the caller framed
    /// `buf`), until the C2H completion path releases it on its
    /// matching ack.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`]:
    /// rings programmed through the Prepared owner, firmware
    /// running, no reset/removal racing.
    pub(super) unsafe fn submit_be_h2c(
        &self,
        framed: super::fwcmd_8922a::FramedH2c,
        buf: &[u8],
    ) -> Result<super::tx_8922a::H2cPrepared, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.submit_fwcmd_authorized(FwcmdHold::Ack(framed), buf) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    /// BE firmware-download submit (`rtw89_h2c_tx`, `core.c:1336`):
    /// one FWHDR_DL command (`fwdl = false`, RPKT type H2C) or one
    /// raw section packet (`fwdl = true`, RPKT type FWDL) across
    /// CH12. Neither has a firmware ack, so the owner frees the
    /// buffer once the chip consumes its TXBD
    /// (`Prepared8922a::reclaim_fwcmd`).
    ///
    /// # Safety
    /// Rings programmed through the Prepared owner, WCPU held in
    /// firmware-download mode (`fwdl_be::enable_wcpu`), no
    /// reset/removal racing.
    pub(super) unsafe fn submit_be_fwdl(
        &self,
        buf: &[u8],
        fwdl: bool,
    ) -> Result<super::tx_8922a::H2cPrepared, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live ring/FWDL-mode contract.
            unsafe { self.submit_fwcmd_authorized(FwcmdHold::Consumed { fwdl }, buf) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn submit_fwcmd_authorized(
        &self,
        hold: FwcmdHold,
        buf: &[u8],
    ) -> Result<super::tx_8922a::H2cPrepared, super::prepared_8922a::Error> {
        use super::dma::{TxBd, DEFAULT_TXBD_NUM, TXCH_CH12};
        use super::fwcmd_8922a::{fwcmd_txdesc, FWCMD_TXDESC_LEN};
        use super::prepared_8922a::Error;
        use super::tx_8922a::BUFFER_DMA_MASK;
        // `rtw89_pci_fwcmd_submit` (pci.c:1551): the 24-byte BE FWCMD
        // descriptor (dword0 = length | RPKT_TYPE H2C or FWDL)
        // precedes the payload in the same DMA buffer the TXBD
        // points at.
        let fwdl = matches!(hold, FwcmdHold::Consumed { fwdl: true });
        let desc = fwcmd_txdesc(buf.len(), fwdl)
            .ok_or(Error::Transport(super::tx_8922a::Error::BadFrame))?;
        let total = FWCMD_TXDESC_LEN + buf.len();
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let dma_buf = alloc_coherent_masked(total, DomainId::DRIVER_0, BUFFER_DMA_MASK)
            .map_err(|_| Error::NoMemory)?;
        // SAFETY: fresh owned allocation covers exactly `total` bytes:
        // the descriptor then the payload.
        unsafe {
            core::ptr::copy_nonoverlapping(desc.as_ptr(), dma_buf.as_mut_ptr(), FWCMD_TXDESC_LEN);
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                dma_buf.as_mut_ptr().add(FWCMD_TXDESC_LEN),
                buf.len(),
            );
        }
        dma_buf.sync(0, total);
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        let mut owner = owner_lock.lock();
        // `rtw89_h2c_tx`: reclaim consumed CH12 buffers first and
        // refuse when no TXBD is free (-ENOSPC in Linux).
        if owner.reclaim_fwcmd(regs)? == 0 {
            return Err(Error::Transport(super::tx_8922a::Error::Full));
        }
        let ring_dma = &self.tx_ring_dma[TXCH_CH12 as usize];
        // SAFETY: same ring-slice contract as `submit_be_data_authorized`.
        let bd = unsafe {
            core::slice::from_raw_parts_mut(
                ring_dma.as_mut_ptr() as *mut TxBd,
                DEFAULT_TXBD_NUM as usize,
            )
        };
        let prepared = owner.prepare_h2c(bd, dma_buf.dma_addr().raw(), total)?;
        match hold {
            FwcmdHold::Ack(framed) => {
                owner.retain_h2c(framed, dma_buf);
                owner.retain_fwcmd(None);
            }
            FwcmdHold::Consumed { .. } => owner.retain_fwcmd(Some(dma_buf)),
        }
        ring_dma.sync(
            prepared.slot as usize * core::mem::size_of::<TxBd>(),
            core::mem::size_of::<TxBd>(),
        );
        native_dma_barrier();
        owner.kick_h2c(regs, &prepared)?;
        Ok(prepared)
    }

    /// Apply one validated BE RPQ release (Linux's original 4-byte
    /// record) together with the current DMA read pointer state.
    /// Returns the TX status only once both the TXBD-consumption
    /// half and the report half have arrived; the retired frame's
    /// DMA buffers are freed here, never on the RP half alone.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    /// `bytes` must come from this device's coherently acquired RPQ
    /// (not untrusted network data).
    pub(super) unsafe fn complete_be_report(
        &self,
        bytes: &[u8],
    ) -> Result<Option<u8>, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller guarantees an acquired BE RPQ/live ring.
            unsafe { self.complete_be_report_authorized(bytes) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn complete_be_report_authorized(
        &self,
        bytes: &[u8],
    ) -> Result<Option<u8>, super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let completion = owner.observe_data_report(bytes)?;
        if let Some(done) = completion {
            owner.release_data(done.resource.header_dma, done.resource.frame_dma);
            Ok(Some(done.status))
        } else {
            Ok(None)
        }
    }

    /// Apply a BE TX ring read-pointer update: report the retained
    /// addresses of DMA-complete frames (the caller frees them only
    /// after the matching RPQ release — see
    /// [`Self::complete_be_report`]).
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    pub(super) unsafe fn observe_be_rp(
        &self,
        channel: u8,
    ) -> Result<Vec<super::tx_8922a::Retained>, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller guarantees a live BE ring.
            unsafe { self.observe_be_rp_authorized(channel) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn observe_be_rp_authorized(
        &self,
        channel: u8,
    ) -> Result<Vec<super::tx_8922a::Retained>, super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        let completed = owner.observe_data_rp(regs, channel)?;
        Ok(completed.into_iter().map(|done| done.resource).collect())
    }

    /// BE interrupt arm for a probed 8922A device: `rtw89_pci_request_irq`
    /// + `rtw89_pci_ops_start` through the Prepared owner — bind one
    ///   MSI vector to `line` and enable the v2 mask. Returns the CPU
    ///   vector; the caller (the future start/worker owner) records it
    ///   and drives `irq_service_8922a` / `irq_rearm_8922a` from the
    ///   line's wakeups. Refused until the rings are programmed.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    pub(super) unsafe fn irq_start_8922a(
        &self,
        line: &Arc<super::irq::Line>,
    ) -> Result<u8, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.irq_start_8922a_authorized(line) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn irq_start_8922a_authorized(
        &self,
        line: &Arc<super::irq::Line>,
    ) -> Result<u8, super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        owner.irq_start(&self.device, &self.cap, line, regs)
    }

    /// BE interrupt service for a probed 8922A device: mask, then
    /// recognize and acknowledge enabled v2 sources, classified for
    /// the completion worker. Without an armed binding this reports
    /// no events (polled mode).
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    pub(super) unsafe fn irq_service_8922a(
        &self,
    ) -> Result<super::irq::Events, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.irq_service_8922a_authorized() }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn irq_service_8922a_authorized(
        &self,
    ) -> Result<super::irq::Events, super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        owner.irq_service(regs)
    }

    /// BE interrupt re-arm for a probed 8922A device: re-enable the
    /// v2 mask after the worker drained RPQ/RXQ. Without an armed
    /// binding this is a no-op.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    pub(super) unsafe fn irq_rearm_8922a(&self) -> Result<(), super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.irq_rearm_8922a_authorized() }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn irq_rearm_8922a_authorized(&self) -> Result<(), super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        owner.irq_rearm(regs)
    }

    /// BE completion worker for a probed 8922A device: drain the
    /// RPQ/RXQ rings for the `events` `irq_service_8922a`
    /// classified, in Linux `rtw89_pci_napi_poll` order, over the
    /// probe-allocated RX buffers. TX completions free their
    /// retained DMA buffers; WIFI frames arrive admitted for a
    /// retained station; C2H messages arrive parsed and routed.
    /// When `Outcome::rearm` is true the caller runs
    /// `irq_rearm_8922a` (it cannot run inside this call: the
    /// capability park is not re-entrant).
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`].
    pub(super) unsafe fn complete_8922a(
        &self,
        events: super::irq::Events,
        budget: usize,
    ) -> Result<super::completion_8922a::Outcome, super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller guarantees an acquired BE RPQ/RXQ and
            // a live ring, as for `submit_be_data`.
            unsafe { self.complete_8922a_authorized(events, budget) }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn complete_8922a_authorized(
        &self,
        events: super::irq::Events,
        budget: usize,
    ) -> Result<super::completion_8922a::Outcome, super::prepared_8922a::Error> {
        use super::dma::{RXCH_RPQ, RXCH_RXQ};
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        // The worker reads plain slices: sync each probe-allocated
        // RX buffer for the CPU first, then hand it a mutable
        // slice over exactly its bytes. The slices die before the
        // buffers are synced back for the device.
        let mut rxq: Vec<&mut [u8]> = Vec::new();
        for buf in &self.rx_buffers[RXCH_RXQ as usize] {
            buf.sync(0, buf.as_slice().len());
            // SAFETY: `buf` is a fresh probe-allocated coherent
            // buffer; `as_mut_ptr` + length covers exactly its
            // bytes, and the slice is dropped below before any
            // other access to the buffer.
            let slice =
                unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.as_slice().len()) };
            rxq.push(slice);
        }
        let mut rpq: Vec<&mut [u8]> = Vec::new();
        for buf in &self.rx_buffers[RXCH_RPQ as usize] {
            buf.sync(0, buf.as_slice().len());
            // SAFETY: same probe-allocation contract as above.
            let slice =
                unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.as_slice().len()) };
            rpq.push(slice);
        }
        let outcome = owner.complete(regs, events, &mut rxq, &mut rpq, budget)?;
        drop(rxq);
        drop(rpq);
        for buf in &self.rx_buffers[RXCH_RXQ as usize] {
            buf.sync(0, buf.as_slice().len());
        }
        for buf in &self.rx_buffers[RXCH_RPQ as usize] {
            buf.sync(0, buf.as_slice().len());
        }
        Ok(outcome)
    }

    /// BE interrupt release for a probed 8922A device:
    /// `rtw89_pci_ops_stop` + `rtw89_pci_free_irq` through the
    /// Prepared owner. Idempotent when unarmed.
    ///
    /// # Safety
    /// Same live-ring/no-reset contract as [`Self::submit_be_data`]:
    /// no reset/removal can race, and the device can no longer
    /// target the vector once this returns.
    pub(super) unsafe fn irq_release_8922a(&self) -> Result<(), super::prepared_8922a::Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            // SAFETY: caller's live initialized ring/no-reset contract.
            unsafe { self.irq_release_8922a_authorized() }
        })
        .map_err(|_| super::prepared_8922a::Error::Authority)?
    }

    unsafe fn irq_release_8922a_authorized(&self) -> Result<(), super::prepared_8922a::Error> {
        use super::prepared_8922a::Error;
        let owner_lock = self.be_8922a.as_ref().ok_or(Error::NoOwner)?;
        let mut owner = owner_lock.lock();
        let regs = &mut super::prepared_8922a::MmioRegs(&self.mmio_bar2);
        owner.irq_release(regs, &self.cap);
        Ok(())
    }
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
///
/// **Must be 1:1 per device id.** The bus's `register_pci_driver`
/// registry is keyed on `name` and a later entry with the same name
/// overwrites the earlier one — collapsing two device ids onto one
/// name silently drops the first from the match table. Variant
/// suffixes (`-vt`, `-alt`) keep the chip-family prefix readable
/// while preserving uniqueness.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8852AE => "rtw89-8852ae",
        RTL_DEV_8852AE_VT => "rtw89-8852ae-vt",
        RTL_DEV_8852BE => "rtw89-8852be",
        RTL_DEV_8852BE_ALT => "rtw89-8852be-alt",
        RTL_DEV_8852CE => "rtw89-8852ce",
        RTL_DEV_8851BE => "rtw89-8851be",
        RTL_DEV_8922AE => "rtw89-8922ae",
        RTL_DEV_8922AE_ALT => "rtw89-8922ae-alt",
        _ => "rtw89",
    }
}

/// PCI driver match registration.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: REALTEK_VENDOR,
                device: did,
            },
            probe,
        });
        if super::bootstrap_did(did) {
            narf_bus::register_pci_remove(name_for(did), super::bootstrap::remove);
        }
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Rtw89Device) -> R) -> Option<R> {
    let g = CONTROLLER.lock();
    let arc = g.as_ref()?;
    Some(f(arc))
}

/// Test-only reset of the bound slot. Avoids cross-test leak when the
/// smoke suite re-probes; gated under `kernel-test`-style cfg so it
/// drops from production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
