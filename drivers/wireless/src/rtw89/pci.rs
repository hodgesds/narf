//! RTW89 PCI probe.
//!
//! Driver-match registration + **BAR2** mapping. Notable difference
//! from the sibling rtw88: the AX-generation 8852/8851/8922 parts
//! expose only BAR2 as a single 64 KiB window — the register block
//! Linux walks during init lives entirely inside BAR2, not BAR0.
//!
//! Linux's `rtw89/pci.c::rtw89_pci_claim_device` (~L3340..L3420) hard-
//! codes `u8 bar_id = 2;` before the `pci_iomap` call. We mirror that
//! exactly.
//!
//! ## What this file does *not* do at Stage 0/1 (deferred)
//!
//! - MSI/MSI-X vector setup. Lands with Stage-2 TX/RX rings.
//! - Firmware load. Stubbed in `fw.rs`; needs `narf-firmware` blobs
//!   for `rtw89/8852a_*.bin` / `rtw89/8852b_*.bin` etc.
//! - PHY parameter table load. Stubbed in `phy.rs`.
//! - DMA channel ring setup. The Linux code in `pci.c` allocates 13
//!   TX + 2 RX rings; that's a non-trivial pile (~600 LOC of ring
//!   bookkeeping) that lands with Stage 2.

#![allow(dead_code)]

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::efuse;
use super::mac::{self, ChipId};
use super::*;

use super::tx_transport::{self, Ticket, TxQueue};
use crate::rtw89::datapath::{RxChannelState, TxChannelState};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_io::{alloc_coherent, alloc_coherent_masked, DmaBuffer};
use narf_lib::id::DomainId;

/// One bound RTW89 device.
pub struct Rtw89Device {
    /// Retained bus identity; a repeat probe must not park the active owner.
    pub(crate) bus_addr: narf_bus::BusAddr,
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

/// Probe entry called by `narf-bus::driver_match`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let bound = CONTROLLER.lock().as_ref().map(|owner| owner.bus_addr);
    match crate::rtw88::pci_park::admission(bound, device.addr) {
        crate::rtw88::pci_park::Admission::Bound => return Ok(()),
        crate::rtw88::pci_park::Admission::ParkExtra => {
            crate::rtw88::pci_park::park(&device, &cap)
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

    let mac = dev.mac;
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

    narf_net::iface::register("wlan%d", mac, send_frame);

    spawn_pumps(arc_dev);

    Ok(())
}

fn spawn_pumps(device: Arc<Rtw89Device>) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        rtw89_rx_pump(d1).await;
    });
}

async fn rtw89_rx_pump(device: Arc<Rtw89Device>) {
    use crate::rtw89::datapath::*;
    use crate::rtw89::dma::*;

    let _ = writeln!(narf_console::Writer, "  rtw89: RX pump started");

    loop {
        if let Some(v) = device.irq_vector {
            narf_interrupts::wait::wait_for_irq(v).await;
        } else {
            narf_scheduler::yield_now().await;
        }

        {
            let mut rx_q = device.rx_rings[RXCH_RXQ as usize].lock();
            let mmio = &device.mmio_bar2;
            // SAFETY: `mmio` is the BAR2 region mapped + owned by `bring_up`;
            // `rx_q.regs` holds in-range RX ring-index register offsets for this
            // channel, so the MMIO read of the HW ring index is to a valid device
            // register.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let idx = unsafe { read_rx_ring_idx(mmio, &rx_q.regs) };
            let (rp, _) = split_idx(idx);

            // hardware advances rp when it fills a BD.
            // host wp is where we last acknowledged.
            while rx_q.state.wp != rp {
                let slot = rx_q.state.wp as usize;
                let bd_payload = device.rx_buffers[RXCH_RXQ as usize][slot].as_slice();

                if let Some(delivery) = consume_rx_bd(bd_payload) {
                    // Push to network stack.
                    // For now we just log.
                    let _ = writeln!(
                        narf_console::Writer,
                        "  rtw89: RX frame len={}",
                        delivery.rxd.pkt_len
                    );
                }

                rx_q.state.advance_wp(1);
            }

            // Acknowledge processed BDs by updating doorbell WP.
            // SAFETY: `mmio` is the BAR2 region mapped + owned by `bring_up`;
            // `rx_q.regs` holds the in-range RX doorbell register offset, and
            // `wp` is a valid write-pointer index, so this MMIO write targets a
            // valid device register.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                ring_doorbell_rx(mmio, &rx_q.regs, rx_q.state.wp);
            }
        }
    }
}

/// Bring the chip up: map BAR2, run baseline power-on, detect chip
/// version, read MAC from EFUSE, and setup DMA rings.
///
/// # Safety
/// Caller owns the device's PCI configuration and BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Rtw89Device, ProbeError> {
    crate::rtw88::pci_park::park(device, cap).map_err(|_| ProbeError::PciAccess)?;
    // SAFETY: caller-asserted BAR exclusivity. rtw89 maps BAR2 only.
    let mmio_bar2 = unsafe { map_bar_control(device, 2) }.map_err(|_| ProbeError::Bar2MapFailed)?;
    if mmio_bar2.len < 0x10000 {
        return Err(ProbeError::Bar2MapFailed);
    }

    let chip_id = ChipId::from_pci_did(device.id.device).ok_or(ProbeError::UnknownChip)?;
    if chip_id == ChipId::Rtl8922A {
        return Err(ProbeError::Efuse(efuse::EfuseError::UnsupportedChip));
    }

    // SAFETY: BAR2 mapped + owned.
    unsafe {
        mac::baseline_power_on(&mmio_bar2).map_err(ProbeError::PowerOn)?;
    }

    // SAFETY: `mmio_bar2` is the just-mapped, caller-owned BAR2 region; reading
    // the chip-version field (`R_AX_SYS_CFG1`) is an MMIO read of a valid,
    // in-range device register on this owned window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let chip_version = unsafe { mac::read_chip_version(&mmio_bar2) };
    // SAFETY: `mmio_bar2` is the caller-owned BAR2 region; `efuse::read_mac`
    // only touches in-range EFUSE registers on this owned window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mac =
        unsafe { efuse::read_mac(&mmio_bar2, chip_id, chip_version) }.map_err(ProbeError::Efuse)?;

    // ── MSI-X Setup ──
    let mut irq_vector = None;
    if let Ok(v) = narf_interrupts::vector::alloc() {
        if let Ok(mut msix) = narf_bus::msix::enable_msix(cap, device) {
            // SAFETY: `msix` is a live MSI-X table handle returned by
            // `enable_msix` for this owned device; table entry 0 is in range and
            // `v` is a freshly allocated interrupt vector, so programming the
            // vector and enabling the table writes only valid MSI-X registers.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                let _ = msix.program_vector(0, 0, v);
                let _ = msix.enable();
            }
            irq_vector = Some(v);
            narf_interrupts::install_handler(v, rtw89_isr);
        }
    }

    // ── DMA Ring Allocation ──
    use crate::rtw89::dma::*;

    let mut tx_rings = Vec::new();
    let mut tx_ring_dma = Vec::new();
    let mut native_tx = Vec::new();
    for ch in 0..12 {
        native_tx.push(IrqSafeSpinLock::new(
            TxQueue::new(ch, DEFAULT_TXBD_NUM).map_err(|_| ProbeError::NoMemory)?,
        ));
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

    // ── Hardware Ring Init ──
    for i in 0..TXCH_NUM {
        let r = &tx_rings[i].lock();
        let dma = &tx_ring_dma[i];
        let phys = dma.dma_addr().raw();
        // SAFETY: `mmio_bar2` is the caller-owned BAR2 region; `r.regs` holds the
        // in-range TX ring register offsets (`desa_l/h`, `num`, `bdram`, `idx`)
        // for this channel, so these MMIO writes target valid device registers
        // with matching access widths.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio_bar2.write32(r.regs.desa_l, (phys & 0xFFFFFFFF) as u32);
            mmio_bar2.write32(r.regs.desa_h, (phys >> 32) as u32);
            mmio_bar2.write16(r.regs.num, DEFAULT_TXBD_NUM);
            // BDRAM_CTRL init — typical values from Linux pci.c
            mmio_bar2.write32(r.regs.bdram, 0);
            // Set initial host write pointer to 0.
            mmio_bar2.write32(r.regs.idx, 0);
        }
    }

    for i in 0..RXCH_NUM {
        let r = &rx_rings[i].lock();
        let dma = &rx_ring_dma[i];
        let phys = dma.dma_addr().raw();
        // SAFETY: `mmio_bar2` is the caller-owned BAR2 region; `r.regs` holds the
        // in-range RX ring register offsets (`desa_l/h`, `num`, `idx`) for this
        // channel, so these MMIO writes target valid device registers with
        // matching access widths.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio_bar2.write32(r.regs.desa_l, (phys & 0xFFFFFFFF) as u32);
            mmio_bar2.write32(r.regs.desa_h, (phys >> 32) as u32);
            mmio_bar2.write16(r.regs.num, DEFAULT_RXBD_NUM);
            // Set WP to len-1 so all buffers are owned by HW.
            let idx_val = pack_idx(0, DEFAULT_RXBD_NUM - 1);
            mmio_bar2.write32(r.regs.idx, idx_val);
        }
    }

    Ok(Rtw89Device {
        bus_addr: device.addr,
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
        irq_vector,
    })
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
    /// selected AX channel with the exact ring geometry installed by bring_up;
    /// no reset/removal can race. The RPQ consumer must pass release records to
    /// complete_native_report. `frame` is an unprotected, non-QoS native MPDU.
    pub(super) unsafe fn submit_native(
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
