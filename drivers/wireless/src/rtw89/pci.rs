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

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::efuse;
use super::mac::{self, ChipId};
use super::*;

use crate::rtw89::datapath::{RxChannelState, TxChannelState};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

/// One bound RTW89 device.
pub struct Rtw89Device {
    /// BAR2 MMIO mapping — the only BAR rtw89 silicon exposes.
    pub mmio_bar2: MmioRegion,
    /// Factory MAC read from logical EFUSE offset 0.
    pub mac: [u8; efuse::MAC_ADDR_LEN],
    /// PCI device id we matched on.
    pub device_id: u16,
    /// Chip family decoded from the PCI device id.
    pub chip_id: Option<ChipId>,
    /// Chip-version field from `R_AX_SYS_CFG1`.
    pub chip_version: u8,

    // ── Stage-2 Data Path ──
    pub tx_rings: Vec<IrqSafeSpinLock<TxChannelState>>,
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

/// Errors raised by the Stage-0/1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
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
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

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

    narf_net::iface::register("wlan0", mac, send_frame);

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
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<Rtw89Device, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity. rtw89 maps BAR2 only.
    let mmio_bar2 = unsafe { map_bar(device, 2) }.map_err(|_| ProbeError::Bar2MapFailed)?;

    // SAFETY: BAR2 mapped + owned.
    unsafe {
        mac::baseline_power_on(&mmio_bar2).map_err(ProbeError::PowerOn)?;
    }

    let chip_id = ChipId::from_pci_did(device.id.device).ok_or(ProbeError::UnknownChip)?;
    // SAFETY: `mmio_bar2` is the just-mapped, caller-owned BAR2 region; reading
    // the chip-version field (`R_AX_SYS_CFG1`) is an MMIO read of a valid,
    // in-range device register on this owned window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let chip_version = unsafe { mac::read_chip_version(&mmio_bar2) };
    // SAFETY: `mmio_bar2` is the caller-owned BAR2 region; `efuse::read_mac`
    // only touches in-range EFUSE registers on this owned window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let mac = unsafe { efuse::read_mac(&mmio_bar2) }.map_err(ProbeError::Efuse)?;

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
        mmio_bar2,
        mac,
        device_id: device.id.device,
        chip_id: Some(chip_id),
        chip_version,
        tx_rings,
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

/// SendFn registered with `narf_net::iface` at probe time.
pub fn send_frame(frame: &[u8]) -> Result<(), ()> {
    with_controller(|dev| {
        use crate::rtw89::datapath::*;
        use crate::rtw89::dma::*;

        // ACH0 (BE) for general data.
        let mut tx_q = dev.tx_rings[TXCH_ACH0 as usize].lock();
        let mmio = &dev.mmio_bar2;

        if tx_q.state.is_full() {
            // Poll for completion to free up slots.
            // SAFETY: `mmio` is the bound device's BAR2 region; `tx_q.regs` holds
            // the in-range TX ring-index register offset for this channel, so the
            // MMIO read of the HW ring index is to a valid device register.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let idx = unsafe { read_tx_ring_idx(mmio, &tx_q.regs) };
            let (rp, _) = split_idx(idx);
            tx_q.state.set_rp(rp);
            if tx_q.state.is_full() {
                return Err(());
            }
        }

        // 1. Stage TXWD.
        // mac_id 0, qsel BE (ACH0)
        let sub = stage_tx(TXCH_ACH0, 0, 0, frame).ok_or(())?;

        // 2. Setup DMA.
        // We reuse the pre-allocated packet buffers in a real driver,
        // but for now we allocate coherent memory for simplicity
        // (Audit #14: in production we'd use a pool).
        let buf = alloc_coherent(sub.total, DomainId::DRIVER_0).map_err(|_| ())?;
        // SAFETY: `buf` is a fresh DMA allocation of `sub.total` bytes, and
        // `stage_tx` guarantees `sub.total == sub.txwd.len() + sub.frame.len()`,
        // so both copies stay in bounds; the TXWD is written at offset 0 and the
        // frame immediately after at `sub.txwd.len()`, neither overlapping the
        // distinct source slices.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::copy_nonoverlapping(sub.txwd.as_ptr(), buf.as_mut_ptr(), sub.txwd.len());
            core::ptr::copy_nonoverlapping(
                sub.frame.as_ptr(),
                buf.as_mut_ptr().add(sub.txwd.len()),
                sub.frame.len(),
            );
        }

        // 3. Fill BD.
        let ring_dma = &dev.tx_ring_dma[TXCH_ACH0 as usize];
        let ring_ptr = ring_dma.as_mut_ptr() as *mut TxBd;
        let slot = tx_q.state.wp as usize;

        // SAFETY: `ring_ptr` points into the `DEFAULT_TXBD_NUM`-entry TX ring DMA
        // buffer for ACH0; `slot == tx_q.state.wp` is a valid in-range write
        // pointer (the full check above guarantees the ring is not full), so
        // `ring_ptr.add(slot)` is an in-bounds, properly aligned `TxBd` slot, and
        // `set_phys` records the physical address of `buf`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let mut bd = TxBd {
                length: sub.total as u16,
                opt: TXBD_OPT_LS,
                ..Default::default()
            };
            bd.set_phys(buf.dma_addr().raw());
            core::ptr::write_volatile(ring_ptr.add(slot), bd);
        }

        // 4. Advance WP + Ring Doorbell.
        tx_q.state.advance_wp(1);
        // SAFETY: `mmio` is the bound device's BAR2 region; `tx_q.regs` holds the
        // in-range TX doorbell register offset, and `wp` is a valid write-pointer
        // index, so this MMIO write targets a valid device register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            ring_doorbell_tx(mmio, &tx_q.regs, tx_q.state.wp);
        }

        // Keep buf alive (leaked for now in this Stage-2 sketch;
        // real driver would stash it for completion cleanup).
        Box::leak(Box::new(buf));

        Ok(())
    })
    .unwrap_or(Err(()))
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
