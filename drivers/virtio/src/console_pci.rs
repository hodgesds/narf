//! virtio-console over modern virtio-PCI transport (VirtIO 1.2 §5.3).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern PCI device id = `0x1040 + virtio_device_id`; virtio-console
//! is type 3, so the modern id is `0x1043`. The legacy id `0x1003`
//! is also matched.
//!
//! Two virtqueues without `VIRTIO_CONSOLE_F_MULTIPORT`:
//!   * queue 0 — receiveq(port 0): device→driver bytes
//!   * queue 1 — transmitq(port 0): driver→device bytes
//!
//! Device-specific config (§5.3.4, 16 bytes total at the Device cfg
//! cap window, all little-endian):
//! ```text
//!   +0x00 cols           u16
//!   +0x02 rows           u16
//!   +0x04 max_nr_ports   u32   (only valid with F_MULTIPORT)
//!   +0x08 emerg_wr       u32   (only valid with F_EMERG_WRITE)
//! ```
//!
//! Public surface: `bring_up`, `write_bytes`, `read_bytes`,
//! `cols`/`rows`. `register_pci_driver` registers a probe under
//! both modern and legacy VID/DIDs; `with_console` exposes the
//! singleton for the driver-side console-mux to send through.

use core::sync::atomic::{compiler_fence, Ordering};

extern crate alloc;
use alloc::vec::Vec;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, enable_msix_queue, map_cap, VirtioCaps, VirtioPciError, VirtioRegion,
    CC_DEVICE_FEATURE, CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE,
    CC_DRIVER_FEATURE_SELECT, CC_NUM_QUEUES, CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER,
    CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF, CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_CONSOLE_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_CONSOLE_PCI_DEVICE_MODERN: u16 = 0x1043;
pub const VIRTIO_CONSOLE_PCI_DEVICE_LEGACY: u16 = 0x1003;

// §5.3.3 feature bits.
pub const VIRTIO_CONSOLE_F_SIZE: u64 = 0;
pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1;
pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 2;

// Device-cfg byte offsets within the Device cap window.
pub const CFG_OFF_COLS: u64 = 0x00;
pub const CFG_OFF_ROWS: u64 = 0x02;
pub const CFG_OFF_MAX_NR_PORTS: u64 = 0x04;
pub const CFG_OFF_EMERG_WR: u64 = 0x08;
pub const CFG_LEN: usize = 16;

// Queue indices.
const QIDX_RX: u16 = 0;
const QIDX_TX: u16 = 1;

// Number of pre-posted RX descriptors (one byte per descriptor —
// chunky RX is built up by aggregating the used ring).
const RX_PREPOST: u16 = 16;
const RX_BUF_LEN: u32 = 64;

/// Decoded device-specific config. `cols`/`rows` are zero unless
/// `F_SIZE` was negotiated; `max_nr_ports` is zero unless
/// `F_MULTIPORT`; `emerg_wr` is the byte offset of the emergency-
/// write register, only meaningful with `F_EMERG_WRITE`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsoleConfig {
    pub cols: u16,
    pub rows: u16,
    pub max_nr_ports: u32,
    pub emerg_wr: u32,
}

impl ConsoleConfig {
    /// Decode a 16-byte device-cfg blob (§5.3.4).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < CFG_LEN {
            return None;
        }
        Some(Self {
            cols: u16::from_le_bytes([bytes[0], bytes[1]]),
            rows: u16::from_le_bytes([bytes[2], bytes[3]]),
            max_nr_ports: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            emerg_wr: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }

    /// Encode into 16 bytes — round-trip helper for smokes.
    pub fn encode(&self) -> [u8; CFG_LEN] {
        let mut o = [0u8; CFG_LEN];
        o[0..2].copy_from_slice(&self.cols.to_le_bytes());
        o[2..4].copy_from_slice(&self.rows.to_le_bytes());
        o[4..8].copy_from_slice(&self.max_nr_ports.to_le_bytes());
        o[8..12].copy_from_slice(&self.emerg_wr.to_le_bytes());
        o
    }
}

// ── Multiport control message (§5.3.6.5) — pure-data builders ─────

pub const CONTROL_HDR_LEN: usize = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ControlEvent {
    DeviceReady = 0,
    DeviceAdd = 1,
    DeviceRemove = 2,
    PortReady = 3,
    ConsolePort = 4,
    Resize = 5,
    PortOpen = 6,
    PortName = 7,
    Unknown = 0xFFFF,
}

impl ControlEvent {
    pub fn from_raw(b: u16) -> Self {
        match b {
            0 => Self::DeviceReady,
            1 => Self::DeviceAdd,
            2 => Self::DeviceRemove,
            3 => Self::PortReady,
            4 => Self::ConsolePort,
            5 => Self::Resize,
            6 => Self::PortOpen,
            7 => Self::PortName,
            _ => Self::Unknown,
        }
    }
}

/// Encode an 8-byte control header: id(u32 LE) | event(u16 LE) | value(u16 LE).
pub fn build_control(id: u32, event: ControlEvent, value: u16) -> [u8; CONTROL_HDR_LEN] {
    let mut o = [0u8; CONTROL_HDR_LEN];
    o[0..4].copy_from_slice(&id.to_le_bytes());
    let ev = if matches!(event, ControlEvent::Unknown) {
        0xFFFFu16
    } else {
        event as u16
    };
    o[4..6].copy_from_slice(&ev.to_le_bytes());
    o[6..8].copy_from_slice(&value.to_le_bytes());
    o
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ControlMsg {
    pub id: u32,
    pub event: ControlEvent,
    pub value: u16,
}

pub fn decode_control(b: &[u8]) -> Option<ControlMsg> {
    if b.len() < CONTROL_HDR_LEN {
        return None;
    }
    let id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let ev = u16::from_le_bytes([b[4], b[5]]);
    let value = u16::from_le_bytes([b[6], b[7]]);
    Some(ControlMsg {
        id,
        event: ControlEvent::from_raw(ev),
        value,
    })
}

// ── Live driver state ────────────────────────────────────────────

pub struct VirtioConsolePci {
    common: VirtioRegion,
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    rx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    _rx_buf: DmaBuffer,
    _tx_buf: DmaBuffer,
    /// RX descriptor scratch — RX_PREPOST × RX_BUF_LEN bytes.
    rx_pool: DmaBuffer,
    /// Map of descriptor head index → byte offset into `rx_pool`.
    rx_slots: IrqSafeSpinLock<Vec<u64>>,
    cfg: ConsoleConfig,
    rx_notify_off: u16,
    tx_notify_off: u16,
    /// Allocated MSI-X IDT vector (queue 0 / receiveq); `None` until
    /// `enable_msix` runs. Consumers wait via
    /// `narf_interrupts::wait_for_irq(irq_vector)`.
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
}

impl core::fmt::Debug for VirtioConsolePci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioConsolePci")
            .field("ready", &self.ready)
            .field("cols", &self.cfg.cols)
            .field("rows", &self.cfg.rows)
            .finish_non_exhaustive()
    }
}

impl VirtioConsolePci {
    /// Bring up the console on its first port (queues 0 + 1). Does
    /// not negotiate `F_MULTIPORT` — single-port consoles are the
    /// QEMU default and the simplest useful surface.
    ///
    /// # Safety
    /// Caller owns the device's BAR window exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk against identity-mapped cfg.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-asserted exclusive ownership.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        // `device_cfg` is optional in the spec — without it cols/rows/emerg_wr default to zero.
        let device_cfg = match caps.device_cfg.as_ref() {
            // SAFETY: same (caller-asserted exclusive ownership).
            Some(c) => Some(unsafe { map_cap(device, c) }?),
            None => None,
        };
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset → ACK → DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // Feature negotiation: VERSION_1 only. F_SIZE optional —
        // we'll pick it up if the device advertises it because
        // there's no harm to the wire-up either way.
        // SAFETY: identity-mapped MMIO.
        let feats_lo = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            common.read32(CC_DEVICE_FEATURE)
        };
        // SAFETY: same.
        let feats_hi = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 1);
            common.read32(CC_DEVICE_FEATURE)
        };
        let feats = (feats_hi as u64) << 32 | feats_lo as u64;
        if feats & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let mut want = 1u64 << VIRTIO_F_VERSION_1;
        if feats & (1u64 << VIRTIO_CONSOLE_F_SIZE) != 0 {
            want |= 1u64 << VIRTIO_CONSOLE_F_SIZE;
        }
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, want as u32);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, (want >> 32) as u32);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: same.
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Read device-specific cfg if present.
        let cfg = match device_cfg.as_ref() {
            Some(d) => {
                // SAFETY: identity-mapped MMIO; offsets are within the mapped region.
                unsafe {
                    ConsoleConfig {
                        cols: d.read16(CFG_OFF_COLS),
                        rows: d.read16(CFG_OFF_ROWS),
                        max_nr_ports: d.read32(CFG_OFF_MAX_NR_PORTS),
                        emerg_wr: d.read32(CFG_OFF_EMERG_WR),
                    }
                }
            }
            None => ConsoleConfig::default(),
        };

        // SAFETY: identity-mapped MMIO.
        let n_q = unsafe { common.read16(CC_NUM_QUEUES) };
        if n_q < 2 {
            return Err(VirtioPciError::NoQueues);
        }

        // RX queue (index 0) + TX queue (index 1).
        let (rx_buf, rx_q, rx_notify_off) =
            // SAFETY: identity-mapped MMIO.
            unsafe { setup_queue(&common, QIDX_RX) }?;
        let (tx_buf, tx_q, tx_notify_off) =
            // SAFETY: same.
            unsafe { setup_queue(&common, QIDX_TX) }?;

        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // RX pool — pre-post RX_PREPOST descriptors so the device
        // can deliver bytes immediately.
        let rx_pool =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let rx_pool_phys = rx_pool.phys_addr().raw();
        // SAFETY: page-sized DMA buffer.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(rx_pool_phys).kernel_mut_ptr::<u8>(),
                0,
                4096,
            );
        }

        let mut rx_q_lock = IrqSafeSpinLock::new(Some(rx_q));
        let mut rx_slots: Vec<u64> = Vec::with_capacity(RX_PREPOST as usize);
        {
            let mut g = rx_q_lock.lock();
            let q = g.as_mut().unwrap();
            for i in 0..RX_PREPOST {
                let off = (i as u64) * (RX_BUF_LEN as u64);
                let addr = rx_pool_phys + off;
                let descs = [VirtqDesc {
                    addr,
                    len: RX_BUF_LEN,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }];
                if let Some(_h) = q.add_buffer(&descs) {
                    rx_slots.push(off);
                } else {
                    break;
                }
            }
        }
        // Kick the device so it sees the available RX descriptors.
        let off = (rx_notify_off as u64) * (notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            notify.write16(off, QIDX_RX);
        }

        // Force the lock guard to drop before moving rx_q_lock.
        // (rx_q_lock contains the populated queue; we move it into self.)
        let _ = &mut rx_q_lock;

        Ok(Self {
            common,
            notify,
            notify_off_multiplier,
            rx_queue: rx_q_lock,
            tx_queue: IrqSafeSpinLock::new(Some(tx_q)),
            _rx_buf: rx_buf,
            _tx_buf: tx_buf,
            rx_pool,
            rx_slots: IrqSafeSpinLock::new(rx_slots),
            cfg,
            rx_notify_off,
            tx_notify_off,
            irq_vector: None,
            msix: None,
            ready: true,
        })
    }

    /// Bind queue 0 (receiveq) to an MSI-X vector so the kernel
    /// gets woken on incoming console bytes.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, QIDX_RX)? };
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    pub fn cols(&self) -> u16 {
        self.cfg.cols
    }
    pub fn rows(&self) -> u16 {
        self.cfg.rows
    }
    pub fn config(&self) -> ConsoleConfig {
        self.cfg
    }

    /// Write `data` to the console (driver → device) via the
    /// transmit queue. Returns the number of bytes accepted on
    /// success — equal to `data.len()` for the polled path.
    pub fn write_bytes(&self, data: &[u8]) -> Result<usize, VirtioPciError> {
        if data.is_empty() {
            return Ok(0);
        }
        if data.len() > 4096 {
            return Err(VirtioPciError::QueueTooSmall);
        }

        // Stage payload in a fresh DMA page.
        let buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let phys = buf.phys_addr().raw();
        // SAFETY: page-sized DMA buffer.
        unsafe {
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(phys + i as u64).kernel_mut_ptr::<u8>(),
                    b,
                );
            }
        }
        // TX descriptor: device-readable (no F_WRITE).
        let descs = [VirtqDesc {
            addr: phys,
            len: data.len() as u32,
            flags: 0,
            next: 0,
        }];
        let head = {
            let mut g = self.tx_queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (self.tx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, QIDX_TX);
        }

        // Poll for completion. responsive_spin_until ticks sleep_pumps so
        // cursor/FB stay alive on a slow / wedged device.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.tx_queue.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let mut g = self.tx_queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        let _ = buf;
        Ok(data.len())
    }

    /// Drain any RX bytes the device wrote into our pre-posted
    /// descriptors. Returns up to `out.len()` bytes; replaces each
    /// consumed descriptor with a fresh one so the receive path
    /// stays primed.
    pub fn read_bytes(&self, out: &mut [u8]) -> Result<usize, VirtioPciError> {
        if out.is_empty() {
            return Ok(0);
        }
        let pool_phys = self.rx_pool.phys_addr().raw();
        let mut written = 0usize;

        loop {
            if written >= out.len() {
                break;
            }
            let elem = {
                let mut g = self.rx_queue.lock();
                let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
                q.poll_used()
            };
            let (id, len) = match elem {
                Some(p) => p,
                None => break,
            };
            let slot_off = {
                let slots = self.rx_slots.lock();
                slots.get(id as usize).copied()
            };
            let off = match slot_off {
                Some(o) => o,
                None => break,
            };
            let n = (len as usize)
                .min(out.len() - written)
                .min(RX_BUF_LEN as usize);
            // SAFETY: identity-mapped DMA buffer; offset in-pool.
            unsafe {
                for i in 0..n {
                    out[written + i] = core::ptr::read_volatile(
                        narf_memory::PhysAddr::new(pool_phys + off + i as u64).kernel_ptr::<u8>(),
                    );
                }
            }
            written += n;
            // Re-post this descriptor.
            let descs = [VirtqDesc {
                addr: pool_phys + off,
                len: RX_BUF_LEN,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            let mut g = self.rx_queue.lock();
            if let Some(q) = g.as_mut() {
                q.free_chain(id as u16);
                let _ = q.add_buffer(&descs);
            }
        }

        if written > 0 {
            let off = (self.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped notify region.
            unsafe {
                self.notify.write16(off, QIDX_RX);
            }
        }
        Ok(written)
    }
}

/// Helper: select queue `idx`, allocate a 4 KiB backing page, sized
/// power-of-two queue. Returns the backing buf, the live `Virtqueue`,
/// and the queue's `notify_off`.
unsafe fn setup_queue(
    common: &VirtioRegion,
    idx: u16,
) -> Result<(DmaBuffer, Virtqueue, u16), VirtioPciError> {
    // SAFETY: identity-mapped MMIO.
    let qsize_max = unsafe {
        common.write16(CC_QUEUE_SELECT, idx);
        common.read16(CC_QUEUE_SIZE)
    };
    if qsize_max == 0 {
        return Err(VirtioPciError::QueueTooSmall);
    }
    let qsize = qsize_max.min(64).next_power_of_two() / 2;
    let qsize = if qsize == 0 { 4 } else { qsize.min(qsize_max) };

    let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
    let layout =
        VirtqueueLayout::new(qsize, buf.phys_addr().raw()).ok_or(VirtioPciError::QueueTooSmall)?;

    // SAFETY: identity-mapped MMIO.
    unsafe {
        common.write16(CC_QUEUE_SIZE, qsize);
        common.write64_split(CC_QUEUE_DESC, layout.desc_table);
        common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
        common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
    }
    // SAFETY: same.
    let notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
    // SAFETY: same.
    unsafe {
        common.write16(CC_QUEUE_ENABLE, 1);
    }

    // SAFETY: Virtqueue::new wipes the layout regions; alloc_coherent
    // pages are recycled and may carry stale bytes.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let q = unsafe { Virtqueue::new(layout) };
    Ok((buf, q, notify_off))
}

// ── Singleton + PCI driver registration ──────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<VirtioConsolePci>> = IrqSafeSpinLock::new(None);

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}
pub fn with_controller<R>(f: impl FnOnce(&VirtioConsolePci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // Enable MEM_SPACE + BUS_MASTER so the device can DMA.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: probe contract — bus hands us exclusive BAR ownership.
    let mut dev = match unsafe { VirtioConsolePci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) }; // best-effort
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vcon0"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    use narf_bus::{register_pci_driver as reg, MatchKind, PciMatch};
    reg(PciMatch {
        name: "virtio-console-pci-modern",
        kind: MatchKind::VendorDevice {
            vendor: VIRTIO_CONSOLE_PCI_VENDOR,
            device: VIRTIO_CONSOLE_PCI_DEVICE_MODERN,
        },
        probe,
    });
    reg(PciMatch {
        name: "virtio-console-pci-legacy",
        kind: MatchKind::VendorDevice {
            vendor: VIRTIO_CONSOLE_PCI_VENDOR,
            device: VIRTIO_CONSOLE_PCI_DEVICE_LEGACY,
        },
        probe,
    });
}

mod tests;
