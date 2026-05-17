//! virtio-input over modern virtio-PCI transport (VirtIO 1.2 §5.8).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-input PCI device id: `0x1040 + 18 = 0x1052`.
//! Two virtqueues:
//!   * `queue 0` — eventQ: device→driver, fills descriptors with
//!     `virtio_input_event` records.
//!   * `queue 1` — statusQ: driver→device, used for LED / sound
//!     feedback. M0 leaves it idle.
//!
//! Each event is a packed 8-byte struct:
//!   ```
//!   struct virtio_input_event {
//!       u16 type;   // EV_SYN / EV_KEY / EV_REL / EV_ABS / …
//!       u16 code;   // KEY_*  / REL_*  / ABS_*  / SYN_*
//!       u32 value;  // 0 = key release, 1 = press, 2 = autorepeat
//!   }
//!   ```
//!
//! M0 surface: probe the device, bring up both queues, pre-fill the
//! eventQ with 32 receive descriptors. `drain_events` polls the used
//! ring, decodes each entry, and pushes a `narf_input::InputEvent`
//! into the global ring. IRQ-driven completion is a follow-up — the
//! poll-on-demand path is enough to validate the contract today.

use core::sync::atomic::Ordering;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use narf_input::{
    push_global, push_key, InputEvent, KeyCode, PointerButtons, PointerEvent,
};

use crate::pci::{
    discover, enable_msix_queue, map_cap, VirtioCaps, VirtioPciError, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF,
    CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

pub const VIRTIO_INPUT_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_INPUT_PCI_DEVICE: u16 = 0x1052;

/// Sizeof one `virtio_input_event` struct.
const EVENT_SIZE: usize = 8;
/// Number of receive descriptors we pre-post on eventQ.
const NUM_RX: u16 = 32;

// Linux input-event-codes (subset we decode).
//   <https://github.com/torvalds/linux/blob/master/include/uapi/linux/input-event-codes.h>
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;

// REL_X = 0, REL_Y = 1, REL_WHEEL = 8 (we ignore HWHEEL for M0).
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_WHEEL: u16 = 8;

// Mouse-button BTN_* codes (input-event-codes.h §BTN_MOUSE). These
// are EV_KEY codes that virtio-tablet / -mouse devices emit instead
// of letter keys, so they don't round-trip through the keyboard
// mapping — we translate them into PointerButtons directly.
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

#[derive(Debug)]
struct Queues {
    event_q: Virtqueue,
    /// Status queue exists for LED writes; we don't use it yet but
    /// hold the layout so the device sees both queues enabled and
    /// doesn't fail its sanity check.
    _status_q: Virtqueue,
}

#[doc(hidden)]
pub struct VirtioInputPci {
    notify: crate::pci::VirtioRegion,
    common: crate::pci::VirtioRegion,
    notify_off_multiplier: u32,
    queues: IrqSafeSpinLock<Option<Queues>>,
    rx_buf: DmaBuffer,
    _status_buf: DmaBuffer,
    _q0_layout_buf: DmaBuffer,
    event_q_notify_off: u16,
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
    rel_dx_acc: core::sync::atomic::AtomicI32,
    rel_dy_acc: core::sync::atomic::AtomicI32,
    /// Live button state, updated by BTN_* key events. virtio-input
    /// reports presses + releases independently; we mirror them
    /// into a `PointerButtons` bitset that's stamped onto each
    /// pointer event emitted at EV_SYN.
    buttons: core::sync::atomic::AtomicU8,
}

impl core::fmt::Debug for VirtioInputPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioInputPci")
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl VirtioInputPci {
    /// # Safety
    /// Caller owns the device exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset + ACK + DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // Feature negotiation: only VERSION_1.
        // SAFETY: same.
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
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, 0);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, 1u32 << (VIRTIO_F_VERSION_1 - 32));
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

        // ── eventQ (queue 0) ──
        // SAFETY: same.
        let qmax_e = unsafe {
            common.write16(CC_QUEUE_SELECT, 0);
            common.read16(CC_QUEUE_SIZE)
        };
        if qmax_e == 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let mut qsize_e = NUM_RX.min(qmax_e);
        if !qsize_e.is_power_of_two() {
            qsize_e = 1u16 << (15 - qsize_e.leading_zeros() as u16);
        }
        if qsize_e == 0 {
            qsize_e = 1;
        }
        let q0_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let layout_e = VirtqueueLayout::new(qsize_e, q0_buf.phys_addr().raw())
            .ok_or(VirtioPciError::QueueTooSmall)?;
        // SAFETY: same.
        unsafe {
            common.write16(CC_QUEUE_SIZE, qsize_e);
            common.write64_split(CC_QUEUE_DESC, layout_e.desc_table);
            common.write64_split(CC_QUEUE_DRIVER, layout_e.avail_ring);
            common.write64_split(CC_QUEUE_DEVICE, layout_e.used_ring);
            common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
        }
        // SAFETY: same.
        let event_q_notify_off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
        // SAFETY: same.
        unsafe {
            common.write16(CC_QUEUE_ENABLE, 1);
        }

        // ── statusQ (queue 1) ──
        // SAFETY: same.
        let qmax_s = unsafe {
            common.write16(CC_QUEUE_SELECT, 1);
            common.read16(CC_QUEUE_SIZE)
        };
        // statusQ is optional in some virtio-input devices; if max is 0
        // (or we can't allocate), skip it — eventQ alone is sufficient
        // for read-only consumers.
        let (status_q, q1_buf) = if qmax_s > 0 {
            let mut qsize_s = 4u16.min(qmax_s);
            if !qsize_s.is_power_of_two() {
                qsize_s = 1u16 << (15 - qsize_s.leading_zeros() as u16);
            }
            if qsize_s == 0 {
                qsize_s = 1;
            }
            let q1_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout_s = VirtqueueLayout::new(qsize_s, q1_buf.phys_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize_s);
                common.write64_split(CC_QUEUE_DESC, layout_s.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout_s.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout_s.used_ring);
                common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // SAFETY: zero-initialised coherent DMA.
            (unsafe { Virtqueue::new(layout_s) }, q1_buf)
        } else {
            // Make a placeholder zero-size Virtqueue is awkward; reuse
            // a tiny buffer + size=1 layout instead.
            let q1_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout_s = VirtqueueLayout::new(1, q1_buf.phys_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            (unsafe { Virtqueue::new(layout_s) }, q1_buf)
        };

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // SAFETY: zero-initialised coherent DMA.
        let mut event_q = unsafe { Virtqueue::new(layout_e) };

        // RX-buffer pool: pre-allocate one 4 KiB DMA frame, slice it
        // into NUM_RX × 8-byte chunks, post each as a device-writable
        // descriptor. The device drops events into these and posts
        // descriptor heads to the used ring.
        let rx_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let rx_phys = rx_buf.phys_addr().raw();
        for i in 0..qsize_e {
            let off = i as u64 * EVENT_SIZE as u64;
            let descs = [VirtqDesc {
                addr: rx_phys + off,
                len: EVENT_SIZE as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            let _ = event_q.add_buffer(&descs);
        }
        // Notify the device that descriptors are available.
        let off = (event_q_notify_off as u64) * (notify_off_multiplier as u64);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            notify.write16(off, 0);
        }

        Ok(Self {
            notify,
            common,
            notify_off_multiplier,
            queues: IrqSafeSpinLock::new(Some(Queues {
                event_q,
                _status_q: status_q,
            })),
            rx_buf,
            _status_buf: q1_buf,
            _q0_layout_buf: q0_buf,
            event_q_notify_off,
            irq_vector: None,
            msix: None,
            ready: true,
            rel_dx_acc: core::sync::atomic::AtomicI32::new(0),
            rel_dy_acc: core::sync::atomic::AtomicI32::new(0),
            buttons: core::sync::atomic::AtomicU8::new(0),
        })
    }

    /// Bind the eventQ (queue 0) to MSI-X so input events wake the kernel.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-asserted.
        let (v, table) = unsafe { enable_msix_queue(&self.common, cap, device, 0)? };
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Take the accumulated REL_X / REL_Y delta since last read.
    /// `drain_events` clears these at every EV_SYN boundary and
    /// emits a consolidated `PointerEvent`; this accessor is kept
    /// for tests + diagnostics that want to peek between SYN
    /// frames. Production cursor consumers should pop
    /// `PointerEvent`s from the global ring instead.
    pub fn take_rel_delta(&self) -> (i32, i32) {
        let dx = self
            .rel_dx_acc
            .swap(0, core::sync::atomic::Ordering::AcqRel);
        let dy = self
            .rel_dy_acc
            .swap(0, core::sync::atomic::Ordering::AcqRel);
        (dx, dy)
    }

    /// Drain whatever events the device has posted to the used ring.
    /// Decodes EV_KEY events into `KeyEvent`s and pushes them through
    /// the global input ring. Returns the number of events consumed.
    ///
    /// Rebinds each freed descriptor as a fresh receive buffer so the
    /// eventQ stays full.
    pub fn drain_events(&self) -> usize {
        let rx_phys = self.rx_buf.phys_addr().raw();
        let mut g = self.queues.lock();
        let queues = match g.as_mut() {
            Some(q) => q,
            None => return 0,
        };
        let mut count = 0usize;
        loop {
            let elem = queues.event_q.poll_used();
            let (head_u32, _len) = match elem {
                Some(x) => x,
                None => break,
            };
            let head = head_u32 as u16;
            // Read the 8-byte event from the descriptor's slot. We
            // know the head index → byte offset.
            let off = (head as u64) * EVENT_SIZE as u64;
            // SAFETY: identity-mapped DMA, 8-byte aligned read.
            let raw = unsafe { core::ptr::read_volatile((rx_phys + off) as *const [u8; 8]) };
            let etype = u16::from_le_bytes([raw[0], raw[1]]);
            let code = u16::from_le_bytes([raw[2], raw[3]]);
            let value = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

            match etype {
                EV_KEY => {
                    let pressed = value != 0;
                    // Mouse buttons (BTN_*) live in the EV_KEY code
                    // space but map onto PointerButtons, not KeyCode.
                    let btn = match code {
                        BTN_LEFT => Some(PointerButtons::LEFT),
                        BTN_RIGHT => Some(PointerButtons::RIGHT),
                        BTN_MIDDLE => Some(PointerButtons::MIDDLE),
                        _ => None,
                    };
                    if let Some(b) = btn {
                        let mut buttons = PointerButtons::from_bits_truncate(
                            self.buttons.load(Ordering::Acquire),
                        );
                        if pressed {
                            buttons.insert(b);
                        } else {
                            buttons.remove(b);
                        }
                        self.buttons.store(buttons.bits(), Ordering::Release);
                        // PointerEvent will be flushed at the next
                        // EV_SYN with the live button bitset.
                    } else {
                        let kc = KeyCode::from_evdev(code);
                        let _ = push_key(kc, pressed);
                        count += 1;
                    }
                }
                EV_REL => {
                    let delta = value as i32;
                    match code {
                        REL_X => {
                            self.rel_dx_acc.fetch_add(delta, Ordering::Relaxed);
                        }
                        REL_Y => {
                            self.rel_dy_acc.fetch_add(delta, Ordering::Relaxed);
                        }
                        REL_WHEEL => {
                            // Scroll-wheel ticks emit a Scroll event
                            // immediately — wheels are already
                            // semantically discrete, so there's
                            // nothing to accumulate-until-SYN.
                            let _ = push_global(InputEvent::Scroll(
                                narf_input::ScrollEvent { dx: 0, dy: delta },
                            ));
                        }
                        _ => {}
                    }
                }
                EV_SYN => {
                    // End of an input frame. If we accumulated REL
                    // deltas or a button-state change, emit one
                    // consolidated PointerEvent so consumers see a
                    // single transition rather than a flurry of
                    // deltas that arrive as separate REL/SYN packets.
                    let dx = self.rel_dx_acc.swap(0, Ordering::AcqRel);
                    let dy = self.rel_dy_acc.swap(0, Ordering::AcqRel);
                    let buttons =
                        PointerButtons::from_bits_truncate(self.buttons.load(Ordering::Acquire));
                    if dx != 0 || dy != 0 || buttons != PointerButtons::EMPTY {
                        let _ = push_global(InputEvent::Pointer(PointerEvent {
                            dx,
                            dy,
                            buttons,
                        }));
                    }
                }
                _ => {}
            }

            // Re-post the slot as a fresh receive buffer.
            let descs = [VirtqDesc {
                addr: rx_phys + off,
                len: EVENT_SIZE as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            queues.event_q.free_chain(head);
            let _ = queues.event_q.add_buffer(&descs);
        }
        if count > 0 {
            let off = (self.event_q_notify_off as u64) * (self.notify_off_multiplier as u64);
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped notify region.
            unsafe {
                self.notify.write16(off, 0);
            }
        }
        count
    }
}

static CONTROLLER: IrqSafeSpinLock<Option<VirtioInputPci>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let mut dev = match unsafe { VirtioInputPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: same.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vinput0"),
        kind: narf_drivers::BoundKind::Input,
        pci_vid: Some(VIRTIO_INPUT_PCI_VENDOR),
        pci_did: Some(VIRTIO_INPUT_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Input.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-input-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_INPUT_PCI_VENDOR,
            device: VIRTIO_INPUT_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&VirtioInputPci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only: replay a sequence of `(type, code, value)` triplets
/// through the same decode path `drain_events` uses, pushing onto
/// the global rings. Honours EV_KEY (BTN_* → PointerButtons), EV_REL
/// accumulators, EV_SYN PointerEvent flush, and EV_REL REL_WHEEL →
/// ScrollEvent. Returns the count of Key events pushed.
pub fn feed_synthetic_events_for_test(events: &[(u16, u16, u32)]) -> usize {
    use core::sync::atomic::AtomicI32;
    let mut count = 0usize;
    let rel_dx = AtomicI32::new(0);
    let rel_dy = AtomicI32::new(0);
    let mut buttons = PointerButtons::EMPTY;
    for &(etype, code, value) in events {
        match etype {
            EV_KEY => {
                let pressed = value != 0;
                let btn = match code {
                    BTN_LEFT => Some(PointerButtons::LEFT),
                    BTN_RIGHT => Some(PointerButtons::RIGHT),
                    BTN_MIDDLE => Some(PointerButtons::MIDDLE),
                    _ => None,
                };
                if let Some(b) = btn {
                    if pressed {
                        buttons.insert(b);
                    } else {
                        buttons.remove(b);
                    }
                } else {
                    let kc = KeyCode::from_evdev(code);
                    let _ = push_key(kc, pressed);
                    count += 1;
                }
            }
            EV_REL => {
                let delta = value as i32;
                match code {
                    REL_X => {
                        rel_dx.fetch_add(delta, Ordering::Relaxed);
                    }
                    REL_Y => {
                        rel_dy.fetch_add(delta, Ordering::Relaxed);
                    }
                    REL_WHEEL => {
                        let _ = push_global(InputEvent::Scroll(narf_input::ScrollEvent {
                            dx: 0,
                            dy: delta,
                        }));
                    }
                    _ => {}
                }
            }
            EV_SYN => {
                let dx = rel_dx.swap(0, Ordering::AcqRel);
                let dy = rel_dy.swap(0, Ordering::AcqRel);
                if dx != 0 || dy != 0 || buttons != PointerButtons::EMPTY {
                    let _ = push_global(InputEvent::Pointer(PointerEvent {
                        dx,
                        dy,
                        buttons,
                    }));
                }
            }
            _ => {}
        }
    }
    count
}
