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
    abs, push_global, push_key, AbsoluteEvent, ButtonEvent, InputEvent, KeyCode, PointerButtons,
    PointerEvent, TouchEvent,
};

/// True when `code` belongs to the Linux evdev BTN_* range but
/// isn't already routed to PointerButtons or MT-slot-0 by the
/// caller. Used to fan EV_KEY into either Key (KeyCode), Button
/// (gamepad / joystick / digitiser), or pointer/touch handling.
fn is_gamepad_or_aux_btn(code: u16) -> bool {
    (0x100..0x300).contains(&code)
}

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
const EV_ABS: u16 = 0x03;

// REL_X = 0, REL_Y = 1, REL_HWHEEL = 6, REL_WHEEL = 8.
// Linux input-event-codes.h §REL_*. REL_HWHEEL is the horizontal
// (left/right) scroll axis that trackballs + tilt-wheel mice
// emit; we map it to ScrollEvent.dx so consumers see the same
// shape used by REL_WHEEL.
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_HWHEEL: u16 = 6;
const REL_WHEEL: u16 = 8;

// Mouse-button BTN_* codes (input-event-codes.h §BTN_MOUSE). These
// are EV_KEY codes that virtio-tablet / -mouse devices emit instead
// of letter keys, so they don't round-trip through the keyboard
// mapping — we translate them into PointerButtons directly.
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;
const BTN_FORWARD: u16 = 0x115;
const BTN_BACK: u16 = 0x116;
const BTN_TASK: u16 = 0x117;
// BTN_TOUCH is the "any finger is on the digitiser" signal. Tablets
// emit it alongside ABS_X/ABS_Y to mark proximity / contact. We
// don't pipe it to PointerButtons (a tap isn't a left-click);
// consumers that care correlate it with the touch slot state.
const BTN_TOUCH: u16 = 0x14a;

/// Largest multi-touch slot we track per controller. Protocol-B
/// devices typically advertise 5–10 slots; modern trackpads and
/// touchscreens cap at 10 simultaneous contacts. Higher slot
/// indices coming off the wire are silently dropped.
const MAX_MT_SLOTS: usize = 10;

// virtio-input device-config selector codes (VirtIO 1.2 §5.8.4).
const CFG_ID_NAME: u8 = 0x01;
const CFG_EV_BITS: u8 = 0x11;
const CFG_ABS_INFO: u8 = 0x12;

/// EV_LED event type (Linux input-event-codes.h §EV_*).
const EV_LED: u16 = 0x11;

/// LED_* codes we mirror from `narf_input::current_modifiers()` —
/// the three keyboard indicator LEDs every laptop ships with.
const LED_NUMLOCK: u8 = 0x00;
const LED_CAPSLOCK: u8 = 0x01;
const LED_SCROLLLOCK: u8 = 0x02;

/// statusQ scratch buffer slot count. Each LED transition writes
/// one 8-byte event into a slot. 64 slots × 8 B = 512 bytes —
/// fits in the single 4 KiB DMA page with room to spare. Cyclic
/// reuse with opportunistic used-ring drain in `set_led`.
const LED_SLOTS: u64 = 64;

// Device-config register offsets (within the device-cfg cap).
const CFG_SELECT: u64 = 0x00;
const CFG_SUBSEL: u64 = 0x01;
const CFG_SIZE: u64 = 0x02;
const CFG_PAYLOAD: u64 = 0x08;
const CFG_PAYLOAD_MAX: usize = 128;

/// Largest `ABS_*` axis code we track bounds for. Covers everything
/// through the MT range (ABS_MT_TOOL_Y = 0x3D). Codes above are
/// device-specific and rare enough to skip until needed.
const ABS_BOUNDS_LEN: usize = 0x40;

/// Per-slot state for evdev multi-touch protocol B. We mirror the
/// axes the device writes (`ABS_MT_TRACKING_ID`, `ABS_MT_POSITION_X
/// /_Y`, `ABS_MT_PRESSURE`) into one snapshot per slot, and flip
/// `dirty` whenever any of them changes. EV_SYN walks the array and
/// emits a `TouchEvent` for every dirty slot, clearing the flag.
///
/// `tracking_id == None` represents "slot released" — the
/// evdev convention is `tracking_id = -1` on the wire; the driver
/// translates that to `None` once and consumers see a clean
/// `Option<i32>` instead of a magic sentinel.
///
/// `was_active` lets the SYN flush compute the explicit
/// [`narf_input::TouchState`] (Down / Move / Up) the consumer
/// surface uses — Down on `!was_active && tracking_id.is_some()`,
/// Up on `was_active && tracking_id.is_none()`, Move otherwise.
#[derive(Copy, Clone, Default, Debug)]
struct MtSlot {
    tracking_id: Option<i32>,
    x: i32,
    y: i32,
    pressure: i32,
    dirty: bool,
    /// Whether the slot held a live tracking id at the *previous*
    /// SYN boundary. Used by the flush to derive Down vs Move
    /// without re-scanning history.
    was_active: bool,
}

/// Read the (`select`, `subsel`) device-config block. Writes the
/// selector pair, samples `size`, and copies up to `size` bytes
/// (capped at the 128-byte payload window) into `out`. Returns the
/// number of bytes actually copied.
///
/// # Safety
/// `region` must be a live virtio-input device-cfg mapping.
unsafe fn read_cfg(
    region: &crate::pci::VirtioRegion,
    select: u8,
    subsel: u8,
    out: &mut [u8],
) -> usize {
    // SAFETY: caller-asserted; offsets within the 8-byte cfg header.
    unsafe {
        region.write8(CFG_SELECT, select);
        region.write8(CFG_SUBSEL, subsel);
    }
    // Devices need a moment to populate the payload window. We
    // re-read `size` to determine validity — virtio-input's contract
    // is that `size > 0` indicates the data at `u` is valid for the
    // current (`select`, `subsel`).
    // SAFETY: same.
    let size = unsafe { region.read8(CFG_SIZE) } as usize;
    let take = size.min(CFG_PAYLOAD_MAX).min(out.len());
    for i in 0..take {
        // SAFETY: payload window is exactly CFG_PAYLOAD_MAX bytes.
        out[i] = unsafe { region.read8(CFG_PAYLOAD + i as u64) };
    }
    take
}

/// Read the device name + per-axis bounds + LED bitmap. Returns
/// the (name, axis_info[], led_bits) triple. Best-effort — missing
/// selectors leave fields empty / `None` / `0`. Called once at
/// probe.
///
/// # Safety
/// `region` must be a live virtio-input device-cfg mapping.
unsafe fn read_device_metadata(
    region: &crate::pci::VirtioRegion,
) -> (
    alloc::string::String,
    [Option<narf_input::AxisInfo>; ABS_BOUNDS_LEN],
    u8,
) {
    // Name: ASCII, null-padded. Trim trailing NULs + non-printable.
    let mut name_buf = [0u8; 128];
    // SAFETY: caller-asserted.
    let n = unsafe { read_cfg(region, CFG_ID_NAME, 0, &mut name_buf) };
    let trimmed = &name_buf[..n];
    let stop = trimmed
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(trimmed.len());
    let name = alloc::string::String::from_utf8_lossy(&trimmed[..stop]).into_owned();

    // EV_BITS for EV_ABS tells us which axes have abs-info to read.
    let mut ev_abs_bits = [0u8; 128];
    // SAFETY: same. EV_ABS = 3 (Linux input-event-codes.h).
    let nbits = unsafe { read_cfg(region, CFG_EV_BITS, 3, &mut ev_abs_bits) };
    let mut axis_info = [None; ABS_BOUNDS_LEN];
    for axis in 0..ABS_BOUNDS_LEN {
        let byte = axis / 8;
        let bit = axis % 8;
        if byte >= nbits {
            break;
        }
        if (ev_abs_bits[byte] >> bit) & 1 == 0 {
            continue;
        }
        let mut abs_buf = [0u8; 20];
        // SAFETY: same.
        let got = unsafe { read_cfg(region, CFG_ABS_INFO, axis as u8, &mut abs_buf) };
        if got >= 20 {
            axis_info[axis] = narf_input::AxisInfo::from_virtio_absinfo(&abs_buf);
        }
    }

    // LED support: CFG_EV_BITS with subsel=EV_LED returns a
    // bitmap of supported LED_* codes (one bit per code). For a
    // virtio-keyboard this typically advertises NUM/CAPS/SCROLL.
    // Mouse / tablet devices return size=0 here and we'll skip
    // LED writes for them.
    let mut led_buf = [0u8; 16];
    // SAFETY: same.
    let nled = unsafe { read_cfg(region, CFG_EV_BITS, EV_LED as u8, &mut led_buf) };
    let led_bits = if nled == 0 { 0u8 } else { led_buf[0] };

    (name, axis_info, led_bits)
}

#[derive(Debug)]
struct Queues {
    event_q: Virtqueue,
    /// Status queue (driver→device). LED indicator writes go
    /// through here. Devices that don't expose LED support
    /// (mouse / tablet) still allocate the queue so the device's
    /// sanity check passes — they just ignore the EV_LED events
    /// or post them straight back to the used ring.
    status_q: Virtqueue,
}

#[doc(hidden)]
pub struct VirtioInputPci {
    notify: crate::pci::VirtioRegion,
    common: crate::pci::VirtioRegion,
    /// Device-specific config region (VirtIO 1.2 §5.8.4). Holds the
    /// `select`/`subsel`/`size` selector + 128-byte payload window.
    /// `None` when the device didn't expose a Device cfg cap —
    /// older QEMU builds skip it for virtio-multitouch and the
    /// driver carries on without axis bounds in that case.
    device_cfg: Option<crate::pci::VirtioRegion>,
    /// Human-readable device name pulled from
    /// `VIRTIO_INPUT_CFG_ID_NAME` at probe. Empty when the cap
    /// wasn't present or the device left the field blank.
    name: alloc::string::String,
    /// Per-axis bounds. Indexed by ABS_* code; `Some` for axes the
    /// device advertised through `VIRTIO_INPUT_CFG_ABS_INFO`. Read
    /// once at probe — virtio-input devices don't renegotiate.
    axis_info: [Option<narf_input::AxisInfo>; ABS_BOUNDS_LEN],
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
    /// Multi-touch slot state (evdev protocol B). `current_slot`
    /// is the slot selected by the most recent `ABS_MT_SLOT`; all
    /// subsequent `ABS_MT_*` axes update `slots[current_slot]`
    /// until the next slot switch. Wrapped together so the EV_SYN
    /// flush sees one consistent snapshot.
    mt: IrqSafeSpinLock<MtState>,
    /// Buffer holding EV_LED event payloads for statusQ writes.
    /// Sliced into `LED_SLOTS` × 8-byte cells; `led_slot_next`
    /// cycles through them. Each set_led drains the used ring
    /// opportunistically so the device gets a chance to ack
    /// before we wrap.
    led_event_buf: DmaBuffer,
    led_slot_next: core::sync::atomic::AtomicU64,
    /// statusQ notify offset (within the Notify cap). `None` when
    /// the device didn't expose a usable statusQ — set_led / sync_leds
    /// short-circuit in that case.
    status_q_notify_off: Option<u16>,
    /// Bitmap of LED_* codes the device advertises through
    /// `CFG_EV_BITS(EV_LED)`. Bit N set ⇒ LED_N supported. Devices
    /// without any LED bits skip sync_leds entirely so we don't
    /// pollute statusQ on mouse / tablet hardware.
    led_bits: u8,
    /// Last-known LED bitmap we wrote. Diff'd against the live
    /// modifier state in sync_leds so only transitions hit
    /// statusQ.
    last_leds: core::sync::atomic::AtomicU8,
}

#[derive(Debug)]
struct MtState {
    slots: [MtSlot; MAX_MT_SLOTS],
    current_slot: u8,
}

impl Default for MtState {
    fn default() -> Self {
        Self {
            slots: [MtSlot::default(); MAX_MT_SLOTS],
            current_slot: 0,
        }
    }
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
        let (status_q, q1_buf, status_q_notify_off) = if qmax_s > 0 {
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
            }
            // SAFETY: same.
            let s_notify = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // SAFETY: zero-initialised coherent DMA.
            (unsafe { Virtqueue::new(layout_s) }, q1_buf, Some(s_notify))
        } else {
            // Make a placeholder zero-size Virtqueue is awkward; reuse
            // a tiny buffer + size=1 layout instead. LED writes are
            // disabled in this branch via status_q_notify_off = None.
            let q1_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout_s = VirtqueueLayout::new(1, q1_buf.phys_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            (unsafe { Virtqueue::new(layout_s) }, q1_buf, None)
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

        // Device-specific config region (optional). Used after
        // DRIVER_OK so the device is in its operating state for
        // any spec-defined config-read interactions.
        let device_cfg = if let Some(cap) = caps.device_cfg.as_ref() {
            // SAFETY: caller-owned device.
            match unsafe { map_cap(device, cap) } {
                Ok(r) => Some(r),
                Err(_) => None,
            }
        } else {
            None
        };
        let (name, axis_info, led_bits) = match device_cfg.as_ref() {
            // SAFETY: device-cfg region was just mapped; read_cfg
            // bounds-checks every offset.
            Some(r) => unsafe { read_device_metadata(r) },
            None => (alloc::string::String::new(), [None; ABS_BOUNDS_LEN], 0u8),
        };

        // Scratch buffer for outbound EV_LED events. One 4 KiB
        // page is enough for LED_SLOTS × 8-byte events with room
        // to spare.
        let led_event_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        Ok(Self {
            notify,
            common,
            device_cfg,
            name,
            axis_info,
            notify_off_multiplier,
            queues: IrqSafeSpinLock::new(Some(Queues { event_q, status_q })),
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
            mt: IrqSafeSpinLock::new(MtState::default()),
            led_event_buf,
            led_slot_next: core::sync::atomic::AtomicU64::new(0),
            status_q_notify_off,
            led_bits,
            last_leds: core::sync::atomic::AtomicU8::new(0),
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

    /// Device's reported human-readable name (e.g. "QEMU Virtio
    /// Tablet"). Empty when the device didn't expose a Device cfg
    /// cap or left `VIRTIO_INPUT_CFG_ID_NAME` blank.
    pub fn device_name(&self) -> &str {
        &self.name
    }

    /// Bounds + filter parameters the device advertised for `axis`.
    /// Returns `None` for axes the device doesn't expose or that
    /// fall outside the tracked `ABS_*` range.
    pub fn axis_info(&self, axis: u16) -> Option<narf_input::AxisInfo> {
        let idx = axis as usize;
        if idx >= ABS_BOUNDS_LEN {
            return None;
        }
        self.axis_info[idx]
    }

    /// Bitmap of LED_* codes the device supports. Bit N set ⇒
    /// LED_N can be driven through `set_led`. Used by sync_leds to
    /// skip devices (mouse, tablet) that don't have any LEDs.
    pub fn led_support(&self) -> u8 {
        self.led_bits
    }

    /// Post one EV_LED event to statusQ. `led_code` is a Linux
    /// LED_* code; `on` lights or extinguishes that indicator.
    /// Devices that didn't expose a usable statusQ silently return
    /// `Ok(())` — the rest of the driver shouldn't gate on LED
    /// support.
    pub fn set_led(&self, led_code: u8, on: bool) -> Result<(), VirtioPciError> {
        let notify_off = match self.status_q_notify_off {
            Some(o) => o,
            None => return Ok(()),
        };
        // Pick the next 8-byte slot in led_event_buf. Cyclic wrap;
        // 64 slots is plenty since LED transitions track human
        // keystrokes (a few per second at most).
        let slot = self
            .led_slot_next
            .fetch_add(1, Ordering::AcqRel)
            .rem_euclid(LED_SLOTS);
        let phys = self.led_event_buf.phys_addr().raw();
        let off = slot.checked_mul(8).ok_or(VirtioPciError::QueueTooSmall)?;
        // virtio_input_event { type=EV_LED, code=led_code, value=on }
        let etype = EV_LED;
        let code = led_code as u16;
        let value: u32 = if on { 1 } else { 0 };
        let mut event = [0u8; 8];
        event[0..2].copy_from_slice(&etype.to_le_bytes());
        event[2..4].copy_from_slice(&code.to_le_bytes());
        event[4..8].copy_from_slice(&value.to_le_bytes());
        // SAFETY: phys + off + 8 ≤ phys + 4096 because slot < 64.
        unsafe {
            core::ptr::write_volatile((phys + off) as *mut [u8; 8], event);
        }
        let descs = [VirtqDesc {
            addr: phys + off,
            len: 8,
            flags: 0,
            next: 0,
        }];
        {
            let mut g = self.queues.lock();
            let queues = match g.as_mut() {
                Some(q) => q,
                None => return Err(VirtioPciError::NoQueues),
            };
            // Reclaim any acked descriptors before we add. Cheap
            // best-effort drain — keeps the descriptor table free
            // even when LED writes happen in a tight burst.
            while let Some((id, _)) = queues.status_q.poll_used() {
                queues.status_q.free_chain(id as u16);
            }
            queues
                .status_q
                .add_buffer(&descs)
                .ok_or(VirtioPciError::QueueTooSmall)?;
        }
        let off = (notify_off as u64) * (self.notify_off_multiplier as u64);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region. Queue 1 = statusQ.
        unsafe {
            self.notify.write16(off, 1);
        }
        Ok(())
    }

    /// Diff the live `narf_input::current_modifiers()` lock bits
    /// against the last-known LED state and post deltas through
    /// `set_led`. Idempotent — re-calling without a state change
    /// touches statusQ zero times. Skipped entirely when the device
    /// advertises no LED support.
    pub fn sync_leds(&self) {
        if self.led_bits == 0 {
            return;
        }
        let mods = narf_input::current_modifiers();
        let mut want = 0u8;
        if mods.contains(narf_input::Modifiers::NUM_LOCK) {
            want |= 1 << LED_NUMLOCK;
        }
        if mods.contains(narf_input::Modifiers::CAPS_LOCK) {
            want |= 1 << LED_CAPSLOCK;
        }
        if mods.contains(narf_input::Modifiers::SCROLL_LOCK) {
            want |= 1 << LED_SCROLLLOCK;
        }
        // Mask out LEDs the device doesn't support so we don't
        // emit no-op events.
        want &= self.led_bits;
        let prev = self.last_leds.load(Ordering::Acquire);
        let diff = prev ^ want;
        if diff == 0 {
            return;
        }
        for led in 0..8u8 {
            if (diff >> led) & 1 == 0 {
                continue;
            }
            let on = (want >> led) & 1 != 0;
            let _ = self.set_led(led, on);
        }
        self.last_leds.store(want, Ordering::Release);
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
                        BTN_SIDE => Some(PointerButtons::SIDE),
                        BTN_EXTRA => Some(PointerButtons::EXTRA),
                        BTN_FORWARD => Some(PointerButtons::FORWARD),
                        BTN_BACK => Some(PointerButtons::BACK),
                        BTN_TASK => Some(PointerButtons::TASK),
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
                    } else if code == BTN_TOUCH {
                        // BTN_TOUCH proxies finger-on-digitiser for
                        // tablets that don't use full MT-protocol-B.
                        // Mirror it onto slot 0 so a single-finger
                        // tap is observable as a Touch event without
                        // the device having to send ABS_MT_*.
                        let mut g = self.mt.lock();
                        let slot = &mut g.slots[0];
                        if pressed {
                            if slot.tracking_id.is_none() {
                                slot.tracking_id = Some(0);
                            }
                        } else {
                            slot.tracking_id = None;
                        }
                        slot.dirty = true;
                    } else if is_gamepad_or_aux_btn(code) {
                        // Gamepad face / shoulder / D-pad, joystick
                        // triggers, stylus barrel — everything that
                        // isn't keyboard or mouse-pointer-button
                        // shaped. Consumers compare `code` against
                        // narf_input::btn constants.
                        let _ = push_global(InputEvent::Button(ButtonEvent { code, pressed }));
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
                            let _ = push_global(InputEvent::Scroll(narf_input::ScrollEvent {
                                dx: 0,
                                dy: delta,
                            }));
                        }
                        REL_HWHEEL => {
                            let _ = push_global(InputEvent::Scroll(narf_input::ScrollEvent {
                                dx: delta,
                                dy: 0,
                            }));
                        }
                        _ => {}
                    }
                }
                EV_ABS => {
                    // Signed value: i32 reinterpreted from the
                    // virtio wire's u32 field. evdev allows the
                    // full signed range (tilt axes, sign-centred
                    // joystick axes go negative).
                    let signed = value as i32;
                    if code == abs::ABS_MT_SLOT {
                        // Switch the active slot for subsequent
                        // ABS_MT_* axis writes. Out-of-range slots
                        // get clamped — we don't track > MAX_MT_SLOTS.
                        let mut g = self.mt.lock();
                        if (signed as usize) < MAX_MT_SLOTS {
                            g.current_slot = signed as u8;
                        }
                    } else if code == abs::ABS_MT_TRACKING_ID
                        || code == abs::ABS_MT_POSITION_X
                        || code == abs::ABS_MT_POSITION_Y
                        || code == abs::ABS_MT_PRESSURE
                    {
                        let mut g = self.mt.lock();
                        let cur = g.current_slot as usize;
                        if cur < MAX_MT_SLOTS {
                            let slot = &mut g.slots[cur];
                            match code {
                                c if c == abs::ABS_MT_TRACKING_ID => {
                                    // evdev: -1 means "slot released".
                                    slot.tracking_id = if signed < 0 { None } else { Some(signed) };
                                }
                                c if c == abs::ABS_MT_POSITION_X => slot.x = signed,
                                c if c == abs::ABS_MT_POSITION_Y => slot.y = signed,
                                c if c == abs::ABS_MT_PRESSURE => slot.pressure = signed,
                                _ => unreachable!(),
                            }
                            slot.dirty = true;
                        }
                    } else {
                        // Non-MT absolute axis (tablet ABS_X/Y,
                        // joystick stick, hat, tilt, pressure for
                        // single-touch styluses, …). Push raw —
                        // consumers track latest-per-axis themselves.
                        let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
                            axis: code,
                            value: signed,
                        }));
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
                        let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
                    }
                    // Flush every dirty MT slot as one Touch event.
                    // Pulled out under the lock so concurrent EV_ABS
                    // arrivals don't tear a slot's snapshot. Derive
                    // the lifecycle state from per-slot `was_active`
                    // transitions before clearing dirty.
                    let dirty: alloc::vec::Vec<(u8, MtSlot, bool)> = {
                        let mut g = self.mt.lock();
                        let mut out = alloc::vec::Vec::new();
                        for (idx, slot) in g.slots.iter_mut().enumerate() {
                            if slot.dirty {
                                let prev_active = slot.was_active;
                                out.push((idx as u8, *slot, prev_active));
                                slot.dirty = false;
                                slot.was_active = slot.tracking_id.is_some();
                            }
                        }
                        out
                    };
                    for (slot_id, snap, prev_active) in dirty {
                        let active = snap.tracking_id.is_some();
                        let state = match (prev_active, active) {
                            (false, true) => narf_input::TouchState::Down,
                            (true, false) => narf_input::TouchState::Up,
                            _ => narf_input::TouchState::Move,
                        };
                        let id = snap
                            .tracking_id
                            .map(|t| (t as u32 & 0xFFFF) as u16)
                            .unwrap_or(0);
                        let _ = push_global(InputEvent::Touch(TouchEvent {
                            slot: slot_id,
                            tracking_id: snap.tracking_id,
                            id,
                            x: snap.x,
                            y: snap.y,
                            pressure: snap.pressure,
                            state,
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

/// Bound virtio-input devices. A modern desktop config can attach
/// keyboard + tablet + mouse simultaneously and the dispatcher binds
/// each one to its own controller — `Vec` rather than `Option` so
/// the second device doesn't get silently swallowed (the prior
/// shape returned `Ok(())` without binding when one was already
/// installed, leaving the second card present but inert).
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<VirtioInputPci>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
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
    let idx = {
        let mut g = CONTROLLERS.lock();
        let i = g.len();
        g.push(dev);
        i
    };
    let bound_name = alloc::format!("vinput{}", idx);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: bound_name,
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
    !CONTROLLERS.lock().is_empty()
}

/// Number of bound virtio-input devices.
pub fn count() -> usize {
    CONTROLLERS.lock().len()
}

/// Run `f` against the first bound controller, if any. Use the
/// `with_each` iterator instead when behaviour should fan out over
/// every device (drain pump, MSI-X dispatch, …).
pub fn with_controller<R>(f: impl FnOnce(&VirtioInputPci) -> R) -> Option<R> {
    CONTROLLERS.lock().first().map(f)
}

/// Run `f` against the controller at `idx`, if any. Used by the
/// per-device pump tasks so each one drains its own queue without
/// stepping on its siblings.
pub fn with_at<R>(idx: usize, f: impl FnOnce(&VirtioInputPci) -> R) -> Option<R> {
    CONTROLLERS.lock().get(idx).map(f)
}

/// Run `f` against every bound controller in probe order. Used by
/// the pump task so a keyboard + tablet + mouse all get drained in
/// one tick.
pub fn with_each(mut f: impl FnMut(&VirtioInputPci)) {
    let g = CONTROLLERS.lock();
    for c in g.iter() {
        f(c);
    }
}

/// Test-only: replay a sequence of `(type, code, value)` triplets
/// through the same decode path `drain_events` uses, pushing onto
/// the global rings. Mirrors the live decode for EV_KEY (BTN_* →
/// PointerButtons, BTN_TOUCH → slot 0 contact), EV_REL accumulators,
/// EV_REL REL_WHEEL → ScrollEvent, EV_ABS stable axes → Absolute,
/// EV_ABS ABS_MT_* → MT slot state, EV_SYN flushes Pointer + dirty
/// Touch slots. Returns the count of Key events pushed.
pub fn feed_synthetic_events_for_test(events: &[(u16, u16, u32)]) -> usize {
    use core::sync::atomic::AtomicI32;
    let mut count = 0usize;
    let rel_dx = AtomicI32::new(0);
    let rel_dy = AtomicI32::new(0);
    let mut buttons = PointerButtons::EMPTY;
    let mut mt = MtState::default();
    for &(etype, code, value) in events {
        match etype {
            EV_KEY => {
                let pressed = value != 0;
                let btn = match code {
                    BTN_LEFT => Some(PointerButtons::LEFT),
                    BTN_RIGHT => Some(PointerButtons::RIGHT),
                    BTN_MIDDLE => Some(PointerButtons::MIDDLE),
                    BTN_SIDE => Some(PointerButtons::SIDE),
                    BTN_EXTRA => Some(PointerButtons::EXTRA),
                    BTN_FORWARD => Some(PointerButtons::FORWARD),
                    BTN_BACK => Some(PointerButtons::BACK),
                    BTN_TASK => Some(PointerButtons::TASK),
                    _ => None,
                };
                if let Some(b) = btn {
                    if pressed {
                        buttons.insert(b);
                    } else {
                        buttons.remove(b);
                    }
                } else if code == BTN_TOUCH {
                    let slot = &mut mt.slots[0];
                    if pressed {
                        if slot.tracking_id.is_none() {
                            slot.tracking_id = Some(0);
                        }
                    } else {
                        slot.tracking_id = None;
                    }
                    slot.dirty = true;
                } else if is_gamepad_or_aux_btn(code) {
                    let _ = push_global(InputEvent::Button(ButtonEvent { code, pressed }));
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
                    REL_HWHEEL => {
                        let _ = push_global(InputEvent::Scroll(narf_input::ScrollEvent {
                            dx: delta,
                            dy: 0,
                        }));
                    }
                    _ => {}
                }
            }
            EV_ABS => {
                let signed = value as i32;
                if code == abs::ABS_MT_SLOT {
                    if (signed as usize) < MAX_MT_SLOTS {
                        mt.current_slot = signed as u8;
                    }
                } else if code == abs::ABS_MT_TRACKING_ID
                    || code == abs::ABS_MT_POSITION_X
                    || code == abs::ABS_MT_POSITION_Y
                    || code == abs::ABS_MT_PRESSURE
                {
                    let cur = mt.current_slot as usize;
                    if cur < MAX_MT_SLOTS {
                        let slot = &mut mt.slots[cur];
                        match code {
                            c if c == abs::ABS_MT_TRACKING_ID => {
                                slot.tracking_id = if signed < 0 { None } else { Some(signed) };
                            }
                            c if c == abs::ABS_MT_POSITION_X => slot.x = signed,
                            c if c == abs::ABS_MT_POSITION_Y => slot.y = signed,
                            c if c == abs::ABS_MT_PRESSURE => slot.pressure = signed,
                            _ => unreachable!(),
                        }
                        slot.dirty = true;
                    }
                } else {
                    let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
                        axis: code,
                        value: signed,
                    }));
                }
            }
            EV_SYN => {
                let dx = rel_dx.swap(0, Ordering::AcqRel);
                let dy = rel_dy.swap(0, Ordering::AcqRel);
                if dx != 0 || dy != 0 || buttons != PointerButtons::EMPTY {
                    let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
                }
                for (idx, slot) in mt.slots.iter_mut().enumerate() {
                    if slot.dirty {
                        let prev_active = slot.was_active;
                        let active = slot.tracking_id.is_some();
                        let state = match (prev_active, active) {
                            (false, true) => narf_input::TouchState::Down,
                            (true, false) => narf_input::TouchState::Up,
                            _ => narf_input::TouchState::Move,
                        };
                        let id = slot
                            .tracking_id
                            .map(|t| (t as u32 & 0xFFFF) as u16)
                            .unwrap_or(0);
                        let _ = push_global(InputEvent::Touch(TouchEvent {
                            slot: idx as u8,
                            tracking_id: slot.tracking_id,
                            id,
                            x: slot.x,
                            y: slot.y,
                            pressure: slot.pressure,
                            state,
                        }));
                        slot.dirty = false;
                        slot.was_active = active;
                    }
                }
            }
            _ => {}
        }
    }
    count
}
