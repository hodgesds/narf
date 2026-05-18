//! virtio-net over modern virtio-PCI transport (VirtIO 1.2 §5.1).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-net's PCI device id is `0x1000 + 0x40 + 0x01`
//! = 0x1041 (`0x1040 + virtio_id`, virtio_id 1 = net).
//!
//! Queue layout (VirtIO 1.2 §5.1.2):
//!   - queue 2N     = receiveq[N]
//!   - queue 2N+1   = transmitq[N]
//!   - queue 2 * max_virtqueue_pairs = controlq (when F_CTRL_VQ
//!     negotiated; sits at fixed index 2 when F_MQ is *not*
//!     negotiated since max_virtqueue_pairs is implicitly 1).
//!
//! Multi-queue (VIRTIO_NET_F_MQ, §5.1.3.1 feature bit 22): the
//! device advertises `max_virtqueue_pairs` (§5.1.4 u16 at device-cfg
//! offset 8). After feature ack + DRIVER_OK we issue
//! `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` (§5.1.6.5.5: class 4, cmd 0,
//! 2-byte LE payload) to tell the device how many pairs to keep
//! active. Frames still funnel into a single `narf_net::Interface`
//! per device — MQ is a throughput optimisation, not a multi-iface
//! fan-out — but TX submissions round-robin across the pairs so
//! parallel callers don't serialise on a single virtqueue lock,
//! and each RX pair gets its own forwarder.

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF,
    CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

/// Modern virtio-net PCI ids.
pub const VIRTIO_NET_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_NET_PCI_DEVICE: u16 = 0x1041;

// virtio-net feature bits (VirtIO 1.2 §5.1.3). We negotiate the
// subset the kernel actually reads from device-cfg / drives via
// the control queue.
const VIRTIO_NET_F_CSUM: u64 = 0; // device handles packet checksums
const VIRTIO_NET_F_MTU: u64 = 3;
const VIRTIO_NET_F_MAC: u64 = 5;
const VIRTIO_NET_F_STATUS: u64 = 16;
const VIRTIO_NET_F_CTRL_VQ: u64 = 17;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_MQ (bit 22). Device supports
/// multi-queue with auto receive-steering across `max_virtqueue_pairs`.
const VIRTIO_NET_F_MQ: u64 = 22;

// virtio-net control-queue command classes + sub-commands
// (VirtIO 1.2 §5.1.6.5). One class per logical operation group
// (RX filter, MAC, VLAN, …); each class has a numeric command
// space the driver fills in `virtio_net_ctrl_hdr::cmd`.
const VIRTIO_NET_CTRL_RX: u8 = 0;
const VIRTIO_NET_CTRL_RX_PROMISC: u8 = 0;
const VIRTIO_NET_CTRL_RX_ALLMULTI: u8 = 1;

/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ class.
const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET.
/// Payload is a `__virtio16` (2-byte LE) count of pairs to enable.
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;

const VIRTIO_NET_OK: u8 = 0;

// virtio-net config status bits.
const VIRTIO_NET_S_LINK_UP: u16 = 1 << 0;

// Offsets within the device-specific config region (VirtIO 1.2
// §5.1.4 — `struct virtio_net_config`).
const CFG_MAC: u64 = 0;
const CFG_STATUS: u64 = 6;
/// Per §5.1.4: u16 LE, only valid when VIRTIO_NET_F_MQ negotiated.
/// Reports the maximum number of TX/RX queue pairs the device
/// supports. Spec guarantees 1 ≤ value ≤ 0x8000.
const CFG_MAX_VIRTQUEUE_PAIRS: u64 = 8;
const CFG_MTU: u64 = 10;

/// Upper bound on how many queue pairs we'll actually bring up,
/// regardless of what `max_virtqueue_pairs` reports. Keeps DMA-page
/// + MSI-X-vector consumption bounded for absurd device-advertised
/// counts (some emulators advertise 0x8000). 4 is enough to spread
/// TX submission across a typical small-core machine.
const MAX_QUEUE_PAIRS: u16 = 4;

/// virtio-net header (VirtIO 1.2 §5.1.6.1). 12 bytes when
/// VIRTIO_F_VERSION_1 is negotiated and VIRTIO_NET_F_MRG_RXBUF /
/// VIRTIO_NET_F_HASH_REPORT are *not* — the form we use.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

/// Maximum frame we'll accept on RX. Standard MTU + Ethernet
/// header + virtio-net header headroom.
pub const MAX_FRAME: usize = 1518 + 16;

/// Per-pair RX/TX virtqueue + descriptor-id → buffer slot table.
/// With VIRTIO_NET_F_MQ the device exposes N of these as virtqueues
/// 2N (RX) + 2N+1 (TX). Each pair carries its own notify offset
/// (read once from `queue_notify_off` at bring_up) so the TX
/// round-robin selector can fire the right notify register without
/// re-walking the cfg space, and its own buffer slot table so RX
/// refills land back in the right pair.
#[derive(Debug)]
struct QueuePair {
    /// virtqueue index 2*N. Stored explicitly because `tx_dma` /
    /// `rx_take` need it for the device notify write, and a Vec
    /// position isn't necessarily the pair index after future
    /// hot-unplug paths land.
    rx_qidx: u16,
    /// virtqueue index 2*N + 1.
    tx_qidx: u16,
    rx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    /// RX descriptor → buffer table for this pair only.
    rx_buffers: IrqSafeSpinLock<Vec<Option<DmaBuffer>>>,
    /// Holds DMA pages backing the desc/avail/used rings alive.
    _rx_q_buf: DmaBuffer,
    _tx_q_buf: DmaBuffer,
    /// 12-byte virtio-net header scratch. Per-pair so concurrent
    /// TX submissions on different pairs don't clobber each other's
    /// header bytes mid-DMA.
    tx_hdr_buf: DmaBuffer,
    rx_qsize: u16,
    tx_qsize: u16,
    rx_notify_off: u16,
    tx_notify_off: u16,
}

pub struct VirtioNetPci {
    common: VirtioRegion,
    notify: VirtioRegion,
    /// Device-specific config region. `None` when the device didn't
    /// expose a Device cap (rare on modern QEMU); MAC defaults to
    /// `[0; 6]`, MTU to 1500, link assumed up in that case.
    device_cfg: Option<VirtioRegion>,
    notify_off_multiplier: u32,
    /// Active RX/TX queue pairs. Always non-empty post-bring_up;
    /// pair index 0 is the "primary" pair (still bound to MSI-X for
    /// RX-arrival wakeups). Pairs 1..N rely on the 16 ms polling
    /// fallback for now — per-queue MSI-X for MQ is a follow-up.
    pairs: Vec<QueuePair>,
    /// Round-robin TX-pair selector. `tx_dma` increments this then
    /// mods by `pairs.len()` to pick which TX virtqueue gets the
    /// next outbound frame. AtomicU64 to keep wraparound trivial
    /// (overflow ~ 5 × 10^11 years at 1 Gpps); Relaxed because we
    /// only need monotonic-ish, not coherence-with-data.
    tx_rr: AtomicU64,
    /// IDT vector bound to receiveq pair-0 (queue 0) when MSI-X is
    /// enabled. `None` means polled-only completion. Consumers wait
    /// via `narf_interrupts::wait_for_irq(v).await`.
    pub irq_vector: Option<u8>,
    /// Per-queue MSI-X vector for TX completions on pair 0. `None`
    /// = caller hasn't called `enable_tx_msix` yet, TX uses polled
    /// used-ring drain.
    pub tx_irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
    /// 48-bit hardware address captured from device-cfg. Zero when
    /// the device didn't advertise `VIRTIO_NET_F_MAC` (QEMU always
    /// does; bare-metal NICs may not).
    mac: [u8; 6],
    /// Last-read MTU from device-cfg (when `VIRTIO_NET_F_MTU`
    /// negotiated). Default 1500 otherwise.
    mtu: u32,
    /// True when `VIRTIO_NET_F_STATUS` was negotiated. Without it
    /// the spec says treat link as always up.
    has_status: bool,
    /// Runtime control-queue index (VirtIO 1.2 §5.1.2): with F_MQ
    /// negotiated and pairs > 1 the controlq sits at
    /// `2 * num_pairs`; without F_MQ it sits at fixed index 2.
    /// Stored so `submit_control` notifies the right queue.
    ctrl_qidx: u16,
    /// Control queue. `None` when the device didn't offer
    /// `F_CTRL_VQ`. Wrapped together with its scratch buffer +
    /// notify offset so callers can submit one command without
    /// trampolining through multiple locks.
    ctrl: Option<IrqSafeSpinLock<CtrlQueue>>,
    /// Phys address of the device's PCIe config space. Used by
    /// probe() as a per-device fingerprint so a second probe pass
    /// against the same device (e.g. tests that reset the bus
    /// driver-match registry + re-walk PCI) is idempotent — we
    /// recognise the device and don't push a duplicate controller.
    cfg_phys: u64,
}

/// Control-queue runtime state. `ctrl_buf` holds back-to-back
/// (hdr, payload, ack) byte regions used by `submit_control`;
/// 256 bytes is enough for a 2-byte hdr + ≤253 bytes of payload +
/// 1 byte ack, covering every RX/MAC/VLAN command we care about
/// today.
#[derive(Debug)]
struct CtrlQueue {
    q: Virtqueue,
    /// 4 KiB scratch page. The same page backs every submitted
    /// command (single-flight serialised by the outer lock); the
    /// device sees an [hdr|payload|ack] layout at fixed offsets
    /// 0 / 16 / 256 within the page.
    buf: DmaBuffer,
    notify_off: u16,
    /// Layout-buffer DMA backing the descriptor / avail / used
    /// rings — held so the page stays allocated for the device's
    /// lifetime.
    _layout_buf: DmaBuffer,
}

const RX_POOL_LEN: usize = 8;

impl core::fmt::Debug for VirtioNetPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetPci")
            .field("ready", &self.ready)
            .field("num_pairs", &self.pairs.len())
            .field("rx_qsize", &self.pairs.first().map(|p| p.rx_qsize).unwrap_or(0))
            .field("tx_qsize", &self.pairs.first().map(|p| p.tx_qsize).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl VirtioNetPci {
    /// Bring up the device with RX + TX virtqueues. RX is pre-
    /// populated with `RX_POOL_LEN` empty buffers.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        let cfg_phys = match device.kind {
            narf_bus::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => 0,
        };
        // SAFETY: bounded walk over identity-mapped cfg.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned device.
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

        // Feature negotiation: we only ask for VERSION_1.
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
        // Opportunistic negotiation: take F_MAC / F_STATUS / F_MTU
        // / F_CSUM when the device offers them. Each is a "device
        // tells us something" feature — accepting it just unlocks
        // the corresponding device-cfg field. We don't yet drive
        // the offload paths F_CSUM enables (we only checksum on
        // RX inspection), so guests built with strict feature
        // checks still accept the negotiation. F_MQ stays off —
        // we use the single-queue path.
        let want_mac = feats & (1u64 << VIRTIO_NET_F_MAC) != 0;
        let want_status = feats & (1u64 << VIRTIO_NET_F_STATUS) != 0;
        let want_mtu = feats & (1u64 << VIRTIO_NET_F_MTU) != 0;
        let want_csum = feats & (1u64 << VIRTIO_NET_F_CSUM) != 0;
        let want_ctrl_vq = feats & (1u64 << VIRTIO_NET_F_CTRL_VQ) != 0;
        // F_MQ requires F_CTRL_VQ (we can only command the device to
        // enable a pair count through the control queue). Reject MQ
        // when the device skipped F_CTRL_VQ — keeps the pair vector
        // single-entry and avoids a control-queue-less code path.
        let want_mq = (feats & (1u64 << VIRTIO_NET_F_MQ) != 0) && want_ctrl_vq;
        // All virtio-net F_* bits we care about live in the low
        // 32 (max is F_MQ = 22); only F_VERSION_1 = 32 is in
        // the high half.
        let drv_lo = (1u32 << VIRTIO_NET_F_MAC) * (want_mac as u32)
            | (1u32 << VIRTIO_NET_F_MTU) * (want_mtu as u32)
            | (1u32 << VIRTIO_NET_F_CSUM) * (want_csum as u32)
            | (1u32 << VIRTIO_NET_F_STATUS) * (want_status as u32)
            | (1u32 << VIRTIO_NET_F_CTRL_VQ) * (want_ctrl_vq as u32)
            | (1u32 << VIRTIO_NET_F_MQ) * (want_mq as u32);
        let drv_hi = 1u32 << (VIRTIO_F_VERSION_1 - 32);
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, drv_lo);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, drv_hi);
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

        // Per-queue setup. Helper to size + program one queue.
        let size_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer, u16, u16), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            let qsize = qmax.min(64).next_power_of_two() / 2;
            let qsize = if qsize == 0 { 4 } else { qsize.min(qmax) };
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let phys = buf.phys_addr().raw();
            let layout = VirtqueueLayout::new(qsize, phys).ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
            }
            // SAFETY: same.
            let nof = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            Ok((layout, buf, qsize, nof))
        };
        // Map device-cfg now (pre-queue-setup) — we need it to
        // peek `max_virtqueue_pairs` (§5.1.4) when F_MQ was
        // negotiated. The same mapping is reused further down for
        // MAC / MTU / link-status reads, so map_cap fires once.
        let device_cfg = if let Some(cap) = caps.device_cfg.as_ref() {
            // SAFETY: caller-owned device.
            match unsafe { crate::pci::map_cap(device, cap) } {
                Ok(r) => Some(r),
                Err(_) => None,
            }
        } else {
            None
        };
        let mut max_pairs: u16 = 1;
        if want_mq {
            if let Some(r) = device_cfg.as_ref() {
                // SAFETY: device-cfg region was just mapped; u16
                // at offset 8 per §5.1.4.
                let p = unsafe { r.read16(CFG_MAX_VIRTQUEUE_PAIRS) };
                if p >= 1 {
                    max_pairs = p.min(MAX_QUEUE_PAIRS);
                }
            }
        }
        let num_pairs: u16 = if want_mq { max_pairs.max(1) } else { 1 };

        // Bring up `num_pairs` RX/TX pairs at virtqueue indices
        // (0,1), (2,3), ..., (2N-2, 2N-1). The control queue (if
        // F_CTRL_VQ negotiated) sits at index 2*num_pairs.
        let mut pair_setups: Vec<(
            VirtqueueLayout,
            DmaBuffer,
            u16,
            u16,
            VirtqueueLayout,
            DmaBuffer,
            u16,
            u16,
        )> = Vec::with_capacity(num_pairs as usize);
        for n in 0..num_pairs {
            let rxi = 2 * n;
            let txi = 2 * n + 1;
            let (rx_layout, rx_q_buf, rx_qsize, rx_notify_off) = size_q(rxi)?;
            let (tx_layout, tx_q_buf, tx_qsize, tx_notify_off) = size_q(txi)?;
            pair_setups.push((
                rx_layout,
                rx_q_buf,
                rx_qsize,
                rx_notify_off,
                tx_layout,
                tx_q_buf,
                tx_qsize,
                tx_notify_off,
            ));
        }
        // Control queue is queue `2 * num_pairs` when F_CTRL_VQ was
        // negotiated (§5.1.2). With F_MQ off, num_pairs == 1, so
        // that's queue 2 — matches the legacy single-queue layout.
        let ctrl_qidx: u16 = 2 * num_pairs;
        let ctrl_setup = if want_ctrl_vq {
            match size_q(ctrl_qidx) {
                Ok(t) => Some(t),
                Err(_) => None,
            }
        } else {
            None
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

        // Build the per-pair Virtqueue instances and pre-populate
        // each RX with RX_POOL_LEN empty buffers. Per-pair buffer
        // tables so refills in `rx_take` find the slot they came
        // from regardless of which pair handled the arrival.
        let mut pairs: Vec<QueuePair> = Vec::with_capacity(num_pairs as usize);
        for (
            n,
            (
                rx_layout,
                rx_q_buf,
                rx_qsize,
                rx_notify_off,
                tx_layout,
                tx_q_buf,
                tx_qsize,
                tx_notify_off,
            ),
        ) in pair_setups.into_iter().enumerate()
        {
            let rx_qidx = 2 * n as u16;
            let tx_qidx = 2 * n as u16 + 1;
            // SAFETY: Virtqueue::new wipes the layout regions; the
            // backing pages may be recycled (alloc_frame doesn't zero).
            let mut rx_q = unsafe { Virtqueue::new(rx_layout) };
            // SAFETY: same.
            let tx_q = unsafe { Virtqueue::new(tx_layout) };

            let mut rx_buffers: Vec<Option<DmaBuffer>> = (0..rx_qsize).map(|_| None).collect();
            let posted = RX_POOL_LEN.min(rx_qsize as usize);
            for _ in 0..posted {
                let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| VirtioPciError::BarMapFailed)?;
                let phys = buf.phys_addr().raw();
                let descs = [VirtqDesc {
                    addr: phys,
                    len: MAX_FRAME as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }];
                if let Some(head) = rx_q.add_buffer(&descs) {
                    rx_buffers[head as usize] = Some(buf);
                }
            }

            // Kick the device about the freshly-posted RX buffers.
            let rx_off = (rx_notify_off as u64) * (notify_off_multiplier as u64);
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped notify region.
            unsafe {
                notify.write16(rx_off, rx_qidx);
            }

            // Per-pair TX header scratch. 4 KiB is overkill for 12
            // bytes but matches the smallest DMA-coherent allocation
            // granularity we have.
            let tx_hdr_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;

            pairs.push(QueuePair {
                rx_qidx,
                tx_qidx,
                rx_queue: IrqSafeSpinLock::new(Some(rx_q)),
                tx_queue: IrqSafeSpinLock::new(Some(tx_q)),
                rx_buffers: IrqSafeSpinLock::new(rx_buffers),
                _rx_q_buf: rx_q_buf,
                _tx_q_buf: tx_q_buf,
                tx_hdr_buf,
                rx_qsize,
                tx_qsize,
                rx_notify_off,
                tx_notify_off,
            });
        }

        // Build the CtrlQueue handle now that we have the layout
        // tuple from the optional size_q call earlier.
        let ctrl = match ctrl_setup {
            Some((c_layout, c_layout_buf, _c_qsize, c_notify_off)) => {
                let ctrl_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| VirtioPciError::BarMapFailed)?;
                // SAFETY: Virtqueue::new zeros the layout regions.
                let q = unsafe { Virtqueue::new(c_layout) };
                Some(IrqSafeSpinLock::new(CtrlQueue {
                    q,
                    buf: ctrl_buf,
                    notify_off: c_notify_off,
                    _layout_buf: c_layout_buf,
                }))
            }
            None => None,
        };

        // Read MAC + MTU + status from device-cfg, gated on whether
        // the feature was negotiated. Spec: the corresponding field
        // is only valid when its feature was negotiated.
        let mut mac = [0u8; 6];
        let mut mtu: u32 = 1500;
        let mut link_up_init = true;
        if let Some(r) = device_cfg.as_ref() {
            if want_mac {
                // SAFETY: device-cfg region was just mapped; field
                // at offset 0..6.
                for i in 0..6u64 {
                    mac[i as usize] = unsafe { r.read8(CFG_MAC + i) };
                }
            }
            if want_status {
                // SAFETY: same. Status at offset 6 (u16 LE).
                let s = unsafe { r.read16(CFG_STATUS) };
                link_up_init = s & VIRTIO_NET_S_LINK_UP != 0;
            }
            if want_mtu {
                // SAFETY: same. MTU at offset 10 (u16 LE).
                let m = unsafe { r.read16(CFG_MTU) };
                if m >= 64 {
                    mtu = m as u32;
                }
            }
        }
        // Stash an initial link-state guess on the controller so
        // accessors don't need to re-read MMIO on every poll.
        let _ = link_up_init;

        let mut this = Self {
            common,
            notify,
            device_cfg,
            notify_off_multiplier,
            pairs,
            tx_rr: AtomicU64::new(0),
            irq_vector: None,
            tx_irq_vector: None,
            msix: None,
            ready: true,
            mac,
            mtu,
            has_status: want_status,
            ctrl_qidx,
            ctrl,
            cfg_phys,
        };

        // VirtIO 1.2 §5.1.6.5.5: after DRIVER_OK, tell the device
        // how many queue pairs to actually use. Without this command
        // the device defaults to a single pair even though we
        // brought up more — frames would silently disappear from
        // pairs 1..N. Best-effort: if the command fails (device
        // refused, or no ctrl queue despite F_MQ being set, which
        // shouldn't happen but isn't worth panicking over), fall
        // back to using just pair 0.
        if want_mq && num_pairs > 1 {
            match this.submit_control(
                VIRTIO_NET_CTRL_MQ,
                VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET,
                &num_pairs.to_le_bytes(),
            ) {
                Ok(VIRTIO_NET_OK) => {}
                _ => {
                    // Device rejected the MQ command. Truncate down
                    // to a single pair — the extra rings stay
                    // allocated but unused, which is fine for now.
                    this.pairs.truncate(1);
                }
            }
        }
        Ok(this)
    }

    /// Phys address of this controller's PCIe config space. Used by
    /// the probe-time dedupe check + diagnostics.
    pub fn cfg_phys(&self) -> u64 {
        self.cfg_phys
    }

    /// Bind the receiveq pair-0 (queue 0) to a fresh MSI-X vector.
    /// After this call, frame-arrival on the primary pair is
    /// observable via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())`.
    /// RX pairs 1..N rely on the 16 ms polling fallback in their
    /// forwarders — per-queue MSI-X for the MQ case is a follow-up.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) =
            unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, 0) }?;
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// TX-queue MSI-X for pair 0 (queue index 1). Reuses the
    /// existing `MsixTable` if RX MSI-X is already enabled — both
    /// vectors land on the same MSI-X table.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_tx_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) =
            unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, 1) }?;
        self.tx_irq_vector = Some(v);
        // Replace the MSI-X table handle with the latest one
        // (enable_msix_queue allocates a fresh slot in the
        // existing table; there's only one table per device,
        // and the new handle keeps both vectors live).
        self.msix = Some(table);
        Ok(v)
    }

    /// Number of active TX/RX queue pairs after `bring_up` (and
    /// after the optional `VQ_PAIRS_SET` ack). Always ≥ 1.
    pub fn num_pairs(&self) -> usize {
        self.pairs.len()
    }

    /// Round-robin TX-pair pick. `tx_dma` calls this to spread
    /// outbound frames across pairs without callers having to know
    /// the pair count. Wraps via modulo — safe on overflow because
    /// AtomicU64 wraps and modulo is unaffected by the wrap.
    fn next_tx_pair(&self) -> usize {
        // Relaxed: the only invariant is "two concurrent calls get
        // different-ish indices over time". No data is published
        // through this counter — the per-pair virtqueue lock is the
        // real synchroniser.
        let n = self.tx_rr.fetch_add(1, Ordering::Relaxed);
        (n as usize) % self.pairs.len()
    }

    /// Transmit a frame backed by a caller-owned `DmaBuffer`.
    /// Zero-copy: the payload descriptor points at `buf` directly
    /// — the driver never memcpys the frame body, only the 12-byte
    /// virtio-net header stub at the front of the chain. `payload`
    /// gives the slice of `buf` to send (offset + len within the
    /// page); the caller must keep `buf` alive until this call
    /// returns since the descriptor chain references its phys
    /// address.
    ///
    /// Picks a TX pair via the round-robin selector. With
    /// VIRTIO_NET_F_MQ negotiated and >1 pairs active, parallel
    /// callers fan out across the device's TX virtqueues; with a
    /// single pair the round-robin degenerates to "always pair 0".
    ///
    /// Polled completion via `responsive_spin_until` so sleep_pumps
    /// keep advancing while the device drains.
    pub fn tx_dma(
        &self,
        buf: &DmaBuffer,
        payload_offset: u32,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        let pair_idx = self.next_tx_pair();
        self.tx_dma_on(pair_idx, buf, payload_offset, payload_len)
    }

    /// Like `tx_dma` but submits on a specific pair. Used by the
    /// TX forwarder (already picks the pair, doesn't need to
    /// re-roll the round-robin) and by tests that want to exercise
    /// a particular queue.
    pub fn tx_dma_on(
        &self,
        pair_idx: usize,
        buf: &DmaBuffer,
        payload_offset: u32,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        let pair = self.pairs.get(pair_idx).ok_or(VirtioPciError::NoQueues)?;
        let payload_offset = payload_offset as usize;
        let payload_len = payload_len as usize;
        if payload_len == 0 || payload_len > MAX_FRAME - 12 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        if payload_offset.saturating_add(payload_len) > buf.len() {
            return Err(VirtioPciError::QueueTooSmall);
        }
        // Per-pair header scratch keeps concurrent submissions on
        // sibling pairs from racing on the same 12-byte region.
        let hdr_phys = pair.tx_hdr_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; offset 0..12 within
        // the 4 KiB tx_hdr_buf page.
        unsafe {
            for i in 0..12u64 {
                core::ptr::write_volatile((hdr_phys + i) as *mut u8, 0);
            }
        }
        let payload_phys = buf.phys_addr().raw() + payload_offset as u64;
        // Two descriptors: header + payload, both device-readable.
        let descs = [
            VirtqDesc {
                addr: hdr_phys,
                len: 12,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: payload_len as u32,
                flags: 0,
                next: 0,
            },
        ];
        let head = {
            let mut g = pair.tx_queue.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        let off = (pair.tx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped.
        unsafe {
            self.notify.write16(off, pair.tx_qidx);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive
        // while waiting for the device to publish a used-ring entry.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = pair.tx_queue.lock();
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
        let mut g = pair.tx_queue.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(())
    }

    /// Queue size for the primary RX pair (pair 0). Kept as a
    /// shorthand for tests that don't care about MQ specifics.
    pub fn rx_queue_size(&self) -> u16 {
        self.pairs.first().map(|p| p.rx_qsize).unwrap_or(0)
    }
    /// Queue size for the primary TX pair (pair 0).
    pub fn tx_queue_size(&self) -> u16 {
        self.pairs.first().map(|p| p.tx_qsize).unwrap_or(0)
    }

    /// 48-bit hardware address. Zero when `VIRTIO_NET_F_MAC` wasn't
    /// negotiated (rare; QEMU advertises a vendor-default MAC).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Negotiated MTU. Defaults to 1500 when `VIRTIO_NET_F_MTU`
    /// wasn't offered.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Live link state. Reads the status word from device-cfg every
    /// call when `VIRTIO_NET_F_STATUS` was negotiated; returns
    /// `true` unconditionally otherwise (spec: absence of the
    /// feature means assume link up).
    pub fn link_up(&self) -> bool {
        if !self.has_status {
            return true;
        }
        let r = match self.device_cfg.as_ref() {
            Some(r) => r,
            None => return true,
        };
        // SAFETY: device-cfg region was mapped at bring_up; field
        // at offset 6 stays valid for the controller's lifetime.
        let s = unsafe { r.read16(CFG_STATUS) };
        s & VIRTIO_NET_S_LINK_UP != 0
    }

    /// `true` iff this controller negotiated F_CTRL_VQ and has a
    /// working control queue. Callers gate `set_promisc` /
    /// `set_allmulti` etc. on this.
    pub fn has_ctrl_vq(&self) -> bool {
        self.ctrl.is_some()
    }

    /// Submit one control command to virtqueue 2 and wait for the
    /// device's 1-byte ack. The chain is [hdr, payload, ack]
    /// (device-readable, device-readable, device-writable). Returns
    /// the ack byte — `VIRTIO_NET_OK` (0) on success, anything else
    /// is a device-side error.
    ///
    /// Single-flight per controller — the outer lock serialises
    /// callers, so concurrent set_promisc + set_allmulti pairs are
    /// fine but interleaving is sequential. Control commands are
    /// rare (PHY-driven events), so no contention concern.
    pub fn submit_control(
        &self,
        class: u8,
        cmd: u8,
        payload: &[u8],
    ) -> Result<u8, VirtioPciError> {
        let ctrl = self.ctrl.as_ref().ok_or(VirtioPciError::NoQueues)?;
        let mut g = ctrl.lock();
        // Layout within `buf`:
        //   0..2     hdr  (class, cmd)         device-readable
        //   16..16+N payload                    device-readable
        //   256..257 ack                        device-writable
        // The 256-byte stride leaves slack for ≤240 byte payloads
        // — covers RX_MODE (1 byte) and MAC_ADDR_SET (6 bytes)
        // trivially. Larger payloads (MAC_TABLE_SET with many
        // entries) will need a per-call allocation later.
        if payload.len() > 240 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let phys = g.buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; the offsets stay
        // within the 4 KiB page allocated above.
        unsafe {
            core::ptr::write_volatile(phys as *mut u8, class);
            core::ptr::write_volatile((phys + 1) as *mut u8, cmd);
            for (i, b) in payload.iter().enumerate() {
                core::ptr::write_volatile((phys + 16 + i as u64) as *mut u8, *b);
            }
            // Seed the ack byte with a sentinel so we can spot
            // "device didn't write anything".
            core::ptr::write_volatile((phys + 256) as *mut u8, 0xFF);
        }
        let descs = [
            VirtqDesc {
                addr: phys,
                len: 2,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: phys + 16,
                len: payload.len() as u32,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: phys + 256,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = g
            .q
            .add_buffer(&descs)
            .ok_or(VirtioPciError::QueueTooSmall)?;
        let notify_off = (g.notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region. Notify the runtime
        // controlq index — it shifts based on `num_pairs` when F_MQ
        // is negotiated (§5.1.2).
        unsafe {
            self.notify.write16(notify_off, self.ctrl_qidx);
        }
        // Spin for completion while letting sleep_pumps tick.
        let done = narf_scheduler::responsive_spin_until(
            || matches!(g.q.poll_used(), Some((id, _)) if id == head as u32),
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(VirtioPciError::QueueTooSmall);
        }
        g.q.free_chain(head);
        // SAFETY: device wrote the ack byte before publishing the
        // used-ring entry; identity-mapped read.
        let ack = unsafe { core::ptr::read_volatile((phys + 256) as *const u8) };
        Ok(ack)
    }

    /// Convenience wrapper for `VIRTIO_NET_CTRL_RX_PROMISC`. Asks
    /// the device to enable / disable promiscuous mode (deliver
    /// every frame to RX, even those destined for other MACs).
    /// Returns `Err` if the device didn't negotiate F_CTRL_VQ or
    /// the ack wasn't `VIRTIO_NET_OK`.
    pub fn set_promisc(&self, on: bool) -> Result<(), VirtioPciError> {
        let payload = [u8::from(on)];
        let ack =
            self.submit_control(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Convenience wrapper for `VIRTIO_NET_CTRL_RX_ALLMULTI`.
    /// Requests delivery of every multicast frame regardless of the
    /// MAC-filter list — useful for IPv6 NDP / mDNS consumers
    /// without per-address filter setup.
    pub fn set_allmulti(&self, on: bool) -> Result<(), VirtioPciError> {
        let payload = [u8::from(on)];
        let ack =
            self.submit_control(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_ALLMULTI, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Take ownership of one device-filled RX frame from pair 0.
    /// Shorthand for `rx_take_on(0)`; kept for tests that don't
    /// care about MQ specifics.
    pub fn rx_take(&self) -> Option<(DmaBuffer, u32)> {
        self.rx_take_on(0)
    }

    /// Take ownership of one device-filled RX frame from the given
    /// pair. Zero-copy: returns the actual `DmaBuffer` the device
    /// wrote into + total bytes (including the 12-byte virtio-net
    /// header). Allocates a replacement buffer and re-posts it in
    /// the avail ring before returning so the device always has a
    /// place to land the next frame.
    ///
    /// Returns `None` if the pair index is out of range, the used
    /// ring is empty, or the replacement allocation fails (in which
    /// case the original stays in place — the device-filled buffer
    /// is not surrendered until the refill is guaranteed).
    pub fn rx_take_on(&self, pair_idx: usize) -> Option<(DmaBuffer, u32)> {
        let pair = self.pairs.get(pair_idx)?;
        let elem = {
            let mut g = pair.rx_queue.lock();
            let q = g.as_mut()?;
            q.poll_used()
        };
        let (id, len) = elem?;
        let head = id as u16;
        // Allocate the replacement up front. If we can't, we leave
        // the device-filled buffer parked in its slot and return
        // None — better than handing the stack a frame and losing
        // the refill slot.
        let replacement = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
        let rep_phys = replacement.phys_addr().raw();
        // Now swap: take the original out of its slot, free the
        // descriptor chain, post the replacement, stash it under
        // its new head index.
        let original = {
            let mut bufs = pair.rx_buffers.lock();
            bufs.get_mut(head as usize).and_then(|s| s.take())?
        };
        let new_head = {
            let mut g = pair.rx_queue.lock();
            let q = match g.as_mut() {
                Some(q) => q,
                None => {
                    // Queue vanished — return the original to its
                    // slot so we don't lose it.
                    pair.rx_buffers.lock()[head as usize] = Some(original);
                    return None;
                }
            };
            q.free_chain(head);
            let descs = [VirtqDesc {
                addr: rep_phys,
                len: MAX_FRAME as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            match q.add_buffer(&descs) {
                Some(h) => h,
                None => {
                    // Refill failed: device is one descriptor down
                    // until the next caller frees one. Return the
                    // original anyway — the stack already drained
                    // it logically.
                    drop(replacement);
                    let off = (pair.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
                    compiler_fence(Ordering::SeqCst);
                    // SAFETY: identity-mapped notify region.
                    unsafe {
                        self.notify.write16(off, pair.rx_qidx);
                    }
                    return Some((original, len));
                }
            }
        };
        // Park the replacement in its slot for the next rx_take.
        pair.rx_buffers.lock()[new_head as usize] = Some(replacement);
        // Re-notify the device about the refill.
        let off = (pair.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(off, pair.rx_qidx);
        }
        Some((original, len))
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Every bound virtio-net device. A modern host can attach more than
/// one virtio-net controller (separate vlans, separate netdevs); the
/// singleton-Option shape used to swallow the second probe — match
/// the virtio-input fix and keep all bound devices.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<VirtioNetPci>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Dedupe: tests that reset the bus driver-match registry and
    // re-walk PCI would otherwise push a second controller for
    // the same device. Match by config-space phys address — every
    // PCIe device has a unique one.
    let dev_cfg = match device.kind {
        narf_bus::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
        _ => 0,
    };
    if dev_cfg != 0 {
        let already = {
            let g = CONTROLLERS.lock();
            g.iter().any(|c| c.cfg_phys() == dev_cfg)
        };
        if already {
            return Ok(());
        }
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device.
    let mut dev = match unsafe { VirtioNetPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: probe-time caller owns the device. Best-effort —
    // failure leaves the polled fallback in place inside the
    // forwarder.
    let _ = unsafe { dev.enable_msix(&cap, &device) };
    let idx = {
        let mut g = CONTROLLERS.lock();
        let i = g.len();
        g.push(dev);
        i
    };
    let bound_name = alloc::format!("vnet{}", idx);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: bound_name.clone(),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(VIRTIO_NET_PCI_VENDOR),
        pci_did: Some(VIRTIO_NET_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Register this specific controller's interface and spawn its
    // forwarder pair.
    register_net_interface(idx, bound_name);
    Ok(())
}

/// Build a `VirtioNet` from the controller at `idx`, register it
/// with `narf_net::registry()` under `name`, and spawn the RX/TX
/// forwarder tasks scoped to that controller's index.
///
/// Forwarder shape with VIRTIO_NET_F_MQ:
/// - One TX forwarder per device. Drains the iface tx_consumer once
///   and demuxes each frame to one of N TX virtqueues via the
///   controller's round-robin selector. Single-consumer of the
///   `narf_ipc::Consumer<Frame>`; no lock contention on the consumer
///   half (narf_ipc is SPSC and we hold the single S/C side).
/// - N RX forwarders, one per pair. Each pair has its own used-ring
///   to drain; pair 0 waits on MSI-X, pairs 1..N fall back to a
///   16 ms poll. All N RX forwarders push into the same shared
///   `Producer<Frame>`, behind an `Arc<IrqSafeSpinLock<...>>` —
///   `narf_ipc::Producer` is `!Sync` so the lock is required to
///   serialise the multiple producer halves. Push frequency is
///   low (one short critical section per frame, no awaits held
///   under the lock) so contention is bounded even on a 4-pair
///   line-rate workload.
fn register_net_interface(idx: usize, name: alloc::string::String) {
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    let (mac, mtu, link_up, irq_vector, num_pairs) = match with_at(idx, |c| {
        (c.mac(), c.mtu(), c.link_up(), c.irq_vector, c.num_pairs())
    }) {
        Some(t) => t,
        None => return,
    };
    let (tx_prod, mut tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
    let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
    let iface =
        narf_net::virtio_net::VirtioNet::new(name, mac, mtu, link_up, tx_prod, rx_cons);
    let authority = narf_net::bootstrap_authority();
    // Registration failure leaks the iface (returned by-value into
    // the registry would have moved it) — we constructed it above
    // and Registry::register consumes it on success. On failure
    // the Vec slot stays free and the forwarders below would talk
    // to nothing useful, so bail.
    if narf_net::registry().register(&authority, iface).is_err() {
        return;
    }
    // Wrap the rx_prod in an Arc<IrqSafeSpinLock> so all N RX
    // forwarders can push to it. Producer is !Sync (narf_ipc SPSC);
    // the lock serialises the N producer halves into one logical
    // producer feeding the iface's RX ring.
    let rx_prod = Arc::new(IrqSafeSpinLock::new(Some(rx_prod)));

    // Spawn one RX forwarder per active pair.
    for pair_idx in 0..num_pairs {
        let rx_prod = Arc::clone(&rx_prod);
        // Only pair 0 gets the MSI-X wakeup; pairs 1..N poll. See
        // function-level comment for why we don't allocate per-queue
        // MSI-X vectors yet.
        let irq = if pair_idx == 0 { irq_vector } else { None };
        narf_scheduler::spawn(async move {
            const PUMP_CYCLES: u64 = 53_000_000;
            loop {
                if let Some(v) = irq {
                    narf_interrupts::wait::wait_for_irq(v).await;
                } else {
                    narf_time::sleep_cycles(PUMP_CYCLES).await;
                }
                loop {
                    let taken = match with_at(idx, |c| c.rx_take_on(pair_idx)) {
                        Some(t) => t,
                        None => return, // controller vanished
                    };
                    let (buf, total_len) = match taken {
                        Some(t) => t,
                        None => break,
                    };
                    // virtio-net always prepends a 12-byte header to
                    // every RX frame. Strip it via Frame::with_offset
                    // — the bytes stay where the device wrote them.
                    let payload_len = (total_len as u32).saturating_sub(12);
                    if payload_len == 0 {
                        // Empty frame (just header); drop it and keep
                        // draining. `buf` frees on scope exit.
                        continue;
                    }
                    let frame = Frame::with_offset(buf, 12, payload_len);
                    // Tap: synchronously dispatch the payload through
                    // the legacy iface RX handler. Only meaningful for
                    // the primary controller (idx 0) — the TCP stack
                    // installed itself there at boot. Cheap fn-pointer
                    // call when no handler is installed.
                    if idx == 0 {
                        narf_net::iface::on_rx_frame(frame.payload());
                    }
                    // try_send-then-yield loop. We can't hold the
                    // IrqSafeSpinLockGuard across an await (the guard
                    // is !Send because it disables IRQs on lock), so
                    // we drop the lock between full-ring retries and
                    // yield the task to let the iface consumer drain.
                    let mut frame_opt = Some(frame);
                    loop {
                        let outcome = {
                            let mut g = rx_prod.lock();
                            let prod = match g.as_mut() {
                                Some(p) => p,
                                None => return,
                            };
                            // try_send takes the value by-move; on
                            // Full it hands the value back so we can
                            // retry. Closed = consumer dropped, bail
                            // out of this forwarder.
                            match prod.try_send(frame_opt.take().unwrap()) {
                                Ok(()) => Ok(()),
                                Err(narf_ipc::TrySendError::Closed(_)) => {
                                    *g = None;
                                    return;
                                }
                                Err(narf_ipc::TrySendError::Full(f)) => {
                                    frame_opt = Some(f);
                                    Err(())
                                }
                            }
                        };
                        if outcome.is_ok() {
                            break;
                        }
                        // Ring full — yield so the iface consumer
                        // gets a chance to drain before we try again.
                        narf_scheduler::yield_now().await;
                    }
                }
            }
        });
    }

    // Single TX forwarder per device. Drains the tx_consumer once
    // and round-robins each frame to one of the N TX virtqueues
    // via the controller's `tx_dma` (which calls `next_tx_pair`).
    // Zero-copy: the payload descriptor points at the Frame's
    // DmaBuffer directly.
    narf_scheduler::spawn(async move {
        while let Ok(frame) = tx_cons.recv().await {
            let (buf, offset, len) = frame.into_parts_with_offset();
            let _ = with_at(idx, |c| c.tx_dma(&buf, offset, len));
            // `buf` drops here → DmaBuffer::drop frees the page.
        }
    });

    // Wire the controller into the legacy `narf_net::iface` registry
    // (fn-pointer-based) that the TCP stack consumes via
    // `iface::send` / `iface::on_rx_frame` / `iface::drain_pump`.
    // Only the primary controller (idx 0) registers here — the
    // legacy registry has one "primary iface" slot; multi-NIC
    // routing is a Stage-2 concern.
    if idx == 0 {
        narf_net::iface::register("vnet0", mac, vnet0_send_fn);
        narf_net::iface::install_rx_drain(vnet0_drain_fn);
    }
}

/// `iface::SendFn` for the primary virtio-net controller. The TCP
/// stack invokes this with a full Ethernet frame; we allocate a
/// fresh DmaBuffer, memcpy the bytes in, and submit through the
/// existing zero-copy tx_dma path. The single memcpy is on the
/// stack-side slow path (one alloc per outbound frame); zero-copy
/// stays in effect when the producer pushes a pre-built Frame
/// through `tx_prod` directly.
fn vnet0_send_fn(frame: &[u8]) -> Result<(), ()> {
    if frame.is_empty() || frame.len() > MAX_FRAME - 12 {
        return Err(());
    }
    let mut buf =
        alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| ())?;
    {
        let slice = buf.as_mut_slice();
        if slice.len() < frame.len() {
            return Err(());
        }
        slice[..frame.len()].copy_from_slice(frame);
    }
    let res = with_controller(|c| c.tx_dma(&buf, 0, frame.len() as u32));
    match res {
        Some(Ok(())) => Ok(()),
        _ => Err(()),
    }
    // `buf` drops at end of scope → DmaBuffer::drop frees the page.
}

/// `iface::DrainFn` — synchronous one-frame drain used by the TCP
/// stack's `arp_resolve` busy-wait inside a syscall handler. We
/// pull one received frame off pair 0's used ring (zero-copy via
/// rx_take), strip the 12-byte virtio-net header, dispatch the
/// payload through `iface::on_rx_frame`, and let the DmaBuffer
/// drop. Returns `true` iff a frame was actually processed.
fn vnet0_drain_fn() -> bool {
    let taken = with_controller(|c| c.rx_take()).flatten();
    let (buf, total_len) = match taken {
        Some(t) => t,
        None => return false,
    };
    let payload_len = (total_len as u32).saturating_sub(12);
    if payload_len == 0 {
        return true;
    }
    let end = (12 + payload_len as usize).min(buf.len());
    narf_net::iface::on_rx_frame(&buf.as_slice()[12..end]);
    true
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-net-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_NET_PCI_VENDOR,
            device: VIRTIO_NET_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// Number of bound virtio-net devices.
pub fn count() -> usize {
    CONTROLLERS.lock().len()
}

/// Run `f` against the first bound controller, if any. Use the
/// `with_each` iterator instead when behaviour should fan out over
/// every device.
pub fn with_controller<R>(f: impl FnOnce(&VirtioNetPci) -> R) -> Option<R> {
    CONTROLLERS.lock().first().map(f)
}

/// Run `f` against every bound controller in probe order.
pub fn with_each(mut f: impl FnMut(&VirtioNetPci)) {
    let g = CONTROLLERS.lock();
    for c in g.iter() {
        f(c);
    }
}

/// Run `f` against the controller at `idx`, if any. Per-device
/// forwarder tasks call this every tick to drain/post on their own
/// queues without stepping on siblings.
pub fn with_at<R>(idx: usize, f: impl FnOnce(&VirtioNetPci) -> R) -> Option<R> {
    CONTROLLERS.lock().get(idx).map(f)
}

