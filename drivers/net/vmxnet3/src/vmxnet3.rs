//! VMware vmxnet3 paravirtual NIC driver — runs inside a VMware-ESX /
//! Workstation guest. The host advertises `1ad:07b0` and presents two
//! BARs the driver consumes:
//!
//! - **BAR0** — *PT* (pass-through) register window, 4 KiB. Doorbells:
//!   `VMXNET3_REG_IMR` per-vector mask at offset 0x000, `TXPROD`
//!   producer doorbell at 0x600, `RXPROD` ring-1 producer at 0x800,
//!   `RXPROD2` ring-2 producer at 0xA00.
//! - **BAR1** — *VD* (vmxnet device) register window, 4 KiB. Control
//!   plane: `VRRS` at 0x00 (revision report select), `UVRS` at 0x08
//!   (UPT version report select), `DSAL`/`DSAH` at 0x10/0x18 (driver-
//!   shared structure phys addr split), `CMD` at 0x20, `MACL`/`MACH`
//!   at 0x28/0x30, `ICR`/`ECR` at 0x38/0x40.
//!
//! The task brief listed MAC at "0x12/0x18 in BAR0" — that's
//! inaccurate; both `vmxnet3_defs.h` (VMware's own header, GPL-2.0)
//! and the live `vmxnet3_drv.c::VMXNET3_WRITE_BAR1_REG` macro confirm
//! the control plane lives in BAR1, the doorbells in BAR0. We follow
//! the Linux/VMware definition.
//!
//! ## Bring-up sequence (per `vmxnet3_drv.c::vmxnet3_probe_device` +
//! `vmxnet3_activate_dev`)
//!
//! 1. Map BAR0 + BAR1. Read VRRS at BAR1+0x00 → bitmap of revisions
//!    the host supports. Pick the highest bit we know (REV_1 = bit 0)
//!    and write that bit back to VRRS to acknowledge.
//! 2. Read UVRS at BAR1+0x08 → bitmap of UPT versions the host
//!    supports; ack UPT version 1 (write `1 << 0`).
//! 3. Allocate `Vmxnet3_DriverShared` in DMA-coherent memory. Stage 0
//!    only populates `magic` + `size`; Stage 1 fills `devRead`.
//! 4. Write the shared-struct phys addr split into DSAL/DSAH.
//! 5. Issue `VMXNET3_CMD_ACTIVATE_DEV` via CMD; read MAC from
//!    MACL/MACH; issue `VMXNET3_CMD_GET_LINK` and read the CMD
//!    register back to capture link state.
//!
//! ## Stage 3 — datapath + publication (issue #800, vmxnet3 slice)
//!
//! `bring_up` additionally opens the frame-ring channel pair
//! (`narf_ipc::channel`) and the probe publishes the NIC two ways:
//!
//! - **Frame rings** — `Vmxnet3Iface` implements `narf_net::Interface`
//!   + `HwNic` and registers with the cap-gated registry, so the
//!     stack daemon / XDP consumers see the device. The TX pump drains
//!     the TX consumer into `transmit`; the RX pump drains the RX
//!     completion ring and fans frames out through `dispatch_rx_frame`
//!     (ring mirror + kernel-stack delivery, e1000's shape).
//! - **Netdev publication** — probe registers an `eth%d` netdev via
//!   `narf_drivers_net_core::publish::publish_netdev_with_context` and stamps the
//!   initial link sample from the `GET_LINK` reply. Carrier stops
//!   being a probe-time photograph: the RX pump polls the
//!   `DriverShared.ecr` event word (`vmxnet3_drv.c::vmxnet3_do_poll`
//!   checks `shared->ecr` then `vmxnet3_process_events`) and
//!   re-samples `GET_LINK` on `VMXNET3_ECR_LINK`, republishing on
//!   change; a periodic re-sample covers a lost event.
//!
//! The pumps poll — no MSI-X vector is bound yet, and the device's
//! `intrCtrl` stays at `VMXNET3_IC_DISABLE_ALL` from bring-up, so no
//! interrupt can arrive. The device still DMAs against the rings:
//! descriptor availability is carried by the generation bits alone
//! (QEMU `vmxnet3_pop_next_tx_descr` / `vmxnet3_get_next_head_rx_descr`
//! pop a descriptor exactly when its gen equals the ring's current
//! gen). RXPROD is rung only when the queue-descriptor control word
//! `updateRxProd` is set by the device (Linux `vmxnet3_rq_rx_complete`);
//! QEMU never sets it, and Linux never writes RXPROD at init either.
//!
//! ## Reference
//!
//! - Linux `drivers/net/vmxnet3/vmxnet3_defs.h` (GPL-2.0, VMware
//!   2008-2024). Defines every register offset and shared-mem layout
//!   touched here.
//! - Linux `drivers/net/vmxnet3/vmxnet3_drv.c` (GPL-2.0). Reference
//!   bring-up sequence + bit-twiddling.

#![allow(dead_code)]

use alloc::sync::Arc;
use core::fmt::Write;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write as WriteCap,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

use crate::publish::LinkSample;

pub mod regs;
pub mod shared;

mod tests;

pub use regs::*;
pub use shared::*;

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: VMware, Inc.
pub const VMWARE_VENDOR: u16 = 0x15AD;
/// VMware vmxnet3 paravirtual NIC.
pub const VMWARE_DEV_VMXNET3: u16 = 0x07B0;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Vmxnet3Error {
    /// One of the BARs (PT or VD) couldn't be mapped.
    BarMapFailed,
    /// DMA allocation for the DriverShared / ring page failed.
    NoMemory,
    /// VRRS read returned 0 — host advertises no compatible revision.
    NoRevisionSupported,
    /// Activate command returned non-zero ⇒ device-side rejection.
    ActivateFailed,
    /// Frame outside [1, 1518].
    FrameTooLong,
    /// No free TX descriptor for the producer cursor.
    TxRingFull,
    /// Link is down; Linux stops the TX queue on link-down
    /// (`vmxnet3_drv.c::vmxnet3_check_link` → `vmxnet3_tq_stop`),
    /// so frames are refused rather than sunk into a dead link.
    LinkDown,
}

// ── Pure ring rules (spec fixtures test these, never the impl) ────────

/// Flip a generation bit. Rings flip their gen exactly when their
/// cursor wraps (`vmxnet3_drv.c::vmxnet3_cmd_ring_adv_next2fill` uses
/// `VMXNET3_FLIP_RING_GEN`; QEMU `vmxnet3_ring_inc` XORs `ring->gen`
/// on wrap).
pub const fn flip_gen(gen: u32) -> u32 {
    gen ^ 1
}

/// Advance a ring cursor of `len` slots. Returns `(next, wrapped)`;
/// `wrapped` is exactly when the generation flips.
pub const fn ring_advance(idx: u32, len: u32) -> (u32, bool) {
    let next = idx + 1;
    if next >= len {
        (0, true)
    } else {
        (next, false)
    }
}

/// The gen a staged TX descriptor carries before publication.
/// `vmxnet3_drv.c::vmxnet3_map_pkt` writes the SOP desc with
/// "the previous gen bit" (`tq->tx_ring.gen ^ 0x1`) so the device
/// cannot fetch a half-written packet; `vmxnet3_tq_xmit` flips it to
/// the live gen only after `dma_wmb()` ("finally flips the GEN bit
/// of the SOP desc").
pub const fn tx_stage_gen(gen: u32) -> u32 {
    gen ^ 1
}

/// Decode a `VMXNET3_CMD_GET_LINK` reply word into a link sample.
/// `vmxnet3_drv.c::vmxnet3_check_link`: bit 0 is carrier, bits 31:16
/// are the negotiated speed in Mbit/s (rev ≥ 9 reports Gbps and
/// Linux multiplies by 1000; we negotiate rev 1, so the field is
/// already Mbit/s — QEMU reports `(1000 << 16) | 1`). No duplex bit
/// exists in the reply, so duplex is always `None` — never invented.
/// A zero speed field means "unknown", not 0 Mbit/s.
pub fn link_sample_from_get_link(reply: u32) -> LinkSample {
    let carrier = reply & 0x1 != 0;
    if !carrier {
        return LinkSample::DOWN;
    }
    let speed_mbps = reply >> 16;
    LinkSample::up(
        if speed_mbps == 0 {
            None
        } else {
            Some(speed_mbps)
        },
        None,
    )
}

/// RX drain budget per pump pass. Mirrors e1000's `RX_DRAIN_BUDGET`:
/// one pass drains at most this many completions, then yields, so a
/// burst cannot starve the TX pump or the scheduler.
pub const RX_DRAIN_BUDGET: usize = 64;

/// RX pump poll interval while idle (no MSI-X vector bound yet).
/// Matches e1000's 1 ms no-vector fallback.
pub const RX_POLL_INTERVAL_NS: u64 = 1_000_000;

/// Pump passes between periodic `GET_LINK` re-samples. The ECR event
/// word is the live path; this is only the lost-event safety net, so
/// ~1 s at the 1 ms poll interval is plenty.
pub const LINK_RESAMPLE_PASSES: u32 = 1000;

/// TX queue state, guarded by one lock so `transmit` (stack context)
/// and the TX pump's reclaim cannot interleave a slot allocation
/// with a completion walk.
#[derive(Copy, Clone, Debug)]
struct TxState {
    /// Next TX ring slot to fill.
    head: u32,
    /// Generation stamped on the next TX descriptor. Starts at
    /// `VMXNET3_INIT_GEN` (1); the device pops a descriptor exactly
    /// when its gen equals the ring's current gen (QEMU
    /// `vmxnet3_pop_next_tx_descr`).
    gen: u32,
    /// Free TX slots. Reclaim from the TX completion ring is the only
    /// thing that raises this; a slot is reusable only after its
    /// completion arrived, which proves the device consumed it.
    free: u32,
    /// Next TX completion-ring slot to check.
    comp_head: u32,
    /// Generation the next TX completion is expected to carry.
    comp_gen: u32,
}

/// RX queue state, guarded by one lock so the RX pump and the
/// syscall-context drain (`rx_pump_step`) cannot interleave a
/// completion walk with a refill.
#[derive(Copy, Clone, Debug)]
struct RxState {
    /// Next RX completion-ring slot to check.
    comp_head: u32,
    /// Generation the next RX completion is expected to carry.
    comp_gen: u32,
    /// Next ring-1 slot to refill.
    next2fill: u32,
    /// Generation stamped on the next refilled RX descriptor. Starts
    /// at 0, not 1: the initial fill already spent the gen-1 pass
    /// (all 256 slots stamped 1 at bring-up), so the first refill
    /// belongs to the device's second pass, which expects gen 0
    /// (Linux `vmxnet3_rq_alloc_rx_buf` leaves `ring->gen` flipped
    /// after the full initial fill for the same reason).
    gen: u32,
    /// Pump passes until the next periodic `GET_LINK` re-sample.
    link_resample_in: u32,
}

/// Driver-side datapath counters. The device also maintains its own
/// queue statistics in the queue-descriptor table
/// (`UPT1TxStats`/`UPT1RxStats`); these count what the driver itself
/// did, for diagnostics and the ethtool follow-up.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3Stats {
    /// Frames posted to the TX ring.
    pub tx_ok: u64,
    /// Frames refused (ring full, link down, or oversize).
    pub tx_drop: u64,
    /// Frames delivered to the stack / ring mirror.
    pub rx_ok: u64,
    /// Frames dropped on receive (error completion, zero length, or
    /// a multi-buffer frame this lane does not reassemble).
    pub rx_drop: u64,
}

// ── Driver state ────────────────────────────────────────────────────

/// Live vmxnet3 controller. Built by `bring_up`; stored in a static
/// instance registry so callbacks and diagnostics can retain it after probe.
pub struct Vmxnet3Nic {
    /// Bus identity and published name belong to this function, not the family.
    pub addr: narf_bus::BusAddr,
    ifname: crate::publish::IfName,
    /// PT register window (BAR0). Doorbells.
    pt: MmioRegion,
    /// VD register window (BAR1). Control plane.
    vd: MmioRegion,
    /// Driver-shared structure (`Vmxnet3_DriverShared`). Lives for
    /// the controller's lifetime; the device polls it on each command.
    shared: DmaBuffer,
    /// TX descriptor ring (`Vmxnet3_TxDesc[TX_RING_LEN]`).
    tx_ring: DmaBuffer,
    /// TX completion ring (`Vmxnet3_TxCompDesc[TX_COMP_RING_LEN]`).
    tx_comp_ring: DmaBuffer,
    /// RX descriptor ring 1 (`Vmxnet3_RxDesc[RX_RING_LEN]`). Linux
    /// uses two RX rings — ring 1 receives head buffers, ring 2 body
    /// buffers — but Stage 2 only wires ring 1.
    rx_ring1: DmaBuffer,
    /// RX descriptor ring 2 — body-only buffers per `VMXNET3_RXD_BTYPE_BODY`.
    rx_ring2: DmaBuffer,
    /// RX completion ring (`Vmxnet3_RxCompDesc[RX_COMP_RING_LEN]`).
    rx_comp_ring: DmaBuffer,
    /// Queue-descriptor table — TxQueueDesc + RxQueueDesc back-to-back.
    queue_desc: DmaBuffer,
    /// Per-RX-buffer DMA pool. One buffer per ring-1 descriptor.
    rx_buffers: alloc::vec::Vec<DmaBuffer>,
    /// Per-TX-buffer DMA pool. One scratch per ring slot, reused.
    tx_buffers: alloc::vec::Vec<DmaBuffer>,
    /// TX ring cursors + completion state. One lock covers the whole
    /// TX side so `transmit` and completion reclaim cannot interleave.
    tx_state: IrqSafeSpinLock<TxState>,
    /// RX ring cursors + completion state. One lock covers the whole
    /// RX side so the pump and the syscall-context drain cannot
    /// interleave a completion walk with a refill.
    rx_state: IrqSafeSpinLock<RxState>,
    /// RX frame-ring producer. Held here until a consumer takes it
    /// via `Interface::rx_ring`; the pump mirrors frames into it
    /// only once a consumer has attached (see `rx_mirror_enabled`).
    rx_ipc_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    /// RX frame-ring consumer. Handed out once via
    /// `Interface::rx_ring` (Stage-3 rings are never handed back).
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    /// TX frame-ring producer. Held here until a consumer takes it
    /// via `Interface::tx_ring`; the TX pump owns the consumer half.
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    /// A frame-ring consumer has attached (set in
    /// `Interface::rx_ring` at take time, e1000's shape). The mirror
    /// gate is this flag alone — never the published name — so an
    /// attached-but-unpublished device still mirrors, matching the
    /// `publish::dispatch_rx` contract.
    rx_mirror_enabled: AtomicBool,
    /// Live carrier, updated by the RX pump's ECR drain / periodic
    /// `GET_LINK` re-sample. `Interface::link_up` reads this, not
    /// the probe-time snapshot below.
    live_link_up: AtomicBool,
    /// Live negotiated speed in Mbit/s, 0 when unknown. Updated with
    /// `live_link_up`.
    live_link_speed_mbps: AtomicU32,
    /// Driver-side datapath counters (see `Vmxnet3Stats`).
    tx_ok: AtomicU64,
    tx_drop: AtomicU64,
    rx_ok: AtomicU64,
    rx_drop: AtomicU64,
    /// Negotiated revision. 1 = `VMXNET3_REV_1`, the floor every host
    /// supports. Stage 0 always negotiates 1.
    pub revision: u32,
    /// MAC address. Read post-activate from MACL/MACH.
    pub mac: [u8; 6],
    /// `true` if `VMXNET3_CMD_GET_LINK` reported a live link at
    /// bring-up. Bit 0 of the CMD readback (`vmxnet3_drv.c` line 203).
    /// Probe-time snapshot only; live carrier is `live_link_up`.
    pub link_up: bool,
}

impl core::fmt::Debug for Vmxnet3Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vmxnet3Nic")
            .field("revision", &self.revision)
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .finish_non_exhaustive()
    }
}

impl Vmxnet3Nic {
    /// The name assigned to this NIC, or empty before publication.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }

    /// Bring up the controller. See module-level docs for the
    /// 5-step sequence; this implements Stage 0 + Stage 1 + Stage 2
    /// plus the Stage 3 frame-ring channels: the returned
    /// `Producer` feeds the RX pump's mirror and the returned
    /// `Consumer` feeds the TX pump.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg window exclusively for
    /// the duration of `bring_up`.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, WriteCap>,
    ) -> Result<(Self, Producer<Frame, RX_RING_N>, Consumer<Frame, TX_RING_N>), Vmxnet3Error> {
        // 1. Map BAR0 (PT — doorbells) + BAR1 (VD — control plane).
        //    `vmxnet3_defs.h` reserves 4 KiB at each (`VMXNET3_PT_REG_
        //    SIZE` / `VMXNET3_VD_REG_SIZE`).
        // SAFETY: caller-asserted exclusive ownership.
        let pt = unsafe { map_bar(device, 0) }.map_err(|_| Vmxnet3Error::BarMapFailed)?;
        // SAFETY: same.
        let vd = unsafe { map_bar(device, 1) }.map_err(|_| Vmxnet3Error::BarMapFailed)?;

        // 2. Probe VRRS. The host returns a bitmap of supported
        //    Vmxnet3 revisions (bit N ⇒ REV_(N+1)). We always
        //    acknowledge REV_1 (bit 0) — the floor every ESX from
        //    4.0 onward exposes. Stage 0 doesn't probe higher revs.
        // SAFETY: identity-mapped MMIO.
        let vrrs = unsafe { vd.read32(REG_VRRS) };
        if vrrs == 0 {
            return Err(Vmxnet3Error::NoRevisionSupported);
        }
        let chosen_rev_bit: u32 = 1 << 0;
        if vrrs & chosen_rev_bit == 0 {
            return Err(Vmxnet3Error::NoRevisionSupported);
        }
        // SAFETY: same.
        unsafe {
            vd.write32(REG_VRRS, chosen_rev_bit);
        }

        // 3. UVRS — same dance for the UPT (Universal Pass-Through)
        //    version. Bit 0 == UPT version 1. Linux: `vmxnet3_acquire_
        //    shared_intr_resources` writes 1 here right after VRRS.
        // SAFETY: same.
        unsafe {
            vd.write32(REG_UVRS, 1 << 0);
        }

        // 4. Allocate the DriverShared structure. `Vmxnet3_DriverShared`
        //    sits at the head of a contiguous DMA page; the device
        //    polls `cu.cmdInfo` + `devRead` on each command. Stage 0
        //    only stamps the magic + size; Stage 1+ fills `devRead`.
        let shared = alloc_coherent(
            core::mem::size_of::<Vmxnet3DriverShared>(),
            DomainId::DRIVER_0,
        )
        .map_err(|_| Vmxnet3Error::NoMemory)?;
        // SAFETY: alloc_coherent returns a zeroed identity-mapped page.
        let shared_ptr = shared.cpu_mut_ptr::<Vmxnet3DriverShared>();
        // SAFETY: shared_ptr fits an identity-mapped DMA page sized
        // for sizeof::<Vmxnet3DriverShared>().
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            (*shared_ptr).magic = VMXNET3_REV1_MAGIC.to_le();
            (*shared_ptr).size = (core::mem::size_of::<Vmxnet3DriverShared>() as u32).to_le();
        }

        // 5. Allocate TX + TX-comp + RX (ring1 + ring2) + RX-comp
        //    descriptor rings, plus the queue-descriptor table (one
        //    TxQueueDesc + one RxQueueDesc back-to-back, 128-byte
        //    aligned per `VMXNET3_QUEUE_DESC_ALIGN`).
        let tx_ring = alloc_coherent(TX_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        let tx_comp_ring = alloc_coherent(TX_COMP_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        let rx_ring1 = alloc_coherent(RX_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        let rx_ring2 = alloc_coherent(RX_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        let rx_comp_ring = alloc_coherent(RX_COMP_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        let queue_desc = alloc_coherent(
            core::mem::size_of::<Vmxnet3TxQueueDesc>() + core::mem::size_of::<Vmxnet3RxQueueDesc>(),
            DomainId::DRIVER_0,
        )
        .map_err(|_| Vmxnet3Error::NoMemory)?;

        // 6. RX buffer pool — one DMA buffer per ring-1 descriptor.
        //    Each is `RX_BUF_LEN` bytes, matching the standard
        //    `VMXNET3_DEF_RXDATA_DESC_SIZE`-class non-jumbo MTU.
        let mut rx_buffers: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for _ in 0..RX_RING_LEN {
            rx_buffers.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0)
                    .map_err(|_| Vmxnet3Error::NoMemory)?,
            );
        }
        let mut tx_buffers: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            tx_buffers.push(
                alloc_coherent(TX_BUF_LEN, DomainId::DRIVER_0)
                    .map_err(|_| Vmxnet3Error::NoMemory)?,
            );
        }

        // 7. Pre-fill ring-1 RX descriptors. The device DMAs the
        //    head-buffer of every incoming frame into the slot whose
        //    GEN bit matches the driver's current GEN; once consumed,
        //    the device flips its GEN and writes a comp-ring entry.
        //    Stage 2: gen = 1 on every initial slot (per
        //    `VMXNET3_INIT_GEN`).
        for (i, buf) in rx_buffers.iter().enumerate().take(RX_RING_LEN) {
            let buf_pa = buf.dma_addr().raw();
            // len in low 14 bits, btype HEAD (=0), gen=1 — the whole
            // ring is offered at once. The refill generation starts
            // at 0 (`RxState::gen`): the initial fill already spent
            // the gen-1 pass, so the first refill belongs to the
            // device's second pass. Unlike Linux
            // (`vmxnet3_rq_alloc_rx_buf` leaves the last slot
            // unready so `next2fill != next2comp` distinguishes full
            // from empty), no slot is held back here: our refill is
            // driven by completions, never by comparing cursors, so
            // no gap is needed to disambiguate.
            let desc = Vmxnet3RxDesc {
                addr: buf_pa.to_le(),
                flags: rx_desc_flags(RX_BUF_LEN as u32, VMXNET3_RXD_BTYPE_HEAD, VMXNET3_INIT_GEN)
                    .to_le(),
                ext1: 0,
            };
            // SAFETY: identity-mapped DMA page, i < RX_RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    rx_ring1.cpu_mut_ptr_at::<Vmxnet3RxDesc>(
                        (i * core::mem::size_of::<Vmxnet3RxDesc>()) as u64,
                    ),
                    desc,
                );
            }
        }

        // 8. Stamp DriverShared.devRead.misc with the queue-desc
        //    table phys addr + queue/ring sizes, devRead.intrConf
        //    with a single auto-mask vector, and the queue-desc
        //    table itself with the ring-base PAs.
        let queue_desc_pa = queue_desc.dma_addr().raw();
        // SAFETY: identity-mapped DMA page. devRead lives at offset
        // 8 of Vmxnet3DriverShared (after magic + size).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            (*shared_ptr).devRead.misc.driverInfo.version = VMXNET3_DRIVER_VERSION_NUM.to_le();
            (*shared_ptr).devRead.misc.driverInfo.gos = Vmxnet3GOSInfo::for_narf().to_raw().to_le();
            (*shared_ptr).devRead.misc.driverInfo.vmxnet3RevSpt = 1u32.to_le();
            (*shared_ptr).devRead.misc.driverInfo.uptVerSpt = 1u32.to_le();
            (*shared_ptr).devRead.misc.uptFeatures = 0u64.to_le();
            (*shared_ptr).devRead.misc.ddPA = shared.dma_addr().raw().to_le();
            (*shared_ptr).devRead.misc.queueDescPA = queue_desc_pa.to_le();
            (*shared_ptr).devRead.misc.ddLen =
                (core::mem::size_of::<Vmxnet3DriverShared>() as u32).to_le();
            (*shared_ptr).devRead.misc.queueDescLen = ((core::mem::size_of::<Vmxnet3TxQueueDesc>()
                + core::mem::size_of::<Vmxnet3RxQueueDesc>())
                as u32)
                .to_le();
            (*shared_ptr).devRead.misc.mtu = (DEFAULT_MTU as u32).to_le();
            (*shared_ptr).devRead.misc.maxNumRxSG = 1u16.to_le();
            (*shared_ptr).devRead.misc.numTxQueues = 1;
            (*shared_ptr).devRead.misc.numRxQueues = 1;

            // Single MSI-X-ish vector slot. Real MSI-X wiring lands
            // in a follow-up; Stage 2 leaves the interrupt subsystem
            // disabled at IMR until the bus-side MSI-X bring-up
            // pumps a vector in.
            (*shared_ptr).devRead.intrConf.autoMask = 0;
            (*shared_ptr).devRead.intrConf.numIntrs = 1;
            (*shared_ptr).devRead.intrConf.eventIntrIdx = 0;
            (*shared_ptr).devRead.intrConf.intrCtrl = VMXNET3_IC_DISABLE_ALL.to_le();

            // RX filter: receive unicast + broadcast (no multicast
            // filtering at Stage 2). `vmxnet3_defs.h` enum.
            (*shared_ptr).devRead.rxFilterConf.rxMode =
                (VMXNET3_RXM_UCAST | VMXNET3_RXM_BCAST).to_le();
            (*shared_ptr).devRead.rxFilterConf.mfTableLen = 0;
            (*shared_ptr).devRead.rxFilterConf.mfTablePA = 0;
        }

        // 9. Queue-descriptor table. The TxQueueDesc lives at the head
        //    of the page; the RxQueueDesc follows immediately. Each
        //    carries the ring base PAs + sizes the device needs to
        //    DMA the rings.
        // SAFETY: identity-mapped DMA page sized for both descs.
        unsafe {
            let txqd = queue_desc.cpu_mut_ptr::<Vmxnet3TxQueueDesc>();
            (*txqd).conf.txRingBasePA = tx_ring.dma_addr().raw().to_le();
            (*txqd).conf.dataRingBasePA = 0;
            (*txqd).conf.compRingBasePA = tx_comp_ring.dma_addr().raw().to_le();
            (*txqd).conf.ddPA = 0;
            (*txqd).conf.txRingSize = (TX_RING_LEN as u32).to_le();
            (*txqd).conf.dataRingSize = 0;
            (*txqd).conf.compRingSize = (TX_COMP_RING_LEN as u32).to_le();
            (*txqd).conf.ddLen = 0;
            (*txqd).conf.intrIdx = 0;
            (*txqd).conf.txDataRingDescSize = 0;

            let rxqd = queue_desc.cpu_mut_ptr_at::<Vmxnet3RxQueueDesc>(core::mem::size_of::<
                Vmxnet3TxQueueDesc,
            >() as u64);
            (*rxqd).conf.rxRingBasePA[0] = rx_ring1.dma_addr().raw().to_le();
            (*rxqd).conf.rxRingBasePA[1] = rx_ring2.dma_addr().raw().to_le();
            (*rxqd).conf.compRingBasePA = rx_comp_ring.dma_addr().raw().to_le();
            (*rxqd).conf.ddPA = 0;
            (*rxqd).conf.rxDataRingBasePA = 0;
            (*rxqd).conf.rxRingSize[0] = (RX_RING_LEN as u32).to_le();
            (*rxqd).conf.rxRingSize[1] = (RX_RING_LEN as u32).to_le();
            (*rxqd).conf.compRingSize = (RX_COMP_RING_LEN as u32).to_le();
            (*rxqd).conf.ddLen = 0;
            (*rxqd).conf.intrIdx = 0;
            (*rxqd).conf.rxDataRingDescSize = 0;
        }

        // 10. Publish the DriverShared phys addr split into DSAL/DSAH.
        //     The device latches these on the next CMD write, so the
        //     order matters: DSAL first, DSAH second, then CMD.
        let shared_pa = shared.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            vd.write32(REG_DSAL, (shared_pa & 0xFFFF_FFFF) as u32);
            vd.write32(REG_DSAH, (shared_pa >> 32) as u32);
        }
        compiler_fence(Ordering::SeqCst);

        // 11. ACTIVATE_DEV. The device reads DriverShared.devRead +
        //     the queue-desc table, validates the layout, and either
        //     writes 0 (success) or non-zero (rejection) back to CMD.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            vd.write32(REG_CMD, VMXNET3_CMD_ACTIVATE_DEV);
        }
        // SAFETY: same.
        let activate_status = unsafe { vd.read32(REG_CMD) };
        if activate_status != 0 {
            return Err(Vmxnet3Error::ActivateFailed);
        }

        // 12. Read MAC from MACL/MACH. Linux: `vmxnet3_drv.c::
        //     vmxnet3_set_mac_addr` writes; we read the perm MAC.
        // SAFETY: same.
        let macl = unsafe { vd.read32(REG_MACL) };
        // SAFETY: same.
        let mach = unsafe { vd.read32(REG_MACH) };
        let mac = [
            (macl & 0xFF) as u8,
            ((macl >> 8) & 0xFF) as u8,
            ((macl >> 16) & 0xFF) as u8,
            ((macl >> 24) & 0xFF) as u8,
            (mach & 0xFF) as u8,
            ((mach >> 8) & 0xFF) as u8,
        ];

        // 13. GET_LINK. The CMD register is overloaded: writing a
        //     get-class cmd (≥ 0xF00D0000) then reading CMD gives the
        //     reply value. Bit 0 = link up, bits 31:16 = speed in
        //     Mbit/s (`vmxnet3_drv.c::vmxnet3_check_link`).
        // SAFETY: same.
        unsafe {
            vd.write32(REG_CMD, VMXNET3_CMD_GET_LINK);
        }
        // SAFETY: same.
        let link_reply = unsafe { vd.read32(REG_CMD) };
        let initial_sample = link_sample_from_get_link(link_reply);
        let link_up = initial_sample.carrier;

        // 14. No RX producer doorbell write at init. The device
        //     starts from the generation bits (QEMU
        //     `vmxnet3_get_next_head_rx_descr` pops a descriptor
        //     exactly when its gen equals the ring's current gen),
        //     and Linux never writes RXPROD at init either — it
        //     rings it only when the queue-descriptor control word
        //     `updateRxProd` is set by the device
        //     (`vmxnet3_rq_rx_complete`). QEMU never sets it.
        //     `pt` is still owned here; the TX doorbell is rung by
        //     `transmit` and the RX doorbell by the drain, when the
        //     device asks for it.
        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let _ =
            writeln!(
            narf_console::Writer,
            "  vmxnet3: VRRS={:#010x} rev=1 MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
            vrrs,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if link_up { "up" } else { "down" },
        );

        Ok((
            Self {
                addr: device.addr,
                ifname: crate::publish::IfName::new(),
                pt,
                vd,
                shared,
                tx_ring,
                tx_comp_ring,
                rx_ring1,
                rx_ring2,
                rx_comp_ring,
                queue_desc,
                rx_buffers,
                tx_buffers,
                tx_state: IrqSafeSpinLock::new(TxState {
                    head: 0,
                    gen: VMXNET3_INIT_GEN,
                    free: TX_RING_LEN as u32,
                    comp_head: 0,
                    comp_gen: VMXNET3_INIT_GEN,
                }),
                rx_state: IrqSafeSpinLock::new(RxState {
                    comp_head: 0,
                    comp_gen: VMXNET3_INIT_GEN,
                    next2fill: 0,
                    gen: 0,
                    link_resample_in: LINK_RESAMPLE_PASSES,
                }),
                rx_ipc_prod: IrqSafeSpinLock::new(None),
                rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
                rx_mirror_enabled: AtomicBool::new(false),
                live_link_up: AtomicBool::new(link_up),
                live_link_speed_mbps: AtomicU32::new(initial_sample.speed_mbps.unwrap_or(0)),
                tx_ok: AtomicU64::new(0),
                tx_drop: AtomicU64::new(0),
                rx_ok: AtomicU64::new(0),
                rx_drop: AtomicU64::new(0),
                revision: 1,
                mac,
                link_up,
            },
            rx_prod,
            tx_cons,
        ))
    }

    /// Ring the TX producer doorbell. Stage 2 helper used by smoke
    /// tests to assert a descriptor round-trip; the Stage 3
    /// `transmit` path rings it after every publish.
    ///
    /// # Safety
    /// The MMIO BAR is identity-mapped + owned by this driver.
    pub fn ring_tx_doorbell(&self, idx: u32) {
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.pt.write32(REG_TXPROD, idx);
        }
    }

    /// Ring the RX-ring-1 producer doorbell. Same shape as TX above.
    pub fn ring_rx_doorbell(&self, idx: u32) {
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.pt.write32(REG_RXPROD, idx);
        }
    }

    /// Current link sample from the live atomics (pump-maintained).
    pub fn link_sample(&self) -> LinkSample {
        if !self.live_link_up.load(Ordering::Acquire) {
            return LinkSample::DOWN;
        }
        let speed = self.live_link_speed_mbps.load(Ordering::Acquire);
        LinkSample::up(if speed == 0 { None } else { Some(speed) }, None)
    }

    /// Driver-side datapath counters.
    pub fn stats(&self) -> Vmxnet3Stats {
        Vmxnet3Stats {
            tx_ok: self.tx_ok.load(Ordering::Relaxed),
            tx_drop: self.tx_drop.load(Ordering::Relaxed),
            rx_ok: self.rx_ok.load(Ordering::Relaxed),
            rx_drop: self.rx_drop.load(Ordering::Relaxed),
        }
    }

    /// The TX completion at `idx` if the device has written it for
    /// generation `gen`, else `None`. Gen-first, see
    /// [`Vmxnet3TxCompDesc::sample`].
    fn read_tx_comp(&self, idx: u32, gen: u32) -> Option<Vmxnet3TxCompDesc> {
        Vmxnet3TxCompDesc::sample(gen, |dword| {
            // SAFETY: TX comp ring page; `idx < TX_COMP_RING_LEN` at every
            // caller and `dword < 4`, so the aligned dword lies inside the
            // 16-byte descriptor `idx`.
            unsafe {
                core::ptr::read_volatile(
                    self.tx_comp_ring
                        .cpu_ptr_at::<u32>((idx as usize * 16 + dword * 4) as u64),
                )
            }
        })
    }

    /// The RX completion at `idx` if the device has written it for
    /// generation `gen`, else `None`. Gen-first, see
    /// [`Vmxnet3RxCompDesc::sample`].
    fn read_rx_comp(&self, idx: u32, gen: u32) -> Option<Vmxnet3RxCompDesc> {
        Vmxnet3RxCompDesc::sample(gen, |dword| {
            // SAFETY: RX comp ring page; `idx < RX_COMP_RING_LEN` at every
            // caller and `dword < 4`, so the aligned dword lies inside the
            // 16-byte descriptor `idx`.
            unsafe {
                core::ptr::read_volatile(
                    self.rx_comp_ring
                        .cpu_ptr_at::<u32>((idx as usize * 16 + dword * 4) as u64),
                )
            }
        })
    }

    /// Reclaim TX slots whose completions the device has written.
    /// Mirrors `vmxnet3_drv.c::vmxnet3_tq_tx_complete`: walk the
    /// completion ring while the gen matches, free the slot named by
    /// `txdIdx`, advance (flipping the comp gen on wrap). A slot is
    /// reusable only after its completion arrived, which proves the
    /// device consumed it. Returns the number of slots freed.
    pub fn reclaim_tx_completed(&self) -> u32 {
        let mut state = self.tx_state.lock();
        let mut reclaimed = 0;
        while reclaimed < TX_COMP_RING_LEN as u32 {
            let Some(comp) = self.read_tx_comp(state.comp_head, state.comp_gen) else {
                break;
            };
            // Pair the device's completion write with the CPU's later
            // buffer reuse.
            compiler_fence(Ordering::SeqCst);
            let idx = comp.txd_idx();
            if (idx as usize) < TX_RING_LEN && state.free < TX_RING_LEN as u32 {
                state.free += 1;
            }
            let (next, wrapped) = ring_advance(state.comp_head, TX_COMP_RING_LEN as u32);
            state.comp_head = next;
            if wrapped {
                state.comp_gen = flip_gen(state.comp_gen);
            }
            reclaimed += 1;
        }
        reclaimed
    }

    /// Transmit one frame: copy it into the next TX slot's scratch
    /// buffer, publish a single-descriptor packet (SOP == EOP, CQ
    /// requested so the device writes a completion), and ring the TX
    /// producer doorbell with the new head.
    ///
    /// The descriptor is staged with the inverted gen and flipped to
    /// the live gen only after a fence — the Linux SOP publish
    /// protocol (`vmxnet3_map_pkt` stages `gen ^ 1`;
    /// `vmxnet3_tq_xmit` flips it after `dma_wmb()`), so the device
    /// can never fetch a half-written packet. No TSO/CSUM offload is
    /// advertised, so every frame here is a plain frame (`om` = 0).
    pub fn transmit(&self, frame: &[u8]) -> Result<(), Vmxnet3Error> {
        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
            self.tx_drop.fetch_add(1, Ordering::Relaxed);
            return Err(Vmxnet3Error::FrameTooLong);
        }
        if !self.live_link_up.load(Ordering::Acquire) {
            self.tx_drop.fetch_add(1, Ordering::Relaxed);
            return Err(Vmxnet3Error::LinkDown);
        }
        // Reclaim first so a burst of completions frees slots.
        self.reclaim_tx_completed();
        let mut state = self.tx_state.lock();
        if state.free == 0 {
            self.tx_drop.fetch_add(1, Ordering::Relaxed);
            return Err(Vmxnet3Error::TxRingFull);
        }
        let slot = state.head as usize;
        let gen = state.gen;
        let buf = &self.tx_buffers[slot];
        let buf_pa = buf.dma_addr().raw();
        // SAFETY: scratch buffer is TX_BUF_LEN bytes and owned by
        // this slot; the frame fits (checked above); one writer
        // under `tx_state`.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.cpu_mut_ptr::<u8>(), frame.len());
        }
        // Stage with the inverted gen, fence, then flip gen to
        // publish. `dword2` sits at offset 8 in the 16-byte desc.
        let staged = Vmxnet3TxDesc::new(buf_pa, frame.len() as u32, tx_stage_gen(gen), true, true);
        let slot_off = (slot * core::mem::size_of::<Vmxnet3TxDesc>()) as u64;
        // SAFETY: TX ring page; `slot < TX_RING_LEN`.
        unsafe {
            core::ptr::write_volatile(
                self.tx_ring.cpu_mut_ptr_at::<Vmxnet3TxDesc>(slot_off),
                staged,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same slot, dword2 word.
        unsafe {
            core::ptr::write_volatile(
                self.tx_ring.cpu_mut_ptr_at::<u32>(slot_off + 8),
                staged.dword2 ^ TXD_GEN_BIT,
            );
        }
        let (next_head, wrapped) = ring_advance(state.head, TX_RING_LEN as u32);
        state.head = next_head;
        if wrapped {
            state.gen = flip_gen(state.gen);
        }
        state.free -= 1;
        drop(state);
        compiler_fence(Ordering::SeqCst);
        // Linux writes `next2fill` to TXPROD after posting
        // (`vmxnet3_tq_xmit`); QEMU processes the queue on the write.
        self.ring_tx_doorbell(next_head);
        self.tx_ok.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Rewrite one ring-1 RX descriptor for the same buffer with a
    /// fresh generation. The buffer address never changes on refill
    /// (the ring buffer stays driver-owned; the stack consumes a
    /// borrowed slice), so only the `flags` word changes meaning —
    /// and it lands as a single aligned 4-byte store whose gen bit
    /// is the publish the device keys on.
    fn write_rx_desc(&self, idx: u32, gen: u32) {
        let buf = &self.rx_buffers[idx as usize];
        let desc = Vmxnet3RxDesc {
            addr: buf.dma_addr().raw().to_le(),
            flags: rx_desc_flags(RX_BUF_LEN as u32, VMXNET3_RXD_BTYPE_HEAD, gen).to_le(),
            ext1: 0,
        };
        // SAFETY: RX ring-1 page; `idx < RX_RING_LEN` at every caller.
        unsafe {
            core::ptr::write_volatile(
                self.rx_ring1.cpu_mut_ptr_at::<Vmxnet3RxDesc>(
                    (idx as usize * core::mem::size_of::<Vmxnet3RxDesc>()) as u64,
                ),
                desc,
            );
        }
    }

    /// Whether the device asked for RX producer doorbell updates.
    /// `RxQueueCtrl.updateRxProd` lives in the queue-descriptor
    /// table and is device-written; Linux rings RXPROD only when it
    /// is set (`vmxnet3_rq_rx_complete`). QEMU never sets it.
    fn rx_queue_update_rx_prod(&self) -> bool {
        // SAFETY: queue-desc page; the RxQueueDesc follows the
        // TxQueueDesc immediately.
        unsafe {
            let rxqd =
                self.queue_desc
                    .cpu_ptr_at::<Vmxnet3RxQueueDesc>(
                        core::mem::size_of::<Vmxnet3TxQueueDesc>() as u64
                    );
            (*rxqd).ctrl.updateRxProd != 0
        }
    }

    /// Drain RX completions, calling `f` with each received frame's
    /// bytes borrowed straight out of its ring buffer (the stack
    /// consumes the slice synchronously, e1000's shape). Returns the
    /// number of completions processed.
    ///
    /// Mirrors `vmxnet3_drv.c::vmxnet3_rq_rx_complete`: walk the
    /// completion ring while the gen matches (`dma_rmb()` after
    /// reading gen), take `len` bytes from `rx_buffers[rxdIdx]`,
    /// refill the descriptor, and advance. Single-buffer frames only
    /// (`sop && eop`, no error, non-zero length): a multi-buffer
    /// frame would need ring-2 BODY buffers, which this lane never
    /// fills (1500 MTU fits the 1536-byte head buffer), so a
    /// non-EOP completion is dropped and its slot refilled rather
    /// than reassembled.
    pub fn rx_drain_in_place<F: FnMut(&mut [u8])>(&self, budget: usize, mut f: F) -> usize {
        let mut delivered = 0;
        let mut state = self.rx_state.lock();
        while delivered < budget {
            let Some(comp) = self.read_rx_comp(state.comp_head, state.comp_gen) else {
                break;
            };
            // Pair the device's completion write with the CPU's later
            // buffer reads (Linux: `dma_rmb()` after reading gen).
            compiler_fence(Ordering::SeqCst);
            let idx = comp.rxd_idx();
            if (idx as usize) < RX_RING_LEN {
                let len = comp.len();
                if comp.sop() && comp.eop() && !comp.err() && len != 0 {
                    let take = (len as usize).min(RX_BUF_LEN);
                    // SAFETY: `idx < RX_RING_LEN`; `take` is clamped
                    // to the ring buffer's length.
                    let frame = unsafe {
                        core::slice::from_raw_parts_mut(
                            self.rx_buffers[idx as usize].cpu_mut_ptr::<u8>(),
                            take,
                        )
                    };
                    f(frame);
                    self.rx_ok.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.rx_drop.fetch_add(1, Ordering::Relaxed);
                }
                // Refill in `next2fill` order through `idx`, stamping
                // the current refill gen and flipping it on wrap.
                // In-order completions make this exactly one slot;
                // the loop only exists for descriptors the device
                // skipped (Linux's out-of-order refill path).
                loop {
                    let cur = state.next2fill;
                    self.write_rx_desc(cur, state.gen);
                    let (next, wrapped) = ring_advance(cur, RX_RING_LEN as u32);
                    state.next2fill = next;
                    if wrapped {
                        state.gen = flip_gen(state.gen);
                    }
                    if cur == idx {
                        break;
                    }
                }
            } else {
                // Bogus completion index from faulty hardware: count
                // it and move on without touching any ring slot.
                self.rx_drop.fetch_add(1, Ordering::Relaxed);
            }
            let (next, wrapped) = ring_advance(state.comp_head, RX_COMP_RING_LEN as u32);
            state.comp_head = next;
            if wrapped {
                state.comp_gen = flip_gen(state.comp_gen);
            }
            delivered += 1;
        }
        // Ring RXPROD only when the device asked for it, and only on
        // a 16-descriptor boundary, exactly like Linux
        // (`vmxnet3_rq_rx_complete`).
        let next2fill = state.next2fill;
        drop(state);
        if self.rx_queue_update_rx_prod() && (next2fill & 0xf) == 0 {
            self.ring_rx_doorbell(next2fill);
        }
        delivered
    }

    /// Re-sample link state from the device and republish on change.
    fn check_link_and_publish(&self) {
        // SAFETY: identity-mapped MMIO; GET_LINK is a readback
        // command (write CMD, read CMD).
        unsafe {
            self.vd.write32(REG_CMD, VMXNET3_CMD_GET_LINK);
        }
        // SAFETY: same.
        let reply = unsafe { self.vd.read32(REG_CMD) };
        let sample = link_sample_from_get_link(reply);
        let prev_up = self.live_link_up.swap(sample.carrier, Ordering::AcqRel);
        let prev_speed = self
            .live_link_speed_mbps
            .swap(sample.speed_mbps.unwrap_or(0), Ordering::AcqRel);
        if prev_up != sample.carrier || prev_speed != sample.speed_mbps.unwrap_or(0) {
            crate::publish::publish_link(self.ifname(), sample);
        }
    }

    /// Drain device events from `DriverShared.ecr`. The device writes
    /// events there; the driver acks by writing the bits back to BAR1
    /// ECR (Linux `vmxnet3_process_events` / `vmxnet3_ack_events`).
    /// With interrupts disabled this poll is the only event path until
    /// MSI-X lands. A periodic `GET_LINK` re-sample covers a lost
    /// `ECR_LINK` event.
    pub fn poll_events(&self) {
        let shared_ptr = self.shared.cpu_mut_ptr::<Vmxnet3DriverShared>();
        // SAFETY: identity-mapped DMA; `ecr` is device-written.
        let events = unsafe { core::ptr::read_volatile(&(*shared_ptr).ecr) };
        let events = u32::from_le(events);
        if events != 0 {
            // SAFETY: identity-mapped MMIO; ECR is write-to-ack.
            unsafe {
                self.vd.write32(REG_ECR, events);
            }
            compiler_fence(Ordering::SeqCst);
            if events & VMXNET3_ECR_LINK != 0 {
                self.check_link_and_publish();
            }
            if events & (VMXNET3_ECR_RQERR | VMXNET3_ECR_TQERR) != 0 {
                // Queue error: the queue-status words in the
                // queue-descriptor table carry the device's error
                // code. A full recovery (`reset`) is a follow-up's
                // job; count it here so the failure is visible
                // instead of silent.
                self.rx_drop.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut state = self.rx_state.lock();
        if state.link_resample_in == 0 {
            state.link_resample_in = LINK_RESAMPLE_PASSES;
            drop(state);
            self.check_link_and_publish();
        } else {
            state.link_resample_in -= 1;
        }
    }

    /// Quiesce the device — drain in-flight DMA and tell the host to
    /// stop generating events. Must be called before `reset_dev` to
    /// guarantee the host has stopped writing into our rings.
    ///
    /// Linux ref: `vmxnet3_drv.c::vmxnet3_quiesce_dev` (line 3253).
    /// The host sets `VMXNET3_STATE_BIT_QUIESCED` once the command
    /// completes; on ESX this is synchronous (command write returns
    /// only after the device has drained). Our poll loop mirrors the
    /// Linux pattern of writing the CMD register and then reading it
    /// back — a non-zero readback would mean rejection, but quiesce
    /// has no explicit rejection code in the spec so we log and proceed.
    ///
    /// # Safety
    /// Caller must ensure no concurrent TX/RX DMA is in flight to
    /// the descriptor rings while this runs.
    pub unsafe fn quiesce_dev(&self) {
        // SAFETY: identity-mapped BAR1 MMIO.
        unsafe {
            self.vd.write32(REG_CMD, VMXNET3_CMD_QUIESCE_DEV);
        }
        // The command register doubles as a status latch for "get"
        // class commands (≥ 0xF00D0000); for "set" class (0xCAFE…)
        // the readback reflects completion status — 0 = success.
        // vmxnet3_drv.c line 3262 writes without checking; we do the
        // same and rely on a subsequent RESET if the NIC is wedged.
        compiler_fence(Ordering::SeqCst);
    }

    /// Reset the device — restores it to a post-power-on state, ready
    /// for a fresh `bring_up` / activate sequence.
    ///
    /// Linux ref: `vmxnet3_drv.c::vmxnet3_reset_dev` (line 3243).
    /// Full recovery sequence: quiesce → reset → re-activate, per
    /// `vmxnet3_drv.c::vmxnet3_reset_work` (line 3937) and
    /// `vmxnet3_drv.c` line 3648–3649.
    ///
    /// # Safety
    /// Same as `quiesce_dev` — caller owns the BAR exclusively.
    pub unsafe fn reset_dev(&self) {
        // SAFETY: identity-mapped BAR1 MMIO.
        unsafe {
            self.vd.write32(REG_CMD, VMXNET3_CMD_RESET_DEV);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Full error-recovery sequence: quiesce, reset, re-activate.
    ///
    /// Mirrors `vmxnet3_drv.c::vmxnet3_reset_work` (line 3937):
    /// ```c
    ///   vmxnet3_quiesce_dev(adapter);
    ///   vmxnet3_reset_dev(adapter);
    ///   vmxnet3_activate_dev(adapter);
    /// ```
    ///
    /// After reset the DriverShared structure + ring base PAs are
    /// already in-place (they survive across reset; the device re-reads
    /// them from DSAL/DSAH on ACTIVATE_DEV). The DSAL/DSAH registers
    /// must be re-written because RESET_DEV clears them (documented
    /// in `vmxnet3_defs.h`). Re-writing shared-PA and re-issuing
    /// ACTIVATE_DEV restores full RX/TX.
    ///
    /// The rings themselves do NOT survive: the device restarts its
    /// cursors at gen 1, so stale descriptors would be re-fetched
    /// (a TX desc still carrying gen 1 looks fresh) and stale
    /// completions would be misread as new. Linux zeroes the rings
    /// on re-init (`vmxnet3_tq_init` / `vmxnet3_rq_init` memset the
    /// TX, TX-comp and RX-comp rings), and this does the same —
    /// zero TX + both comp rings, refill the RX ring, reset every
    /// cursor — before re-activating.
    ///
    /// Returns `Ok(())` on successful re-activate; `Err(ActivateFailed)`
    /// if the device rejects the activate after reset.
    ///
    /// # Safety
    /// Caller must hold exclusive access to the BAR windows.
    pub unsafe fn reset(&self) -> Result<(), Vmxnet3Error> {
        // Step 1: quiesce — stop host-side DMA into our rings.
        // Safety: caller-asserted exclusive BAR access.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.quiesce_dev() };

        // Step 2: hard reset — returns device to power-on state.
        // Safety: same.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.reset_dev() };

        // Step 2b: re-init the rings. Zero the TX ring (a stale desc
        // with gen 1 would be re-fetched as fresh) and both comp
        // rings (a stale completion with gen 1 would be misread as
        // new), refill the RX ring, and reset every cursor to its
        // bring-up value.
        // SAFETY: identity-mapped DMA pages owned by this driver.
        unsafe {
            for i in 0..TX_RING_LEN {
                core::ptr::write_volatile(
                    self.tx_ring.cpu_mut_ptr_at::<Vmxnet3TxDesc>(
                        (i * core::mem::size_of::<Vmxnet3TxDesc>()) as u64,
                    ),
                    Vmxnet3TxDesc::default(),
                );
            }
            for i in 0..TX_COMP_RING_LEN {
                core::ptr::write_volatile(
                    self.tx_comp_ring.cpu_mut_ptr_at::<Vmxnet3TxCompDesc>(
                        (i * core::mem::size_of::<Vmxnet3TxCompDesc>()) as u64,
                    ),
                    Vmxnet3TxCompDesc::default(),
                );
            }
            for i in 0..RX_COMP_RING_LEN {
                core::ptr::write_volatile(
                    self.rx_comp_ring.cpu_mut_ptr_at::<Vmxnet3RxCompDesc>(
                        (i * core::mem::size_of::<Vmxnet3RxCompDesc>()) as u64,
                    ),
                    Vmxnet3RxCompDesc::default(),
                );
            }
        }
        for i in 0..RX_RING_LEN {
            self.write_rx_desc(i as u32, VMXNET3_INIT_GEN);
        }
        *self.tx_state.lock() = TxState {
            head: 0,
            gen: VMXNET3_INIT_GEN,
            free: TX_RING_LEN as u32,
            comp_head: 0,
            comp_gen: VMXNET3_INIT_GEN,
        };
        *self.rx_state.lock() = RxState {
            comp_head: 0,
            comp_gen: VMXNET3_INIT_GEN,
            next2fill: 0,
            gen: 0,
            link_resample_in: LINK_RESAMPLE_PASSES,
        };

        // Step 3: re-publish DriverShared PA into DSAL/DSAH (cleared
        // by RESET_DEV) and re-activate.
        let shared_pa = self.shared.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.vd.write32(REG_DSAL, (shared_pa & 0xFFFF_FFFF) as u32);
            self.vd.write32(REG_DSAH, (shared_pa >> 32) as u32);
        }
        compiler_fence(Ordering::SeqCst);

        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.vd.write32(REG_CMD, VMXNET3_CMD_ACTIVATE_DEV);
        }
        // SAFETY: same.
        let status = unsafe { self.vd.read32(REG_CMD) };
        if status != 0 {
            return Err(Vmxnet3Error::ActivateFailed);
        }

        // Re-enable interrupts: clear VMXNET3_IC_DISABLE_ALL from
        // intrCtrl in DriverShared.devRead.intrConf.
        // Linux: vmxnet3_activate_dev() → vmxnet3_enable_all_intrs():
        //   shared->devRead.intrConf.intrCtrl &=
        //       cpu_to_le32(~VMXNET3_IC_DISABLE_ALL);
        // Must happen after ACTIVATE_DEV so the device sees the
        // updated intrCtrl on its next shared-memory read.
        let shared_ptr = self.shared.cpu_mut_ptr::<Vmxnet3DriverShared>();
        // SAFETY: identity-mapped DMA; shared struct lifetime ≥ self.
        unsafe {
            let ctrl = (*shared_ptr).devRead.intrConf.intrCtrl;
            (*shared_ptr).devRead.intrConf.intrCtrl =
                (u32::from_le(ctrl) & !VMXNET3_IC_DISABLE_ALL).to_le();
        }
        compiler_fence(Ordering::SeqCst);

        // The link may have changed across the reset; re-sample and
        // republish rather than trusting the probe-time value.
        self.check_link_and_publish();
        Ok(())
    }
}

// ── Driver-match registration ───────────────────────────────────────

// Append-only: a stack send cookie remains tied to its original PCI function.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<Vmxnet3Nic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// First NIC's interface name for diagnostics; empty before publication.
pub fn vmxnet3_ifname() -> &'static str {
    probed_controller().map_or("", |c| c.ifname())
}

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, WriteCap>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLERS.lock().iter().any(|c| c.addr == device.addr) {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER + INTX_DISABLE — same shape as the other
    // PCI NIC drivers in this crate. BUS_MASTER is required because
    // the device DMAs every ring + the DriverShared structure.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device for the duration of
    // bring_up.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let (dev_inner, rx_prod, tx_cons) = match unsafe { Vmxnet3Nic::bring_up(&device, &cap) } {
        Ok(t) => t,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *dev_inner.rx_ipc_prod.lock() = Some(rx_prod);
    let dev = Arc::new(dev_inner);
    let index = {
        let mut controllers = CONTROLLERS.lock();
        controllers.push(dev.clone());
        controllers.len() - 1
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vmxnet3"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Register with the kernel-side TCP stack: hands the stack a
    // `(mac, send_fn)` pair and a name, and stamps the initial link
    // sample from the probe-time `GET_LINK` reply. The RX-drain hook
    // lets kernel-side busy-wait paths (ARP / TCP handshake) pull
    // frames off the NIC ring directly while spinning, since the
    // spawned RX-pump task can't run while a syscall is parked
    // in `responsive_spin_until`.
    let name = crate::publish::publish_netdev_with_context(
        dev.mac,
        index as u64,
        vmxnet3_send_frame,
        dev.link_sample(),
    );
    // `vmxnet3_get_drvinfo`: driver "vmxnet3", no version (the core reports the
    // kernel release), bus_info = pci_name().
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "vmxnet3", None, bus_info);
    dev.ifname.set(name);
    narf_net::iface::install_rx_drain(rx_pump_step);
    // One RX queue, MTU-sized descriptors: software GRO is what
    // amortizes the shared stack work under burst, e1000's rationale.
    let _ = narf_net::iface::set_software_gro(dev.ifname(), true);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Vmxnet3Iface(dev.clone()));
    }

    spawn_pumps(dev, tx_cons);

    Ok(())
}

fn spawn_pumps(device: Arc<Vmxnet3Nic>, tx_cons: Consumer<Frame, TX_RING_N>) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        vmxnet3_rx_pump(d1).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        vmxnet3_tx_pump(d2, tx_cons).await;
    });
}

async fn vmxnet3_rx_pump(device: Arc<Vmxnet3Nic>) {
    // No MSI-X vector is bound yet, so there is no IRQ waiter: poll
    // the completion ring every millisecond (e1000's no-vector
    // fallback shape). Once awake, drain without yielding until the
    // ring is empty.
    let poll_cycles = narf_time::ns_to_cycles(RX_POLL_INTERVAL_NS);
    loop {
        // ECR event drain: a LINK event re-samples GET_LINK and
        // republishes carrier; the periodic re-sample covers a lost
        // event.
        device.poll_events();
        if device.rx_drain_in_place(RX_DRAIN_BUDGET, |frame| dispatch_rx_frame(&device, frame)) != 0
        {
            continue;
        }
        // Reclaim TX completions even when the stack is idle, so the
        // TX ring does not pin slots after a burst.
        device.reclaim_tx_completed();
        narf_time::sleep_cycles(poll_cycles).await;
    }
}

async fn vmxnet3_tx_pump(device: Arc<Vmxnet3Nic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload());
    }
}

/// Single RX fan-out used by both the async pump and the
/// syscall-context drain. e1000's `dispatch_rx_frame` shape: the ring
/// mirror gets a pristine copy (the stack path may rewrite the frame
/// in place), a full or closed ring drops the mirror rather than the
/// packet, and with no consumer attached no copy is made at all.
fn dispatch_rx_frame(device: &Vmxnet3Nic, frame: &mut [u8]) {
    if device.rx_mirror_enabled.load(Ordering::Acquire) {
        if let Ok(dma_buf) = alloc_coherent(frame.len(), DomainId::DRIVER_0) {
            let mut mirror = Frame::new(dma_buf, frame.len() as u32);
            mirror.payload_mut().copy_from_slice(frame);
            if let Some(prod) = device.rx_ipc_prod.lock().as_mut() {
                let _ = prod.try_send(mirror);
            }
        }
    }
    crate::publish::deliver_rx(device.ifname(), frame);
}

/// Called from a kernel-side polling task spawned at boot. Drains one
/// RX budget synchronously so syscall-context busy-wait paths (ARP /
/// TCP handshake) can pull frames off the NIC ring directly while
/// spinning, since the spawned RX-pump task can't run while a syscall
/// is parked in `responsive_spin_until` (e1000's shape).
pub fn rx_pump_step() -> bool {
    let controllers = CONTROLLERS.lock().clone();
    let mut any = false;
    for c in controllers {
        c.poll_events();
        any |= c.rx_drain_in_place(RX_DRAIN_BUDGET, |frame| dispatch_rx_frame(&c, frame)) != 0;
    }
    any
}

/// Stack `SendCtxFn`: transmit through the cookie's controller. Clone the
/// `Arc` out rather than holding the IRQ-masking CONTROLLERS lock
/// across `transmit` (e1000's thundering-herd note). No offloads are
/// advertised, so `meta` is ignored and every frame goes out plain.
fn vmxnet3_send_frame(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = controller(usize::try_from(cookie).map_err(|_| ())?).ok_or(())?;
    ctrl.transmit(frame).map_err(|_| ())
}

/// Register the driver with the bus's match table.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "vmxnet3",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VMWARE_VENDOR,
            device: VMWARE_DEV_VMXNET3,
        },
        probe,
    });
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    instance_count() != 0
}

/// Clone the first installed controller handle, holding `CONTROLLERS` only for
/// the refcount bump.
///
/// `CONTROLLERS` is an `IrqSafeSpinLock`, so holding it across a device
/// round-trip masks interrupts on the waiting CPU for the whole wait
/// and forces every other CPU touching the NIC to spin with interrupts
/// masked too. Cloning the `Arc` out instead keeps the device alive
/// without any lock held; mutual exclusion on the rings is provided by
/// the controller's own `tx_state`/`rx_state` locks, which are held
/// only across the bounded descriptor post/drain, never across a
/// device wait.
pub fn probed_controller() -> Option<Arc<Vmxnet3Nic>> {
    controller(0)
}

/// Resolve the stable send cookie assigned at probe.
pub fn controller(index: usize) -> Option<Arc<Vmxnet3Nic>> {
    CONTROLLERS.lock().get(index).cloned()
}

/// Number of retained PCI functions.
pub fn instance_count() -> usize {
    CONTROLLERS.lock().len()
}

/// Test-side accessor.
pub fn with_controller<R>(f: impl FnOnce(&Vmxnet3Nic) -> R) -> Option<R> {
    probed_controller().map(|c| f(&c))
}

#[derive(Debug)]
pub struct Vmxnet3Iface(pub Arc<Vmxnet3Nic>);

impl Interface for Vmxnet3Iface {
    fn name(&self) -> &str {
        self.0.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac
    }
    fn mtu(&self) -> u32 {
        DEFAULT_MTU as u32
    }
    fn link_up(&self) -> bool {
        // Live carrier, maintained by the RX pump's ECR drain /
        // periodic GET_LINK re-sample — not the probe-time snapshot.
        self.0.live_link_up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_mirror_enabled.store(true, Ordering::Release);
        &self.0.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx_ipc_ring
    }
}

impl crate::HwNic for Vmxnet3Iface {
    fn name(&self) -> &'static str {
        self.0.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac
    }
    fn mtu(&self) -> u32 {
        DEFAULT_MTU as u32
    }
    fn link_up(&self) -> bool {
        self.0.live_link_up.load(Ordering::Acquire)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::VmwareVmxnet3
    }
    fn caps(&self) -> crate::NicCaps {
        // Plain frames only: no TX/RX checksum, TSO, RSS or VLAN
        // offload is advertised until the datapath implements one.
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        RX_RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as Interface>::tx_ring(self)
    }
}
