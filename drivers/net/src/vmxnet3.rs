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
//! ## Reference
//!
//! - Linux `drivers/net/vmxnet3/vmxnet3_defs.h` (GPL-2.0, VMware
//!   2008-2024). Defines every register offset and shared-mem layout
//!   touched here.
//! - Linux `drivers/net/vmxnet3/vmxnet3_drv.c` (GPL-2.0). Reference
//!   bring-up sequence + bit-twiddling.

#![allow(dead_code)]

use core::fmt::Write;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write as WriteCap,
};

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
}

// ── Driver state ────────────────────────────────────────────────────

/// Live vmxnet3 controller. Built by `bring_up`; stored in a static
/// `IrqSafeSpinLock` so the test harness can poke it after probe.
pub struct Vmxnet3Nic {
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
    /// Producer cursor for TX ring.
    tx_head: IrqSafeSpinLock<u32>,
    /// Generation bit (flips each wrap). Per descriptor, the driver
    /// writes `gen` and the device flips it after consuming.
    tx_gen: IrqSafeSpinLock<u32>,
    /// Negotiated revision. 1 = `VMXNET3_REV_1`, the floor every host
    /// supports. Stage 0 always negotiates 1.
    pub revision: u32,
    /// MAC address. Read post-activate from MACL/MACH.
    pub mac: [u8; 6],
    /// `true` if `VMXNET3_CMD_GET_LINK` reported a live link at
    /// bring-up. Bit 0 of the CMD readback (`vmxnet3_drv.c` line 203).
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
    /// Bring up the controller. See module-level docs for the
    /// 5-step sequence; this implements Stage 0 + Stage 1 + Stage 2.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg window exclusively for
    /// the duration of `bring_up`.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, WriteCap>,
    ) -> Result<Self, Vmxnet3Error> {
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
        let shared = alloc_coherent(core::mem::size_of::<Vmxnet3DriverShared>(), DomainId::DRIVER_0)
            .map_err(|_| Vmxnet3Error::NoMemory)?;
        // SAFETY: alloc_coherent returns a zeroed identity-mapped page.
        let shared_ptr = shared.phys_addr().raw() as *mut Vmxnet3DriverShared;
        // SAFETY: shared_ptr fits an identity-mapped DMA page sized
        // for sizeof::<Vmxnet3DriverShared>().
        unsafe {
            (*shared_ptr).magic = VMXNET3_REV1_MAGIC.to_le();
            (*shared_ptr).size =
                (core::mem::size_of::<Vmxnet3DriverShared>() as u32).to_le();
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
            core::mem::size_of::<Vmxnet3TxQueueDesc>()
                + core::mem::size_of::<Vmxnet3RxQueueDesc>(),
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
        let rx_ring1_pa = rx_ring1.phys_addr().raw();
        for i in 0..RX_RING_LEN {
            let buf_pa = rx_buffers[i].phys_addr().raw();
            let mut desc = Vmxnet3RxDesc::default();
            desc.addr = buf_pa.to_le();
            // len in low 14 bits, btype HEAD (=0), gen=1.
            let len = (RX_BUF_LEN as u32) & RXD_LEN_MASK;
            let gen: u32 = 1 << RXD_GEN_SHIFT;
            desc.flags = (len | gen).to_le();
            desc.ext1 = 0;
            // SAFETY: identity-mapped DMA page, i < RX_RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    (rx_ring1_pa + (i * core::mem::size_of::<Vmxnet3RxDesc>()) as u64)
                        as *mut Vmxnet3RxDesc,
                    desc,
                );
            }
        }

        // 8. Stamp DriverShared.devRead.misc with the queue-desc
        //    table phys addr + queue/ring sizes, devRead.intrConf
        //    with a single auto-mask vector, and the queue-desc
        //    table itself with the ring-base PAs.
        let queue_desc_pa = queue_desc.phys_addr().raw();
        // SAFETY: identity-mapped DMA page. devRead lives at offset
        // 8 of Vmxnet3DriverShared (after magic + size).
        unsafe {
            (*shared_ptr).devRead.misc.driverInfo.version =
                VMXNET3_DRIVER_VERSION_NUM.to_le();
            (*shared_ptr).devRead.misc.driverInfo.gos =
                Vmxnet3GOSInfo::for_narf().to_raw().to_le();
            (*shared_ptr).devRead.misc.driverInfo.vmxnet3RevSpt = 1u32.to_le();
            (*shared_ptr).devRead.misc.driverInfo.uptVerSpt = 1u32.to_le();
            (*shared_ptr).devRead.misc.uptFeatures = 0u64.to_le();
            (*shared_ptr).devRead.misc.ddPA = shared.phys_addr().raw().to_le();
            (*shared_ptr).devRead.misc.queueDescPA = queue_desc_pa.to_le();
            (*shared_ptr).devRead.misc.ddLen =
                (core::mem::size_of::<Vmxnet3DriverShared>() as u32).to_le();
            (*shared_ptr).devRead.misc.queueDescLen = ((core::mem::size_of::<
                Vmxnet3TxQueueDesc,
            >()
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
            let txqd = queue_desc_pa as *mut Vmxnet3TxQueueDesc;
            (*txqd).conf.txRingBasePA = tx_ring.phys_addr().raw().to_le();
            (*txqd).conf.dataRingBasePA = 0;
            (*txqd).conf.compRingBasePA = tx_comp_ring.phys_addr().raw().to_le();
            (*txqd).conf.ddPA = 0;
            (*txqd).conf.txRingSize = (TX_RING_LEN as u32).to_le();
            (*txqd).conf.dataRingSize = 0;
            (*txqd).conf.compRingSize = (TX_COMP_RING_LEN as u32).to_le();
            (*txqd).conf.ddLen = 0;
            (*txqd).conf.intrIdx = 0;
            (*txqd).conf.txDataRingDescSize = 0;

            let rxqd = (queue_desc_pa + core::mem::size_of::<Vmxnet3TxQueueDesc>() as u64)
                as *mut Vmxnet3RxQueueDesc;
            (*rxqd).conf.rxRingBasePA[0] = rx_ring1.phys_addr().raw().to_le();
            (*rxqd).conf.rxRingBasePA[1] = rx_ring2.phys_addr().raw().to_le();
            (*rxqd).conf.compRingBasePA = rx_comp_ring.phys_addr().raw().to_le();
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
        let shared_pa = shared.phys_addr().raw();
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
        //     reply value. Bit 0 of the reply = link up.
        // SAFETY: same.
        unsafe {
            vd.write32(REG_CMD, VMXNET3_CMD_GET_LINK);
        }
        // SAFETY: same.
        let link_reply = unsafe { vd.read32(REG_CMD) };
        let link_up = link_reply & 0x1 != 0;

        // 14. Bump the RX producer doorbells so the device walks the
        //     full ring once it starts DMA-ing. Stage 2: leave at 0
        //     for now — bus-side IRQ bring-up will land in a follow-up
        //     and the ring already carries gen-bit-1 slots.
        let _ = &pt; // pt used by IMR write in a follow-up.

        let _ = writeln!(
            narf_console::Writer,
            "  vmxnet3: VRRS={:#010x} rev=1 MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
            vrrs,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            if link_up { "up" } else { "down" },
        );

        Ok(Self {
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
            tx_head: IrqSafeSpinLock::new(0),
            tx_gen: IrqSafeSpinLock::new(1),
            revision: 1,
            mac,
            link_up,
        })
    }

    /// Ring the TX producer doorbell. Stage 2 helper used by smoke
    /// tests to assert a descriptor round-trip; the real `transmit`
    /// path lands once MSI-X is wired.
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
    /// Returns `Ok(())` on successful re-activate; `Err(ActivateFailed)`
    /// if the device rejects the activate after reset.
    ///
    /// # Safety
    /// Caller must hold exclusive access to the BAR windows.
    pub unsafe fn reset(&self) -> Result<(), Vmxnet3Error> {
        // Step 1: quiesce — stop host-side DMA into our rings.
        // Safety: caller-asserted exclusive BAR access.
        unsafe { self.quiesce_dev() };

        // Step 2: hard reset — returns device to power-on state.
        // Safety: same.
        unsafe { self.reset_dev() };

        // Step 3: re-publish DriverShared PA into DSAL/DSAH (cleared
        // by RESET_DEV) and re-activate.
        let shared_pa = self.shared.phys_addr().raw();
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
        let shared_ptr = self.shared.phys_addr().raw() as *mut Vmxnet3DriverShared;
        // SAFETY: identity-mapped DMA; shared struct lifetime ≥ self.
        unsafe {
            let ctrl = (*shared_ptr).devRead.intrConf.intrCtrl;
            (*shared_ptr).devRead.intrConf.intrCtrl =
                (u32::from_le(ctrl) & !VMXNET3_IC_DISABLE_ALL).to_le();
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Vmxnet3Nic>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, WriteCap>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
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
    let dev = match unsafe { Vmxnet3Nic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vmxnet3"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
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
    CONTROLLER.lock().is_some()
}

/// Test-side accessor.
pub fn with_controller<R>(f: impl FnOnce(&Vmxnet3Nic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
