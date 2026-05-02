//! mlx5 — Mellanox / NVIDIA ConnectX-4/5/6/7 HCA driver.
//!
//! Spec: `drivers/net/specification/mlx5.md` (Stage 1).
//!
//! Clean-room: register + command-interface layouts come from the
//! public Mellanox PRM. No GPL Linux `mlx5_core` source consulted.
//!
//! ## Stage 1 scope
//!
//! - PCI match for the documented ConnectX-4..6 vendor/device pairs.
//! - `InitSegment` decoder over the 4 KiB BAR0 init-segment region.
//! - `is_initializing` helper that returns bit 31 of the `0x0FFC`
//!   "initializing" register.
//! - `Mlx5Hca::bring_up` that maps BAR0, decodes the segment, polls
//!   the initializing bit with a documented timeout, and records the
//!   bound driver.
//!
//! Everything past bring-up (firmware commands, EQ/CQ/QP) lands in
//! later stages — this file stays small and the smokes that prove it
//! works live next door at `mlx5/tests.rs`.

use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use cmd::{
    build_cqe_inline, decode_response, is_complete, CmdError, CmdOp,
    CmdResponse, CQE_LEN, CQE_OFF_STATUS_OWN, STATUS_OWN_BIT,
};

// Smokes live in the driver directory, not the shared tests.rs.
mod tests;

pub mod cmd;

// ── PCI device IDs (ConnectX-4 .. ConnectX-6 Dx) ───────────────────

/// Vendor: Mellanox (now NVIDIA Networking).
pub const MLX5_VENDOR: u16 = 0x15B3;

/// ConnectX-4.
pub const MLX5_DEV_CX4:       u16 = 0x1011;
/// ConnectX-4 Lx.
pub const MLX5_DEV_CX4_LX:    u16 = 0x1013;
/// ConnectX-4 Lx Virtual Function.
pub const MLX5_DEV_CX4_LX_VF: u16 = 0x1015;
/// ConnectX-5.
pub const MLX5_DEV_CX5:       u16 = 0x1017;
/// ConnectX-5 Ex.
pub const MLX5_DEV_CX5_EX:    u16 = 0x1019;
/// ConnectX-6.
pub const MLX5_DEV_CX6:       u16 = 0x101B;
/// ConnectX-6 Dx.
pub const MLX5_DEV_CX6_DX:    u16 = 0x101D;

const ALL_DEV_IDS: &[u16] = &[
    MLX5_DEV_CX4, MLX5_DEV_CX4_LX, MLX5_DEV_CX4_LX_VF,
    MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX,
];

// ── Init-segment register offsets (BAR0) ───────────────────────────
//
// All multi-byte fields are big-endian per PRM §1.4. The decoder
// byte-swaps on read.

const ISEG_FW_REV_MAJOR:    usize = 0x0000;
const ISEG_FW_REV_MINOR:    usize = 0x0002;
const ISEG_FW_REV_SUB:      usize = 0x0004;
const ISEG_CMD_IFACE_REV:   usize = 0x0006;
const ISEG_CMDQ_ADDR_HIGH:  usize = 0x0010;
const ISEG_CMDQ_ADDR_LO_SZ: usize = 0x0014;
const ISEG_CMD_DBELL:       usize = 0x0018;
const ISEG_HEALTH_BUF:      usize = 0x001C;
const ISEG_HEALTH_BUF_LEN:  usize = 64;
const ISEG_INITIALIZING:    usize = 0x0FFC;

/// Total length of the init segment we decode against.
pub const INIT_SEGMENT_LEN: usize = 0x1000;

/// `initializing` register bit set by FW while it is starting; driver
/// must poll it clear before issuing any command.
const INITIALIZING_BIT: u32 = 1 << 31;

/// PRM-documented worst-case startup wait (~2 s) before the driver
/// should declare the HCA dead. Scaled to spin-loop iterations; on
/// real silicon a sleep-pump is preferred — Stage 1 just polls.
const INIT_POLL_LIMIT: u32 = 20_000_000;

/// Stage 3: cmdq sizing.
///
/// `log_size = 0` → 1 outstanding command (smallest legal value, plenty
/// for synchronous bring-up). One CQE = 64 B; we still allocate a 4-KiB
/// page for natural alignment.
const STAGE3_CMDQ_LOG_SIZE: u8 = 0;
const STAGE3_CMDQ_PAGE_LEN: usize = 4096;

/// Per-CQE polling budget. mlx5 NOP / QUERY_HCA_CAP latency is
/// well under a microsecond; we give plenty of headroom for a busy
/// host before declaring the firmware hung.
const CMD_POLL_LIMIT: u32 = 50_000_000;

// ── Decoded init-segment ───────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InitSegment {
    pub fw_rev_major:      u16,
    pub fw_rev_minor:      u16,
    pub fw_rev_subminor:   u16,
    pub cmd_interface_rev: u16,
    pub cmdq_addr:         u64,
    pub cmdq_log_size:     u8,
    pub cmd_dbell_vector:  u32,
    /// Raw 64-byte health buffer; parsed in a later stage.
    pub health_buffer:     [u8; ISEG_HEALTH_BUF_LEN],
    pub initializing:      bool,
}

#[inline]
fn be16(raw: &[u8; INIT_SEGMENT_LEN], off: usize) -> u16 {
    u16::from_be_bytes([raw[off], raw[off + 1]])
}

#[inline]
fn be32(raw: &[u8; INIT_SEGMENT_LEN], off: usize) -> u32 {
    u32::from_be_bytes([
        raw[off], raw[off + 1], raw[off + 2], raw[off + 3],
    ])
}

/// Decode a 4-KiB snapshot of BAR0 into the structured init segment.
/// All field accesses are byte-indexed so this is callable from a
/// smoke harness without any MMIO mapping.
pub fn decode_init_segment(raw: &[u8; INIT_SEGMENT_LEN]) -> InitSegment {
    let cmdq_high   = be32(raw, ISEG_CMDQ_ADDR_HIGH) as u64;
    let cmdq_low_sz = be32(raw, ISEG_CMDQ_ADDR_LO_SZ);
    // Low 4 bits = log2(#commands); upper 28 bits = address bits
    // [31:4] of the cmd queue base. The full 64-bit phys is
    // (high << 32) | (low_sz & ~0xF).
    let cmdq_addr      = (cmdq_high << 32) | (cmdq_low_sz as u64 & !0xFu64);
    let cmdq_log_size  = (cmdq_low_sz & 0xF) as u8;
    let cmd_dbell_vec  = be32(raw, ISEG_CMD_DBELL);
    let initializing   = (be32(raw, ISEG_INITIALIZING) & INITIALIZING_BIT) != 0;
    let mut health = [0u8; ISEG_HEALTH_BUF_LEN];
    health.copy_from_slice(
        &raw[ISEG_HEALTH_BUF .. ISEG_HEALTH_BUF + ISEG_HEALTH_BUF_LEN]);
    InitSegment {
        fw_rev_major:      be16(raw, ISEG_FW_REV_MAJOR),
        fw_rev_minor:      be16(raw, ISEG_FW_REV_MINOR),
        fw_rev_subminor:   be16(raw, ISEG_FW_REV_SUB),
        cmd_interface_rev: be16(raw, ISEG_CMD_IFACE_REV),
        cmdq_addr,
        cmdq_log_size,
        cmd_dbell_vector:  cmd_dbell_vec,
        health_buffer:     health,
        initializing,
    }
}

/// Cheap variant that reads only the `0x0FFC` initializing register
/// — useful in the bring-up poll loop where we don't want to re-decode
/// 4 KiB of BAR0 each spin.
pub fn is_initializing(raw: &[u8; INIT_SEGMENT_LEN]) -> bool {
    (be32(raw, ISEG_INITIALIZING) & INITIALIZING_BIT) != 0
}

// ── Driver state ───────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mlx5Error {
    BarMapFailed,
    InitTimeout,
    UnsupportedDevice,
    /// Stage 3: failed to allocate the cmdq DMA backing.
    CmdqAlloc,
    /// Stage 3: CQE polling exceeded the per-command budget.
    CmdTimeout,
    /// Stage 3: command builder rejected the call (inline overflow,
    /// etc.).
    CmdBuild(CmdError),
    /// Stage 3: firmware completed the CQE with a non-OK status.
    CmdFailed(CmdError),
}

pub struct Mlx5Hca {
    mmio:    MmioRegion,
    segment: InitSegment,
    /// Stage 3: 4-KiB DMA-coherent backing for the command queue.
    /// One slot used (log_size = 0); kept resident for the life of
    /// the device.
    cmdq:    DmaBuffer,
    /// Per-command polling cursor — token rotates so each issued CQE
    /// gets a unique tag, useful for diagnostics.
    next_token: IrqSafeSpinLock<u8>,
}

impl fmt::Debug for Mlx5Hca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mlx5Hca")
            .field("fw",           &(self.segment.fw_rev_major,
                                     self.segment.fw_rev_minor,
                                     self.segment.fw_rev_subminor))
            .field("cmd_iface",    &self.segment.cmd_interface_rev)
            .field("cmdq_log_sz",  &self.segment.cmdq_log_size)
            .finish_non_exhaustive()
    }
}

impl Mlx5Hca {
    /// Bring the HCA up to the point where the cmdq is alive and the
    /// init segment is cached. Stage 3 lifecycle:
    ///
    /// 1. Map BAR0.
    /// 2. Poll the initializing bit clear (PRM §1.6).
    /// 3. Snapshot the init segment.
    /// 4. Allocate the cmdq DMA backing (one 4-KiB page).
    /// 5. Program `cmdq_addr_high` / `cmdq_addr_low_sz` so firmware
    ///    sees the cmdq.
    ///
    /// Stage 4 will issue the first NOP from probe; Stage 3 only
    /// stages the transport.
    ///
    /// # Safety
    /// Caller owns the device's BARs exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Mlx5Error> {
        // SAFETY: caller-authority over the device.
        let mmio = unsafe { map_bar(device, 0) }
            .map_err(|_| Mlx5Error::BarMapFailed)?;

        // Poll the initializing register at 0x0FFC until bit 31
        // clears. Two-second worst case per PRM §1.6.
        let mut spins = 0u32;
        loop {
            // SAFETY: identity-mapped MMIO.
            let v = unsafe { mmio.read32(ISEG_INITIALIZING as u64) };
            // Register is BE on the wire; read32 returns LE-host
            // bytes, so swap.
            if (v.swap_bytes() & INITIALIZING_BIT) == 0 { break; }
            spins += 1;
            if spins > INIT_POLL_LIMIT { return Err(Mlx5Error::InitTimeout); }
            core::hint::spin_loop();
        }

        // Snapshot the init segment region. We do byte-by-byte reads
        // so the BE byte order is preserved exactly as the PRM lays
        // it out.
        let mut raw = [0u8; INIT_SEGMENT_LEN];
        for i in 0..INIT_SEGMENT_LEN {
            // SAFETY: identity-mapped MMIO; offset bounded.
            raw[i] = unsafe { mmio.read8(i as u64) };
        }
        let segment = decode_init_segment(&raw);

        // Stage 3: cmdq allocation + register programming.
        let cmdq = alloc_coherent(STAGE3_CMDQ_PAGE_LEN, DomainId::DRIVER_0)
            .map_err(|_| Mlx5Error::CmdqAlloc)?;
        let cmdq_phys = cmdq.phys_addr().raw();
        program_cmdq_registers(&mmio, cmdq_phys, STAGE3_CMDQ_LOG_SIZE);

        Ok(Self {
            mmio,
            segment,
            cmdq,
            next_token: IrqSafeSpinLock::new(1),
        })
    }

    /// Issue an inline-mode command (≤8 B input, ≤8 B output) to slot
    /// 0 of the cmdq, ring the doorbell, poll for completion, and
    /// decode the inline response. Used by Stage 3 to bring up NOP
    /// and any other small synchronous command.
    pub fn issue_command_inline(
        &self,
        op:             CmdOp,
        input_modifier: u32,
        inline_input:   &[u8],
    ) -> Result<CmdResponse, Mlx5Error> {
        let token = {
            let mut tok = self.next_token.lock();
            let v = *tok;
            *tok = tok.wrapping_add(1);
            v
        };
        let cqe = build_cqe_inline(op, input_modifier, inline_input, token)
            .map_err(Mlx5Error::CmdBuild)?;

        // Write the CQE bytes into slot 0 of the cmdq DMA buffer.
        let slot_phys = self.cmdq.phys_addr().raw();
        // SAFETY: identity-mapped DMA; cmdq is exclusively owned by
        // this driver.
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    (slot_phys + i as u64) as *mut u8, b);
            }
        }
        compiler_fence(Ordering::SeqCst);

        // Ring the cmd_dbell doorbell with bit 0 set (slot 0).
        self.ring_cmd_doorbell(1);

        // Poll the slot's status_own byte until the ownership bit
        // clears.
        let own_phys = slot_phys + CQE_OFF_STATUS_OWN as u64;
        let mut spins = 0u32;
        loop {
            // SAFETY: identity-mapped DMA.
            let v = unsafe { core::ptr::read_volatile(own_phys as *const u8) };
            if v & STATUS_OWN_BIT == 0 { break; }
            spins += 1;
            if spins > CMD_POLL_LIMIT { return Err(Mlx5Error::CmdTimeout); }
            core::hint::spin_loop();
        }

        // Read the completed CQE back out.
        let mut completed = [0u8; CQE_LEN];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..CQE_LEN {
                completed[i] = core::ptr::read_volatile(
                    (slot_phys + i as u64) as *const u8);
            }
        }
        // Sanity check + decode.
        debug_assert!(is_complete(&completed));
        decode_response(&completed).map_err(Mlx5Error::CmdFailed)
    }

    /// Ring the BAR0+0x18 cmd_dbell register with `slot_mask` — bit
    /// `i` set launches CQE in slot `i`. Field is BE on wire.
    pub fn ring_cmd_doorbell(&self, slot_mask: u32) {
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(ISEG_CMD_DBELL as u64,
                              slot_mask.swap_bytes());
        }
    }

    /// Phys address of the cmdq DMA backing (Stage 3+).
    pub fn cmdq_phys(&self) -> u64 { self.cmdq.phys_addr().raw() }

    pub fn fw_rev(&self) -> (u16, u16, u16) {
        (self.segment.fw_rev_major,
         self.segment.fw_rev_minor,
         self.segment.fw_rev_subminor)
    }

    pub fn cmd_interface_rev(&self) -> u16 { self.segment.cmd_interface_rev }

    pub fn cmdq_addr(&self) -> u64 { self.segment.cmdq_addr }

    pub fn cmdq_log_size(&self) -> u8 { self.segment.cmdq_log_size }

    pub fn segment(&self) -> &InitSegment { &self.segment }

    /// Read a raw 4-byte field from BAR0 (BE on wire). Used by
    /// later-stage code; exposed here so smokes can prod the live
    /// device through the same accessor.
    pub fn read_be32(&self, off: u64) -> u32 {
        // SAFETY: identity-mapped MMIO.
        let v = unsafe { self.mmio.read32(off) };
        v.swap_bytes()
    }
}

// ── cmdq register programming ──────────────────────────────────────

/// Program the init-segment's `cmdq_addr_high` (BAR0+0x10) and
/// `cmdq_addr_low_sz` (BAR0+0x14) registers to point firmware at the
/// driver-allocated cmdq backing. Both fields are BE on wire.
///
/// `cmdq_phys` MUST be ≥ 4-KiB aligned (the low 12 bits are reserved
/// in the register and discarded — page-aligned DMA satisfies that).
/// `log_size` is packed into the low 4 bits of the low register.
pub(crate) fn program_cmdq_registers(
    mmio:      &MmioRegion,
    cmdq_phys: u64,
    log_size:  u8,
) {
    let high = (cmdq_phys >> 32) as u32;
    let low_aligned = (cmdq_phys as u32) & 0xFFFF_F000;
    let low_sz  = low_aligned | ((log_size as u32) & 0xF);
    // SAFETY: identity-mapped MMIO; offsets bounded; caller has
    // exclusive ownership of the device.
    unsafe {
        mmio.write32(ISEG_CMDQ_ADDR_HIGH as u64, high.swap_bytes());
        mmio.write32(ISEG_CMDQ_ADDR_LO_SZ as u64, low_sz.swap_bytes());
    }
}

// ── Driver-match registration ──────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Mlx5Hca>> =
    IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over device.
    let dev = match unsafe { Mlx5Hca::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from(name_for(device.id.device)),
        kind:    narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

/// Register the driver against every ConnectX-4..6 device id we
/// recognise. One match per id pair so each is independently
/// maintainable.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MLX5_VENDOR, device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        MLX5_DEV_CX4       => "mlx5-cx4",
        MLX5_DEV_CX4_LX    => "mlx5-cx4-lx",
        MLX5_DEV_CX4_LX_VF => "mlx5-cx4-lx-vf",
        MLX5_DEV_CX5       => "mlx5-cx5",
        MLX5_DEV_CX5_EX    => "mlx5-cx5-ex",
        MLX5_DEV_CX6       => "mlx5-cx6",
        MLX5_DEV_CX6_DX    => "mlx5-cx6-dx",
        _                  => "mlx5",
    }
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&Mlx5Hca) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
