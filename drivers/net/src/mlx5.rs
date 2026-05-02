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

use alloc::vec::Vec;

use cmd::{
    build_cqe_inline, build_cqe_with_mailboxes, decode_response,
    is_complete, CmdError, CmdOp, CmdResponse, CQE_LEN,
    CQE_OFF_STATUS_OWN, MAILBOX_BLOCK_LEN, STATUS_OWN_BIT,
};

// Smokes live in the driver directory, not the shared tests.rs.
mod tests;

pub mod bit_field;
pub mod caps;
pub mod cmd;
pub mod eq;
pub mod mailbox;

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

/// Capability groups for `QUERY_HCA_CAP` (PRM §15.2). Encoded into
/// the op_mod field; combined with a "current vs max" bit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum HcaCapGroup {
    GeneralDevice  = 0x0,
    EthernetOffload = 0x1,
    Atomic          = 0x3,
    Roce            = 0x4,
    IpoibOffloads   = 0x5,
}

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
    /// Stage 7: caller-supplied EQ parameters were invalid.
    EqBuild(eq::EqError),
}

/// Stage 7: live-EQ bookkeeping. Holds the FW-assigned `eq_number`
/// + the DMA pages backing the EQ buffer so they're not dropped
/// while the EQ is live.
pub struct LiveEq {
    pub eq_number: u32,
    _pages:        Vec<DmaBuffer>,
    pub params:    eq::EqParams,
}

impl fmt::Debug for LiveEq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveEq")
            .field("eq_number", &self.eq_number)
            .field("params",    &self.params)
            .finish_non_exhaustive()
    }
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
    /// Stage 4: result of the bring-up self-test NOP. `Some(Ok(()))`
    /// means the cmdq transport works end-to-end with this device;
    /// `Some(Err(_))` means probe ran but the NOP self-test failed
    /// (driver still bound — operator can investigate).
    nop_selftest: Option<Result<(), Mlx5Error>>,
    /// Stage 7: registry of live EQs (eq_number + backing DMA).
    eqs: IrqSafeSpinLock<Vec<LiveEq>>,
    /// Stage 7: BAR0 byte-offset where UAR pages start. PRM-documented
    /// for ConnectX-4..6 at 0x100000 (1 MiB into BAR0). Driver-level
    /// override is kept on the struct so a future stage can refine
    /// after a proper QUERY_HCA_CAP read.
    uar_base: u64,
}

/// Default BAR0 offset where UAR pages live on ConnectX-4..6.
const UAR_BASE_DEFAULT: u64 = 0x100000;

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
            nop_selftest: None,
            eqs: IrqSafeSpinLock::new(Vec::new()),
            uar_base: UAR_BASE_DEFAULT,
        })
    }

    /// Stage 4 self-check: post a single NOP through the live cmdq
    /// transport. Records the result on the driver so callers can
    /// query it later via `nop_selftest()`. Idempotent — each call
    /// re-runs the NOP and overwrites the stored result.
    pub fn run_nop_selftest(&mut self) -> Result<(), Mlx5Error> {
        let r = self.issue_command_inline(CmdOp::Nop, 0, &[])
                    .map(|_| ());
        self.nop_selftest = Some(r);
        r
    }

    /// Latest stored NOP self-test outcome, or `None` if it was
    /// never run.
    pub fn nop_selftest(&self) -> Option<Result<(), Mlx5Error>> {
        self.nop_selftest
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

    /// Stage 4: issue a command with DMA-mailbox input and output.
    /// Allocates an N-block input chain + an M-block output chain,
    /// posts the CQE pointing at the head of each, polls for
    /// completion, and returns the raw output bytes.
    ///
    /// `output_len` is the firmware-declared byte count to read back;
    /// we trust caller-provided bounds (the FW writes exactly that
    /// many bytes — extra block storage is left zero).
    pub fn issue_command_with_mailboxes(
        &self,
        op:             CmdOp,
        input_modifier: u32,
        input:          &[u8],
        output_len:     usize,
    ) -> Result<Vec<u8>, Mlx5Error> {
        let token = {
            let mut tok = self.next_token.lock();
            let v = *tok;
            *tok = tok.wrapping_add(1);
            v
        };
        let n_in  = mailbox::block_count_for(input.len());
        let n_out = mailbox::block_count_for(output_len);

        // Allocate per-block DMA pages (one block per page is
        // wasteful but simplifies alignment + safety; mailbox blocks
        // must be 512-B aligned and a fresh page is page-aligned).
        let mut in_blocks:  Vec<DmaBuffer> = Vec::with_capacity(n_in);
        let mut out_blocks: Vec<DmaBuffer> = Vec::with_capacity(n_out);
        for _ in 0..n_in {
            in_blocks.push(
                alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        for _ in 0..n_out {
            out_blocks.push(
                alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let in_phys: Vec<u64> = in_blocks.iter()
            .map(|b| b.phys_addr().raw()).collect();
        let out_phys: Vec<u64> = out_blocks.iter()
            .map(|b| b.phys_addr().raw()).collect();

        // Populate input mailbox blocks.
        let in_data = mailbox::write_input_chain(input, &in_phys, token);
        for (block, dma) in in_data.iter().zip(in_blocks.iter()) {
            let phys = dma.phys_addr().raw();
            // SAFETY: identity-mapped DMA; driver-owned buffer.
            unsafe {
                for (i, &b) in block.iter().enumerate() {
                    core::ptr::write_volatile(
                        (phys + i as u64) as *mut u8, b);
                }
            }
        }
        // Output blocks: zero them so any "left untouched" bytes
        // read back as 0 rather than stale DMA contents.
        for dma in out_blocks.iter() {
            let phys = dma.phys_addr().raw();
            // SAFETY: identity-mapped DMA; driver-owned buffer.
            unsafe {
                for i in 0..MAILBOX_BLOCK_LEN {
                    core::ptr::write_volatile(
                        (phys + i as u64) as *mut u8, 0);
                }
            }
        }
        // Stitch output-block chain pointers (FW reads the chain to
        // know where to deposit each segment of output).
        for i in 0..n_out {
            let next = if i + 1 < n_out { out_phys[i + 1] } else { 0 };
            // Write next-pointer at offset 0x1F0 / 0x1F4 (BE).
            let phys = out_phys[i];
            let h = (next >> 32) as u32;
            let l = (next & 0xFFFF_FFFF) as u32;
            // SAFETY: identity-mapped DMA; offsets within block.
            unsafe {
                for (j, &b) in h.to_be_bytes().iter().enumerate() {
                    core::ptr::write_volatile(
                        (phys + 0x1F0 + j as u64) as *mut u8, b);
                }
                for (j, &b) in l.to_be_bytes().iter().enumerate() {
                    core::ptr::write_volatile(
                        (phys + 0x1F4 + j as u64) as *mut u8, b);
                }
            }
        }

        // Build + post the CQE.
        let cqe = build_cqe_with_mailboxes(
            op, input_modifier,
            in_phys[0],  input.len() as u32,
            out_phys[0], output_len as u32,
            token,
        );
        let slot_phys = self.cmdq.phys_addr().raw();
        // SAFETY: identity-mapped DMA cmdq, exclusively owned.
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    (slot_phys + i as u64) as *mut u8, b);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.ring_cmd_doorbell(1);

        // Poll for completion.
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

        // Decode CQE status; even on failure we want to surface
        // exactly what FW reported.
        let mut completed = [0u8; CQE_LEN];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..CQE_LEN {
                completed[i] = core::ptr::read_volatile(
                    (slot_phys + i as u64) as *const u8);
            }
        }
        debug_assert!(is_complete(&completed));
        let _resp = decode_response(&completed).map_err(Mlx5Error::CmdFailed)?;

        // Read output blocks back into a contiguous Vec.
        let mut blocks: Vec<[u8; MAILBOX_BLOCK_LEN]> =
            Vec::with_capacity(n_out);
        for dma in out_blocks.iter() {
            let phys = dma.phys_addr().raw();
            let mut block = [0u8; MAILBOX_BLOCK_LEN];
            // SAFETY: identity-mapped DMA.
            unsafe {
                for i in 0..MAILBOX_BLOCK_LEN {
                    block[i] = core::ptr::read_volatile(
                        (phys + i as u64) as *const u8);
                }
            }
            blocks.push(block);
        }
        Ok(mailbox::read_output_chain(&blocks, output_len))
    }

    /// Stage 7: issue a command whose input rides through a DMA
    /// mailbox chain but whose output fits in the CQE's 8-byte
    /// inline window — much cheaper than `issue_command_with_mailboxes`
    /// when the response is just status + a small ID (CREATE_EQ /
    /// CREATE_CQ / ALLOC_PD return wire IDs in the
    /// `output_modifier` field of the inline response).
    pub fn issue_command_with_input_mailbox(
        &self,
        op:             CmdOp,
        input_modifier: u32,
        input:          &[u8],
    ) -> Result<CmdResponse, Mlx5Error> {
        let token = {
            let mut tok = self.next_token.lock();
            let v = *tok;
            *tok = tok.wrapping_add(1);
            v
        };
        let n_in = mailbox::block_count_for(input.len());
        let mut in_blocks: Vec<DmaBuffer> = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            in_blocks.push(
                alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let in_phys: Vec<u64> = in_blocks.iter()
            .map(|b| b.phys_addr().raw()).collect();
        let in_data = mailbox::write_input_chain(input, &in_phys, token);
        for (block, dma) in in_data.iter().zip(in_blocks.iter()) {
            let phys = dma.phys_addr().raw();
            // SAFETY: identity-mapped DMA; driver-owned buffer.
            unsafe {
                for (i, &b) in block.iter().enumerate() {
                    core::ptr::write_volatile(
                        (phys + i as u64) as *mut u8, b);
                }
            }
        }
        // Build the CQE: input mailbox set, output mailbox = 0, len = 0.
        let cqe = build_cqe_with_mailboxes(
            op, input_modifier,
            in_phys[0], input.len() as u32,
            /* output_mb_phys */ 0, /* output_len */ 0,
            token,
        );
        let slot_phys = self.cmdq.phys_addr().raw();
        // SAFETY: identity-mapped cmdq DMA.
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    (slot_phys + i as u64) as *mut u8, b);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.ring_cmd_doorbell(1);

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

        let mut completed = [0u8; CQE_LEN];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..CQE_LEN {
                completed[i] = core::ptr::read_volatile(
                    (slot_phys + i as u64) as *const u8);
            }
        }
        debug_assert!(is_complete(&completed));
        decode_response(&completed).map_err(Mlx5Error::CmdFailed)
    }

    /// Stage 7: live `CREATE_EQ`. Allocates `page_count` 4-KiB DMA
    /// pages for the EQ buffer, hands them to `build_create_eq_input`,
    /// posts the command via the input-mailbox transport, and returns
    /// the firmware-assigned `eq_number` from the inline response.
    /// The backing pages + recorded eq_number live on the driver's
    /// `eqs` registry so they're not dropped while the EQ is live.
    pub fn create_eq(
        &self,
        params:     eq::EqParams,
        page_count: usize,
    ) -> Result<u32, Mlx5Error> {
        let mut pages: Vec<DmaBuffer> = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(
                alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let phys: Vec<u64> = pages.iter()
            .map(|p| p.phys_addr().raw()).collect();
        let payload = eq::build_create_eq_input(params, &phys)
            .map_err(Mlx5Error::EqBuild)?;
        let resp = self.issue_command_with_input_mailbox(
            CmdOp::CreateEq, 0, &payload)?;
        // PRM: eq_number rides in the low 24 bits of output_modifier.
        let eq_number = resp.output_modifier & 0x00FF_FFFF;
        self.eqs.lock().push(LiveEq {
            eq_number,
            _pages: pages,
            params,
        });
        Ok(eq_number)
    }

    /// Stage 7: write a 4-byte BE doorbell into a UAR page. `uar_page`
    /// is the index assigned by `ALLOC_UAR` (Stage 8); `byte_offset`
    /// is the offset within the 4-KiB UAR page. Used by EQ arming
    /// + WQ tail bumps.
    pub fn uar_write32(&self, uar_page: u32, byte_offset: u32, value: u32) {
        let abs = self.uar_base + (uar_page as u64) * 4096
                 + byte_offset as u64;
        // SAFETY: identity-mapped MMIO; caller asserts uar_page is
        // owned.
        unsafe { self.mmio.write32(abs, value.swap_bytes()); }
    }

    /// Number of currently-allocated EQs.
    pub fn eq_count(&self) -> usize { self.eqs.lock().len() }

    /// Stage 5: typed wrapper around QUERY_HCA_CAP(GeneralDevice).
    /// Returns the decoded view; callers needing fields beyond the
    /// Stage-5 subset go through `caps::HcaGeneralCaps::raw()`.
    pub fn query_general_caps(
        &self,
        current: bool,
    ) -> Result<caps::HcaGeneralCaps, Mlx5Error> {
        let bytes = self.query_hca_cap(HcaCapGroup::GeneralDevice, current)?;
        caps::HcaGeneralCaps::from_bytes(bytes)
            .map_err(|_| Mlx5Error::CmdFailed(CmdError::NotComplete))
    }

    /// Stage 5: typed wrapper around QUERY_HCA_CAP(EthernetOffload).
    pub fn query_ethernet_offload_caps(
        &self,
        current: bool,
    ) -> Result<caps::EthernetOffloadCaps, Mlx5Error> {
        let bytes = self.query_hca_cap(HcaCapGroup::EthernetOffload, current)?;
        caps::EthernetOffloadCaps::from_bytes(bytes)
            .map_err(|_| Mlx5Error::CmdFailed(CmdError::NotComplete))
    }

    /// Stage 4: issue `QUERY_HCA_CAP` for a chosen capability group
    /// and return the raw response bytes. Decoding the structured
    /// fields lands in Stage 5.
    pub fn query_hca_cap(
        &self,
        group:   HcaCapGroup,
        current: bool,
    ) -> Result<Vec<u8>, Mlx5Error> {
        // Op modifier per PRM §15.2.1: bits [15:1] = cap group, bit
        // [0] = 0 (max) / 1 (current).
        let op_mod_high  = (group as u16) << 1
                         | if current { 1 } else { 0 };
        // The op_mod field rides in the upper 16 bits of the
        // input_modifier slot for QUERY_HCA_CAP — different
        // commands position op_mod differently, but for QUERY_HCA_CAP
        // the entire 32-bit input_modifier carries the op_mod_high
        // value (other bits reserved, zero).
        let input_modifier = op_mod_high as u32;
        // QUERY_HCA_CAP general-cap output is documented at 0x1000
        // bytes (4 KiB → 9 mailbox blocks). Reserve that and let
        // Stage-5 trim to what's actually meaningful.
        const HCA_CAP_OUTPUT_LEN: usize = 0x1000;
        self.issue_command_with_mailboxes(
            CmdOp::QueryHcaCap, input_modifier,
            &[], HCA_CAP_OUTPUT_LEN,
        )
    }

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
    let mut dev = match unsafe { Mlx5Hca::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // Stage 4: post a NOP through the live cmdq transport to verify
    // bring-up didn't just program registers but actually has FW
    // talking. We log via the stored selftest result rather than
    // failing probe — a NOP timeout might be a slow host, not a
    // broken device.
    let _ = dev.run_nop_selftest();
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
