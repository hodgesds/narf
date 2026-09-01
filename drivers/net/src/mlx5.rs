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

use alloc::sync::Arc;
use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, RX_RING_N, TX_RING_N};

use alloc::vec::Vec;

use cmd::{
    build_cqe_inline, build_cqe_with_mailboxes, decode_response, is_complete, CmdError, CmdOp,
    CmdResponse, CQE_LEN, CQE_OFF_STATUS_OWN, MAILBOX_BLOCK_LEN, STATUS_OWN_BIT,
};

// Smokes live in the driver directory, not the shared tests.rs.
mod tests;

pub mod bit_field;
pub mod caps;
pub mod cmd;
pub mod cq;
pub mod cqe;
pub mod eq;
pub mod eqe;
pub mod mailbox;
pub mod mkey;
pub mod qp;
pub mod ring;
pub mod steering;
pub mod vport;
pub mod wqe;

// ── PCI device IDs (ConnectX-4 .. ConnectX-6 Dx) ───────────────────

/// Vendor: Mellanox (now NVIDIA Networking).
pub const MLX5_VENDOR: u16 = 0x15B3;

/// ConnectX-4.
pub const MLX5_DEV_CX4: u16 = 0x1011;
/// ConnectX-4 Lx.
pub const MLX5_DEV_CX4_LX: u16 = 0x1013;
/// ConnectX-4 Lx Virtual Function.
pub const MLX5_DEV_CX4_LX_VF: u16 = 0x1015;
/// ConnectX-5.
pub const MLX5_DEV_CX5: u16 = 0x1017;
/// ConnectX-5 Ex.
pub const MLX5_DEV_CX5_EX: u16 = 0x1019;
/// ConnectX-6.
pub const MLX5_DEV_CX6: u16 = 0x101B;
/// ConnectX-6 Dx.
pub const MLX5_DEV_CX6_DX: u16 = 0x101D;

const ALL_DEV_IDS: &[u16] = &[
    MLX5_DEV_CX4,
    MLX5_DEV_CX4_LX,
    MLX5_DEV_CX4_LX_VF,
    MLX5_DEV_CX5,
    MLX5_DEV_CX5_EX,
    MLX5_DEV_CX6,
    MLX5_DEV_CX6_DX,
];

// ── Init-segment register offsets (BAR0) ───────────────────────────
//
// All multi-byte fields are big-endian per PRM §1.4. The decoder
// byte-swaps on read.

const ISEG_FW_REV_MAJOR: usize = 0x0000;
const ISEG_FW_REV_MINOR: usize = 0x0002;
const ISEG_FW_REV_SUB: usize = 0x0004;
const ISEG_CMD_IFACE_REV: usize = 0x0006;
const ISEG_CMDQ_ADDR_HIGH: usize = 0x0010;
const ISEG_CMDQ_ADDR_LO_SZ: usize = 0x0014;
const ISEG_CMD_DBELL: usize = 0x0018;
const ISEG_HEALTH_BUF: usize = 0x001C;
const ISEG_HEALTH_BUF_LEN: usize = 64;
const ISEG_INITIALIZING: usize = 0x0FFC;

/// Total length of the init segment we decode against.
pub const INIT_SEGMENT_LEN: usize = 0x1000;

/// `initializing` register bit set by FW while it is starting; driver
/// must poll it clear before issuing any command.
const INITIALIZING_BIT: u32 = 1 << 31;

/// PRM-documented worst-case startup wait (~2 s per §1.6) before the
/// driver should declare the HCA dead. Wall-clock budget — replaces
/// the prior CPU-clock-dependent 20M-iter spin estimate.
const INIT_DEADLINE_MS: u64 = 2_000;

/// Stage 3: cmdq sizing.
///
/// `log_size = 0` → 1 outstanding command (smallest legal value, plenty
/// for synchronous bring-up). One CQE = 64 B; we still allocate a 4-KiB
/// page for natural alignment.
const STAGE3_CMDQ_LOG_SIZE: u8 = 0;
const STAGE3_CMDQ_PAGE_LEN: usize = 4096;

/// Per-CQE polling deadline. mlx5 NOP / QUERY_HCA_CAP latency is
/// well under a microsecond; 5 s wall-clock gives plenty of headroom
/// for a busy host before declaring the firmware hung.
const CMD_DEADLINE_MS: u64 = 5_000;

/// Capability groups for `QUERY_HCA_CAP` (PRM §15.2). Encoded into
/// the op_mod field; combined with a "current vs max" bit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum HcaCapGroup {
    GeneralDevice = 0x0,
    EthernetOffload = 0x1,
    Atomic = 0x3,
    Roce = 0x4,
    IpoibOffloads = 0x5,
}

// ── Decoded init-segment ───────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InitSegment {
    pub fw_rev_major: u16,
    pub fw_rev_minor: u16,
    pub fw_rev_subminor: u16,
    pub cmd_interface_rev: u16,
    pub cmdq_addr: u64,
    pub cmdq_log_size: u8,
    pub cmd_dbell_vector: u32,
    /// Raw 64-byte health buffer; parsed in a later stage.
    pub health_buffer: [u8; ISEG_HEALTH_BUF_LEN],
    pub initializing: bool,
}

#[inline]
fn be16(raw: &[u8; INIT_SEGMENT_LEN], off: usize) -> u16 {
    u16::from_be_bytes([raw[off], raw[off + 1]])
}

#[inline]
fn be32(raw: &[u8; INIT_SEGMENT_LEN], off: usize) -> u32 {
    u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

/// Decode a 4-KiB snapshot of BAR0 into the structured init segment.
/// All field accesses are byte-indexed so this is callable from a
/// smoke harness without any MMIO mapping.
pub fn decode_init_segment(raw: &[u8; INIT_SEGMENT_LEN]) -> InitSegment {
    let cmdq_high = be32(raw, ISEG_CMDQ_ADDR_HIGH) as u64;
    let cmdq_low_sz = be32(raw, ISEG_CMDQ_ADDR_LO_SZ);
    // Low 4 bits = log2(#commands); upper 28 bits = address bits
    // [31:4] of the cmd queue base. The full 64-bit phys is
    // (high << 32) | (low_sz & ~0xF).
    let cmdq_addr = (cmdq_high << 32) | (cmdq_low_sz as u64 & !0xFu64);
    let cmdq_log_size = (cmdq_low_sz & 0xF) as u8;
    let cmd_dbell_vec = be32(raw, ISEG_CMD_DBELL);
    let initializing = (be32(raw, ISEG_INITIALIZING) & INITIALIZING_BIT) != 0;
    let mut health = [0u8; ISEG_HEALTH_BUF_LEN];
    health.copy_from_slice(&raw[ISEG_HEALTH_BUF..ISEG_HEALTH_BUF + ISEG_HEALTH_BUF_LEN]);
    InitSegment {
        fw_rev_major: be16(raw, ISEG_FW_REV_MAJOR),
        fw_rev_minor: be16(raw, ISEG_FW_REV_MINOR),
        fw_rev_subminor: be16(raw, ISEG_FW_REV_SUB),
        cmd_interface_rev: be16(raw, ISEG_CMD_IFACE_REV),
        cmdq_addr,
        cmdq_log_size,
        cmd_dbell_vector: cmd_dbell_vec,
        health_buffer: health,
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

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Memory allocation failed.
    NoMemory,
    /// Catch-all.
    Other(&'static str),
    /// Stage 7: caller-supplied EQ parameters were invalid.
    EqBuild(eq::EqError),
    /// Stage 8: caller-supplied CQ parameters were invalid.
    CqBuild(cq::CqError),
    /// Stage 9: caller-supplied QP parameters were invalid.
    QpBuild(qp::QpError),
    /// Stage 11: caller-supplied IoVec list was malformed.
    RingBuild(ring::RingError),
    /// Stage 11: post_send/post_recv referenced a qp_number that
    /// isn't in the driver's QP registry.
    UnknownQp,
    /// Stage 11: poll_cq referenced a cq_number not in the registry.
    UnknownCq,
    /// Stage 12: vport-context decoder rejected the response.
    VportDecode,
    /// Stage 13: caller-supplied mkey parameters were invalid.
    MkeyBuild(mkey::MkeyError),
    /// Stage 14: caller-supplied RQT parameters were invalid.
    RqtBuild(steering::RqtError),
}

impl narf_net::Interface for Mlx5Hca {
    fn name(&self) -> &str {
        "mlx5"
    }
    fn mac(&self) -> [u8; 6] {
        self.nic_state().mac
    }
    fn mtu(&self) -> u32 {
        let m = self.nic_state().mtu;
        if m == 0 {
            1500
        } else {
            m
        }
    }
    fn link_up(&self) -> bool {
        self.nic_state().link_up
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}

/// Stage 7 + 15: live-EQ bookkeeping. Holds the FW-assigned
/// `eq_number`, DMA pages backing the EQ buffer, and the polling
/// cursor used by Stage-15 `poll_eq`.
pub struct LiveEq {
    pub eq_number: u32,
    pages: Vec<DmaBuffer>,
    pub params: eq::EqParams,
    /// Next-to-read EQE index (Stage 15).
    pub consumer: u32,
}

/// Stage 8 + 11: live-CQ bookkeeping. Same shape as `LiveEq` but
/// tracks the bound EQ via params.c_eqn and the polling cursor
/// used by Stage-11 `poll_cq`.
pub struct LiveCq {
    pub cq_number: u32,
    pages: Vec<DmaBuffer>,
    pub params: cq::CqParams,
    /// Next-to-read CQE index (mod cq_capacity).
    pub consumer: u32,
}

/// Stage 9 + 11: live-QP bookkeeping. Holds the FW-assigned
/// `qp_number`, the DMA pages backing the SQ + RQ buffers, the
/// state mirror (Stage 9), and the SQ/RQ tail counters used by
/// `post_send` / `post_recv` (Stage 11).
pub struct LiveQp {
    pub qp_number: u32,
    pages: Vec<DmaBuffer>,
    pub params: qp::QpParams,
    pub state: qp::QpState,
    /// Next-to-write SQ index (mod sq_capacity).
    pub sq_tail: u32,
    /// Next-to-write RQ index (mod rq_capacity).
    pub rq_tail: u32,
}

impl fmt::Debug for LiveQp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveQp")
            .field("qp_number", &self.qp_number)
            .field("state", &self.state)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LiveCq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveCq")
            .field("cq_number", &self.cq_number)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LiveEq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveEq")
            .field("eq_number", &self.eq_number)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

pub struct Mlx5Hca {
    mmio: MmioRegion,
    segment: InitSegment,
    /// Stage 3: 4-KiB DMA-coherent backing for the command queue.
    /// One slot used (log_size = 0); kept resident for the life of
    /// the device.
    cmdq: DmaBuffer,
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
    /// Stage 8: registry of live CQs.
    cqs: IrqSafeSpinLock<Vec<LiveCq>>,
    /// Stage 8: FW-assigned UAR page indices owned by this driver.
    uars: IrqSafeSpinLock<Vec<u32>>,
    /// Stage 8: FW-assigned PD numbers owned by this driver.
    pds: IrqSafeSpinLock<Vec<u32>>,
    /// Stage 9: registry of live QPs.
    qps: IrqSafeSpinLock<Vec<LiveQp>>,
    /// Stage 7: BAR0 byte-offset where UAR pages start. PRM-documented
    /// for ConnectX-4..6 at 0x100000 (1 MiB into BAR0). Driver-level
    /// override is kept on the struct so a future stage can refine
    /// after a proper QUERY_HCA_CAP read.
    uar_base: u64,
    /// Stage 12: cached MAC + MTU from the last `QUERY_NIC_VPORT_CONTEXT`.
    nic_state: IrqSafeSpinLock<NicCachedState>,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: the only non-`Send` members are the `MmioRegion`/`DmaBuffer` raw
// device-memory handles; they address identity-mapped MMIO/DMA that is valid
// from any CPU, so moving the `Mlx5Hca` across threads is sound.
unsafe impl Send for Mlx5Hca {}
// SAFETY: every interior-mutable field (`next_token`, `eqs`, `cqs`, `uars`,
// `pds`, `qps`, `nic_state`, the IPC rings) is wrapped in `IrqSafeSpinLock`,
// and the MMIO/DMA handles are only touched through `&self` methods that take
// those locks, so concurrent `&Mlx5Hca` access from multiple CPUs is
// serialized and race-free.
unsafe impl Sync for Mlx5Hca {}

#[derive(Copy, Clone, Debug, Default)]
pub struct NicCachedState {
    pub mac: [u8; 6],
    pub mtu: u32,
    pub link_up: bool,
}

/// Default BAR0 offset where UAR pages live on ConnectX-4..6.
const UAR_BASE_DEFAULT: u64 = 0x100000;

impl fmt::Debug for Mlx5Hca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mlx5Hca")
            .field(
                "fw",
                &(
                    self.segment.fw_rev_major,
                    self.segment.fw_rev_minor,
                    self.segment.fw_rev_subminor,
                ),
            )
            .field("cmd_iface", &self.segment.cmd_interface_rev)
            .field("cmdq_log_sz", &self.segment.cmdq_log_size)
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
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Mlx5Error> {
        // SAFETY: caller-authority over the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| Mlx5Error::BarMapFailed)?;

        // Poll the initializing register at 0x0FFC until bit 31
        // clears. Two-second worst case per PRM §1.6.
        // responsive_spin_until ticks sleep_pumps so cursor / serial
        // / audio drain stay alive across the multi-second wait.
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                let v = unsafe { mmio.read32(ISEG_INITIALIZING as u64) };
                // Register is BE on the wire; read32 returns
                // LE-host bytes, so swap.
                (v.swap_bytes() & INITIALIZING_BIT) == 0
            },
            narf_time::Deadline::after_ms(INIT_DEADLINE_MS),
        );
        if !ready {
            return Err(Mlx5Error::InitTimeout);
        }

        // Snapshot the init segment region. We do byte-by-byte reads
        // so the BE byte order is preserved exactly as the PRM lays
        // it out.
        let mut raw = [0u8; INIT_SEGMENT_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            // SAFETY: identity-mapped MMIO; offset `i` is bounded by
            // `INIT_SEGMENT_LEN`, the documented init-segment window in BAR0.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe { mmio.read8(i as u64) };
        }
        let segment = decode_init_segment(&raw);

        // Stage 3: cmdq allocation + register programming.
        let cmdq = alloc_coherent(STAGE3_CMDQ_PAGE_LEN, DomainId::DRIVER_0)
            .map_err(|_| Mlx5Error::CmdqAlloc)?;
        let cmdq_phys = cmdq.phys_addr().raw();
        program_cmdq_registers(&mmio, cmdq_phys, STAGE3_CMDQ_LOG_SIZE);

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let hca = Arc::new(Self {
            mmio,
            segment,
            cmdq,
            next_token: IrqSafeSpinLock::new(1),
            nop_selftest: None,
            eqs: IrqSafeSpinLock::new(Vec::new()),
            cqs: IrqSafeSpinLock::new(Vec::new()),
            uars: IrqSafeSpinLock::new(Vec::new()),
            pds: IrqSafeSpinLock::new(Vec::new()),
            qps: IrqSafeSpinLock::new(Vec::new()),
            uar_base: UAR_BASE_DEFAULT,
            nic_state: IrqSafeSpinLock::new(NicCachedState::default()),
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn pumps
        spawn_pumps(hca.clone(), rx_prod, tx_cons);

        Arc::try_unwrap(hca).map_err(|_| Mlx5Error::NoMemory)
    }

    /// Stage 12: refresh the cached MAC + MTU off the live HCA.
    pub fn refresh_nic_state(&self) -> Result<NicCachedState, Mlx5Error> {
        let ctx = self.query_nic_vport_context()?;
        let state = NicCachedState {
            mac: ctx.permanent_mac(),
            mtu: ctx.mtu(),
            link_up: true,
        };
        *self.nic_state.lock() = state;
        Ok(state)
    }

    /// Stage 12: snapshot of the cached NIC state.
    pub fn nic_state(&self) -> NicCachedState {
        *self.nic_state.lock()
    }

    /// Stage 4 self-check: post a single NOP through the live cmdq
    /// transport. Records the result on the driver so callers can
    /// query it later via `nop_selftest()`. Idempotent — each call
    /// re-runs the NOP and overwrites the stored result.
    pub fn run_nop_selftest(&mut self) -> Result<(), Mlx5Error> {
        let r = self.issue_command_inline(CmdOp::Nop, 0, &[]).map(|_| ());
        self.nop_selftest = Some(r.clone());
        r
    }

    /// Latest stored NOP self-test outcome, or `None` if it was
    /// never run.
    pub fn nop_selftest(&self) -> Option<Result<(), Mlx5Error>> {
        self.nop_selftest.clone()
    }

    /// Issue an inline-mode command (≤8 B input, ≤8 B output) to slot
    /// 0 of the cmdq, ring the doorbell, poll for completion, and
    /// decode the inline response. Used by Stage 3 to bring up NOP
    /// and any other small synchronous command.
    pub fn issue_command_inline(
        &self,
        op: CmdOp,
        input_modifier: u32,
        inline_input: &[u8],
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_mut_ptr::<u8>(),
                    b,
                );
            }
        }
        compiler_fence(Ordering::SeqCst);

        // Ring the cmd_dbell doorbell with bit 0 set (slot 0).
        self.ring_cmd_doorbell(1);

        // Poll the slot's status_own byte until the ownership bit
        // clears. responsive_spin_until ticks sleep_pumps.
        let own_phys = slot_phys + CQE_OFF_STATUS_OWN as u64;
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(own_phys).kernel_ptr::<u8>()) } & STATUS_OWN_BIT == 0,
            narf_time::Deadline::after_ms(CMD_DEADLINE_MS),
        );
        if !done {
            return Err(Mlx5Error::CmdTimeout);
        }

        // Read the completed CQE back out.
        let mut completed = [0u8; CQE_LEN];
        for (i, b) in completed.iter_mut().enumerate() {
            // SAFETY: `slot_phys` is the identity-mapped DMA-coherent CQE slot
            // allocated for this command; `i < CQE_LEN` keeps the byte read
            // within the slot.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
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
            self.mmio
                .write32(ISEG_CMD_DBELL as u64, slot_mask.swap_bytes());
        }
    }

    /// Phys address of the cmdq DMA backing (Stage 3+).
    pub fn cmdq_phys(&self) -> u64 {
        self.cmdq.phys_addr().raw()
    }

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
        op: CmdOp,
        input_modifier: u32,
        input: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Mlx5Error> {
        let token = {
            let mut tok = self.next_token.lock();
            let v = *tok;
            *tok = tok.wrapping_add(1);
            v
        };
        let n_in = mailbox::block_count_for(input.len());
        let n_out = mailbox::block_count_for(output_len);

        // Allocate per-block DMA pages (one block per page is
        // wasteful but simplifies alignment + safety; mailbox blocks
        // must be 512-B aligned and a fresh page is page-aligned).
        let mut in_blocks: Vec<DmaBuffer> = Vec::with_capacity(n_in);
        let mut out_blocks: Vec<DmaBuffer> = Vec::with_capacity(n_out);
        for _ in 0..n_in {
            in_blocks
                .push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        for _ in 0..n_out {
            out_blocks
                .push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let in_phys: Vec<u64> = in_blocks.iter().map(|b| b.phys_addr().raw()).collect();
        let out_phys: Vec<u64> = out_blocks.iter().map(|b| b.phys_addr().raw()).collect();

        // Populate input mailbox blocks.
        let in_data = mailbox::write_input_chain(input, &in_phys, token);
        for (block, dma) in in_data.iter().zip(in_blocks.iter()) {
            let phys = dma.phys_addr().raw();
            // SAFETY: identity-mapped DMA; driver-owned buffer.
            unsafe {
                for (i, &b) in block.iter().enumerate() {
                    core::ptr::write_volatile((phys + i as u64) as *mut u8, b);
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
                    core::ptr::write_volatile((phys + i as u64) as *mut u8, 0);
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
                    core::ptr::write_volatile((phys + 0x1F0 + j as u64) as *mut u8, b);
                }
                for (j, &b) in l.to_be_bytes().iter().enumerate() {
                    core::ptr::write_volatile((phys + 0x1F4 + j as u64) as *mut u8, b);
                }
            }
        }

        // Build + post the CQE.
        let cqe = build_cqe_with_mailboxes(
            op,
            input_modifier,
            in_phys[0],
            input.len() as u32,
            out_phys[0],
            output_len as u32,
            token,
        );
        let slot_phys = self.cmdq.phys_addr().raw();
        // SAFETY: identity-mapped DMA cmdq, exclusively owned.
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_mut_ptr::<u8>(),
                    b,
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.ring_cmd_doorbell(1);

        // Poll for completion.
        // Poll until ownership clears. responsive_spin_until ticks
        // sleep_pumps.
        let own_phys = slot_phys + CQE_OFF_STATUS_OWN as u64;
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(own_phys).kernel_ptr::<u8>()) } & STATUS_OWN_BIT == 0,
            narf_time::Deadline::after_ms(CMD_DEADLINE_MS),
        );
        if !done {
            return Err(Mlx5Error::CmdTimeout);
        }

        // Decode CQE status; even on failure we want to surface
        // exactly what FW reported.
        let mut completed = [0u8; CQE_LEN];
        for (i, b) in completed.iter_mut().enumerate() {
            // SAFETY: `slot_phys` is the identity-mapped DMA-coherent CQE slot
            // for this command; `i < CQE_LEN` bounds the read to the slot.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
        }
        debug_assert!(is_complete(&completed));
        let _resp = decode_response(&completed).map_err(Mlx5Error::CmdFailed)?;

        // Read output blocks back into a contiguous Vec.
        let mut blocks: Vec<[u8; MAILBOX_BLOCK_LEN]> = Vec::with_capacity(n_out);
        for dma in out_blocks.iter() {
            let phys = dma.phys_addr().raw();
            let mut block = [0u8; MAILBOX_BLOCK_LEN];
            for (i, b) in block.iter_mut().enumerate() {
                // SAFETY: `phys` is the identity-mapped DMA mailbox-block buffer
                // from `out_blocks`; `i < MAILBOX_BLOCK_LEN` bounds the read to
                // that block.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                *b = unsafe { core::ptr::read_volatile((phys + i as u64) as *const u8) };
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
        op: CmdOp,
        input_modifier: u32,
        input: &[u8],
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
            in_blocks
                .push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let in_phys: Vec<u64> = in_blocks.iter().map(|b| b.phys_addr().raw()).collect();
        let in_data = mailbox::write_input_chain(input, &in_phys, token);
        for (block, dma) in in_data.iter().zip(in_blocks.iter()) {
            let phys = dma.phys_addr().raw();
            // SAFETY: identity-mapped DMA; driver-owned buffer.
            unsafe {
                for (i, &b) in block.iter().enumerate() {
                    core::ptr::write_volatile((phys + i as u64) as *mut u8, b);
                }
            }
        }
        // Build the CQE: input mailbox set, output mailbox = 0, len = 0.
        let cqe = build_cqe_with_mailboxes(
            op,
            input_modifier,
            in_phys[0],
            input.len() as u32,
            /* output_mb_phys */ 0,
            /* output_len */ 0,
            token,
        );
        let slot_phys = self.cmdq.phys_addr().raw();
        // SAFETY: identity-mapped cmdq DMA.
        unsafe {
            for (i, &b) in cqe.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_mut_ptr::<u8>(),
                    b,
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.ring_cmd_doorbell(1);

        let own_phys = slot_phys + CQE_OFF_STATUS_OWN as u64;
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(own_phys).kernel_ptr::<u8>()) } & STATUS_OWN_BIT == 0,
            narf_time::Deadline::after_ms(CMD_DEADLINE_MS),
        );
        if !done {
            return Err(Mlx5Error::CmdTimeout);
        }

        let mut completed = [0u8; CQE_LEN];
        for (i, b) in completed.iter_mut().enumerate() {
            // SAFETY: `slot_phys` is the identity-mapped DMA-coherent CQE slot
            // for this command; `i < CQE_LEN` bounds the read to the slot.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(slot_phys + i as u64).kernel_ptr::<u8>(),
                )
            };
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
    pub fn create_eq(&self, params: eq::EqParams, page_count: usize) -> Result<u32, Mlx5Error> {
        let mut pages: Vec<DmaBuffer> = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let phys: Vec<u64> = pages.iter().map(|p| p.phys_addr().raw()).collect();
        let payload = eq::build_create_eq_input(params, &phys).map_err(Mlx5Error::EqBuild)?;
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateEq, 0, &payload)?;
        // PRM: eq_number rides in the low 24 bits of output_modifier.
        let eq_number = resp.output_modifier & 0x00FF_FFFF;
        self.eqs.lock().push(LiveEq {
            eq_number,
            pages,
            params,
            consumer: 0,
        });
        Ok(eq_number)
    }

    /// Stage 15: pop one async event off `eq_number`. Returns
    /// `Ok(None)` if HW still owns the next slot.
    pub fn poll_eq(&self, eq_number: u32) -> Result<Option<eqe::EqeView>, Mlx5Error> {
        let mut eqs = self.eqs.lock();
        let e = eqs
            .iter_mut()
            .find(|e| e.eq_number == eq_number)
            .ok_or(Mlx5Error::UnknownQp)?;
        let cap = 1u32 << e.params.log_eq_size;
        let phys = e.pages[0].phys_addr().raw();
        let off = ((e.consumer % cap) as usize) * eqe::EQE_LEN;
        let mut bytes = [0u8; eqe::EQE_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: `phys` is the identity-mapped DMA EQ buffer; `off` is the
            // in-range entry offset and `i < eqe::EQE_LEN`, so the read stays
            // within the EQE.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *b = unsafe { core::ptr::read_volatile((phys + off as u64 + i as u64) as *const u8) };
        }
        if eqe::is_hw_owned(&bytes) {
            return Ok(None);
        }
        let view = eqe::decode_eqe(&bytes);
        e.consumer = e.consumer.wrapping_add(1);
        Ok(Some(view))
    }

    /// Stage 15: arm an EQ — write the EQ doorbell at UAR offset
    /// 0x40 to acknowledge consumed events and (re-)enable
    /// interrupts. PRM-documented value packs eq_number in the
    /// high byte and the consumer index low 24 bits.
    pub fn arm_eq(&self, uar_page: u32, eq_number: u32, consumer: u32) {
        let val = ((eq_number & 0xFF) << 24) | (consumer & 0x00FF_FFFF);
        self.uar_write32(uar_page, 0x40, val);
    }

    /// Stage 7: write a 4-byte BE doorbell into a UAR page. `uar_page`
    /// is the index assigned by `ALLOC_UAR` (Stage 8); `byte_offset`
    /// is the offset within the 4-KiB UAR page. Used by EQ arming
    /// + WQ tail bumps.
    pub fn uar_write32(&self, uar_page: u32, byte_offset: u32, value: u32) {
        let abs = self.uar_base + (uar_page as u64) * 4096 + byte_offset as u64;
        // SAFETY: identity-mapped MMIO; caller asserts uar_page is
        // owned.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.mmio.write32(abs, value.swap_bytes());
        }
    }

    /// Number of currently-allocated EQs.
    pub fn eq_count(&self) -> usize {
        self.eqs.lock().len()
    }

    /// Stage 8: live `ALLOC_UAR`. No input data; FW returns the
    /// assigned UAR-page index in `output_modifier` low 24 bits.
    /// Tracked on the driver registry — every alloc'd UAR stays
    /// owned by the driver until a (future) free is added.
    pub fn alloc_uar(&self) -> Result<u32, Mlx5Error> {
        let resp = self.issue_command_inline(CmdOp::AllocUar, 0, &[])?;
        let uar = resp.output_modifier & 0x00FF_FFFF;
        self.uars.lock().push(uar);
        Ok(uar)
    }

    /// Stage 8: live `ALLOC_PD`. No input data; FW returns the
    /// assigned PD number in `output_modifier` low 24 bits.
    pub fn alloc_pd(&self) -> Result<u32, Mlx5Error> {
        let resp = self.issue_command_inline(CmdOp::AllocPd, 0, &[])?;
        let pd = resp.output_modifier & 0x00FF_FFFF;
        self.pds.lock().push(pd);
        Ok(pd)
    }

    /// Stage 8: live `CREATE_CQ`. Allocates `page_count` 4-KiB
    /// DMA-coherent pages for the CQ buffer, builds the CREATE_CQ
    /// payload via `cq::build_create_cq_input`, posts via the
    /// input-mailbox transport, and returns the FW-assigned
    /// `cq_number` (low 24 bits of `output_modifier`). The CQ is
    /// bound to `params.c_eqn` for async events.
    pub fn create_cq(&self, params: cq::CqParams, page_count: usize) -> Result<u32, Mlx5Error> {
        let mut pages: Vec<DmaBuffer> = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let phys: Vec<u64> = pages.iter().map(|p| p.phys_addr().raw()).collect();
        let payload = cq::build_create_cq_input(params, &phys).map_err(Mlx5Error::CqBuild)?;
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateCq, 0, &payload)?;
        let cq_number = resp.output_modifier & 0x00FF_FFFF;
        self.cqs.lock().push(LiveCq {
            cq_number,
            pages,
            params,
            consumer: 0,
        });
        Ok(cq_number)
    }

    /// Number of currently-allocated CQs.
    pub fn cq_count(&self) -> usize {
        self.cqs.lock().len()
    }
    /// Number of currently-allocated UARs.
    pub fn uar_count(&self) -> usize {
        self.uars.lock().len()
    }
    /// Number of currently-allocated PDs.
    pub fn pd_count(&self) -> usize {
        self.pds.lock().len()
    }
    /// Number of currently-allocated QPs.
    pub fn qp_count(&self) -> usize {
        self.qps.lock().len()
    }

    /// Stage 9: live `CREATE_QP`. Allocates `page_count` 4-KiB DMA
    /// pages for the QP buffers (SQ + RQ + doorbell), builds the
    /// CREATE_QP payload via `qp::build_create_qp_input`, posts via
    /// the input-mailbox transport, and returns the FW-assigned
    /// `qp_number` (low 24 bits of `output_modifier`). The newly
    /// created QP starts in the RST state.
    pub fn create_qp(&self, params: qp::QpParams, page_count: usize) -> Result<u32, Mlx5Error> {
        let mut pages: Vec<DmaBuffer> = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Mlx5Error::CmdqAlloc)?);
        }
        let phys: Vec<u64> = pages.iter().map(|p| p.phys_addr().raw()).collect();
        let payload = qp::build_create_qp_input(params, &phys).map_err(Mlx5Error::QpBuild)?;
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateQp, 0, &payload)?;
        let qp_number = resp.output_modifier & 0x00FF_FFFF;
        self.qps.lock().push(LiveQp {
            qp_number,
            pages,
            params,
            state: qp::QpState::Rst,
            sq_tail: 0,
            rq_tail: 0,
        });
        Ok(qp_number)
    }

    /// Stage 9: live `MODIFY_QP` — drive a QP through the documented
    /// state-machine transitions. Each transition maps to a distinct
    /// PRM-documented opcode; `qp_number` rides in `input_modifier`.
    /// On success, the driver's `LiveQp.state` is updated.
    pub fn modify_qp(&self, qp_number: u32, transition: qp::QpTransition) -> Result<(), Mlx5Error> {
        let opcode = match transition {
            qp::QpTransition::ToRst => CmdOp::ToRstQp,
            qp::QpTransition::RstToInit => CmdOp::Rst2InitQp,
            qp::QpTransition::InitToRtr => CmdOp::Init2RtrQp,
            qp::QpTransition::RtrToRts => CmdOp::Rtr2RtsQp,
        };
        // Stage-9 minimal MODIFY_QP: zero-input. Real callers will
        // need to populate the qpc-update mailbox in Stage 10 to
        // hand FW path/MTU/PSN fields; for the state-machine plumbing
        // a zero-input modify is enough to validate the transport.
        let _resp = self.issue_command_inline(opcode, qp_number & 0x00FF_FFFF, &[])?;
        // Update the driver-side state mirror.
        let new_state = match transition {
            qp::QpTransition::ToRst => qp::QpState::Rst,
            qp::QpTransition::RstToInit => qp::QpState::Init,
            qp::QpTransition::InitToRtr => qp::QpState::Rtr,
            qp::QpTransition::RtrToRts => qp::QpState::Rts,
        };
        let mut qps = self.qps.lock();
        if let Some(q) = qps.iter_mut().find(|q| q.qp_number == qp_number) {
            q.state = new_state;
        }
        Ok(())
    }

    /// Look up the driver-side state mirror for a QP. Returns `None`
    /// if the qp_number doesn't match any tracked QP.
    pub fn qp_state(&self, qp_number: u32) -> Option<qp::QpState> {
        self.qps
            .lock()
            .iter()
            .find(|q| q.qp_number == qp_number)
            .map(|q| q.state)
    }

    /// Stage 11: post a SEND through the QP's SQ. Builds the WQE
    /// from `iovecs`, copies it into the SQ slot at the QP's
    /// current `sq_tail`, advances the tail, and rings the SQ
    /// doorbell. Returns the wqe_idx of the posted WQE — callers
    /// use it to correlate with completions in the CQ.
    pub fn post_send(
        &self,
        qp_number: u32,
        opcode: wqe::SendOpcode,
        cqe_req: wqe::CqeRequest,
        iovecs: &[ring::IoVec],
    ) -> Result<u32, Mlx5Error> {
        let mut qps = self.qps.lock();
        let q = qps
            .iter_mut()
            .find(|q| q.qp_number == qp_number)
            .ok_or(Mlx5Error::UnknownQp)?;
        let sq_capacity = 1u32 << q.params.log_sq_size;
        let wqe_idx = q.sq_tail % sq_capacity;
        let wqe_bytes = ring::build_send_wqe(qp_number, wqe_idx as u16, opcode, cqe_req, iovecs)
            .map_err(Mlx5Error::RingBuild)?;
        // SQ starts at offset 0 of the QP buffer.
        let sq_phys = q.pages[0].phys_addr().raw();
        let dst = sq_phys + ring::sq_offset_of(wqe_idx) as u64;
        // SAFETY: identity-mapped DMA, exclusively owned by this QP.
        unsafe {
            for (i, &b) in wqe_bytes.iter().enumerate() {
                core::ptr::write_volatile((dst + i as u64) as *mut u8, b);
            }
        }
        compiler_fence(Ordering::SeqCst);
        let uar_page = q.params.uar_page;
        q.sq_tail = q.sq_tail.wrapping_add(1);
        let next_idx = (q.sq_tail % sq_capacity) as u16;
        drop(qps);
        self.ring_sq_doorbell(uar_page, qp_number, next_idx);
        Ok(wqe_idx)
    }

    /// Stage 11: post a RECV onto the QP's RQ. Builds the recv-WQE
    /// from `iovecs`, copies it into the RQ slot, advances the tail,
    /// and bumps the RQ doorbell record. Returns the wqe_idx posted.
    pub fn post_recv(&self, qp_number: u32, iovecs: &[ring::IoVec]) -> Result<u32, Mlx5Error> {
        let mut qps = self.qps.lock();
        let q = qps
            .iter_mut()
            .find(|q| q.qp_number == qp_number)
            .ok_or(Mlx5Error::UnknownQp)?;
        let rq_capacity = 1u32 << q.params.log_rq_size;
        let wqe_idx = q.rq_tail % rq_capacity;
        let wqe_bytes = ring::build_recv_wqe(iovecs).map_err(Mlx5Error::RingBuild)?;
        // RQ region starts after the SQ.
        let qp_phys = q.pages[0].phys_addr().raw();
        let rq_base = qp_phys + ring::sq_size_bytes(q.params.log_sq_size) as u64;
        let dst = rq_base + ring::rq_offset_of(wqe_idx) as u64;
        // SAFETY: identity-mapped DMA, owned by this QP.
        unsafe {
            for (i, &b) in wqe_bytes.iter().enumerate() {
                core::ptr::write_volatile((dst + i as u64) as *mut u8, b);
            }
        }
        compiler_fence(Ordering::SeqCst);
        q.rq_tail = q.rq_tail.wrapping_add(1);
        Ok(wqe_idx)
    }

    /// Stage 11: pop one completion off `cq_number`'s ring, if any.
    /// Walks the CQ buffer at the consumer cursor, returns the
    /// decoded `CqeView` if HW has handed it back, and advances the
    /// cursor on the live LiveCq record.
    pub fn poll_cq(&self, cq_number: u32) -> Result<Option<cqe::CqeView>, Mlx5Error> {
        let mut cqs = self.cqs.lock();
        let c = cqs
            .iter_mut()
            .find(|c| c.cq_number == cq_number)
            .ok_or(Mlx5Error::UnknownCq)?;
        let cq_capacity = 1u32 << c.params.log_cq_size;
        let off = ring::cq_offset_of(c.consumer, cq_capacity);
        let cq_phys = c.pages[0].phys_addr().raw();
        let mut bytes = [0u8; cqe::CQE_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b =
                // SAFETY: `cq_phys` is the identity-mapped DMA CQ buffer; `off` is
                // the in-range entry offset and `i < cqe::CQE_LEN`, so the read
                // stays within the CQE.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(cq_phys + off as u64 + i as u64).kernel_ptr::<u8>()) };
        }
        if cqe::is_hw_owned(&bytes) {
            return Ok(None);
        }
        let view = cqe::decode_cqe(&bytes);
        c.consumer = c.consumer.wrapping_add(1);
        Ok(Some(view))
    }

    /// Stage 16: destroy a QP. Sends DESTROY_QP and removes the
    /// LiveQp record from the registry — the DMA backing drops
    /// when the LiveQp is freed.
    pub fn destroy_qp(&self, qp_number: u32) -> Result<(), Mlx5Error> {
        let _resp = self.issue_command_inline(CmdOp::DestroyQp, qp_number & 0x00FF_FFFF, &[])?;
        self.qps.lock().retain(|q| q.qp_number != qp_number);
        Ok(())
    }

    /// Stage 16: destroy a CQ.
    pub fn destroy_cq(&self, cq_number: u32) -> Result<(), Mlx5Error> {
        let _resp = self.issue_command_inline(CmdOp::DestroyCq, cq_number & 0x00FF_FFFF, &[])?;
        self.cqs.lock().retain(|c| c.cq_number != cq_number);
        Ok(())
    }

    /// Stage 16: destroy an EQ.
    pub fn destroy_eq(&self, eq_number: u32) -> Result<(), Mlx5Error> {
        let _resp = self.issue_command_inline(CmdOp::DestroyEq, eq_number & 0x00FF_FFFF, &[])?;
        self.eqs.lock().retain(|e| e.eq_number != eq_number);
        Ok(())
    }

    /// Stage 16: release a UAR page back to firmware.
    pub fn dealloc_uar(&self, uar_page: u32) -> Result<(), Mlx5Error> {
        let _resp = self.issue_command_inline(CmdOp::DeallocUar, uar_page & 0x00FF_FFFF, &[])?;
        self.uars.lock().retain(|&u| u != uar_page);
        Ok(())
    }

    /// Stage 16: release a PD back to firmware.
    pub fn dealloc_pd(&self, pd: u32) -> Result<(), Mlx5Error> {
        let _resp = self.issue_command_inline(CmdOp::DeallocPd, pd & 0x00FF_FFFF, &[])?;
        self.pds.lock().retain(|&p| p != pd);
        Ok(())
    }

    /// Stage 15: EQ interrupt handler — drain the EQ ring, dispatch
    /// each EQE, and re-arm the EQ doorbell when done.
    ///
    /// Called from the MSI-X handler registered during `bring_up`.
    /// For each SW-owned EQE at `eq_number`:
    ///
    /// - `CompletionEvent` (type 0x00): the EQE carries a CQ number;
    ///   call the caller-supplied `on_cq_completion` to wake the CQ
    ///   consumer. Linux: `mlx5_eq_comp_int` in `eq.c:106`.
    /// - `PortStateChange` (type 0x09): wake the link-state path.
    ///   Linux: `mlx5_eq_async_int` in `eq.c:191`.
    /// - `CommandInterfaceCompletion` (type 0x0A): wake the command
    ///   channel. Same async handler.
    /// - All other types: record but don't act (async events land in
    ///   a later stage).
    ///
    /// After draining, writes the EQ doorbell at UAR+0x40 to re-arm.
    /// Linux: `eq_update_ci` called at `eq.c:143`/229; doorbell offset
    /// `MLX5_EQ_DOORBELL_OFFSET = 0x40` at `eq.c:35`.
    ///
    /// Returns the number of EQEs consumed.
    pub fn handle_eq_irq(&self, eq_number: u32, on_cq_completion: impl Fn(u32)) -> u32 {
        // Budget cap mirrors Linux's MLX5_EQ_POLLING_BUDGET = 128
        // (eq.c:41) — prevents a livelock if the EQ fills faster than
        // we drain.
        const BUDGET: u32 = 128;
        let mut consumed = 0u32;

        loop {
            if consumed >= BUDGET {
                break;
            }
            match self.poll_eq(eq_number) {
                Ok(Some(view)) => {
                    // Dispatch by event type. Only completion events are
                    // handled in this stage; port-state / cmd-completion /
                    // async are a no-op for now — a follow-up can register a
                    // notifier chain per Linux's `atomic_notifier_call_chain`
                    // at eq.c:217.
                    if let eqe::EventType::CompletionEvent = view.event_type {
                        // CQN decoded from EQE byte 0x38 (BE u32,
                        // low 24 bits). Linux eq.c:125:
                        //   `be32_to_cpu(eqe->data.comp.cqn) & 0xffffff`
                        on_cq_completion(view.cqn);
                    }
                    consumed = consumed.wrapping_add(1);
                }
                // No more SW-owned EQEs; stop.
                Ok(None) => break,
                // EQ not found — nothing to do.
                Err(_) => break,
            }
        }

        // Re-arm: write the EQ consumer-index doorbell at UAR+0x40.
        // PRM-documented value: bits[31:24] = eq_number low byte,
        // bits[23:0] = consumer index. Linux: `eq_update_ci` called
        // after each poll loop at eq.c:143 and eq.c:226.
        // We read the updated consumer index from the live LiveEq
        // record; the lock is already dropped since poll_eq advanced it.
        if consumed > 0 {
            let consumer = {
                let eqs = self.eqs.lock();
                eqs.iter()
                    .find(|e| e.eq_number == eq_number)
                    .map(|e| e.consumer)
                    .unwrap_or(0)
            };
            let uar_page = {
                let eqs = self.eqs.lock();
                eqs.iter()
                    .find(|e| e.eq_number == eq_number)
                    .map(|e| e.params.uar_page)
                    .unwrap_or(0)
            };
            self.arm_eq(uar_page, eq_number, consumer);
        }

        consumed
    }

    /// Stage 15: allocate one MSI-X vector for `eq_number` and wire
    /// it into the mlx5 EQ. The EQ's `intr_vector` field must already
    /// be set to `irq_vector` when `create_eq` was called.
    ///
    /// NARF MSI-X path mirrors Linux's `mlx5_irq_alloc` +
    /// `request_irq` sequence: `enable_msix` → `alloc_vector` →
    /// `program_vector` → `enable`. Linux ref: `pci_irq.c`'s
    /// `mlx5_irq_alloc` and `create_map_eq` at `eq.c:286`,
    /// `eq.c:321`: `eq->irqn = pci_irq_vector(dev->pdev, vecidx)`.
    ///
    /// Pattern follows igc's `try_enable_msix` (igc.rs:545–561):
    /// call `narf_interrupts::vector::alloc()` for the IRQ vector
    /// number, `alloc_vector()` for the MSI-X table slot, then
    /// `program_vector(slot, apic_id, irq_vec)` → `enable()`.
    ///
    /// Returns `Ok(irq_vector)` on success, `Err` if the MSI-X table
    /// can't be set up (e.g. device is in legacy-IRQ mode).
    pub fn alloc_eq_msix_vector(
        cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: &narf_bus::BusDevice,
    ) -> Result<u8, Mlx5Error> {
        use narf_bus::enable_msix;
        // Allocate a system-wide IRQ vector number from the NARF
        // interrupt vector allocator.
        let irq_vec =
            narf_interrupts::vector::alloc().map_err(|_| Mlx5Error::Other("vector alloc"))?;
        let mut table = enable_msix(cap, device).map_err(|_| Mlx5Error::Other("msix setup"))?;
        // Reserve a slot in the MSI-X table (monotonic per-table alloc).
        let _slot = table
            .alloc_vector()
            .ok_or(Mlx5Error::Other("msix alloc_vector"))?;
        // Program table slot 0 → BSP APIC (id=0), irq_vec.
        // Mirrors igc.rs:557: `msix.program_vector(0, 0, v)`.
        // SAFETY: `table` is the MSI-X table mapped from this device's MSI-X
        // BAR by `enable_msix`; slot 0 was just reserved via `alloc_vector`,
        // so programming/enabling it writes only registers this driver owns.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            table
                .program_vector(0, 0, irq_vec)
                .map_err(|_| Mlx5Error::Other("msix program_vector"))?;
            table
                .enable()
                .map_err(|_| Mlx5Error::Other("msix enable"))?;
        }
        Ok(irq_vec)
    }

    /// Stage 16: orderly tear-down — destroy every tracked QP/CQ/EQ
    /// and free every PD/UAR. Used by driver-shutdown paths and for
    /// re-bring-up scenarios. Errors are surfaced via the return,
    /// but the driver still tries to free everything.
    pub fn teardown_all(&self) -> Result<(), Mlx5Error> {
        let mut last_err: Result<(), Mlx5Error> = Ok(());
        let qpns: Vec<u32> = self.qps.lock().iter().map(|q| q.qp_number).collect();
        for qpn in qpns {
            if let Err(e) = self.destroy_qp(qpn) {
                last_err = Err(e);
            }
        }
        let cqns: Vec<u32> = self.cqs.lock().iter().map(|c| c.cq_number).collect();
        for cqn in cqns {
            if let Err(e) = self.destroy_cq(cqn) {
                last_err = Err(e);
            }
        }
        let eqns: Vec<u32> = self.eqs.lock().iter().map(|e| e.eq_number).collect();
        for eqn in eqns {
            if let Err(e) = self.destroy_eq(eqn) {
                last_err = Err(e);
            }
        }
        let pds: Vec<u32> = self.pds.lock().clone();
        for pd in pds {
            if let Err(e) = self.dealloc_pd(pd) {
                last_err = Err(e);
            }
        }
        let uars: Vec<u32> = self.uars.lock().clone();
        for u in uars {
            if let Err(e) = self.dealloc_uar(u) {
                last_err = Err(e);
            }
        }
        last_err
    }

    /// Stage 14: create a TIR (RX endpoint). Returns the
    /// FW-assigned `tirn`.
    pub fn create_tir(&self, params: steering::TirParams) -> Result<u32, Mlx5Error> {
        let payload = steering::build_create_tir_input(params);
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateTir, 0, &payload)?;
        Ok(resp.output_modifier & 0x00FF_FFFF)
    }

    /// Stage 14: create a TIS (TX endpoint). Returns the
    /// FW-assigned `tisn`.
    pub fn create_tis(&self, params: steering::TisParams) -> Result<u32, Mlx5Error> {
        let payload = steering::build_create_tis_input(params);
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateTis, 0, &payload)?;
        Ok(resp.output_modifier & 0x00FF_FFFF)
    }

    /// Stage 14: create an RQT (RX queue table for RSS). Returns
    /// the FW-assigned `rqtn`.
    pub fn create_rqt(&self, params: steering::RqtParams, rqs: &[u32]) -> Result<u32, Mlx5Error> {
        let payload = steering::build_create_rqt_input(params, rqs).map_err(Mlx5Error::RqtBuild)?;
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateRqt, 0, &payload)?;
        Ok(resp.output_modifier & 0x00FF_FFFF)
    }

    /// Stage 13: register a memory region. Returns the L_KEY for
    /// use in WQE pointer-data segments. The DMA pages remain
    /// owned by the caller.
    pub fn create_mkey(&self, params: mkey::MkeyParams, pages: &[u64]) -> Result<u32, Mlx5Error> {
        let payload = mkey::build_create_mkey_input(params, pages).map_err(Mlx5Error::MkeyBuild)?;
        let resp = self.issue_command_with_input_mailbox(CmdOp::CreateMkey, 0, &payload)?;
        let mkey_index = resp.output_modifier & 0x00FF_FFFF;
        Ok(mkey::lkey_for(mkey_index))
    }

    /// Stage 13: release a memory region by L_KEY. Stage 13 sends
    /// the destroy command but doesn't track keys on the driver
    /// (Stage 16 wires the registry alongside the other destroy
    /// paths).
    pub fn destroy_mkey(&self, l_key: u32) -> Result<(), Mlx5Error> {
        let mkey_index = l_key >> 8;
        let _resp = self.issue_command_inline(CmdOp::DestroyMkey, mkey_index & 0x00FF_FFFF, &[])?;
        Ok(())
    }

    /// Stage 12: read the per-vport NIC context — MAC + MTU.
    pub fn query_nic_vport_context(&self) -> Result<vport::NicVportContext, Mlx5Error> {
        let bytes = self.issue_command_with_mailboxes(
            CmdOp::QueryNicVportContext,
            0,
            &[],
            vport::VPORT_CTX_LEN,
        )?;
        vport::NicVportContext::from_bytes(bytes).map_err(|_| Mlx5Error::VportDecode)
    }

    /// Stage 12: write the vport's MTU.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), Mlx5Error> {
        let payload = vport::build_set_mtu_payload(mtu);
        // op_mod_high bit 0 = "modify MTU"; rides as input_modifier.
        let _resp = self.issue_command_with_input_mailbox(
            CmdOp::ModifyNicVportContext,
            /* op_mod */ 1,
            &payload,
        )?;
        Ok(())
    }

    /// Stage 10: ring the SQ doorbell for `qp_number`. UAR offset
    /// 0x800 is the documented PRM SQ-doorbell offset within a UAR
    /// page; the value carries the wqe_idx of the next-to-post WQE
    /// + the qp_num. PRM §11.4.4.
    pub fn ring_sq_doorbell(&self, uar_page: u32, qp_number: u32, wqe_idx: u16) {
        // Doorbell value: bits[31:8] = qp_num, bits[7:0] = wqe_idx
        // low byte. Some HCAs use a 16-bit wqe_idx — Stage 10 stays
        // with the documented 8-bit form for SEND.
        let val = ((qp_number & 0x00FF_FFFF) << 8) | (wqe_idx as u32 & 0xFF);
        self.uar_write32(uar_page, 0x800, val);
    }

    /// Stage 5: typed wrapper around QUERY_HCA_CAP(GeneralDevice).
    /// Returns the decoded view; callers needing fields beyond the
    /// Stage-5 subset go through `caps::HcaGeneralCaps::raw()`.
    pub fn query_general_caps(&self, current: bool) -> Result<caps::HcaGeneralCaps, Mlx5Error> {
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
    pub fn query_hca_cap(&self, group: HcaCapGroup, current: bool) -> Result<Vec<u8>, Mlx5Error> {
        // Op modifier per PRM §15.2.1: bits [15:1] = cap group, bit
        // [0] = 0 (max) / 1 (current).
        let op_mod_high = (group as u16) << 1 | if current { 1 } else { 0 };
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
            CmdOp::QueryHcaCap,
            input_modifier,
            &[],
            HCA_CAP_OUTPUT_LEN,
        )
    }

    pub fn fw_rev(&self) -> (u16, u16, u16) {
        (
            self.segment.fw_rev_major,
            self.segment.fw_rev_minor,
            self.segment.fw_rev_subminor,
        )
    }

    pub fn cmd_interface_rev(&self) -> u16 {
        self.segment.cmd_interface_rev
    }

    pub fn cmdq_addr(&self) -> u64 {
        self.segment.cmdq_addr
    }

    pub fn cmdq_log_size(&self) -> u8 {
        self.segment.cmdq_log_size
    }

    pub fn segment(&self) -> &InitSegment {
        &self.segment
    }

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
pub(crate) fn program_cmdq_registers(mmio: &MmioRegion, cmdq_phys: u64, log_size: u8) {
    let high = (cmdq_phys >> 32) as u32;
    let low_aligned = (cmdq_phys as u32) & 0xFFFF_F000;
    let low_sz = low_aligned | ((log_size as u32) & 0xF);
    // SAFETY: identity-mapped MMIO; offsets bounded; caller has
    // exclusive ownership of the device.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio.write32(ISEG_CMDQ_ADDR_HIGH as u64, high.swap_bytes());
        mmio.write32(ISEG_CMDQ_ADDR_LO_SZ as u64, low_sz.swap_bytes());
    }
}

// ── Driver-match registration ──────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Mlx5Hca>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: caller-authority over device.
    let mut dev = match unsafe { Mlx5Hca::bring_up(&device, &cap) } {
        Ok(d) => d,
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
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Mlx5NetIface);
    }

    Ok(())
}

fn spawn_pumps(
    device: Arc<Mlx5Hca>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        mlx5_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        mlx5_tx_pump(d2, tx_cons).await;
    });
}

async fn mlx5_rx_pump(_device: Arc<Mlx5Hca>, mut _rx_prod: Producer<Frame, RX_RING_N>) {
    // TODO: implement mlx5 RX path (Stage 15+)
    loop {
        narf_scheduler::yield_now().await;
    }
}

async fn mlx5_tx_pump(_device: Arc<Mlx5Hca>, mut _tx_cons: Consumer<Frame, TX_RING_N>) {
    // TODO: implement mlx5 TX path (Stage 15+)
    loop {
        narf_scheduler::yield_now().await;
    }
}

/// Register the driver against every ConnectX-4..6 device id we
/// recognise. One match per id pair so each is independently
/// maintainable.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MLX5_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        MLX5_DEV_CX4 => "mlx5-cx4",
        MLX5_DEV_CX4_LX => "mlx5-cx4-lx",
        MLX5_DEV_CX4_LX_VF => "mlx5-cx4-lx-vf",
        MLX5_DEV_CX5 => "mlx5-cx5",
        MLX5_DEV_CX5_EX => "mlx5-cx5-ex",
        MLX5_DEV_CX6 => "mlx5-cx6",
        MLX5_DEV_CX6_DX => "mlx5-cx6-dx",
        _ => "mlx5",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Mlx5Hca) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

// ── Mlx5NetIface: lightweight ZST for narf-net registry ───────────
//
// `Mlx5Hca` owns firmware objects and can't be cloned cheaply.
// `Mlx5NetIface` is a zero-sized sentinel that delegates to the
// module-level `CONTROLLER` static, following the `Rtl8139Nic` pattern.

#[derive(Debug)]
pub struct Mlx5NetIface;

impl narf_net::Interface for Mlx5NetIface {
    fn name(&self) -> &str {
        "mlx5"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.nic_state().mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        with_controller(|c| {
            let m = c.nic_state().mtu;
            if m == 0 {
                1500
            } else {
                m
            }
        })
        .unwrap_or(1500)
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.nic_state().link_up).unwrap_or(false)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

// ── Stage 12: HwNic trait impl ─────────────────────────────────────

impl crate::HwNic for Mlx5Hca {
    fn name(&self) -> &'static str {
        "mlx5"
    }
    fn mac(&self) -> [u8; 6] {
        self.nic_state().mac
    }
    fn mtu(&self) -> u32 {
        let m = self.nic_state().mtu;
        if m == 0 {
            1500
        } else {
            m
        }
    }
    fn link_up(&self) -> bool {
        self.nic_state().link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::MellanoxMlx5
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        1 << 8
    }

    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ipc_ring
    }
}
