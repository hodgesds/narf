//! TPM 2.0 driver — clean-room (CRB + TIS).
//!
//! References (free PDFs, trustedcomputinggroup.org):
//!
//! - **"PC Client Specific TPM Interface Specification (TIS)"**
//!   v1.21 — legacy memory-mapped interface with ACCESS / STS /
//!   DATA_FIFO / DID_VID register block.
//! - **"PC Client Platform TPM Profile (PTP) for TPM 2.0"** rev
//!   1.05 — defines the **CRB (Command/Response Buffer)** interface
//!   used by modern TPMs and QEMU's `swtpm` backend.
//! - **"Trusted Platform Module Library Part 3: Commands"** rev
//!   1.59 — TPM2_GetRandom, TPM2_GetCapability, etc.
//!   <https://trustedcomputinggroup.org/resource/tpm-library-specification/>
//!
//! ## Discovery
//!
//! The control-area address comes from firmware, in order:
//!
//! 1. The **TPM2 ACPI table** (`control_address` field), parsed by
//!    `narf_acpi` — this is the only way to find an AMD fTPM whose
//!    control area firmware publishes at a non-fixed address (TCG
//!    ACPI spec; Linux `tpm_crb.c` discovers the same way). Start
//!    methods 11 (ARM SMC) and 15 (CRB with ARM FF-A) are named in
//!    `drivers/tpm/src/probe.rs` and are **not** driven here — they
//!    have no transport in-tree yet, so a table advertising one is
//!    skipped rather than probed as if it were MMIO CRB.
//! 2. The platform-fixed locality-0 window `0xFED4_0000` (PC Client
//!    PTP §5.2.1.1) when no usable table entry exists.
//!
//! At the chosen base, `TPM_INTERFACE_ID` (offset `0x30`) tells us
//! which interface the silicon exposes — bits[3:0] = 0 means CRB,
//! 0xF means TIS-only. An undefined interface type is a clean
//! `NotPresent`, never a guess.
//!
//! ## CRB register layout (PTP §6)
//!
//! Offsets relative to the control-area base. This map is the one
//! validated against Linux `tpm_crb.c`'s register structs and is
//! identical to the reference model in `drivers/tpm/src/crb.rs`.
//! (The map this file used before #939 based the block at `+0x40`,
//! disagreeing with both other in-tree CRB implementations.)
//!
//! | offset | name                    | width |
//! |--------|-------------------------|-------|
//! | 0x00   | LOC_STATE               | u32   |
//! | 0x08   | LOC_CTRL                | u32   |
//! | 0x0C   | LOC_STS                 | u32   |
//! | 0x30   | INTF_ID                 | u32   |
//! | 0x40   | CTRL_REQ                | u32   |
//! | 0x44   | CTRL_STS                | u32   |
//! | 0x48   | CTRL_CANCEL             | u32   |
//! | 0x4C   | CTRL_START              | u32   |
//! | 0x58   | CMD_SIZE                | u32   |
//! | 0x5C   | CMD_PA_LO               | u32   |
//! | 0x60   | CMD_PA_HI               | u32   |
//! | 0x68   | RSP_SIZE                | u32   |
//! | 0x6C   | RSP_PA_LO               | u32   |
//! | 0x70   | RSP_PA_HI               | u32   |
//!
//! ## CRB buffer contract (PTP §6)
//!
//! The `CMD_*` / `RSP_*` registers are **host-programmed**: the host
//! allocates the command/response buffers and writes their physical
//! addresses + sizes into the chip (cf.
//! `drivers/tpm/src/crb.rs::program_buffers`, which writes all six).
//! Probe therefore allocates host-owned coherent buffers and
//! programs them; firmware is never expected to publish them. The
//! pre-#939 probe *read* the registers as firmware-published and
//! failed `NoCommandBuffer` whenever firmware had left them zero —
//! the expected state — so CRB probe could never succeed on the
//! target laptops.
//!
//! ## Scope
//!
//! x86_64 only for now: off-x86_64 `probe` reports `NotPresent`,
//! preserving the previous stub behaviour. aarch64 CRB arrives via
//! the FF-A/SMC start methods above, which need their own transport.
//!
//! ## Composition (#934)
//!
//! This is the sole production TPM transport. It owns the MMIO
//! probe/submit paths and the probed-device singleton; it does NOT
//! own a wire codec — every command frame it submits is built by
//! the canonical builders in `narf_tpm` (`tpm2` / `commands`), and
//! the device is exposed to consumers through `narf_tpm`'s
//! `TpmDevice` trait and registry. (Registry registration on probe
//! success is the keystone seam, #943/#934.)

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_tpm::{TpmDevice, TpmError as HighLevelTpmError, TpmInfo};

use narf_lib::sync::IrqSafeSpinLock;

/// Platform-fixed locality 0 base for TPM 2.0 (PC Client PTP §5.2.1.1).
/// Used only as the fallback when the TPM2 ACPI table publishes no
/// usable control-area address.
pub const TPM_BASE_LOCALITY_0: u64 = 0xFED4_0000;

/// One locality / control area is 4 KiB (PC Client PTP §5.2).
const TPM_LOCALITY_LEN: u64 = 0x1000;

/// Size of each host-owned CRB buffer. 4 KiB covers the largest
/// TPM 2.0 command/response (TPM_BUFSIZE); CRB transfers are bounded
/// by the programmed size, so this is the transfer ceiling.
const CRB_BUFFER_LEN: usize = 4096;

/// CRB interface identification offset (PTP §6). bits[3:0]:
///   0x0 = CRB  0xF = TIS only.
pub(crate) const REG_INTERFACE_ID: u64 = 0x30;

// CRB control-area registers (offsets relative to the control-area
// base). Identical to drivers/tpm/src/crb.rs — see the module doc.
pub(crate) const REG_LOC_STATE: u64 = 0x00;
pub(crate) const REG_LOC_CTRL: u64 = 0x08;
pub(crate) const REG_CRB_CTRL_REQ: u64 = 0x40;
pub(crate) const REG_CRB_CTRL_STS: u64 = 0x44;
pub(crate) const REG_CRB_CTRL_CANCEL: u64 = 0x48;
pub(crate) const REG_CRB_CTRL_START: u64 = 0x4C;
pub(crate) const REG_CRB_CMD_SIZE: u64 = 0x58;
pub(crate) const REG_CRB_CMD_LO: u64 = 0x5C;
pub(crate) const REG_CRB_CMD_HI: u64 = 0x60;
pub(crate) const REG_CRB_RSP_SIZE: u64 = 0x68;
pub(crate) const REG_CRB_RSP_LO: u64 = 0x6C;
pub(crate) const REG_CRB_RSP_HI: u64 = 0x70;

pub(crate) const LOC_CTRL_REQ_ACCESS: u32 = 1 << 0;
pub(crate) const LOC_STATE_LOC_ASSIGNED: u32 = 1 << 1;

const CTRL_REQ_CMD_READY: u32 = 1 << 0;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CTRL_STS_ERROR: u32 = 1 << 0;
const CTRL_STS_TPM_IDLE: u32 = 1 << 1;
const CTRL_START_GO: u32 = 1 << 0;

// TIS register layout (TIS v1.21 §5.6), offsets relative to the same
// window base.
pub(crate) const REG_TIS_ACCESS: u64 = 0x00;
pub(crate) const REG_TIS_STS: u64 = 0x18;
pub(crate) const REG_TIS_DATA_FIFO: u64 = 0x24;
pub(crate) const REG_TIS_DID_VID: u64 = 0xF00;

const TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;
const TIS_ACCESS_ACTIVE: u8 = 1 << 5;
const TIS_STS_VALID: u8 = 1 << 7;
const TIS_STS_CMD_READY: u8 = 1 << 6;
const TIS_STS_DATA_AVAIL: u8 = 1 << 4;
const TIS_STS_GO: u8 = 1 << 5;
const TIS_STS_EXPECT: u8 = 1 << 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmKind {
    Crb,
    Tis,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TpmError {
    NotPresent,
    LocalityTimeout,
    BusyTimeout,
    /// Retained for the `narf_tpm::TpmError` mapping. Probe no
    /// longer produces it: since #939 the CRB buffers are
    /// host-owned and host-programmed, so "firmware published no
    /// buffer" is not a failure mode.
    NoCommandBuffer,
    /// Host-side allocation of the CRB command/response buffers
    /// failed.
    BufferAlloc,
    BadResponse,
}

/// Yielding equivalent of `narf_scheduler::responsive_spin_until`.
/// Polls `cond()` between `narf_scheduler::yield_now().await`s so
/// peer tasks (FB drain, cursor pump, USB-HID supervisor) keep
/// making progress while we wait on a TPM status bit that can take
/// up to 5 s on real silicon. Returns true if `cond` succeeded
/// before `deadline`, false on timeout. The TSC-based `Deadline`
/// uses `RDTSC` directly so it doesn't depend on the timer wheel.
async fn poll_yielding_until<F: FnMut() -> bool>(
    mut cond: F,
    deadline: narf_time::Deadline,
) -> bool {
    loop {
        if cond() {
            return true;
        }
        if deadline.expired() {
            return false;
        }
        narf_scheduler::yield_now().await;
    }
}

// ── CRB register window + probe core ────────────────────────────────
//
// The probe sequence and both submit paths are written against a
// minimal register-window trait so kernel-test fixtures can drive
// them against a register-level model of the device (see
// `crate::tpm_fixture`) — the same split `drivers/tpm/src/crb.rs`
// uses with its `CrbMmio` trait. The production implementation is
// [`MmioCrbRegs`] over an ioremap'd window.

/// A register window over a TPM control area; offsets are
/// relative to the control-area base. The 32-bit accessors serve
/// the CRB control area and the probe core; the 8-bit accessors
/// serve the TIS register block (ACCESS / STS / DATA_FIFO are
/// byte-wide in TIS v1.21 §5.6).
pub(crate) trait CrbRegs {
    fn rd32(&self, offset: u64) -> u32;
    fn wr32(&self, offset: u64, value: u32);
    fn rd8(&self, offset: u64) -> u8;
    fn wr8(&self, offset: u64, value: u8);
}

/// Production [`CrbRegs`]: volatile MMIO over an ioremap'd window.
struct MmioCrbRegs {
    va: u64,
}

impl CrbRegs for MmioCrbRegs {
    fn rd32(&self, offset: u64) -> u32 {
        // SAFETY: `va` is the device window mapped at probe; `offset`
        // is a register offset inside the 4 KiB locality window.
        unsafe { core::ptr::read_volatile((self.va + offset) as *const u32) }
    }
    fn wr32(&self, offset: u64, value: u32) {
        // SAFETY: as `rd32`.
        unsafe { core::ptr::write_volatile((self.va + offset) as *mut u32, value) }
    }
    fn rd8(&self, offset: u64) -> u8 {
        // SAFETY: as `rd32`.
        unsafe { core::ptr::read_volatile((self.va + offset) as *const u8) }
    }
    fn wr8(&self, offset: u64, value: u8) {
        // SAFETY: as `rd32`.
        unsafe { core::ptr::write_volatile((self.va + offset) as *mut u8, value) }
    }
}

/// Identify the interface a control area exposes, from its
/// `INTF_ID` register. Fails cleanly (`NotPresent`) on an absent
/// window (all-zero / all-ones reads with no TIS `DID_VID` behind
/// them) and on an interface type the PTP does not define — the
/// pre-#939 probe guessed CRB for undefined types.
pub(crate) fn identify<R: CrbRegs>(regs: &R) -> Result<TpmKind, TpmError> {
    let intf = regs.rd32(REG_INTERFACE_ID);
    if intf == 0 || intf == u32::MAX {
        // INTF_ID not implemented (or a floating bus): a TIS part
        // still proves itself through DID_VID.
        let did_vid = regs.rd32(REG_TIS_DID_VID);
        if did_vid == 0 || did_vid == u32::MAX {
            return Err(TpmError::NotPresent);
        }
        return Ok(TpmKind::Tis);
    }
    match intf & 0xF {
        0x0 => Ok(TpmKind::Crb),
        0xF => {
            // TIS-only. Require a sane DID_VID as well, so a garbage
            // control area cannot alias a TIS detection.
            let did_vid = regs.rd32(REG_TIS_DID_VID);
            if did_vid == 0 || did_vid == u32::MAX {
                return Err(TpmError::NotPresent);
            }
            Ok(TpmKind::Tis)
        }
        _ => Err(TpmError::NotPresent),
    }
}

/// CRB bring-up sequence (PTP §6.5, mirroring
/// `drivers/tpm/src/crb.rs::acquire_locality` + `program_buffers`):
/// request locality 0, wait for `LOC_STATE.locAssigned`, then
/// program the six buffer registers with the host-owned buffers.
pub(crate) fn crb_acquire_and_program<R: CrbRegs>(
    regs: &R,
    cmd_phys: u64,
    cmd_size: u32,
    rsp_phys: u64,
    rsp_size: u32,
    locality_deadline: narf_time::Deadline,
) -> Result<(), TpmError> {
    regs.wr32(REG_LOC_CTRL, LOC_CTRL_REQ_ACCESS);
    let granted = narf_scheduler::responsive_spin_until(
        || regs.rd32(REG_LOC_STATE) & LOC_STATE_LOC_ASSIGNED != 0,
        locality_deadline,
    );
    if !granted {
        return Err(TpmError::LocalityTimeout);
    }
    // The buffer registers are host-programmed (module doc): write
    // all six. Nothing is read back as a precondition — firmware
    // leaving them zero is the normal, expected state.
    regs.wr32(REG_CRB_CMD_SIZE, cmd_size);
    regs.wr32(REG_CRB_CMD_LO, cmd_phys as u32);
    regs.wr32(REG_CRB_CMD_HI, (cmd_phys >> 32) as u32);
    regs.wr32(REG_CRB_RSP_SIZE, rsp_size);
    regs.wr32(REG_CRB_RSP_LO, rsp_phys as u32);
    regs.wr32(REG_CRB_RSP_HI, (rsp_phys >> 32) as u32);
    Ok(())
}

#[derive(Debug)]
pub struct Tpm {
    base: u64,
    kind: TpmKind,
    /// Kernel VA of the ioremap'd control-area / locality window at
    /// `base`. All register access for this device goes through it.
    regs_va: u64,
    /// Host-owned CRB command buffer (CRB kind only). Allocated at
    /// probe and programmed into the `CMD_*` registers; kept alive
    /// for the device's lifetime.
    cmd_buf: Option<narf_io::DmaBuffer>,
    /// Host-owned CRB response buffer (CRB kind only).
    rsp_buf: Option<narf_io::DmaBuffer>,
    /// Device identity, cached at probe time by `query_info`
    /// (#941). Holds the unqueried defaults until `try_init_default`
    /// replaces them with the TPM's own GetCapability answer; a
    /// failed query leaves the defaults in place (identity is
    /// diagnostic, not a liveness gate — see `set_info`).
    info: IrqSafeSpinLock<TpmInfo>,
}

/// The identity `get_info` reports before the probe-time
/// GetCapability query lands (#941): the values the pre-#941 stub
/// returned, kept as the honest "not yet queried" default.
const UNQUERIED_INFO: TpmInfo = TpmInfo {
    manufacturer: 0,
    version: 2,
    spec_level: 159,
};

impl Tpm {
    /// Probe the TPM whose control area / locality window is at
    /// `base`. On success returns either a CRB or TIS implementation
    /// depending on what the silicon advertises.
    ///
    /// # Safety
    /// Caller asserts `base` is a 4 KiB MMIO window backed by a
    /// TPM 2.0 device.
    pub unsafe fn probe(base: u64) -> Result<Self, TpmError> {
        if !cfg!(target_arch = "x86_64") {
            // aarch64 CRB start methods are FF-A/SMC (TPM2 table
            // start methods 11/15), which have no transport in-tree
            // yet. Preserve the previous stub behaviour — probe
            // reports NotPresent — instead of touching a window we
            // cannot drive; see the module doc's scope note.
            return Err(TpmError::NotPresent);
        }
        // SAFETY: caller-asserted MMIO window; mapped Device
        // (uncached) for the device's lifetime.
        let mapped = unsafe {
            narf_memory::ioremap::ioremap(
                base,
                TPM_LOCALITY_LEN,
                narf_memory::ioremap::MmioAttrs::Device,
            )
        }
        .map_err(|_| TpmError::NotPresent)?;
        let regs = MmioCrbRegs { va: mapped.va() };
        let kind = identify(&regs)?;
        match kind {
            TpmKind::Tis => Ok(Self {
                base,
                kind,
                regs_va: mapped.va(),
                cmd_buf: None,
                rsp_buf: None,
                info: IrqSafeSpinLock::new(UNQUERIED_INFO),
            }),
            TpmKind::Crb => {
                // Host-owned buffers, programmed into the chip by
                // `crb_acquire_and_program` (the CRB contract).
                let cmd_buf =
                    narf_io::alloc_coherent(CRB_BUFFER_LEN, narf_lib::id::DomainId::DRIVER_0)
                        .map_err(|_| TpmError::BufferAlloc)?;
                let rsp_buf =
                    narf_io::alloc_coherent(CRB_BUFFER_LEN, narf_lib::id::DomainId::DRIVER_0)
                        .map_err(|_| TpmError::BufferAlloc)?;
                crb_acquire_and_program(
                    &regs,
                    cmd_buf.dma_addr().raw(),
                    CRB_BUFFER_LEN as u32,
                    rsp_buf.dma_addr().raw(),
                    CRB_BUFFER_LEN as u32,
                    // 750 ms wall-clock — TCG TPM 2.0 Library spec
                    // TIMEOUT_A covers the locality grant.
                    narf_time::Deadline::after_ms(750),
                )?;
                Ok(Self {
                    base,
                    kind,
                    regs_va: mapped.va(),
                    cmd_buf: Some(cmd_buf),
                    rsp_buf: Some(rsp_buf),
                    info: IrqSafeSpinLock::new(UNQUERIED_INFO),
                })
            }
        }
    }

    pub fn kind(&self) -> TpmKind {
        self.kind
    }
    pub fn base(&self) -> u64 {
        self.base
    }

    fn regs(&self) -> MmioCrbRegs {
        MmioCrbRegs { va: self.regs_va }
    }

    /// Submit a TPM2 command (caller-encoded wire form starting
    /// with the 10-byte `TPM2_RC_HEADER`). Returns the response
    /// bytes (header + body).
    ///
    /// CRB path: writes the command into the host-owned
    /// command buffer programmed at probe, sets CRB_CTRL_START.GO,
    /// polls until the start bit clears, reads the response from
    /// the host-owned response buffer.
    ///
    /// TIS path: writes byte-by-byte into the data FIFO with
    /// EXPECT/VALID flow control, sets STS.GO, drains the FIFO
    /// when DATA_AVAIL asserts.
    ///
    /// Async-shaped because the worst-case CRB / TIS poll budgets
    /// run up to 5 s on real silicon (RSA keygen, AMD PSP fTPM
    /// slow paths). A sync spin would block the executor for that
    /// entire window, starving every other task (FB drain, cursor
    /// pump, USB-HID supervisor, init). Each polling loop yields
    /// to the executor between MMIO reads so peers keep ticking.
    pub async fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        match self.kind {
            TpmKind::Crb => self.submit_crb(cmd).await,
            TpmKind::Tis => self.submit_tis(cmd).await,
        }
    }

    async fn submit_crb(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        let (Some(cmd_buf), Some(rsp_buf)) = (self.cmd_buf.as_ref(), self.rsp_buf.as_ref()) else {
            // CRB device without its probe-time buffers: cannot
            // happen through `probe`; fail rather than guess.
            return Err(TpmError::BadResponse);
        };
        submit_crb_over(
            &self.regs(),
            cmd_buf.cpu_mut_ptr::<u8>(),
            cmd_buf.len(),
            rsp_buf.cpu_mut_ptr::<u8>(),
            rsp_buf.len(),
            cmd,
        )
        .await
    }

    async fn submit_tis(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        submit_tis_over(&self.regs(), cmd).await
    }
}

/// The CRB submit sequence (PTP §6.5) over an abstract register
/// window: set CMD_READY, copy the command into the host-owned
/// command buffer, kick CTRL_START.GO, poll for completion
/// (CANCEL on timeout), then read the response out of the
/// host-owned response buffer. Factored out of `Tpm::submit_crb`
/// so kernel-test fixtures can drive the identical sequence
/// against a register-level device model (#946); the method is a
/// thin wrapper passing the device's probe-time DMA buffers.
///
/// # Safety
/// `cmd_buf` / `rsp_buf` must each point at `*_len` bytes of
/// memory the caller owns exclusively for the call's duration
/// and that the device side may read/write (production passes
/// its coherent DMA buffers).
pub(crate) async fn submit_crb_over<R: CrbRegs>(
    regs: &R,
    cmd_buf: *mut u8,
    cmd_buf_len: usize,
    rsp_buf: *mut u8,
    rsp_buf_len: usize,
    cmd: &[u8],
) -> Result<Vec<u8>, TpmError> {
    if cmd.is_empty() || cmd.len() > cmd_buf_len {
        return Err(TpmError::BadResponse);
    }
    // 1. Set CMD_READY.
    regs.wr32(REG_CRB_CTRL_REQ, CTRL_REQ_CMD_READY);
    // Wait until idle clears (TPM is in command-ready state).
    // 750 ms TIMEOUT_A. Timeout ignored, mirroring prior
    // behaviour — the GO write below will fail loudly if the
    // TPM never left idle.
    let _ = poll_yielding_until(
        || regs.rd32(REG_CRB_CTRL_STS) & CTRL_STS_TPM_IDLE == 0,
        narf_time::Deadline::after_ms(750),
    )
    .await;
    // 2. Write command into the host-owned command buffer.
    // SAFETY: the caller contract guarantees `cmd_buf` is valid
    // for `cmd_buf_len` bytes; `cmd.len()` was bounded by it
    // above.
    unsafe {
        for (i, b) in cmd.iter().enumerate() {
            core::ptr::write_volatile(cmd_buf.add(i), *b);
        }
    }
    // 3. Kick CRB_CTRL_START.GO.
    regs.wr32(REG_CRB_CTRL_START, CTRL_START_GO);
    // 4. Poll for start bit to self-clear (cmd complete).
    // 5 s wall-clock budget — TIMEOUT_C / TIMEOUT_D worst
    // cases (e.g. RSA keygen). Yields to the executor between
    // MMIO reads so peer tasks make progress during the wait.
    let done = poll_yielding_until(
        || regs.rd32(REG_CRB_CTRL_START) & CTRL_START_GO == 0,
        narf_time::Deadline::after_ms(5_000),
    )
    .await;
    if !done {
        // Cancel the wedged command before reporting, mirroring
        // `drivers/tpm/src/crb.rs::run_command`.
        regs.wr32(REG_CRB_CTRL_CANCEL, 1);
        return Err(TpmError::BusyTimeout);
    }
    if regs.rd32(REG_CRB_CTRL_STS) & CTRL_STS_ERROR != 0 {
        return Err(TpmError::BadResponse);
    }
    // 5. Read response from the host-owned response buffer. The
    //    size lives in bytes [2..6] of the response header
    //    (TPM2 §5.6 paragraphSize).
    let mut header = [0u8; 10];
    // SAFETY: the caller contract guarantees `rsp_buf` is valid
    // for `rsp_buf_len` bytes (4096 in production — at least the
    // 10-byte response header).
    unsafe {
        for (i, byte) in header.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(rsp_buf.add(i));
        }
    }
    let resp_size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    if resp_size < 10 || resp_size as usize > rsp_buf_len {
        return Err(TpmError::BadResponse);
    }
    let mut out = alloc::vec![0u8; resp_size as usize];
    for (i, byte) in out.iter_mut().enumerate() {
        // SAFETY: `resp_size <= rsp_buf_len` was checked above,
        // so every `i` addresses a byte inside the response
        // buffer.
        *byte = unsafe { core::ptr::read_volatile(rsp_buf.add(i)) };
    }
    Ok(out)
}

/// The TIS submit sequence (TIS v1.21) over an abstract register
/// window: request locality 0, assert STS.commandReady and observe
/// it set, push the command into DATA_FIFO under EXPECT flow
/// control, issue STS.GO, then drain the response FIFO while
/// DATA_AVAIL asserts. Factored out of `Tpm::submit_tis` for the
/// same fixture seam as [`submit_crb_over`] (#946).
pub(crate) async fn submit_tis_over<R: CrbRegs>(regs: &R, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
    // 1. Request locality 0.
    regs.wr8(REG_TIS_ACCESS, TIS_ACCESS_REQUEST_USE);
    // 750 ms TIMEOUT_A — locality acknowledgement.
    let _ = poll_yielding_until(
        || regs.rd8(REG_TIS_ACCESS) & TIS_ACCESS_ACTIVE != 0,
        narf_time::Deadline::after_ms(750),
    )
    .await;
    // 2. Assert commandReady (TIS §5.6). A powered-on TPM presents
    //    commandReady set, but the device clears it when it takes a
    //    command at GO; from the second command on, the host must
    //    re-assert it and observe it set before the FIFO writes, or
    //    the device drops the bytes and the command cannot complete
    //    (Linux `tpm_tis_ready`, called at the head of every send;
    //    the `drivers/tpm` reference flow documents the same step).
    //    The neighbouring polls ignore their timeouts, but this one
    //    cannot: proceeding without commandReady is exactly the
    //    byte-drop failure, so surface the typed timeout instead
    //    (#942).
    regs.wr8(REG_TIS_STS, TIS_STS_CMD_READY);
    let ready = poll_yielding_until(
        || regs.rd8(REG_TIS_STS) & TIS_STS_CMD_READY != 0,
        narf_time::Deadline::after_ms(750),
    )
    .await;
    if !ready {
        return Err(TpmError::BusyTimeout);
    }
    // 3. Write command into the FIFO.
    for b in cmd {
        // Wait for STS.EXPECT before each byte. 750 ms
        // TIMEOUT_A — typical sub-microsecond on real TPMs.
        let _ = poll_yielding_until(
            || regs.rd8(REG_TIS_STS) & TIS_STS_EXPECT != 0,
            narf_time::Deadline::after_ms(750),
        )
        .await;
        regs.wr8(REG_TIS_DATA_FIFO, *b);
    }
    // 4. Issue STS.GO.
    regs.wr8(REG_TIS_STS, TIS_STS_GO);
    // 5. Wait for STS.DATA_AVAIL. 5 s wall-clock budget —
    // TIMEOUT_C / TIMEOUT_D worst cases (RSA keygen etc.).
    let done = poll_yielding_until(
        || {
            let s = regs.rd8(REG_TIS_STS);
            s & (TIS_STS_VALID | TIS_STS_DATA_AVAIL) == (TIS_STS_VALID | TIS_STS_DATA_AVAIL)
        },
        narf_time::Deadline::after_ms(5_000),
    )
    .await;
    if !done {
        return Err(TpmError::BusyTimeout);
    }
    // 6. Drain FIFO until DATA_AVAIL clears.
    let mut out: Vec<u8> = Vec::new();
    for _ in 0..0x4000u32 {
        let s = regs.rd8(REG_TIS_STS);
        if s & TIS_STS_DATA_AVAIL == 0 {
            break;
        }
        let b = regs.rd8(REG_TIS_DATA_FIFO);
        out.push(b);
        if out.len() > 0x1000 {
            return Err(TpmError::BadResponse);
        }
    }
    Ok(out)
}

impl Tpm {
    /// `TPM2_GetRandom(bytes_requested)` — convenience wrapper.
    /// Returns up to `bytes` bytes of random data. The TPM may
    /// return fewer than requested.
    pub async fn tpm2_get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError> {
        // The frame comes from the canonical codec in `narf_tpm`
        // (composition, #934) — this transport no longer hand-rolls
        // its own copy of the GetRandom encoding.
        let req = narf_tpm::tpm2::get_random(bytes);
        let resp = self.submit(&req).await?;
        if resp.len() < 12 {
            return Err(TpmError::BadResponse);
        }
        // resp[0..2] = tag, resp[2..6] = size, resp[6..10] = rc,
        // resp[10..12] = randomBytes.size, resp[12..] = data.
        let n = u16::from_be_bytes([resp[10], resp[11]]) as usize;
        if 12 + n > resp.len() {
            return Err(TpmError::BadResponse);
        }
        Ok(resp[12..12 + n].to_vec())
    }
}

impl Tpm {
    /// Cache the identity `query_info` read from the device
    /// (#941). Called by `try_init_default` on the probe success
    /// path, before the device is registered, so `get_info`
    /// answers with the TPM's own values from first visibility.
    pub fn set_info(&self, info: TpmInfo) {
        *self.info.lock() = info;
    }
}

#[async_trait]
impl TpmDevice for Tpm {
    fn get_info(&self) -> TpmInfo {
        // The probe-time GetCapability answer (#941), or the
        // unqueried defaults if the query failed at probe.
        *self.info.lock()
    }

    async fn submit_raw(&self, cmd: &[u8]) -> Result<Vec<u8>, HighLevelTpmError> {
        self.submit(cmd).await.map_err(|e| match e {
            TpmError::NotPresent => HighLevelTpmError::NotPresent,
            TpmError::LocalityTimeout => HighLevelTpmError::LocalityTimeout,
            TpmError::BusyTimeout => HighLevelTpmError::BusyTimeout,
            TpmError::NoCommandBuffer => HighLevelTpmError::NoCommandBuffer,
            TpmError::BufferAlloc => HighLevelTpmError::HardwareError,
            TpmError::BadResponse => HighLevelTpmError::BadResponse,
        })
    }

    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, HighLevelTpmError> {
        self.tpm2_get_random(bytes)
            .await
            .map_err(|_| HighLevelTpmError::HardwareError)
    }

    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), HighLevelTpmError> {
        let req = build_pcr_extend_request(pcr, digest);
        let resp = self.submit_raw(&req).await?;
        // The old hand-rolled path discarded the response unread, so
        // even a well-framed TPM rejection (e.g. TPM_RC_VALUE) was
        // reported to measured boot as success. Validate it.
        validate_pcr_extend_response(&resp)
    }

    async fn read_pcr(&self, pcr: u32) -> Result<Vec<u8>, HighLevelTpmError> {
        // Canonical PCR_Read frame from `narf_tpm` (composition,
        // #934); this transport previously hand-rolled a third copy.
        let mut mask = [0u8; 3];
        if pcr < 24 {
            mask[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        let req = narf_tpm::tpm2::pcr_read(narf_tpm::tpm2::TPM_ALG_SHA256, &mask);

        let resp = self.submit_raw(&req).await?;
        // Structural parse of the spec framing (Part 3 §22.6) via
        // the canonical parser. This path previously sliced the
        // digest off the response tail, which coincides with the
        // framing only for a single-PCR response (#1065).
        let parser = narf_tpm::commands::ResponseParser::new(&resp)?;
        parser.parse_pcr_read()
    }
}

/// Build the `TPM2_PCR_Extend` request submitted by `extend_pcr`.
///
/// The frame comes from the canonical `narf_tpm` builder — the
/// `TPM_ST_SESSIONS` + `TPM_RS_PW` encoding of TPM 2.0 Part 3
/// §22.2, identical in structure to
/// `drivers/tpm/src/tpm2/commands.rs::pcr_extend`. A hand-rolled
/// copy here previously emitted `TPM_ST_NO_SESSIONS` with a zero
/// authorizationSize (and a commandSize hardcoded to a 32-byte
/// digest): a real TPM parses the digest count as 0 and rejects
/// the command with `TPM_RC_VALUE` (#937). Factored out of the
/// trait method so the kernel-test fixture
/// (`smoke_tpm_pcr_extend_request_bytes`) can pin the exact wire
/// bytes at this seam without hardware.
pub fn build_pcr_extend_request(pcr: u32, digest: &[u8]) -> Vec<u8> {
    narf_tpm::commands::CommandBuilder::pcr_extend(pcr, digest)
}

/// Validate a `TPM2_PCR_Extend` response: a complete header, a
/// declared size that fits the buffer, and a zero response code.
///
/// Malformed or truncated responses fail clean with a typed error
/// (`BadResponse` for framing, `Rc(..)` for a TPM rejection) —
/// never a panic, never silent success. Factored out so the
/// negative fixture (`smoke_tpm_pcr_extend_response_validation`)
/// can pin the behaviour without hardware.
pub fn validate_pcr_extend_response(resp: &[u8]) -> Result<(), HighLevelTpmError> {
    // Checks length >= 10 and maps a non-zero RC to a typed error.
    let _ = narf_tpm::commands::ResponseParser::new(resp)?;
    // ResponseParser guarantees the 10-byte header is present.
    let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    if size < 10 || size > resp.len() {
        return Err(HighLevelTpmError::BadResponse);
    }
    Ok(())
}

// ── Singleton ──────────────────────────────────────────────────────

static TPM: IrqSafeSpinLock<Option<Arc<Tpm>>> = IrqSafeSpinLock::new(None);

/// Firmware discovery for the default probe: the TPM2 ACPI table's
/// `control_address`, when the table publishes one we can drive.
///
/// Ensures the table is parsed first — `narf_acpi::parse_tpm2` has
/// no boot caller, so this initcall drives it from the RSDP the
/// boot-time SRAT parse cached (the parse is idempotent; a failure
/// just leaves the fixed-window fallback in place).
pub(crate) fn discovered_base() -> Option<u64> {
    if narf_acpi::tpm2_info().is_none() {
        if let Some(rsdp) = narf_acpi::cached_rsdp() {
            // SAFETY: `rsdp` comes from narf_acpi's own boot-parse
            // cache; parse_tpm2 walks the table chain through the
            // kernel phys map and only stores the parsed fields.
            let _ = unsafe { narf_acpi::parse_tpm2(rsdp) };
        }
    }
    let info = narf_acpi::tpm2_info()?;
    // Start methods publishing a memory-mapped control area at
    // `control_address`: 2 (ACPI start method), 6 (memory-mapped),
    // 7 (CRB), 8 (CRB with start method). At that address the
    // device's own INTF_ID decides CRB vs TIS in `probe`. Method 0
    // is NOT_ALLOWED; 11 (ARM SMC) and 15 (CRB with ARM FF-A) have
    // no transport in-tree and are deliberately not probed as MMIO.
    match info.start_method {
        2 | 6 | 7 | 8 if info.control_area_addr != 0 => Some(info.control_area_addr),
        _ => None,
    }
}

/// Best-effort initialisation: probe the TPM2-table control area
/// when firmware published one, else the fixed locality-0 window.
/// Used from the Stage::Subsys initcall — silently no-ops on hosts
/// without a TPM. (`pub(crate)` so the discovery-composition
/// fixture can drive the same decision the initcall drives, #946.)
///
/// On a successful probe the device is started (TPM2_Startup,
/// #942) and then published through two handles on the SAME
/// `Arc<Tpm>`: this crate's singleton (backing `with_tpm` /
/// `is_present` / `kind`) and `narf_tpm::registry` — the dispatch
/// target `frame::measure` consults for hardware PCR extends.
/// The same success path also composes the userspace surface
/// (#940): [`publish_userspace_surface`] installs a transport over
/// the registered device into the `drivers/tpm` bridges, which
/// instantiate `/dev/tpm0`, `/dev/tpmrm0` and
/// `/sys/class/tpm/tpm0`. Publication happens exactly once, on the
/// None→Some transition guarded by the early return above, so a
/// repeated initcall can never double-register the device.
pub fn try_init_default() {
    if !cfg!(target_arch = "x86_64") {
        return;
    }
    if TPM.lock().is_some() {
        return;
    }
    let base = discovered_base().unwrap_or(TPM_BASE_LOCALITY_0);
    // SAFETY: boot-time exclusive access; `base` is either the
    // firmware-published TPM control area or the architectural
    // locality-0 window, and `probe` maps it before touching it.
    if let Ok(dev) = unsafe { Tpm::probe(base) } {
        let dev = Arc::new(dev);
        // Lifecycle (#942): a powered-on TPM rejects every command
        // with TPM_RC_INITIALIZE until TPM2_Startup, and this is
        // the only production path that can submit it — measured
        // boot reaches the device through the registry at
        // Stage::Late and previously worked on the target laptops
        // only because firmware had started the TPM during POST.
        // Start the device here, before either handle is published,
        // so the registry contract ("a registered device is a
        // started device", narf-tpm spec §3.3) holds on firmware
        // paths that leave the TPM unstarted too. CLEAR is the
        // power-on form; a firmware-started TPM answers
        // TPM_RC_VALUE, which `TpmDevice::startup` folds into
        // success.
        //
        // The Stage::Subsys initcall runs synchronously on the BSP,
        // not inside an executor poll, no IrqSafeSpinLock is held
        // here (the TPM singleton guard above was dropped with its
        // statement), and the submit paths are self-waking register
        // polls — `block_on_spin` is the correct bridge, the same
        // one the fixture seams use to drive these submit paths.
        match narf_scheduler::block_on_spin(dev.startup(narf_tpm::StartupType::Clear)) {
            Ok(()) => {
                // Identity (#941): read the TPM's own
                // manufacturer / firmware / spec revision via
                // TPM2_GetCapability while the device is still
                // unpublished, so `get_info` answers with real
                // values from first visibility. A failed query is
                // not fatal — the device works without its
                // identity — so log it and keep the unqueried
                // defaults rather than withholding a started TPM.
                match narf_scheduler::block_on_spin(dev.query_info()) {
                    Ok(info) => dev.set_info(info),
                    Err(e) => {
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "  tpm: TPM2_GetCapability failed ({e:?}); device info defaults retained"
                        );
                    }
                }
                narf_tpm::registry::register(dev.clone());
                // Userspace publication (#940): the devfs/sysfs
                // bridges, composed onto the same started device
                // the registry now dispatches through.
                publish_userspace_surface(dev.clone());
                *TPM.lock() = Some(dev);
            }
            Err(e) => {
                // Probed but would not start: every command would
                // fail with TPM_RC_INITIALIZE, so publishing the
                // device would let measured boot claim a hardware
                // anchor that cannot extend. Publish neither handle
                // — `hardware_dispatch_active()` stays honest — and
                // say so on the console.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  tpm: TPM2_Startup failed ({e:?}); device not registered"
                );
            }
        }
    }
}

// ── Userspace publication (#940) ─────────────────────────────────────

/// Production `TpmTransport` for the `drivers/tpm` bridges: submits
/// through a registered `narf_tpm::TpmDevice`.
///
/// The bridge trait is synchronous (the devfs nodes submit inside
/// `FileOps::write`, mirroring Linux's tpm-dev write path) while
/// `TpmDevice::submit_raw` is async. The bridge point is
/// `block_on_spin`: the device's submit futures are self-waking
/// register polls (they never pend on an external waker — the same
/// property the Startup call in `try_init_default` relies on), and
/// the write path runs in syscall context, never inside an executor
/// poll. No lock is held across the call: `devfs_bridge` clones the
/// transport `Arc` out of its slot before invoking `submit`, the
/// response slot the node holds is its own per-fd lock taken only
/// after `submit` returns, and the registry device here is the
/// concrete `Tpm` (or a fixture adapter), whose submit path takes
/// no `IrqSafeSpinLock` across its polls.
struct RegistryTransport {
    dev: Arc<dyn narf_tpm::TpmDevice>,
}

impl narf_drivers_tpm::devfs_bridge::TpmTransport for RegistryTransport {
    fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()> {
        narf_scheduler::block_on_spin(self.dev.submit_raw(cmd)).map_err(|_| ())
    }
}

/// Publish the userspace TPM surface for a registered device:
/// `/dev/tpm0`, `/dev/tpmrm0` and `/sys/class/tpm/tpm0`, backed by
/// `dev` through the `drivers/tpm` bridges (#940).
///
/// Called exactly once per device, from `try_init_default`'s
/// success path — after TPM2_Startup and registry registration, so
/// the surface only ever exposes a started device (narf-tpm spec
/// §3.3). The bridges keep no second registry: the devfs nodes
/// submit through the transport slot this installs, and the sysfs
/// attributes query the same transport per read. The devfs nodes
/// are per-fd from here on — `sys_open` clones them through
/// `FileOps::open_instance`, so response state and the RM node's
/// transient-handle flush live and die with each fd.
pub fn publish_userspace_surface(dev: Arc<dyn narf_tpm::TpmDevice>) {
    let transport: Arc<dyn narf_drivers_tpm::devfs_bridge::TpmTransport> =
        Arc::new(RegistryTransport { dev });
    narf_drivers_tpm::devfs_bridge::register_transport(transport.clone());
    narf_drivers_tpm::devfs_bridge::register_dev_nodes();
    narf_drivers_tpm::sysfs_bridge::register_sysfs_tpm0(transport);
}

pub fn is_present() -> bool {
    TPM.lock().is_some()
}

pub fn kind() -> Option<TpmKind> {
    TPM.lock().as_ref().map(|t| t.kind())
}

pub fn with_tpm<R>(f: impl FnOnce(&Tpm) -> R) -> Option<R> {
    TPM.lock().as_ref().map(|t| f(t.as_ref()))
}

/// Test-only: drop the singleton handle. The `narf_tpm::registry`
/// registration made at probe time is a second handle on the same
/// device; fixtures that need the full no-TPM state must also call
/// `narf_tpm::registry::__reset_for_test`.
#[doc(hidden)]
pub fn __reset_for_test() {
    *TPM.lock() = None;
}
