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
//! ## Memory map
//!
//! Both TIS and CRB live in MMIO at the platform-fixed base
//! `0xFED4_0000` for locality 0 (PC Client PTP §5.2.1.1, "PCR
//! TPM Interface and physical address mapping"). Locality `n`
//! starts at `0xFED4_n000`; we always use locality 0.
//!
//! At offset `+0x30` is the CRB-specific block. The first 4 bytes
//! at offset `+0xF00` (`TPM_INTERFACE_ID_x`) tell us which
//! interface the silicon exposes — bits[3:0] = 0 means CRB,
//! 0xF means TIS-only. Stage cut: probe both, prefer CRB.
//!
//! ## CRB register layout (PTP §6.4.5)
//!
//! Locality 0 CRB block at `0xFED40000 + 0x40`:
//!
//! | offset (rel 0xFED40040) | name                    | width |
//! |-------------------------|-------------------------|-------|
//! | 0x00                    | LOC_CTRL                | u32   |
//! | 0x04                    | LOC_STS                 | u32   |
//! | 0x40                    | INTF_ID                 | u32   |
//! | 0x80                    | CTRL_REQ                | u32   |
//! | 0x84                    | CTRL_STS                | u32   |
//! | 0x88                    | CTRL_CANCEL             | u32   |
//! | 0x8C                    | CTRL_START              | u32   |
//! | 0x90                    | INT_ENABLE / STATUS     | u32×2 |
//! | 0x98                    | CMD_SIZE                | u32   |
//! | 0x9C                    | CMD_PA_LO               | u32   |
//! | 0xA0                    | CMD_PA_HI               | u32   |
//! | 0xA4                    | RSP_SIZE                | u32   |
//! | 0xA8                    | RSP_PA_LO               | u32   |
//! | 0xAC                    | RSP_PA_HI               | u32   |
//!
//! Stage cut: probe at `0xFED40000`, identify CRB vs TIS, expose
//! `submit(&[u8]) -> Vec<u8>` for callers that already speak the
//! TPM2 wire protocol. A `tpm2_get_random(bytes)` convenience is
//! built on top.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_tpm::{TpmDevice, TpmError as HighLevelTpmError, TpmInfo};

use narf_lib::sync::IrqSafeSpinLock;

/// Platform-fixed locality 0 base for TPM 2.0 (PC Client PTP §5.2.1.1).
pub const TPM_BASE_LOCALITY_0: u64 = 0xFED4_0000;

/// CRB interface identification offset (PTP §6.4.5). bits[3:0]:
///   0x0 = CRB  0xF = TIS only.
const REG_INTERFACE_ID: u64 = 0x30;

// CRB control block (offsets relative to `TPM_BASE_LOCALITY_0`).
const REG_LOC_CTRL: u64 = 0x40 + 0x00;
const REG_LOC_STS: u64 = 0x40 + 0x04;
const REG_CRB_CTRL_REQ: u64 = 0x40 + 0x80;
const REG_CRB_CTRL_STS: u64 = 0x40 + 0x84;
const REG_CRB_CTRL_START: u64 = 0x40 + 0x8C;
const REG_CRB_CMD_SIZE: u64 = 0x40 + 0x98;
const REG_CRB_CMD_LO: u64 = 0x40 + 0x9C;
const REG_CRB_CMD_HI: u64 = 0x40 + 0xA0;
const REG_CRB_RSP_SIZE: u64 = 0x40 + 0xA4;
const REG_CRB_RSP_LO: u64 = 0x40 + 0xA8;
const REG_CRB_RSP_HI: u64 = 0x40 + 0xAC;

const CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CTRL_STS_TPM_IDLE: u32 = 1 << 1;
const CTRL_START_GO: u32 = 1 << 0;

const LOC_CTRL_REQ_ACCESS: u32 = 1 << 0;
const LOC_STS_GRANTED: u32 = 1 << 0;

// TIS register layout (TIS v1.21 §5.6).
const REG_TIS_ACCESS: u64 = 0x00;
const REG_TIS_STS: u64 = 0x18;
const REG_TIS_DATA_FIFO: u64 = 0x24;
const REG_TIS_DID_VID: u64 = 0xF00;

const TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;
const TIS_ACCESS_ACTIVE: u8 = 1 << 5;
const TIS_STS_VALID: u8 = 1 << 7;
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
    /// CRB command/response buffer hasn't been published in cfg.
    NoCommandBuffer,
    BadResponse,
}

#[derive(Debug)]
pub struct Tpm {
    base: u64,
    kind: TpmKind,
    /// CRB command-buffer phys (read from CRB_CMD_PA_*).
    cmd_phys: u64,
    /// CRB command buffer max size (CRB_CMD_SIZE).
    cmd_size: u32,
    /// CRB response-buffer phys.
    rsp_phys: u64,
    rsp_size: u32,
}

impl Tpm {
    /// Probe the TPM at `base`. On success returns either a CRB
    /// or TIS implementation depending on what the silicon
    /// advertises.
    ///
    /// # Safety
    /// Caller asserts `base` is a 4 KiB MMIO window backed by a
    /// TPM 2.0 device.
    pub unsafe fn probe(base: u64) -> Result<Self, TpmError> {
        // SAFETY: caller-asserted MMIO window.
        let intf = unsafe { read32(base + REG_INTERFACE_ID) };
        if intf == 0 || intf == u32::MAX {
            // TIS-only fallback: check DID_VID at +0xF00.
            // SAFETY: same window, in-range.
            let did_vid = unsafe { read32(base + REG_TIS_DID_VID) };
            if did_vid == 0 || did_vid == u32::MAX {
                return Err(TpmError::NotPresent);
            }
            return Ok(Self {
                base,
                kind: TpmKind::Tis,
                cmd_phys: 0,
                cmd_size: 0,
                rsp_phys: 0,
                rsp_size: 0,
            });
        }
        let kind = match intf & 0xF {
            0x0 => TpmKind::Crb,
            0xF => TpmKind::Tis,
            _ => TpmKind::Crb, // future variants — assume CRB.
        };
        match kind {
            TpmKind::Crb => {
                // Request locality.
                // SAFETY: same.
                unsafe {
                    write32(base + REG_LOC_CTRL, LOC_CTRL_REQ_ACCESS);
                }
                // 750 ms wall-clock — TCG TPM 2.0 Library spec
                // TIMEOUT_A (short timeout) covers locality
                // grant. responsive_spin_until ticks sleep_pumps.
                let granted = narf_scheduler::responsive_spin_until(
                    // SAFETY: identity-mapped MMIO.
                    || unsafe { read32(base + REG_LOC_STS) } & LOC_STS_GRANTED != 0,
                    narf_time::Deadline::after_ms(750),
                );
                if !granted {
                    return Err(TpmError::LocalityTimeout);
                }
                // Read CRB command + response buffer phys + size.
                // SAFETY: same.
                let cmd_size = unsafe { read32(base + REG_CRB_CMD_SIZE) };
                // SAFETY: same.
                let cmd_lo = unsafe { read32(base + REG_CRB_CMD_LO) };
                // SAFETY: same.
                let cmd_hi = unsafe { read32(base + REG_CRB_CMD_HI) };
                let cmd_phys = ((cmd_hi as u64) << 32) | cmd_lo as u64;
                // SAFETY: same.
                let rsp_size = unsafe { read32(base + REG_CRB_RSP_SIZE) };
                // SAFETY: same.
                let rsp_lo = unsafe { read32(base + REG_CRB_RSP_LO) };
                // SAFETY: same.
                let rsp_hi = unsafe { read32(base + REG_CRB_RSP_HI) };
                let rsp_phys = ((rsp_hi as u64) << 32) | rsp_lo as u64;
                if cmd_phys == 0 || rsp_phys == 0 || cmd_size == 0 {
                    return Err(TpmError::NoCommandBuffer);
                }
                Ok(Self {
                    base,
                    kind: TpmKind::Crb,
                    cmd_phys,
                    cmd_size,
                    rsp_phys,
                    rsp_size,
                })
            }
            TpmKind::Tis => Ok(Self {
                base,
                kind: TpmKind::Tis,
                cmd_phys: 0,
                cmd_size: 0,
                rsp_phys: 0,
                rsp_size: 0,
            }),
        }
    }

    pub fn kind(&self) -> TpmKind {
        self.kind
    }
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Submit a TPM2 command (caller-encoded wire form starting
    /// with the 10-byte `TPM2_RC_HEADER`). Returns the response
    /// bytes (header + body).
    ///
    /// CRB path: writes the command into the publishable
    /// command-buffer phys, sets CRB_CTRL_START.GO, polls until
    /// the start bit clears, reads response from rsp buffer.
    ///
    /// TIS path: writes byte-by-byte into the data FIFO with
    /// EXPECT/VALID flow control, sets STS.GO, drains the FIFO
    /// when DATA_AVAIL asserts.
    pub fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        match self.kind {
            TpmKind::Crb => self.submit_crb(cmd),
            TpmKind::Tis => self.submit_tis(cmd),
        }
    }

    fn submit_crb(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        if cmd.is_empty() || cmd.len() > self.cmd_size as usize {
            return Err(TpmError::BadResponse);
        }
        // 1. Set CMD_READY.
        // SAFETY: identity-mapped MMIO window.
        unsafe {
            write32(self.base + REG_CRB_CTRL_REQ, CTRL_REQ_CMD_READY);
        }
        // Wait until idle clears (TPM is in command-ready state).
        // 750 ms TIMEOUT_A. Timeout ignored, mirroring prior
        // behaviour — the GO write below will fail loudly if the
        // TPM never left idle.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { read32(self.base + REG_CRB_CTRL_STS) } & CTRL_STS_TPM_IDLE == 0,
            narf_time::Deadline::after_ms(750),
        );
        // 2. Write command into the command buffer.
        // SAFETY: command buffer phys was published by firmware/ACPI.
        unsafe {
            for (i, b) in cmd.iter().enumerate() {
                core::ptr::write_volatile((self.cmd_phys + i as u64) as *mut u8, *b);
            }
        }
        // 3. Kick CRB_CTRL_START.GO.
        // SAFETY: same.
        unsafe {
            write32(self.base + REG_CRB_CTRL_START, CTRL_START_GO);
        }
        // 4. Poll for start bit to self-clear (cmd complete).
        // 5 s wall-clock budget — TIMEOUT_C / TIMEOUT_D worst
        // cases (e.g. RSA keygen). responsive_spin_until ticks
        // sleep_pumps.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { read32(self.base + REG_CRB_CTRL_START) } & CTRL_START_GO == 0,
            narf_time::Deadline::after_ms(5_000),
        );
        if !done {
            return Err(TpmError::BusyTimeout);
        }
        // 5. Read response. The size lives in bytes [2..6] of the
        //    response header (TPM2 §5.6 paragraphSize).
        let mut header = [0u8; 10];
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..10 {
                header[i] = core::ptr::read_volatile((self.rsp_phys + i as u64) as *const u8);
            }
        }
        let resp_size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
        if resp_size < 10 || resp_size > self.rsp_size {
            return Err(TpmError::BadResponse);
        }
        let mut out = alloc::vec![0u8; resp_size as usize];
        // SAFETY: same.
        for i in 0..resp_size as usize {
            out[i] = unsafe { core::ptr::read_volatile((self.rsp_phys + i as u64) as *const u8) };
        }
        Ok(out)
    }

    fn submit_tis(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        // 1. Request locality 0.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            write8(self.base + REG_TIS_ACCESS, TIS_ACCESS_REQUEST_USE);
        }
        // 750 ms TIMEOUT_A — locality acknowledgement.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { read8(self.base + REG_TIS_ACCESS) } & TIS_ACCESS_ACTIVE != 0,
            narf_time::Deadline::after_ms(750),
        );
        // 2. Write command into the FIFO.
        for b in cmd {
            // Wait for STS.EXPECT before each byte. 750 ms
            // TIMEOUT_A — typical sub-microsecond on real TPMs.
            let _ = narf_scheduler::responsive_spin_until(
                // SAFETY: identity-mapped MMIO.
                || unsafe { read8(self.base + REG_TIS_STS) } & TIS_STS_EXPECT != 0,
                narf_time::Deadline::after_ms(750),
            );
            // SAFETY: same.
            unsafe {
                write8(self.base + REG_TIS_DATA_FIFO, *b);
            }
        }
        // 3. Issue STS.GO.
        // SAFETY: same.
        unsafe {
            write8(self.base + REG_TIS_STS, TIS_STS_GO);
        }
        // 4. Wait for STS.DATA_AVAIL. 5 s wall-clock budget —
        // TIMEOUT_C / TIMEOUT_D worst cases (RSA keygen etc.).
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                let s = unsafe { read8(self.base + REG_TIS_STS) };
                s & (TIS_STS_VALID | TIS_STS_DATA_AVAIL) == (TIS_STS_VALID | TIS_STS_DATA_AVAIL)
            },
            narf_time::Deadline::after_ms(5_000),
        );
        if !done {
            return Err(TpmError::BusyTimeout);
        }
        // 5. Drain FIFO until DATA_AVAIL clears.
        let mut out: Vec<u8> = Vec::new();
        for _ in 0..0x4000u32 {
            // SAFETY: same.
            let s = unsafe { read8(self.base + REG_TIS_STS) };
            if s & TIS_STS_DATA_AVAIL == 0 {
                break;
            }
            // SAFETY: same.
            let b = unsafe { read8(self.base + REG_TIS_DATA_FIFO) };
            out.push(b);
            if out.len() > 0x1000 {
                return Err(TpmError::BadResponse);
            }
        }
        Ok(out)
    }

    /// `TPM2_GetRandom(bytes_requested)` — convenience wrapper.
    /// Returns up to `bytes` bytes of random data. The TPM may
    /// return fewer than requested.
    pub fn tpm2_get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError> {
        // TPM2 wire format §5.6:
        //   tag: u16 BE = 0x8001 (TPM_ST_NO_SESSIONS)
        //   commandSize: u32 BE
        //   commandCode: u32 BE = 0x0000017B (TPM2_CC_GetRandom)
        //   bytesRequested: u16 BE
        let mut req = Vec::with_capacity(12);
        req.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
        req.extend_from_slice(&12u32.to_be_bytes()); // size
        req.extend_from_slice(&0x0000_017Bu32.to_be_bytes()); // GetRandom
        req.extend_from_slice(&bytes.to_be_bytes());
        let resp = self.submit(&req)?;
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

#[async_trait]
impl TpmDevice for Tpm {
    fn get_info(&self) -> TpmInfo {
        TpmInfo {
            manufacturer: 0, // Should be read from hardware
            version: 2,
            spec_level: 159,
        }
    }

    async fn submit_raw(&self, cmd: &[u8]) -> Result<Vec<u8>, HighLevelTpmError> {
        self.submit(cmd).map_err(|e| match e {
            TpmError::NotPresent => HighLevelTpmError::NotPresent,
            TpmError::LocalityTimeout => HighLevelTpmError::LocalityTimeout,
            TpmError::BusyTimeout => HighLevelTpmError::BusyTimeout,
            TpmError::NoCommandBuffer => HighLevelTpmError::NoCommandBuffer,
            TpmError::BadResponse => HighLevelTpmError::BadResponse,
        })
    }

    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, HighLevelTpmError> {
        self.tpm2_get_random(bytes)
            .map_err(|_| HighLevelTpmError::HardwareError)
    }

    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), HighLevelTpmError> {
        // TPM2_CC_PCR_Extend: tag=0x8001, cc=0x00000182, pcrIndex=u32, auth=0, count=1, alg=SHA256, digest
        let mut req = Vec::new();
        req.extend_from_slice(&0x8001u16.to_be_bytes());
        req.extend_from_slice(&(10 + 4 + 4 + 4 + 2 + 32u32).to_be_bytes()); // size
        req.extend_from_slice(&0x0000_0182u32.to_be_bytes());
        req.extend_from_slice(&pcr.to_be_bytes());
        // authArea (empty session)
        req.extend_from_slice(&0u32.to_be_bytes());
        // digestCount = 1
        req.extend_from_slice(&1u32.to_be_bytes());
        // alg = SHA256 (0x000B)
        req.extend_from_slice(&0x000Bu16.to_be_bytes());
        req.extend_from_slice(digest);

        let _resp = self.submit_raw(&req).await?;
        Ok(())
    }

    async fn read_pcr(&self, pcr: u32) -> Result<Vec<u8>, HighLevelTpmError> {
        // TPM2_CC_PCR_Read: tag=0x8001, cc=0x0000017E
        let mut req = Vec::new();
        req.extend_from_slice(&0x8001u16.to_be_bytes());
        req.extend_from_slice(&20u32.to_be_bytes()); // header + pcrSelection
        req.extend_from_slice(&0x0000_017Eu32.to_be_bytes());
        // pcrSelection: count=1, alg=SHA256, bitmask
        req.extend_from_slice(&1u32.to_be_bytes());
        req.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
        req.push(3); // size of bitmask
        let mut mask = [0u8; 3];
        if pcr < 24 {
            mask[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        req.extend_from_slice(&mask);

        let resp = self.submit_raw(&req).await?;
        if resp.len() < 30 {
            return Err(HighLevelTpmError::BadResponse);
        }
        // The PCR value is at the end of the response for a single PCR read.
        Ok(resp[resp.len() - 32..].to_vec())
    }
}

// ── Singleton ──────────────────────────────────────────────────────

static TPM: IrqSafeSpinLock<Option<Tpm>> = IrqSafeSpinLock::new(None);

/// Best-effort initialisation against `TPM_BASE_LOCALITY_0`. Used
/// from the Stage::Subsys initcall — silently no-ops on hosts
/// without a TPM.
pub fn try_init_default() {
    if !cfg!(target_arch = "x86_64") {
        return;
    }
    if TPM.lock().is_some() {
        return;
    }
    // SAFETY: boot-time exclusive access; the locality-0 window
    // is identity-mapped on x86_64.
    if let Ok(dev) = unsafe { Tpm::probe(TPM_BASE_LOCALITY_0) } {
        *TPM.lock() = Some(dev);
    }
}

pub fn is_present() -> bool {
    TPM.lock().is_some()
}

pub fn kind() -> Option<TpmKind> {
    TPM.lock().as_ref().map(|t| t.kind())
}

pub fn with_tpm<R>(f: impl FnOnce(&Tpm) -> R) -> Option<R> {
    TPM.lock().as_ref().map(f)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *TPM.lock() = None;
}

// ── helpers ─────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn read32(phys: u64) -> u32 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(phys as *const u32) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write32(phys: u64, v: u32) {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe {
        core::ptr::write_volatile(phys as *mut u32, v);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read8(phys: u64) -> u8 {
    // SAFETY: same.
    unsafe { core::ptr::read_volatile(phys as *const u8) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write8(phys: u64, v: u8) {
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(phys as *mut u8, v);
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn read32(_phys: u64) -> u32 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn write32(_phys: u64, _v: u32) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read8(_phys: u64) -> u8 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn write8(_phys: u64, _v: u8) {}
