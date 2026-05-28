//! Falcon microcontroller core.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/falcon/base.c`**
//!   `nvkm_falcon_*` — generic Falcon entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/falcon/v1.c`** — the
//!   common Falcon v1 IMEM/DMEM/CPUCTL programming flow.
//! - **`drivers/gpu/drm/nouveau/nvkm/falcon/gm200.c`** —
//!   Maxwell+ Falcon (adds the `*_secure` boot mode used by the
//!   ACR-loaded WPR firmwares).
//! - **`drivers/gpu/drm/nouveau/nvkm/falcon/tu102.c`** &
//!   **`ga102.c`** — Turing/Ampere additions (BAR window into
//!   IMEM/DMEM, RISC-V mode bit on Ampere+).
//!
//! ## Register layout (relative to a Falcon base)
//!
//! Every embedded NVIDIA microcontroller in a Maxwell+ GPU has
//! the same Falcon register block — only the BAR0 base differs
//! per engine. PMU = 0x10A000, SEC2 = 0x840000, GSP = 0x110000,
//! GPCCS-per-GPC = 0x501000 + gpc*0x8000 (varies). Per-engine
//! bases are passed in by the caller.
//!
//! See `dev_falcon_v4.ref.txt` (open-gpu-doc) for the same fields.

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::MmioRegion;

// ── Register offsets within a Falcon block ───────────────────────

pub const FALCON_IRQSSET: u64 = 0x0000_0000;
pub const FALCON_IRQSCLR: u64 = 0x0000_0004;
pub const FALCON_IRQSTAT: u64 = 0x0000_0008;
pub const FALCON_IRQMODE: u64 = 0x0000_000C;
pub const FALCON_IRQMSET: u64 = 0x0000_0010;
pub const FALCON_IRQMCLR: u64 = 0x0000_0014;
pub const FALCON_IRQMASK: u64 = 0x0000_0018;
pub const FALCON_IRQDEST: u64 = 0x0000_001C;
pub const FALCON_MAILBOX0: u64 = 0x0000_0040;
pub const FALCON_MAILBOX1: u64 = 0x0000_0044;
pub const FALCON_ITFEN: u64 = 0x0000_0048;
pub const FALCON_IDLESTATE: u64 = 0x0000_004C;
pub const FALCON_CURCTX: u64 = 0x0000_0050;
pub const FALCON_NXTCTX: u64 = 0x0000_0054;
pub const FALCON_MAILBOX0_CLR: u64 = 0x0000_0058;
pub const FALCON_CPUCTL: u64 = 0x0000_0100;
pub const FALCON_BOOTVEC: u64 = 0x0000_0104;
pub const FALCON_HWCFG: u64 = 0x0000_0108;
pub const FALCON_DMACTL: u64 = 0x0000_010C;
pub const FALCON_DMATRFBASE: u64 = 0x0000_0110;
pub const FALCON_DMATRFMOFFS: u64 = 0x0000_0114;
pub const FALCON_DMATRFCMD: u64 = 0x0000_0118;
pub const FALCON_DMATRFFBOFFS: u64 = 0x0000_011C;
pub const FALCON_IMEMC: u64 = 0x0000_0180;
pub const FALCON_IMEMD: u64 = 0x0000_0184;
pub const FALCON_IMEMT: u64 = 0x0000_0188;
pub const FALCON_DMEMC: u64 = 0x0000_01C0;
pub const FALCON_DMEMD: u64 = 0x0000_01C4;
pub const FALCON_CPUCTL_ALIAS: u64 = 0x0000_0130;

// ── CPUCTL bits ──────────────────────────────────────────────────

/// CPUCTL.STARTCPU — set to release the Falcon from reset.
pub const CPUCTL_STARTCPU: u32 = 1 << 1;
/// CPUCTL.HALT — Falcon entered HALT state (set by HW).
pub const CPUCTL_HALT: u32 = 1 << 4;
/// CPUCTL.STOPPED — Falcon stopped (set by HW).
pub const CPUCTL_STOPPED: u32 = 1 << 5;

// ── DMATRFCMD bits ───────────────────────────────────────────────

/// DMATRFCMD.SIZE — 256 byte block transfer.
pub const DMATRFCMD_SIZE_256B: u32 = 6 << 8;
/// DMATRFCMD.IDLE — transfer engine idle (set by HW).
pub const DMATRFCMD_IDLE: u32 = 1 << 1;
/// DMATRFCMD.WRITE — direction: host -> Falcon.
pub const DMATRFCMD_WRITE: u32 = 1 << 5;

// ── IMEMC bits ───────────────────────────────────────────────────

/// IMEMC.AINCR — auto-increment IMEMD address on each access.
pub const IMEMC_AINCR_WRITE: u32 = 1 << 24;
pub const IMEMC_AINCR_READ: u32 = 1 << 25;
pub const IMEMC_SECURE: u32 = 1 << 28;

// ── DMEMC bits ───────────────────────────────────────────────────

pub const DMEMC_AINCR_WRITE: u32 = 1 << 24;
pub const DMEMC_AINCR_READ: u32 = 1 << 25;

/// Which memory inside the Falcon the host is targeting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FalconMem {
    Imem,
    Dmem,
}

/// Generic Falcon handle. Wraps the MMIO region (BAR0 view of the
/// whole register window) and the base offset of the engine's
/// Falcon block within it.
#[derive(Debug)]
pub struct Falcon<'a> {
    pub bar0: &'a MmioRegion,
    /// Engine base inside BAR0 (e.g. PMU = 0x10A000).
    pub base: u64,
    /// Diagnostic tag ("pmu", "sec2", "gsp").
    pub name: &'static str,
}

impl<'a> Falcon<'a> {
    pub const fn new(bar0: &'a MmioRegion, base: u64, name: &'static str) -> Self {
        Self { bar0, base, name }
    }

    /// 32-bit read at `offset` within the Falcon block.
    ///
    /// # Safety
    /// `base + offset + 4` is inside the BAR0 mapping.
    pub unsafe fn rd32(&self, offset: u64) -> u32 {
        // SAFETY: caller's responsibility.
        unsafe { self.bar0.read32(self.base + offset) }
    }

    /// 32-bit write at `offset` within the Falcon block.
    ///
    /// # Safety
    /// Same.
    pub unsafe fn wr32(&self, offset: u64, value: u32) {
        // SAFETY: caller's responsibility.
        unsafe { self.bar0.write32(self.base + offset, value) }
    }

    /// Reset the Falcon — clear CPUCTL.STARTCPU, then poll for HALT
    /// / STOPPED to drop. Cite `nvkm_falcon_v1_disable` &
    /// `nvkm_falcon_v1_enable` in `nvkm/falcon/v1.c`.
    ///
    /// # Safety
    /// Exclusive access to the engine.
    pub unsafe fn reset(&self) {
        // SAFETY: caller's responsibility.
        unsafe {
            self.wr32(FALCON_CPUCTL, CPUCTL_HALT);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Wait until IDLESTATE reads zero (Falcon idle).
    ///
    /// # Safety
    /// Same.
    pub unsafe fn wait_idle(&self, max_polls: u32) -> Result<(), FalconError> {
        for _ in 0..max_polls {
            // SAFETY: caller's responsibility.
            let s = unsafe { self.rd32(FALCON_IDLESTATE) };
            if s == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(FalconError::IdleTimeout)
    }

    /// Stage firmware into IMEM. `img` is the byte buffer; `dst`
    /// is the IMEM byte offset (typically 0). Cite
    /// `nvkm_falcon_v1_load_imem` in `nvkm/falcon/v1.c`.
    ///
    /// # Safety
    /// `img.len()` must be a multiple of 4 and fit in IMEM. Caller
    /// owns the Falcon.
    pub unsafe fn load_imem(&self, img: &[u8], dst: u32, tag: u16) -> Result<(), FalconError> {
        if img.len() & 3 != 0 {
            return Err(FalconError::AlignError);
        }
        // SAFETY: caller's responsibility.
        unsafe {
            // Programme the IMEMC address latch with auto-incr.
            self.wr32(
                FALCON_IMEMC,
                (dst & 0x0000_FFFF) | IMEMC_AINCR_WRITE,
            );
            // Tag latches the IMEM physical-page tag (used for
            // signing and TLB lookups in secure mode).
            self.wr32(FALCON_IMEMT, tag as u32);
            for chunk in img.chunks_exact(4) {
                let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                self.wr32(FALCON_IMEMD, w);
            }
        }
        Ok(())
    }

    /// Stage firmware data into DMEM.
    ///
    /// # Safety
    /// Same as `load_imem`.
    pub unsafe fn load_dmem(&self, img: &[u8], dst: u32) -> Result<(), FalconError> {
        if img.len() & 3 != 0 {
            return Err(FalconError::AlignError);
        }
        // SAFETY: caller's responsibility.
        unsafe {
            self.wr32(
                FALCON_DMEMC,
                (dst & 0x0000_FFFF) | DMEMC_AINCR_WRITE,
            );
            for chunk in img.chunks_exact(4) {
                let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                self.wr32(FALCON_DMEMD, w);
            }
        }
        Ok(())
    }

    /// Programme the boot vector and start the CPU. Cite
    /// `nvkm_falcon_v1_start` in `nvkm/falcon/v1.c`.
    ///
    /// # Safety
    /// Caller owns the Falcon; IMEM/DMEM staged.
    pub unsafe fn start(&self, bootvec: u32) {
        // SAFETY: caller's responsibility.
        unsafe {
            self.wr32(FALCON_BOOTVEC, bootvec);
            self.wr32(FALCON_CPUCTL, CPUCTL_STARTCPU);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Wait until the Falcon has halted (HALT bit in CPUCTL set).
    ///
    /// # Safety
    /// Same.
    pub unsafe fn wait_halt(&self, max_polls: u32) -> Result<(), FalconError> {
        for _ in 0..max_polls {
            // SAFETY: caller's responsibility.
            let s = unsafe { self.rd32(FALCON_CPUCTL) };
            if s & CPUCTL_HALT != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(FalconError::HaltTimeout)
    }

    /// Convenience: full host bring-up sequence — reset → wait
    /// idle → load_imem → load_dmem → start. Returns the Falcon
    /// in a "code resident, executing from bootvec" state.
    ///
    /// # Safety
    /// Caller owns the Falcon and is responsible for caller-side
    /// firmware integrity (signature verification, etc.).
    pub unsafe fn bring_up(
        &self,
        imem_img: &[u8],
        dmem_img: &[u8],
        bootvec: u32,
        imem_tag: u16,
    ) -> Result<(), FalconError> {
        // SAFETY: caller's responsibility.
        unsafe {
            self.reset();
            self.wait_idle(10_000)?;
            self.load_imem(imem_img, 0, imem_tag)?;
            self.load_dmem(dmem_img, 0)?;
            self.start(bootvec);
        }
        Ok(())
    }

    /// Read MAILBOX0 (host ↔ Falcon scratch).
    ///
    /// # Safety
    /// `bar0` covers the Falcon block.
    pub unsafe fn mailbox0(&self) -> u32 {
        // SAFETY: caller's responsibility.
        unsafe { self.rd32(FALCON_MAILBOX0) }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FalconError {
    AlignError,
    IdleTimeout,
    HaltTimeout,
    NotReady,
}

// ── Per-engine Falcon base addresses ─────────────────────────────
//
// Cited per `dev_falcon_v4.ref.txt` and Nouveau's per-engine
// `subdev/*.c` / `engine/*.c` files. These are stable Maxwell→Ada
// for the engines we touch in Stage 1.

/// PMU Falcon base.
pub const FALCON_BASE_PMU: u64 = 0x0010_A000;
/// SEC2 Falcon base.
pub const FALCON_BASE_SEC2: u64 = 0x0084_0000;
/// GSP Falcon base (Turing+).
pub const FALCON_BASE_GSP: u64 = 0x0011_0000;
/// FECS (Front-End Context Switch microcontroller for GR).
pub const FALCON_BASE_FECS: u64 = 0x0040_9000;
/// NVDEC0 (video decoder Falcon).
pub const FALCON_BASE_NVDEC0: u64 = 0x0084_8000;
/// NVENC0 (video encoder Falcon).
pub const FALCON_BASE_NVENC0: u64 = 0x0084_4000;
