//! Copy Engine (CE) — ath10k's DMA primitive.
//!
//! A Copy Engine is a programmable DMA pipe with two rings:
//! a **source ring** (host → device) and a **destination ring**
//! (device → host). The host posts descriptors describing payload
//! buffers; the device walks the rings and DMAs the payloads.
//!
//! ath10k uses 8 CE pipes (12 on QCA99X0-class):
//!
//! | Pipe | Direction | Service              | Notes              |
//! |------|-----------|----------------------|--------------------|
//! | CE0  | host→dev  | HTC control          | TX-only            |
//! | CE1  | dev→host  | HTC control resp     | RX-only            |
//! | CE2  | dev→host  | WMI events           | RX-only            |
//! | CE3  | host→dev  | WMI cmds             | TX-only            |
//! | CE4  | host→dev  | HTT data TX          | bulk TX            |
//! | CE5  | dev→host  | HTT data RX          | bulk RX            |
//! | CE6  | bidir     | reserved / diag      | unused on most     |
//! | CE7  | bidir     | reserved / diag      | unused on most     |
//!
//! ## Stage 1 scope
//!
//! - Descriptor structs (`CeDesc` 8-byte, `CeDesc64` 16-byte).
//! - `RingConfig` describing one source / dest ring.
//! - `program_src_ring` / `program_dst_ring` — emit the SR_BASE / SR_SIZE
//!   / CTRL1 writes against a generic `Ath10kMmio` shim. The owned
//!   boot rings in `dma.rs` allocate coherent DMA32 backing storage.
//! - `halt_pipe` — drive a CE into the halted state for re-init.
//!
//! `boot.rs` drives CE0/CE1 BMI and CE7 diagnostics. Runtime WMI/HTT
//! queue ownership and per-AC frame dispatch remain to be implemented.
//!
//! ## References (Linux v6.10)
//!
//! - `drivers/net/wireless/ath/ath10k/ce.c` —
//!   `ath10k_ce_init_src_ring`, `ath10k_ce_init_dest_ring`,
//!   `ath10k_ce_alloc_src_ring`, `__ath10k_ce_send_revert`.
//! - `drivers/net/wireless/ath/ath10k/ce.h` — `struct ce_desc`,
//!   `struct ce_desc_64`, `CE_DESC_FLAGS_*`.
//! - `drivers/net/wireless/ath/ath10k/hw.h::ath10k_hw_ce_regs` —
//!   per-bank register layout.

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use super::hw::*;

// ── MMIO trait ─────────────────────────────────────────────────────
//
// Same pattern as iwlwifi's `IwlMmio` — abstract the BAR access so
// the CE setup code is unit-testable against a mock.

/// 32-bit MMIO surface against the ath10k BAR0. Real impl wraps
/// `narf_bus::MmioRegion`; tests use the in-memory mock.
pub trait Ath10kMmio {
    /// Current authority before descriptor/bounce publication. Pure models
    /// have no revocation source; the physical owner checks its real cap.
    fn authorized(&self) -> bool {
        true
    }
    /// Read a 32-bit register at the given BAR0-relative offset.
    fn read32(&mut self, offset: u64) -> u32;
    /// Write a 32-bit register at the given BAR0-relative offset.
    fn write32(&mut self, offset: u64, value: u32);
}

// ── Descriptor formats ─────────────────────────────────────────────

/// 8-byte CE descriptor — used by QCA988X / 6174 / 9377 / 9888 /
/// 9984. `ath10k/ce.h::struct ce_desc`.
///
/// Field layout (little-endian, packed):
///   - `addr`   : `__le32` — host phys (low 32 bits)
///   - `nbytes` : `__le16`
///   - `flags`  : `__le16` (`CE_DESC_FLAGS_*`)
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CeDesc {
    pub addr: u32,
    pub nbytes: u16,
    pub flags: u16,
}

impl CeDesc {
    /// Build a fresh 8-byte descriptor. Sets all 8 bytes — caller
    /// is responsible for `core::ptr::write_volatile`-ing it into
    /// the CE-owned ring memory.
    pub const fn new(addr: u32, nbytes: u16, flags: u16) -> Self {
        Self {
            addr,
            nbytes,
            flags,
        }
    }

    /// `true` iff the `GATHER` bit is set, meaning more descriptors
    /// chain after this one.
    pub fn is_gather(self) -> bool {
        self.flags & CE_DESC_FLAGS_GATHER != 0
    }
}

const _: () = assert!(core::mem::size_of::<CeDesc>() == CE_DESC_SIZE);

/// 16-byte CE descriptor — WCN3990 with 64-bit DMA addressing.
/// The PCIe families handled by this driver use `CeDesc`. `ath10k/ce.h::struct ce_desc_64`.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CeDesc64 {
    pub addr: u64,
    pub nbytes: u16,
    pub flags: u16,
    pub toeplitz_hash: u32,
}

impl CeDesc64 {
    pub const fn new(addr: u64, nbytes: u16, flags: u16) -> Self {
        Self {
            addr,
            nbytes,
            flags,
            toeplitz_hash: 0,
        }
    }
}

const _: () = assert!(core::mem::size_of::<CeDesc64>() == CE_DESC_SIZE_64);

// ── Ring config ────────────────────────────────────────────────────

/// One CE ring's host-visible config. Filled by upstream
/// (which owns the DMA-coherent ring allocation), then handed to
/// `program_src_ring` / `program_dst_ring` to actually program the
/// CE registers.
#[derive(Copy, Clone, Debug)]
pub struct RingConfig {
    /// Select the real per-family CE bank map.
    pub hw_rev: HwRev,
    /// CE pipe index 0..=7.
    pub pipe: u8,
    /// Host phys of the ring (lo 32 bits; ath10k only uses 35 bits
    /// of phys so the hi nibble lives in a separate register on the
    /// 64-bit-descriptor parts — Stage 1 lo-only is fine for QCA988X
    /// + QCA6174 / 9377 which use the 32-bit descriptor).
    pub base_phys_lo: u32,
    /// Number of entries — must be a power of two, 2..=8192.
    pub nentries: u32,
    /// Max single-descriptor byte count (used in CTRL1.DMAX_LENGTH).
    /// Linux defaults to 0x0E80 (3712 — leaves headroom under the
    /// 4 KiB DMA-bounce upper bound).
    pub dmax_length: u16,
    /// `true` iff host-side completion interrupts should be
    /// disabled for this ring. Set on the bulk-TX pipes once
    /// firmware-managed credit-flow is live.
    pub host_int_disabled: bool,
    /// `true` iff src ring should byte-swap payloads. Only matters
    /// on big-endian host platforms talking to little-endian device
    /// firmware; NARF runs little-endian everywhere so this is
    /// always false.
    pub src_byte_swap: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CeError {
    /// `pipe >= 8` (or `>= 12` on QCA99X0-class), or `nentries`
    /// isn't a power of two.
    BadConfig,
    /// CE halt-status didn't go true within the polling budget.
    HaltTimeout,
}

/// Validate a ring config. Cheap structural check used by the
/// callers and the smoke tests.
pub fn validate(cfg: &RingConfig) -> Result<(), CeError> {
    if cfg
        .hw_rev
        .registers()
        .and_then(|regs| regs.ce_base(cfg.pipe))
        .is_none()
    {
        return Err(CeError::BadConfig);
    }
    if !cfg.nentries.is_power_of_two() || cfg.nentries < 2 || cfg.nentries > 8192 {
        return Err(CeError::BadConfig);
    }
    if cfg.base_phys_lo & 7 != 0 || cfg.dmax_length == 0 {
        return Err(CeError::BadConfig);
    }
    Ok(())
}

/// Program a CE source ring. Mirrors
/// `ce.c::ath10k_ce_init_src_ring` — write SR_BASE, SR_SIZE, then
/// CTRL1 with the merged flags.
///
/// Pre-condition: ring is currently halted (so the descriptor base
/// can be safely re-pointed).
pub fn program_src_ring<M: Ath10kMmio>(mmio: &mut M, cfg: &RingConfig) -> Result<(), CeError> {
    validate(cfg)?;
    let base = cfg.hw_rev.registers().unwrap().ce_base(cfg.pipe).unwrap();

    // SR_BASE_LO + SR_SIZE.
    mmio.write32(base + ce_off::SR_BASE_LO, cfg.base_phys_lo);
    mmio.write32(base + ce_off::SR_SIZE, cfg.nentries);

    // CTRL1: source DMAX_LENGTH and byte swap. HOST_IE controls interrupts.
    let mut ctrl1 = mmio.read32(base + ce_off::CTRL1)
        & !(CE_CTRL1_DMAX_LENGTH_MASK | CE_CTRL1_SRC_RING_BYTE_SWAP_EN);
    ctrl1 |= cfg.dmax_length as u32;
    if cfg.src_byte_swap {
        ctrl1 |= CE_CTRL1_SRC_RING_BYTE_SWAP_EN;
    }
    mmio.write32(base + ce_off::CTRL1, ctrl1);
    program_interrupts(mmio, base, cfg.host_int_disabled);

    // Linux seeds software indices from the hardware. Do not reset a
    // producer index here: nonzero empty rings can survive a warm reset.

    // Ensure the writes are observable before the device starts
    // walking the ring.
    compiler_fence(Ordering::SeqCst);
    Ok(())
}

/// Program a CE destination ring. Same shape as
/// `program_src_ring`, but writes DR_BASE / DR_SIZE / DR_WR_INDEX.
pub fn program_dst_ring<M: Ath10kMmio>(mmio: &mut M, cfg: &RingConfig) -> Result<(), CeError> {
    validate(cfg)?;
    let base = cfg.hw_rev.registers().unwrap().ce_base(cfg.pipe).unwrap();

    mmio.write32(base + ce_off::DR_BASE_LO, cfg.base_phys_lo);
    mmio.write32(base + ce_off::DR_SIZE, cfg.nentries);

    // DMAX is a source-ring limit, not a destination-buffer size. Keep
    // source configuration intact when a pipe has both ring directions.
    let ctrl1 = mmio.read32(base + ce_off::CTRL1);
    mmio.write32(
        base + ce_off::CTRL1,
        ctrl1 & !CE_CTRL1_DST_RING_BYTE_SWAP_EN,
    );
    program_interrupts(mmio, base, cfg.host_int_disabled);

    compiler_fence(Ordering::SeqCst);
    Ok(())
}

/// Halt a CE pipe so its rings can be re-pointed safely.
/// `ce.c::ath10k_ce_halt_pipe`: write CE_CMD.HALT, then poll the
/// halt-status register at offset 0x14 until bit 0 reads 1.
pub fn halt_pipe<M: Ath10kMmio>(mmio: &mut M, hw_rev: HwRev, pipe: u8) -> Result<(), CeError> {
    let base = hw_rev
        .registers()
        .and_then(|regs| regs.ce_base(pipe))
        .ok_or(CeError::BadConfig)?;
    let cmd = mmio.read32(base + ce_off::CMD);
    mmio.write32(base + ce_off::CMD, cmd | CE_CMD_HALT);

    // Bounded spin — Linux uses a 1 ms budget but the chip halts in
    // a few cycles in practice. Cap at 1000 reads so a faulty mock
    // doesn't wedge a test.
    let mut gone = false;
    let halted = narf_scheduler::responsive_spin_until(
        || {
            let v = mmio.read32(base + CE_CMD_HALT_STATUS_OFFSET);
            if v == 0xFFFF_FFFF {
                gone = true;
                return true;
            }
            v & CE_CMD_HALT_STATUS_HALTED != 0
        },
        narf_time::Deadline::after_ms(10),
    );
    if halted && !gone {
        Ok(())
    } else {
        Err(CeError::HaltTimeout)
    }
}

fn program_interrupts<M: Ath10kMmio>(mmio: &mut M, base: u64, disabled: bool) {
    let enabled = mmio.read32(base + ce_off::HOST_IE);
    mmio.write32(
        base + ce_off::HOST_IE,
        if disabled { enabled & !1 } else { enabled | 1 },
    );
}

// ── Default per-pipe configs ───────────────────────────────────────
//
// `ath10k/ce.c::host_ce_config_wlan` (Linux v6.10 ~L1900..L2050)
// pins one config per CE. Reproduced here in a compact form so
// upstream Stage-1 callers can plug them into RingConfig.
//
// `nentries` follows Linux's defaults:
//   CE0 (HTC TX)      : 16
//   CE1 (HTC RX)      : 16
//   CE2 (WMI events)  : 32
//   CE3 (WMI cmds)    : 32
//   CE4 (HTT TX bulk) : 256
//   CE5 (HTT RX bulk) : 512
//   CE6/CE7           : 0 (unused — caller skips)

/// Direction + default ring depth for one of the 8 standard ath10k CE
/// pipes. Sourced from Linux's `host_ce_config_wlan`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PipeDefault {
    pub pipe: u8,
    pub is_src: bool,
    pub nentries: u32,
    pub service: &'static str,
}

/// Default ath10k CE pipe configuration (5 active + 1 RX dest for
/// HTT). The pure-data table lets Stage 1 unit-test the
/// "build N ring configs" path without touching MMIO.
pub const DEFAULT_PIPE_CONFIG: &[PipeDefault] = &[
    PipeDefault {
        pipe: 0,
        is_src: true,
        nentries: 16,
        service: "htc-ctrl-tx",
    },
    PipeDefault {
        pipe: 1,
        is_src: false,
        nentries: 512,
        service: "htc-ctrl-rx",
    },
    PipeDefault {
        pipe: 2,
        is_src: false,
        nentries: 128,
        service: "wmi-events",
    },
    PipeDefault {
        pipe: 3,
        is_src: true,
        nentries: 32,
        service: "wmi-cmds",
    },
    PipeDefault {
        pipe: 4,
        is_src: true,
        nentries: 8192,
        service: "htt-tx",
    },
    PipeDefault {
        pipe: 5,
        is_src: false,
        nentries: 512,
        service: "htt-rx",
    },
];
