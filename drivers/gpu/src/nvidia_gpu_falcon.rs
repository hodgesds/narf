//! NVIDIA Falcon CPU register-block codec — clean-room.
//!
//! Reference: **`open-gpu-doc/manuals/turing/tu102/dev_falcon_v4.ref.txt`**
//! and the corresponding files for Ampere / Ada (the Falcon v4
//! register layout is identical across Turing+).
//!
//! License note: open-gpu-doc is MIT-licensed top-to-bottom.
//! **No GPL Linux `nouveau` source consulted.**
//!
//! ## Falcon
//!
//! Every NVIDIA microcontroller embedded in a modern GPU is a
//! "Falcon" CPU — a small RISC core with 16 KiB of IMEM (code) +
//! 16 KiB of DMEM (data) and a register-mapped boot/control
//! surface. The host driver stages firmware into IMEM/DMEM,
//! programs the boot vector, and starts the core through the
//! `CPUCTL.STARTCPU` bit. Engines that use Falcons:
//!
//! - **PMU** — power management.
//! - **SEC2** — security engine (HDCP, sometimes signed-blob
//!   firmware verification).
//! - **GSP** — the GPU System Processor (Turing+ adds this; the
//!   host driver hands almost all chip control to it).
//! - **GPCCS** — graphics-pipeline microcontroller (per-GPC).
//!
//! The Falcon register block is identical at all of them; only
//! the BAR0 base offset shifts per engine. Stage-2 ships the
//! per-register field codec; per-engine bases are supplied by
//! the caller (the driver core knows which engine it's bringing
//! up).
//!
//! ## Block layout (Falcon v4)
//!
//! All offsets are relative to the engine's Falcon base. The
//! base for each engine is documented in its own register file:
//! the GSP Falcon lives at BAR0 `0x110000`, SEC2 at `0x840000`,
//! PMU at `0x10A000`, etc.

// ── Register offsets within a Falcon block ───────────────────────

/// `IRQSSET` — set bits in the IRQ status register.
pub const FALCON_IRQSSET: u32 = 0x0000_0000;
/// `IRQSCLR` — clear bits in the IRQ status register.
pub const FALCON_IRQSCLR: u32 = 0x0000_0004;
/// `IRQSTAT` — IRQ status, read-only.
pub const FALCON_IRQSTAT: u32 = 0x0000_0008;
/// `IRQMODE` — edge / level select per IRQ source.
pub const FALCON_IRQMODE: u32 = 0x0000_000C;
/// `IRQMSET` — set bits in the IRQ mask.
pub const FALCON_IRQMSET: u32 = 0x0000_0010;
/// `IRQMCLR` — clear bits in the IRQ mask.
pub const FALCON_IRQMCLR: u32 = 0x0000_0014;
/// `IRQMASK` — current IRQ mask, read-only.
pub const FALCON_IRQMASK: u32 = 0x0000_0018;
/// `IRQDEST` — IRQ destination select (host vs CPU).
pub const FALCON_IRQDEST: u32 = 0x0000_001C;
/// `MAILBOX0` — host ↔ Falcon scratch communication.
pub const FALCON_MAILBOX0: u32 = 0x0000_0040;
/// `MAILBOX1` — second mailbox slot.
pub const FALCON_MAILBOX1: u32 = 0x0000_0044;
/// `ITFEN` — IO interface enables.
pub const FALCON_ITFEN: u32 = 0x0000_0048;
/// `IDLESTATE` — read-only, asserted when the Falcon is idle.
pub const FALCON_IDLESTATE: u32 = 0x0000_004C;
/// `CURCTX` — current context (set by the host).
pub const FALCON_CURCTX: u32 = 0x0000_0050;
/// `NXTCTX` — next-context staging slot.
pub const FALCON_NXTCTX: u32 = 0x0000_0054;
/// `MAILBOX0_CLR` — clear-on-write mailbox 0 alias.
pub const FALCON_CPUCTL: u32 = 0x0000_0100;
/// `BOOTVEC` — first instruction the Falcon executes after
/// `CPUCTL.STARTCPU` is set.
pub const FALCON_BOOTVEC: u32 = 0x0000_0104;
/// `HWCFG` — read-only hardware configuration.
pub const FALCON_HWCFG: u32 = 0x0000_0108;
/// `DMACTL` — DMA control.
pub const FALCON_DMACTL: u32 = 0x0000_010C;
/// `DMATRFBASE` — DMA transfer base address.
pub const FALCON_DMATRFBASE: u32 = 0x0000_0110;
/// `DMATRFMOFFS` — DMA transfer memory offset.
pub const FALCON_DMATRFMOFFS: u32 = 0x0000_0114;
/// `DMATRFCMD` — DMA transfer command + length.
pub const FALCON_DMATRFCMD: u32 = 0x0000_0118;
/// `DMATRFFBOFFS` — DMA transfer framebuffer offset.
pub const FALCON_DMATRFFBOFFS: u32 = 0x0000_011C;
/// `DBGCTL` — debug control (host-only access).
pub const FALCON_DBGCTL: u32 = 0x0000_0120;
/// `IBRKPT` — instruction breakpoints (debug).
pub const FALCON_IBRKPT: u32 = 0x0000_0124;
/// `IMEMC` — IMEM (code RAM) command/address window.
pub const FALCON_IMEMC: u32 = 0x0000_0180;
/// `IMEMD` — IMEM data port.
pub const FALCON_IMEMD: u32 = 0x0000_0184;
/// `IMEMT` — IMEM tag port.
pub const FALCON_IMEMT: u32 = 0x0000_0188;
/// `DMEMC` — DMEM (data RAM) command/address window.
pub const FALCON_DMEMC: u32 = 0x0000_01C0;
/// `DMEMD` — DMEM data port.
pub const FALCON_DMEMD: u32 = 0x0000_01C4;
/// `BOOTROM_RESET` — reset the boot ROM-driven pre-IMEM
/// initialization sequence (Turing+ Falcons run a small boot ROM
/// before the host gets to load IMEM).
pub const FALCON_BOOTROM_RESET: u32 = 0x0000_01D0;

// ── CPUCTL field bits ────────────────────────────────────────────

/// `CPUCTL.IINVAL` — invalidate IMEM cache.
pub const CPUCTL_IINVAL: u32 = 1 << 0;
/// `CPUCTL.STARTCPU` — release the Falcon from reset and begin
/// executing at `BOOTVEC`.
pub const CPUCTL_STARTCPU: u32 = 1 << 1;
/// `CPUCTL.SRESET` — soft reset (clears IMEM/DMEM controllers
/// without clearing IMEM/DMEM contents).
pub const CPUCTL_SRESET: u32 = 1 << 2;
/// `CPUCTL.HRESET` — hard reset.
pub const CPUCTL_HRESET: u32 = 1 << 3;
/// `CPUCTL.HALTED` — read-only, asserted when the core has hit a
/// halt instruction.
pub const CPUCTL_HALTED: u32 = 1 << 4;
/// `CPUCTL.STOPPED` — read-only, core has hit a stop signal.
pub const CPUCTL_STOPPED: u32 = 1 << 5;

// ── IMEMC / DMEMC field codecs ───────────────────────────────────
//
// Both registers carry the same field layout:
//
//   bits 23: 0  blk + offset within the IMEM/DMEM (byte addr)
//   bit  24     AINCW    — auto-increment-on-write
//   bit  25     AINCR    — auto-increment-on-read
//   bit  28     SECURE   — IMEMC only: secure-load
//
// The host writes IMEMC with the staging address, then writes
// IMEMD repeatedly to push 32-bit words; auto-increment handles
// the address advance.

/// IMEM / DMEM command-register encoder. `addr` is the byte
/// address within the engine's IMEM / DMEM; `aincw` requests
/// auto-increment on write.
pub const fn imemc_dmemc(addr: u32, aincw: bool, aincr: bool) -> u32 {
    let mut v = addr & 0x00FF_FFFF;
    if aincw {
        v |= 1 << 24;
    }
    if aincr {
        v |= 1 << 25;
    }
    v
}

/// IMEMC variant that asks for a "secure" load (Falcon HS mode
/// signed-blob path). Used for SEC2 / GSP signed firmware.
pub const fn imemc_secure(addr: u32, aincw: bool) -> u32 {
    imemc_dmemc(addr, aincw, false) | (1 << 28)
}

// ── IMEM / DMEM staging helper ───────────────────────────────────

/// One programmed step of an IMEM staging sequence: write `cmd`
/// to `IMEMC` then `data` to `IMEMD`. The Stage-3 driver core
/// dispatches these through MMIO.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImemWrite {
    pub addr: u32,
    pub cmd: u32,
    pub data: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FalconError {
    /// IMEM payload longer than the documented 16 KiB IMEM size.
    PayloadTooLarge,
    /// Payload length isn't 4-byte aligned.
    UnalignedPayload,
}

/// Falcon v4 IMEM size — 16 KiB on every engine the spec
/// documents (the per-engine `HWCFG` register confirms at run
/// time, but 16 KiB is the conservative pre-check).
pub const FALCON_IMEM_SIZE: u32 = 16 * 1024;

/// Build the IMEMC + IMEMD writes that stage `payload` into IMEM
/// starting at byte address 0. Each entry is one (cmd, data)
/// pair the driver writes to `IMEMC` + `IMEMD` in order.
///
/// Auto-increment is set on the first entry so subsequent IMEMD
/// writes advance the staging pointer automatically.
pub fn build_imem_load(
    payload: &[u8],
    out: &mut [ImemWrite],
) -> Result<usize, FalconError> {
    if payload.len() > FALCON_IMEM_SIZE as usize {
        return Err(FalconError::PayloadTooLarge);
    }
    if payload.len() % 4 != 0 {
        return Err(FalconError::UnalignedPayload);
    }
    let n = payload.len() / 4;
    if out.len() < n {
        return Err(FalconError::PayloadTooLarge);
    }
    for i in 0..n {
        let addr = (i * 4) as u32;
        let cmd = if i == 0 {
            imemc_dmemc(addr, true, false)
        } else {
            // Subsequent writes ride the auto-increment.
            imemc_dmemc(0, true, false)
        };
        let word = u32::from_le_bytes([
            payload[i * 4],
            payload[i * 4 + 1],
            payload[i * 4 + 2],
            payload[i * 4 + 3],
        ]);
        out[i] = ImemWrite {
            addr,
            cmd,
            data: word,
        };
    }
    Ok(n)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_imemc_field_layout() -> TestResult {
        let v = imemc_dmemc(0x1234, true, false);
        if v & 0x00FF_FFFF != 0x1234 {
            return TestResult::Fail("address not in low 24 bits");
        }
        if v & (1 << 24) == 0 {
            return TestResult::Fail("AINCW not set");
        }
        if v & (1 << 25) != 0 {
            return TestResult::Fail("AINCR shouldn't be set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_falcon",
        smoke_imemc_field_layout
    );

    fn smoke_imemc_secure_bit() -> TestResult {
        let v = imemc_secure(0x100, true);
        if v & (1 << 28) == 0 {
            return TestResult::Fail("SECURE bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_falcon", smoke_imemc_secure_bit);

    fn smoke_imem_load_round_trip() -> TestResult {
        let payload: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut out = [ImemWrite {
            addr: 0,
            cmd: 0,
            data: 0,
        }; 2];
        let n = match build_imem_load(&payload, &mut out) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if n != 2 {
            return TestResult::Fail("payload should expand to 2 dwords");
        }
        if out[0].data != u32::from_le_bytes([1, 2, 3, 4]) {
            return TestResult::Fail("first dword wrong");
        }
        if out[1].data != u32::from_le_bytes([5, 6, 7, 8]) {
            return TestResult::Fail("second dword wrong");
        }
        // First entry programs full address; rest ride the
        // auto-increment with addr=0 in the cmd field.
        if out[0].cmd & 0x00FF_FFFF != 0 {
            return TestResult::Fail("first cmd should anchor at 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_falcon",
        smoke_imem_load_round_trip
    );

    fn smoke_imem_load_rejects_unaligned() -> TestResult {
        let mut out = [ImemWrite {
            addr: 0,
            cmd: 0,
            data: 0,
        }];
        match build_imem_load(&[1, 2, 3], &mut out) {
            Err(FalconError::UnalignedPayload) => TestResult::Pass,
            _ => TestResult::Fail("non-4-byte payload must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_falcon",
        smoke_imem_load_rejects_unaligned
    );
}
