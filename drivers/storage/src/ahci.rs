//! AHCI HBA driver (Intel ICH9 + compatible).
//!
//! Spec: AHCI 1.3.1 — Serial ATA Advanced Host Controller Interface.
//! <https://www.intel.com/content/www/us/en/io/serial-ata/serial-ata-ahci-spec-rev1-3-1.html>
//!
//! Interrupt model (this revision):
//! - HBA `GHC.IE` (bit 1) is the master "deliver any interrupt" gate
//!   (§3.1.2). When clear no port-level IRQ ever leaves the HBA.
//! - Per-port `PORT_IE` (offset +0x14) selects which events on a port
//!   raise the port's bit in HBA `IS` (§3.3.6). We unmask the
//!   completion-bearing events: D2H Register FIS (bit 0), PIO Setup
//!   (bit 1), DMA Setup (bit 2), plus Task File Error (bit 30) so a
//!   failing command doesn't sit unnoticed.
//! - The ISR walks HBA `IS` to find ports with pending events
//!   (§3.1.3), drains each port's `PORT_IS` (W1C), then clears the
//!   port bit in HBA `IS` (also W1C).
//! - `narf_interrupts::on_irq` (called from the registered sync
//!   handler via the dispatch table) bumps a per-vector `fire_count`
//!   and wakes any task awaiting `wait_for_irq`. Async I/O paths
//!   (`*_async`) construct the wait future BEFORE writing PORT_CI so
//!   they cannot race the IRQ.
//!
//! QEMU's q35 AHCI controller is at `8086:2922` (00:1f.2 by default);
//! ICH9 family.
//!
//! HBA register layout (BAR5 = ABAR, MMIO):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x00    | CAP  | HBA Capabilities                  |
//! | 0x04    | GHC  | Global Host Control               |
//! | 0x08    | IS   | Interrupt Status                  |
//! | 0x0C    | PI   | Ports Implemented (bitmap)        |
//! | 0x10    | VS   | AHCI Version                      |
//! | 0x100   | port[0]                                |
//! | 0x180   | port[1]                                |
//! | 0x200   | port[2]                                |
//! | ...                                              |
//!
//! Per-port (offset = 0x100 + 0x80 * n):
//!
//! | offset  | name  | description                     |
//! |---------|-------|---------------------------------|
//! | +0x00   | CLB   | Command List Base Low           |
//! | +0x04   | CLBU  | Command List Base High          |
//! | +0x08   | FB    | FIS Base Low                    |
//! | +0x0C   | FBU   | FIS Base High                   |
//! | +0x10   | IS    | Interrupt Status                |
//! | +0x14   | IE    | Interrupt Enable                |
//! | +0x18   | CMD   | Command and Status              |
//! | +0x20   | TFD   | Task File Data                  |
//! | +0x24   | SIG   | Signature (after spin-up)       |
//! | +0x28   | SSTS  | SATA Status                     |
//! | +0x2C   | SCTL  | SATA Control                    |
//! | +0x30   | SERR  | SATA Error                      |
//! | +0x34   | SACT  | SATA Active                     |
//! | +0x38   | CI    | Command Issue                   |

use core::sync::atomic::{compiler_fence, AtomicU8, AtomicUsize, Ordering};

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};

/// Persistent shared scratch for the per-LBA AHCI paths (audit
/// #3: pre-fix every read/write/identify did
/// `alloc_coherent(4096)` and dropped it at function end — under
/// AMD-Vi the freed page could be reused while the controller
/// still had a delayed DMA write in flight). Single global
/// 4 KiB shared because all callers serialize on the per-port
/// busy register; concurrent multi-port AHCI (rare) would still
/// be correct under this lock but slower than per-port scratches.
/// Layout matches the per-call buffers: cmd_list@0x000,
/// fis_recv@0x400, cmd_tbl@0x500, data_buf@0x600 (offsets used
/// by every path below).
static AHCI_SCRATCH: narf_lib::sync::IrqSafeSpinLock<Option<DmaBuffer>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn with_ahci_scratch<R>(f: impl FnOnce(&DmaBuffer) -> R) -> Option<R> {
    let mut g = AHCI_SCRATCH.lock();
    if g.is_none() {
        *g = alloc_coherent(4096, DomainId::DRIVER_0).ok();
    }
    g.as_ref().map(f)
}

/// Return the persistent scratch phys address, lazily allocating
/// on first use. Returns 0 on alloc failure (caller checks).
/// Thin wrapper around the locked accessor that gives back just
/// the `phys` so the caller's existing buffer-access code (which
/// works in raw u64 offsets) doesn't need to nest in a closure.
/// SAFETY: callers serialise on per-port busy registers; the
/// returned phys is stable for the controller's lifetime.
fn ahci_scratch_phys() -> u64 {
    with_ahci_scratch(|b| b.phys_addr().raw()).unwrap_or(0)
}
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

pub const AHCI_VENDOR: u16 = 0x8086;
/// QEMU q35 ICH9 AHCI.
pub const AHCI_ICH9_DEV: u16 = 0x2922;
/// Real silicon ICH10 AHCI.
pub const AHCI_ICH10_DEV: u16 = 0x3A22;

const ABAR_BAR: u8 = 5;

const HBA_CAP: u64 = 0x00;
const HBA_GHC: u64 = 0x04;
/// HBA Interrupt Status — one bit per port; W1C (AHCI 1.3.1 §3.1.3).
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0C;
const HBA_VS: u64 = 0x10;

// GHC bits.
const GHC_HR: u32 = 1 << 0; // HBA Reset
/// GHC.IE — Interrupt Enable, master gate (AHCI 1.3.1 §3.1.2).
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31; // AHCI Enable

// Per-port offsets.
const PORT_BASE_OFF: u64 = 0x100;
const PORT_STRIDE: u64 = 0x80;

/// PORT_IS — port interrupt status; W1C (AHCI 1.3.1 §3.3.5).
const PORT_IS: u64 = 0x10;
/// PORT_IE — port interrupt enable mask (AHCI 1.3.1 §3.3.6).
const PORT_IE: u64 = 0x14;
const PORT_CMD: u64 = 0x18;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
/// PORT_SCTL — SATA Control (SCR2): DET field at bits[3:0] (AHCI 1.3.1 §3.3.11).
const PORT_SCTL: u64 = 0x2C;
const PORT_SERR: u64 = 0x30;
/// PORT_CI — Command Issue, written to launch a command (§3.3.14).
const PORT_CI: u64 = 0x38;

/// PORT_SSTS.DET field values (AHCI 1.3.1 §3.3.10 / SATA 3.x §8.1):
///   0 — no device, no PHY.
///   1 — device present but PHY comms not established.
///   3 — device present and PHY comms established (normal run).
pub const SSTS_DET_NO_DEVICE: u32 = 0;
pub const SSTS_DET_NO_COMM: u32 = 1;
pub const SSTS_DET_PRESENT: u32 = 3; // link-up

/// PORT_SSTS.IPM field values (Interface Power Management, bits[11:8]):
///   0 — not present / slumber.
///   1 — active.
///   2 — partial power.
pub const SSTS_IPM_NOT_PRESENT: u32 = 0;
pub const SSTS_IPM_ACTIVE: u32 = 1;

/// Decode PORT_SSTS into `(det, ipm)` nibbles.
#[inline]
pub fn ssts_decode(ssts: u32) -> (u32, u32) {
    (ssts & 0x0F, (ssts >> 8) & 0x0F)
}

// PORT_IE / PORT_IS event bits (AHCI 1.3.1 §3.3.6).
const PIE_D2H_REG_FIS: u32 = 1 << 0; // Device-to-Host Register FIS Interrupt
const PIE_PIO_SETUP_FIS: u32 = 1 << 1; // PIO Setup FIS Interrupt
const PIE_DMA_SETUP_FIS: u32 = 1 << 2; // DMA Setup FIS Interrupt
const PIE_TASK_FILE_ERR: u32 = 1 << 30; // Task File Error Status

/// Mask of port-level events we unmask at bring-up. Anything outside
/// this mask still stays in PORT_IS but does not raise the port's
/// HBA-IS bit, so the ISR won't see it.
const PORT_IE_MASK: u32 =
    PIE_D2H_REG_FIS | PIE_PIO_SETUP_FIS | PIE_DMA_SETUP_FIS | PIE_TASK_FILE_ERR;

// PORT_CMD bits.
const CMD_ST: u32 = 1 << 0; // Start
const CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const CMD_FR: u32 = 1 << 14; // FIS Receive Running
const CMD_CR: u32 = 1 << 15; // Command List Running

/// Detected device class on a port (from PORT_SIG).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortKind {
    None,
    Sata,  // SIG = 0x00000101
    Atapi, // SIG = 0xEB140101
    Semb,  // SIG = 0xC33C0101
    Pmp,   // SIG = 0x96690101
    Unknown(u32),
}

impl PortKind {
    fn from_sig(sig: u32, ssts: u32) -> Self {
        // SSTS DET bits[3:0] = 3 means device present + comm OK.
        if (ssts & 0x0F) != 3 {
            return PortKind::None;
        }
        match sig {
            0x0000_0101 => PortKind::Sata,
            0xEB14_0101 => PortKind::Atapi,
            0xC33C_0101 => PortKind::Semb,
            0x9669_0101 => PortKind::Pmp,
            other => PortKind::Unknown(other),
        }
    }
}

/// One discovered port.
#[derive(Copy, Clone, Debug)]
pub struct PortInfo {
    pub index: u8,
    pub kind: PortKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AhciError {
    BarMapFailed,
    /// HBA reset never cleared GHC.HR within the bounded poll.
    ResetTimeout,
    /// PORT_CMD never reported FR + CR cleared so we couldn't safely
    /// reprogram the port.
    PortIdleTimeout,
}

/// Live AHCI HBA. Stage-4 cut keeps just the MMIO + the discovered
/// port list. Per-port command-list / FIS-receive structures are
/// allocated by `claim_port` (a follow-up).
pub struct Ahci {
    mmio: MmioRegion,
    pub cap: u32,
    pub vs: u32,
    pub pi: u32,
    pub ports: alloc::vec::Vec<PortInfo>,
}

impl core::fmt::Debug for Ahci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ahci")
            .field("cap", &format_args!("{:#x}", self.cap))
            .field("vs", &format_args!("{:#x}", self.vs))
            .field("pi", &format_args!("{:#x}", self.pi))
            .field("ports", &self.ports.len())
            .finish_non_exhaustive()
    }
}

impl Ahci {
    /// Bring up the HBA: reset, enable AHCI mode, enumerate
    /// implemented ports, capture each port's signature.
    ///
    /// # Safety
    /// Caller owns the device's BAR5 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AhciError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, ABAR_BAR) }.map_err(|_| AhciError::BarMapFailed)?;

        // Force AHCI mode (some HBAs come up in legacy IDE mode).
        // SAFETY: identity-mapped MMIO.
        let ghc = unsafe { mmio.read32(HBA_GHC) };
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_GHC, ghc | GHC_AE);
        }

        // HBA Reset.
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_GHC, GHC_AE | GHC_HR);
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive during HBA reset. AHCI 1.3.1 §10.4.3: HBA reset
        // self-clears within 1 s.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(HBA_GHC) } & GHC_HR == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(AhciError::ResetTimeout);
        }
        // Re-enable AHCI mode after the reset (HR clears AE on some
        // implementations).
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_GHC, GHC_AE);
        }

        // SAFETY: same.
        let cap = unsafe { mmio.read32(HBA_CAP) };
        // SAFETY: same.
        let vs = unsafe { mmio.read32(HBA_VS) };
        // SAFETY: same.
        let pi = unsafe { mmio.read32(HBA_PI) };

        // Drain any stale per-port interrupt state and clear the
        // master HBA IS bitmap (W1C, §3.1.3) before unmasking, so a
        // pre-existing latched IS bit doesn't fire the moment GHC.IE
        // is set.
        // SAFETY: identity-mapped MMIO.
        let stale_is = unsafe { mmio.read32(HBA_IS) };
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_IS, stale_is);
        }

        // Enumerate ports + program per-port IRQ mask.
        let mut ports = alloc::vec::Vec::new();
        for n in 0..32 {
            if pi & (1u32 << n) == 0 {
                continue;
            }
            let off = PORT_BASE_OFF + (n as u64) * PORT_STRIDE;
            // SAFETY: same.
            let sig = unsafe { mmio.read32(off + PORT_SIG) };
            // SAFETY: same.
            let ssts = unsafe { mmio.read32(off + PORT_SSTS) };
            // Clear SERR (write-1-to-clear).
            // SAFETY: same.
            let serr = unsafe { mmio.read32(off + PORT_SERR) };
            // SAFETY: same.
            unsafe {
                mmio.write32(off + PORT_SERR, serr);
            }
            // Clear stale PORT_IS (W1C, §3.3.5) and unmask the
            // events we care about (§3.3.6).
            // SAFETY: same.
            unsafe {
                mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
                mmio.write32(off + PORT_IE, PORT_IE_MASK);
            }
            let kind = PortKind::from_sig(sig, ssts);
            ports.push(PortInfo { index: n, kind });
        }

        // Now that per-port masks + stale IS are clean, flip the
        // master IRQ enable (§3.1.2). The HBA still cannot deliver
        // until the platform routes the vector (MSI-X / MSI / INTx),
        // which happens in `probe`.
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_GHC, GHC_AE | GHC_IE);
        }

        Ok(Self {
            mmio,
            cap,
            vs,
            pi,
            ports,
        })
    }

    /// Write the PORT_CI doorbell for the slot mask `bit` and wait
    /// for completion via the IRQ path. The wait future is
    /// constructed BEFORE the doorbell write — an IRQ landing
    /// between doorbell and waiter-construction would let the
    /// baseline fire-count capture a post-IRQ value and hang the
    /// await forever (see `interrupts/src/wait.rs` and the matching
    /// fix in `drivers/nvme/src/lib.rs::submit_io_irq_async`).
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively;
    /// `port_idx < 32`; PORT_CLB / PORT_FB / PORT_CMD are programmed
    /// and `bit` corresponds to the slot whose command-table is set
    /// up.
    pub async unsafe fn issue_and_wait_async(
        &self,
        port_idx: u8,
        bit: u32,
    ) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
        let vector = AHCI_IRQ_VECTOR.load(Ordering::Acquire);

        if vector == 0 {
            // No IRQ wired — issue + sync-poll.
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio.write32(off + PORT_CI, bit);
            }
            // SAFETY: caller-asserted ownership.
            return unsafe { self.issue_and_wait_sync(port_idx, bit) };
        }

        // Construct the waiter FIRST — captures the pre-doorbell
        // fire_count baseline. Then ring CI. Then await.
        // Each wait is bounded by a 5 s deadline — matches Linux
        // libata's ATA_TMOUT_INTERNAL_QUICK. On expiry we fall
        // through the loop to re-read CI: if the command actually
        // completed but the IRQ was lost, the read sees ci & bit
        // == 0 and returns Ok. Otherwise loop again with a fresh
        // baseline (bounded by the total command-level timeout
        // the caller enforces).
        let mut deadline = narf_time::Deadline::after_ms(5_000);
        let mut waiter = narf_interrupts::wait_for_irq_until(vector, deadline);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(off + PORT_CI, bit);
        }

        loop {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { self.mmio.read32(off + PORT_CI) };
            // SAFETY: same.
            let tfd = unsafe { self.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                return Err(AhciError::ResetTimeout);
            }
            if ci & bit == 0 {
                return Ok(());
            }
            // Park until the next IRQ OR deadline. After wake-up,
            // install a fresh waiter for the next iteration so we
            // observe any IRQ that lands between this drain and
            // the next CI read.
            let _ = (&mut waiter).await;
            deadline = narf_time::Deadline::after_ms(5_000);
            waiter = narf_interrupts::wait_for_irq_until(vector, deadline);
        }
    }

    /// Sync polled completion — kept for the existing block-device
    /// path so smoke tests that call directly into `ahci_read_lba`
    /// don't change behaviour.
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively;
    /// `port_idx < 32`; the slots in `bit` have already been issued.
    pub unsafe fn issue_and_wait_sync(&self, port_idx: u8, bit: u32) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
        // responsive_spin_until keeps cursor/FB alive while waiting
        // for the controller to clear CI; bail early on TFD.ERR.
        // 30 s wall-clock budget covers the worst-case ATA DMA
        // timeout for spinning rust (per ATA-8 §4.20.1 the longest
        // legitimate command is bounded well below this).
        let mut errored = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                let ci = unsafe { self.mmio.read32(off + PORT_CI) };
                // SAFETY: same.
                let tfd = unsafe { self.mmio.read32(off + 0x20) };
                if tfd & 0x01 != 0 {
                    errored = true;
                    return true;
                }
                ci & bit == 0
            },
            narf_time::Deadline::after_ms(30_000),
        );
        if errored || !done {
            return Err(AhciError::ResetTimeout);
        }
        Ok(())
    }

    /// Stop a port — clears PORT_CMD.ST + PORT_CMD.FRE and waits for
    /// CR + FR to clear. Required before reprogramming CLB / FB.
    ///
    /// # Safety
    /// Caller owns the HBA exclusively; `port_index < 32`.
    pub unsafe fn port_idle(&self, port_index: u8) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_index as u64) * PORT_STRIDE;
        // SAFETY: identity-mapped MMIO.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_CMD, cmd & !(CMD_ST | CMD_FRE));
        }
        // responsive_spin_until ticks sleep_pumps while CR/FR drain.
        // AHCI 1.3.1 §10.3.2: post-clear-ST the engine drains within
        // 500 ms; FR drain after clear-FRE is similar.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(off + PORT_CMD) } & (CMD_FR | CMD_CR) == 0,
            narf_time::Deadline::after_ms(500),
        );
        if done {
            Ok(())
        } else {
            Err(AhciError::PortIdleTimeout)
        }
    }

    /// COMRESET / SATA link-up sequence for a port.
    ///
    /// Sequence (mirrors `libata::sata_link_hardreset`, Linux
    /// `drivers/ata/libata-sata.c::sata_link_hardreset`):
    ///
    /// 1. Idle the port (CMD.ST = 0, wait CR = 0) via `port_idle`.
    /// 2. Set PORT_SCTL.DET = 1 — asserts COMRESET on the SATA PHY.
    /// 3. Hold for ≥ 1 ms (AHCI 1.3.1 §10.4.2 / SATA I spec §7.2.2).
    /// 4. Clear PORT_SCTL.DET = 0 — release COMRESET, begin OOB.
    /// 5. Poll PORT_SSTS.DET until it reads 3 (device + comms OK);
    ///    bail after 1 s.
    ///
    /// On success the port is ready for CLB/FB programming + FRE/ST.
    ///
    /// # Safety
    /// Caller owns the HBA exclusively; `port_index < 32`.
    pub unsafe fn port_reset(&self, port_index: u8) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_index as u64) * PORT_STRIDE;

        // 1. Stop any running command engine.
        // SAFETY: delegated; same ownership contract.
        unsafe { self.port_idle(port_index) }?;

        // 2. Write PORT_SCTL.DET = 1 (COMRESET), preserving other
        //    SPD / IPM fields. Linux uses mask 0x0f0 to keep the
        //    SPD nibble: `(scontrol & 0x0f0) | 0x301`.
        // SAFETY: identity-mapped MMIO.
        let sctl = unsafe { self.mmio.read32(off + PORT_SCTL) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SCTL, (sctl & 0x0F0) | 0x301);
        }

        // 3. Hold COMRESET for ≥ 1 ms (spec minimum).
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(1));

        // 4. Release COMRESET: DET = 0, keep SPD/IPM as-is.
        // SAFETY: identity-mapped MMIO.
        let sctl = unsafe { self.mmio.read32(off + PORT_SCTL) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SCTL, sctl & !0x0F);
        }

        // 5. Wait for PORT_SSTS.DET = 3 (device present + comms OK).
        //    AHCI 1.3.1 §10.1.2 allows up to 1 s for COMRESET to
        //    complete and OOB to finish.
        let found = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(off + PORT_SSTS) } & 0x0F == SSTS_DET_PRESENT,
            narf_time::Deadline::after_ms(1_000),
        );
        if !found {
            return Err(AhciError::ResetTimeout);
        }

        // Clear any SERR / PORT_IS latched during OOB.
        // SAFETY: identity-mapped MMIO.
        let serr = unsafe { self.mmio.read32(off + PORT_SERR) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SERR, serr);
            self.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        }

        Ok(())
    }

    /// HBA's capability bitmap.
    pub fn caps(&self) -> u32 {
        self.cap
    }

    /// AHCI version (BCD, e.g. 0x0001_0301 = v1.3.1).
    pub fn version(&self) -> u32 {
        self.vs
    }

    /// Implemented-port bitmap (PI register).
    pub fn ports_implemented(&self) -> u32 {
        self.pi
    }

    /// Issue ATA `IDENTIFY DEVICE` (opcode 0xEC) on the given port,
    /// returning the 512-byte device-data block.
    ///
    /// Stage-4 cut: allocates per-call DMA structures (command list +
    /// FIS receive + command table + 512-byte data buffer) and frees
    /// them after the response arrives. A real driver caches these
    /// per port; we trade allocations for code simplicity until the
    /// per-port BlockDevice surface lands.
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively; `port_idx <
    /// 32` and the port's PortKind was Sata at probe.
    pub unsafe fn identify_device(&self, port_idx: u8) -> Result<[u8; 512], AhciError> {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

        // Stop the port if it's running.
        // SAFETY: port_idx bound is the caller's contract.
        let _ = unsafe { self.port_idle(port_idx) };

        // Allocate one 4 KiB DMA page covering everything:
        //   +0x000  Command List  (1 KiB, 32 entries × 32 bytes)
        //   +0x400  Received FIS  (256 bytes)
        //   +0x500  Command Table (128 bytes — 64 cfis + 0 acmd + 16 PRDT0)
        //   +0x600  Data buffer   (512 bytes for IDENTIFY response)
        let scratch =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| AhciError::BarMapFailed)?;
        let base = scratch.phys_addr().raw();
        let cmd_list = base + 0x000;
        let fis_recv = base + 0x400;
        let cmd_tbl = base + 0x500;
        let data_buf = base + 0x600;

        // Zero the regions we touch.
        // SAFETY: identity-mapped DMA page.
        unsafe {
            for i in 0..(0x600 + 512) {
                core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
            }
        }

        // Command List entry 0: H[5..0] = FIS length in DWORDs (5
        // for H2D Register FIS), W bit = 0 (read), PRDT length = 1.
        // Fields:
        //   +0x00 u32 = (PRDT length << 16) | flags
        //   +0x04 u32 = bytes transferred (RW; HBA writes)
        //   +0x08 u64 = command-table phys
        //
        // CFL = 5 (H2D FIS = 5 DWORDs). Bits[4:0]. R=0, B=0, C=0,
        // RST=0, P=0. PRDT length = 1.
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(cmd_list as *mut u32, (1u32 << 16) | 5);
            core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
            core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
        }

        // Command Table:
        //   +0x00..0x40  CFIS (Command FIS — 64 bytes)
        //   +0x40..0x50  ACMD (ATAPI command — 16 bytes; unused)
        //   +0x50..0x80  Reserved
        //   +0x80..0x90  PRDT entry 0 (16 bytes)
        //
        // CFIS = H2D Register FIS (FIS type 0x27):
        //   +0  type = 0x27
        //   +1  bit 7 = C (command), bits[3:0] = port multiplier
        //   +2  command = 0xEC (IDENTIFY DEVICE)
        //   +3  features (low) = 0
        // SAFETY: same DMA page.
        unsafe {
            core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
            core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
            core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0xEC);
        }
        // PRDT entry 0 at +0x80 of cmd table:
        //   +0x00 u64 data base PA
        //   +0x08 u32 reserved
        //   +0x0C u32 = (Interrupt-on-completion bit 31) | (byte count - 1)
        let prdt = cmd_tbl + 0x80;
        // SAFETY: same DMA page.
        unsafe {
            core::ptr::write_volatile(prdt as *mut u64, data_buf);
            core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
            core::ptr::write_volatile((prdt + 12) as *mut u32, 511);
        }

        // Program port CLB / FB.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(off + 0x00, cmd_list as u32);
            self.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
            self.mmio.write32(off + 0x08, fis_recv as u32);
            self.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        }

        // Clear PORT_IS / PORT_SERR (write-1-to-clear).
        // SAFETY: same.
        let serr = unsafe { self.mmio.read32(off + PORT_SERR) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SERR, serr);
        }
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + 0x10, 0xFFFF_FFFF);
        }

        // Start the port (FRE first, then ST).
        // SAFETY: same.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        }
        // SAFETY: same.
        let cmd = unsafe { self.mmio.read32(off + PORT_CMD) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
        }

        // Issue command 0 by writing PORT_CI bit 0.
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + 0x38, 1);
        }

        // Poll until CI bit clears. responsive_spin_until keeps cursor
        // / FB / serial alive and bails on TFD.ERR. IDENTIFY DEVICE
        // is sub-millisecond on real hardware; 5 s wall-clock budget
        // covers a stuck/slow controller without hanging boot.
        let mut errored = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                let ci = unsafe { self.mmio.read32(off + 0x38) };
                // SAFETY: same.
                let tfd = unsafe { self.mmio.read32(off + 0x20) };
                if tfd & 0x01 != 0 {
                    errored = true;
                    return true;
                }
                ci & 1 == 0
            },
            narf_time::Deadline::after_ms(5_000),
        );
        if errored || !done {
            return Err(AhciError::ResetTimeout);
        }

        // Copy out the IDENTIFY DEVICE response.
        let mut out = [0u8; 512];
        // SAFETY: identity-mapped DMA.
        for i in 0..512usize {
            out[i] = unsafe { core::ptr::read_volatile((data_buf + i as u64) as *const u8) };
        }
        // Stop the port.
        // SAFETY: caller-asserted.
        let _ = unsafe { self.port_idle(port_idx) };
        // (no scratch drop needed — buffer is persistent now)
        Ok(out)
    }
}

/// Issue ATA `WRITE DMA EXT` (opcode 0x35) for `n_sectors`
/// 512-byte sectors starting at `lba`, sourcing from `data`. Same
/// scratch-page shape as READ DMA EXT.
///
/// # Safety
/// Same as `ahci_read_lba`.
pub unsafe fn ahci_write_lba(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > 4096 {
        return Err(AhciError::BarMapFailed);
    }
    if data.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // Zero the cmd-list / FIS / cmd-table prefix; copy caller payload
    // into the data buffer.
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..0x600 {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
        for i in 0..(n_sectors as usize) * 512 {
            core::ptr::write_volatile((data_buf + i as u64) as *mut u8, data[i]);
        }
    }

    // Cmd list slot 0: PRDT length = 1, CFL = 5, W bit = 1 (write).
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_list as *mut u32, (1u32 << 16) | (1u32 << 6) | 5); // bit 6 = W
        core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
        core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
    }

    // CFIS = H2D for WRITE DMA EXT (0x35).
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0x35);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, 0);
        core::ptr::write_volatile((cmd_tbl + 4) as *mut u8, (lba & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 5) as *mut u8, ((lba >> 8) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 6) as *mut u8, ((lba >> 16) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 7) as *mut u8, 0x40);
        core::ptr::write_volatile((cmd_tbl + 8) as *mut u8, ((lba >> 24) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 9) as *mut u8, ((lba >> 32) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 10) as *mut u8, ((lba >> 40) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 12) as *mut u8, (n_sectors & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 13) as *mut u8, ((n_sectors >> 8) & 0xFF) as u8);
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(prdt as *mut u64, data_buf);
        core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
        core::ptr::write_volatile((prdt + 12) as *mut u32, bytes - 1);
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1);
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive while waiting for WRITE DMA EXT to finish. 30 s
    // wall-clock budget for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Issue ATA `READ DMA EXT` (opcode 0x25) for `n_sectors` 512-byte
/// sectors starting at `lba`, copying the result into `out`. `out`
/// must be at least `n_sectors * 512` bytes.
///
/// Stage-4 cut: same per-call DMA scratch + single-PRDT-entry shape
/// as identify_device. Caps `n_sectors * 512` at 4096 bytes (one
/// page) — multi-page reads need a multi-PRDT chain.
///
/// # Safety
/// Same as `identify_device`.
pub unsafe fn ahci_read_lba(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > 4096 {
        return Err(AhciError::BarMapFailed);
    }
    if out.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..(0x600 + (n_sectors as usize) * 512) {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
    }

    // Cmd list slot 0: PRDT length = 1, CFL = 5 (H2D FIS).
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_list as *mut u32, (1u32 << 16) | 5);
        core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
        core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
    }

    // CFIS: H2D Register FIS for READ DMA EXT.
    //   +0  type = 0x27
    //   +1  bit 7 = C (command)
    //   +2  command = 0x25 (READ DMA EXT)
    //   +3  features (low) = 0
    //   +4  LBA[7:0]
    //   +5  LBA[15:8]
    //   +6  LBA[23:16]
    //   +7  Device = 0x40 (LBA mode)
    //   +8  LBA[31:24]
    //   +9  LBA[39:32]
    //   +10 LBA[47:40]
    //   +11 features (high) = 0
    //   +12 sector count low
    //   +13 sector count high
    //   +14 ICC = 0
    //   +15 Control = 0
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0x25);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, 0);
        core::ptr::write_volatile((cmd_tbl + 4) as *mut u8, (lba & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 5) as *mut u8, ((lba >> 8) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 6) as *mut u8, ((lba >> 16) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 7) as *mut u8, 0x40);
        core::ptr::write_volatile((cmd_tbl + 8) as *mut u8, ((lba >> 24) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 9) as *mut u8, ((lba >> 32) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 10) as *mut u8, ((lba >> 40) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 12) as *mut u8, (n_sectors & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 13) as *mut u8, ((n_sectors >> 8) & 0xFF) as u8);
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(prdt as *mut u64, data_buf);
        core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
        core::ptr::write_volatile((prdt + 12) as *mut u32, bytes - 1);
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF); // clear PORT_IS
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1);
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive while waiting for READ DMA EXT to finish. 30 s
    // wall-clock budget for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }

    // SAFETY: identity-mapped DMA.
    for i in 0..(n_sectors as usize) * 512 {
        out[i] = unsafe { core::ptr::read_volatile((data_buf + i as u64) as *const u8) };
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// IRQ-driven sibling of [`ahci_read_lba`]. Identical wire-form +
/// DMA-scratch shape; the only difference is that completion is
/// signalled by an MSI-X / MSI / INTx interrupt walked by
/// [`ahci_isr`] instead of by the host spin-polling PORT_CI.
///
/// Falls back to spin-polling when no IRQ path is wired (i.e. when
/// `AHCI_IRQ_VECTOR` is 0). This keeps the function safe to call
/// even when MSI-X / MSI / INTx negotiation failed at probe.
///
/// # Safety
/// Same as [`ahci_read_lba`].
pub async unsafe fn ahci_read_lba_async(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > 4096 {
        return Err(AhciError::BarMapFailed);
    }
    if out.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..(0x600 + (n_sectors as usize) * 512) {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_list as *mut u32, (1u32 << 16) | 5);
        core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
        core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0x25);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, 0);
        core::ptr::write_volatile((cmd_tbl + 4) as *mut u8, (lba & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 5) as *mut u8, ((lba >> 8) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 6) as *mut u8, ((lba >> 16) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 7) as *mut u8, 0x40);
        core::ptr::write_volatile((cmd_tbl + 8) as *mut u8, ((lba >> 24) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 9) as *mut u8, ((lba >> 32) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 10) as *mut u8, ((lba >> 40) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 12) as *mut u8, (n_sectors & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 13) as *mut u8, ((n_sectors >> 8) & 0xFF) as u8);
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(prdt as *mut u64, data_buf);
        core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
        core::ptr::write_volatile((prdt + 12) as *mut u32, bytes - 1);
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        // Drain stale PORT_IS so an old latched bit can't get
        // mis-attributed to this command.
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // Hand off to issue_and_wait_async — it constructs the IRQ
    // waiter BEFORE writing PORT_CI, which closes the race
    // documented in the module header.
    // SAFETY: port set up above; bit 0 = slot 0.
    let r = unsafe { ahci.issue_and_wait_async(port_idx, 1).await };
    r?;

    // SAFETY: identity-mapped DMA.
    for i in 0..(n_sectors as usize) * 512 {
        out[i] = unsafe { core::ptr::read_volatile((data_buf + i as u64) as *const u8) };
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// IRQ-driven sibling of [`ahci_write_lba`]. Same shape as
/// [`ahci_read_lba_async`].
///
/// # Safety
/// Same as [`ahci_write_lba`].
pub async unsafe fn ahci_write_lba_async(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > 4096 {
        return Err(AhciError::BarMapFailed);
    }
    if data.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..0x600 {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
        for i in 0..(n_sectors as usize) * 512 {
            core::ptr::write_volatile((data_buf + i as u64) as *mut u8, data[i]);
        }
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        // bit 6 = W (write).
        core::ptr::write_volatile(cmd_list as *mut u32, (1u32 << 16) | (1u32 << 6) | 5);
        core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
        core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80);
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0x35);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, 0);
        core::ptr::write_volatile((cmd_tbl + 4) as *mut u8, (lba & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 5) as *mut u8, ((lba >> 8) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 6) as *mut u8, ((lba >> 16) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 7) as *mut u8, 0x40);
        core::ptr::write_volatile((cmd_tbl + 8) as *mut u8, ((lba >> 24) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 9) as *mut u8, ((lba >> 32) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 10) as *mut u8, ((lba >> 40) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 12) as *mut u8, (n_sectors & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 13) as *mut u8, ((n_sectors >> 8) & 0xFF) as u8);
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(prdt as *mut u64, data_buf);
        core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
        core::ptr::write_volatile((prdt + 12) as *mut u32, bytes - 1);
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // SAFETY: port set up above.
    unsafe { ahci.issue_and_wait_async(port_idx, 1).await }?;

    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Issue ATA `READ FPDMA QUEUED` (NCQ, opcode 0x60) for a single
/// outstanding command on slot `tag` (0..31), reading `n_sectors`
/// 512-byte sectors at `lba`. Polled completion on PORT_CI bit
/// `tag` clearing. Same single-page scratch shape as the non-NCQ
/// variants.
///
/// NCQ wire-form differs from READ DMA EXT (§7.21 of ATA8-ACS): the
/// "sector count" register holds the tag (bits[7:3]) instead of the
/// xfer length, and the xfer length lives in the features register.
/// Tag-zero scheduling ("priority 0, normal") is used here.
///
/// `pmp` is the port-multiplier port number (0 for direct-attach).
///
/// # Safety
/// Same as `ahci_read_lba`. Caller asserts `tag < 32`.
pub unsafe fn ahci_read_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    if tag >= 32
        || n_sectors == 0
        || (n_sectors as usize) * 512 > 4096
        || out.len() < (n_sectors as usize) * 512
    {
        return Err(AhciError::BarMapFailed);
    }
    // SAFETY: caller-asserted.
    unsafe {
        ahci_lba_ncq(
            ahci,
            port_idx,
            pmp,
            tag,
            /*write=*/ false,
            lba,
            n_sectors,
            out,
            &[],
        )
    }
}

/// Issue ATA `WRITE FPDMA QUEUED` (NCQ, opcode 0x61). Mirror of
/// `ahci_read_lba_ncq` for outbound transfers.
///
/// # Safety
/// Same as `ahci_write_lba`.
pub unsafe fn ahci_write_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    if tag >= 32
        || n_sectors == 0
        || (n_sectors as usize) * 512 > 4096
        || data.len() < (n_sectors as usize) * 512
    {
        return Err(AhciError::BarMapFailed);
    }
    let mut sink = [0u8; 0];
    // SAFETY: caller-asserted.
    unsafe {
        ahci_lba_ncq(
            ahci, port_idx, pmp, tag, /*write=*/ true, lba, n_sectors, &mut sink, data,
        )
    }
}

unsafe fn ahci_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    write: bool,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
    data_in: &[u8],
) -> Result<(), AhciError> {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // Zero scratch + (for writes) copy caller payload in.
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..0x600 {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
        if write {
            for i in 0..(n_sectors as usize) * 512 {
                core::ptr::write_volatile((data_buf + i as u64) as *mut u8, data_in[i]);
            }
        }
    }

    // Cmd-list slot for `tag`. Each command-header is 32 bytes; we
    // only program slot `tag` so seek to its base.
    let slot = cmd_list + (tag as u64) * 32;
    // CFL = 5 (H2D FIS = 5 DWORDs), W bit = 1 if writing, P bit
    // (prefetchable) = 0 for NCQ. PRDT length = 1.
    let header_w0 = (1u32 << 16) | (if write { 1u32 << 6 } else { 0 }) | 5;
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(slot as *mut u32, header_w0);
        core::ptr::write_volatile((slot + 4) as *mut u32, 0);
        core::ptr::write_volatile((slot + 8) as *mut u64, cmd_tbl);
    }

    // CFIS H2D (FIS type 0x27) for FPDMA QUEUED:
    //   +0  type = 0x27
    //   +1  bit 7 = C (command), bits[3:0] = PMP target
    //   +2  command = 0x60 (READ) or 0x61 (WRITE)
    //   +3  features (low) = sector count low
    //   +4..7 LBA[23..0] + Device (0x40 = LBA)
    //   +8..10 LBA[47..24]
    //   +11 features (high) = sector count high
    //   +12 sector_count register = (tag << 3) | priority
    //   +13 0 (auxiliary)
    //   +14 ICC = 0
    //   +15 Control = 0
    let opcode = if write { 0x61u8 } else { 0x60u8 };
    let sec_lo = (n_sectors & 0xFF) as u8;
    let sec_hi = ((n_sectors >> 8) & 0xFF) as u8;
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80 | (pmp & 0x0F));
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, opcode);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, sec_lo);
        core::ptr::write_volatile((cmd_tbl + 4) as *mut u8, (lba & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 5) as *mut u8, ((lba >> 8) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 6) as *mut u8, ((lba >> 16) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 7) as *mut u8, 0x40);
        core::ptr::write_volatile((cmd_tbl + 8) as *mut u8, ((lba >> 24) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 9) as *mut u8, ((lba >> 32) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 10) as *mut u8, ((lba >> 40) & 0xFF) as u8);
        core::ptr::write_volatile((cmd_tbl + 11) as *mut u8, sec_hi);
        core::ptr::write_volatile((cmd_tbl + 12) as *mut u8, tag << 3);
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(prdt as *mut u64, data_buf);
        core::ptr::write_volatile((prdt + 8) as *mut u32, 0);
        core::ptr::write_volatile((prdt + 12) as *mut u32, bytes - 1);
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // Set PORT_SACT bit `tag` BEFORE PORT_CI to mark this command
    // queued (NCQ requirement, AHCI 1.3.1 §5.3.13).
    compiler_fence(Ordering::SeqCst);
    let bit = 1u32 << tag;
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x34, bit); // PORT_SACT
        ahci.mmio.write32(off + 0x38, bit); // PORT_CI
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive during the user-issued R/W DMA. 30 s wall-clock budget
    // for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & bit == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }

    // For reads, copy back.
    if !write {
        // SAFETY: identity-mapped DMA.
        for i in 0..(n_sectors as usize) * 512 {
            out[i] = unsafe { core::ptr::read_volatile((data_buf + i as u64) as *const u8) };
        }
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Snapshot of port-multiplier topology behind a port whose
/// `PortKind` was reported as `Pmp` at probe.
///
/// Per SATA 3.x PMP spec §10.3, the host queries the multiplier's
/// GSCR[2] (Number of Device Ports) to learn how many downstream
/// ports it exposes; the GSCR registers are read via READ PORT
/// MULTIPLIER (0xE4). This snapshot is what `discover_pmp_topology`
/// returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PmpTopology {
    /// Number of downstream ports advertised by the multiplier.
    pub num_ports: u8,
    /// Port-multiplier vendor id (GSCR[0] low half).
    pub vendor: u16,
    /// Port-multiplier product id (GSCR[0] high half).
    pub product: u16,
    /// PMP revision byte (GSCR[1] bits[15:8]).
    pub revision: u8,
    /// Raw GSCR[64] Features register.
    pub features: u32,
}

// ── PMP GSCR indices (SATA 3.x PMP spec §10.3 / Linux ata.h) ────────
/// GSCR[0] = ProductId in high 16 bits, VendorId in low 16 bits.
const GSCR_PROD_ID: u8 = 0;
/// GSCR[1] = Revision: bits[15:8] = major, bits[7:0] = minor.
const GSCR_REV: u8 = 1;
/// GSCR[2] = Port Info: bits[3:0] = number of device ports.
const GSCR_PORT_INFO: u8 = 2;
/// GSCR[64] = Features (optional capability flags).
const GSCR_FEAT: u8 = 64;

/// PMP control port address — READ PORT MULTIPLIER commands that
/// target the PMP's own register set use port-address 0x0F.
/// Reference: SATA Port Multiplier Spec §6.2.2.
const PMP_CTRL_PORT: u8 = 0x0F;

/// Issue one READ PORT MULTIPLIER command (ATA opcode 0xE4) to read
/// GSCR register `reg` from the PMP behind `port_idx`. Returns the
/// 32-bit register value.
///
/// Wire format (SATA PMP spec §6.2 / ATA8-ACS §7.43):
///
///   CFIS (H2D Register FIS):
///     +0  type   = 0x27 (Register H2D)
///     +1  C=1    | PMP port = 0x0F (control port)
///     +2  opcode = 0xE4 (READ PORT MULTIPLIER)
///     +3  features = GSCR register index
///     +12 sector-count = 0 (NODATA)
///
///   Response (D2H):
///     nsect  = val[7:0]
///     lbal   = val[15:8]
///     lbam   = val[23:16]
///     lbah   = val[31:24]
///
/// Reference: Linux `drivers/ata/libata-pmp.c::sata_pmp_read`, which
/// sets `tf.feature = reg; tf.device = link->pmp` and reads back
/// `tf.nsect | tf.lbal<<8 | tf.lbam<<16 | tf.lbah<<24`.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn pmp_read_gscr(
    ahci: &Ahci,
    port_idx: u8,
    reg: u8,
) -> Result<u32, AhciError> {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

    // Stop port if running.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Use the persistent scratch at the same layout as identify_device
    // (cmd_list@0x000, fis_recv@0x400, cmd_tbl@0x500, data_buf@0x600).
    let base = ahci_scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base + 0x000;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;

    // Zero the used range.
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..(0x500 + 64) {
            core::ptr::write_volatile((base + i as u64) as *mut u8, 0);
        }
    }

    // Command-list header 0: PRDT length = 0 (NODATA), CFL = 5.
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_list as *mut u32, 5); // PRDT_LEN=0, CFL=5
        core::ptr::write_volatile((cmd_list + 4) as *mut u32, 0);
        core::ptr::write_volatile((cmd_list + 8) as *mut u64, cmd_tbl);
    }

    // CFIS: H2D Register FIS for READ PORT MULTIPLIER (0xE4).
    //   +0  type = 0x27
    //   +1  C=1 | PMP_port = 0x0F  → 0x80 | 0x0F = 0x8F
    //   +2  command = 0xE4
    //   +3  features = GSCR register index
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(cmd_tbl as *mut u8, 0x27);
        core::ptr::write_volatile((cmd_tbl + 1) as *mut u8, 0x80 | PMP_CTRL_PORT);
        core::ptr::write_volatile((cmd_tbl + 2) as *mut u8, 0xE4);
        core::ptr::write_volatile((cmd_tbl + 3) as *mut u8, reg);
    }

    // Program port CLB / FB.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x00, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1); // issue slot 0
    }

    // Poll for completion (5 s; NODATA round-trips in microseconds).
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let ci = unsafe { ahci.mmio.read32(off + PORT_CI) };
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if errored || !done {
        let _ = unsafe { ahci.port_idle(port_idx) };
        return Err(AhciError::ResetTimeout);
    }

    // The D2H Register FIS is deposited at fis_recv + 0x40 (D2H FIS
    // area in the received FIS structure, AHCI 1.3.1 §4.2.1.3).
    // Bytes at the D2H FIS:
    //   +0  type (0x34)
    //   +1  misc
    //   +2  status
    //   +3  error
    //   +4  LBA[7:0]   = nsect
    //   +5  LBA[15:8]  = lbal
    //   +6  LBA[23:16] = lbam
    //   +8  LBA[31:24] = lbah
    // For READ PORT MULTIPLIER the returned value occupies:
    //   nsect = val[7:0], lbal = val[15:8], lbam = val[23:16],
    //   lbah = val[31:24].  Reference: Linux libata-pmp.c line 57.
    let d2h = fis_recv + 0x40;
    let val = unsafe {
        let nsect = core::ptr::read_volatile((d2h + 4) as *const u8) as u32;
        let lbal  = core::ptr::read_volatile((d2h + 5) as *const u8) as u32;
        let lbam  = core::ptr::read_volatile((d2h + 6) as *const u8) as u32;
        let lbah  = core::ptr::read_volatile((d2h + 8) as *const u8) as u32;
        nsect | (lbal << 8) | (lbam << 16) | (lbah << 24)
    };

    let _ = unsafe { ahci.port_idle(port_idx) };
    Ok(val)
}

/// Discover the topology behind a PMP-attached port. Returns `None`
/// if the port wasn't a PMP at probe.
///
/// Issues READ PORT MULTIPLIER (ATA 0xE4) commands to read GSCR[0]
/// (ProductId/VendorId), GSCR[1] (Revision), GSCR[2] (Port count),
/// and GSCR[64] (Features). Topology is reported regardless of
/// whether all GSCR reads succeed — partial failures yield zeroed
/// fields.
///
/// Reference: Linux `drivers/ata/libata-pmp.c::sata_pmp_read_gscr`
/// which reads registers {0,1,2,32,33,64,96} on attach.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn discover_pmp_topology(
    ahci: &Ahci,
    port_idx: u8,
) -> Option<PmpTopology> {
    let info = ahci.ports.iter().find(|p| p.index == port_idx)?;
    if info.kind != PortKind::Pmp {
        return None;
    }

    // GSCR[0] = ProductId[31:16] | VendorId[15:0]
    let prod_id = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_PROD_ID) }.unwrap_or(0);
    // GSCR[1] = Revision
    let rev_raw = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_REV) }.unwrap_or(0);
    // GSCR[2] = bits[3:0] = number of device ports
    let port_info = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_PORT_INFO) }.unwrap_or(0);
    // GSCR[64] = Features
    let features = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_FEAT) }.unwrap_or(0);

    Some(PmpTopology {
        vendor: (prod_id & 0xFFFF) as u16,
        product: (prod_id >> 16) as u16,
        // Revision major byte: bits[15:8] per Linux ata.h sata_pmp_gscr_rev macro.
        revision: ((rev_raw >> 8) & 0xFF) as u8,
        // bits[3:0] = number of device ports.
        num_ports: (port_info & 0x0F) as u8,
        features,
    })
}

/// Decode the model-number string from an IDENTIFY DEVICE response.
/// ATA strings are byte-swapped per pair (ATA-8 §7.16.7.36): byte 54
/// = char 0 high, byte 55 = char 0 low, etc. 40 bytes total.
///
/// ATA word 27 = byte offset 54; 20 words (40 bytes) for the model.
pub fn identify_model(id: &[u8; 512]) -> [u8; 40] {
    let mut out = [b' '; 40];
    for i in 0..20 {
        out[i * 2] = id[54 + i * 2 + 1];
        out[i * 2 + 1] = id[54 + i * 2];
    }
    out
}

/// Extract the LBA-28 addressable sector count from an IDENTIFY
/// DEVICE response (ATA-8 §7.16 word 60–61, byte offsets 120–123).
/// Returns 0 if 28-bit LBA is not supported. A non-zero value here
/// always means at least 28-bit LBA is available.
pub fn identify_lba28_capacity(id: &[u8; 512]) -> u32 {
    // Word 60 is low word, word 61 is high word (LE pair).
    let lo = u16::from_le_bytes([id[120], id[121]]) as u32;
    let hi = u16::from_le_bytes([id[122], id[123]]) as u32;
    (hi << 16) | lo
}

/// Extract the LBA-48 addressable sector count from an IDENTIFY
/// DEVICE response (ATA-8 §7.16 words 100–103, byte offsets
/// 200–207). Words 82–83 (bytes 164–167) bit 10 of word 83 gates
/// LBA-48 support. Returns 0 if device does not support 48-bit LBA.
pub fn identify_lba48_capacity(id: &[u8; 512]) -> u64 {
    // Word 83 bit 10 = LBA-48 supported (ATA-8 §7.16.7.83 table 21).
    let word83 = u16::from_le_bytes([id[166], id[167]]);
    if word83 & (1 << 10) == 0 {
        return 0;
    }
    // Words 100..103 = 64-bit total LBA count (LE quad-word).
    let b = &id[200..208];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Extract the supported-feature bitmask from IDENTIFY DEVICE words
/// 82 (byte 164) and 83 (byte 166). The upper byte of word 83 must
/// read `0x40`/`0xC0` (validity marker); if it doesn't, word 83 is
/// invalid and only word 82's low 16 bits are returned.
/// Returns `(word82, word83)` as raw values for further decoding.
pub fn identify_features(id: &[u8; 512]) -> (u16, u16) {
    let w82 = u16::from_le_bytes([id[164], id[165]]);
    let w83 = u16::from_le_bytes([id[166], id[167]]);
    (w82, w83)
}


/// Sync block-device adapter for the registry. Routes reads /
/// writes through `ahci_read_lba` / `ahci_write_lba` against the
/// first SATA port (or port 0 as a fallback when probe-time
/// PortKind classification missed the SIG window).
#[derive(Debug)]
pub struct AhciBlockSync;

impl narf_block::BlockDeviceSync for AhciBlockSync {
    fn lba_size(&self) -> u32 {
        512
    }
    fn capacity(&self) -> u64 {
        // Stage-4 stub. IDENTIFY DEVICE words 100..103 = total
        // user-addressable LBAs (48-bit); we don't cache that yet.
        0
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        if (n_blocks as usize) * 512 > 4096 || out.len() < (n_blocks as usize) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let g = CONTROLLER.lock();
        let ahci = g.as_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let port = ahci
            .ports
            .iter()
            .find(|p| p.kind == PortKind::Sata)
            .map(|p| p.index)
            .unwrap_or(0);
        // SAFETY: caller-trusted single-thread access.
        unsafe { ahci_read_lba(ahci, port, lba, n_blocks, out) }
            .map_err(|_| narf_block::BlockIoError::DriverError)
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if (n_blocks as usize) * 512 > 4096 || data.len() < (n_blocks as usize) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let g = CONTROLLER.lock();
        let ahci = g.as_ref().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let port = ahci
            .ports
            .iter()
            .find(|p| p.kind == PortKind::Sata)
            .map(|p| p.index)
            .unwrap_or(0);
        // SAFETY: same.
        unsafe { ahci_write_lba(ahci, port, lba, n_blocks, data) }
            .map_err(|_| narf_block::BlockIoError::DriverError)
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Ahci>> = IrqSafeSpinLock::new(None);

/// IDT vector our ISR is installed on, or 0 if no IRQ path was
/// successfully negotiated. Loaded by both ISR and async waiters.
/// Stays at 0 until `try_setup_irq` succeeds.
static AHCI_IRQ_VECTOR: AtomicU8 = AtomicU8::new(0);

/// MMIO base for the registered HBA. Stored as `usize` so the ISR
/// can reach it without locking (the ISR runs in IRQ context where
/// taking `IrqSafeSpinLock` would deadlock if the lock was already
/// held by the path that triggered the IRQ).
static AHCI_MMIO_BASE: AtomicUsize = AtomicUsize::new(0);

/// MSI-X table backing — kept alive for the life of the controller
/// so its physical pages aren't reclaimed underneath us.
static AHCI_MSIX: IrqSafeSpinLock<Option<MsixTable>> = IrqSafeSpinLock::new(None);

/// Synchronous AHCI ISR. Called by `narf_interrupts::dispatch::on_irq`
/// before the per-vector `fire_count` increment + waker fan-out. Job:
/// drain the level-triggered IRQ source so the next event is allowed
/// to fire.
///
/// Bounded work: HBA `IS` is a 32-bit per-port bitmap, so at worst
/// we walk 32 ports per fire (AHCI 1.3.1 §3.1.3). Each port's
/// `PORT_IS` is also a fixed 32-bit register. No unbounded loops.
fn ahci_isr() {
    let base = AHCI_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: identity-mapped MMIO; `base` is the ABAR PA stored
    // post-bring-up, owned by the AHCI driver.
    let is = unsafe { core::ptr::read_volatile((base as u64 + HBA_IS) as *const u32) };
    if is == 0 {
        return;
    }
    // Clear each port's per-port IS first (W1C inside the port,
    // §3.3.5), then clear the HBA-wide IS bit (W1C, §3.1.3). Order
    // matters: per spec the HBA IS bit only re-asserts if PORT_IS
    // is non-zero after the host clears it, so draining PORT_IS
    // first prevents an immediate re-fire.
    for n in 0..32u8 {
        let bit = 1u32 << n;
        if is & bit == 0 {
            continue;
        }
        let off = PORT_BASE_OFF + (n as u64) * PORT_STRIDE;
        // SAFETY: same identity-mapped MMIO window.
        let pis = unsafe { core::ptr::read_volatile((base as u64 + off + PORT_IS) as *mut u32) };
        if pis != 0 {
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile((base as u64 + off + PORT_IS) as *mut u32, pis);
            }
        }
    }
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile((base as u64 + HBA_IS) as *mut u32, is);
    }
}

/// Try to bring up MSI-X for the AHCI controller. Mirrors
/// `Xhci::try_enable_msix` — walks the cap, allocates an IDT vector,
/// programs MSI-X table entry 0 to deliver to the BSP, then flips
/// the global enable. Returns `(table, vector)` on success.
fn try_enable_msix_ahci(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Option<(MsixTable, u8)> {
    let mut msix = enable_msix(cap, device).ok()?;
    let v = narf_interrupts::vector::alloc().ok()?;
    let _ = msix.alloc_vector()?;
    // SAFETY: we hold the BusDeviceCap and own the MSI-X table; the
    // vector + handler are installed by the caller before enable().
    unsafe { msix.program_vector(0, 0, v) }.ok()?;
    // SAFETY: cfg-space write to a known cap-list offset.
    unsafe { msix.enable() }.ok()?;
    Some((msix, v))
}

/// Try MSI (single-vector) as a middle fallback between MSI-X and
/// legacy INTx. Some emulated AHCI controllers expose the MSI cap
/// but not MSI-X.
#[cfg(target_arch = "x86_64")]
fn try_enable_msi_ahci(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Option<u8> {
    let mut cfg = narf_bus::msi::enable_msi(cap, device, 1).ok()?;
    let v = narf_interrupts::vector::alloc().ok()?;
    // SAFETY: caller-authority over cfg space; vector reserved.
    let _ = unsafe { narf_bus::msi::program_msi(&mut cfg, 0, v) }.ok()?;
    // SAFETY: same.
    unsafe { narf_bus::msi::enable(&cfg) }.ok()?;
    Some(v)
}
#[cfg(not(target_arch = "x86_64"))]
fn try_enable_msi_ahci(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
    None
}

/// Legacy INTx fallback. Walks PCI INTERRUPT_PIN, looks the line up
/// in the AML `_PRT`, allocates an IDT vector, and routes the GSI
/// through the IOAPIC level/active-low.
#[cfg(target_arch = "x86_64")]
fn try_install_intx_ahci(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
    let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
    if pin == 0 || pin > 4 {
        return None;
    }
    let slot = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => addr.device,
        _ => return None,
    };
    let prt_pin = pin - 1;
    let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
    if route.entry.source.is_some() {
        return None;
    }
    let gsi = route.entry.source_index;
    let v = narf_interrupts::vector::alloc().ok()?;
    // Handler is installed by the caller before this routes the GSI,
    // so the first delivered IRQ already has the AHCI ISR registered.
    // SAFETY: vector + handler set above before the route.
    let ok = unsafe {
        narf_acpi::ioapic::route_gsi_to_vector(
            gsi,
            v,
            0,
            narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
        )
    };
    if !ok {
        return None;
    }
    Some(v)
}
#[cfg(not(target_arch = "x86_64"))]
fn try_install_intx_ahci(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
    None
}

/// Negotiate an IRQ delivery path (MSI-X → MSI → INTx). On success,
/// installs `ahci_isr` on the chosen vector + records the vector in
/// `AHCI_IRQ_VECTOR`. On total failure leaves `AHCI_IRQ_VECTOR` at
/// 0 — async paths will fall back to sync polling.
fn try_setup_irq(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) {
    if let Some((tbl, v)) = try_enable_msix_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        *AHCI_MSIX.lock() = Some(tbl);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
        return;
    }
    if let Some(v) = try_enable_msi_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
        return;
    }
    if let Some(v) = try_install_intx_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
    }
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // Enable MEM_SPACE + BUS_MASTER. We leave INTX_DISABLE clear so
    // that the legacy INTx fallback is reachable; if MSI / MSI-X
    // negotiation succeeds, the device's INTx pin is still inert
    // because no per-port IS bit will translate into an INTx
    // assertion under the device's MSI-mode behaviour (PCIe spec
    // §6.8: MSI/MSI-X enable in cfg-space suppresses INTx).
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device's BAR.
    let dev = match unsafe { Ahci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // Stash MMIO base for the ISR before any IRQ can fire.
    AHCI_MMIO_BASE.store(dev.mmio.phys.raw() as usize, Ordering::Release);
    // Negotiate IRQ delivery (MSI-X → MSI → INTx). Best-effort —
    // failure leaves the driver in sync-poll mode.
    try_setup_irq(&cap, &device);
    *CONTROLLER.lock() = Some(dev);
    // Register against the unified block-device registry.
    narf_block::register_block_device(
        "sata0",
        alloc::sync::Arc::new(AhciBlockSync) as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>,
    );
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("sata0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    for did in [AHCI_ICH9_DEV, AHCI_ICH10_DEV] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: AHCI_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        AHCI_ICH9_DEV => "ahci-ich9",
        AHCI_ICH10_DEV => "ahci-ich10",
        _ => "ahci",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Ahci) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

#[allow(dead_code)]
fn unused_silencer(mmio: &MmioRegion) {
    // Force compiler to keep compiler_fence import alive in low-cfg
    // builds.
    let _ = mmio;
    compiler_fence(Ordering::SeqCst);
}
