//! Multi-pipe display arbitration — pipe ownership, DBUF
//! partitioning and per-pipe scanout windows (#1017, tracker
//! #1093 lane Q11).
//!
//! Before this module, the Intel display stack had exactly one
//! pipe consumer at a time by construction: the modeset
//! orchestrator was hardwired to Pipe A, and the GGTT scanout
//! allocator mapped every surface into the same window. An
//! internal panel and an external display could never be live
//! together, and two external sessions would silently steal
//! each other's pipe and framebuffer.
//!
//! This module owns the three pieces of shared state that make
//! concurrent pipes safe:
//!
//! - **Pipe ownership** ([`PipeAllocator`]): pipes A–C are
//!   claimed by exactly one consumer at a time, keyed by the
//!   DDI that consumer drives. Claims are explicit, releases
//!   must come from the owning DDI, and a second claimant is
//!   refused — never queued over a live display. Pipe D is not
//!   arbitrated (it has no power well in the orchestrator's
//!   map); the internal panel claims Pipe A explicitly, external
//!   sessions take the lowest free pipe, so a lone external
//!   session lands on Pipe A exactly as it did before
//!   multi-pipe support.
//! - **DBUF partitioning** ([`dbuf_shares`]): the display
//!   buffer's S1 slice (1024 blocks — TGL PRM Vol. 12, "Basic
//!   Allocation Method": S1 alone = 1024 blocks, S1+S2 = 2048)
//!   is split into contiguous, equal shares across the active
//!   pipes in pipe order. The coordinator engages only when
//!   two or more pipes are active: a single pipe keeps the PRM
//!   pre-boot programming the orchestrator has always written,
//!   byte-identical. Enabling slice S2 to double the pool is
//!   deliberately not done here — its slice-to-pipe assignment
//!   table is a separate PRM step, named in specification
//!   §16's open items.
//! - **Scanout windows** ([`scanout_gtt_offset`]): each pipe
//!   owns a GGTT window 32 MiB (the maximum scanout block)
//!   above Pipe A's historical window, and its surface is
//!   allocated there via
//!   `intel_gpu_gtt::alloc_contiguous_scanout_at`.
//!
//! The allocator struct is deliberately separate from the
//! global registry at the bottom of this file: fixtures drive
//! the struct directly, production glue uses the registry.

extern crate alloc;

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_modeset::program_pipe_dbuf_share;
use crate::intel_gpu_pipes::Pipe;

/// What a pipe claim is for. Recorded with the claim so a
/// refusal can name the incumbent, and so the claim's lifetime
/// matches the consumer's session shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PipeUse {
    /// The firmware/internal panel taken over at probe.
    InternalPanel,
    /// An external single-stream DP session (#1092).
    ExternalSst,
    /// One stream of a DP MST link (#1017).
    ExternalMst,
    /// A USB-C DP Alt-Mode bridge session.
    AltModeBridge,
}

/// A pipe claim: the DDI whose session owns the pipe, and why.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PipeOwner {
    pub ddi: Ddi,
    pub used_for: PipeUse,
}

/// Why a pipe claim failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PipeClaimError {
    /// The pipe is outside the arbitration set (Pipe D).
    NotAllocatable,
    /// Another consumer owns the pipe; carries the incumbent
    /// so the refusal is diagnosable, never silent.
    Busy(PipeOwner),
}

/// Pipes under arbitration: A, B, C.
const ARBITRATED_PIPES: [Pipe; 3] = [Pipe::A, Pipe::B, Pipe::C];

fn slot(pipe: Pipe) -> Option<usize> {
    ARBITRATED_PIPES.iter().position(|p| *p == pipe)
}

/// The pipe allocator. One instance lives in the global
/// registry; fixtures construct their own.
#[derive(Debug)]
pub struct PipeAllocator {
    owners: [Option<PipeOwner>; 3],
}

impl Default for PipeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeAllocator {
    pub const fn new() -> Self {
        Self { owners: [None; 3] }
    }

    /// Claim `pipe` for `owner`. Fails with
    /// [`PipeClaimError::Busy`] when another DDI holds it;
    /// re-claiming a pipe the same DDI already owns (for the
    /// same use) is idempotent.
    pub fn claim(&mut self, pipe: Pipe, owner: PipeOwner) -> Result<(), PipeClaimError> {
        let idx = slot(pipe).ok_or(PipeClaimError::NotAllocatable)?;
        match self.owners[idx] {
            None => {
                self.owners[idx] = Some(owner);
                Ok(())
            }
            Some(incumbent) if incumbent == owner => Ok(()),
            Some(incumbent) => Err(PipeClaimError::Busy(incumbent)),
        }
    }

    /// Claim the lowest free pipe for `owner` (A, then B, then
    /// C — a lone external session therefore lands on Pipe A,
    /// exactly the pre-multi-pipe behaviour). `None` when all
    /// three pipes are owned.
    pub fn claim_any(&mut self, owner: PipeOwner) -> Option<Pipe> {
        for (idx, pipe) in ARBITRATED_PIPES.iter().enumerate() {
            if self.owners[idx].is_none() {
                self.owners[idx] = Some(owner);
                return Some(*pipe);
            }
        }
        None
    }

    /// Claim a pipe for `owner`, returning the pipe the owner's
    /// DDI already holds when it holds one. This is the
    /// re-entry shape for consumers whose sessions can be
    /// re-entered on the same connector (the DP Alt-Mode
    /// bridge): a repeat entry reuses its pipe instead of
    /// consuming a second one.
    pub fn claim_for(&mut self, owner: PipeOwner) -> Option<Pipe> {
        if let Some(pipe) = self.pipe_of(owner.ddi) {
            return Some(pipe);
        }
        self.claim_any(owner)
    }

    /// Release `pipe`. Only the owning DDI can release its
    /// pipe — a session tearing down the wrong DDI's display
    /// is exactly the failure this registry exists to prevent.
    /// Returns `true` when a claim was actually released.
    pub fn release(&mut self, pipe: Pipe, by: Ddi) -> bool {
        let Some(idx) = slot(pipe) else { return false };
        match self.owners[idx] {
            Some(owner) if owner.ddi == by => {
                self.owners[idx] = None;
                true
            }
            _ => false,
        }
    }

    /// Release whatever pipe `ddi` owns, if any (the disconnect
    /// shape: the session knows its DDI, the registry knows
    /// the rest).
    pub fn release_ddi(&mut self, ddi: Ddi) -> Option<Pipe> {
        let pipe = self.pipe_of(ddi)?;
        let idx = slot(pipe)?;
        self.owners[idx] = None;
        Some(pipe)
    }

    /// The owner of `pipe`, if claimed.
    pub fn owner_of(&self, pipe: Pipe) -> Option<PipeOwner> {
        self.owners[slot(pipe)?]
    }

    /// The pipe `ddi` owns, if any.
    pub fn pipe_of(&self, ddi: Ddi) -> Option<Pipe> {
        ARBITRATED_PIPES
            .iter()
            .copied()
            .find(|pipe| self.owner_of(*pipe).is_some_and(|o| o.ddi == ddi))
    }

    /// The currently claimed pipes, in pipe order.
    pub fn active_pipes(&self) -> Vec<Pipe> {
        ARBITRATED_PIPES
            .iter()
            .copied()
            .filter(|pipe| self.owner_of(*pipe).is_some())
            .collect()
    }
}

// ── DBUF partitioning ────────────────────────────────────────

/// Total DBUF blocks in slice S1, the slice firmware leaves
/// enabled (TGL PRM Vol. 12, "Basic Allocation Method": "If
/// only DBUF_S1 is enabled, TotalBlocksAvailable = 1024").
pub const DBUF_TOTAL_BLOCKS: u16 = 1024;

/// Partition the DBUF pool across `active` pipes: contiguous
/// equal shares in pipe order, earlier pipes taking the
/// remainder one block at a time by construction of the
/// `(i * total / n, (i+1) * total / n)` boundaries. Returns
/// `(pipe, start_block, end_block)` triples sorted by pipe.
/// With one active pipe the share is the whole pool — but see
/// the module docs: the coordinator only *applies* shares when
/// two or more pipes are active, so a lone pipe keeps its
/// pre-boot programming.
pub fn dbuf_shares(active: &[Pipe]) -> Vec<(Pipe, u16, u16)> {
    let mut pipes: Vec<Pipe> = active.to_vec();
    pipes.sort_by_key(|p| *p as u8);
    pipes.dedup();
    let n = pipes.len() as u32;
    if n == 0 {
        return Vec::new();
    }
    let total = DBUF_TOTAL_BLOCKS as u32;
    pipes
        .iter()
        .enumerate()
        .map(|(i, pipe)| {
            let start = (i as u32 * total / n) as u16;
            let end = ((i as u32 + 1) * total / n - 1) as u16;
            (*pipe, start, end)
        })
        .collect()
}

/// The share `pipe` would get if `active` were the active set.
pub fn share_for(active: &[Pipe], pipe: Pipe) -> Option<(u16, u16)> {
    dbuf_shares(active)
        .into_iter()
        .find(|(p, _, _)| *p == pipe)
        .map(|(_, start, end)| (start, end))
}

/// Reprogram every active pipe's DBUF share after the active
/// set changed (a pipe lit or went dark while at least one
/// other pipe stays active). No-op below two active pipes: a
/// single pipe's programming is the orchestrator's pre-boot
/// shape and must not be rewritten.
pub fn reprogram_dbuf_shares<M: MmioWindow + ?Sized>(mmio: &M, allocator: &PipeAllocator) {
    let active = allocator.active_pipes();
    if active.len() < 2 {
        return;
    }
    for (pipe, start, end) in dbuf_shares(&active) {
        program_pipe_dbuf_share(mmio, pipe, start, end);
    }
}

// ── Per-pipe scanout windows ─────────────────────────────────

/// GGTT distance between neighbouring pipes' scanout windows:
/// 32 MiB, the largest block the scanout allocator hands out
/// (`scanout_order_for` caps at order 13), so windows can
/// never overlap.
pub const SCANOUT_GTT_STRIDE: u64 = crate::intel_gpu_gtt::CONSOLE_SCANOUT_WINDOW_BYTES;

/// The GGTT offset of `pipe`'s scanout window. Pipe A keeps
/// the historical single-scanout offset (0x1000000); B and C
/// follow at one stride each.
pub fn scanout_gtt_offset(pipe: Pipe) -> u64 {
    crate::intel_gpu_gtt::SCANOUT_GTT_OFFSET_PIPE_A + (pipe as u64) * SCANOUT_GTT_STRIDE
}

// ── Global registry ──────────────────────────────────────────
//
// The production instance. Sessions claim on connect and
// release on disconnect through these wrappers; the HPD glue
// in `intel_gpu` and the DP Alt-Mode bridge are the callers.

static PIPE_ALLOCATOR: IrqSafeSpinLock<PipeAllocator> = IrqSafeSpinLock::new(PipeAllocator::new());

/// Global-registry form of [`PipeAllocator::claim`].
pub fn claim_pipe(pipe: Pipe, owner: PipeOwner) -> Result<(), PipeClaimError> {
    PIPE_ALLOCATOR.lock().claim(pipe, owner)
}

/// Global-registry form of [`PipeAllocator::claim_any`].
pub fn claim_any_pipe(owner: PipeOwner) -> Option<Pipe> {
    PIPE_ALLOCATOR.lock().claim_any(owner)
}

/// Global-registry form of [`PipeAllocator::claim_for`].
pub fn claim_pipe_for(owner: PipeOwner) -> Option<Pipe> {
    PIPE_ALLOCATOR.lock().claim_for(owner)
}

/// Global-registry form of [`PipeAllocator::release`].
pub fn release_pipe(pipe: Pipe, by: Ddi) -> bool {
    PIPE_ALLOCATOR.lock().release(pipe, by)
}

/// Global-registry form of [`PipeAllocator::release_ddi`].
pub fn release_ddi_pipes(ddi: Ddi) -> Option<Pipe> {
    PIPE_ALLOCATOR.lock().release_ddi(ddi)
}

/// Global-registry form of [`PipeAllocator::owner_of`].
pub fn pipe_owner(pipe: Pipe) -> Option<PipeOwner> {
    PIPE_ALLOCATOR.lock().owner_of(pipe)
}

/// Global-registry form of [`PipeAllocator::pipe_of`].
pub fn pipe_of(ddi: Ddi) -> Option<Pipe> {
    PIPE_ALLOCATOR.lock().pipe_of(ddi)
}

/// The globally active pipes, in pipe order.
pub fn active_pipes() -> Vec<Pipe> {
    PIPE_ALLOCATOR.lock().active_pipes()
}

/// Global-registry form of [`reprogram_dbuf_shares`].
pub fn reprogram_active_dbuf_shares<M: MmioWindow + ?Sized>(mmio: &M) {
    let allocator = PIPE_ALLOCATOR.lock();
    reprogram_dbuf_shares(mmio, &allocator);
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the multi-pipe arbitration: the allocator
    //! discipline (pure), the DBUF partition pins, and a full
    //! second-pipe modeset run against a register-level model
    //! of the Gen12 display block + an always-locking DP sink.
    //! The model mirrors the documented hardware behaviours
    //! (power-well STATE mirrors REQUEST, PIPECONF STATE
    //! mirrors ENABLE, DDI_BUF IDLE mirrors !ENABLE, PLL status
    //! reads locked) — the same behaviours Q4's sink model
    //! encodes, written here for the pipe-B register blocks the
    //! Q4 fixtures never touch.

    extern crate alloc;

    use super::*;
    use crate::intel_gpu_aux::{
        AUX_CTL_DONE, AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY,
        DDI_AUX_CTL_OFFSET, DDI_AUX_DATA_OFFSET,
    };
    use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
    use crate::intel_gpu_modeset::{Framebuffer, LinkPlan, Modeset, PixelFormat};
    use crate::intel_gpu_pipes::{Transcoder, PIPECONF_OFFSET};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn owner(ddi: Ddi, used_for: PipeUse) -> PipeOwner {
        PipeOwner { ddi, used_for }
    }

    fn smoke_allocator_claim_release_discipline() -> TestResult {
        let mut a = PipeAllocator::new();
        // Internal panel takes Pipe A explicitly.
        if a.claim(Pipe::A, owner(Ddi::A, PipeUse::InternalPanel))
            .is_err()
        {
            return TestResult::Fail("Pipe A claim by internal panel");
        }
        // A second claimant for the same pipe is refused and
        // the refusal names the incumbent.
        match a.claim(Pipe::A, owner(Ddi::B, PipeUse::ExternalSst)) {
            Err(PipeClaimError::Busy(inc)) if inc.ddi == Ddi::A => {}
            _ => return TestResult::Fail("double claim of Pipe A must be Busy(A)"),
        }
        // claim_any skips the taken pipe.
        match a.claim_any(owner(Ddi::B, PipeUse::ExternalSst)) {
            Some(Pipe::B) => {}
            _ => return TestResult::Fail("claim_any must land on Pipe B"),
        }
        // A non-owner cannot release someone else's pipe.
        if a.release(Pipe::A, Ddi::B) {
            return TestResult::Fail("release by non-owner must fail");
        }
        if a.owner_of(Pipe::A).map(|o| o.ddi) != Some(Ddi::A) {
            return TestResult::Fail("Pipe A must still belong to DDI A");
        }
        // The owner can.
        if !a.release(Pipe::A, Ddi::A) {
            return TestResult::Fail("release by owner must succeed");
        }
        if a.owner_of(Pipe::A).is_some() {
            return TestResult::Fail("Pipe A must be free after release");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_multipipe",
        smoke_allocator_claim_release_discipline
    );

    fn smoke_allocator_exhaustion_and_pipe_d() -> TestResult {
        let mut a = PipeAllocator::new();
        // Pipe D is outside the arbitration set.
        match a.claim(Pipe::D, owner(Ddi::D, PipeUse::AltModeBridge)) {
            Err(PipeClaimError::NotAllocatable) => {}
            _ => return TestResult::Fail("Pipe D must be NotAllocatable"),
        }
        // Three claims fill the set; the fourth is refused.
        for ddi in [Ddi::A, Ddi::B, Ddi::C] {
            if a.claim_any(owner(ddi, PipeUse::ExternalSst)).is_none() {
                return TestResult::Fail("claim within capacity must succeed");
            }
        }
        if a.claim_any(owner(Ddi::D, PipeUse::ExternalSst)).is_some() {
            return TestResult::Fail("fourth claim must be refused");
        }
        // claim_for is idempotent per DDI: DDI B already owns
        // Pipe B and gets it back, consuming nothing new.
        match a.claim_for(owner(Ddi::B, PipeUse::AltModeBridge)) {
            Some(Pipe::B) => {}
            _ => return TestResult::Fail("claim_for must return the held pipe"),
        }
        if a.active_pipes().len() != 3 {
            return TestResult::Fail("claim_for must not consume another pipe");
        }
        // release_ddi frees by DDI alone.
        match a.release_ddi(Ddi::B) {
            Some(Pipe::B) => {}
            _ => return TestResult::Fail("release_ddi must free Pipe B"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_multipipe",
        smoke_allocator_exhaustion_and_pipe_d
    );

    fn smoke_dbuf_shares_partition() -> TestResult {
        // One pipe: the whole S1 pool.
        let one = dbuf_shares(&[Pipe::A]);
        if one != alloc::vec![(Pipe::A, 0, 1023)] {
            return TestResult::Fail("single-pipe share must be (0, 1023)");
        }
        // Two pipes: equal halves in pipe order, regardless of
        // the order the caller lists them in.
        let two = dbuf_shares(&[Pipe::B, Pipe::A]);
        if two != alloc::vec![(Pipe::A, 0, 511), (Pipe::B, 512, 1023)] {
            return TestResult::Fail("two-pipe shares must be (0,511) + (512,1023)");
        }
        // Three pipes: contiguous, gapless, covering the pool.
        let three = dbuf_shares(&[Pipe::A, Pipe::B, Pipe::C]);
        if three != alloc::vec![(Pipe::A, 0, 340), (Pipe::B, 341, 681), (Pipe::C, 682, 1023)] {
            return TestResult::Fail("three-pipe shares must tile the pool");
        }
        // Shares never overlap and always end at the pool edge.
        let mut covered = 0u32;
        for (_, start, end) in &three {
            if *start as u32 != covered {
                return TestResult::Fail("shares must be contiguous");
            }
            covered = *end as u32 + 1;
        }
        if covered != DBUF_TOTAL_BLOCKS as u32 {
            return TestResult::Fail("shares must cover the whole pool");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_multipipe",
        smoke_dbuf_shares_partition
    );

    fn smoke_scanout_windows_are_distinct() -> TestResult {
        if scanout_gtt_offset(Pipe::A) != 0x100_0000 {
            return TestResult::Fail("Pipe A keeps the historical window");
        }
        if scanout_gtt_offset(Pipe::B) != 0x300_0000 || scanout_gtt_offset(Pipe::C) != 0x500_0000 {
            return TestResult::Fail("Pipe B/C windows at one stride each");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_multipipe",
        smoke_scanout_windows_are_distinct
    );

    // ── Register model + always-locking sink ────────────────

    const PWR_WELL_CTL2: u64 = 0x4_5404;
    const PLL_POWER_STATE: u32 = 1 << 26;
    const PLL_LOCK: u32 = 1 << 30;

    /// A minimal DP sink for link training: DP 1.4 caps at
    /// HBR2 ×4, lane status locks immediately (CR under TPS1,
    /// EQ under TPS2 with one poll), adjust requests stay at
    /// level 0. The AUX frame decode is written from DP 1.4a
    /// §2.7.4, as in Q4's fixture: byte 0 = command nibble +
    /// address[19:16], bytes 1–2 = address[15:0], byte 3 =
    /// LEN − 1.
    #[derive(Debug)]
    struct AlwaysLockSink {
        caps: [u8; 16],
        pattern: u8,
        polls: u32,
        powered: bool,
    }

    impl AlwaysLockSink {
        fn new() -> Self {
            let mut caps = [0u8; 16];
            caps[0] = 0x14; // DPCD_REV: DP 1.4
            caps[1] = 0x14; // MAX_LINK_RATE: HBR2
            caps[2] = 0xC4; // MAX_LANE_COUNT: 4 | TPS3 | enhanced framing
            Self {
                caps,
                pattern: 0,
                polls: 0,
                powered: false,
            }
        }

        fn cr_locked(&self) -> bool {
            self.powered && self.pattern >= 1
        }

        fn eq_done(&self) -> bool {
            self.pattern >= 2 && self.polls >= 1 && self.cr_locked()
        }

        fn lane_status_byte(&self) -> u8 {
            let mut nibble = 0u8;
            if self.cr_locked() {
                nibble |= 0x1; // CR_DONE
            }
            if self.eq_done() {
                nibble |= 0x2 | 0x4; // CHANNEL_EQ_DONE | SYMBOL_LOCKED
            }
            nibble | (nibble << 4)
        }

        fn read_dpcd(&mut self, addr: u32, len: usize) -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..len {
                let a = addr + i as u32;
                out.push(match a {
                    0x000..=0x00F => self.caps[a as usize],
                    0x202 => {
                        self.polls += 1;
                        self.lane_status_byte()
                    }
                    0x203 => self.lane_status_byte(),
                    0x204 => {
                        if self.eq_done() {
                            0x01 // INTERLANE_ALIGN_DONE
                        } else {
                            0x00
                        }
                    }
                    _ => 0,
                });
            }
            out
        }

        fn write_dpcd(&mut self, addr: u32, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            match addr {
                0x102 => {
                    self.pattern = data[0] & 0x7;
                    self.polls = 0;
                }
                0x600 => {
                    self.powered = data[0] & 0x1 != 0;
                }
                _ => {}
            }
        }

        fn transact(&mut self, wire: &[u8]) -> Vec<u8> {
            let cmd = wire[0] >> 4;
            let addr = (((wire[0] & 0x0F) as u32) << 16) | ((wire[1] as u32) << 8) | wire[2] as u32;
            let len = wire[3] as usize + 1;
            match cmd {
                0x8 => {
                    self.write_dpcd(addr, &wire[4..4 + len]);
                    alloc::vec![0x00]
                }
                0x9 => {
                    let mut reply = alloc::vec![0x00];
                    reply.extend_from_slice(&self.read_dpcd(addr, len));
                    reply
                }
                _ => alloc::vec![0x10],
            }
        }
    }

    #[derive(Debug)]
    struct PipeMmio {
        regs: RefCell<BTreeMap<u64, u32>>,
        pub writes: RefCell<Vec<(u64, u32)>>,
        sink: RefCell<AlwaysLockSink>,
        ddi: Ddi,
        aux_reply: RefCell<Vec<u8>>,
        aux_data: RefCell<[u8; 20]>,
        aux_ctl_state: RefCell<u32>,
    }

    impl PipeMmio {
        fn new(ddi: Ddi) -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                writes: RefCell::new(Vec::new()),
                sink: RefCell::new(AlwaysLockSink::new()),
                ddi,
                aux_reply: RefCell::new(Vec::new()),
                aux_data: RefCell::new([0u8; 20]),
                aux_ctl_state: RefCell::new(0),
            }
        }

        fn stored(&self, off: u64) -> u32 {
            self.regs.borrow().get(&off).copied().unwrap_or(0)
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        pub fn any_write_in(&self, lo: u64, hi: u64) -> bool {
            self.writes
                .borrow()
                .iter()
                .any(|(o, _)| *o >= lo && *o < hi)
        }

        fn aux_ctl_off(&self) -> u64 {
            self.ddi.base() + DDI_AUX_CTL_OFFSET
        }

        fn is_aux_data(&self, off: u64) -> Option<usize> {
            let base = self.ddi.base() + DDI_AUX_DATA_OFFSET;
            if off >= base && off < base + 20 && (off - base) % 4 == 0 {
                Some(((off - base) / 4) as usize)
            } else {
                None
            }
        }
    }

    impl crate::intel_gpu_aux::MmioWindow for PipeMmio {
        fn read32(&self, off: u64) -> u32 {
            if off == self.aux_ctl_off() {
                return *self.aux_ctl_state.borrow();
            }
            if let Some(idx) = self.is_aux_data(off) {
                let reply = self.aux_reply.borrow();
                let mut v: u32 = 0;
                for b in 0..4 {
                    let byte = reply.get(idx * 4 + b).copied().unwrap_or(0);
                    v |= (byte as u32) << (24 - 8 * b);
                }
                return v;
            }
            let v = self.stored(off);
            if off == PWR_WELL_CTL2 {
                // STATE(idx) mirrors REQUEST(idx).
                return v | ((v & 0xAAAA_AAAA) >> 1);
            }
            if (0x4_6010..=0x4_6018).contains(&off) && (off - 0x4_6010) % 4 == 0 {
                // Every DPLL enable block reads powered + locked.
                return v | PLL_POWER_STATE | PLL_LOCK;
            }
            // DBUF slices grant power when requested.
            {
                use crate::intel_gpu_wm::{
                    DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST, DBUF_POWER_STATE,
                };
                if (off == DBUF_CTL_S1 || off == DBUF_CTL_S2) && v & DBUF_POWER_REQUEST != 0 {
                    return v | DBUF_POWER_STATE;
                }
            }
            // PIPECONF blocks (pipe/transcoder conf are aliased
            // per pipe): STATE mirrors ENABLE.
            for pipe in [Pipe::A, Pipe::B, Pipe::C] {
                if off == pipe.base() + PIPECONF_OFFSET {
                    use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
                    let state = if v & PIPECONF_ENABLE != 0 {
                        PIPECONF_STATE
                    } else {
                        0
                    };
                    return (v & !PIPECONF_STATE) | state;
                }
            }
            if off == self.ddi.base() + DDI_BUF_CTL_OFFSET {
                use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                let idle = if v & DDI_BUF_CTL_ENABLE != 0 {
                    0
                } else {
                    DDI_BUF_CTL_IDLE_STATUS
                };
                return (v & !DDI_BUF_CTL_IDLE_STATUS) | idle;
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
            if let Some(idx) = self.is_aux_data(off) {
                let mut data = self.aux_data.borrow_mut();
                for b in 0..4 {
                    data[idx * 4 + b] = (val >> (24 - 8 * b)) as u8;
                }
            }
            if off == self.aux_ctl_off() {
                if val & AUX_CTL_SEND_BUSY != 0 {
                    let msgsize = ((val & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
                    let wire = self.aux_data.borrow()[..msgsize].to_vec();
                    let reply = self.sink.borrow_mut().transact(&wire);
                    let total = reply.len() as u32;
                    *self.aux_reply.borrow_mut() = reply;
                    *self.aux_ctl_state.borrow_mut() =
                        AUX_CTL_DONE | (total << AUX_CTL_MSGSIZE_SHIFT);
                } else {
                    *self.aux_ctl_state.borrow_mut() = 0;
                }
            }
        }
    }

    fn smoke_second_pipe_modeset_run() -> TestResult {
        use crate::dp_link_training::LinkRate;
        use crate::intel_gpu_modeset::{PLANE_BUF_CFG_OFFSET, PLANE_WM_BASE_OFFSET};
        use crate::intel_gpu_pipes::{
            PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET, TRANS_HTOTAL_OFFSET,
        };
        // A full plan modeset on Pipe B / DDI B, with the
        // two-pipe DBUF share for B set the way the coordinator
        // sets it.
        let mmio = PipeMmio::new(Ddi::B);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::B);
        ms.set_dbuf_share(512, 1023);
        let fb = Framebuffer {
            phys_addr: 0x300_0000,
            stride_bytes: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        };
        let mode = crate::intel_gpu_modeset::Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let plan = LinkPlan {
            rate: LinkRate::Hbr2,
            lanes: 4,
        };
        match ms.modeset_with_plan(&fb, &mode, plan) {
            Ok(_) => {}
            Err(e) => {
                let _ = e;
                return TestResult::Fail("Pipe B modeset run failed");
            }
        }
        // PG3 was requested (Pipe B's well).
        let pg3_req = 0x2u32 << (2 * 2);
        if mmio
            .writes_to(PWR_WELL_CTL2)
            .iter()
            .all(|w| w & pg3_req == 0)
        {
            return TestResult::Fail("PG3 REQUEST never written");
        }
        // DPLL1 was programmed and enabled; DPLL0's CFGCR0 was
        // not touched.
        if mmio
            .writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL1)
            .is_empty()
        {
            return TestResult::Fail("DPLL1 CFGCR0 not written");
        }
        if !mmio
            .writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0)
            .is_empty()
        {
            return TestResult::Fail("DPLL0 CFGCR0 must not be written for DDI B");
        }
        // DPCLKA routed DPLL1 to PHY B: select field (bits
        // [3:2]) == 1 in the first write, clock-off (bit 11)
        // set there and clear in the second.
        let dpclka = mmio.writes_to(crate::intel_gpu_pll::DPCLKA_CFGCR0);
        if dpclka.len() != 2 {
            return TestResult::Fail("DPCLKA routing must be two writes");
        }
        if (dpclka[0] >> 2) & 0x3 != 1 || dpclka[0] & (1 << 11) == 0 {
            return TestResult::Fail("DPCLKA must select DPLL1 for PHY B, clock off first");
        }
        if dpclka[1] & (1 << 11) != 0 {
            return TestResult::Fail("DPCLKA second write must turn PHY B's clock on");
        }
        // Transcoder B timing + PIPECONF + plane landed in B's
        // blocks.
        if mmio
            .writes_to(Transcoder::B.base() + TRANS_HTOTAL_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("Transcoder B timing not written");
        }
        let pipeconf_b = mmio.writes_to(Pipe::B.base() + PIPECONF_OFFSET);
        if pipeconf_b
            .iter()
            .all(|w| w & crate::intel_gpu_pipes::PIPECONF_ENABLE == 0)
        {
            return TestResult::Fail("Pipe B PIPECONF ENABLE never set");
        }
        let plane_b = Pipe::B.base() + PLANE_PRIMARY_OFFSET;
        if mmio.writes_to(plane_b + PLANE_CTL_OFFSET).is_empty()
            || mmio.writes_to(plane_b + PLANE_SURF_OFFSET).is_empty()
        {
            return TestResult::Fail("Pipe B plane not programmed");
        }
        // The DBUF share landed in B's watermark block.
        if mmio.writes_to(Pipe::B.base() + PLANE_BUF_CFG_OFFSET)
            != alloc::vec![crate::intel_gpu_modeset::dbuf_buf_cfg(512, 1023)]
        {
            return TestResult::Fail("Pipe B PLANE_BUF_CFG must carry the (512,1023) share");
        }
        if mmio.writes_to(Pipe::B.base() + PLANE_WM_BASE_OFFSET)
            != alloc::vec![crate::intel_gpu_modeset::plane_wm0_for_blocks(512)]
        {
            return TestResult::Fail("Pipe B PLANE_WM0 must carry the 512-block share");
        }
        // Nothing at all landed in Pipe A's pipe block or
        // Transcoder A's timing block.
        if mmio.any_write_in(Pipe::A.base(), Pipe::B.base()) {
            return TestResult::Fail("Pipe B run wrote into Pipe A's block");
        }
        if mmio.any_write_in(Transcoder::A.base(), Transcoder::B.base()) {
            return TestResult::Fail("Pipe B run wrote into Transcoder A's block");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_multipipe",
        smoke_second_pipe_modeset_run
    );
}
