//! Intel Gen12 forcewake domains — GT register access under
//! power gating.
//!
//! ## What forcewake is (and is not)
//!
//! Most of the GT register space sits behind per-block power
//! gates: when a block is asleep, reads return garbage and
//! writes are dropped. Forcewake is the driver's lever on those
//! gates — write the request bit in the domain's FORCEWAKE
//! register, wait for the hardware ack, touch registers, clear
//! the request. It is **not** the display power-well machinery
//! (HSW_PWR_WELL_CTL2 / PG1–PG5 in `intel_gpu_modeset`): display
//! wells power the display block, forcewake domains gate the
//! GT/media engine blocks. Nothing in this module touches a
//! display well, and the display paths take no forcewake.
//!
//! The domains in scope are the three aggregate Gen12 domains
//! from the queue brief (#1013): render, blitter, media. The
//! per-engine media sub-domains (VDBOX/VEBOX, Gen11+) belong to
//! the media-engines lane (#1022); the aggregate media domain
//! here covers the media G-unit surface.
//!
//! ## Register facts — sources
//!
//! Derived from the i915 uncore layer, the authoritative
//! restatement of the PRM Vol. 12 forcewake registers (the same
//! sourcing the rest of this crate uses — see
//! `intel_gpu_regions`' header):
//!
//! - `drivers/gpu/drm/i915/i915_reg.h` (Gen9-named registers,
//!   used by i915 for the Gen11/Gen12 domain table):
//!   `FORCEWAKE_BLITTER_GEN9` = 0xA188 (the legacy
//!   `FORCEWAKE_MT` register), `FORCEWAKE_MEDIA_GEN9` = 0xA270,
//!   `FORCEWAKE_RENDER_GEN9` = 0xA278;
//!   `FORCEWAKE_ACK_RENDER_GEN9` = 0x0D84,
//!   `FORCEWAKE_ACK_MEDIA_GEN9` = 0x0D88,
//!   `FORCEWAKE_ACK_BLITTER_GEN9` = 0x130044.
//! - `drivers/gpu/drm/i915/intel_uncore.c`: the request bit the
//!   kernel driver owns is `FORCEWAKE_KERNEL` = BIT(0) (BIT(1)
//!   is `FORCEWAKE_USER`, another requestor's bit in the same
//!   register — never touched here). Writes are *masked*:
//!   `fw_set` writes `_MASKED_BIT_ENABLE(v)` = `v | (v << 16)`
//!   and `fw_clear` writes `_MASKED_BIT_DISABLE(v)` = `v << 16`
//!   — the high half is the per-bit write mask, the low half the
//!   value, so one requestor never disturbs another's bits.
//!   `fw_domain_reset` clears 0xFFFF of request bits with no ack
//!   wait (engines may be fused off). The ack wait carries one
//!   documented quirk (`fw_domain_wait_ack_with_fallback`):
//!   the driver's wake request can collide with the hardware's
//!   own wake requests and the ack can be lost; the recovery is
//!   a clear→set re-kick of the request bit, then wait again.
//!   i915's ack-wait bound is `FORCEWAKE_ACK_TIMEOUT_MS` = 50.
//!
//! ## Discipline (this implementation)
//!
//! - **Refcounted holds.** Each domain has a hold count;
//!   concurrent/nested users share one hardware request. Only
//!   the 0→1 transition programs the set register + waits for
//!   the ack; only the 1→0 transition programs the clear +
//!   waits for the ack to drop. A domain can never be dropped
//!   under another holder.
//! - **No leaked hold on timeout.** If the ack never arrives
//!   (after the one documented re-kick), acquire rolls the
//!   request bit back off and returns an error with the count
//!   still zero — a later acquire starts from a clean slate.
//! - **Release errors don't wedge state.** If the ack never
//!   clears on release, the hold is still dropped (the request
//!   is off; the hardware is merely slow to gate, which is the
//!   safe direction) and the error is returned for the caller
//!   to log.
//! - **Poll-counted waits.** The ack wait is bounded in polls,
//!   not wall-clock time: one poll is one MMIO read + a spin
//!   hint, sub-µs on silicon, so [`ACK_POLL_BUDGET`] polls is
//!   ≫ i915's 50 ms at silicon read cost — while fixtures,
//!   which model ack latency in polls, stay deterministic
//!   under TCG, whose cycle counters crawl and leap (the #879
//!   lesson: fixture correctness must never depend on a
//!   clock). Production timeouts are not shrunk for TCG.
//! - **Immediate clear on last release.** i915 defers the
//!   clear by ~1 ms (hrtimer) to batch rapid get/put cycles;
//!   that is a host-OS optimisation, not hardware protocol.
//!   NARF's holds are explicit scopes, so the clear is
//!   programmed at the 1→0 transition directly.
//!
//! ## Composition
//!
//! [`Forcewake`] owns no register window — every operation
//! takes the caller's `&M: MmioWindow`, so it composes with
//! whatever window the caller already has (the RCS engine's
//! window, a production `BarWindow`, a fixture). The production
//! composition lives in `intel_gpu_rcs::submit_dwords`: the
//! default engine's state carries a `Forcewake`, sanitized at
//! attach (mirroring i915's probe-time `fw_domain_reset`), and
//! each submission runs inside a render-domain hold — the RCS0
//! register conversation (ELSP, ring registers) is exactly the
//! GT access the PRM gates on the render domain.
//! `poll_default_completions` deliberately takes **no** hold:
//! it reads the CSB from the status page, which is host memory
//! (a `GpuBacking`), not a gated register. Probe's presence
//! reads (GMD_ID) are always-on-block reads and likewise stay
//! unwrapped, as in i915's early probe.

use crate::intel_gpu_aux::MmioWindow;

// ── Register map (i915_reg.h, Gen9-named / Gen11+12 domains) ──

/// FORCEWAKE request register, blitter domain. This is the
/// legacy `FORCEWAKE_MT` register (0xA188) — on Gen9+ it is the
/// blitter domain's request register.
pub const FORCEWAKE_BLITTER: u64 = 0xA188;
/// FORCEWAKE request register, media domain (0xA270).
pub const FORCEWAKE_MEDIA: u64 = 0xA270;
/// FORCEWAKE request register, render domain (0xA278).
pub const FORCEWAKE_RENDER: u64 = 0xA278;
/// FORCEWAKE ack register, render domain (0x0D84).
pub const FORCEWAKE_ACK_RENDER: u64 = 0x0D84;
/// FORCEWAKE ack register, media domain (0x0D88).
pub const FORCEWAKE_ACK_MEDIA: u64 = 0x0D88;
/// FORCEWAKE ack register, blitter domain (0x130044).
pub const FORCEWAKE_ACK_BLITTER: u64 = 0x130044;

/// The request bit owned by the kernel driver (i915
/// `FORCEWAKE_KERNEL`). BIT(1) of the same registers is
/// `FORCEWAKE_USER`, another requestor's bit; the masked-write
/// encoding guarantees we never disturb it.
pub const FORCEWAKE_KERNEL: u32 = 1 << 0;

/// Poll budget for one ack wait (set or clear). Sized from
/// i915's `FORCEWAKE_ACK_TIMEOUT_MS` (50 ms): one poll is one
/// MMIO read + spin hint (sub-µs on silicon), so 100 000 polls
/// exceeds 50 ms of silicon read cost with wide margin, while
/// remaining a plain count fixtures can reason about exactly.
pub const ACK_POLL_BUDGET: u32 = 100_000;

/// Masked-write encoding for setting request bits (i915
/// `_MASKED_BIT_ENABLE`): value bits in the low half, their
/// write mask in the high half.
const fn masked_enable(bits: u32) -> u32 {
    bits | (bits << 16)
}

/// Masked-write encoding for clearing request bits (i915
/// `_MASKED_BIT_DISABLE`): mask in the high half, zeros below.
const fn masked_disable(bits: u32) -> u32 {
    bits << 16
}

// ── Domains ─────────────────────────────────────────────────────

/// One forcewake domain. The discriminants index the hold-count
/// array in [`Forcewake`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum FwDomain {
    /// Render engine block (RCS0 and the GT register tail).
    Render = 0,
    /// Blitter engine block (BCS0).
    Blitter = 1,
    /// Media G-unit block (aggregate media domain).
    Media = 2,
}

/// All domains, for iteration (sanitize, fixtures).
pub const FW_DOMAINS: [FwDomain; 3] = [FwDomain::Render, FwDomain::Blitter, FwDomain::Media];

impl FwDomain {
    /// Canonical short name (matches i915's domain names).
    pub const fn name(self) -> &'static str {
        match self {
            FwDomain::Render => "render",
            FwDomain::Blitter => "blitter",
            FwDomain::Media => "media",
        }
    }

    /// The domain's FORCEWAKE request register offset.
    pub const fn set_reg(self) -> u64 {
        match self {
            FwDomain::Render => FORCEWAKE_RENDER,
            FwDomain::Blitter => FORCEWAKE_BLITTER,
            FwDomain::Media => FORCEWAKE_MEDIA,
        }
    }

    /// The domain's FORCEWAKE ack register offset.
    pub const fn ack_reg(self) -> u64 {
        match self {
            FwDomain::Render => FORCEWAKE_ACK_RENDER,
            FwDomain::Blitter => FORCEWAKE_ACK_BLITTER,
            FwDomain::Media => FORCEWAKE_ACK_MEDIA,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

// ── Errors ──────────────────────────────────────────────────────

/// Forcewake failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The ack bit never set within the poll budget (after the
    /// one documented re-kick). The request was rolled back;
    /// the domain is NOT held.
    AckTimeout(FwDomain),
    /// The ack bit never cleared within the poll budget after
    /// the request was cleared. The hold IS dropped — the
    /// hardware is slow to gate, not held by us.
    AckClearTimeout(FwDomain),
    /// `release` on a domain with no outstanding hold. No
    /// register traffic was generated.
    NotHeld(FwDomain),
    /// Hold count would overflow `u32` — a caller bug (nesting
    /// is bounded by construction at every real call site).
    RefcountOverflow(FwDomain),
}

// ── The domain manager ──────────────────────────────────────────

/// Per-domain forcewake hold counts. Owns no window: every
/// operation takes the caller's [`MmioWindow`], so one
/// `Forcewake` composes with any register path that needs it.
///
/// Not internally synchronized — the owner serializes access
/// (in production, the RCS state lock; a future media engine
/// carries its own). That matches how i915 funnels forcewake
/// through the uncore lock.
#[derive(Debug)]
pub struct Forcewake {
    counts: [u32; FW_DOMAINS.len()],
}

impl Default for Forcewake {
    fn default() -> Self {
        Self::new()
    }
}

impl Forcewake {
    /// A fresh manager: no holds, no register traffic yet (the
    /// hardware side is reconciled by [`Forcewake::sanitize`]
    /// at attach time).
    pub const fn new() -> Self {
        Self {
            counts: [0; FW_DOMAINS.len()],
        }
    }

    /// Outstanding holds on `domain`.
    pub fn count(&self, domain: FwDomain) -> u32 {
        self.counts[domain.index()]
    }

    /// `true` while at least one hold keeps `domain` awake.
    pub fn is_held(&self, domain: FwDomain) -> bool {
        self.count(domain) > 0
    }

    /// Probe-time reset, mirroring i915's `fw_domain_reset`:
    /// masked-clear *all* request bits in every domain (any
    /// state firmware left behind) and zero the hold counts.
    /// No ack waits — a domain's power well may not exist
    /// (fused-off engines), so nothing may wait on it here.
    pub fn sanitize<M: MmioWindow>(&mut self, regs: &M) {
        for domain in FW_DOMAINS {
            regs.write32(domain.set_reg(), masked_disable(0xFFFF));
        }
        self.counts = [0; FW_DOMAINS.len()];
    }

    /// Take a hold on `domain`. Nested acquires only bump the
    /// count — the hardware conversation happens once, at the
    /// 0→1 transition: masked-enable `FORCEWAKE_KERNEL`, then
    /// poll the ack bit until it sets (one clear→set re-kick
    /// if the first wait loses the ack, per the documented
    /// hardware quirk). On final timeout the request is rolled
    /// back and the count stays zero.
    pub fn acquire<M: MmioWindow>(&mut self, regs: &M, domain: FwDomain) -> Result<(), FwError> {
        let idx = domain.index();
        if self.counts[idx] > 0 {
            self.counts[idx] = self.counts[idx]
                .checked_add(1)
                .ok_or(FwError::RefcountOverflow(domain))?;
            return Ok(());
        }
        // 0→1: program the request.
        regs.write32(domain.set_reg(), masked_enable(FORCEWAKE_KERNEL));
        if !wait_ack(regs, domain.ack_reg(), true) {
            // Lost-ack quirk (intel_uncore.c): the driver's
            // request can collide with the hardware's own wake
            // requests and the ack is never delivered. Toggle
            // the request once to kick the state machine, then
            // wait again.
            regs.write32(domain.set_reg(), masked_disable(FORCEWAKE_KERNEL));
            regs.write32(domain.set_reg(), masked_enable(FORCEWAKE_KERNEL));
            if !wait_ack(regs, domain.ack_reg(), true) {
                // Roll back: leave no request behind, hold
                // nothing.
                regs.write32(domain.set_reg(), masked_disable(FORCEWAKE_KERNEL));
                return Err(FwError::AckTimeout(domain));
            }
        }
        self.counts[idx] = 1;
        Ok(())
    }

    /// Drop one hold on `domain`. Only the 1→0 transition
    /// touches hardware: masked-disable `FORCEWAKE_KERNEL`,
    /// then poll the ack bit until it clears. An ack-clear
    /// timeout is reported but the hold is still dropped (see
    /// the module header).
    pub fn release<M: MmioWindow>(&mut self, regs: &M, domain: FwDomain) -> Result<(), FwError> {
        let idx = domain.index();
        if self.counts[idx] == 0 {
            return Err(FwError::NotHeld(domain));
        }
        self.counts[idx] -= 1;
        if self.counts[idx] > 0 {
            return Ok(());
        }
        // 1→0: program the clear.
        regs.write32(domain.set_reg(), masked_disable(FORCEWAKE_KERNEL));
        if !wait_ack(regs, domain.ack_reg(), false) {
            return Err(FwError::AckClearTimeout(domain));
        }
        Ok(())
    }

    /// Run `f` inside a hold on `domain`: acquire, run, release
    /// (the release runs even though `f` is infallible — holds
    /// are scopes, not results). A release failure after a
    /// successful acquire surfaces as the error; the state is
    /// consistent either way (see [`Forcewake::release`]).
    pub fn with_domain<M: MmioWindow, R>(
        &mut self,
        regs: &M,
        domain: FwDomain,
        f: impl FnOnce() -> R,
    ) -> Result<R, FwError> {
        self.acquire(regs, domain)?;
        let out = f();
        self.release(regs, domain)?;
        Ok(out)
    }
}

/// Poll `ack_reg` until its `FORCEWAKE_KERNEL` bit equals
/// `want_set`, bounded by [`ACK_POLL_BUDGET`] polls. The first
/// read doubles as the posting read for the request write that
/// precedes the wait.
fn wait_ack<M: MmioWindow>(regs: &M, ack_reg: u64, want_set: bool) -> bool {
    let mut polls = 0u32;
    loop {
        let acked = regs.read32(ack_reg) & FORCEWAKE_KERNEL != 0;
        if acked == want_set {
            return true;
        }
        polls += 1;
        if polls >= ACK_POLL_BUDGET {
            return false;
        }
        core::hint::spin_loop();
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the forcewake conversation. The fake is a
    //! model of the *hardware side* of the PRM conversation,
    //! built from the register semantics in the module header —
    //! masked writes against the request registers, ack bits
    //! that follow the request after a programmable number of
    //! ack-register polls — not a recording of what the driver
    //! happens to do. Expected write values in the assertions
    //! are hand-derived literals from the masked-encoding rule.

    use super::*;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Fake hardware ───────────────────────────────────────

    /// Hardware model state for one domain.
    #[derive(Clone)]
    struct FakeDomain {
        /// Current request-register value (masked writes applied).
        set_val: u32,
        /// Current ack bit (what the ack register reports).
        ack: bool,
        /// Ack value the hardware is converging to.
        ack_target: bool,
        /// Ack-register polls remaining before `ack` follows
        /// `ack_target`.
        ack_pending: u32,
        /// Polls of latency the hardware applies to ack changes.
        ack_delay: u32,
        /// Fault injection: the ack never sets.
        stuck_set: bool,
        /// Fault injection: the ack never clears.
        stuck_clear: bool,
    }

    impl FakeDomain {
        fn new() -> Self {
            Self {
                set_val: 0,
                ack: false,
                ack_target: false,
                ack_pending: 0,
                ack_delay: 0,
                stuck_set: false,
                stuck_clear: false,
            }
        }
    }

    /// A fake MMIO window modelling the forcewake hardware
    /// conversation. Writes apply the PRM masked-write rule;
    /// reads of an ack register advance that domain's ack
    /// convergence by one poll.
    #[derive(Clone)]
    struct FakeFw {
        domains: Rc<RefCell<[FakeDomain; 3]>>,
        writes: Rc<RefCell<Vec<(u64, u32)>>>,
        reads: Rc<RefCell<Vec<u64>>>,
    }

    impl FakeFw {
        fn new() -> Self {
            Self {
                domains: Rc::new(RefCell::new([
                    FakeDomain::new(),
                    FakeDomain::new(),
                    FakeDomain::new(),
                ])),
                writes: Rc::new(RefCell::new(Vec::new())),
                reads: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn with_domain(&self, domain: FwDomain, f: impl FnOnce(&mut FakeDomain)) {
            f(&mut self.domains.borrow_mut()[domain.index()]);
        }

        fn set_ack_delay(&self, domain: FwDomain, polls: u32) {
            self.with_domain(domain, |d| d.ack_delay = polls);
        }

        fn writes(&self) -> Vec<(u64, u32)> {
            self.writes.borrow().clone()
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn ack_reads(&self) -> usize {
            self.reads.borrow().len()
        }

        /// The request bit as the hardware currently holds it.
        fn request_bit(&self, domain: FwDomain) -> bool {
            self.domains.borrow()[domain.index()].set_val & FORCEWAKE_KERNEL != 0
        }
    }

    impl MmioWindow for FakeFw {
        fn read32(&self, off: u64) -> u32 {
            self.reads.borrow_mut().push(off);
            for domain in FW_DOMAINS {
                if off == domain.ack_reg() {
                    let mut domains = self.domains.borrow_mut();
                    let d = &mut domains[domain.index()];
                    if d.ack_pending > 0 {
                        d.ack_pending -= 1;
                    } else {
                        d.ack = d.ack_target;
                    }
                    return if d.ack { FORCEWAKE_KERNEL } else { 0 };
                }
            }
            // Non-ack reads: report the raw request register for
            // set registers, zero elsewhere.
            for domain in FW_DOMAINS {
                if off == domain.set_reg() {
                    return self.domains.borrow()[domain.index()].set_val;
                }
            }
            0
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            for domain in FW_DOMAINS {
                if off == domain.set_reg() {
                    let mut domains = self.domains.borrow_mut();
                    let d = &mut domains[domain.index()];
                    // PRM masked-write rule: high half is the
                    // per-bit write mask, low half the value.
                    let mask = val >> 16;
                    d.set_val = (d.set_val & !mask) | (val & mask);
                    let want = d.set_val & FORCEWAKE_KERNEL != 0;
                    if want != d.ack_target {
                        let frozen = (want && d.stuck_set) || (!want && d.stuck_clear);
                        if !frozen {
                            d.ack_target = want;
                            d.ack_pending = d.ack_delay;
                        }
                    }
                }
            }
        }
    }

    // ── Fixtures ────────────────────────────────────────────

    fn smoke_register_map_pinned() -> TestResult {
        // Hand-pinned from i915_reg.h (Gen9-named registers,
        // Gen11/12 domain table) — see the module header.
        if FORCEWAKE_RENDER != 0xA278 || FORCEWAKE_MEDIA != 0xA270 || FORCEWAKE_BLITTER != 0xA188 {
            return TestResult::Fail("FORCEWAKE request register offsets diverge from i915_reg.h");
        }
        if FORCEWAKE_ACK_RENDER != 0x0D84
            || FORCEWAKE_ACK_MEDIA != 0x0D88
            || FORCEWAKE_ACK_BLITTER != 0x130044
        {
            return TestResult::Fail("FORCEWAKE ack register offsets diverge from i915_reg.h");
        }
        if FORCEWAKE_KERNEL != 1 {
            return TestResult::Fail("FORCEWAKE_KERNEL must be BIT(0)");
        }
        // Request and ack registers are distinct per domain,
        // and no two domains share a register.
        for (i, a) in FW_DOMAINS.iter().enumerate() {
            for b in FW_DOMAINS.iter().skip(i + 1) {
                if a.set_reg() == b.set_reg() || a.ack_reg() == b.ack_reg() {
                    return TestResult::Fail("forcewake domains must not share registers");
                }
            }
            if a.set_reg() == a.ack_reg() {
                return TestResult::Fail("a domain's set and ack registers must differ");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_forcewake", smoke_register_map_pinned);

    fn smoke_acquire_release_conversation() -> TestResult {
        // The full hardware conversation, pinned write-for-write:
        // masked-enable 0x0001_0001 → ack → (access) →
        // masked-disable 0x0001_0000 → ack clear.
        let fake = FakeFw::new();
        fake.set_ack_delay(FwDomain::Render, 3);
        let mut fw = Forcewake::new();

        if fw.acquire(&fake, FwDomain::Render).is_err() {
            return TestResult::Fail("acquire(render) failed against a healthy fake");
        }
        if !fw.is_held(FwDomain::Render) || fw.count(FwDomain::Render) != 1 {
            return TestResult::Fail("render hold not recorded after acquire");
        }
        if !fake.request_bit(FwDomain::Render) {
            return TestResult::Fail("hardware request bit not set after acquire");
        }
        if fake.writes() != [(FORCEWAKE_RENDER, 0x0001_0001)] {
            return TestResult::Fail("acquire must write exactly masked_enable(KERNEL) once");
        }

        if fw.release(&fake, FwDomain::Render).is_err() {
            return TestResult::Fail("release(render) failed against a healthy fake");
        }
        if fw.is_held(FwDomain::Render) {
            return TestResult::Fail("render still held after release");
        }
        if fake.request_bit(FwDomain::Render) {
            return TestResult::Fail("hardware request bit not cleared after release");
        }
        if fake.writes()
            != [
                (FORCEWAKE_RENDER, 0x0001_0001),
                (FORCEWAKE_RENDER, 0x0001_0000),
            ]
        {
            return TestResult::Fail("release must append exactly masked_disable(KERNEL)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_acquire_release_conversation
    );

    fn smoke_nested_acquire_single_request() -> TestResult {
        // Three nested holds program the request exactly once;
        // the domain stays up until the LAST release.
        let fake = FakeFw::new();
        let mut fw = Forcewake::new();
        for _ in 0..3 {
            if fw.acquire(&fake, FwDomain::Media).is_err() {
                return TestResult::Fail("nested acquire(media) failed");
            }
        }
        if fw.count(FwDomain::Media) != 3 {
            return TestResult::Fail("nested holds not counted");
        }
        if fake.writes_to(FORCEWAKE_MEDIA) != [0x0001_0001] {
            return TestResult::Fail("nested acquires must not re-program the request");
        }
        for _ in 0..2 {
            if fw.release(&fake, FwDomain::Media).is_err() {
                return TestResult::Fail("nested release(media) failed");
            }
        }
        if !fw.is_held(FwDomain::Media) || !fake.request_bit(FwDomain::Media) {
            return TestResult::Fail("domain dropped while a hold remained");
        }
        if fake.writes_to(FORCEWAKE_MEDIA).len() != 1 {
            return TestResult::Fail("clear programmed before the last release");
        }
        if fw.release(&fake, FwDomain::Media).is_err() {
            return TestResult::Fail("final release(media) failed");
        }
        if fake.writes_to(FORCEWAKE_MEDIA) != [0x0001_0001, 0x0001_0000] {
            return TestResult::Fail("final release must program the clear exactly once");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_nested_acquire_single_request
    );

    fn smoke_ack_timeout_rolls_back() -> TestResult {
        // Ack never arrives: acquire must fail, roll the
        // request back off (after the one documented re-kick),
        // and leave NO leaked hold — a later acquire against a
        // healthy domain starts clean.
        let fake = FakeFw::new();
        fake.with_domain(FwDomain::Render, |d| d.stuck_set = true);
        let mut fw = Forcewake::new();

        match fw.acquire(&fake, FwDomain::Render) {
            Err(FwError::AckTimeout(FwDomain::Render)) => {}
            _ => return TestResult::Fail("acquire with a stuck ack must return AckTimeout"),
        }
        if fw.is_held(FwDomain::Render) || fw.count(FwDomain::Render) != 0 {
            return TestResult::Fail("timed-out acquire leaked a hold");
        }
        if fake.request_bit(FwDomain::Render) {
            return TestResult::Fail("timed-out acquire left the request bit set");
        }
        // Exact write sequence: set, re-kick (clear + set),
        // rollback clear.
        if fake.writes_to(FORCEWAKE_RENDER) != [0x0001_0001, 0x0001_0000, 0x0001_0001, 0x0001_0000]
        {
            return TestResult::Fail("timeout path must be set → re-kick → rollback");
        }
        // No leaked state: unstick and the same manager acquires.
        fake.with_domain(FwDomain::Render, |d| d.stuck_set = false);
        if fw.acquire(&fake, FwDomain::Render).is_err() || !fw.is_held(FwDomain::Render) {
            return TestResult::Fail("acquire after a rolled-back timeout must succeed");
        }
        if fw.release(&fake, FwDomain::Render).is_err() {
            return TestResult::Fail("release after recovery failed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_ack_timeout_rolls_back
    );

    fn smoke_ack_clear_timeout_drops_hold() -> TestResult {
        // The ack never clears on release: the error is
        // reported, but the hold is dropped (request off,
        // count zero) — the state machine is not wedged.
        let fake = FakeFw::new();
        let mut fw = Forcewake::new();
        if fw.acquire(&fake, FwDomain::Blitter).is_err() {
            return TestResult::Fail("acquire(blitter) failed");
        }
        fake.with_domain(FwDomain::Blitter, |d| d.stuck_clear = true);
        match fw.release(&fake, FwDomain::Blitter) {
            Err(FwError::AckClearTimeout(FwDomain::Blitter)) => {}
            _ => return TestResult::Fail("release with a stuck ack must return AckClearTimeout"),
        }
        if fw.is_held(FwDomain::Blitter) || fw.count(FwDomain::Blitter) != 0 {
            return TestResult::Fail("ack-clear timeout must still drop the hold");
        }
        if fake.request_bit(FwDomain::Blitter) {
            return TestResult::Fail("request bit must be off after release");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_ack_clear_timeout_drops_hold
    );

    fn smoke_release_without_hold() -> TestResult {
        let fake = FakeFw::new();
        let mut fw = Forcewake::new();
        match fw.release(&fake, FwDomain::Render) {
            Err(FwError::NotHeld(FwDomain::Render)) => {}
            _ => return TestResult::Fail("release without a hold must return NotHeld"),
        }
        if !fake.writes().is_empty() {
            return TestResult::Fail("NotHeld release must not generate register traffic");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_release_without_hold
    );

    fn smoke_domains_independent() -> TestResult {
        // Masking-defeating case: all three domains live at
        // once; releasing one disturbs neither the other
        // domains' request bits nor their hold counts.
        let fake = FakeFw::new();
        let mut fw = Forcewake::new();
        for domain in FW_DOMAINS {
            if fw.acquire(&fake, domain).is_err() {
                return TestResult::Fail("acquire of a domain failed");
            }
        }
        if fw.release(&fake, FwDomain::Media).is_err() {
            return TestResult::Fail("release(media) failed");
        }
        if fake.request_bit(FwDomain::Media) {
            return TestResult::Fail("media request bit survived its release");
        }
        if !fake.request_bit(FwDomain::Render) || !fake.request_bit(FwDomain::Blitter) {
            return TestResult::Fail("media release disturbed another domain's request");
        }
        if !fw.is_held(FwDomain::Render)
            || !fw.is_held(FwDomain::Blitter)
            || fw.is_held(FwDomain::Media)
        {
            return TestResult::Fail("hold counts not independent across domains");
        }
        // The media register saw exactly its own conversation;
        // render/blitter saw only their sets.
        if fake.writes_to(FORCEWAKE_MEDIA) != [0x0001_0001, 0x0001_0000]
            || fake.writes_to(FORCEWAKE_RENDER) != [0x0001_0001]
            || fake.writes_to(FORCEWAKE_BLITTER) != [0x0001_0001]
        {
            return TestResult::Fail("per-domain write streams are not independent");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_forcewake", smoke_domains_independent);

    fn smoke_sanitize_clears_all() -> TestResult {
        // Firmware left request bits behind (including another
        // requestor's USER bit): sanitize masked-clears all
        // request bits in all domains, zeroes counts, and
        // performs no ack reads (nothing may wait at probe).
        let fake = FakeFw::new();
        for domain in FW_DOMAINS {
            fake.with_domain(domain, |d| d.set_val = 0x0000_FFFF);
        }
        let mut fw = Forcewake::new();
        fw.sanitize(&fake);
        for domain in FW_DOMAINS {
            if fake.request_bit(domain) || fake.domains.borrow()[domain.index()].set_val != 0 {
                return TestResult::Fail("sanitize left request state behind");
            }
            if fw.count(domain) != 0 {
                return TestResult::Fail("sanitize left a hold count behind");
            }
        }
        if fake.writes().len() != 3 {
            return TestResult::Fail("sanitize must write exactly one clear per domain");
        }
        for (off, val) in fake.writes() {
            if val != 0xFFFF_0000 {
                return TestResult::Fail("sanitize clear must be masked_disable(0xFFFF)");
            }
            let _ = off;
        }
        if fake.ack_reads() != 0 {
            return TestResult::Fail("sanitize must not read ack registers");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_forcewake", smoke_sanitize_clears_all);

    fn smoke_with_domain_scope_and_order() -> TestResult {
        // The scoped composition: the forcewake request write
        // precedes the first gated-register access inside the
        // scope, the clear follows the last one. The gated
        // access here is a write to the RCS0 ring tail register
        // (render domain), standing in for the engine's MMIO
        // conversation.
        let fake = FakeFw::new();
        let mut fw = Forcewake::new();
        let ring_tail = crate::intel_gpu_rcs::RING_TAIL;
        let out = fw.with_domain(&fake, FwDomain::Render, || {
            fake.write32(ring_tail, 0x40);
            42u32
        });
        match out {
            Ok(42) => {}
            _ => return TestResult::Fail("with_domain must return the closure's value"),
        }
        if fw.is_held(FwDomain::Render) {
            return TestResult::Fail("with_domain left the domain held");
        }
        let writes = fake.writes();
        if writes
            != [
                (FORCEWAKE_RENDER, 0x0001_0001),
                (ring_tail, 0x40),
                (FORCEWAKE_RENDER, 0x0001_0000),
            ]
        {
            return TestResult::Fail("forcewake set/clear must bracket the gated access");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_forcewake",
        smoke_with_domain_scope_and_order
    );
}
