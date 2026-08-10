//! BPF hardware-domain confinement.
//!
//! Runs a program's execution inside the BPF PKS domain
//! ([`DomainId::BPF`]) via the framekernel's `enter_domain` primitive.
//! FRAME (domain 0) stays reachable, so the interpreter's own stack, the
//! kfunc shims, the maps on the kernel heap, and — critically — the `#PF`
//! handler all keep working; every *other* subsystem's domain (the
//! capability table, the scheduler, the driver domains) is denied. A
//! verifier or JIT escape that stores outside the program's own memory
//! into one of those domains takes a protection-key `#PF` instead of
//! corrupting it. That is hardware defense-in-depth *under* the verifier:
//! today a verified-but-wrong program is an arbitrary-Ring-0 primitive;
//! confined, its blast radius is the domains `enter_domain` leaves open.
//!
//! FRAME stays read-*write*, not read-only: a read-only FRAME would fault
//! the interpreter's own stack writes and the `#PF` handler's, cascading
//! to a triple fault. Protection of a subsystem's state therefore comes
//! from that subsystem tagging its pages into its own domain (so they are
//! not FRAME); the fence denies those domains to BPF. The strength grows
//! as that tagging lands — the mechanism here is complete regardless.
//!
//! Backed by whichever hardware domain primitive the platform provides.
//! On x86_64 that is **PKS** (Intel SPR+, per-page protection keys) or, when
//! PKS is absent, **PCID** (AMD / pre-SPR Intel), which swaps `CR3` to the BPF
//! domain's PML4 on entry — a byte-clone of the bootstrap tables, so every BPF
//! kernel-VA region (per-CPU stack, arena, JIT text) stays mapped, while the
//! domain's private VA range is its own. On aarch64 that is **MTE**, currently a
//! structural `SCTLR_EL1`/`GCR_EL1` save (real tag-fault enforcement pairs with
//! the MTE-tag-aware allocator, a Stage-3 task). Each is entered through the
//! same unified `enter_domain` seam. Where no primitive is live the guard is
//! inert and execution is unconfined exactly as before. As with PKS, the
//! *mechanism* is complete on every backend; the isolation *strength* grows as
//! subsystems move their state into private domains.

/// An active confinement scope. While it lives, supervisor data accesses
/// are gated to the FRAME and BPF domains; [`Drop`] restores the prior
/// protection-key rights.
#[derive(Debug)]
#[must_use = "confinement ends the moment the guard is dropped"]
pub struct Confined {
    /// The saved domain state to restore on exit, or `None` when no backend is
    /// live (then this guard is inert). On x86_64 the unified `Pks` enforcer's
    /// `SavedState` opaquely carries either a PKRS value (PKS) or a `CR3` value
    /// (PCID); on aarch64 it is the saved `SCTLR_EL1`/`GCR_EL1`.
    #[cfg(target_arch = "x86_64")]
    saved: Option<narf_arch::x86_64::pks::SavedPkrs>,
    #[cfg(target_arch = "aarch64")]
    saved: Option<narf_arch::aarch64::mte::SavedMteState>,
}

/// Enter the BPF domain for the lifetime of the returned guard.
///
/// Cheap: one `RDMSR` + one `WRMSR` under PKS (no TLB effect), a single
/// `CR3` swap with the no-flush bit under PCID, a pair of system-register
/// reads under MTE, and a plain construction when no backend is live.
#[inline]
pub fn enter() -> Confined {
    #[cfg(target_arch = "x86_64")]
    {
        use narf_arch::x86_64::{pcid, pks, Pks};
        use narf_arch::DomainPrimitive;
        use narf_lib::id::DomainId;
        // PKS (SPR+) or PCID (AMD / pre-SPR) — `Pks::enter_domain` dispatches
        // between them. Only pay for it when one is actually live, so an
        // unconfined platform constructs an inert guard and nothing more.
        if pks::is_active() || pcid::is_active() {
            // SAFETY: BPF runs at CPL0. `Pks::enter_domain` keeps FRAME
            // reachable under PKS (so the interpreter stack, kfunc shims, and
            // `#PF` handler still work) or swaps `CR3` to the BPF domain's PML4
            // under PCID (a bootstrap byte-clone, so every BPF kernel-VA region
            // stays mapped). Balanced by `Pks::exit_domain` in `Drop`.
            let saved = unsafe { Pks::enter_domain(DomainId::FRAME.raw(), DomainId::BPF.raw()) };
            return Confined { saved: Some(saved) };
        }
        Confined { saved: None }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use narf_arch::aarch64::{mte, Mte};
        use narf_arch::DomainPrimitive;
        use narf_lib::id::DomainId;
        if mte::supported() {
            // SAFETY: BPF runs at EL1 and MTE is present. `Mte::enter_domain` is
            // a structural `SCTLR_EL1`/`GCR_EL1` save today (real tag-fault
            // enforcement pairs with the MTE-tag-aware allocator, a Stage-3
            // task); balanced by `Mte::exit_domain` in `Drop`.
            let saved = unsafe { Mte::enter_domain(DomainId::FRAME.raw(), DomainId::BPF.raw()) };
            return Confined { saved: Some(saved) };
        }
        Confined { saved: None }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // No domain primitive on this target; execution is unconfined.
        Confined {}
    }
}

impl Drop for Confined {
    #[inline]
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(saved) = self.saved {
            use narf_arch::DomainPrimitive;
            // SAFETY: `saved` is the value the matching `enter_domain` returned;
            // still CPL0 on the same backend that produced it.
            unsafe {
                narf_arch::x86_64::Pks::exit_domain(saved);
            }
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(saved) = self.saved {
            use narf_arch::DomainPrimitive;
            // SAFETY: `saved` is the value the matching `enter_domain` returned;
            // still EL1 with MTE present.
            unsafe {
                narf_arch::aarch64::Mte::exit_domain(saved);
            }
        }
    }
}
