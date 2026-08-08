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
//! No-op unless the PKS backend is live. AMD PCID and aarch64 MTE
//! confinement are deferred (see `bpf/specification/domain-confinement.md`
//! §8), so on those platforms execution is unconfined exactly as before.

/// An active confinement scope. While it lives, supervisor data accesses
/// are gated to the FRAME and BPF domains; [`Drop`] restores the prior
/// protection-key rights.
#[derive(Debug)]
#[must_use = "confinement ends the moment the guard is dropped"]
pub struct Confined {
    /// The PKRS to restore on exit, or `None` when PKS is not the live
    /// backend (then this guard is inert).
    #[cfg(target_arch = "x86_64")]
    saved: Option<narf_arch::x86_64::pks::SavedPkrs>,
}

/// Enter the BPF domain for the lifetime of the returned guard.
///
/// Cheap: one `RDMSR` + one `WRMSR` on x86_64 (no TLB effect), and a plain
/// construction when PKS is inactive.
#[inline]
pub fn enter() -> Confined {
    #[cfg(target_arch = "x86_64")]
    {
        use narf_arch::x86_64::pks;
        use narf_lib::id::DomainId;
        if pks::is_active() {
            // SAFETY: `is_active()` reports CR4.PKS=1, and BPF runs at
            // CPL0. `enter_domain` keeps FRAME reachable (so our own
            // stack, the kfunc shims, and the fault handler still work)
            // and denies every domain except FRAME and BPF.
            let saved = unsafe { pks::enter_domain(DomainId::FRAME.raw(), DomainId::BPF.raw()) };
            return Confined { saved: Some(saved) };
        }
        Confined { saved: None }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // MTE confinement is deferred; execution is unconfined.
        Confined {}
    }
}

impl Drop for Confined {
    #[inline]
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(saved) = self.saved {
            // SAFETY: `saved` is the value the matching `enter_domain`
            // returned; still CPL0 with CR4.PKS set.
            unsafe {
                narf_arch::x86_64::pks::exit_domain(saved);
            }
        }
    }
}
