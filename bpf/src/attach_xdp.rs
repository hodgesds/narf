//! XDP attach — a BPF program ahead of the network bypass table.
//!
//! `net/src/bypass/classifier.rs` has named this seam since it was written
//! ("a future eBPF surface would feed the same table"). This is that surface.
//!
//! ## Two limitations, both structural and both recorded
//!
//! **The frame is read-only.** Linux's XDP programs rewrite headers and can
//! return `XDP_TX` or `XDP_REDIRECT`. Those need a `&mut [u8]` frame, which
//! means widening `narf_net::iface::RxHandler` and every driver RX path feeding
//! it — virtio-net and e1000 both hand over an immutable borrow of a DMA buffer
//! today. Deferred deliberately; `Pass`/`Drop` is what filtering and
//! drop-based mitigation need, and it is reached without touching a driver.
//!
//! **Frame reads are dynamically bounded.** Context words 0 and 1 are the
//! frame's `data` and exclusive `data_end` pointers. A program must compare a
//! derived data pointer against that paired end before dereferencing it; the
//! verifier turns only the safe edge into a native bare-access certificate,
//! and the interpreter independently confines reads to this exact slice.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use narf_net::bypass::classifier::{install_xdp, remove_xdp, XdpAction, XdpProgram};

use crate::prog::BpfProg;

/// A loaded program dispatching as an [`XdpProgram`].
#[derive(Debug)]
pub struct BpfXdp {
    prog: Arc<BpfProg>,
    name: String,
}

impl BpfXdp {
    /// Construct one directly, for the smokes.
    ///
    /// The attach path goes through [`attach`], which is cap-gated; a test that
    /// had to mint a capability to check the *dispatch* logic would be testing
    /// two things at once.
    #[must_use]
    pub fn for_test(prog: Arc<BpfProg>, name: &str) -> Self {
        Self {
            prog,
            name: String::from(name),
        }
    }
}

impl XdpProgram for BpfXdp {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, _iface: &str, frame: &[u8]) -> XdpAction {
        // Only a program that *returned* decides. `Outcome::value()` is 0 for a
        // trap, so matching on it treated every trap as an unknown action and
        // therefore dropped the frame — the exact opposite of the policy stated
        // here, and severe: an unbounded loop verifies (fuel bounds it at
        // runtime), so a program that exhausts fuel would have silently dropped
        // *every frame on the interface*.
        match self.prog.run_xdp(frame) {
            // Linux's XDP_PASS is 2 and XDP_DROP is 1; matching those keeps a
            // program written against Linux's constants behaving the same way.
            Some(crate::interp::Outcome::Returned(v)) => match v {
                1 => XdpAction::Drop,
                2 => XdpAction::Pass,
                // Any other *returned* value is a program bug. Linux treats an
                // unknown action as XDP_ABORTED, and so does this — dropping
                // while counting it, so a broken program is visible rather than
                // silently passing everything.
                _ => XdpAction::Aborted,
            },
            // Trapped, or declined by the stack provider: pass the frame.
            // Dropping traffic because a filter could not run would turn a
            // resource limit into a network outage.
            Some(crate::interp::Outcome::Trapped(_)) | None => XdpAction::Pass,
        }
    }
}

/// Attach `prog` to `iface` ahead of the bypass table.
///
/// # Errors
///
/// Propagates `narf_net`'s error if the capability is not live.
pub fn attach(
    cap: &narf_capabilities::Cap<crate::prog::BpfAttach, narf_capabilities::Grant>,
    iface: String,
    prog: Arc<BpfProg>,
) -> Result<(), narf_net::bypass::classifier::ClassifyError> {
    // Spec §4.5: the hook's execution context is part of its type, and an XDP
    // hook is `Atomic`. `attach_probe` has always checked this; this path did
    // not, and the consequence was worse than a missing diagnostic.
    //
    // `BpfXdp::run` calls the type-specific `run_xdp`, which returns `None` for
    // a program verified for `Sleepable` — and `None` means "pass the frame" (declining
    // traffic because a filter could not run would turn a resource limit into a
    // network outage). So a sleepable program installed as an XDP filter
    // succeeded, then **failed open on every frame**: the interface looks
    // filtered and is not.
    if prog.context() != narf_bpf_verifier::Context::Atomic
        || prog.linux_prog_type() != Some(crate::prog::BPF_PROG_TYPE_XDP)
    {
        return Err(narf_net::bypass::classifier::ClassifyError::WrongContext);
    }
    let name = iface.clone();
    install_xdp(cap, iface, Box::new(BpfXdp { prog, name }))
}

/// Detach whatever program is on `iface`. Returns whether one was removed.
///
/// The mirror of [`attach`], and here rather than at the call sites so that the
/// two cannot disagree about which capability the classifier wants: `remove_xdp`
/// is generic over the cap type and checks the *kind* at run time, so passing
/// the wrong one is a run-time `WrongCapKind` rather than a compile error.
/// Naming `Cap<BpfAttach, Grant>` in this signature is what turns it back into
/// one.
///
/// # Errors
///
/// Propagates `narf_net`'s error if the capability is not live.
pub fn detach(
    cap: &narf_capabilities::Cap<crate::prog::BpfAttach, narf_capabilities::Grant>,
    iface: &str,
) -> Result<bool, narf_net::bypass::classifier::ClassifyError> {
    remove_xdp(cap, iface)
}
