//! XDP attach — a BPF program ahead of the network bypass table.
//!
//! `net/src/bypass/classifier.rs` has named this seam since it was written
//! ("a future eBPF surface would feed the same table"). This is that surface.
//!
//! ## Two limitations, both structural and both recorded
//!
//! **The frame is read-only.** `XDP_TX` and `XDP_REDIRECT` *are* supported, but
//! only as retransmission of the **unmodified** frame — reflect it back out the
//! ingress iface (`XDP_TX`), or send it out a program-chosen one
//! (`XDP_REDIRECT`, target ifindex conveyed through the `bpf_redirect` kfunc in
//! [`crate::kfuncs`]). What is deferred is in-place *mutation*: Linux's XDP
//! programs also rewrite headers and `bpf_xdp_adjust_head`, which need a
//! `&mut [u8]` frame, which means widening `narf_net::iface::RxHandler` and
//! every driver RX path feeding it — virtio-net and e1000 both hand over an
//! immutable borrow of a DMA buffer today. `devmap`/`cpumap` fan-out
//! (`BPF_F_BROADCAST`) is likewise a follow-on.
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
        // Drop any redirect target a prior frame's `bpf_redirect` left on this
        // CPU: a program that calls `bpf_redirect` and then returns something
        // other than 4 must not have that ifindex leak into the *next* frame
        // that returns 4. Cleared before the run and consumed (swap-to-clear)
        // on a return of 4, so the slot holds a live request for at most the
        // window between this program's `bpf_redirect` call and its return.
        crate::kfuncs::clear_xdp_redirect_target();
        // Only a program that *returned* decides. `Outcome::value()` is 0 for a
        // trap, so matching on it treated every trap as an unknown action and
        // therefore dropped the frame — the exact opposite of the policy stated
        // here, and severe: an unbounded loop verifies (fuel bounds it at
        // runtime), so a program that exhausts fuel would have silently dropped
        // *every frame on the interface*.
        match self.prog.run_xdp(frame) {
            // Linux's XDP action constants: DROP=1, PASS=2, TX=3, REDIRECT=4.
            // Matching those keeps a program written against Linux's constants
            // behaving the same way.
            Some(crate::interp::Outcome::Returned(v)) => match v {
                1 => XdpAction::Drop,
                2 => XdpAction::Pass,
                // Reflect the unmodified frame out the ingress iface.
                3 => XdpAction::Tx,
                // Redirect: the target ifindex is whatever `bpf_redirect`
                // stashed for this frame on this CPU. A bare `return 4` with no
                // preceding `bpf_redirect` has no target — treat that as
                // `Aborted` (a redirect with nowhere to go is a program bug),
                // matching Linux, where `XDP_REDIRECT` without a prior helper
                // that primed the redirect info is dropped as an error.
                4 => match crate::kfuncs::take_xdp_redirect_target() {
                    Some(ifindex) => XdpAction::Redirect { ifindex },
                    None => XdpAction::Aborted,
                },
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
