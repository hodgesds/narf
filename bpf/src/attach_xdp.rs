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
//! **A program cannot read frame bytes through a pointer.** The verifier
//! rejects dereferencing anything but the frame pointer and the context
//! (`fixpoint.rs`'s `PtrClass` rules, and `jit_glue`'s gate 5), and there is no
//! packet-pointer class yet. So the frame is *summarised into the context
//! tuple*: length, then the first 24 bytes as three little-endian words. That
//! is enough to match on destination MAC prefix and EtherType — the bulk of
//! real filtering — and nothing more. A `PtrClass::Packet` with verifier-proved
//! bounds is what lifts it, and is the same work an arena or map-value pointer
//! needs.
//!
//! Summarising rather than pretending is the point: a program that *looks* like
//! it has a packet pointer but silently sees zeroes would be worse than one
//! whose context says exactly what it gets.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use narf_net::bypass::classifier::{install_xdp, remove_xdp, XdpAction, XdpProgram};

use crate::prog::BpfProg;

/// How many leading frame bytes reach the program, as context words.
///
/// Three of the four context words; the first carries the length. 24 bytes
/// covers both MAC addresses and the EtherType, which is where a filter
/// decides.
pub const FRAME_WORDS: usize = 3;

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
        let mut ctx = [0u64; crate::interp::MAX_CTX_WORDS];
        ctx[0] = frame.len() as u64;
        for (i, w) in ctx[1..].iter_mut().enumerate().take(FRAME_WORDS) {
            let off = i * 8;
            if off + 8 <= frame.len() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&frame[off..off + 8]);
                *w = u64::from_le_bytes(b);
            } else if off < frame.len() {
                // A short frame: zero-pad the tail rather than skipping the
                // word, so a program sees a consistent layout and `ctx[0]`
                // remains the authority on how much of it is real.
                let mut b = [0u8; 8];
                b[..frame.len() - off].copy_from_slice(&frame[off..]);
                *w = u64::from_le_bytes(b);
            }
        }
        // Only a program that *returned* decides. `Outcome::value()` is 0 for a
        // trap, so matching on it treated every trap as an unknown action and
        // therefore dropped the frame — the exact opposite of the policy stated
        // here, and severe: an unbounded loop verifies (fuel bounds it at
        // runtime), so a program that exhausts fuel would have silently dropped
        // *every frame on the interface*.
        match self.prog.run_atomic(ctx, 1 + FRAME_WORDS) {
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
    // `BpfXdp::run` calls `run_atomic`, which returns `None` for a program
    // verified for `Sleepable` — and `None` means "pass the frame" (declining
    // traffic because a filter could not run would turn a resource limit into a
    // network outage). So a sleepable program installed as an XDP filter
    // succeeded, then **failed open on every frame**: the interface looks
    // filtered and is not.
    if prog.context() != narf_bpf_verifier::Context::Atomic {
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
