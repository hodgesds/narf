//! XDP attach — a BPF program ahead of the network bypass table.
//!
//! `net/src/bypass/classifier.rs` has named this seam since it was written
//! ("a future eBPF surface would feed the same table"). This is that surface.
//!
//! ## Writable, resizable frame, dynamically bounded
//!
//! **The frame is writable.** A program may rewrite header bytes in place —
//! `data[k] = v` for a `k` it proved below `data_end` — and `XDP_TX` /
//! `XDP_REDIRECT` then retransmit the *modified* frame (reflect out the ingress
//! iface, or send out a program-chosen one, target ifindex conveyed through the
//! `bpf_redirect` kfunc in [`crate::kfuncs`]). [`BpfXdp::run`] receives the
//! frame `&mut`, threaded from `narf_net::iface::RxHandler` through each
//! driver's RX path; virtio-net and e1000 hand over a `&mut` borrow of the
//! buffer they own and recycle.
//!
//! **The frame is resizable.** `bpf_xdp_adjust_head`/`_tail` move `data` /
//! `data_end` to trim or grow the packet. Because a bare RX frame has no slack —
//! the driver hands over a slice sized to exactly the packet — a program that
//! calls one is run against a per-CPU staging buffer laid out
//! `[headroom | packet | tailroom]` (see [`crate::prog::run_xdp`] and
//! [`crate::xdp_stage`]), so a grow has real room on either side. The resulting
//! `[data, data_end)` window is copied back into the caller's frame and its
//! length threaded through [`BpfXdp::run`] → the classifier → the RX handler, so
//! `XDP_PASS`/`TX`/`REDIRECT` all act on the resized packet. These two kfuncs are
//! interpreter intrinsics — the JIT refuses a program that calls one, exactly as
//! it refuses the ring-buffer intrinsics. A non-resizing program pays no staging
//! copy: it runs against the frame directly. What is still deferred is
//! `devmap`/`cpumap` fan-out (`BPF_F_BROADCAST`).
//!
//! **Frame reads and writes are dynamically bounded, identically.** Context
//! words 0 and 1 are the frame's `data` and exclusive `data_end` pointers. A
//! program must compare a derived data pointer against that paired end before
//! dereferencing it for either a load or a store; the verifier bounds a write
//! against `data_end` with the same interval check it bounds a read, turns only
//! the safe edge into a native bare-access certificate, and the interpreter
//! independently confines both to this exact slice — a store one past either
//! edge traps rather than writing. `data_end` itself stays read-only and is
//! never dereferenceable.

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

    fn run(&self, _iface: &str, frame: &mut [u8]) -> (XdpAction, usize) {
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
        //
        // `run_xdp` also returns the resulting packet length: a program that
        // called `bpf_xdp_adjust_head`/`_tail` resized the frame, and the moved
        // `[data, data_end)` window is what the verdict below applies to (already
        // copied into `frame[..len]`). A non-resizing program returns
        // `frame.len()` unchanged.
        match self.prog.run_xdp(frame) {
            // Linux's XDP action constants: DROP=1, PASS=2, TX=3, REDIRECT=4.
            // Matching those keeps a program written against Linux's constants
            // behaving the same way.
            Some((crate::interp::Outcome::Returned(v), len)) => {
                let action = match v {
                    1 => XdpAction::Drop,
                    2 => XdpAction::Pass,
                    // Reflect the (possibly-rewritten) frame out the ingress
                    // iface.
                    3 => XdpAction::Tx,
                    // Redirect: the target ifindex is whatever `bpf_redirect`
                    // stashed for this frame on this CPU. A bare `return 4` with
                    // no preceding `bpf_redirect` has no target — treat that as
                    // `Aborted` (a redirect with nowhere to go is a program bug),
                    // matching Linux, where `XDP_REDIRECT` without a prior helper
                    // that primed the redirect info is dropped as an error.
                    4 => match crate::kfuncs::take_xdp_redirect_target() {
                        Some(crate::kfuncs::RedirectTarget::Iface(ifindex)) => {
                            XdpAction::Redirect { ifindex }
                        }
                        // A cpumap redirect: deliver to the CPU's stack, which on
                        // NARF's single RX-processing context is local delivery.
                        Some(crate::kfuncs::RedirectTarget::Cpu(cpu)) => {
                            XdpAction::RedirectCpu { cpu }
                        }
                        // A devmap broadcast: copy the staged ports out of the
                        // BPF-side buffer and hand them to the net classifier,
                        // which owns the deferred fan-out send. This is the one
                        // place both crates meet — `attach_xdp` already bridges
                        // BPF and net — so the port list crosses here rather than
                        // bloating the per-frame `XdpAction`/`Verdict` with an
                        // inline array.
                        Some(crate::kfuncs::RedirectTarget::Broadcast { n, exclude_ingress }) => {
                            let mut ports = [0u32; crate::kfuncs::MAX_BROADCAST_PORTS];
                            let n = (n as usize).min(ports.len());
                            let count = crate::kfuncs::copy_broadcast_ports(&mut ports[..n]);
                            narf_net::bypass::classifier::stage_xdp_broadcast(
                                &ports[..count],
                                exclude_ingress,
                            );
                            XdpAction::Broadcast
                        }
                        None => XdpAction::Aborted,
                    },
                    // Any other *returned* value is a program bug. Linux treats
                    // an unknown action as XDP_ABORTED, and so does this —
                    // dropping while counting it, so a broken program is visible
                    // rather than silently passing everything.
                    _ => XdpAction::Aborted,
                };
                (action, len)
            }
            // Trapped, or declined by the stack provider: pass the frame
            // unresized. Dropping traffic because a filter could not run would
            // turn a resource limit into a network outage.
            Some((crate::interp::Outcome::Trapped(_), _)) | None => (XdpAction::Pass, frame.len()),
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
