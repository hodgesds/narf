//! Minimal virtual-terminal (VT) state — enough for systemd-logind's seat0
//! single-session activation.
//!
//! NARF has one physical console, so the "VTs" here are logical: exactly one is
//! *active* at a time. logind treats seat0 as VT-owning (this is hardcoded in
//! logind), so every display manager and compositor on seat0 assumes VT
//! semantics: the DM allocates a VT with `VT_OPENQRY`, passes that `vtnr` to
//! logind's `CreateSession`, and logind marks the session whose `VTNr` equals
//! the *active* VT as the seat's active session. Only the active session is
//! handed DRM device fds via `TakeDevice` — so without a working active-VT,
//! `TakeDevice` is refused ("Could not determine the active graphical
//! session"), the compositor's fallback direct-open of `/dev/dri/card0` fails,
//! and the screen stays black.
//!
//! logind reads the active VT two ways — `VT_GETSTATE` on `/dev/tty0` and the
//! `/sys/class/tty/tty0/active` attribute — so both must agree; see
//! [`active_vt`] and [`active_sysfs`].
//!
//! Real hardware console switching is intentionally omitted (a VM never needs
//! it): [`activate`] just moves the logical active VT so the read paths agree.
//! Linux ref: `drivers/tty/vt/vt_ioctl.c`, `include/uapi/linux/vt.h`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use narf_lib::sync::IrqSafeSpinLock;

/// `vt_mode.mode` values (`include/uapi/linux/vt.h`).
pub const VT_AUTO: u8 = 0x00;
/// The process managing this VT wants to be signalled on switch requests
/// (logind sets this on a session's VT so it can ack releases/acquires).
pub const VT_PROCESS: u8 = 0x01;

/// The highest VT NARF exposes as `/dev/ttyN`. Linux caps at
/// `MAX_NR_CONSOLES = 63`.
pub const MAX_VT: u32 = 63;

/// `struct vt_mode` (`include/uapi/linux/vt.h`) — the per-VT switch mode set by
/// `VT_SETMODE` and read back by `VT_GETMODE`. Stored so the round-trip is
/// faithful; the signals are honoured only trivially since NARF never forces a
/// switch out from under the owner.
#[derive(Clone, Copy, Debug)]
pub struct VtMode {
    pub mode: u8,
    pub waitv: u8,
    pub relsig: i16,
    pub acqsig: i16,
    pub frsig: i16,
}

impl Default for VtMode {
    fn default() -> Self {
        Self {
            mode: VT_AUTO,
            waitv: 0,
            relsig: 0,
            acqsig: 0,
            frsig: 0,
        }
    }
}

struct State {
    /// The active VT — VT 1 at boot. `VT_GETSTATE.v_active` and
    /// `/sys/class/tty/tty0/active` both read this.
    active: u32,
    /// VT numbers handed out by `VT_OPENQRY` (marked in-use so a later query
    /// returns a different one), mirroring the kernel's "VT is allocated once
    /// its `/dev/ttyN` has been opened".
    allocated: BTreeSet<u32>,
    /// Per-VT switch modes set via `VT_SETMODE`.
    modes: BTreeMap<u32, VtMode>,
    /// Per-VT owner `(uid, gid)`. logind `chown`s a session's VT to the session
    /// user (and back to root on restore); the default is `root:tty` = `(0, 5)`,
    /// matching devtmpfs' `/dev/ttyN`.
    owners: BTreeMap<u32, (u32, u32)>,
}

static STATE: IrqSafeSpinLock<State> = IrqSafeSpinLock::new(State {
    active: 1,
    allocated: BTreeSet::new(),
    modes: BTreeMap::new(),
    owners: BTreeMap::new(),
});

/// The default VT node owner — `root:tty` (`gid 5`), as devtmpfs creates
/// `/dev/ttyN`.
const DEFAULT_VT_OWNER: (u32, u32) = (0, 5);

/// The currently active VT (1-based). `VT_GETSTATE` and the sysfs `active`
/// attribute both surface this; logind compares it against each session's
/// `VTNr` to decide which session is active on seat0.
pub fn active_vt() -> u32 {
    STATE.lock().active
}

/// `VT_ACTIVATE(n)` — make `n` the active VT. This is the switch logind
/// performs to activate a session (`chvt`-equivalent). Logical only: no console
/// is repainted, but the active-VT read paths now report `n`, so logind sees
/// the target session become active. `EINVAL` for an out-of-range VT.
pub fn activate(n: u32) -> Result<(), ()> {
    if !(1..=MAX_VT).contains(&n) {
        return Err(());
    }
    STATE.lock().active = n;
    Ok(())
}

/// `VT_OPENQRY` — the lowest free VT (`>= 1`, not already allocated), which the
/// DM runs its session on. Marks it allocated. `None` when every VT is in use
/// (Linux returns `-1` in the out param / `EBUSY`).
pub fn openqry() -> Option<u32> {
    let mut s = STATE.lock();
    for n in 1..=MAX_VT {
        if !s.allocated.contains(&n) {
            s.allocated.insert(n);
            return Some(n);
        }
    }
    None
}

/// The switch mode for VT `vt` (default `VT_AUTO` if never set).
pub fn get_mode(vt: u32) -> VtMode {
    STATE.lock().modes.get(&vt).copied().unwrap_or_default()
}

/// Record the switch mode `VT_SETMODE` installs for VT `vt`.
pub fn set_mode(vt: u32, mode: VtMode) {
    STATE.lock().modes.insert(vt, mode);
}

/// The owner `(uid, gid)` of VT `vt` (default `root:tty` if never chowned).
/// logind chowns a session's VT to the session user so the compositor can drive
/// it, and back to root on restore.
pub fn owner(vt: u32) -> (u32, u32) {
    STATE
        .lock()
        .owners
        .get(&vt)
        .copied()
        .unwrap_or(DEFAULT_VT_OWNER)
}

/// `chown(/dev/ttyN, uid, gid)` — record the new owner of VT `vt`. A `-1`
/// (`u32::MAX`) component means "leave unchanged", matching `chown(2)`.
pub fn set_owner(vt: u32, uid: u32, gid: u32) {
    let mut s = STATE.lock();
    let cur = s.owners.get(&vt).copied().unwrap_or(DEFAULT_VT_OWNER);
    let new = (
        if uid == u32::MAX { cur.0 } else { uid },
        if gid == u32::MAX { cur.1 } else { gid },
    );
    s.owners.insert(vt, new);
}

/// The contents of `/sys/class/tty/tty0/active` — the active VT's tty name plus
/// a trailing newline, e.g. `"tty1\n"`. logind parses this to learn the active
/// VT on seat0.
pub fn active_sysfs() -> String {
    alloc::format!("tty{}\n", active_vt())
}

/// Reset the VT state to its boot default (`active = 1`, nothing allocated, no
/// modes or non-default owners). Test-only: the state is a process-global
/// singleton, so each test must start from a known baseline.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut s = STATE.lock();
    s.active = 1;
    s.allocated.clear();
    s.modes.clear();
    s.owners.clear();
}
