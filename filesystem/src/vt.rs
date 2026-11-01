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
//! Logical switching still needs the Linux VT_PROCESS handshake: the old
//! controller must drop DRM master before acknowledging release, then the new
//! controller may acquire it. No framebuffer repaint is performed here.
//! Linux ref: `drivers/tty/vt/vt_ioctl.c`, `include/uapi/linux/vt.h`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

#[path = "vt_tests.rs"]
mod tests;

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
/// faithful; release/acquire signals are delivered to its installing thread.
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
    controllers: BTreeMap<u32, u64>,
    /// A process-controlled active VT must acknowledge before it changes.
    pending: Option<u32>,
    /// Per-VT owner `(uid, gid)`. logind `chown`s a session's VT to the session
    /// user (and back to root on restore); the default is `root:tty` = `(0, 5)`,
    /// matching devtmpfs' `/dev/ttyN`.
    owners: BTreeMap<u32, (u32, u32)>,
}

static STATE: IrqSafeSpinLock<State> = IrqSafeSpinLock::new(State {
    active: 1,
    allocated: BTreeSet::new(),
    modes: BTreeMap::new(),
    controllers: BTreeMap::new(),
    pending: None,
    owners: BTreeMap::new(),
});

static CURRENT_CONTROLLER: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_CONTROLLER: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_CHANGED: Readiness = Readiness::new(0);
static NEXT_WAITER: AtomicU64 = AtomicU64::new(1);

/// Install the userspace thread-identity and privileged signal enqueue hooks.
/// Identities are opaque kernel task tokens, never caller-supplied Linux pids.
/// The signal hook returns false for a dead controller. It runs under the VT
/// state lock, like Linux's console lock: it must only enqueue/wake, and must
/// neither wait nor re-enter this module. Install before userspace starts.
pub fn install_process_hooks(current: fn() -> u64, signal: fn(u64, u32) -> bool) {
    CURRENT_CONTROLLER.store(current as usize, Ordering::Release);
    SIGNAL_CONTROLLER.store(signal as usize, Ordering::Release);
}

fn current_controller() -> u64 {
    let raw = CURRENT_CONTROLLER.load(Ordering::Acquire);
    if raw == 0 {
        return 0;
    }
    // SAFETY: only install_process_hooks writes this pointer/signature.
    let current: fn() -> u64 = unsafe { core::mem::transmute(raw) };
    current()
}

fn signal_controller(task: u64, signal: i16) -> bool {
    let raw = SIGNAL_CONTROLLER.load(Ordering::Acquire);
    if raw == 0 || task == 0 {
        return false;
    }
    // SAFETY: only install_process_hooks writes this pointer/signature.
    let enqueue: fn(u64, u32) -> bool = unsafe { core::mem::transmute(raw) };
    enqueue(task, signal as u32)
}

/// Complete a switch with release already acknowledged (or VT_AUTO).
/// Caller holds STATE, serializing acquire signals with subsequent releases.
fn complete_switch(state: &mut State, target: u32) {
    state.active = target;
    state.pending = None;
    let mode = state.modes.get(&target).copied().unwrap_or_default();
    if mode.mode == VT_PROCESS {
        let controller = state.controllers.get(&target).copied().unwrap_or(0);
        if !signal_controller(controller, mode.acqsig) {
            state.modes.remove(&target);
            state.controllers.remove(&target);
        }
    }
}

fn notify_switch() {
    crate::sysfs::notify_tty_active();
    ACTIVE_CHANGED.notify(1);
}

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
/// performs to activate a session (`chvt`-equivalent). A VT_PROCESS controller
/// receives relsig and must acknowledge via release_display before active VT
/// and sysfs change. A dead controller falls back to VT_AUTO, as in Linux.
pub fn activate(n: u32) -> Result<(), ()> {
    if !(1..=MAX_VT).contains(&n) {
        return Err(());
    }
    {
        let mut state = STATE.lock();
        if state.active == n {
            return Ok(());
        }
        let old = state.active;
        let mode = state.modes.get(&old).copied().unwrap_or_default();
        if mode.mode == VT_PROCESS {
            // Publish before signalling: another CPU may immediately ack.
            state.pending = Some(n);
            let controller = state.controllers.get(&old).copied().unwrap_or(0);
            if signal_controller(controller, mode.relsig) {
                return Ok(());
            }
            state.modes.remove(&old);
            state.controllers.remove(&old);
        }
        complete_switch(&mut state, n);
    }
    notify_switch();
    Ok(())
}

/// VT_RELDISP: reject a pending release (0), accept it (nonzero), or
/// acknowledge acquisition (2) when no release is pending. Linux vt_reldisp
/// requires VT_PROCESS and rejects release acknowledgements without a request.
pub fn release_display(vt: u32, response: u64) -> Result<(), ()> {
    {
        let mut state = STATE.lock();
        if state
            .modes
            .get(&vt)
            .is_none_or(|mode| mode.mode != VT_PROCESS)
        {
            return Err(());
        }
        if state.active != vt || state.pending.is_none() {
            return if response == 2 { Ok(()) } else { Err(()) };
        }
        let target = state.pending.take().unwrap();
        if response == 0 {
            return Ok(());
        }
        complete_switch(&mut state, target);
    }
    notify_switch();
    Ok(())
}

struct WaitActive {
    target: u32,
    id: u64,
}

impl Future for WaitActive {
    type Output = Result<(), crate::FsError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Register before checking, so completion cannot race past the wait.
        let _ = ACTIVE_CHANGED.arm(self.id, 1, cx.waker());
        if active_vt() == self.target {
            ACTIVE_CHANGED.disarm(self.id);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for WaitActive {
    fn drop(&mut self) {
        ACTIVE_CHANGED.disarm(self.id);
    }
}

/// Sleep until the requested VT is active. No state/IRQ lock crosses await;
/// the future unregisters its durable wake on completion or cancellation.
pub fn wait_active(target: u32) -> crate::FsFuture<'static, ()> {
    if !(1..=MAX_VT).contains(&target) {
        return alloc::boxed::Box::pin(async { Err(crate::FsError::InvalidData) });
    }
    alloc::boxed::Box::pin(WaitActive {
        target,
        id: NEXT_WAITER.fetch_add(1, Ordering::Relaxed),
    })
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
pub fn set_mode(vt: u32, mut mode: VtMode) -> Result<(), ()> {
    if !(1..=MAX_VT).contains(&vt) || !matches!(mode.mode, VT_AUTO | VT_PROCESS) {
        return Err(());
    }
    let controller = current_controller();
    // Linux ignores frsig and clears a previous pending release on SETMODE.
    mode.frsig = 0;
    let mut state = STATE.lock();
    state.modes.insert(vt, mode);
    state.controllers.insert(vt, controller);
    if state.active == vt {
        state.pending = None;
    }
    Ok(())
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

/// Whether VT `vt` is allocated — Linux's `vc_cons_allocated`, which is what
/// makes `/dev/vcsN` exist (`vcs_make_sysfs` runs from `con_install`). VT 1
/// is the boot console and always allocated; others once a DM or getty has
/// claimed them.
pub fn is_allocated(vt: u32) -> bool {
    vt == 1 || (vt <= MAX_VT && STATE.lock().allocated.contains(&vt))
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
    s.controllers.clear();
    s.pending = None;
    s.owners.clear();
    drop(s);
    *KBD.lock() = Kbd::new();
}

// ── Keyboard translation state (drivers/tty/vt/keyboard.c) ─────────────
//
// The KD* keyboard ioctls `loadkeys`, `kbd_mode`, `setfont` and
// systemd-vconsole-setup drive. The tables are GLOBAL in Linux (one
// `key_maps[]`, one `func_table[]`, one `accent_table[]` for every VT) and
// the translation mode is per VT (`kbd_table[console].kbdmode`).
//
// LINUX-GAP: NARF translates console input itself (serial + evdev), so the
// tables are stored and read back exactly as Linux validates them but do
// not drive key translation. The built-in `defkeymap.c` contents are not
// reproduced: the seven maps it defines exist (plain, shift, altgr, ctrl,
// shift+ctrl, alt, ctrl+alt), and their unset entries read back as
// `K_HOLE` rather than the US layout.

/// `K_RAW` .. `K_OFF` (`include/uapi/linux/kd.h`).
pub const K_RAW: u32 = 0x00;
pub const K_XLATE: u32 = 0x01;
pub const K_MEDIUMRAW: u32 = 0x02;
pub const K_UNICODE: u32 = 0x03;
pub const K_OFF: u32 = 0x04;
/// `K_METABIT` / `K_ESCPREFIX`.
pub const K_METABIT: u32 = 0x03;
pub const K_ESCPREFIX: u32 = 0x04;
/// `NR_KEYS`, `MAX_NR_KEYMAPS`, `MAX_NR_FUNC`, `MAX_DIACR`.
pub const NR_KEYS: usize = 256;
pub const MAX_NR_KEYMAPS: usize = 256;
pub const MAX_NR_FUNC: usize = 256;
pub const MAX_DIACR: usize = 256;
/// `K(KT_SPEC, 0)`, `K(KT_SPEC, 15)`, `K(KT_SPEC, 127)`.
pub const K_HOLE: u16 = 0x0200;
pub const K_SAK: u16 = 0x020f;
pub const K_NOSUCHMAP: u16 = 0x027f;

/// `keyboard.c::max_vals[]`, indexed by `KTYP`; its length is `NR_TYPES`.
/// KT_FN is `ARRAY_SIZE(func_table) - 1`, KT_SPEC `ARRAY_SIZE(fn_handler) -
/// 1` (20 handlers), KT_PAD `NR_PAD - 1`, KT_DEAD `NR_DEAD - 1`, KT_SHIFT
/// `NR_SHIFT - 1`, KT_ASCII `NR_ASCII - 1`, KT_LOCK/KT_SLOCK `NR_LOCK - 1`,
/// KT_BRL `NR_BRL - 1`.
const MAX_VALS: [u16; 15] = [255, 255, 19, 19, 26, 255, 3, 8, 255, 25, 8, 255, 8, 255, 10];

/// `struct kbdiacruc { __u32 diacr, base, result; }`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiacrUc {
    pub diacr: u32,
    pub base: u32,
    pub result: u32,
}

struct Kbd {
    /// Per-VT `kbdmode` as the `K_*` value `KDGKBMODE` reports. Absent =
    /// the boot default: `default_utf8 ? VC_UNICODE : VC_XLATE`, and
    /// `vt.default_utf8` defaults to 1, so `K_UNICODE`.
    modes: BTreeMap<u32, u32>,
    /// Per-VT `VC_META` (true = `K_ESCPREFIX`).
    meta_esc: BTreeSet<u32>,
    /// `key_maps[]`: which maps exist, and the entries set in them.
    maps: BTreeSet<u8>,
    /// Built-in maps a `KDSKBENT(0, K_NOSUCHMAP)` deallocated.
    removed: BTreeSet<u8>,
    entries: BTreeMap<(u8, u8), u16>,
    /// `func_table[]`.
    funcs: BTreeMap<u8, alloc::vec::Vec<u8>>,
    /// `accent_table[]` / `accent_table_size`.
    accents: alloc::vec::Vec<DiacrUc>,
}

impl Kbd {
    const fn new() -> Self {
        Self {
            modes: BTreeMap::new(),
            meta_esc: BTreeSet::new(),
            maps: BTreeSet::new(),
            removed: BTreeSet::new(),
            entries: BTreeMap::new(),
            funcs: BTreeMap::new(),
            accents: alloc::vec::Vec::new(),
        }
    }
}

static KBD: IrqSafeSpinLock<Kbd> = IrqSafeSpinLock::new(Kbd::new());

/// `defkeymap.c::key_maps[]`: plain, shift, altgr, ctrl, shift_ctrl, alt,
/// ctrl_alt.
fn default_map(map: u8) -> bool {
    matches!(map, 0 | 1 | 2 | 4 | 5 | 8 | 12)
}

fn map_exists(k: &Kbd, map: u8) -> bool {
    k.maps.contains(&map) || (default_map(map) && !k.removed.contains(&map))
}

/// `vt_do_kdgkbmode`.
pub fn kbd_mode(vt: u32) -> u32 {
    KBD.lock().modes.get(&vt).copied().unwrap_or(K_UNICODE)
}

/// `vt_do_kdskbmode`: one of the five modes, else -EINVAL (`Err`).
pub fn set_kbd_mode(vt: u32, mode: u32) -> Result<(), ()> {
    if !matches!(mode, K_RAW | K_XLATE | K_MEDIUMRAW | K_UNICODE | K_OFF) {
        return Err(());
    }
    KBD.lock().modes.insert(vt, mode);
    Ok(())
}

/// `vt_do_kdgkbmeta`.
pub fn kbd_meta(vt: u32) -> u32 {
    if KBD.lock().meta_esc.contains(&vt) {
        K_ESCPREFIX
    } else {
        K_METABIT
    }
}

/// `vt_do_kdskbmeta`: `K_METABIT` or `K_ESCPREFIX`, else -EINVAL.
pub fn set_kbd_meta(vt: u32, meta: u32) -> Result<(), ()> {
    let mut k = KBD.lock();
    match meta {
        K_METABIT => {
            k.meta_esc.remove(&vt);
        }
        K_ESCPREFIX => {
            k.meta_esc.insert(vt);
        }
        _ => return Err(()),
    }
    Ok(())
}

/// `vt_kdgkbent`.
pub fn get_kbent(vt: u32, idx: u8, map: u8) -> u16 {
    let unicode = kbd_mode(vt) == K_UNICODE;
    let k = KBD.lock();
    if !map_exists(&k, map) {
        return if idx != 0 { K_HOLE } else { K_NOSUCHMAP };
    }
    let val = k.entries.get(&(map, idx)).copied().unwrap_or(K_HOLE);
    if !unicode && (val >> 8) as usize >= MAX_VALS.len() {
        return K_HOLE;
    }
    val
}

/// Why a `KDSKBENT` was refused: `Inval` is -EINVAL, `Perm` -EPERM.
#[derive(Debug, PartialEq, Eq)]
pub enum KbentError {
    Inval,
    Perm,
}

/// `vt_kdskbent`, in its order. `sys_admin` is `capable(CAP_SYS_ADMIN)`,
/// which only a change to or from `K_SAK` consults.
pub fn set_kbent(vt: u32, idx: u8, map: u8, val: u16, sys_admin: bool) -> Result<(), KbentError> {
    let unicode = kbd_mode(vt) == K_UNICODE;
    let mut k = KBD.lock();
    if idx == 0 && val == K_NOSUCHMAP {
        // Deallocate map `map` (never the plain map).
        if map != 0 && map_exists(&k, map) {
            k.maps.remove(&map);
            k.entries.retain(|(m, _), _| *m != map);
            if default_map(map) {
                k.removed.insert(map);
            }
        }
        return Ok(());
    }
    let ktyp = (val >> 8) as usize;
    if ktyp < MAX_VALS.len() {
        if (val & 0xff) > MAX_VALS[ktyp] {
            return Err(KbentError::Inval);
        }
    } else if !unicode {
        return Err(KbentError::Inval);
    }
    // "assignment to entry 0 only tests validity of args"
    if idx == 0 {
        return Ok(());
    }
    if !map_exists(&k, map) {
        k.removed.remove(&map);
        k.maps.insert(map);
    }
    let old = k.entries.get(&(map, idx)).copied().unwrap_or(K_HOLE);
    if val == old {
        return Ok(());
    }
    if (old == K_SAK || val == K_SAK) && !sys_admin {
        return Err(KbentError::Perm);
    }
    k.entries.insert((map, idx), val);
    Ok(())
}

/// `KDGKBSENT`: the function-key string (empty when unset).
pub fn get_func(func: u8) -> alloc::vec::Vec<u8> {
    KBD.lock().funcs.get(&func).cloned().unwrap_or_default()
}

/// `KDSKBSENT`: store `s` (already `strndup_user`'d, no NUL).
pub fn set_func(func: u8, s: alloc::vec::Vec<u8>) {
    KBD.lock().funcs.insert(func, s);
}

/// `KDGKBDIACRUC`.
pub fn accents() -> alloc::vec::Vec<DiacrUc> {
    KBD.lock().accents.clone()
}

/// `KDSKBDIACR[UC]`: replace the accent table (`ct < MAX_DIACR` checked by
/// the caller).
pub fn set_accents(table: alloc::vec::Vec<DiacrUc>) {
    KBD.lock().accents = table;
}
