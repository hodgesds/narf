//! Controller abstraction for cgroup-v2.
//!
//! A [`Controller`] is a resource subsystem (pids, memory, cpu, io,
//! cpuset, misc, …). One global instance per controller is registered
//! at boot via [`register_controller`]; the set of registered
//! controllers is exactly what the root cgroup advertises in
//! `cgroup.controllers`.
//!
//! When a controller is *enabled* on a cgroup (its name appears in the
//! parent's `cgroup.subtree_control`), the core asks the controller for
//! a per-cgroup [`ControllerState`] via [`Controller::new_state`]. That
//! state object owns the controller's tunables and counters for that
//! one cgroup and renders/parses its interface files.
//!
//! # Hierarchy
//!
//! `ControllerState` objects are deliberately *self-contained*: each
//! holds its own counters, and the core (`mod.rs`) walks the cgroup
//! ancestor chain on every membership change, charging each level's
//! state in turn (the css-charging model from
//! `kernel/cgroup/cgroup.c`). Controllers therefore do not need a
//! back-reference to the cgroup tree. The one exception is
//! value *inheritance* (e.g. `cpuset.cpus.effective` derives from the
//! parent's effective mask): `new_state` is handed the parent cgroup's
//! state for the same controller (if any), which the controller may
//! downcast via [`ControllerState::as_any`].

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use crate::FsError;

/// A globally-registered resource controller. Stateless itself; it is
/// a factory for per-cgroup [`ControllerState`].
pub trait Controller: Send + Sync + 'static {
    /// Name as it appears in `cgroup.controllers` /
    /// `cgroup.subtree_control` (e.g. `"pids"`).
    fn name(&self) -> &'static str;

    /// Create per-cgroup state. `parent` is the same controller's state
    /// on the nearest ancestor cgroup that also has it active, for
    /// value inheritance (`None` if this is the topmost active level).
    fn new_state(&self, parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState>;
}

/// Per-cgroup state for one controller.
///
/// Renders/parses the controller's interface files and accounts
/// membership through `can_attach` / `on_attach` / `on_detach`. The
/// core invokes the attach/detach hooks on *every* ancestor level that
/// has the controller active, so each state need only track its own
/// cgroup's charge.
pub trait ControllerState: Send + Sync + core::fmt::Debug + 'static {
    /// Interface file names exposed in the cgroup directory, e.g.
    /// `["pids.current", "pids.max", "pids.events"]`. Must be stable.
    fn files(&self) -> &'static [&'static str];

    /// Render a file's current content (full replacement on each read).
    fn read(&self, file: &str) -> String;

    /// Apply a write to a file. Default: read-only (EROFS-ish — maps to
    /// `FsError::ReadOnly`). Implementations parse `buf` and return
    /// `FsError::InvalidData` on malformed input.
    fn write(&self, _file: &str, _buf: &[u8]) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    /// Whether `file` accepts writes (drives the stat mode bits).
    fn writable(&self, _file: &str) -> bool {
        false
    }

    /// Veto a process joining this cgroup (e.g. `pids.max` reached).
    /// Called as a pure pre-check on each active ancestor level before
    /// any `on_attach` runs, so a rejection charges nothing. Default:
    /// allow.
    fn can_attach(&self, _pid: u64) -> Result<(), FsError> {
        Ok(())
    }

    /// Commit: a process joined this cgroup level. Charge counters here.
    fn on_attach(&self, _pid: u64) {}

    /// A process left this cgroup level. Uncharge counters here.
    fn on_detach(&self, _pid: u64) {}

    /// Downcast hook for parent-state inheritance (see module docs).
    fn as_any(&self) -> &dyn Any;
}

// ── Registry ────────────────────────────────────────────────────────

static CONTROLLERS: IrqSafeSpinLock<Vec<Arc<dyn Controller>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a controller. Call at boot (e.g. from an initcall) before
/// userspace mounts cgroupfs. Idempotent on name: a second registration
/// of the same name is ignored.
pub fn register_controller(c: Arc<dyn Controller>) {
    let mut g = CONTROLLERS.lock();
    if g.iter().any(|existing| existing.name() == c.name()) {
        return;
    }
    g.push(c);
}

/// Snapshot of every registered controller.
pub(crate) fn registered() -> Vec<Arc<dyn Controller>> {
    CONTROLLERS.lock().clone()
}

/// Look up a registered controller by name.
pub(crate) fn find(name: &str) -> Option<Arc<dyn Controller>> {
    CONTROLLERS
        .lock()
        .iter()
        .find(|c| c.name() == name)
        .cloned()
}

#[doc(hidden)]
pub fn __test_reset_controllers() {
    CONTROLLERS.lock().clear();
}
