//! Module lifecycle state machine.
//!
//! Linux ref: `linux/include/linux/module.h::module_state` and
//! `linux/kernel/module/main.c::do_init_module` (`main.c:2845`).
//!
//! NARF state transitions are stricter and explicit-failure-only —
//! there's no fallback "module is dead but still in the list":
//!
//! ```text
//!  Loading ──init Ok──▶ Live ──rmmod──▶ Going ──exit────▶ Dead
//!     │                                                    ▲
//!     └──init Err──────────────────────────────────────────┘
//! ```

/// Fixed ABI for `narf_module_init`. Returns 0 on success, negative
/// error code on failure.
pub type ModuleInitFn = unsafe extern "C" fn() -> i32;

/// Fixed ABI for `narf_module_exit`.
pub type ModuleExitFn = unsafe extern "C" fn();

/// Module state.
///
/// Linux equivalent: `enum module_state` in `include/linux/module.h:364`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ModuleState {
    /// ELF parsed + memory allocated + relocations applied. The
    /// `init` function has not yet been called.
    Loading,
    /// `init` returned `Ok(0)`. Module is operational.
    Live,
    /// `rmmod` issued; `exit` is about to be (or is being) called.
    Going,
    /// `exit` returned. Memory pending free; refcount is 0.
    Dead,
}

impl ModuleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            ModuleState::Loading => "Loading",
            ModuleState::Live => "Live",
            ModuleState::Going => "Going",
            ModuleState::Dead => "Dead",
        }
    }
}

/// Errors from a state transition attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    /// `init` returned a non-zero status code (the value is the
    /// returned i32).
    InitFailed(i32),
    /// `rmmod` issued while refcount > 0.
    Busy(usize),
    /// Transition request didn't match current state (e.g. tried to
    /// re-init a Live module).
    BadState { from: ModuleState, to: ModuleState },
}
