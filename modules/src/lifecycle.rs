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

/// Define a module's lifecycle entry points.
///
/// `MODULE_AUTHORING.md` has documented this macro since it was written; it
/// did not exist. Every module author following the guide got a
/// `cannot find macro` error and had to fall back to hand-writing the
/// `extern "C"` symbols, which is the thing the macro is for.
///
/// ```ignore
/// fn my_init() -> Result<(), &'static str> { Ok(()) }
/// fn my_exit() {}
///
/// narf_modules::narf_module! {
///     name: "rtl9999",
///     init: my_init,
///     exit: my_exit,
/// }
/// ```
///
/// `exit` is optional — a module with nothing to tear down omits it, and the
/// loader treats a missing `narf_module_exit` as "nothing to do".
///
/// An `Err` from `init` becomes `-1`. A module that needs a specific errno
/// (`-ENODEV` for absent hardware, say) writes the `extern "C"` symbol
/// directly; the macro deliberately does not try to encode an error type
/// across the ABI boundary.
#[macro_export]
macro_rules! narf_module {
    (name: $name:literal, init: $init:path, exit: $exit:path $(,)?) => {
        /// Kernel entry point. Called once, after relocations are applied and
        /// the image is sealed.
        #[unsafe(no_mangle)]
        pub extern "C" fn narf_module_init() -> i32 {
            let _ = $name;
            match $init() {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }

        /// Kernel teardown. Called on `rmmod` once the refcount reaches zero.
        #[unsafe(no_mangle)]
        pub extern "C" fn narf_module_exit() {
            $exit()
        }
    };
    (name: $name:literal, init: $init:path $(,)?) => {
        /// Kernel entry point. Called once, after relocations are applied and
        /// the image is sealed.
        #[unsafe(no_mangle)]
        pub extern "C" fn narf_module_init() -> i32 {
            let _ = $name;
            match $init() {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
    };
}
