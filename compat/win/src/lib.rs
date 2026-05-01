//! narf-compat-win — Win32-on-NARF compatibility layer (kernel side).
//!
//! Spec: `compat/win/specification/spec.md` v1.0. Stage 4+,
//! depends on `userspace/` reaching its Stage-4 exit gate first.
//!
//! v1.0 architecture: this crate owns the kernel-side pieces
//! only — the PE32+ parser, the `WinProcess` AS materialiser,
//! and the cap-checked user-pointer accessor. All Win32 API
//! thunks (`kernel32!*`, `user32!*`, …) live in the userspace
//! `compat-win-rt` crate which is mapped into every WinProcess
//! as a system DLL. IAT slots resolve to user-mode VAs in that
//! library — no SYS_WIN_THUNK syscall, no kernel-mode thunk
//! dispatcher, no per-process trampoline page.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod dll;
pub mod entry;
pub mod pe;
pub mod personality;
pub mod process;
pub mod user_ptr;

pub use pe::{parse as parse_pe, PeError, PeImage};
pub use personality::{init_peb, init_teb, Layout};
pub use process::{load_pe, ImportResolver, LoadError, Spawn, WinProcess};
