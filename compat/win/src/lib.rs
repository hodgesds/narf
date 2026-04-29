//! narf-compat-win — Win32-on-NARF compatibility layer.
//!
//! Spec: `compat/win/specification/spec.md`. Stage 4+, depends on
//! `userspace/` reaching its Stage-4 exit gate first.
//!
//! Milestone 0 surface — what the skeleton in this crate is meant
//! to grow into:
//!
//! - `pe::parse` — PE32+ header / section / import / reloc parser.
//! - `process::WinProcess` — the NT-personality bundle wrapping a
//!   `narf_userspace::UserProcess`.
//! - `thunks::{Thunk, install_registry, dispatch_thunk, resolve_addr}`
//!   — Win32 API import-resolution table.
//! - `thunks::kernel32` — the M0 minimum: `GetStdHandle`,
//!   `WriteConsole{A,W}`, `ExitProcess`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod dll;
pub mod pe;
pub mod personality;
pub mod process;
pub mod syscall;
pub mod thunks;
pub mod trampoline;

pub use pe::{parse as parse_pe, PeError, PeImage};
pub use personality::{init_peb, init_teb, Layout};
pub use process::{load_pe, ImportResolver, LoadError, Spawn, WinProcess};
pub use thunks::{
    dispatch_thunk, install_registry, resolve_addr, thunk_by_id, thunk_id, Thunk,
};
