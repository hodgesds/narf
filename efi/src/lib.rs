//! narf-efi — UEFI Runtime Services codecs (clean-room).
//!
//! ## Sources (public only)
//!
//! - **Unified Extensible Firmware Interface (UEFI) Specification,
//!   Version 2.10**, August 2022. UEFI Forum.
//!   <https://uefi.org/specs/UEFI/2.10/>
//!   - §4 — EFI System Table layout (revision, fw vendor / revision,
//!     ConIn / ConOut / StdErr handles, Runtime Services pointer,
//!     ConfigurationTable pointer + count).
//!   - §8 — Runtime Services (GetTime/SetTime, GetVariable /
//!     SetVariable / GetNextVariableName, ResetSystem,
//!     QueryVariableInfo).
//!   - §32 — Secure Boot variable shapes (PK, KEK, db, dbx).
//!
//! No GPL / Linux source consulted.
//!
//! ## What this crate is
//!
//! Transport-neutral codecs for the UEFI Runtime-Services data
//! structures the kernel exchanges with firmware after
//! `ExitBootServices`. Every shape here is the *wire* layout — the
//! arch-specific glue that issues an indirect call through the RT
//! services function-pointer table (after pinning the firmware's
//! page tables) lives in `arch/`.
//!
//! Modules:
//!
//! - [`time`] — `EFI_TIME` / `EFI_TIME_CAPABILITIES` structs.
//! - [`variable`] — Variable Attributes, well-known GUIDs, name
//!   wide-string encoder/decoder, signature-list (EFI_SIGNATURE_LIST)
//!   walker for SecureBoot db / dbx.
//! - [`reset`] — `EfiResetType` enum + status codes.
//! - [`system_table`] — `EFI_SYSTEM_TABLE` / `EFI_TABLE_HEADER`
//!   decoders, signature constants, CRC32 verification helper.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod reset;
pub mod system_table;
pub mod time;
pub mod variable;

mod tests;
