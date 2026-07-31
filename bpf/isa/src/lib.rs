//! # `narf-bpf-isa` — the BPF instruction set
//!
//! Encoding, decoding, and disassembly of BPF instructions. This crate is the
//! shared vocabulary of the whole BPF subsystem: the verifier decodes with it,
//! the JIT lowers from it, and the runtime disassembles with it for logs.
//!
//! ## Why the encoding is Linux's
//!
//! NARF's BPF is **instruction-set compatible with Linux and ABI-divergent**
//! (see `bpf/specification/spec.md` §2). The encoding is not ours to change:
//! LLVM's `bpf` target is our compiler, and rewriting it would mean writing a
//! backend. So the warts come along — `off` selecting the `SDIV`/`SMOD`/
//! `MOVSX` variants, `off` selecting `ADDR_SPACE_CAST`, atomic operations
//! living in `imm` with two of them (`BPF_LOAD_ACQ`, `BPF_STORE_REL`) too wide
//! for eight bits, and `src_reg` selecting seven `LD_IMM64` pseudo-forms and
//! three kinds of call.
//!
//! Everything *above* the encoding is designed fresh. In particular this crate
//! rejects two things Linux accepts:
//!
//!   * **Helper calls** ([`DecodeError::HelperCall`]). NARF has one call ABI,
//!     not two — kfuncs only, with argument semantics carried by Rust types
//!     rather than BTF parameter-name suffixes. See spec §3.
//!   * **`LD_ABS` / `LD_IND`** ([`DecodeError::LegacyPacketLoad`]), which
//!     `Documentation/bpf/bpf_design_QA.rst:227` itself calls an "artifact of
//!     compatibility with classic BPF".
//!
//! Rejecting them here, at decode, is deliberate: it keeps the exclusion in
//! one place instead of scattering "unreachable" arms through the verifier and
//! both JIT backends.
//!
//! ## Layering
//!
//! [`Decoded`] is a *decoding*, not an IR — it is faithful to the encoding,
//! one variant per instruction shape. The verifier builds a CFG/SSA IR on top
//! and everything downstream works on that, so instruction indices stop being
//! meaningful after verification. That split is what lets NARF lower once
//! instead of patching instructions in place the way Linux does (spec §7).
//!
//! ## Testing
//!
//! Zero dependencies and `#![forbid(unsafe_code)]`, so this crate builds and
//! tests on the host: `cargo test -p narf-bpf-isa`, or through
//! `cargo xtask host-test`. In-kernel smokes are behind the `kernel-test`
//! feature.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod disasm;
pub mod encode;
pub mod insn;
pub mod opcode;

#[cfg(test)]
mod tests;

#[cfg(feature = "kernel-test")]
mod smoke;

pub use insn::{decode, slots_from_bytes, CallTarget, DecodeError, Decoded, Imm64, Insn};
pub use opcode::{
    AluOp, AtomicOp, ByteOrder, Class, CondOp, Reg, Size, Source, INSN_SIZE, NUM_REGS,
};
