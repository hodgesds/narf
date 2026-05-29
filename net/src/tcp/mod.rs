//! Production-grade TCP — modular layout.
//!
//! Sub-modules:
//!
//! - [`state_machine`] — the 11-state RFC 9293 FSM enum plus
//!   `Shutdown` / `DropCause` value spaces.
//! - [`retransmit`] — RFC 6298 RTO computation + Karn's algorithm.
//! - [`congestion`] — CUBIC (RFC 9438) + NewReno (RFC 5681).
//! - [`sack`] — RFC 2018 selective ACK book-keeping.
//! - [`options`] — TCP option parsing/emit (MSS, WS, TS, SACK).
//! - [`socket_buf`] — send queue + receive reassembly buffer.
//! - [`core`] — TCB struct, the per-segment arrival processor, the
//!   `tcp_listen` / `tcp_connect` / `tcp_send` / etc. public API.
//!
//! The crate-root re-exports the public API from `core` so call
//! sites use `narf_net::tcp_stack::send` etc. unchanged.

pub mod congestion;
pub mod core;
pub mod options;
pub mod retransmit;
pub mod sack;
pub mod socket_buf;
pub mod state_machine;
