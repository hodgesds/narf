//! Non-NVMe storage drivers (AHCI today).
//!
//! Spec: AHCI base 1.3.1.
//!
//! Stage-4 cut: AHCI structural bring-up — map ABAR, reset the
//! HBA, enumerate ports via PI (Ports Implemented), and read each
//! port's signature so the driver can later route IDENTIFY DEVICE
//! / IDENTIFY PACKET DEVICE per port. Per-port command-list +
//! IDENTIFY-DEVICE issuance is a follow-up that lands once a smoke
//! has a guaranteed disk to talk to.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod ahci;
