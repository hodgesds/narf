//! AMD CCP (Crypto Co-Processor) driver crate.
//!
//! Exports the `amd_ccp` module which implements the CCP v5 queue engine,
//! AES-128/192/256 (CBC/ECB/CTR/XTS/GCM) and SHA-1/224/256/384/512
//! for Renoir and Phoenix HawkPoint1 targets.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod amd_ccp;
