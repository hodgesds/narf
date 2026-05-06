//! SPDM common types.

use alloc::vec::Vec;
use narf_tpm::TpmError;

#[derive(Debug, Clone)]
pub struct SpdmCaps {
    pub version: u16,
    pub capabilities: u32,
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub index: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpdmError {
    Transport,
    Protocol,
    Tpm(TpmError),
}
