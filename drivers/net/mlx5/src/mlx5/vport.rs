//! NIC vport-context decoder (Stage 12).
//!
//! Reference: public Mellanox PRM §15.4 ("Virtual NIC vport
//! Context").
//!
//! `QUERY_NIC_VPORT_CONTEXT` returns a structured 256-byte payload
//! describing the per-vport NIC configuration. Stage 12 commits to
//! the byte-aligned subset NIC bring-up needs:
//!
//! | offset      | field            | width  |
//! |-------------|------------------|--------|
//! | 0x24        | mtu              | u32 BE |
//! | 0xF4..0xFA  | permanent_mac    | 6 B    |
//! | 0xFA..0x100 | current_mac      | 6 B    |

extern crate alloc;
use alloc::vec::Vec;

pub const VPORT_CTX_LEN: usize = 256;
pub const VPORT_OFF_MTU: usize = 0x24;
pub const VPORT_OFF_PERMANENT_MAC: usize = 0xF4;
pub const VPORT_OFF_CURRENT_MAC: usize = 0xFA;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VportError {
    Truncated,
}

#[derive(Debug)]
pub struct NicVportContext {
    bytes: Vec<u8>,
}

impl NicVportContext {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, VportError> {
        if bytes.len() < VPORT_CTX_LEN {
            return Err(VportError::Truncated);
        }
        Ok(Self { bytes })
    }

    pub fn mtu(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[VPORT_OFF_MTU],
            self.bytes[VPORT_OFF_MTU + 1],
            self.bytes[VPORT_OFF_MTU + 2],
            self.bytes[VPORT_OFF_MTU + 3],
        ])
    }

    pub fn permanent_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.bytes[VPORT_OFF_PERMANENT_MAC..VPORT_OFF_PERMANENT_MAC + 6]);
        mac
    }

    pub fn current_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.bytes[VPORT_OFF_CURRENT_MAC..VPORT_OFF_CURRENT_MAC + 6]);
        mac
    }

    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }
}

/// Build a 256-byte vport-context modification payload that sets
/// just the MTU field. The HCA's modifier mask in op_mod selects
/// which fields it consumes; Stage 12 always writes the MTU bit.
pub fn build_set_mtu_payload(mtu: u32) -> Vec<u8> {
    let mut out = alloc::vec![0u8; VPORT_CTX_LEN];
    out[VPORT_OFF_MTU..VPORT_OFF_MTU + 4].copy_from_slice(&mtu.to_be_bytes());
    out
}
