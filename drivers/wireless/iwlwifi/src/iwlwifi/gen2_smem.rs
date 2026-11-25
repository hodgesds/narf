// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Gen2 shared-memory geometry from the retained firmware, as parsed by
//! Linux fw/smem.c::iwl_parse_shared_mem_22000. Addresses remain opaque
//! values; firmware reports never become host pointers or RF authority.
//!
//! Shared by the Gen2 MVM owner (`mvm_smem.rs`) and the MLD runtime
//! (`runtime_smem.rs`), in both the built-in and the module build.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedMemory {
    lmacs: u8,
    tx_fifo: [[u32; 15]; 2],
}
impl SharedMemory {
    pub fn lmac_count(&self) -> u8 {
        self.lmacs
    }
    pub fn tx_fifo_bytes(&self, lmac: u8, fifo: u8) -> Option<u32> {
        if lmac >= self.lmacs {
            return None;
        }
        self.tx_fifo
            .get(usize::from(lmac))?
            .get(usize::from(fifo))
            .copied()
    }
    /// Gen2 EDCA FIFO BK1/BE2/VI3/VO4, with Linux's 256-byte security
    /// margin for the command/header and start of the following packet.
    /// The result still needs negotiated peer, TLC and qualified-program
    /// limits; this geometry supplies no transmit authority.
    pub fn edca_payload_ceiling(&self, lmac: u8, tid: u8) -> Option<u32> {
        let fifo = match tid {
            0 | 3 => 2,
            1 | 2 => 1,
            4 | 5 => 3,
            6 | 7 => 4,
            _ => return None,
        };
        self.tx_fifo_bytes(lmac, fifo)?.checked_sub(256)
    }
    pub(in crate::iwlwifi) fn parse(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        if version > 4
            || bytes.len() < 180
            || bytes.len() > 260
            || bytes.len() % 4 != 0
            || version == 4 && bytes.len() < 260
        {
            return Err("unsupported Gen2 shared-memory response extent/version");
        }
        let count = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        if !(1..=2).contains(&count) {
            return Err("Gen2 shared-memory response has invalid LMAC count");
        }
        let mut result = Self {
            lmacs: count as u8,
            tx_fifo: [[0; 15]; 2],
        };
        for lmac in 0..usize::from(result.lmacs) {
            // Header36, SHARED_MEM_ALLOC_LMAC72; skip txfifo_addr.
            for fifo in 0..15 {
                let at = 40 + lmac * 72 + fifo * 4;
                result.tx_fifo[lmac][fifo] =
                    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            }
        }
        Ok(result)
    }
}
