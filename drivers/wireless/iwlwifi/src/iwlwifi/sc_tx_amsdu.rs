// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Sc TLC/FIFO intersection; reports supply no transmit authority.
//! Linux mld/tlc.c::iwl_mld_handle_tlc_notif and
//! iwl_mld_get_amsdu_size_of_tid; fw/api/{rs,txq}.h.
//! Firmware geometry/limits supply no key, port or RF authority.

/// The native TLC owner promises3839, independent of an AP's larger cap.
/// Reserve QoS MAC26 +CCMP16 +FCS4 for the complete on-air MPDU.
pub(super) const MAX_MPDU: u16 = 3839;
pub(super) const MAX_BODY: usize = MAX_MPDU as usize - 46;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Limits {
    size: u16,
    tids: u8,
}
impl Limits {
    pub fn active(&self) -> bool {
        self.size != 0 && self.tids != 0
    }
    pub fn permits(&self, tid: u8) -> bool {
        tid < 8 && self.size != 0 && self.tids & (1 << tid) != 0
    }
    pub fn observe(&mut self, version: u8, bytes: &[u8]) {
        // The single-link native AP is station0. A foreign report cannot
        // replace its facts. Malformed matching input suppresses batching.
        if bytes.first().is_some_and(|station| *station != 0) {
            return;
        }
        if !matches!(version, 2..=4) || bytes.len() != 20 || bytes[1..4] != [0; 3] {
            *self = Self::default();
            return;
        }
        let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if flags & !3 != 0 {
            *self = Self::default();
            return;
        }
        if flags & 2 == 0 {
            return;
        }
        let size = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        if !(2000..=u32::from(MAX_MPDU)).contains(&size) {
            *self = Self::default();
            return;
        }
        self.size = size as u16;
        self.tids = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as u8;
    }
    pub fn payload_ceiling(
        &self,
        memory: &super::Gen2SharedMemory,
        lmac: u8,
        tid: u8,
        he: bool,
    ) -> Option<usize> {
        if tid > 7 || self.tids & (1 << tid) == 0 || self.size == 0 {
            return None;
        }
        // Bz FIFO numbering starts at0. HE redirects to the corresponding
        // trigger FIFO, rather than reusing Gen2's EDCA offset1 layout.
        let fifo = match tid {
            1 | 2 => 0,
            0 | 3 => 1,
            4 | 5 => 2,
            6 | 7 => 3,
            _ => return None,
        } + if he { 4 } else { 0 };
        let fifo = memory.tx_fifo_bytes(lmac, fifo)?.checked_sub(256)?;
        Some(usize::from(self.size).min(fifo as usize).min(MAX_BODY))
    }
}
