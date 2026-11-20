// SPDX-License-Identifier: GPL-2.0-or-later
//! Prepared off-channel Null frames, not an Ethernet or key API.
//! mac80211/mlme.c::ieee80211_send_nullfunc sets DONT_ENCRYPT and requests
//! TX status only with REPORTS_TX_ACK_STATUS, which RTL8xxxu does not set.
use super::receive_runtime::Error;
use alloc::vec::Vec;

/// An internally prepared, payload-free, plaintext station power indication.
/// Its construction grants neither current channel nor transmit authority.
pub(super) struct Prepared {
    own: [u8; 6],
    peer: [u8; 6],
    qos: bool,
    bytes: Vec<u8>,
}
impl Prepared {
    pub(super) fn new(
        own: [u8; 6],
        peer: [u8; 6],
        asleep: bool,
        qos: bool,
        sequence: u16,
    ) -> Result<Self, Error> {
        if own == [0; 6]
            || peer == [0; 6]
            || own == peer
            || own[0] & 1 != 0
            || peer[0] & 1 != 0
            || sequence > 4095
            || qos && sequence != 0
        {
            return Err(Error::State);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(if qos { 26 } else { 24 })
            .map_err(|_| Error::State)?;
        bytes.extend_from_slice(&[
            if qos { 0xc8 } else { 0x48 },
            if asleep { 0x11 } else { 0x01 },
            0,
            0,
        ]);
        bytes.extend_from_slice(&peer);
        bytes.extend_from_slice(&own);
        bytes.extend_from_slice(&peer);
        bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
        if qos {
            // ieee80211_nullfunc_get: WMM peer -> TID7/VO. The sequence
            // handler explicitly skips QoS Null, leaving the zero SSN.
            bytes.extend_from_slice(&[7, 0]);
        }
        Ok(Self {
            own,
            peer,
            qos,
            bytes,
        })
    }
    pub(super) fn matches(&self, own: [u8; 6], peer: [u8; 6], qos: bool) -> bool {
        self.own == own && self.peer == peer && self.qos == qos
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn qos(&self) -> bool {
        self.qos
    }
}
