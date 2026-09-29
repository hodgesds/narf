//! WPA2-PSK/CCMP EAPOL processing for the live station path.
//! Authenticate the original wire PDU before changing replay/key state.
//! Retransmissions return cached replies without reinstalling keys.

use super::{handshake, rekey, wpa};
use alloc::vec::Vec;
use narf_wireless::eapol::*;
use zeroize::{Zeroize, Zeroizing};

pub struct KeyUpdate {
    pub pairwise: Option<[u8; 16]>,
    pub group: [u8; 16],
    pub group_id: u8,
    pub group_rx_pn: u64,
}

impl core::fmt::Debug for KeyUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyUpdate")
            .field("group_id", &self.group_id)
            .finish_non_exhaustive()
    }
}

impl Drop for KeyUpdate {
    fn drop(&mut self) {
        if let Some(key) = &mut self.pairwise {
            key.zeroize();
        }
        self.group.zeroize();
    }
}

#[derive(Debug)]
pub struct Response {
    pub bytes: Vec<u8>,
    pub keys: Option<KeyUpdate>,
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn hex(bytes: &str) -> Vec<u8> {
        bytes
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |ch| match ch {
                    b'0'..=b'9' => ch - b'0',
                    b'a'..=b'f' => ch - b'a' + 10,
                    _ => panic!("hex"),
                };
                nibble(pair[0]) * 16 + nibble(pair[1])
            })
            .collect()
    }

    // Independently generated with Python hashlib/HMAC and
    // cryptography's RFC3394 AES key wrap. No driver encoder generated
    // these received PDUs or the expected temporal key.
    fn fixture() -> (Session, Vec<u8>, Vec<u8>) {
        let rsn = hex("0100000fac040100000fac040100000fac020000");
        let session = Session::new(
            [0x11; 32],
            [2, 1, 2, 3, 4, 5],
            [2, 6, 7, 8, 9, 10],
            [0x33; 32],
            rsn,
        );
        let m1 = hex("0203005f02008a0010000000000000000122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let m3 = hex("020300970213ca00100000000000000002222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000006cdc612e45aabd5eb5b738d95b80be0e0038f46db379e9627aaf30c244132bcf973013fa695a53b39487397cd085fa6324776aba88cc6ba0fc0f8ccc41a59c9a5069ae43f5ffe26e975a");
        (session, m1, m3)
    }

    fn smoke_wpa2_authenticated_key_install() -> TestResult {
        let (mut session, m1, m3) = fixture();
        let reply = session.process(&m1).unwrap();
        if reply.keys.is_some() || session.complete() {
            return TestResult::Fail("M1 opened controlled port");
        }
        let m2 = KeyFrame::decode(&reply.bytes[4..], 16).unwrap();
        if m2.key_information != 0x10a || m2.key_mic.len() != 16 || m2.key_data.first() != Some(&48)
        {
            return TestResult::Fail("invalid M2 descriptor/MIC/RSN");
        }
        let reply = session.process(&m3).unwrap();
        let keys = reply.keys.unwrap();
        if !session.complete()
            || keys.group != [0x44; 16]
            || keys.group_id != 1
            || keys.pairwise.unwrap().as_slice() != hex("f54200ef831912972fc8f81c95b606a7")
        {
            return TestResult::Fail("independent PTK/GTK vector mismatch");
        }
        let duplicate = session.process(&m3).unwrap();
        if duplicate.keys.is_some() || duplicate.bytes != reply.bytes {
            return TestResult::Fail("M3 retransmission reinstalled keys");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa2_authenticated_key_install
    );

    fn smoke_wpa2_bad_mic_preserves_state() -> TestResult {
        let (mut session, m1, m3) = fixture();
        session.process(&m1).unwrap();
        for offset in [81, 100, 150] {
            let mut bad = m3.clone();
            bad[offset] ^= 1;
            if session.process(&bad).is_ok() || session.complete() || session.replay != 1 {
                return TestResult::Fail("unauthenticated M3 changed keys/replay state");
            }
        }
        if session.process(&m3).is_err() {
            return TestResult::Fail("bad MIC poisoned valid retry");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa2_bad_mic_preserves_state
    );

    fn smoke_wpa2_higher_counter_retransmit_no_reinstall() -> TestResult {
        let (mut session, m1, m3) = fixture();
        session.process(&m1).unwrap();
        session.process(&m3).unwrap();
        // AP retry with a new replay counter and independently computed MIC.
        let retry = hex("020300970213ca001000000000000000032222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000091a7404529360321c0a5568c86bbd0de0038f46db379e9627aaf30c244132bcf973013fa695a53b39487397cd085fa6324776aba88cc6ba0fc0f8ccc41a59c9a5069ae43f5ffe26e975a");
        let reply = match session.process(&retry) {
            Ok(reply) => reply,
            Err(error) => return TestResult::Fail(error),
        };
        if reply.keys.is_some() || session.replay != 3 || !session.complete() {
            return TestResult::Fail("authenticated M3 retry reset installed keys");
        }
        if session.process(&m3).is_ok() {
            return TestResult::Fail("old replay accepted after authenticated retry");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa2_higher_counter_retransmit_no_reinstall
    );
}

pub struct Session {
    pmk: [u8; 32],
    ap: [u8; 6],
    local: [u8; 6],
    snonce: [u8; 32],
    anonce: [u8; 32],
    ptk: Option<Ptk>,
    replay: u64,
    ap_rsn: Vec<u8>,
    last_request: Vec<u8>,
    last_response: Vec<u8>,
    initial_key_data: Vec<u8>,
    complete: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wpa2Session")
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.pmk.zeroize();
        if let Some(ptk) = &mut self.ptk {
            ptk.kck.zeroize();
            ptk.kek.zeroize();
            ptk.tk.zeroize();
        }
        self.initial_key_data.zeroize();
    }
}

impl Session {
    pub fn new(
        pmk: [u8; 32],
        ap: [u8; 6],
        local: [u8; 6],
        snonce: [u8; 32],
        ap_rsn: Vec<u8>,
    ) -> Self {
        Self {
            pmk,
            ap,
            local,
            snonce,
            anonce: [0; 32],
            ptk: None,
            replay: 0,
            ap_rsn,
            last_request: Vec::new(),
            last_response: Vec::new(),
            initial_key_data: Vec::new(),
            complete: false,
        }
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn process(&mut self, pdu: &[u8]) -> Result<Response, &'static str> {
        if pdu.len() < 99
            || !matches!(pdu[0], 1 | 2)
            || pdu[1] != 3
            || u16::from_be_bytes([pdu[2], pdu[3]]) as usize != pdu.len() - 4
        {
            return Err("invalid EAPOL envelope");
        }
        let key = KeyFrame::decode(&pdu[4..], 16).ok_or("invalid EAPOL key")?;
        if pdu.len() != 99 + key.key_data.len()
            || key.descriptor_type != KEY_DESCRIPTOR_RSN
            || key.key_information & 7 != KI_VERSION_HMAC_SHA1_AES
            || key.key_length != 16
        {
            return Err("unsupported EAPOL key format");
        }
        if pdu == self.last_request {
            return Ok(Response {
                bytes: self.last_response.clone(),
                keys: None,
            });
        }
        let (mut reply, update) = if self.ptk.is_none() {
            if key.key_information != (KI_VERSION_HMAC_SHA1_AES | KI_KEY_ACK | KI_KEY_TYPE_PAIRWISE)
                || key.key_nonce == [0; 32]
            {
                return Err("invalid WPA2 message 1");
            }
            let ptk = wpa::derive_ptk_sha1(
                &self.pmk,
                &self.ap,
                &self.local,
                &key.key_nonce,
                &self.snonce,
                16,
            );
            let mut reply = KeyFrame::empty(16);
            reply.key_information = KI_VERSION_HMAC_SHA1_AES | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
            reply.replay_counter = key.replay_counter;
            reply.key_nonce = self.snonce;
            let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
            reply.key_data.extend_from_slice(&[48, rsn.len() as u8]);
            reply.key_data.extend_from_slice(&rsn);
            self.ptk = Some(ptk);
            self.anonce = key.key_nonce;
            (reply, None)
        } else {
            if key.replay_counter <= self.replay {
                return Err("EAPOL replay");
            }
            let ptk = self.ptk.as_ref().unwrap();
            let mut authenticated = pdu.to_vec();
            authenticated[81..97].fill(0);
            let expected = handshake::compute_mic(&ptk.kck, &authenticated);
            if expected
                .iter()
                .zip(&pdu[81..97])
                .fold(0, |diff, (a, b)| diff | (a ^ b))
                != 0
            {
                return Err("EAPOL MIC mismatch");
            }
            let common = KI_VERSION_HMAC_SHA1_AES
                | KI_KEY_ACK
                | KI_KEY_MIC
                | KI_SECURE
                | KI_ENCRYPTED_KEY_DATA;
            let pairwise_message = key.pairwise();
            let expected_flags = common
                | if pairwise_message {
                    KI_KEY_TYPE_PAIRWISE | KI_INSTALL
                } else {
                    0
                };
            if key.key_information != expected_flags
                || (pairwise_message && key.key_nonce != self.anonce)
                || (!self.complete && !pairwise_message)
            {
                return Err("invalid WPA2 message 3/group rekey");
            }
            let kek: [u8; 16] = ptk
                .kek
                .as_slice()
                .try_into()
                .map_err(|_| "invalid KEK length")?;
            let kek = Zeroizing::new(kek);
            let clear = Zeroizing::new(
                rekey::aes_key_unwrap(&kek, &key.key_data).ok_or("invalid encrypted key data")?,
            );
            if pairwise_message && !contains_ie(&clear, 48, &self.ap_rsn) {
                return Err("AP RSN changed during handshake");
            }
            if pairwise_message && self.complete && *clear != self.initial_key_data {
                return Err("retransmitted M3 changed key data");
            }
            let gtk = rekey::parse_gtk_kde(&clear).ok_or("message lacks GTK")?;
            let group_id = gtk.key_id;
            let gtk = Zeroizing::new(gtk.gtk);
            let group = gtk
                .as_slice()
                .try_into()
                .map_err(|_| "invalid CCMP GTK length")?;
            let pairwise = if self.complete {
                None
            } else {
                Some(
                    ptk.tk
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid TK length")?,
                )
            };
            let pn = u64::from_le_bytes(key.key_rsc);
            if pn >> 48 != 0 {
                return Err("invalid GTK replay counter");
            }
            let mut reply = KeyFrame::empty(16);
            reply.key_information = KI_VERSION_HMAC_SHA1_AES
                | KI_KEY_MIC
                | KI_SECURE
                | if pairwise_message {
                    KI_KEY_TYPE_PAIRWISE
                } else {
                    0
                };
            reply.replay_counter = key.replay_counter;
            let update = if pairwise_message && self.complete {
                None
            } else {
                Some(KeyUpdate {
                    pairwise,
                    group,
                    group_id,
                    group_rx_pn: pn,
                })
            };
            if pairwise_message && !self.complete {
                self.initial_key_data = clear.to_vec();
            }
            (reply, update)
        };
        reply.key_mic.fill(0);
        let mut bytes = reply.into_eapol();
        bytes[0] = pdu[0];
        let mic = handshake::compute_mic(&self.ptk.as_ref().unwrap().kck, &bytes);
        bytes[81..97].copy_from_slice(&mic);
        self.replay = key.replay_counter;
        self.complete |= update.is_some();
        self.last_request = pdu.to_vec();
        self.last_response = bytes.clone();
        Ok(Response {
            bytes,
            keys: update,
        })
    }
}

fn contains_ie(bytes: &[u8], tag: u8, expected: &[u8]) -> bool {
    let mut offset = 0;
    while bytes.len() - offset >= 2 {
        let len = bytes[offset + 1] as usize;
        if len > bytes.len() - offset - 2 {
            return false;
        }
        if bytes[offset] == tag {
            return bytes[offset + 2..offset + 2 + len] == *expected;
        }
        offset += 2 + len;
    }
    false
}
