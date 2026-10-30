//! Negotiated PSK/SAE CCMP EAPOL processing for the live station path.
//! Authenticate the original wire PDU before changing replay/key state.
//! Retransmissions return cached replies without reinstalling keys.

use super::{handshake, rekey, wpa};
use alloc::{boxed::Box, vec::Vec};
use narf_wireless::eapol::*;
use zeroize::{Zeroize, Zeroizing};

/// Production nonces require the guarded hardware entropy path. A partial
/// failing sample stays private and is zeroized before returning an error.
pub(super) fn fresh_nonce() -> Result<[u8; 32], &'static str> {
    fresh_nonce_with(|bytes| {
        narf_crypto::try_fill_random_bytes(bytes).map_err(|_| "secure entropy unavailable")
    })
}
fn fresh_nonce_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), &'static str>,
) -> Result<[u8; 32], &'static str> {
    let mut bytes = Zeroizing::new([0; 32]);
    fill(bytes.as_mut_slice())?;
    Ok(*bytes)
}

pub struct KeyUpdate {
    pub pairwise: Option<[u8; 16]>,
    pub group: [u8; 16],
    pub group_id: u8,
    pub group_rx_pn: u64,
    /// 802.11w Integrity GTK (BIP-CMAC-128) + its key index, present only
    /// when management-frame protection was negotiated (PSK or SAE).
    /// IGTK material, key index and the KDE IPN (receive replay floor).
    pub igtk: Option<([u8; 16], u16, u64)>,
}

impl core::fmt::Debug for KeyUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyUpdate")
            .field("group_id", &self.group_id)
            .field("mfp", &self.igtk.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for KeyUpdate {
    fn drop(&mut self) {
        if let Some(key) = &mut self.pairwise {
            key.zeroize();
        }
        self.group.zeroize();
        if let Some((igtk, _, _)) = &mut self.igtk {
            igtk.zeroize();
        }
    }
}

/// Authentication/key-management suite selecting the 4-way handshake
/// crypto: EAPOL-Key descriptor version, PTK KDF, and MIC algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Akm {
    /// WPA2-Personal (00-0F-AC:2): HMAC-SHA1 PRF + HMAC-SHA1-128 MIC,
    /// Key Descriptor Version 2.
    Wpa2Psk,
    /// PSK-SHA256 (AKM6), SHA-256 KDF and AES-CMAC MIC, descriptor3.
    Wpa2PskSha256,
    /// WPA3-Personal SAE (00-0F-AC:8): SHA-256 KDF + AES-128-CMAC MIC,
    /// Key Descriptor Version 0, management-frame protection required.
    Wpa3Sae,
    /// SAE-EXT-KEY group19 (AKM24): SHA-256 KDF and HMAC-SHA256-128 MIC.
    Wpa3SaeExtKey,
}

impl Akm {
    /// Low 3 bits of the Key Information field (Key Descriptor Version).
    fn ki_version(self) -> u16 {
        match self {
            Akm::Wpa2Psk => KI_VERSION_HMAC_SHA1_AES,
            Akm::Wpa2PskSha256 => KI_VERSION_AES_128_CMAC,
            Akm::Wpa3Sae | Akm::Wpa3SaeExtKey => 0,
        }
    }

    fn derive_ptk(
        self,
        pmk: &[u8],
        aa: &[u8; 6],
        sa: &[u8; 6],
        anonce: &[u8; 32],
        snonce: &[u8; 32],
        tk_len: usize,
    ) -> Ptk {
        match self {
            Akm::Wpa2Psk => wpa::derive_ptk_sha1(pmk, aa, sa, anonce, snonce, tk_len),
            Akm::Wpa3Sae => wpa::derive_ptk_sha256(pmk, aa, sa, anonce, snonce, tk_len),
            Akm::Wpa2PskSha256 => {
                wpa_pmk_to_ptk(KeyMgmt::PskSha256, pmk, aa, sa, anonce, snonce, tk_len)
            }
            Akm::Wpa3SaeExtKey => {
                wpa_pmk_to_ptk(KeyMgmt::SaeExtKey, pmk, aa, sa, anonce, snonce, tk_len)
            }
        }
    }

    fn mic(self, kck: &[u8], eapol_with_zero_mic: &[u8]) -> [u8; 16] {
        match self {
            Akm::Wpa2Psk => handshake::compute_mic(kck, eapol_with_zero_mic),
            Akm::Wpa3Sae | Akm::Wpa2PskSha256 => wpa::compute_mic_cmac(kck, eapol_with_zero_mic),
            Akm::Wpa3SaeExtKey => narf_crypto::hkdf::hmac_sha256(kck, eapol_with_zero_mic)[..16]
                .try_into()
                .unwrap(),
        }
    }

    /// The STA's own RSN IE body, echoed in M2 and checked by the AP.
    pub(super) fn sta_rsn_ie(self) -> Vec<u8> {
        match self {
            Akm::Wpa2Psk => narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
            Akm::Wpa3Sae => narf_wireless::rsn::RsnIe::wpa3_sae_ccmp().encode_body(),
            Akm::Wpa2PskSha256 | Akm::Wpa3SaeExtKey => {
                let mut rsn = if self == Akm::Wpa2PskSha256 {
                    narf_wireless::rsn::RsnIe::wpa2_psk_ccmp()
                } else {
                    narf_wireless::rsn::RsnIe::wpa3_sae_ccmp()
                };
                rsn.akms = alloc::vec![narf_wireless::rsn::Suite::standard(
                    if self == Akm::Wpa2PskSha256 { 6 } else { 24 }
                )];
                rsn.encode_body()
            }
        }
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
            Akm::Wpa2Psk,
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

    fn smoke_wpa2_eapol3_keeps_descriptor_mic_and_replay_gates() -> TestResult {
        let (mut session, mut m1, _) = fixture();
        // IEEE 802.1X-2010's outer protocol version is independent of the
        // WPA2 EAPOL-Key descriptor version (HMAC-SHA1/AES remains 2).
        m1[0] = 3;
        for version in [0, 4, 255] {
            let mut invalid = m1.clone();
            invalid[0] = version;
            if session.process(&invalid).is_ok() || session.ptk.is_some() {
                return TestResult::Fail("unknown EAPOL envelope version changed key state");
            }
        }
        let mut invalid = m1.clone();
        invalid[6] = 0x8b;
        if session.process(&invalid).is_ok() || session.ptk.is_some() {
            return TestResult::Fail("EAPOL3 accepted a different WPA2 descriptor version");
        }
        let m2 = match session.process(&m1) {
            Ok(reply) => reply,
            Err(error) => return TestResult::Fail(error),
        };
        if m2.bytes[0] != 3 || m2.keys.is_some() || session.complete() {
            return TestResult::Fail(
                "EAPOL3 M1 opened the controlled port or changed reply version",
            );
        }
        // Python hashlib/hmac PRF + MIC over the original independent wrapped
        // GTK vector above. The changed protocol byte is authenticated too.
        let m3 = hex("030300970213ca0010000000000000000222222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000141c9f3d2a77fe734f184250cb5037a80038f46db379e9627aaf30c244132bcf973013fa695a53b39487397cd085fa6324776aba88cc6ba0fc0f8ccc41a59c9a5069ae43f5ffe26e975a");
        let mut changed_envelope = m3.clone();
        changed_envelope[0] = 2;
        if session.process(&changed_envelope).is_ok() || session.complete() || session.replay != 1 {
            return TestResult::Fail("EAPOL protocol byte escaped MIC authentication");
        }
        let m4 = match session.process(&m3) {
            Ok(reply) => reply,
            Err(error) => return TestResult::Fail(error),
        };
        if m4.bytes[0] != 3
            || !session.complete()
            || m4
                .keys
                .as_ref()
                .and_then(|keys| keys.pairwise)
                .is_none_or(|key| key.as_slice() != hex("f54200ef831912972fc8f81c95b606a7"))
        {
            return TestResult::Fail("independent EAPOL3 key-install vector mismatch");
        }
        match session.process(&m3) {
            Ok(retry) if retry.keys.is_none() && retry.bytes == m4.bytes => TestResult::Pass,
            _ => TestResult::Fail("EAPOL3 M3 retry changed key ownership"),
        }
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa2_eapol3_keeps_descriptor_mic_and_replay_gates
    );

    fn smoke_iwl_nonce_entropy_failure_keeps_rekey_and_retransmit_ownership() -> TestResult {
        let (mut session, m1, m3) = fixture();
        session.process(&m1).unwrap();
        session.process(&m3).unwrap();
        let old = session.ptk.as_ref().unwrap().tk.clone();
        let last = session.last_response.clone();
        let rekey=hex("0203005f02008a0010000000000000000355555555555555555555555555555555555555555555555555555555555555550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        if session
            .process_with_nonce(&rekey, || Err("entropy test failure"))
            .err()
            != Some("entropy test failure")
            || !session.complete()
            || session.replay != 2
            || session.pending_rekey.is_some()
            || session.ptk.as_ref().unwrap().tk != old
            || session.last_response != last
        {
            return TestResult::Fail("entropy failure changed active key/replay or published M2");
        }
        let reply = session
            .process_with_nonce(&rekey, || Ok([0x66; 32]))
            .unwrap();
        let retry = session
            .process_with_nonce(&rekey, || Err("retry must not need new entropy"))
            .unwrap();
        if reply.bytes != retry.bytes
            || retry.keys.is_some()
            || session.ptk.as_ref().unwrap().tk != old
        {
            return TestResult::Fail("cached rekey retry regenerated nonce or changed key");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_iwl_nonce_entropy_failure_keeps_rekey_and_retransmit_ownership
    );
    fn smoke_iwl_nonce_partial_entropy_failure_does_not_return_sample() -> TestResult {
        if fresh_nonce_with(|out| {
            out[..16].fill(0xaa);
            Err("entropy test failure")
        }) != Err("entropy test failure")
            || fresh_nonce_with(|out| {
                out.fill(0x55);
                Ok(())
            }) != Ok([0x55; 32])
        {
            return TestResult::Fail("partial entropy failure returned predictable nonce");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_iwl_nonce_partial_entropy_failure_does_not_return_sample
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
    fn smoke_wpa2_pairwise_rekey_preserves_active_key_until_mic() -> TestResult {
        let (mut session, m1, m3) = fixture();
        session.process(&m1).unwrap();
        session.process(&m3).unwrap();
        let old_key = session.ptk.as_ref().unwrap().tk.clone();
        let rekey1 = hex("0203005f02008a0010000000000000000355555555555555555555555555555555555555555555555555555555555555550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let rekey3 = hex("020300970213ca00100000000000000004555555555555555555555555555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000000de565ea6423eacef8a8be83dcfcb76100383d3479c5595f9bb85a430c70134b111b0d4cc49b0d9a98319e6561431ffdb340922b32e3e0be2db08738d74ea6f4a5ebf58be766a01c9765");
        let m2 = session
            .process_with_nonce(&rekey1, || Ok([0x66; 32]))
            .unwrap();
        if m2.keys.is_some() || !session.complete() || session.ptk.as_ref().unwrap().tk != old_key {
            return TestResult::Fail("unauthenticated rekey M1 replaced the active PTK");
        }
        let retry = session
            .process_with_nonce(&rekey1, || panic!("duplicate M1 regenerated SNonce"))
            .unwrap();
        if retry.bytes != m2.bytes || retry.keys.is_some() {
            return TestResult::Fail("M1 retry changed M2/key");
        }
        let mut bad = rekey3.clone();
        bad[81] ^= 1;
        if session.process(&bad).is_ok()
            || session.ptk.as_ref().unwrap().tk != old_key
            || session.replay != 2
        {
            return TestResult::Fail("bad rekey MIC changed active PTK/replay");
        }
        let m4 = session.process(&rekey3).unwrap();
        if m4.keys.as_ref().unwrap().pairwise.unwrap().as_slice()
            != hex("fbf6cf6105dcc23f7ef544dcb168dbb4")
            || session.pending_rekey.is_some()
            || session.replay != 4
            || !session.complete()
        {
            return TestResult::Fail("independent pairwise rekey vector mismatch");
        }
        let duplicate = session.process(&rekey3).unwrap();
        if duplicate.keys.is_some()
            || duplicate.bytes != m4.bytes
            || session.process(&m3).is_ok()
            || session
                .process_with_nonce(&rekey1, || panic!("old M1 reused nonce"))
                .is_ok()
        {
            return TestResult::Fail("rekey retransmission reinstalled or accepted old PTK");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa2_pairwise_rekey_preserves_active_key_until_mic
    );

    // WPA3-SAE 4-way: the M2 reply must use Key Descriptor Version 0, an
    // AES-128-CMAC MIC over the SHA-256-derived PTK KCK, and echo the
    // WPA3 (AKM-SAE, MFP) RSN IE — not the WPA2/SHA-1/HMAC profile.
    fn smoke_wpa3_sae_m1_m2_descriptor_and_cmac_mic() -> TestResult {
        let rsn = narf_wireless::rsn::RsnIe::wpa3_sae_ccmp().encode_body();
        let mut session = Session::new(
            Akm::Wpa3Sae,
            [0x11; 32],
            [2, 1, 2, 3, 4, 5],
            [2, 6, 7, 8, 9, 10],
            [0x33; 32],
            rsn.clone(),
        );
        // WPA2 M1 with the Key Information descriptor version flipped 2→0
        // (0x008a → 0x0088): ACK | Pairwise, version 0.
        let m1 = hex("0203005f0200880010000000000000000122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let reply = match session.process(&m1) {
            Ok(reply) => reply,
            Err(error) => return TestResult::Fail(error),
        };
        if reply.keys.is_some() || session.complete() {
            return TestResult::Fail("WPA3 M1 opened controlled port");
        }
        let m2 = KeyFrame::decode(&reply.bytes[4..], 16).unwrap();
        if m2.key_information != (KI_KEY_MIC | KI_KEY_TYPE_PAIRWISE) {
            return TestResult::Fail("WPA3 M2 not Key Descriptor Version 0");
        }
        let mut expected_kd = alloc::vec![48u8, rsn.len() as u8];
        expected_kd.extend_from_slice(&rsn);
        if m2.key_data != expected_kd {
            return TestResult::Fail("WPA3 M2 did not echo the SAE RSN IE");
        }
        // Independently recompute the MIC: AES-128-CMAC(KCK, M2|mic=0),
        // KCK from the SHA-256 KDF-Length PTK.
        let kck = wpa::derive_ptk_sha256(
            &[0x11; 32],
            &[2, 1, 2, 3, 4, 5],
            &[2, 6, 7, 8, 9, 10],
            &[0x22; 32],
            &[0x33; 32],
            16,
        )
        .kck;
        let mut zeroed = reply.bytes.clone();
        zeroed[81..97].fill(0);
        let expected = wpa::compute_mic_cmac(&kck, &zeroed);
        if reply.bytes[81..97] != expected {
            return TestResult::Fail("WPA3 M2 MIC is not AES-128-CMAC over the SHA-256 KCK");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_wpa3_sae_m1_m2_descriptor_and_cmac_mic
    );
    fn smoke_negotiated_rsnxe_binds_m2_and_authenticated_m3_before_keys() -> TestResult {
        (|| {
            let (session, m1, m3) = fixture();
            let mut session =
                session.with_rsn_extensions(Some(alloc::vec![0x20]), Some(alloc::vec![0x20]))?;
            let response = session.process(&m1)?;
            let m2 = KeyFrame::decode(&response.bytes[4..], 16).ok_or("RSNXE M2 decode")?;
            let mut expected = alloc::vec![48, session.ap_rsn.len() as u8];
            expected.extend_from_slice(&session.ap_rsn);
            expected.extend_from_slice(&[244, 1, 0x20]);
            if m2.key_data != expected {
                return Err("M2 omitted/changed negotiated station RSNXE");
            }
            let ptk = session.ptk.as_ref().unwrap();
            let mut unsigned = response.bytes.clone();
            unsigned[81..97].fill(0);
            if m2.key_mic.as_slice() != handshake::compute_mic(&ptk.kck, &unsigned) {
                return Err("M2 MIC did not authenticate RSNXE");
            }
            let kck = ptk.kck.clone();
            let kek: [u8; 16] = ptk.kek.as_slice().try_into().unwrap();
            // Independently authenticated, encrypted M3 variants: absent,
            // changed and duplicate AP RSNXE must preserve M1's state.
            for variants in [
                alloc::vec![],
                alloc::vec![0],
                alloc::vec![0x20, 0x20],
                alloc::vec![0x20],
            ] {
                let mut clear = alloc::vec![48, session.ap_rsn.len() as u8];
                clear.extend_from_slice(&session.ap_rsn);
                for value in &variants {
                    clear.extend_from_slice(&[244, 1, *value]);
                }
                clear.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
                clear.extend_from_slice(&[0x77; 16]);
                if clear.len() % 8 != 0 {
                    clear.push(221);
                }
                while clear.len() % 8 != 0 {
                    clear.push(0);
                }
                let mut challenge = KeyFrame::decode(&m3[4..], 16).ok_or("RSNXE M3 decode")?;
                challenge.key_data =
                    narf_crypto::aes_kw::aes_wrap(&kek, &clear).ok_or("RSNXE M3 wrap")?;
                handshake::install_mic(&mut challenge, &kck);
                let result = session.process(&challenge.into_eapol());
                if variants == [0x20] {
                    if result?.keys.is_none() || !session.complete() {
                        return Err("valid authenticated AP RSNXE did not complete");
                    }
                } else if result.is_ok() || session.complete() || session.replay != 1 {
                    return Err("authenticated RSNXE mismatch mutated replay/key owner");
                }
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/security",
        smoke_negotiated_rsnxe_binds_m2_and_authenticated_m3_before_keys
    );
}

pub(super) type RsnExtensions = (Option<Vec<u8>>, Option<Vec<u8>>);

pub struct Session {
    akm: Akm,
    pmf: bool,
    pmk: [u8; 32],
    ap: [u8; 6],
    local: [u8; 6],
    snonce: [u8; 32],
    anonce: [u8; 32],
    ptk: Option<Ptk>,
    replay: u64,
    ap_rsn: Vec<u8>,
    /// Exact station RSNE body sent in the association request (SAE: with
    /// its PMKID). `None` keeps the AKM's default body.
    sta_rsn: Option<Vec<u8>>,
    /// Exact Association station/AP RSNXE bodies when explicitly bound.
    rsn_extensions: Option<RsnExtensions>,
    last_request: Vec<u8>,
    last_response: Vec<u8>,
    initial_key_data: Vec<u8>,
    complete: bool,
    pending_rekey: Option<Box<Session>>,
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
        akm: Akm,
        pmk: [u8; 32],
        ap: [u8; 6],
        local: [u8; 6],
        snonce: [u8; 32],
        ap_rsn: Vec<u8>,
    ) -> Self {
        Self {
            akm,
            pmf: matches!(akm, Akm::Wpa3Sae | Akm::Wpa3SaeExtKey),
            pmk,
            ap,
            local,
            snonce,
            anonce: [0; 32],
            ptk: None,
            replay: 0,
            ap_rsn,
            sta_rsn: None,
            rsn_extensions: None,
            last_request: Vec::new(),
            last_response: Vec::new(),
            initial_key_data: Vec::new(),
            complete: false,
            pending_rekey: None,
        }
    }

    pub fn complete(&self) -> bool {
        self.complete
    }
    /// PMF is negotiated by the RSNE, independently of the PSK/SAE AKM.
    pub(super) fn with_pmf(mut self, pmf: bool) -> Self {
        self.pmf = pmf;
        self
    }

    /// Echo `rsn` (the exact association-request RSNE body) in message 2
    /// instead of the AKM default, as wpa_supplicant echoes `assoc_wpa_ie`
    /// (IEEE 802.11-2020 12.7.6.3). Pairwise rekeys keep the same body.
    pub fn with_station_rsn(mut self, rsn: Vec<u8>) -> Self {
        self.sta_rsn = Some(rsn);
        self
    }

    /// wpa_supplicant assoc_rsnxe is repeated beside assoc_wpa_ie in
    /// M2; AP RSNXE must match the authenticated M3 (rsn_supp/wpa.c).
    /// Bodies come from the checked association plan and received AP IEs.
    pub(super) fn with_rsn_extensions(
        mut self,
        station: Option<Vec<u8>>,
        ap: Option<Vec<u8>>,
    ) -> Result<Self, &'static str> {
        for body in [station.as_deref(), ap.as_deref()].into_iter().flatten() {
            if body.is_empty() || body.len() > 16 || usize::from(body[0] & 15) + 1 != body.len() {
                return Err("invalid negotiated RSNXE body");
            }
        }
        self.rsn_extensions = Some((station, ap));
        Ok(self)
    }

    pub fn process(&mut self, pdu: &[u8]) -> Result<Response, &'static str> {
        self.process_with_nonce(pdu, fresh_nonce)
    }

    // The old PTK remains active while the unauthenticated M1 is pending.
    // Commit only after a valid M3 MIC/RSN/wrapped-key check using fresh SNonce.
    pub(super) fn process_with_nonce(
        &mut self,
        pdu: &[u8],
        nonce: impl FnOnce() -> Result<[u8; 32], &'static str>,
    ) -> Result<Response, &'static str> {
        if self.complete
            && pdu.len() >= 99
            && matches!(pdu[0], 1..=3)
            && pdu[1] == 3
            && u16::from_be_bytes([pdu[2], pdu[3]]) as usize == pdu.len() - 4
        {
            let key = KeyFrame::decode(&pdu[4..], 16).ok_or("invalid EAPOL key")?;
            if key.key_information == (self.akm.ki_version() | KI_KEY_ACK | KI_KEY_TYPE_PAIRWISE) {
                if let Some(pending) = &mut self.pending_rekey {
                    if pdu == pending.last_request {
                        return pending.process_inner(pdu);
                    }
                }
                if key.replay_counter <= self.replay
                    || key.key_nonce == self.anonce
                    || key.key_nonce == [0; 32]
                {
                    return Err("stale pairwise rekey challenge");
                }
                let mut candidate = Box::new(Session::new(
                    self.akm,
                    self.pmk,
                    self.ap,
                    self.local,
                    nonce()?,
                    self.ap_rsn.clone(),
                ));
                candidate.sta_rsn = self.sta_rsn.clone();
                candidate.rsn_extensions = self.rsn_extensions.clone();
                candidate.pmf = self.pmf;
                let reply = candidate.process_inner(pdu)?;
                self.pending_rekey = Some(candidate);
                return Ok(reply);
            }
            if key.pairwise()
                && self
                    .pending_rekey
                    .as_ref()
                    .is_some_and(|p| p.anonce == key.key_nonce)
            {
                if key.replay_counter <= self.replay {
                    return Err("stale rekey completion");
                }
                let pending = self.pending_rekey.as_mut().unwrap();
                let response = pending.process_inner(pdu)?;
                if pending.complete {
                    let replacement = self.pending_rekey.take().unwrap();
                    *self = *replacement; // Drop zeroizes the previous PTK.
                }
                return Ok(response);
            }
        }
        self.process_inner(pdu)
    }

    fn process_inner(&mut self, pdu: &[u8]) -> Result<Response, &'static str> {
        if pdu.len() < 99
            || !matches!(pdu[0], 1..=3)
            || pdu[1] != 3
            || u16::from_be_bytes([pdu[2], pdu[3]]) as usize != pdu.len() - 4
        {
            return Err("invalid EAPOL envelope");
        }
        let key = KeyFrame::decode(&pdu[4..], 16).ok_or("invalid EAPOL key")?;
        if pdu.len() != 99 + key.key_data.len()
            || key.descriptor_type != KEY_DESCRIPTOR_RSN
            || key.key_information & 7 != self.akm.ki_version()
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
            if key.key_information != (self.akm.ki_version() | KI_KEY_ACK | KI_KEY_TYPE_PAIRWISE)
                || key.key_nonce == [0; 32]
            {
                return Err("invalid message 1");
            }
            let ptk = self.akm.derive_ptk(
                &self.pmk,
                &self.ap,
                &self.local,
                &key.key_nonce,
                &self.snonce,
                16,
            );
            let mut reply = KeyFrame::empty(16);
            reply.key_information = self.akm.ki_version() | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
            reply.replay_counter = key.replay_counter;
            reply.key_nonce = self.snonce;
            let rsn = self
                .sta_rsn
                .clone()
                .unwrap_or_else(|| self.akm.sta_rsn_ie());
            reply.key_data.extend_from_slice(&[48, rsn.len() as u8]);
            reply.key_data.extend_from_slice(&rsn);
            if let Some(station) = self
                .rsn_extensions
                .as_ref()
                .and_then(|(station, _)| station.as_ref())
            {
                reply
                    .key_data
                    .extend_from_slice(&[244, station.len() as u8]);
                reply.key_data.extend_from_slice(station);
            }
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
            let expected = self.akm.mic(&ptk.kck, &authenticated);
            if expected
                .iter()
                .zip(&pdu[81..97])
                .fold(0, |diff, (a, b)| diff | (a ^ b))
                != 0
            {
                return Err("EAPOL MIC mismatch");
            }
            let common =
                self.akm.ki_version() | KI_KEY_ACK | KI_KEY_MIC | KI_SECURE | KI_ENCRYPTED_KEY_DATA;
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
            if pairwise_message
                && self
                    .rsn_extensions
                    .as_ref()
                    .is_some_and(|(_, ap)| !matches_rsnxe(&clear, ap.as_deref()))
            {
                return Err("AP RSNXE changed during handshake");
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
            // A PMF association requires its initial IGTK irrespective of
            // AKM. Group rekeys may retain the already-installed IGTK.
            let igtk = if self.pmf {
                match rekey::parse_igtk_kde(&clear) {
                    Some(kde) => Some((kde.igtk, kde.key_id, kde.ipn)),
                    None if pairwise_message && !self.complete => {
                        return Err("PMF message 3 lacks IGTK")
                    }
                    None => None,
                }
            } else {
                None
            };
            let mut reply = KeyFrame::empty(16);
            reply.key_information = self.akm.ki_version()
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
                    igtk,
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
        let mic = self.akm.mic(&self.ptk.as_ref().unwrap().kck, &bytes);
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

/// Bounded singleton RSNXE in authenticated key data, allowing only the
/// standard0xdd/zero AES-wrap padding after the final complete element.
fn matches_rsnxe(mut bytes: &[u8], expected: Option<&[u8]>) -> bool {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes[0] == 221 && (bytes.len() == 1 || bytes[1] == 0) {
            if bytes[1..].iter().any(|byte| *byte != 0) {
                return false;
            }
            break;
        }
        if bytes.len() < 2 || bytes.len() < 2 + usize::from(bytes[1]) {
            return false;
        }
        let body = &bytes[2..2 + usize::from(bytes[1])];
        if bytes[0] == 244 {
            if found.is_some() {
                return false;
            }
            found = Some(body);
        }
        bytes = &bytes[2 + usize::from(bytes[1])..];
    }
    found == expected
}
