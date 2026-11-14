//! BIP-GMAC-128/256 against IEEE 802.11ac D7.0 M.9.1 (broadcast
//! Deauthentication, hostap `wlantest/test_vectors.c`); BIP-CMAC-128
//! against the existing CMAC MFP path; replay, forgery and key checks.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn deauth() -> ([u8; 24], Vec<u8>) {
    let mut hdr = [0u8; 24];
    hdr[0] = 0xc0;
    hdr[4..10].fill(0xff);
    hdr[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 0]);
    hdr[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 0]);
    hdr[22] = 9;
    (hdr, vec![2, 0])
}

fn igtk(len: usize) -> Vec<u8> {
    let mut key = vec![
        0x4e, 0xa9, 0x54, 0x3e, 0x09, 0xcf, 0x2b, 0x1e, 0xca, 0x66, 0xff, 0xc5, 0x8b, 0xde, 0xcb,
        0xcf,
    ];
    key.extend(0u8..16);
    key.truncate(len);
    key
}

fn vectors() -> Result<(), &'static str> {
    for (cipher, len, mic) in [
        (
            rsn::CIPHER_BIP_GMAC_128,
            16,
            [
                0x3e, 0xd8, 0x62, 0xfb, 0x0f, 0x33, 0x38, 0xdd, 0x33, 0x86, 0xc8, 0x97, 0xe2, 0xed,
                0x05, 0x3d,
            ],
        ),
        (
            rsn::CIPHER_BIP_GMAC_256,
            32,
            [
                0x23, 0xbe, 0x59, 0xdc, 0xc7, 0x02, 0x2e, 0xe3, 0x83, 0x62, 0x7e, 0xbb, 0x10, 0x17,
                0xdd, 0xfc,
            ],
        ),
    ] {
        let (hdr, mut body) = deauth();
        let mut key = BipKey::new(cipher, &igtk(len), 4, 0).map_err(|_| "IGTK")?;
        key.tx_ipn = 3;
        if bip_protect(&mut key, &hdr, &mut body) != Ok(4) {
            return Err("BIP-GMAC protect");
        }
        let mut expected = vec![2, 0, 0x4c, 0x18, 4, 0, 4, 0, 0, 0, 0, 0];
        expected.extend_from_slice(&mic);
        if body != expected {
            return Err("802.11 BIP-GMAC MMIE");
        }
        let mut store = BipKeyStore::new();
        store.install_active(BipKey::new(cipher, &igtk(len), 4, 3).map_err(|_| "rx IGTK")?);
        if bip_verify(&mut store, &hdr, &body) != Ok(&[2, 0][..]) {
            return Err("BIP-GMAC verify");
        }
        if bip_verify(&mut store, &hdr, &body) != Err(MfpError::Replay) {
            return Err("a replayed IPN verified");
        }
        let mut forged = body.clone();
        forged[0] ^= 1;
        let mut fresh = BipKeyStore::new();
        fresh.install_active(BipKey::new(cipher, &igtk(len), 4, 0).map_err(|_| "rx IGTK")?);
        if bip_verify(&mut fresh, &hdr, &forged) != Err(MfpError::MicFailed)
            || fresh.active.as_ref().map(|key| key.rx_ipn) != Some(0)
        {
            return Err("a forged frame verified or moved the IPN");
        }
    }
    Ok(())
}
fn smoke_bip_gmac_ieee80211_vectors() -> TestResult {
    vectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("wireless/mfp", smoke_bip_gmac_ieee80211_vectors);

fn cmac() -> Result<(), &'static str> {
    // The generic BIP-CMAC-128 matches the existing CMAC path's MMIE.
    let (hdr, plain) = deauth();
    let mut legacy = narf_crypto::bip_cmac::Igtk::install(igtk(16).try_into().unwrap(), 4)
        .map_err(|_| "legacy IGTK")?;
    let mut expected = plain.clone();
    crate::mfp::protect_outbound(&mut legacy, &hdr, &mut expected).map_err(|_| "legacy protect")?;
    let mut key = BipKey::new(rsn::CIPHER_BIP_CMAC_128, &igtk(16), 4, 0).map_err(|_| "IGTK")?;
    let mut body = plain.clone();
    bip_protect(&mut key, &hdr, &mut body).map_err(|_| "CMAC-128 protect")?;
    if body != expected || body.len() != 2 + 18 {
        return Err("BIP-CMAC-128 MMIE differs from the CMAC path");
    }
    // BIP-CMAC-256 round trip with a 16-octet MIC.
    let mut key = BipKey::new(rsn::CIPHER_BIP_CMAC_256, &igtk(32), 5, 0).map_err(|_| "IGTK")?;
    let mut body = plain.clone();
    bip_protect(&mut key, &hdr, &mut body).map_err(|_| "CMAC-256 protect")?;
    let mut store = BipKeyStore::new();
    store.install_active(BipKey::new(rsn::CIPHER_BIP_CMAC_256, &igtk(32), 5, 0).unwrap());
    if body.len() != 2 + 26 || bip_verify(&mut store, &hdr, &body) != Ok(&plain[..]) {
        return Err("BIP-CMAC-256 round trip");
    }
    if BipKey::new(rsn::CIPHER_BIP_GMAC_256, &igtk(16), 4, 0).is_ok()
        || BipKey::new(rsn::CIPHER_BIP_GMAC_128, &igtk(16), 3, 0).is_ok()
    {
        return Err("a wrong key length or key ID was installed");
    }
    Ok(())
}
fn smoke_bip_cmac_generic_matches_legacy() -> TestResult {
    cmac().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("wireless/mfp", smoke_bip_cmac_generic_matches_legacy);
