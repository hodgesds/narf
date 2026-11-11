//! NIST SP 800-38D (the GCM submission's Test Cases 2-4 and 14-16) and
//! IEEE 802.11 GCMP-128/256 and BIP-GMAC-128/256 vectors (802.11ad-2012
//! M.11.1, 802.11ac D7.0 M.11.1 and M.9.1, as carried by hostap
//! `wlantest/test_vectors.c`).
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn hex(text: &str) -> Vec<u8> {
    let digit = |v: u8| {
        if v <= b'9' {
            v - b'0'
        } else {
            (v | 0x20) - b'a' + 10
        }
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect()
}
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

const P64: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const IV: &str = "cafebabefacedbaddecaf888";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

struct Case {
    key: &'static str,
    iv: &'static str,
    plain: &'static str,
    aad: &'static str,
    cipher: &'static str,
    tag: &'static str,
}

fn nist() -> Result<(), &'static str> {
    let k128 = "feffe9928665731c6d6a8f9467308308";
    let k256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    let c3 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
              21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
    let c15 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
               8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
    let cases = [
        Case {
            key: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            plain: "00000000000000000000000000000000",
            aad: "",
            cipher: "0388dace60b6a392f328c2b971b2fe78",
            tag: "ab6e47d42cec13bdf53a67b21257bddf",
        },
        Case {
            key: k128,
            iv: IV,
            plain: P64,
            aad: "",
            cipher: c3,
            tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        Case {
            key: k128,
            iv: IV,
            plain: &P64[..120],
            aad: AAD,
            cipher: &c3[..120],
            tag: "5bc94fbc3221a5db94fae95ae7121a47",
        },
        Case {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            iv: "000000000000000000000000",
            plain: "00000000000000000000000000000000",
            aad: "",
            cipher: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        Case {
            key: k256,
            iv: IV,
            plain: P64,
            aad: "",
            cipher: c15,
            tag: "b094dac5d93471bdec1a502270e3cc6c",
        },
        Case {
            key: k256,
            iv: IV,
            plain: &P64[..120],
            aad: AAD,
            cipher: &c15[..120],
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
    ];
    for case in cases {
        let (key, nonce, aad) = (hex(case.key), array(&hex(case.iv)), hex(case.aad));
        let plain = hex(case.plain);
        let tag: [u8; TAG_LEN] = array(&hex(case.tag));
        let mut body = plain.clone();
        if seal(&key, &nonce, &aad, &mut body) != Ok(tag) || body != hex(case.cipher) {
            return Err("SP 800-38D ciphertext or tag");
        }
        if open(&key, &nonce, &aad, &mut body, &tag) != Ok(()) || body != plain {
            return Err("SP 800-38D known ciphertext did not open");
        }
    }
    Ok(())
}
fn smoke_gcm_sp800_38d_vectors() -> TestResult {
    nist().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("crypto/gcm", smoke_gcm_sp800_38d_vectors);

/// GCMP AAD and nonce (IEEE 802.11-2020 §12.5.5.3.3/4, as CCMP §12.5.3.3.3):
/// a 26-octet QoS Data header with the 8-octet GCMP header after it.
fn gcmp_aad_nonce(mpdu: &[u8]) -> (Vec<u8>, [u8; NONCE_LEN]) {
    let mut aad = Vec::new();
    aad.push(mpdu[0] & 0x8f);
    aad.push((mpdu[1] & !0x38) | 0x40);
    aad.extend_from_slice(&mpdu[4..22]);
    aad.extend_from_slice(&[mpdu[22] & 0x0f, 0]);
    aad.extend_from_slice(&[mpdu[24] & 0x0f, 0]);
    let header = &mpdu[26..34];
    let mut nonce = [0; NONCE_LEN];
    nonce[..6].copy_from_slice(&mpdu[10..16]);
    nonce[6..].copy_from_slice(&[
        header[7], header[6], header[5], header[4], header[1], header[0],
    ]);
    (aad, nonce)
}

fn gcmp() -> Result<(), &'static str> {
    // QoS Data, Protected + Retry, TID 3, and its GCMP header: PN
    // 0x00895f5f2b08, key ID 0, ExtIV.
    let header = hex("88480b000fd2e128a57c5030f1844408\
                      5030f184440880330300");
    let gcmp_header = hex("082b00205f5f8900");
    let payload: Vec<u8> = (0u8..40).collect();
    let tk128 = hex("c97c1f67ce371185514a8a19f2bdd52f");
    let mut tk256 = tk128.clone();
    tk256.extend(0u8..16);
    let vectors: [(&[u8], &str, &str); 2] = [
        // 802.11ad-2012 M.11.1 GCMP test MPDU #2.
        (
            &tk128,
            "60e9700cc4d40ac6d288b201c38f5bf08b807442640a1596e5dbdad41d1f3623\
             f45d7a12db7afb23",
            "def619c2a374b6df66ffa53b6c69d79e",
        ),
        // 802.11ac D7.0 M.11.1 GCMP-256.
        (
            &tk256,
            "658343c8b14447d9211defd46ad89c710c6fc33333236e3997b9176a5a8be779\
             b21266555e70ad79",
            "114316859095473d5b1bd596b3dea3bf",
        ),
    ];
    for (key, encrypted, mic) in vectors {
        let mut mpdu = header.clone();
        mpdu.extend_from_slice(&gcmp_header);
        let (aad, nonce) = gcmp_aad_nonce(&mpdu);
        let mut body = payload.clone();
        let tag = seal(key, &nonce, &aad, &mut body).map_err(|_| "GCMP seal")?;
        if body != hex(encrypted) || tag[..] != hex(mic)[..] {
            return Err("802.11 GCMP ciphertext or MIC");
        }
        let mut tampered = body.clone();
        tampered[0] ^= 1;
        if open(key, &nonce, &aad, &mut tampered, &tag) != Err(Error::Authentication)
            || tampered[0] != body[0] ^ 1
        {
            return Err("a forged GCMP MPDU opened or changed the buffer");
        }
        open(key, &nonce, &aad, &mut body, &tag).map_err(|_| "802.11 GCMP open")?;
        if body != payload {
            return Err("802.11 GCMP plaintext");
        }
    }
    Ok(())
}
fn smoke_gcm_ieee80211_gcmp_vectors() -> TestResult {
    gcmp().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("crypto/gcm", smoke_gcm_ieee80211_gcmp_vectors);

/// BIP-GMAC over a broadcast Deauthentication (802.11ac D7.0 M.9.1): AAD is
/// the masked FC and A1-A3, then the body with the MME MIC zeroed; the
/// nonce is A2 || IPN (big endian).
fn bip_gmac() -> Result<(), &'static str> {
    let frame = hex("c0000000ffffffffffff020000000000020000000000090002004c180400040000000000");
    let igtk128 = hex("4ea9543e09cf2b1eca66ffc58bdecbcf");
    let mut igtk256 = igtk128.clone();
    igtk256.extend(0u8..16);
    let mut aad = Vec::new();
    aad.extend_from_slice(&[frame[0], frame[1] & !0x38]);
    aad.extend_from_slice(&frame[4..22]);
    aad.extend_from_slice(&frame[24..]);
    aad.extend_from_slice(&[0; TAG_LEN]);
    let mut nonce = [0; NONCE_LEN];
    nonce[..6].copy_from_slice(&frame[10..16]);
    nonce[6..].copy_from_slice(&[0, 0, 0, 0, 0, 4]);
    for (key, mic) in [
        (&igtk128, "3ed862fb0f3338dd3386c897e2ed053d"),
        (&igtk256, "23be59dcc7022ee383627ebb1017ddfc"),
    ] {
        let mic: [u8; TAG_LEN] = array(&hex(mic));
        if gmac(key, &nonce, &aad) != Ok(mic) || gmac_verify(key, &nonce, &aad, &mic) != Ok(()) {
            return Err("802.11 BIP-GMAC MIC");
        }
        let mut forged = mic;
        forged[15] ^= 0x80;
        if gmac_verify(key, &nonce, &aad, &forged) != Err(Error::Authentication) {
            return Err("a forged BIP-GMAC MIC verified");
        }
    }
    if gmac(&[0; 24], &nonce, &aad) != Err(Error::Key) {
        return Err("a 192-bit key was accepted");
    }
    Ok(())
}
fn smoke_gcm_ieee80211_bip_gmac_vectors() -> TestResult {
    bip_gmac().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("crypto/gcm", smoke_gcm_ieee80211_bip_gmac_vectors);
