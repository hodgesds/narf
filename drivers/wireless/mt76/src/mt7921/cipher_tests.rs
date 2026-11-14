//! GCMP-128/256 and CCMP-256 with BIP-GMAC-128/256 and BIP-CMAC-256: the
//! supplicant's selected ciphers (its RSNE in the CONNECT elements) drive
//! the shared plan's RSNE, the 4-way key lengths, the STA_REC_KEY_V2
//! cipher IDs (mt76_connac_mcu_get_cipher) and software BIP verification
//! (mt7921_set_key refuses those IGTKs; mac80211 verifies in software),
//! against `FakeAp` offering the same suites.
use super::pmf_tests::prepared;
use super::*;
use crate::mt7921::association::{SaePassword, Security};
use alloc::boxed::Box;
use narf_wifi_fixtures::{ApPhase, ApPmf, ApSaePwe, FakeAp};
use narf_wireless::rsn::{self, Ciphers, RsnIe, Suite};

const PASSWORD: &[u8] = b"narf-sae-password";

fn ap(ciphers: Ciphers, sae: bool) -> FakeAp {
    let ap = if sae {
        FakeAp::wpa3_sae(
            super::wmm_tests::NETWORK,
            b"narf",
            6,
            42,
            PASSWORD,
            ApSaePwe::HuntAndPeck,
            [0xaa; 32],
        )
    } else {
        FakeAp::wpa2(
            super::wmm_tests::NETWORK,
            b"narf",
            6,
            42,
            [0x55; 32],
            [0xaa; 32],
        )
        .and_then(|ap| ap.with_pmf(ApPmf::Required))
    };
    ap.and_then(|ap| ap.with_ciphers(ciphers)).unwrap()
}

/// The supplicant's RSNE (`wpa_gen_wpa_ie_rsn`) naming `ciphers`.
fn supplicant_rsne(ciphers: Ciphers, sae: bool) -> Vec<u8> {
    let body = RsnIe {
        version: 1,
        group_cipher: Suite::standard(ciphers.group),
        pairwise_ciphers: vec![Suite::standard(ciphers.pairwise)],
        akms: vec![Suite::standard(if sae {
            rsn::AKM_SAE
        } else {
            rsn::AKM_PSK
        })],
        rsn_capabilities: rsn::RSN_CAP_MFP_CAPABLE | rsn::RSN_CAP_MFP_REQUIRED,
        pmkids: Vec::new(),
        group_management_cipher: Some(Suite::standard(ciphers.group_mgmt)),
    }
    .encode_body();
    let mut out = vec![48, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// The STA_REC_KEY_V2 (tag 17) single-key records, as (wcid, cipher id,
/// key id, key).
fn key_records(session: &Session<Model>) -> Vec<(u8, u8, u8, Vec<u8>)> {
    session
        .backend
        .frames
        .iter()
        .map(|(_, f)| f)
        .filter_map(|f| {
            let at = f.len().checked_sub(44)?;
            let body = f.get(at..)?;
            (body[..6] == [17, 0, 44, 0, 0, 1]).then(|| {
                let len = usize::from(body[11]);
                (
                    f[f.len() - 44 - 8 + 1],
                    body[8],
                    body[10],
                    body[12..12 + len].to_vec(),
                )
            })
        })
        .collect()
}

fn run_case(ciphers: Ciphers, sae: bool, mcu: u8, mac: u8) -> Result<(), &'static str> {
    let (mut session, bss) = prepared(ap(ciphers, sae));
    let security = if sae {
        Security::Wpa3Sae {
            password: SaePassword::new(PASSWORD).unwrap(),
        }
    } else {
        Security::Wpa2PskPmf {
            psk: [0x55; 32],
            required: true,
        }
    };
    let joined = run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        security,
        test_permission(),
        &supplicant_rsne(ciphers, sae),
    )));
    if joined != Ok(42) {
        return Err(match (ciphers.pairwise, joined) {
            (rsn::CIPHER_GCMP_128, _) => "GCMP-128 association",
            (rsn::CIPHER_GCMP_256, Err(Error::MalformedEvent)) => "GCMP-256 association: malformed",
            (rsn::CIPHER_GCMP_256, Err(Error::Bounds)) => "GCMP-256 association: bounds",
            (rsn::CIPHER_GCMP_256, Err(Error::Authority)) => "GCMP-256 association: authority",
            (rsn::CIPHER_GCMP_256, _) => "GCMP-256 association",
            (_, Err(Error::MalformedEvent)) => "CCMP-256 association: malformed",
            (_, Err(Error::Bounds)) => "CCMP-256 association: bounds",
            _ => "CCMP-256 association",
        });
    }
    let fake = session.backend.access_point.as_ref().unwrap();
    let (Some(tk), Some(gtk), Some((igtk, _))) =
        (fake.pairwise_key(), fake.group_key(), fake.igtk_key())
    else {
        return Err("AP keys");
    };
    if fake.phase() != ApPhase::Authorized
        || tk.len() != ciphers.pairwise_key_len()
        || gtk.len() != ciphers.group_key_len()
        || igtk.len() != ciphers.mgmt_key_len()
    {
        return Err("4-way key lengths");
    }
    // The association request repeats the selected suites.
    let request = session
        .backend
        .frames
        .iter()
        .map(|(_, f)| f)
        .find(|f| f.first() == Some(&0x00))
        .ok_or("no association request")?;
    if !request
        .windows(4)
        .any(|w| w == [0x00, 0x0f, 0xac, ciphers.pairwise])
        || !request
            .windows(4)
            .any(|w| w == [0x00, 0x0f, 0xac, ciphers.group_mgmt])
    {
        return Err("association request RSNE suites");
    }
    // The peer's pairwise key in its full STA record, the GTK as a key
    // record, both with the selected MCU cipher.
    let records = key_records(&session);
    let secure = session.backend.frames.iter().map(|(_, f)| f).any(|f| {
        f.windows(4 + tk.len())
            .any(|w| w[..4] == [mcu, 36, 0, tk.len() as u8] && w[4..] == tk[..])
    });
    if !secure
        || !records
            .iter()
            .any(|(_, cipher, id, key)| *cipher == mcu && *id == 1 && *key == gtk)
    {
        return Err("pairwise/group key records and cipher IDs");
    }
    // No hardware IGTK record: mt7921_set_key takes only AES-CMAC.
    if session
        .backend
        .frames
        .iter()
        .any(|(_, f)| f.len() > 88 && f[f.len() - 80..f.len() - 72] == [17, 0, 80, 0, 0, 2, 0, 0])
    {
        return Err("a BIP-GMAC/CMAC-256 IGTK reached the hardware");
    }
    // Hardware decryption under the negotiated cipher only.
    let security = session.station.security.as_ref().ok_or("security")?;
    for (cipher, admitted) in [(mac, true), (4, false)] {
        let rx = super::scan::CcmpRx {
            pn: 1,
            key_id: 0,
            cipher,
        };
        if security.decrypted_by(&rx) != admitted {
            return Err("RXD cipher check");
        }
    }
    // Software BIP: a forged broadcast deauth is ignored, a valid one ends
    // the link.
    let bip = session
        .backend
        .access_point
        .as_mut()
        .unwrap()
        .bip_broadcast_deauth(3)
        .map_err(|_| "BIP deauth")?;
    let mut forged = bip.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    session
        .backend
        .packets
        .push_back(super::descriptor(&forged));
    if !session.receive_ethernet().is_ok_and(|f| f.is_none()) || session.station.peer_lost {
        return Err("forged BIP deauth accepted");
    }
    session.backend.packets.push_back(super::descriptor(&bip));
    if session.receive_ethernet() != Err(Error::DeviceGone) {
        return Err("valid BIP deauth ignored");
    }
    Ok(())
}

fn mt76_gcmp_ccmp256_and_bip_suites_follow_the_supplicant() -> TestResult {
    let cases = [
        (
            Ciphers {
                pairwise: rsn::CIPHER_GCMP_128,
                group: rsn::CIPHER_GCMP_128,
                group_mgmt: rsn::CIPHER_BIP_GMAC_128,
            },
            false,
            7,
            11,
        ),
        (
            Ciphers {
                pairwise: rsn::CIPHER_GCMP_256,
                group: rsn::CIPHER_GCMP_256,
                group_mgmt: rsn::CIPHER_BIP_GMAC_256,
            },
            true,
            8,
            12,
        ),
        (
            Ciphers {
                pairwise: rsn::CIPHER_CCMP_256,
                group: rsn::CIPHER_CCMP_256,
                group_mgmt: rsn::CIPHER_BIP_CMAC_256,
            },
            false,
            6,
            10,
        ),
    ];
    for (ciphers, sae, mcu, mac) in cases {
        if let Err(error) = run_case(ciphers, sae, mcu, mac) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_gcmp_ccmp256_and_bip_suites_follow_the_supplicant
);

/// A supplicant selection the AP does not offer is refused before any
/// association request.
fn mismatch() -> Result<(), &'static str> {
    let (mut session, bss) = prepared(ap(Ciphers::LEGACY, false));
    let gcmp = Ciphers {
        pairwise: rsn::CIPHER_GCMP_256,
        group: rsn::CIPHER_GCMP_256,
        group_mgmt: rsn::CIPHER_BIP_GMAC_256,
    };
    let joined = run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        Security::Wpa2PskPmf {
            psk: [0x55; 32],
            required: true,
        },
        test_permission(),
        &supplicant_rsne(gcmp, false),
    )));
    if joined.is_ok()
        || session
            .backend
            .frames
            .iter()
            .any(|(_, f)| f.first() == Some(&0x00))
    {
        return Err("a cipher the AP does not offer was negotiated");
    }
    Ok(())
}
fn mt76_cipher_selection_the_ap_does_not_offer_is_refused() -> TestResult {
    mismatch().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_cipher_selection_the_ap_does_not_offer_is_refused
);
