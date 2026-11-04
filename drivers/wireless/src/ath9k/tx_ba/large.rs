// SPDX-License-Identifier: GPL-2.0-or-later
//! N85T v4 is a distinct complete variable-member program, never an
//! interpretation of accepted two-member v1/v2/v3 records.
use super::*;
pub(in crate::ath9k) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF AR9285 N85T full20/40 directionalGI bounded8 sender v4");
    hash.update(&identity);
    hash.update(&digest);
    hash.update(&mac);
    hash.update(&[base.version()]);
    hash.update(&base.geometry().body());
    hash.update(b"all preceding exact H1/H2/H3 factory/calibration/rates/CTL/power/policy/readbacks remain current; separate signed whole-program all temperature/supply/antenna/BT/posture envelope for1..8 original QoS TID0 MPDUs, each34..1550 plus FCS, maximum65535air and4ms, min negotiated factor and halfBAW; source actual NDBPS20/40, directionalSGI40 noSGI20; min256 padding and actual negotiated density for every preceding member, ent_mode0 and softwareCCMP no hardware-key/encryptiondelimiter or OTP60 quirk");
    hash.update(b"actual eight-slot nonEDMA descriptor ring plus separate DMA maps: firstIsAggrMoreAggr owns rate/retry/wholePPDUduration/AggrLen; middleIsAggrMoreAggr has ownPadDelim zero rate/tries, actual next DMA link; lastIsAggr NULL no trailing padding; no per-memberMore-fragment or per-MPDU hardware retry; every original header/independent PN and SC frozen before transportpad2");
    hash.update(b"preflight exact available Ethernet prefix lengths before shared PN/SC reservation; current publication lock and source gates before encoding/publishing; tailTxDone AND QCUidle, all immutable descriptors and all padded payloads proven before release; native BAflag/TID/SSN/64bitmap resolves each member across4095wrap, wrongTID retries all, TxOKwithoutBA terminal; up to3 immutable per-original normalACK software retries samePN/SC/ciphertext Retrybitonly then nativeBAR exact target/BAproof+RXidle before new sequence; keyepoch invalidates all retryCPU authority without releasing publishedDMA; source/policy/copy/stop/cancel/retune/recovery terminal ownership unchanged");
    hash.update(b"N85Q otherTID normalACK singles use independent SC/PN and actual ownQCU; never advance or recover TID0 senderBA head; only exact original QoS TID0 singles consume this BAW");
    hash.update(b"signed v4 members3..8/air1..65535 narrow runtime; bound body includes peak ceiling and halfBAW window4..64; missing new source preserves exact legacy two-frame records; no synthetic board measurements");
    Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-txba-v4-ch{}-ext{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            base.channel(),
            base.geometry().secondary().unwrap_or(0),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ),
    }
}
pub(super) fn decode(
    b: &[u8],
    signer: Option<[u8; 32]>,
    cap: Cap<FirmwareBlob, Read>,
    base: Arc<ht::Grant>,
) -> Result<Grant, Error> {
    let r = request(&base);
    if signer.is_none()
        || b.len() != 128
        || b[..8] != [b'N', b'8', b'5', b'T', 4, 0, 128, 0]
        || b[8..12] != 128u32.to_le_bytes()
        || b[12..16] != [0x8c, 0x16, 0x2b, 0]
        || b[16..48] != r.identity
        || b[48..54] != r.mac
        || b[54..58] != base.geometry().body()
        || !(4..=64).contains(&b[60])
        || b[61] != RETRIES
        || !(3..=MAX_MEMBERS as u8).contains(&b[64])
        || b[65] != base.version()
        || b[68..100] != base.ba_identity().1
        || b[100..] != [0; 28]
    {
        return Err(Error::Packet);
    }
    let grant = Grant {
        base,
        cap,
        peak: i16::from_le_bytes([b[58], b[59]]),
        ceiling: i16::from_le_bytes([b[62], b[63]]),
        window: b[60],
        members: usize::from(b[64]),
        max_air: usize::from(u16::from_le_bytes([b[66], b[67]])),
    };
    if !(-512..=256).contains(&grant.peak)
        || !(-512..=256).contains(&grant.ceiling)
        || grant.max_air == 0
    {
        return Err(Error::Packet);
    }
    Ok(grant)
}
#[cfg(feature = "kernel-test")]
#[path = "large_tests.rs"]
pub(in crate::ath9k) mod tests;
