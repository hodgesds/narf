//! Real AES/MIC/PN/color fragment vectors; no native or port authority.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];
const TK: [u8; 16] = [0x71; 16];
fn header(tx: bool, number: u8, more: bool, tid: Option<u8>, management: bool) -> Vec<u8> {
    let mut h = alloc::vec![0;if tid.is_some(){26}else{24}];
    h[0] = if management {
        0xd0
    } else if tid.is_some() {
        0x88
    } else {
        8
    };
    h[1] =
        0x40 | if management {
            0
        } else if tx {
            1
        } else {
            2
        } | if more { 4 } else { 0 };
    h[4..10].copy_from_slice(&if tx { PEER } else { LOCAL });
    h[10..16].copy_from_slice(&if tx { LOCAL } else { PEER });
    h[16..22].copy_from_slice(&PEER);
    h[22..24].copy_from_slice(&(0x1230 | u16::from(number)).to_le_bytes());
    if let Some(tid) = tid {
        h[24] = tid;
    }
    h
}
fn from_ap(header: &[u8], pn: u64, body: &[u8]) -> Vec<u8> {
    let priority = if header[0] == 0x88 {
        header[24] & 15
    } else {
        0
    };
    let management = header[0] & 12 == 0;
    let mut body = body.to_vec();
    ccmp::protect(&Ccm, header, &TK, pn, 0, priority, management, &mut body).unwrap()
}
fn transmit() -> Result<(), &'static str> {
    for (tid, management) in [(None, false), (Some(7), false), (None, true)] {
        let mut key = Key::new(&TK, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
        for (number, more) in [(0, true), (1, true), (2, false)] {
            let h = header(true, number, more, tid, management);
            let wire = key
                .protect_fragment(&h, b"original fragment")
                .map_err(|_| "fragment TX")?;
            if key.protect(&h, b"ordinary must refuse").is_ok()
                || key.tx_pn != u64::from(number) + 1
            {
                return Err("fragment API weakened ordinary rejection or PN count");
            }
            let mut replay = ReplayWindow { last_seen_pn: 0 };
            let mut bytes = wire.clone();
            if ccmp::unprotect(
                &Ccm,
                &h,
                &TK,
                tid.unwrap_or(0),
                management,
                &mut replay,
                &mut bytes,
            )
            .map_err(|_| "actual fragment nonce/MIC")?
                != b"original fragment"
            {
                return Err("fragment cipher bytes");
            }
            // Both MoreFrag and the fragment number are authenticated exactly.
            for (offset, mask) in [(1, 4), (22, 1)] {
                let mut forged = h.clone();
                forged[offset] ^= mask;
                let mut bytes = wire.clone();
                let mut replay = ReplayWindow { last_seen_pn: 0 };
                if ccmp::unprotect(
                    &Ccm,
                    &forged,
                    &TK,
                    tid.unwrap_or(0),
                    management,
                    &mut replay,
                    &mut bytes,
                )
                .is_ok()
                    || bytes != wire
                    || replay.last_seen_pn != 0
                {
                    return Err("fragment header tamper authenticated/poisoned replay");
                }
            }
        }
        key.tx_pn = MAX_PN;
        if key.protect_fragment(&header(true, 0, true, tid, management), b"x")
            != Err(Error::Exhausted)
            || key.tx_pn != MAX_PN
        {
            return Err("fragment PN wrapped");
        }
    }
    Ok(())
}
fn smoke_ccmp_fragment_original_aad_nonce_per_mpdu_pn_and_ordinary_rejection() -> TestResult {
    transmit().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ccmp/fragment",
    smoke_ccmp_fragment_original_aad_nonce_per_mpdu_pn_and_ordinary_rejection
);
fn receive() -> Result<(), &'static str> {
    for failure in 0..7 {
        let mut key = Key::new(&TK, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
        let mut cache = Reassembly::default();
        let first = header(false, 0, true, Some(3), false);
        let mut wire = from_ap(&first, 1, b"first");
        let part = key
            .unprotect_fragment(&first, &mut wire)
            .map_err(|_| "fragment first MIC")?;
        if cache
            .push(part, 10)
            .map_err(|_| "fragment first cache")?
            .is_some()
        {
            return Err("partial MSDU was delivered");
        }
        let mut last = header(false, 1, false, Some(3), false);
        let mut now = 11;
        let mut pn = 2;
        match failure {
            1 => pn = 3,
            2 => {
                last[22] = 0x32;
            }
            3 => now = 2011,
            4 => {
                key.reinstall(&[9; 16], 0).unwrap();
            }
            5 => {
                key.reinstall(&TK, 0).unwrap();
            }
            6 => {
                last[16] ^= 2;
            }
            _ => {}
        }
        let mut wire = if failure == 4 {
            let mut body = b"last".to_vec();
            ccmp::protect(&Ccm, &last, &[9; 16], pn, 0, 3, false, &mut body).unwrap()
        } else {
            from_ap(&last, pn, b"last")
        };
        let part = key
            .unprotect_fragment(&last, &mut wire)
            .map_err(|_| "fragment last MIC")?;
        let result = cache.push(part, now);
        if matches!(failure, 0 | 5) {
            let Some(frame) = result.map_err(|_| "strict fragment join")? else {
                return Err("complete fragment MSDU missing");
            };
            if frame.management()
                || frame.bytes()[1] != 2
                || frame.bytes()[22..24] != 0x1230u16.to_le_bytes()
                || &frame.bytes()[26..] != b"firstlast"
                || cache.pending()
            {
                return Err("fragment result header/body/identity normalization");
            }
        } else if result.as_ref().is_ok_and(|frame| frame.is_some()) {
            return Err("gap/timeout/key-color/address mixing completed MSDU");
        }
    }
    let mut key = Key::new(&TK, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let h = header(false, 0, true, None, true);
    let mut valid = from_ap(&h, 1, b"robust action");
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1;
    let before = forged.clone();
    if key.unprotect_fragment(&h, &mut forged).is_ok()
        || forged != before
        || key.receive[MGMT].last_seen_pn != 0
    {
        return Err("forged fragment poisoned key management replay");
    }
    let part = key
        .unprotect_fragment(&h, &mut valid)
        .map_err(|_| "auth management fragment")?;
    let mut cache = Reassembly::default();
    cache
        .push(part, 0)
        .map_err(|_| "management fragment cache")?;
    drop(key);
    cache.expire(1);
    if cache.pending() {
        return Err("dropped key left live fragment color");
    }
    Ok(())
}
fn smoke_ccmp_fragment_same_key_color_consecutive_pn_timeout_and_forgery() -> TestResult {
    receive().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ccmp/fragment",
    smoke_ccmp_fragment_same_key_color_consecutive_pn_timeout_and_forgery
);
