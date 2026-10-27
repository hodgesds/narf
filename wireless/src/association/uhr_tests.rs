use super::*;
use crate::association::eht::LocalEht;
use crate::association::he::LocalHe;
use crate::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy, LocalVht, Offer};
use crate::association::{Bss, JoinPlan, SecurityMode};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/uhr", $name);
    };
}
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
fn ht40() -> LocalHt {
    let gi = HtGi {
        rx20: true,
        tx20: true,
        rx40: true,
        tx40: true,
    };
    let mcs = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    LocalHt::new(mcs, mcs, HtWidth::TwentyForty, gi, 0, 0).unwrap()
}
fn local(uhr: Option<LocalUhr>) -> LocalPhy {
    let mut he_phy = [0; 11];
    he_phy[0] = 0x04;
    let phy = LocalPhy::vht80(
        ht40(),
        LocalVht::new(0xfffa, 0xfffa, true, true, 0).unwrap(),
    )
    .unwrap()
    .with_he(LocalHe::new([0; 6], he_phy, 0xfffa, 0xfffa).unwrap())
    .unwrap()
    .with_eht(LocalEht::new([0, 0], [0; 9], [0x22, 0x22, 0x11]).unwrap())
    .unwrap();
    match uhr {
        Some(u) => phy.with_uhr(u).unwrap(),
        None => phy,
    }
}
fn npca_local() -> LocalUhr {
    LocalUhr::new([MAC0_NPCA, 0, 0, 0, 0, 0], 0).for_mld_association()
}
fn uhr_cap(mac0: u8, mac1: u8, dbe: &[u8]) -> Vec<u8> {
    let mut b = vec![EXT_UHR_CAPABILITIES, mac0, mac1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    b.extend_from_slice(dbe);
    b
}
fn uhr_op(params: u16, tail: &[u8]) -> Vec<u8> {
    let mut b = vec![EXT_UHR_OPERATION];
    b.extend_from_slice(&params.to_le_bytes());
    b.extend_from_slice(&[0x11, 0, 0, 0]);
    b.extend_from_slice(tail);
    b
}
fn ml_basic() -> Vec<u8> {
    // Multi-Link Control (Basic, no presence bits), Common Info length 7
    // and the AP MLD MAC address.
    vec![EXT_MULTI_LINK, 0, 0, 7, 2, 0, 0, 0, 0, 9]
}
fn elements(uhr: Option<(Vec<u8>, Vec<u8>)>, ml: bool, selector: Option<u8>) -> Vec<u8> {
    let mut b = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    if let Some(s) = selector {
        element(&mut b, 50, &[s]);
    }
    element(&mut b, 45, &ht40().capability_body());
    let mut op = [0; 22];
    op[0] = 36;
    op[1] = 5;
    element(&mut b, 61, &op);
    element(
        &mut b,
        191,
        &LocalVht::new(0xfffa, 0xfffa, true, true, 0)
            .unwrap()
            .capability_body(),
    );
    element(&mut b, 192, &[1, 42, 0, 0xfc, 0xff]);
    let mut he = vec![35, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    he.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
    element(&mut b, 255, &he);
    let mut heop = vec![36];
    heop.extend_from_slice(&(4u32 | 1023 << 4 | 3 << 24).to_le_bytes());
    heop.extend_from_slice(&0xfffcu16.to_le_bytes());
    element(&mut b, 255, &heop);
    element(
        &mut b,
        255,
        &[108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x22, 0x11],
    );
    element(&mut b, 255, &[106, 0, 0x11, 0, 0, 0]);
    if let Some((cap, op)) = uhr {
        element(&mut b, 255, &cap);
        element(&mut b, 255, &op);
    }
    if ml {
        element(&mut b, 255, &ml_basic());
    }
    b
}
fn offer(bytes: &[u8], local: LocalPhy) -> Result<Option<Offer>, Error> {
    Offer::from_elements(local, bytes, 36)
}

fn wire() -> Result<(), &'static str> {
    let ap = uhr_cap(MAC0_NPCA, MAC1_DBE, &[0x03 | DBE_CAP_160, 0x22, 0x22, 0x11]);
    let cap = UhrCapability::parse(&ap[1..], true).map_err(|_| "AP DBE capability")?;
    check!(
        cap.dbe_capability() == Some(0x0b) && cap.npca() && cap.body() == ap,
        "AP UHR capability round trip"
    );
    check!(
        UhrCapability::parse(&ap[1..], false).is_err(),
        "non-AP capability with DBE parameters admitted"
    );
    let mut short = ap.clone();
    short.pop();
    check!(
        UhrCapability::parse(&short[1..], true).is_err(),
        "truncated DBE map admitted"
    );
    let all = uhr_op(
        OP_DPS_PRES | OP_NPCA_PRES | OP_NPCA_ENA | OP_PEDCA_PRES | OP_DBE_PRES | 2 << 4,
        &[
            1, 2, 3, 4, // DPS
            2, 0, 0x80, 0, 0xaa, 0x00, // NPCA offset2 + bitmap
            5, 6, 7, // P-EDCA
            0x0a, 0, 0, // DBE 80MHz + bitmap
        ],
    );
    let op = UhrOperation::parse(&all[1..]).map_err(|_| "full operation")?;
    check!(
        op.dps_parameters() == Some(0x0403_0201)
            && op.npca_parameters() == Some((0x0080_0002, Some(0xaa)))
            && op.pedca_parameters() == Some([5, 6, 7])
            && op.dbe_parameters() == Some((0x0a, Some(0))),
        "operation fields"
    );
    let disabled = uhr_op(OP_NPCA_PRES, &[2, 0, 0, 0]);
    check!(
        UhrOperation::parse(&disabled[1..]).is_ok_and(|o| o.npca_parameters().is_none()),
        "disabled NPCA reported"
    );
    let mut long = all.clone();
    long.push(0);
    check!(
        UhrOperation::parse(&long[1..]).is_err()
            && UhrOperation::parse(&all[1..all.len() - 1]).is_err(),
        "ieee80211_uhr_oper_size_ok extents"
    );
    check!(
        basic_multi_link(&ml_basic()[1..]) == Ok(true)
            && basic_multi_link(&[1, 0, 7, 0, 0, 0, 0, 0, 0]) == Ok(false)
            && basic_multi_link(&[0, 0, 9, 0, 0]).is_err(),
        "Basic Multi-Link detection"
    );
    Ok(())
}
smoke!(smoke_uhr_capability_operation_extents, wire);

fn admission() -> Result<(), &'static str> {
    let npca = uhr_op(OP_NPCA_PRES | OP_NPCA_ENA, &[2, 0, 0, 0]);
    let full = elements(
        Some((uhr_cap(MAC0_NPCA, 0, &[]), npca.clone())),
        true,
        Some(0x80 | 120),
    );
    let o = offer(&full, local(Some(npca_local())))
        .map_err(|_| "native MLD UHR offer refused")?
        .ok_or("no PHY offer")?;
    check!(
        o.uhr().is_some_and(|u| u.npca_channel() == Some(44)),
        "UHR/NPCA not admitted for a native MLD owner"
    );
    check!(
        offer(&full, local(Some(LocalUhr::new([0; 6], 0)))).is_err(),
        "UHR selector admitted without an MLD association"
    );
    let no_selector = elements(Some((uhr_cap(MAC0_NPCA, 0, &[]), npca.clone())), true, None);
    let o = offer(
        &no_selector,
        local(Some(LocalUhr::new([0; 6], 0).for_mld_association())),
    )
    .unwrap()
    .unwrap();
    check!(
        o.uhr().is_some_and(|u| u.npca_channel().is_none()),
        "NPCA channel reported without local NPCA support"
    );
    let no_ml = elements(
        Some((uhr_cap(MAC0_NPCA, 0, &[]), npca.clone())),
        false,
        None,
    );
    check!(
        offer(&no_ml, local(Some(npca_local()))).is_ok_and(|o| o.unwrap().uhr().is_none()),
        "UHR without a Basic Multi-Link element"
    );
    let same_half = uhr_op(OP_NPCA_PRES | OP_NPCA_ENA, &[1, 0, 0, 0]);
    let ap_no_npca = elements(Some((uhr_cap(0, 0, &[]), npca.clone())), true, None);
    let wrong = elements(Some((uhr_cap(MAC0_NPCA, 0, &[]), same_half)), true, None);
    for bytes in [ap_no_npca, wrong] {
        check!(
            offer(&bytes, local(Some(npca_local()))).is_ok_and(|o| o.unwrap().uhr().is_none()),
            "invalid NPCA kept UHR"
        );
    }
    let dbe = uhr_op(OP_DBE_PRES | 3 << 4, &[0x03]);
    let dbe_ok = elements(
        Some((
            uhr_cap(0, MAC1_DBE, &[0x03 | DBE_CAP_160, 0x22, 0x22, 0x11]),
            dbe.clone(),
        )),
        true,
        None,
    );
    let dbe_wide = elements(
        Some((uhr_cap(0, MAC1_DBE, &[0x02]), dbe.clone())),
        true,
        None,
    );
    let dbe_none = elements(Some((uhr_cap(0, 0, &[]), dbe)), true, None);
    check!(
        offer(&dbe_ok, local(Some(npca_local()))).is_ok_and(|o| o.unwrap().uhr().is_some())
            && offer(&dbe_wide, local(Some(npca_local())))
                .is_ok_and(|o| o.unwrap().uhr().is_none())
            && offer(&dbe_none, local(Some(npca_local())))
                .is_ok_and(|o| o.unwrap().uhr().is_none()),
        "DBE consistency"
    );
    // The single-link JoinPlan never admits UHR, even with an MLD opt-in.
    let bss = Bss {
        bssid: [2, 0, 0, 0, 0, 2],
        ssid: b"narf".to_vec(),
        channel: 36,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: full,
    };
    check!(
        JoinPlan::prepare_with_phy(
            &bss,
            [2, 0, 0, 0, 0, 1],
            b"narf",
            SecurityMode::Open,
            local(Some(npca_local()))
        )
        .is_err(),
        "JoinPlan admitted a mandatory UHR BSS"
    );
    let mut orphan = elements(None, true, None);
    element(&mut orphan, 255, &uhr_op(0, &[]));
    check!(
        offer(&orphan, local(Some(npca_local()))).is_ok(),
        "UHR operation alone must parse (beacon-only capability rule)"
    );
    Ok(())
}
smoke!(
    smoke_uhr_mld_admission_npca_dbe_and_joinplan_refusal,
    admission
);
