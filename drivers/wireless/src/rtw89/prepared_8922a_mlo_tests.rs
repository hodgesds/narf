//! Prepared 8922A MLO link-lifecycle tests (issue #2081).
//!
//! Separate module from `prepared_8922a_tests.rs` so the
//! link-lifecycle coverage does not disturb the set_txpwr
//! tests there: per-instance CAM allocation + held VIF-link
//! contexts, and compose + frame of the add / assoc /
//! disconnect / remove transitions for MLD links and
//! single-link stations, byte-compared against the raw
//! `link_h2c_8922a` composers.

use super::chip_8922a;
use super::efuse_be::BeFactory;
use super::link_h2c_8922a::{
    self, LinkView, VifLinkCtx, CMD_CAM, CMD_DMAC_V2, CMD_JOIN_INFO, CMD_MACID_PAUSE_SLEEP,
    CMD_ROLE_MAINTAIN,
};
use super::prepared_8922a::*;
use super::station_8922a::{Band, LinkRequest, Request};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const VIF_ADDR: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const LINK1_ADDR: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x56];
const MLD_ADDR: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const BSSID: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];

fn factory() -> BeFactory {
    BeFactory {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        rfe_type: 0,
        xtal_cap: 0,
        country: [b'U', b'S'],
        phycap: [0u8; chip_8922a::PHYCAP_SIZE],
        cv: None,
        thermal_k: None,
        secure: super::efuse_be::SecureInfo::disabled(),
    }
}

fn base_req() -> Request<'static> {
    Request {
        peer: BSSID,
        band: Band::Ghz5,
        width_mhz: 160,
        primary: 36,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn link1_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
        band: Band::Ghz2,
        width_mhz: 40,
        primary: 6,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn two_mld_links() -> [LinkRequest<'static>; 2] {
    [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: link1_req(),
        },
    ]
}

fn opts() -> LinkH2cOpts {
    LinkH2cOpts {
        wmm: 0,
        trigger: true,
        bssid: BSSID,
        bssid_valid: true,
        addr_cam_v0: true,
        macid_pause_sleep: false,
    }
}

/// The composer input for one held VIF link instance, built
/// the same way the Prepared owner builds it — so a framed
/// payload mismatch points at the owner, not the fixture.
fn ctx_for(
    owner: &Prepared8922a,
    vif_main: u8,
    index: usize,
    opts: &LinkH2cOpts,
    ap_or_tdls: bool,
) -> Result<VifLinkCtx, &'static str> {
    let vif = owner.vif(vif_main).ok_or("VIF missing")?;
    let link = &vif.links[index];
    Ok(VifLinkCtx {
        own: link.own,
        port: vif.port,
        wmm: opts.wmm,
        trigger: opts.trigger,
        bssid: opts.bssid,
        addr_cam_idx: link.addr_cam_idx,
        bssid_cam_idx: link.bssid_cam_idx,
        bssid_valid: opts.bssid_valid,
        ap_or_tdls,
        addr_cam_v0: opts.addr_cam_v0,
        macid_pause_sleep: opts.macid_pause_sleep,
    })
}

/// One framed body must carry this identity (category, class,
/// function, sequence) and this payload (after the 8-byte
/// FWCMD header).
fn check_frame(
    frame: &FramedLinkH2c,
    cmd: link_h2c_8922a::LinkCmd,
    seq: u8,
    body: &[u8],
) -> Result<(), &'static str> {
    if frame.framed.cat != cmd.cmd.cat
        || frame.framed.class != cmd.cmd.class
        || frame.framed.func != cmd.cmd.func
        || frame.framed.seq != seq
    {
        return Err("framed identity mismatch");
    }
    if frame.bytes.len() != 8 + body.len() || frame.bytes[8..] != *body {
        return Err("framed payload mismatch");
    }
    Ok(())
}

/// True when `frames` is `Ok` with an empty list (station
/// links frame nothing on add / remove).
fn is_empty_ok(frames: Result<Vec<FramedLinkH2c>, Error>) -> bool {
    matches!(frames, Ok(frames) if frames.is_empty())
}

fn smoke_rtw89_prepared_8922a_mlo_cam_alloc() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    // First VIF: lowest-free-first CAM entries, own addresses
    // held per instance.
    let main = match owner.add_vif(VIF_ADDR, VifRole::Station, [VIF_ADDR, LINK1_ADDR]) {
        Ok(main) => main,
        Err(_) => return TestResult::Fail("add_vif failed"),
    };
    if main != 0 {
        return TestResult::Fail("first VIF main MACID not 0");
    }
    let Some(vif) = owner.vif(0) else {
        return TestResult::Fail("admitted VIF not retained");
    };
    if vif.links[0].own != VIF_ADDR || vif.links[1].own != LINK1_ADDR {
        return TestResult::Fail("VIF link own addresses mismatch");
    }
    if vif.links[0].addr_cam_idx != 0
        || vif.links[1].addr_cam_idx != 1
        || vif.links[0].bssid_cam_idx != 0
        || vif.links[1].bssid_cam_idx != 1
    {
        return TestResult::Fail("first VIF CAM indices not lowest-free");
    }
    // Second VIF takes the next entries; indices never alias.
    if owner
        .add_vif(
            [0x02, 0x11, 0x22, 0x33, 0x44, 0x57],
            VifRole::Ap,
            [
                [0x02, 0x11, 0x22, 0x33, 0x44, 0x57],
                [0x02, 0x11, 0x22, 0x33, 0x44, 0x58],
            ],
        )
        .is_err()
    {
        return TestResult::Fail("second add_vif failed");
    }
    let Some(vif) = owner.vif(1) else {
        return TestResult::Fail("second VIF not retained");
    };
    if vif.links[0].addr_cam_idx != 2
        || vif.links[1].addr_cam_idx != 3
        || vif.links[0].bssid_cam_idx != 2
        || vif.links[1].bssid_cam_idx != 3
    {
        return TestResult::Fail("second VIF CAM indices alias the first");
    }
    // Removing a VIF frees its entries: the re-add reuses
    // the lowest indices again.
    owner.remove_vif(0);
    if owner
        .add_vif(VIF_ADDR, VifRole::Station, [VIF_ADDR, LINK1_ADDR])
        .is_err()
    {
        return TestResult::Fail("VIF re-add after removal failed");
    }
    let Some(vif) = owner.vif(0) else {
        return TestResult::Fail("re-added VIF not retained");
    };
    if vif.links[0].addr_cam_idx != 0
        || vif.links[1].addr_cam_idx != 1
        || vif.links[0].bssid_cam_idx != 0
        || vif.links[1].bssid_cam_idx != 1
    {
        return TestResult::Fail("removed VIF CAM entries not reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mlo_cam_alloc
);

fn smoke_rtw89_prepared_8922a_mld_link_frames() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner
        .add_vif(VIF_ADDR, VifRole::Station, [VIF_ADDR, LINK1_ADDR])
        .is_err()
    {
        return TestResult::Fail("add_vif failed");
    }
    let base = match owner.admit_mld(MLD_ADDR, &two_mld_links()) {
        Ok(base) => base,
        Err(_) => return TestResult::Fail("admit_mld failed"),
    };
    let Some(mld) = owner.mld(base) else {
        return TestResult::Fail("admitted MLD not retained");
    };
    let opts = opts();
    // Assoc, link 0: join-info + CAM, sequences 0, 1,
    // payloads identical to the raw composers.
    let ctx = match ctx_for(&owner, 0, 0, &opts, false) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_assoc_h2cs(mld, 0, &ctx) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw assoc composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Assoc, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld assoc frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("assoc must frame join + CAM");
    }
    if check_frame(&frames[0], CMD_JOIN_INFO, 0, &expected.join).is_err()
        || check_frame(
            &frames[1],
            CMD_CAM,
            1,
            match &expected.cam {
                link_h2c_8922a::CamBody::V0(body) => &body[..],
                link_h2c_8922a::CamBody::V1(body) => &body[..],
            },
        )
        .is_err()
    {
        return TestResult::Fail("assoc frames mismatch composer");
    }
    // Assoc, link 1 (non-designated): same shape, fresh
    // sequences, main MACID + init_ps from the MLD record.
    let ctx = match ctx_for(&owner, 0, 1, &opts, false) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_assoc_h2cs(mld, 1, &ctx) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw link-1 assoc composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 1, 0, LinkTransition::Assoc, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld link-1 assoc frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("link-1 assoc must frame join + CAM");
    }
    if check_frame(&frames[0], CMD_JOIN_INFO, 2, &expected.join).is_err()
        || check_frame(
            &frames[1],
            CMD_CAM,
            3,
            match &expected.cam {
                link_h2c_8922a::CamBody::V0(body) => &body[..],
                link_h2c_8922a::CamBody::V1(body) => &body[..],
            },
        )
        .is_err()
    {
        return TestResult::Fail("link-1 assoc frames mismatch composer");
    }
    // Disconnect, link 0: join-info OP bit set (payload W0
    // bit 8), CAM with net type NO_LINK / AID 0.
    let ctx = match ctx_for(&owner, 0, 0, &opts, false) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_disconnect_h2cs(mld, 0, &ctx) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw disconnect composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Disconnect, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld disconnect frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("disconnect must frame join + CAM");
    }
    if u32::from_le_bytes(frames[0].bytes[8..12].try_into().unwrap()) & (1 << 8) == 0 {
        return TestResult::Fail("disconnect join-info OP bit clear");
    }
    if check_frame(&frames[0], CMD_JOIN_INFO, 4, &expected.join).is_err()
        || check_frame(
            &frames[1],
            CMD_CAM,
            5,
            match &expected.cam {
                link_h2c_8922a::CamBody::V0(body) => &body[..],
                link_h2c_8922a::CamBody::V1(body) => &body[..],
            },
        )
        .is_err()
    {
        return TestResult::Fail("disconnect frames mismatch composer");
    }
    // Station links send nothing on add or remove.
    if !is_empty_ok(owner.mld_link_frames(base, 0, 0, LinkTransition::Add, &opts)) {
        return TestResult::Fail("station link add must frame nothing");
    }
    if !is_empty_ok(owner.mld_link_frames(base, 0, 0, LinkTransition::Remove, &opts)) {
        return TestResult::Fail("station link remove must frame nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mld_link_frames
);

fn smoke_rtw89_prepared_8922a_mld_ap_link_frames() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner
        .add_vif(VIF_ADDR, VifRole::Ap, [VIF_ADDR, LINK1_ADDR])
        .is_err()
    {
        return TestResult::Fail("add_vif failed");
    }
    let base = match owner.admit_mld(MLD_ADDR, &two_mld_links()) {
        Ok(base) => base,
        Err(_) => return TestResult::Fail("admit_mld failed"),
    };
    let Some(mld) = owner.mld(base) else {
        return TestResult::Fail("admitted MLD not retained");
    };
    let opts = opts();
    // Add, link 0 (AP-mode): MACID unpause (plain 32-byte
    // body) + role CREATE + default DMAC, in that order.
    let ctx = match ctx_for(&owner, 0, 0, &opts, true) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_add_h2cs(mld, 0, &ctx) {
        Ok(add) => add,
        Err(_) => return TestResult::Fail("raw add composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Add, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld AP add frames failed"),
    };
    if frames.len() != 3 {
        return TestResult::Fail("AP link add must frame pause + role + DMAC");
    }
    let Some(pause) = &expected.pause else {
        return TestResult::Fail("raw add composer has no pause");
    };
    let pause_body = match pause {
        link_h2c_8922a::MacidPause::Plain(body) => &body[..],
        link_h2c_8922a::MacidPause::Sleep(body) => &body[..],
    };
    if check_frame(&frames[0], pause.cmd(), 0, pause_body).is_err() {
        return TestResult::Fail("add pause frame mismatch composer");
    }
    if frames[0].bytes.len() != 8 + link_h2c_8922a::MACID_PAUSE_LEN {
        return TestResult::Fail("plain pause body must be 32 bytes");
    }
    let Some(role) = expected.role else {
        return TestResult::Fail("raw add composer has no role");
    };
    if check_frame(&frames[1], CMD_ROLE_MAINTAIN, 1, &role).is_err() {
        return TestResult::Fail("add role frame mismatch composer");
    }
    let Some(dmac) = expected.dmac else {
        return TestResult::Fail("raw add composer has no DMAC");
    };
    if check_frame(&frames[2], CMD_DMAC_V2, 2, &dmac).is_err() {
        return TestResult::Fail("add DMAC frame mismatch composer");
    }
    // Remove, link 0: role REMOVE only.
    let expected = match link_h2c_8922a::mld_link_remove_h2cs(mld, 0, &ctx) {
        Ok(remove) => remove,
        Err(_) => return TestResult::Fail("raw remove composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Remove, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld AP remove frames failed"),
    };
    if frames.len() != 1 {
        return TestResult::Fail("AP link remove must frame role only");
    }
    let Some(role) = expected else {
        return TestResult::Fail("raw remove composer has no role");
    };
    if check_frame(&frames[0], CMD_ROLE_MAINTAIN, 3, &role).is_err() {
        return TestResult::Fail("remove role frame mismatch composer");
    }
    // SLEEP pause variant: the same add frames the 256-byte
    // body with the SLEEP identity.
    let mut sleep_opts = opts;
    sleep_opts.macid_pause_sleep = true;
    let ctx = match ctx_for(&owner, 0, 0, &sleep_opts, true) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_add_h2cs(mld, 0, &ctx) {
        Ok(add) => add,
        Err(_) => return TestResult::Fail("raw SLEEP add composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Add, &sleep_opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld SLEEP add frames failed"),
    };
    if frames.len() != 3 {
        return TestResult::Fail("SLEEP add must frame pause + role + DMAC");
    }
    let Some(pause) = &expected.pause else {
        return TestResult::Fail("raw SLEEP add composer has no pause");
    };
    let pause_body = match pause {
        link_h2c_8922a::MacidPause::Plain(body) => &body[..],
        link_h2c_8922a::MacidPause::Sleep(body) => &body[..],
    };
    if check_frame(&frames[0], CMD_MACID_PAUSE_SLEEP, 4, pause_body).is_err() {
        return TestResult::Fail("SLEEP pause frame mismatch composer");
    }
    if frames[0].bytes.len() != 8 + link_h2c_8922a::MACID_PAUSE_SLEEP_LEN {
        return TestResult::Fail("SLEEP pause body must be 256 bytes");
    }
    // CAM v1 variant: the assoc CAM carries the 64-byte body
    // with W15 update mode.
    let mut v1_opts = opts;
    v1_opts.addr_cam_v0 = false;
    let ctx = match ctx_for(&owner, 0, 0, &v1_opts, true) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let expected = match link_h2c_8922a::mld_link_assoc_h2cs(mld, 0, &ctx) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw v1 assoc composer failed"),
    };
    let frames = match owner.mld_link_frames(base, 0, 0, LinkTransition::Assoc, &v1_opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("mld v1 assoc frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("v1 assoc must frame join + CAM");
    }
    let link_h2c_8922a::CamBody::V1(cam) = expected.cam else {
        return TestResult::Fail("v1 assoc composer did not build v1 CAM");
    };
    if check_frame(&frames[1], CMD_CAM, 8, &cam).is_err() {
        return TestResult::Fail("v1 CAM frame mismatch composer");
    }
    if frames[1].bytes.len() != 8 + link_h2c_8922a::CAM_V1_LEN {
        return TestResult::Fail("v1 CAM body must be 64 bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mld_ap_link_frames
);

fn smoke_rtw89_prepared_8922a_station_link_frames() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner
        .add_vif(VIF_ADDR, VifRole::Station, [VIF_ADDR, LINK1_ADDR])
        .is_err()
    {
        return TestResult::Fail("add_vif failed");
    }
    // The VIF took MACID 0; the pool station takes 1.
    let macid = match owner.admit_station(&base_req()) {
        Ok(macid) => macid,
        Err(_) => return TestResult::Fail("admit_station failed"),
    };
    if macid != 1 {
        return TestResult::Fail("pool station MACID not 1");
    }
    let Some(station) = owner.station(macid) else {
        return TestResult::Fail("admitted station not retained");
    };
    let opts = opts();
    // Assoc: join-info + CAM, payloads identical to the raw
    // composers built from the same held context.
    let ctx = match ctx_for(&owner, 0, 0, &opts, false) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let view = LinkView::for_station(station, &ctx);
    let expected = match link_h2c_8922a::link_assoc_h2cs(&view) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw station assoc composer failed"),
    };
    let frames = match owner.station_link_frames(macid, 0, LinkTransition::Assoc, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("station assoc frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("station assoc must frame join + CAM");
    }
    if check_frame(&frames[0], CMD_JOIN_INFO, 0, &expected.join).is_err()
        || check_frame(
            &frames[1],
            CMD_CAM,
            1,
            match &expected.cam {
                link_h2c_8922a::CamBody::V0(body) => &body[..],
                link_h2c_8922a::CamBody::V1(body) => &body[..],
            },
        )
        .is_err()
    {
        return TestResult::Fail("station assoc frames mismatch composer");
    }
    // Disconnect: join-info OP bit set.
    let expected = match link_h2c_8922a::link_disconnect_h2cs(&view) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("raw station disconnect composer failed"),
    };
    let frames = match owner.station_link_frames(macid, 0, LinkTransition::Disconnect, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("station disconnect frames failed"),
    };
    if frames.len() != 2 {
        return TestResult::Fail("station disconnect must frame join + CAM");
    }
    if u32::from_le_bytes(frames[0].bytes[8..12].try_into().unwrap()) & (1 << 8) == 0 {
        return TestResult::Fail("station disconnect join-info OP bit clear");
    }
    if check_frame(&frames[0], CMD_JOIN_INFO, 2, &expected.join).is_err()
        || check_frame(
            &frames[1],
            CMD_CAM,
            3,
            match &expected.cam {
                link_h2c_8922a::CamBody::V0(body) => &body[..],
                link_h2c_8922a::CamBody::V1(body) => &body[..],
            },
        )
        .is_err()
    {
        return TestResult::Fail("station disconnect frames mismatch composer");
    }
    // Station links send nothing on add or remove.
    if !is_empty_ok(owner.station_link_frames(macid, 0, LinkTransition::Add, &opts)) {
        return TestResult::Fail("station add must frame nothing");
    }
    if !is_empty_ok(owner.station_link_frames(macid, 0, LinkTransition::Remove, &opts)) {
        return TestResult::Fail("station remove must frame nothing");
    }
    // A TDLS peer takes the AP/TDLS branch: add frames the
    // pause + role CREATE + DMAC triple.
    if owner.admit_tdls_peer(0, &base_req()) != Ok(0) {
        return TestResult::Fail("admit_tdls_peer failed");
    }
    let Some(peer) = owner.station(0) else {
        return TestResult::Fail("TDLS peer not retained");
    };
    let ctx = match ctx_for(&owner, 0, 0, &opts, true) {
        Ok(ctx) => ctx,
        Err(e) => return TestResult::Fail(e),
    };
    let view = LinkView::for_station(peer, &ctx);
    let expected = match link_h2c_8922a::link_add_h2cs(&view) {
        Ok(add) => add,
        Err(_) => return TestResult::Fail("raw TDLS add composer failed"),
    };
    let frames = match owner.station_link_frames(0, 0, LinkTransition::Add, &opts) {
        Ok(frames) => frames,
        Err(_) => return TestResult::Fail("TDLS add frames failed"),
    };
    if frames.len() != 3 {
        return TestResult::Fail("TDLS add must frame pause + role + DMAC");
    }
    let Some(pause) = &expected.pause else {
        return TestResult::Fail("raw TDLS add composer has no pause");
    };
    let pause_body = match pause {
        link_h2c_8922a::MacidPause::Plain(body) => &body[..],
        link_h2c_8922a::MacidPause::Sleep(body) => &body[..],
    };
    if check_frame(&frames[0], pause.cmd(), 4, pause_body).is_err() {
        return TestResult::Fail("TDLS pause frame mismatch composer");
    }
    let Some(role) = expected.role else {
        return TestResult::Fail("raw TDLS add composer has no role");
    };
    if check_frame(&frames[1], CMD_ROLE_MAINTAIN, 5, &role).is_err() {
        return TestResult::Fail("TDLS role frame mismatch composer");
    }
    let Some(dmac) = expected.dmac else {
        return TestResult::Fail("raw TDLS add composer has no DMAC");
    };
    if check_frame(&frames[2], CMD_DMAC_V2, 6, &dmac).is_err() {
        return TestResult::Fail("TDLS DMAC frame mismatch composer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_station_link_frames
);

fn smoke_rtw89_prepared_8922a_mlo_link_refusals() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("Prepared8922a::new failed"),
    };
    if owner
        .add_vif(VIF_ADDR, VifRole::Station, [VIF_ADDR, LINK1_ADDR])
        .is_err()
    {
        return TestResult::Fail("add_vif failed");
    }
    let base = match owner.admit_mld(MLD_ADDR, &two_mld_links()) {
        Ok(base) => base,
        Err(_) => return TestResult::Fail("admit_mld failed"),
    };
    let opts = opts();
    // Unknown MLD / VIF / link, and an MLD link MACID on the
    // single-link path.
    if owner.mld_link_frames(9, 0, 0, LinkTransition::Assoc, &opts) != Err(Error::NoMld) {
        return TestResult::Fail("unknown MLD assoc accepted");
    }
    if owner.mld_link_frames(base, 0, 9, LinkTransition::Assoc, &opts) != Err(Error::NoVif) {
        return TestResult::Fail("unknown VIF assoc accepted");
    }
    if owner.mld_link_frames(base, 9, 0, LinkTransition::Assoc, &opts)
        != Err(Error::LinkH2c(link_h2c_8922a::Error::LinkNotFound))
    {
        return TestResult::Fail("unknown link assoc accepted");
    }
    if owner.station_link_frames(9, 0, LinkTransition::Assoc, &opts) != Err(Error::NoStation) {
        return TestResult::Fail("unknown station assoc accepted");
    }
    if owner.station_link_frames(1, 9, LinkTransition::Assoc, &opts) != Err(Error::NoStation) {
        // No station 1 admitted yet: NoStation precedes NoVif.
        return TestResult::Fail("unknown station/VIF assoc accepted");
    }
    // Port mismatch: a second VIF (port 1) cannot serve the
    // port-0 MLD's transitions.
    let second_vif = match owner.add_vif(
        [0x02, 0x11, 0x22, 0x33, 0x44, 0x57],
        VifRole::Station,
        [
            [0x02, 0x11, 0x22, 0x33, 0x44, 0x57],
            [0x02, 0x11, 0x22, 0x33, 0x44, 0x58],
        ],
    ) {
        Ok(vif) => vif,
        Err(_) => return TestResult::Fail("second add_vif failed"),
    };
    // add_vif returns its allocated main MACID, not its port number;
    // the intervening MLD already owns MACIDs1/17.
    if owner.vif(second_vif).map(|vif| vif.port) != Some(1) {
        return TestResult::Fail("second VIF does not own port1");
    }
    if owner.mld_link_frames(base, 0, second_vif, LinkTransition::Assoc, &opts)
        != Err(Error::PortMismatch)
    {
        return TestResult::Fail("port-mismatched MLD assoc accepted");
    }
    // The MLD's link MACIDs are not single-link stations.
    let Some(mld) = owner.mld(base) else {
        return TestResult::Fail("admitted MLD not retained");
    };
    let link_macid = match mld.link(0) {
        Some(link) => link.macid(),
        None => return TestResult::Fail("MLD link 0 missing"),
    };
    if owner.station_link_frames(link_macid, 0, LinkTransition::Assoc, &opts)
        != Err(Error::NoStation)
    {
        return TestResult::Fail("MLD link MACID took the station path");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_prepared_8922a_mlo_link_refusals
);
