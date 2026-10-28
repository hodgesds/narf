// SPDX-License-Identifier: GPL-2.0-or-later
//! Identical adversarial RSN conversations over both genuine native owners.
//! These exercise firmware offload receipts, not firmware-internal crypto.
use super::*;
use crate::cyw43439::mfp_fixture::{rsne, Conversation, Hold};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_wireless::reg::{db::Database, RegFlags, RegRule, RegulatoryDomain};

pub(super) trait Fixture {
    type Radio: Fullmac + 'static;
    fn device(&self) -> &Arc<Device<Self::Radio>>;
    fn configure(&self, plan: Conversation);
    fn commands(&self) -> Vec<(u32, Vec<u8>)>;
    fn scan(&self) -> Result<(), &'static str>;
    fn key(&self, foreign: bool);
    fn clean_dma(&self) -> bool;
}
pub(super) trait Factory {
    type Native: Fixture;
    fn create(
        &mut self,
        secure: bool,
        supported: bool,
        plan: Conversation,
        db: Option<Arc<Database>>,
    ) -> Result<Self::Native, &'static str>;
}
fn run<F: Future>(future: F) -> Result<F::Output, &'static str> {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..256 {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return Ok(out);
        }
    }
    Err("held actual native PMF conversation")
}
fn request(mode: u32, secure: bool) -> AssociateRequest {
    AssociateRequest {
        bssid: [2, 1, 2, 3, 4, 5],
        ssid: b"test".to_vec(),
        channel: 6,
        frequency_mhz: 2437,
        security: if secure {
            narf_wireless::SecurityConfig::Wpa2 { psk: [0x11; 32] }
        } else {
            narf_wireless::SecurityConfig::Open
        },
        ie: Conversation::new(mode, 0).expected_request(secure),
    }
}
fn associate<H: Fixture>(h: &H, mode: u32, secure: bool) -> Result<(), &'static str> {
    h.scan()?;
    run(h.device().associate(request(mode, secure)))?.map_err(|_| "native PMF association")
}
fn protected<H: Fixture>(h: &H) -> bool {
    h.device()
        .state
        .try_lock()
        .unwrap()
        .station
        .management_protection()
}
fn closed<H: Fixture>(h: &H) -> bool {
    !h.device().link_up()
        && h.device().connected_bssid().is_none()
        && !protected(h)
        && h.clean_dma()
}
fn pump<H: Fixture>(h: &H) {
    for _ in 0..6 {
        h.device().drain();
    }
}
fn domain() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}

pub(super) fn matrix<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    for supported in [false, true] {
        for mode in [0, 1, 2] {
            for ap in [0, 128, 192] {
                let h = factory.create(true, supported, Conversation::new(mode, ap), None)?;
                if h.device().supports_optional_mfp() != supported {
                    return Err("optional PMF capability was not source-derived");
                }
                let result = associate(&h, mode, true);
                let expected =
                    mode == 0 && ap != 192 || supported && (mode == 1 || mode == 2 && ap != 0);
                if result.is_ok() != expected {
                    return Err("native NONE/CAPABLE/REQUIRED AP-policy matrix differs");
                }
                if expected {
                    if !h.device().link_up() || protected(&h) != (mode != 0 && ap != 0) {
                        return Err("configured MFP policy became false negotiated protection");
                    }
                    let commands = h.commands();
                    if supported {
                        let cipher = commands
                            .iter()
                            .position(|(id, _)| *id == 134)
                            .ok_or("native MFP cipher missing")?;
                        let set = commands
                            .iter()
                            .position(|(id, b)| {
                                *id == 263
                                    && b == &[b"mfp\0".as_slice(), &mode.to_le_bytes()].concat()
                            })
                            .ok_or("native MFP mode missing")?;
                        if set <= cipher {
                            return Err("MFP policy preceded native WSEC");
                        }
                    }
                    run(h.device().disassociate())?.map_err(|_| "native MFP teardown")?;
                    if !closed(&h) {
                        return Err("MFP teardown retained protected metadata or lost DMA");
                    }
                } else if !closed(&h) || h.commands().iter().any(|(id, _)| *id == 26) {
                    return Err("unsupported AP/SME MFP policy reached native join");
                }
            }
        }
    }
    Ok(())
}

pub(super) fn proof<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    exact_extent_proof(factory)?;
    let invalid_ap = factory.create(true, true, Conversation::new(1, 64), None)?;
    if associate(&invalid_ap, 1, true).is_ok()
        || !closed(&invalid_ap)
        || invalid_ap.commands().iter().any(|(id, _)| *id == 26)
    {
        return Err("AP MFPR without MFPC reached native association");
    }
    drop(invalid_ap);
    // kind 0 (an MFPC AP omitting its response RSNE) is a valid negotiated
    // association and is admitted below.
    for kind in 1..12 {
        let mut plan = Conversation::new(1, if kind == 2 { 0 } else { 128 });
        match kind {
            0 => plan.response = Some(Vec::new()),
            1 => plan.response = Some(rsne(0)),
            2 => plan.response = Some(rsne(128)),
            3 => plan.response = Some(rsne(192)),
            4 => {
                let mut ie = rsne(128);
                ie[27] = 7;
                plan.response = Some(ie);
            }
            5 => plan.response = Some(vec![48, 20, 1]),
            6 => plan.response = Some([rsne(128), rsne(128)].concat()),
            7 => {
                let mut ie = rsne(128);
                ie[19] = 8;
                plan.response = Some(ie);
            }
            8 => plan.request = Some(rsne(0)),
            9 => plan.request = Some(rsne(192)),
            10 => {
                let mut ie = rsne(128);
                ie[27] = 7;
                plan.request = Some(ie);
            }
            _ => plan.request = Some([rsne(128), rsne(128)].concat()),
        }
        let h = factory.create(true, true, plan, None)?;
        if associate(&h, 1, true).is_ok() || !closed(&h) {
            return Err("spoofed/absent/downgraded native PMF proof authorized the port");
        }
        h.key(false);
        pump(&h);
        if !closed(&h) {
            return Err("late valid key receipt revived failed optional PMF proof");
        }
    }
    for (ap, omitted) in [(0, true), (128, false), (128, true)] {
        let mut plan = Conversation::new(1, ap);
        if omitted {
            plan.response = Some(Vec::new());
        } else {
            let mut default = rsne(128);
            default.truncate(22);
            default[1] = 20;
            plan.request = Some(default.clone());
            plan.response = Some(default);
        }
        let h = factory.create(true, true, plan, None)?;
        associate(&h, 1, true)?;
        if protected(&h) != (ap != 0) {
            return Err("absent response RSNE/default BIP changed negotiated protection");
        }
    }
    Ok(())
}

fn exact_extent_proof<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    for body_length in [19usize, 21, 23, 24, 25, 27] {
        let mut malformed = rsne(128);
        malformed.resize(body_length + 2, 0);
        malformed[1] = body_length as u8;
        for response in [false, true] {
            let mut plan = Conversation::new(1, 128);
            if response {
                plan.response = Some(malformed.clone());
            } else {
                plan.request = Some(malformed.clone());
            }
            let h = factory.create(true, true, plan, None)?;
            if associate(&h, 1, true).is_ok() || !closed(&h) {
                return Err("partial/trailing native RSN fields acquired default BIP authority");
            }
        }
        let h = factory.create(true, true, Conversation::new(1, 128), None)?;
        h.scan()?;
        let before = h.commands();
        let mut req = request(1, true);
        req.ie = malformed.clone();
        if run(h.device().associate(req))?.is_ok() || !closed(&h) || h.commands() != before {
            return Err("partial/trailing typed RSNE reached a native security write");
        }
        let mut plan = Conversation::new(1, 128);
        plan.ap = malformed;
        let h = factory.create(true, true, plan, None)?;
        if associate(&h, 1, true).is_ok()
            || !closed(&h)
            || h.commands().iter().any(|(id, _)| *id == 26)
        {
            return Err("partial/trailing selected AP RSNE reached native join");
        }
    }
    // Default20/22 and explicit26-byte PMF bodies remain valid; only the
    // complete absence of capabilities has the legacy18-byte meaning.
    for body_length in [20usize, 22, 26] {
        let mut complete = rsne(128);
        complete.truncate(body_length + 2);
        complete[1] = body_length as u8;
        let mut plan = Conversation::new(1, 128);
        plan.request = Some(complete.clone());
        plan.response = Some(complete);
        let h = factory.create(true, true, plan, None)?;
        associate(&h, 1, true)?;
        if !protected(&h) {
            return Err("valid default or explicit PMF RSN body rejected");
        }
    }
    let mut legacy = rsne(0);
    legacy.truncate(20);
    legacy[1] = 18;
    for ap in [false, true] {
        let mut plan = Conversation::new(0, 0);
        if ap {
            plan.ap = legacy.clone();
        }
        let h = factory.create(true, true, plan, None)?;
        h.scan()?;
        let mut req = request(0, true);
        if !ap {
            req.ie = legacy.clone();
        }
        if run(h.device().associate(req))?.is_err() || !h.device().link_up() || protected(&h) {
            return Err("valid18-byte legacy RSNE was promoted or refused");
        }
    }
    Ok(())
}

pub(super) fn cancellation<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    for hold in [Hold::Mode, Hold::Request, Hold::Response] {
        let mut plan = Conversation::new(1, 128);
        plan.hold = hold;
        let h = factory.create(true, true, plan.clone(), None)?;
        if associate(&h, 1, true).is_ok() || !closed(&h) {
            return Err("held MFP policy/request/response receipt opened port");
        }
        plan.hold = Hold::None;
        h.configure(plan);
        h.key(false);
        pump(&h);
        if !closed(&h) || associate(&h, 1, true).is_ok() {
            return Err("cancelled MFP waiter reused native receipt or freed owned DMA");
        }
    }
    Ok(())
}

pub(super) fn foreign_keys<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    let mut plan = Conversation::new(1, 128);
    plan.keys = false;
    let h = factory.create(true, true, plan, None)?;
    h.scan()?;
    let mut future = pin!(h.device().associate(request(1, true)));
    let mut cx = Context::from_waker(Waker::noop());
    let mut held = false;
    for _ in 0..256 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("MFP readback/association alone replaced key completion");
        }
        if h.commands().iter().any(|(id, _)| *id == 26) {
            held = true;
            break;
        }
    }
    if !held {
        return Err("native key wait was not reached");
    }
    h.key(true);
    // The native association waiter uses a real one-millisecond scheduler
    // timer between absent-key polls. Let that timer expire without a
    // hand-written hardware spin or pretending that the event was consumed.
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
    if future.as_mut().poll(&mut cx).is_ready() || h.device().link_up() {
        return Err("foreign FWSUP source authorized optional PMF");
    }
    h.key(false);
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
    let mut complete = false;
    for _ in 0..256 {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(())) => {
                complete = true;
                break;
            }
            Poll::Ready(Err(_)) => return Err("genuine native key completion refused"),
            Poll::Pending => {}
        }
    }
    if !complete {
        return Err("matching FWSUP did not complete native PMF");
    }
    if !h.device().link_up() || !protected(&h) || !h.clean_dma() {
        return Err("genuine optional PMF key owner lost its positive control");
    }
    Ok(())
}

pub(super) fn current_policy<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    let db = Arc::new(Database::new());
    db.install(domain());
    let mut plan = Conversation::new(1, 128);
    plan.hold = Hold::Response;
    let h = factory.create(true, true, plan.clone(), Some(db.clone()))?;
    h.scan()?;
    {
        let mut future = pin!(h.device().associate(request(1, true)));
        let mut cx = Context::from_waker(Waker::noop());
        let mut held = false;
        for _ in 0..256 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("current-policy fixture did not hold original response");
            }
            if h.commands()
                .iter()
                .any(|(id, b)| *id == 262 && b.starts_with(b"assoc_resp_ies\0"))
            {
                held = true;
                break;
            }
        }
        if !held {
            return Err("native optional response query missing");
        }
        db.clear();
        plan.hold = Hold::None;
        h.configure(plan);
        if !matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return Err("held optional response ignored current occupied policy");
        }
    }
    db.install(domain());
    h.key(false);
    pump(&h);
    if !closed(&h) {
        return Err("policy reinstall/late keys revived failed optional PMF incarnation");
    }
    Ok(())
}

fn connect_attrs(mode: u32) -> Vec<u8> {
    fn attr(out: &mut Vec<u8>, id: u16, value: &[u8]) {
        out.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
        out.extend_from_slice(&id.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize((out.len() + 3) & !3, 0);
    }
    let mut out = Vec::new();
    attr(&mut out, 52, b"test");
    attr(&mut out, 6, &[2, 1, 2, 3, 4, 5]);
    attr(&mut out, 38, &2437u32.to_ne_bytes());
    attr(&mut out, 254, &[0x11; 32]);
    for (id, value) in [
        (66, mode),
        (75, 2),
        (76, 0x000fac02),
        (73, 0x000fac04),
        (74, 0x000fac04),
    ] {
        attr(&mut out, id, &value.to_ne_bytes());
    }
    attr(&mut out, 42, &rsne(128));
    out
}
pub(super) fn nl_connect<F: Factory>(factory: &mut F) -> Result<(), &'static str> {
    for supported in [false, true] {
        for ap in [0, 128, 192] {
            let h = factory.create(true, supported, Conversation::new(1, ap), None)?;
            let before = h.commands();
            let result = run(narf_wireless::nl80211::connect_for_test(
                h.device().clone(),
                &connect_attrs(2),
            ))?;
            if supported {
                if result.is_err()
                    || !h.device().link_up()
                    || protected(&h) != (ap != 0)
                    || !h.clean_dma()
                {
                    return Err("real Optional-PMF CONNECT did not earn native protected/unprotected result");
                }
            } else if result != Err(95) || h.commands() != before {
                return Err("unsupported Optional-PMF CONNECT reached native commands");
            }
        }
    }
    let h = factory.create(true, true, Conversation::new(1, 128), None)?;
    let before = h.commands();
    if run(narf_wireless::nl80211::connect_for_test(
        h.device().clone(),
        &connect_attrs(0),
    ))? != Err(95)
        || h.commands() != before
    {
        return Err("USE_MFP0 silently acquired an optional-PMF RSNE policy");
    }
    Ok(())
}
