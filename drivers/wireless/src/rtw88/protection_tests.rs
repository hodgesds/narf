//! Actual retained C21/C22 RTS threshold control, native TXD/CCX and kernel IP.
//! All measurement records are private inert fixture inputs, not real assets.
use super::ht_tests::{self as ht, Fixture, AP, OWN};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

type Qualified<F> = (F, Cap<FirmwareBlob, Read>, Vec<Cap<FirmwareBlob, Read>>);
fn record<F: Fixture>(f: &F) -> Result<Vec<u8>, &'static str> {
    let r = f
        .rts_request()
        .map_err(|_| "X actual current H/R/T request")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21X" } else { b"N22X" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&OWN);
    b[54..56].copy_from_slice(&[1, 20]);
    b[58..60].copy_from_slice(&80i16.to_le_bytes());
    for at in [60, 62, 64, 66] {
        b[at..at + 2].copy_from_slice(&8i16.to_le_bytes());
    }
    b[69] = 63;
    Ok(b)
}
fn setup<F: Fixture>(protected: bool, mode: u8) -> Result<Qualified<F>, &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let mut bases = Vec::new();
    if mode > 0 {
        let cap = Cap::bootstrap();
        f.stage_ba(super::rx_ba_tests::record(&f)?, cap)
            .map_err(|_| "X base R")?;
        bases.push(cap);
    }
    if mode > 1 {
        let cap = Cap::bootstrap();
        f.peer().lock().tx_ba_window = Some(64);
        f.stage_tx(super::tx_ba_tests::record(&f)?, cap)
            .map_err(|_| "X base T")?;
        bases.push(cap);
    }
    let cap = Cap::bootstrap();
    f.stage_rts(record(&f)?, cap, true)
        .map_err(|_| "distinct synthetic X qualification")?;
    Ok((f, cap, bases))
}
fn fixture<F: Fixture>(protected: bool, mode: u8) -> Result<Qualified<F>, &'static str> {
    let values = setup::<F>(protected, mode)?;
    ht::join(&values.0)?;
    Ok(values)
}
fn up(label: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    )
}
fn send<F: Fixture>(f: &F, b: &[u8]) -> Result<(), &'static str> {
    f.device()
        .enqueue(b, TxMeta::default())
        .map_err(|_| "RTS native enqueue")
}
fn word(d: &[u8; 48], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn rts(d: &[u8; 48]) -> bool {
    word(d, 12) & (1 << 12) != 0
}
fn data(descriptors: &[[u8; 48]]) -> impl Iterator<Item = &[u8; 48]> {
    descriptors.iter().filter(|d| word(d, 16) & 127 == 19)
}
fn set<F: Fixture>(f: &F, value: u32) -> Result<(), &'static str> {
    f.device()
        .set_rts_threshold(value)
        .map_err(|_| "current drained native RTS setting")?;
    if f.device().rts_threshold() != Some(value) {
        return Err("RTS setting readback metadata differs");
    }
    Ok(())
}

pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    for mode in 0..3 {
        let (f, _, _) = fixture::<F>(protected, mode)?;
        let retained = f.retained();
        if f.device().rts_threshold() != Some(u32::MAX) || f.descriptors().iter().any(rts) {
            return Err("X default enabled RTS or changed EAPOL/management");
        }
        set(&f, 0)?;
        let lease = narf_net::dhcp::dhcp_acquire(f.device().name(), 0)
            .map_err(|_| "RTS real kernel DHCP/IP")?;
        if !f.peer().lock().plan.matches_lease(&lease) {
            return Err("RTS DHCP lease terms");
        }
        let _ = f.received();
        let start = f.peer().lock().uplink.len();
        let frames = (0..4).map(up).collect::<Vec<_>>();
        for b in &frames {
            send(&f, b)?;
        }
        f.pump();
        if f.peer().lock().uplink[start..] != frames
            || f.retained() != retained
            || !f.device().link_up()
        {
            return Err("RTS native original/CCMP/IP/ownership mismatch");
        }
        let descriptors = f.descriptors();
        let ordinary = data(&descriptors).collect::<Vec<_>>();
        if ordinary.len() < 6
            || ordinary.iter().any(|d| {
                !rts(d)
                    || word(d, 16) >> 24 & 31 != 8
                    || word(d, 20) & (1 << 12) == 0
                    || word(d, 8) & (1 << 19) == 0
            })
        {
            return Err("actual RTS24M/short/source bits or native requested CCX absent");
        }
        if descriptors
            .iter()
            .filter(|d| word(d, 16) & 127 == 0)
            .any(rts)
        {
            return Err("EAPOL/management/BAR/DELBA acquired RTS");
        }
        if mode > 0 {
            super::rx_ba_tests::agreement(&f, 0, 91, 0, 64, 0)?;
            if f.register(0x4ce) & 0xffff != 0x0801 {
                return Err("X modified R BAR program");
            }
        }
        if mode > 1 && f.register(0x42a) & 0xffff != 0x0808 {
            return Err("X modified T retry program");
        }
        let b = up(61);
        let length = (b.len() + 20 + if protected { 16 } else { 0 }) as u32;
        set(&f, length)?;
        let before = f.descriptors().len();
        send(&f, &b)?;
        f.pump();
        let d = f.descriptors();
        if data(&d[before..]).any(rts) {
            return Err("RTS threshold used >= instead of source >");
        }
        set(&f, length - 1)?;
        let before = f.descriptors().len();
        send(&f, &b)?;
        f.pump();
        let d = f.descriptors();
        if data(&d[before..]).any(|d| !rts(d)) {
            return Err("RTS one-byte threshold crossing absent");
        }
        set(&f, u32::MAX)?;
        let before = f.descriptors().len();
        send(&f, &b)?;
        f.pump();
        if data(&f.descriptors()[before..]).any(rts) {
            return Err("disabled RTS remained on native DATA");
        }
    }
    Ok(())
}
pub(super) fn assets_and_old_profiles<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    ht::join(&f)?;
    if f.device().rts_threshold().is_some()
        || f.device().set_rts_threshold(0) != Err(narf_wireless::EOPNOTSUPP)
    {
        return Err("old H assets granted RTS");
    }
    send(&f, &up(71))?;
    f.pump();
    if f.descriptors().iter().any(rts) {
        return Err("old H emitted RTS");
    }
    drop(f);
    let f = F::make(false, 255, true, true)?;
    for case in 0..13 {
        let mut b = record(&f)?;
        match case {
            0 => b[0] ^= 3,
            1 => b[16] ^= 1,
            2 => b[48] ^= 2,
            3 => b[14] ^= 3,
            4 => b[68] = 1,
            5 => b[69] = 62,
            6 => b[56..58].copy_from_slice(&128i16.to_le_bytes()),
            7 => b[58..60].copy_from_slice(&0i16.to_le_bytes()),
            8 => b[62..64].copy_from_slice(&120i16.to_le_bytes()),
            9 => b[70..72].copy_from_slice(&2348u16.to_le_bytes()),
            10 => b[127] = 1,
            11 => b.truncate(127),
            _ => {}
        };
        if f.stage_rts(b, Cap::bootstrap(), case != 12).is_ok() {
            return Err("invalid/unsigned X record granted native RTS");
        }
    }
    let mut b = record(&f)?;
    b[70..72].copy_from_slice(&256u16.to_le_bytes());
    f.stage_rts(b, Cap::bootstrap(), true)
        .map_err(|_| "X malformed refusal not retryable")?;
    ht::join(&f)?;
    if f.device().set_rts_threshold(255) != Err(narf_wireless::EOPNOTSUPP)
        || f.device().rts_threshold() != Some(u32::MAX)
        || !f.device().link_up()
    {
        return Err("X measured threshold minimum changed state/admission");
    }
    if f.device().set_rts_threshold(2348) != Err(22) || f.device().rts_threshold() != Some(u32::MAX)
    {
        return Err("invalid public threshold changed native setting");
    }
    set(&f, 256)?;
    drop(f);
    let f = F::make(false, 255, true, true)?;
    let old = record(&f)?;
    let mut rb = super::rx_ba_tests::record(&f)?;
    for at in [60, 62, 64] {
        rb[at..at + 2].copy_from_slice(&76i16.to_le_bytes());
    }
    f.stage_ba(rb, Cap::bootstrap())
        .map_err(|_| "X prior high-peak R")?;
    if f.stage_rts(old, Cap::bootstrap(), true).is_ok() {
        return Err("H-only X asset also granted changed R program");
    }
    let mut narrowed = record(&f)?;
    narrowed[58..60].copy_from_slice(&68i16.to_le_bytes());
    if f.stage_rts(narrowed, Cap::bootstrap(), true).is_ok() {
        return Err("X ceiling ignored prior automatic-BA peak");
    }
    drop(f);
    let f = F::make(false, 255, true, true)?;
    f.stage_rts(record(&f)?, Cap::bootstrap(), true)
        .map_err(|_| "X actual response-rate fixture")?;
    f.peer().lock().response_rates = Some(vec![0x82, 12, 24]);
    ht::join(&f)?;
    if f.device().rts_threshold().is_some()
        || f.device().set_rts_threshold(0) != Err(narf_wireless::EOPNOTSUPP)
        || !f.device().link_up()
    {
        return Err("RTS24M was inferred without actual negotiated24M support");
    }
    Ok(())
}
pub(super) fn held_ccx_key_and_setting<F: Fixture>() -> Result<(), &'static str> {
    let (f, _, _) = fixture::<F>(true, 1)?;
    let retained = f.retained();
    set(&f, 0)?;
    f.peer().lock().hold_data = true;
    send(&f, &up(81))?;
    f.pump();
    let controls = f.controls();
    if !controls.held.load(Ordering::Acquire)
        || f.device().set_rts_threshold(u32::MAX) != Err(16)
        || f.device().rts_threshold() != Some(0)
    {
        return Err("held RTS native CCX did not freeze setting");
    }
    f.peer().lock().qos = false;
    let group = ht::group_rekey(&f)?;
    f.peer().lock().qos = true;
    let before = f.descriptors().len();
    f.inject(&group, 19, 0);
    f.pump();
    if f.descriptors().len() != before {
        return Err("key reply bypassed held RTS DATA/CCX");
    }
    controls.release.store(true, Ordering::Release);
    f.pump();
    if !controls.held.load(Ordering::Acquire) || f.device().set_rts_threshold(u32::MAX) != Err(16) {
        return Err("actual key reply was not held after RTS drain");
    }
    let d = f
        .descriptor()
        .ok_or("actual group reply descriptor missing")?;
    if rts(&d) || word(&d, 16) & 127 != 0 {
        return Err("private EAPOL inherited RTS or HT DATA rate");
    }
    f.peer().lock().hold_data = false;
    controls.release.store(true, Ordering::Release);
    f.pump();
    if !f.device().link_up() || f.device().rts_threshold() != Some(0) || f.retained() != retained {
        return Err("genuine key receipt lost X setting/current native owner");
    }
    send(&f, &up(82))?;
    f.pump();
    set(&f, u32::MAX)
}
pub(super) fn failures_and_current_sources<F: Fixture>() -> Result<(), &'static str> {
    for case in 0..4 {
        let (f, _, _) = fixture::<F>(true, 0)?;
        let retained = f.retained();
        set(&f, 0)?;
        let controls = f.controls();
        if case == 0 {
            controls.rts_failure.store(true, Ordering::Release);
        } else {
            f.peer().lock().hold_data = true;
        }
        send(&f, &up(91))?;
        f.pump();
        match case {
            0 => {}
            1 => {
                controls.fifo_stuck.store(true, Ordering::Release);
                controls.release.store(true, Ordering::Release);
                f.pump();
                f.advance_ms(1001);
            }
            2 => {
                controls.corrupt_receipt.store(true, Ordering::Release);
                controls.release.store(true, Ordering::Release);
            }
            _ => {
                f.device().admission().close();
                controls.release.store(true, Ordering::Release);
            }
        }
        f.pump();
        if !f.device().closed() || f.retained() != retained {
            return Err("RTS negative CCX/FIFO/corrupt/cancel released or reopened native owner");
        }
    }
    let total = {
        let (f, _, bases) = fixture::<F>(true, 2)?;
        f.sources().len() + bases.len() + 2
    };
    for which in 0..total {
        let (f, x, bases) = fixture::<F>(true, 2)?;
        let retained = f.retained();
        set(&f, 0)?;
        f.peer().lock().hold_data = true;
        send(&f, &up(92))?;
        f.pump();
        let mut sources = f.sources();
        sources.extend(bases);
        if which < sources.len() {
            sources[which].revoke();
        } else if which == sources.len() {
            x.revoke();
        } else {
            f.clear_policy();
        }
        f.controls().release.store(true, Ordering::Release);
        f.pump();
        f.install_policy();
        f.pump();
        if !f.device().closed()
            || f.retained() != retained
            || f.device().set_rts_threshold(u32::MAX).is_ok()
        {
            return Err("RTS current base/X/policy loss reopened or released native DMA");
        }
    }
    Ok(())
}
pub(super) fn partial_publication_and_fifo_setting<F: Fixture>() -> Result<(), &'static str> {
    let (f, x, _) = fixture::<F>(true, 2)?;
    let retained = f.retained();
    set(&f, 0)?;
    let before = f.peer().lock().uplink.len();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    f.after_descriptor(Arc::new(move || {
        if observed.fetch_add(1, Ordering::AcqRel) == 1 {
            x.revoke();
        }
    }));
    for i in 0..4 {
        send(&f, &up(i))?;
    }
    f.pump();
    if calls.load(Ordering::Acquire) != 2
        || f.peer().lock().uplink.len() != before
        || !f.device().closed()
        || f.retained() != retained
    {
        return Err("X revocation between native BDs published a doorbell or released pool");
    }
    drop(f);
    let (f, _, _) = fixture::<F>(false, 0)?;
    let controls = f.controls();
    controls.fifo_stuck.store(true, Ordering::Release);
    if f.device().set_rts_threshold(0) != Err(16)
        || f.device().rts_threshold() != Some(u32::MAX)
        || !f.device().link_up()
    {
        return Err("nonempty native FIFO changed RTS setting or terminalized Busy");
    }
    controls.fifo_stuck.store(false, Ordering::Release);
    set(&f, 0)?;
    controls.fifo_invalid.store(true, Ordering::Release);
    if f.device().set_rts_threshold(u32::MAX).is_ok() || !f.device().closed() {
        return Err("invalid native FIFO allowed RTS reconfiguration");
    }
    Ok(())
}
