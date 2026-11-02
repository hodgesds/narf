//! Actual delegated AP source, independent Linux notification wire fields.
use super::*;
const PEER: [u8; 6] = [2, 0, 0, 0, 0x53, 1];
const IES: &[u8] = &[0, 4, b'n', b'a', b'r', b'f', 1, 2, 0x82, 0x84];
fn event(
    f: &Fixture,
    source: Arc<dyn DeferredReplySink>,
) -> Result<ApEventAuthority, &'static str> {
    let authority = bound(f, source)?
        .reserve()
        .map_err(|_| "station event original reservation")?;
    authority
        .event_authority()
        .map_err(|_| "station event actual authority")
}
fn fields(mut raw: &[u8]) -> Result<Vec<(u16, &[u8])>, &'static str> {
    let mut result = Vec::new();
    while !raw.is_empty() {
        let head = raw.get(..4).ok_or("station event short attribute")?;
        let length = usize::from(u16::from_ne_bytes([head[0], head[1]]));
        if length < 4 {
            return Err("station event attribute length");
        }
        let kind = u16::from_ne_bytes([head[2], head[3]]);
        result.push((
            kind,
            raw.get(4..length).ok_or("station event attribute span")?,
        ));
        raw = raw
            .get(length.next_multiple_of(4)..)
            .ok_or("station event attribute padding")?;
    }
    Ok(result)
}
fn wire() -> Result<(), &'static str> {
    let f = fixture()?;
    let source = Arc::new(NativeSource::new());
    let event = event(&f, source.clone())?;
    // Event capture releases the native control lease.
    drop(
        bound(&f, source.clone())?
            .reserve()
            .map_err(|_| "station event retained control lease")?,
    );
    for generation in [0, u32::MAX] {
        let mut ies = IES.to_vec();
        let added = event
            .prepare_station_associated(PEER, generation, &ies)
            .map_err(|_| "prepare actual associated station")?;
        let lost = event
            .prepare_station_lost(PEER, generation)
            .map_err(|_| "prepare actual lost station")?;
        ies.fill(0xff);
        let callbacks = source.callbacks.load(Ordering::Acquire);
        added
            .deliver()
            .map_err(|_| "fixed associated station delivery")?;
        lost.deliver().map_err(|_| "fixed lost station delivery")?;
        if source.callbacks.load(Ordering::Acquire) != callbacks {
            return Err("station event final delivery called arbitrary source code");
        }
    }
    let messages = source.messages.lock();
    let wiphy = crate::registry::wiphy_index(f.radio.wiphy_id()).ok_or("original event wiphy")?;
    let wdev = (u64::from(wiphy) << 32) | u64::from(f.ifindex);
    for (i, raw) in messages.iter().enumerate() {
        let add = i % 2 == 0;
        if raw.len() < 20
            || raw[16] != if add { 19 } else { 20 }
            || raw[8..16] != [0; 8]
            || u32::from_ne_bytes(raw[..4].try_into().unwrap()) as usize != raw.len()
        {
            return Err("station event command or notification header changed");
        }
        let attrs = fields(&raw[20..])?;
        let generation = if i < 2 { 0 } else { u32::MAX };
        let mut expected = alloc::vec![
            (3, f.ifindex.to_ne_bytes().to_vec()),
            (153, wdev.to_ne_bytes().to_vec()),
            (6, PEER.to_vec()),
            (46, generation.to_ne_bytes().to_vec()),
            (21 | (1 << 15), Vec::new()),
        ];
        if add {
            expected.push((42, IES.to_vec()));
        }
        if attrs.len() != expected.len()
            || !attrs
                .iter()
                .zip(&expected)
                .all(|((a, b), (c, d))| a == c && *b == d.as_slice())
        {
            return Err(
                "station event invented fields, lost original identity or borrowed changed IEs",
            );
        }
    }
    if messages.len() != 4 {
        return Err("station event lost actual notifications");
    }
    Ok(())
}
fn prepared_ap_station_events_serialize_original_identity_and_actual_ies_only() -> TestResult {
    wire().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_emission",
    prepared_ap_station_events_serialize_original_identity_and_actual_ies_only
);

fn invalid() -> Result<(), &'static str> {
    let f = fixture()?;
    let source = Arc::new(NativeSource::new());
    let event = event(&f, source.clone())?;
    for peer in [[0; 6], [1, 0, 0, 0, 0, 1], [255; 6]] {
        if !matches!(
            event.prepare_station_associated(peer, 1, IES),
            Err(WirelessError::InvalidArgs)
        ) || !matches!(
            event.prepare_station_lost(peer, 1),
            Err(WirelessError::InvalidArgs)
        ) {
            return Err("station event admitted invalid peer identity");
        }
    }
    let too_big = alloc::vec![0;2305];
    for ies in [
        &[][..],
        &[0][..],
        &[0, 2, 1][..],
        &[0, 0, 1][..],
        too_big.as_slice(),
    ] {
        if !matches!(
            event.prepare_station_associated(PEER, 1, ies),
            Err(WirelessError::InvalidArgs)
        ) {
            return Err("station event admitted malformed or unbounded association IEs");
        }
    }
    let mut maximum = Vec::new();
    for _ in 0..8 {
        maximum.extend_from_slice(&[221, 255]);
        maximum.resize(maximum.len() + 255, 0);
    }
    maximum.extend_from_slice(&[221, 246]);
    maximum.resize(maximum.len() + 246, 0);
    if maximum.len() != 2304 {
        return Err("station event maximum fixture extent");
    }
    event
        .prepare_station_associated(PEER, 1, &maximum)
        .map_err(|_| "bounded complete maximum station IEs refused")?;
    let legacy = bound(&f, f.source.clone())?
        .event_authority()
        .map_err(|_| "legacy metadata authority")?;
    if legacy.prepare_station_lost(PEER, 1).is_ok()
        || source.delivery_attempts.load(Ordering::Acquire) != 0
    {
        return Err("unknown provider or preparation published native station event");
    }
    Ok(())
}
fn prepared_ap_station_events_reject_invalid_peer_ie_and_unknown_native_source() -> TestResult {
    invalid().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_emission",
    prepared_ap_station_events_reject_invalid_peer_ie_and_unknown_native_source
);

fn cuts() -> Result<(), &'static str> {
    for boundary in 0..7 {
        let f = fixture()?;
        let source = Arc::new(NativeSource::new());
        let event = event(&f, source.clone())?;
        let added = event
            .prepare_station_associated(PEER, 7, IES)
            .map_err(|_| "station source capture")?;
        let lost = event
            .prepare_station_lost(PEER, 8)
            .map_err(|_| "station loss source capture")?;
        let callbacks = source.callbacks.load(Ordering::Acquire);
        match boundary {
            1 => source.owner.retire().notify(),
            2 => f.daemon.revoke(),
            3 => f.cap.revoke(),
            4 => {
                narf_net::iface::set_link_state(f.radio.name(), false);
                narf_net::iface::set_link_state(f.radio.name(), true);
            }
            5 => {
                crate::registry::unregister(f.radio.name());
                crate::registry::register(f.iface.clone());
            }
            6 => {
                f.radio.mode.store(2, Ordering::Release);
                f.radio.generation.store(2, Ordering::Release);
                f.radio.mode.store(3, Ordering::Release);
                f.radio.generation.store(3, Ordering::Release);
            }
            _ => {}
        }
        if added.deliver().is_ok() != (boundary == 0)
            || lost.deliver().is_ok() != (boundary == 0)
            || source.delivery_attempts.load(Ordering::Acquire) != if boundary == 0 { 2 } else { 0 }
            || source.callbacks.load(Ordering::Acquire) != callbacks
        {
            return Err("prepared station event crossed original cap/source/role/UP/registration retirement");
        }
    }
    Ok(())
}
fn prepared_ap_station_events_check_fixed_original_proofs_after_preparation() -> TestResult {
    cuts().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_emission",
    prepared_ap_station_events_check_fixed_original_proofs_after_preparation
);
