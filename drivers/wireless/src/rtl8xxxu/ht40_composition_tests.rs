// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual signed-v2/native20/40/ring/peer/crypto/restore compositions.
use super::*;
use crate::rtl8xxxu::{
    device_init::Factory,
    firmware_transport::Executable,
    ht_runtime::{self, Geometry, WideMode, WidePlan, WideProgram, WideQualification},
};
use narf_wireless::station_security::RawFrame;

pub(super) fn elements(geometry: Geometry) -> Vec<u8> {
    let mut bytes = super::super::super::super::ht_tests::elements(255);
    bytes[2] |= 2;
    bytes[30] = geometry.primary();
    bytes[31] = if geometry.secondary() > geometry.primary() {
        5
    } else {
        7
    };
    bytes
}
/// Explicit inert dimensional envelopes, never a registered board artifact.
pub(super) fn artifact(base: &Proof, executable: Executable, geometry: Geometry) -> Vec<u8> {
    let (factory, legacy, _) = base.calibration().binding();
    let mut bytes = vec![0; 1472];
    bytes[..4].copy_from_slice(b"N8HT");
    bytes[4..8].copy_from_slice(&[2, 0, 192, 0]);
    bytes[8..12].copy_from_slice(&1472u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&factory[..4]);
    bytes[16..48].copy_from_slice(&ht_runtime::wide_request(base, executable, geometry).binding);
    bytes[48..77].copy_from_slice(&factory);
    bytes[80..112].copy_from_slice(&legacy);
    bytes[112..118].copy_from_slice(&factory[8..14]);
    bytes[118..124].copy_from_slice(&[
        geometry.primary(),
        40,
        1,
        0,
        geometry.secondary(),
        geometry.center(),
    ]);
    bytes[124..126].copy_from_slice(&8i16.to_le_bytes());
    bytes[126..128].copy_from_slice(&80i16.to_le_bytes());
    bytes[128..160].copy_from_slice(&ht_runtime::request(base, executable).binding);
    for row in bytes[192..].chunks_exact_mut(128) {
        for (gain, value) in row.chunks_exact_mut(2).enumerate() {
            value.copy_from_slice(&(gain as i16 * 2).to_le_bytes());
        }
    }
    bytes
}
fn domain() -> Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>> {
    Arc::new(IrqSafeSpinLock::new(narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2482,
            max_bandwidth_mhz: 40,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }))
}
fn proof(
    factory: Factory,
    geometry: Geometry,
    domain: &Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
    cap: Cap<FirmwareBlob, Read>,
) -> Result<Arc<Proof>, &'static str> {
    let calibration = calibration(factory);
    let permission = calibration
        .permission(&domain.lock(), geometry.primary())
        .map_err(|_| "EU v2 primary permission")?;
    Ok(Proof::model(calibration, permission, cap, domain.clone()))
}
fn make_qualification(
    base: Arc<Proof>,
    executable: Executable,
    factory: Factory,
    geometry: Geometry,
    cap: Cap<FirmwareBlob, Read>,
) -> Result<Arc<WideQualification>, &'static str> {
    let bytes = artifact(&base, executable, geometry);
    WideQualification::parse(
        base,
        executable,
        factory,
        geometry,
        &bytes,
        Some([7; 32]),
        cap,
    )
    .map(Arc::new)
    .map_err(|_| "EU exact v2 full-program record")
}
fn result(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}

fn qualification_binding() -> Result<(), &'static str> {
    let (control, firmware) = initialized_registered_firmware();
    let mut factory = firmware.factory().ok_or("EU v2 factory")?;
    // Primary6 belongs to group2; RF center4 belongs to group1. Only the
    // PRIMARY maximum19 is legitimate, even though center's maximum is32.
    factory.ht40_power[2] = 19;
    let geometry = Geometry::new(6, 2).map_err(|_| "EU v2 minus geometry")?;
    let domain = domain();
    let legacy = Cap::bootstrap();
    let cap = Cap::bootstrap();
    let base = proof(factory, geometry, &domain, legacy)?;
    let executable = firmware.executable().ok_or("EU v2 executable")?;
    let bytes = artifact(&base, executable, geometry);
    let q = make_qualification(base.clone(), executable, factory, geometry, cap)?;
    ensure!(
        q.gains().is_ok_and(|g| g.mcs() == [19; 8]),
        "EU v2 used center group or imported another chip's HT difference"
    );
    let ops = control.0.lock().ops.len();
    ensure!(
        drive(WideProgram::install(
            &firmware,
            WidePlan::new(q.clone(), WideMode::Forty)
        ))?
        .is_err()
            && control.0.lock().ops.len() == ops,
        "EU foreign factory data authorized native programming"
    );
    for at in [
        0, 4, 6, 8, 12, 16, 48, 76, 77, 80, 112, 118, 119, 120, 121, 122, 123, 128, 160,
    ] {
        let mut wrong = bytes.clone();
        wrong[at] ^= 1;
        ensure!(
            WideQualification::parse(
                base.clone(),
                executable,
                factory,
                geometry,
                &wrong,
                Some([7; 32]),
                cap
            )
            .is_err(),
            "EU v2 malformed/foreign/old record granted native profile"
        );
    }
    ensure!(
        WideQualification::parse(
            base.clone(),
            executable,
            factory,
            geometry,
            &bytes,
            None,
            cap
        )
        .is_err()
            && WideQualification::parse(
                base.clone(),
                executable,
                factory,
                geometry,
                &bytes[..1471],
                Some([7; 32]),
                cap
            )
            .is_err(),
        "EU unsigned/truncated v2 granted"
    );
    for row in [0, 1, 2] {
        let mut unknown = bytes.clone();
        unknown[192 + row * 128..192 + (row + 1) * 128]
            .chunks_exact_mut(2)
            .for_each(|value| value.copy_from_slice(&i16::MAX.to_le_bytes()));
        ensure!(
            WideQualification::parse(
                base.clone(),
                executable,
                factory,
                geometry,
                &unknown,
                Some([7; 32]),
                cap
            )
            .is_err(),
            "EU v2 invented legacy/MCS envelope at unknown points"
        );
    }
    ensure!(
        control.0.lock().ops.len() == ops,
        "EU v2 pure admission performed native I/O"
    );
    cap.revoke();
    ensure!(
        q.gains().is_err(),
        "EU v2 retired artifact source stayed current"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht40_v2_binds_full_program_and_primary_factory_group() -> TestResult {
    result(qualification_binding)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_v2_binds_full_program_and_primary_factory_group
);

fn registers(h: &AssociatedFixture, geometry: Geometry, wide: bool) -> Result<(), &'static str> {
    let model = h.link.radio.control.0.lock();
    let value = |reg: usize| u32::from_le_bytes(model.regs[reg..reg + 4].try_into().unwrap());
    ensure!(
        model.rf[0x18] & 0xfff
            == if wide {
                u32::from(geometry.center()) | 0x400
            } else {
                u32::from(geometry.primary()) | 0xc00
            },
        "EU physical RF width/center differs from selected peer program"
    );
    ensure!(
        (model.regs[0x603] & 4 == 0) == wide
            && (value(0x800) & 1 != 0) == wide
            && (value(0x900) & 1 != 0) == wide,
        "EU actual MAC/BB width disagrees with RF"
    );
    if wide {
        let low = geometry.primary() < geometry.secondary();
        ensure!(
            value(0x440) & 0x600000 == (if low { 0x200000 } else { 0x400000 })
                && value(0xa00) & 0x10 == (if low { 0 } else { 0x10 })
                && value(0xd00) & 0xc00 == (if low { 0x400 } else { 0x800 })
                && value(0x818) & 0xc000000 == (if low { 0x8000000 } else { 0x4000000 }),
            "EU literal primary/secondary BB response routing"
        );
    }
    Ok(())
}
fn conversation(protected: bool, geometry: Geometry) -> Result<(), &'static str> {
    let h = AssociatedFixture::new_profile(protected, true, Some(geometry))?;
    h.join()?;
    registers(&h, geometry, true)?;
    let network = h.link.radio.bulk.0.lock().network;
    let lease =
        narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU actual HT40 native DHCP")?;
    ensure!(
        network.matches_lease(&lease)
            && h.device.link_up()
            && h.device.connected_bssid() == Some(AP),
        "EU HT40 DHCP/carrier/native peer"
    );
    let peer = h.link.radio.bulk.0.lock();
    let expected = if geometry.primary() < geometry.secondary() {
        0x02100000
    } else {
        0x02200000
    };
    let data = peer
        .native_tx
        .iter()
        .filter(|p| p.get(TX_DESC) == Some(&0x88))
        .collect::<Vec<_>>();
    ensure!(
        !data.is_empty()
            && data.iter().all(
                |p| u32::from_le_bytes(p[16..20].try_into().unwrap()) & 0x02300000 == expected
                    && p[..TX_DESC]
                        .chunks_exact(2)
                        .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]))
                        == 0
            ),
        "EU HT40 DATA omitted source v3 width/primary or checksum"
    );
    ensure!(
        peer.error.is_none() && (peer.replay.last_seen_pn > 0) == protected,
        "EU HT40 actual peer CCMP/PN validation"
    );
    drop(peer);
    let frame = udp_ipv4(
        h.device.mac(),
        AP,
        [10, 88, 0, 1],
        [10, 88, 0, 42],
        8,
        7,
        b"actual wide downlink",
    );
    h.link.radio.bulk.0.lock().downlink(&frame)?;
    ensure!(
        h.device.progress().contains(&frame),
        "EU native BW40 RX failed original software key/port"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht40_plus_open_literal_native_geometry_and_dhcp() -> TestResult {
    result(|| conversation(false, Geometry::new(1, 5).map_err(|_| "EU plus geometry")?))
}
fn smoke_rtl8188eu_ht40_minus_wpa2_literal_native_geometry_and_dhcp() -> TestResult {
    result(|| conversation(true, Geometry::new(6, 2).map_err(|_| "EU minus geometry")?))
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_plus_open_literal_native_geometry_and_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_minus_wpa2_literal_native_geometry_and_dhcp
);

#[inline(never)]
fn narrow_fallback() -> Result<(), &'static str> {
    let geometry = Geometry::new(1, 5).map_err(|_| "EU fallback geometry")?;
    for mode in 0..3 {
        let selected = if mode == 2 {
            Geometry::new(6, 2).map_err(|_| "EU alternate geometry")?
        } else {
            geometry
        };
        let h = AssociatedFixture::new_profile(true, true, Some(selected))?;
        {
            let mut peer = h.link.radio.bulk.0.lock();
            peer.ht40 = false;
            peer.ht40_request = mode == 1;
            if mode == 2 {
                let alternate =
                    Geometry::new(6, 10).map_err(|_| "EU unsupported alternate secondary")?;
                peer.beacon_ht = Some(elements(alternate));
                peer.response_ht = peer.beacon_ht.clone();
            } else {
                peer.response_ht = Some(super::super::super::super::ht_tests::elements(255));
                if mode == 0 {
                    peer.beacon_ht = peer.response_ht.clone();
                }
            }
        }
        let before = h.link.radio.control.0.lock().cold_generation;
        h.join()?;
        registers(&h, selected, false)?;
        let network = h.link.radio.bulk.0.lock().network;
        let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0)
            .map_err(|_| "EU v2 real20MHz fallback DHCP")?;
        ensure!(
            network.matches_lease(&lease)
                && h.link
                    .radio
                    .bulk
                    .0
                    .lock()
                    .native_tx
                    .iter()
                    .filter(|p| p.get(TX_DESC) == Some(&0x88))
                    .all(|p| u32::from_le_bytes(p[16..20].try_into().unwrap()) & 0x02300000 == 0),
            "EU20 fallback inherited BW40/primary DATA fields"
        );
        if mode == 1 {
            ensure!(
                h.link.radio.control.0.lock().cold_generation >= before + 2,
                "EU narrowed response relabeled physical40 stream instead of cold restoring20"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_ht40_offer_and_response_narrowing_restore_real_twenty_before_keys() -> TestResult
{
    result(narrow_fallback)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_offer_and_response_narrowing_restore_real_twenty_before_keys
);

struct Rig {
    receiver: Receiver<Fake, AssociatedLink>,
    link: AssociatedLink,
    domain: Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
    firmware: Arc<Owner<Fake>>,
    geometry: Geometry,
    source: Cap<FirmwareBlob, Read>,
}
impl Rig {
    #[inline(never)]
    fn new() -> Result<Box<Self>, &'static str> {
        let geometry = Geometry::new(1, 5).map_err(|_| "EU raw geometry")?;
        let (control, firmware) = initialized_registered_firmware();
        let factory = firmware.factory().ok_or("EU raw factory")?;
        let domain = domain();
        let legacy = Cap::bootstrap();
        let source = Cap::bootstrap();
        let base = proof(factory, geometry, &domain, legacy)?;
        let executable = firmware.executable().ok_or("EU raw executable")?;
        let q = make_qualification(base.clone(), executable, factory, geometry, source)?;
        let mut peer = Peer::new(plan(factory.mac), false);
        peer.ht = true;
        peer.ht40 = true;
        peer.beacon_ht = Some(elements(geometry));
        peer.response_ht = peer.beacon_ht.clone();
        let clock = Env::default();
        let link = AssociatedLink {
            home: 1,
            radio: ChannelLink {
                bulk: Link(Arc::new(IrqSafeSpinLock::new(peer))),
                control: control.clone(),
                seen_reset: Arc::new(AtomicU64::new(control.0.lock().cold_generation)),
                beacon: Arc::new(AtomicBool::new(false)),
                beacon_generation: Arc::new(AtomicU64::new(u64::MAX)),
            },
            power: Arc::new(IrqSafeSpinLock::new(PowerIndications {
                home_generation: u64::MAX,
                away_generation: u64::MAX,
                ..Default::default()
            })),
            probes: Arc::new(IrqSafeSpinLock::new(Default::default())),
            clock,
        };
        let mut receiver = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain.lock()).map_err(|_| "EU raw RX")?,
        )
        .map_err(|_| "EU raw owner")?;
        receiver.install_wmm_model(base);
        drive(receiver.install_wide_model(q))?.map_err(|_| "EU raw actual20 program")?;
        drive(receiver.start())?.map_err(|_| "EU raw actual RX")?;
        Ok(Box::new(Self {
            receiver,
            link,
            domain,
            firmware,
            geometry,
            source,
        }))
    }
    fn push_data(&self) -> Result<(), &'static str> {
        let own = self.link.radio.bulk.0.lock().network.station;
        let frame = udp_ipv4(
            own,
            AP,
            [10, 88, 0, 1],
            [10, 88, 0, 42],
            8,
            7,
            b"native qualified raw copy",
        );
        self.link.radio.bulk.0.lock().downlink(&frame)
    }
    fn copied(&mut self) -> Result<Option<packet_codec::Mpdu>, &'static str> {
        for _ in 0..16 {
            if let Some(frames) = self.receiver.poll().map_err(|_| "EU raw current poll")? {
                if let Some(frame) = frames.into_iter().find(|f| f.bytes.first() == Some(&0x88)) {
                    return Ok(Some(frame));
                }
            }
        }
        Ok(None)
    }
}
fn raw_epoch_and_current_span() -> Result<(), &'static str> {
    let mut h = Rig::new()?;
    h.push_data()?;
    ensure!(
        h.copied()?.is_none(),
        "EU untrusted BW40 bit granted wide admission under actual20 program"
    );
    h.push_data()?;
    let old_rx = h.link.radio.bulk.0.lock().rx;
    let before = h.link.radio.control.0.lock().cold_generation;
    drive(h.receiver.select_station_geometry(Some(h.geometry)))?
        .map_err(|_| "EU real same-primary width transition")?;
    ensure!(
        h.link.radio.control.0.lock().cold_generation > before
            && h.link.radio.bulk.0.lock().rx != old_rx
            && h.copied()?.is_none(),
        "EU old queued40 copy was relabeled after width change"
    );
    let before_park = h.link.radio.bulk.0.lock().rx;
    drive(h.receiver.park())?.map_err(|_| "EU wide actual park")?;
    ensure!(
        h.receiver.phase() == crate::rtl8xxxu::receive_runtime::Phase::Parked
            && h.link.radio.bulk.0.lock().rx.is_none(),
        "EU wide park left actual RX posted"
    );
    drive(h.receiver.resume_parked())?.map_err(|_| "EU wide actual wake")?;
    ensure!(
        h.link.radio.bulk.0.lock().rx != before_park
            && h.link.radio.control.0.lock().rf[0x18] & 0xfff == 0x403,
        "EU wide wake lost actual40MHz geometry or reused old RX"
    );
    h.push_data()?;
    let copied = h.copied()?.ok_or("EU actual new wide native copy")?;
    ensure!(
        copied.bandwidth40 && copied.unmodified(),
        "EU actual native40 program omitted sealed RawFrame admission"
    );
    h.domain.lock().rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2430,
        freq_end_mhz: 2431,
        max_bandwidth_mhz: 40,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    let factory = h.firmware.factory().ok_or("EU raw current factory")?;
    // The sealed copied proof re-enters the original model domain through
    // WideQualification -> base Proof::policy. End this guard's scope before
    // that call; retain the independently checked primary20 permission.
    let primary_still_allowed = {
        let current = h.domain.lock();
        calibration(factory).permission(&current, 1).is_ok()
    };
    ensure!(
        primary_still_allowed && !copied.unmodified(),
        "EU40 proof ignored a forbidden subspan outside the original20 primary"
    );
    h.domain.lock().rules.pop();
    ensure!(
        !copied.unmodified(),
        "EU looser policy resurrected a retired native copied program"
    );
    ensure!(
        h.source.invoke(narf_capabilities::NoopOp).is_ok(),
        "EU span test accidentally revoked the artifact instead of current40 policy"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht40_native_stream_cut_and_copied_span_proof_retire_stickily() -> TestResult {
    result(raw_epoch_and_current_span)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_native_stream_cut_and_copied_span_proof_retire_stickily
);

fn held_source() -> Result<(), &'static str> {
    let geometry = Geometry::new(1, 5).map_err(|_| "EU held geometry")?;
    let h = AssociatedFixture::new_profile(true, true, Some(geometry))?;
    h.join()?;
    let network = h.link.radio.bulk.0.lock().network;
    narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU held initial DHCP")?;
    h.pump();
    h.link.radio.bulk.0.lock().hold_data = true;
    let frame = udp_ipv4(
        AP,
        network.station,
        [10, 88, 0, 42],
        [10, 88, 0, 1],
        7,
        8,
        b"wide held actual USB",
    );
    h.device
        .enqueue(&frame, Default::default())
        .map_err(|_| "EU wide held enqueue")?;
    h.pump();
    let tx = h
        .link
        .radio
        .bulk
        .0
        .lock()
        .tx
        .as_ref()
        .filter(|tx| tx.data)
        .map(|tx| tx.id)
        .ok_or("EU wide test did not publish actual DATA TD")?;
    let rx = h.link.radio.bulk.0.lock().rx;
    let ops = h.link.radio.control.0.lock().ops.len();
    h.wide_source.ok_or("EU distinct v2 source")?.revoke();
    ensure!(
        h.device.progress().is_empty()
            && !h.device.link_up()
            && h.link.radio.bulk.0.lock().tx.as_ref().map(|tx| tx.id) == Some(tx)
            && h.link.radio.bulk.0.lock().rx == rx
            && h.link.radio.control.0.lock().ops.len() == ops
            && h.firmware.claim_receive().is_err(),
        "EU revoked v2 source reclaimed a held actual USB/receive owner"
    );
    ensure!(
        h.ht_source.invoke(narf_capabilities::NoopOp).is_ok()
            && h.source.invoke(narf_capabilities::NoopOp).is_ok(),
        "EU v2 loss test revoked unrelated v1/base grants"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht40_revoked_v2_source_keeps_actual_data_and_receive_receipts() -> TestResult {
    result(held_source)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_revoked_v2_source_keeps_actual_data_and_receive_receipts
);

fn ba_restore() -> Result<(), &'static str> {
    let geometry = Geometry::new(1, 5).map_err(|_| "EU BA geometry")?;
    ba_and_away_crypto_on(AssociatedFixture::new_profile(true, true, Some(geometry))?)
}
fn smoke_rtl8188eu_ht40_associated_scan_retains_actual_ba_keys_and_replay() -> TestResult {
    result(ba_restore)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_associated_scan_retains_actual_ba_keys_and_replay
);

fn active_restore_and_cold_loss() -> Result<(), &'static str> {
    let geometry = Geometry::new(6, 2).map_err(|_| "EU active wide geometry")?;
    let h = AssociatedFixture::new_profile(true, true, Some(geometry))?;
    h.join()?;
    h.link.probes.lock().responses = true;
    h.link.probes.lock().suppress_away_beacon = true;
    let mut request = h.scan(&[6, 1]);
    request.active = true;
    request.ssids = vec![SSID.to_vec()];
    drive(h.device.scan(request))?.map_err(|_| "EU active wide home/away restore")?;
    registers(&h, geometry, true)?;
    let network = h.link.radio.bulk.0.lock().network;
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU wide restored DHCP")?;
    ensure!(
        network.matches_lease(&lease),
        "EU wide active return key/peer continuity"
    );
    h.link.radio.control.0.lock().pending_write = Some(0x284);
    let mut scan = Box::pin(h.device.scan(h.scan(&[1])));
    let mut published = false;
    for _ in 0..4096 {
        ensure!(
            scan.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "EU wide cold test ended before real EP0"
        );
        if h.link.radio.control.0.lock().active_td {
            published = true;
            break;
        }
    }
    ensure!(published, "EU wide cold scan did not own native EP0");
    let generation = h.link.radio.control.0.lock().cold_generation;
    let rx = h.link.radio.bulk.0.lock().rx;
    let ops = h.link.radio.control.0.lock().ops.len();
    h.wide_source.ok_or("EU wide source")?.revoke();
    ensure!(
        drive(scan)?.is_err()
            && !h.device.link_up()
            && h.link.radio.control.0.lock().active_td
            && h.link.radio.control.0.lock().cold_generation == generation
            && h.link.radio.bulk.0.lock().rx == rx
            && h.link.radio.control.0.lock().ops.len() == ops
            && h.link.radio.control.0.lock().unsafe_reuses == 0,
        "EU wide cold/source loss reused physical native ownership"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht40_active_restore_and_cold_source_loss_keep_native_owners() -> TestResult {
    result(active_restore_and_cold_loss)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht40",
    smoke_rtl8188eu_ht40_active_restore_and_cold_source_loss_keep_native_owners
);
