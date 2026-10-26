//! Actual native TFH/RFH queue, command and packet ownership after association.
use super::super::super::{firmware_parser_tests, runtime};
use super::super::{
    auth::tests::authenticated_fixture, power::tests::retained_source, queue::tests::Fixture,
};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    cell::Cell,
    pin::Pin,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{
    association::SecurityMode,
    reg::{RegFlags, RegRule},
};

const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const DATA_QUEUE: u16 = 24;
const POINTER: u16 = 0x91;
fn policy() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    }
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn associated(protected: bool, version: u8, mixed_rates: bool) -> Result<Fixture, &'static str> {
    let mut f = authenticated_fixture(protected)?;
    let owner = f.owner.as_mut().unwrap();
    if mixed_rates {
        // Actual observed offer adds6/12/24Mbps, but the response admits
        // only1+6Mbps. TLC must use that response intersection, not the offer.
        owner.beacons[0]
            .information_elements
            .extend_from_slice(&[50, 3, 12, 24, 48]);
    }
    let image = firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&image).unwrap();
    let mut versions = parsed.api.commands.to_vec();
    versions.extend_from_slice(&[
        0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3, 15, 5, version, 0,
    ]);
    runtime::model::versions(&mut owner.hardware, &versions);
    let mut response = vec![0; 81 + usize::from(mixed_rates)];
    response[0] = 33 + u8::from(mixed_rates);
    response[12] = 3;
    response[32] = 40;
    response[34] = 1;
    response[48] = 0x10;
    response[52..58].fill(2);
    response[58..64].copy_from_slice(&AP);
    response[64..70].copy_from_slice(&AP);
    response[72] = if protected { 17 } else { 1 };
    response[76..78].copy_from_slice(&[7, 0xc0]);
    response[78..81].copy_from_slice(&[1, 1 + u8::from(mixed_rates), 0x82]);
    if mixed_rates {
        response[81] = 12;
    }
    {
        let mut op = pin!(owner.associate_legacy_using(
            b"net",
            if protected {
                SecurityMode::Wpa2Psk
            } else {
                SecurityMode::Open
            },
            || Ok(policy())
        ));
        if !poll(op.as_mut()).is_pending() {
            return Err("data prerequisite association enable");
        }
        for stage in 0..7 {
            match stage {
                0 => f.firmware.inject(0x18, 0, 8, &[1, 0, 0, 0]),
                1 => f.firmware.tx_complete(23, 0x47),
                2 => f.firmware.inject(0xc1, 0, 0x8000, &response),
                3 => f.firmware.inject(0x18, 0, 9, &[1, 0, 0, 0]),
                4 => f.firmware.inject(0x18, 0, 10, &[1, 0, 0, 0]),
                5 => f.firmware.inject(9, 3, 11, &[]),
                _ => f.firmware.inject(8, 3, 12, &[]),
            }
            let result = poll(op.as_mut());
            if stage == 6 {
                if !matches!(result, Poll::Ready(Ok(_))) {
                    return Err("actual data prerequisite association");
                }
            } else if !result.is_pending() {
                return Err("data prerequisite skipped native wait");
            }
        }
    }
    while f.trace.take().is_some() {}
    Ok(f)
}
fn queue_reply(id: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&id.to_le_bytes());
    bytes[4..6].copy_from_slice(&POINTER.to_le_bytes());
    bytes
}
fn inject(stage: usize, fw: &mut runtime::model::Firmware) {
    match stage {
        0 => fw.inject(9, 3, 13, &[]),
        1 => fw.inject(15, 5, 14, &[]),
        2 => fw.inject(0x17, 5, 15, &queue_reply(DATA_QUEUE)),
        3 => fw.inject(0x18, 0, 16, &[1, 0, 0, 0]),
        _ => unreachable!(),
    }
}
fn until<T>(
    stage: usize,
    mut op: Pin<&mut impl Future<Output = T>>,
    fw: &mut runtime::model::Firmware,
) -> Result<(), &'static str> {
    if !poll(op.as_mut()).is_pending() {
        return Err("data preparation skipped initial wait");
    }
    for step in 0..stage {
        inject(step, fw);
        if !poll(op.as_mut()).is_pending() {
            return Err("data preparation skipped native wait");
        }
    }
    Ok(())
}
fn prepare(f: &mut Fixture, protected: bool) -> Result<(), &'static str> {
    let mut op = pin!(f
        .owner
        .as_mut()
        .unwrap()
        .prepare_data_using(|| Ok(policy())));
    let last = if protected { 2 } else { 3 };
    until(last, op.as_mut(), &mut f.firmware)?;
    inject(last, &mut f.firmware);
    if !matches!(poll(op.as_mut()), Poll::Ready(Ok(_))) {
        return Err("native data preparation completion");
    }
    Ok(())
}
fn command(
    trace: &runtime::model::TxTrace,
    opcode: u8,
    group: u8,
    sequence: u16,
) -> Result<Vec<u8>, &'static str> {
    let p = trace.take().ok_or("native data control DMA missing")?;
    if p.queue != 0
        || p.bytes.len() < 8
        || p.bytes[..2] != [opcode, group]
        || p.bytes[2..4] != sequence.to_le_bytes()
        || p.bytes[7] != 0
    {
        return Err("native data control header/identity/version mismatch");
    }
    Ok(p.bytes[8..].to_vec())
}
fn ethernet(outgoing: bool) -> Vec<u8> {
    let mut bytes = vec![];
    let remote = [6, 1, 2, 3, 4, 5];
    bytes.extend_from_slice(if outgoing { &remote } else { &[2; 6] });
    bytes.extend_from_slice(if outgoing { &[2; 6] } else { &remote });
    bytes.extend_from_slice(&[8, 0, 1, 2, 3, 4]);
    bytes
}
fn rx(ethernet: &[u8], sequence: u16) -> Vec<u8> {
    let mut bytes = vec![0; 48 + 24 + 6];
    bytes[12] = 3;
    bytes[32] = 40;
    bytes[34] = 1;
    bytes[48..50].copy_from_slice(&[8, 2]);
    bytes[52..58].copy_from_slice(&ethernet[..6]);
    bytes[58..64].copy_from_slice(&AP);
    bytes[64..70].copy_from_slice(&ethernet[6..12]);
    bytes[70..72].copy_from_slice(&(sequence << 4).to_le_bytes());
    bytes[72..78].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    bytes.extend_from_slice(&ethernet[12..]);
    let length = (bytes.len() - 48) as u16;
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes
}
fn smoke_gen2_data_native_edca_tlc_queue_open_tx_rx_and_retirement() -> TestResult {
    check(|| {
        for version in [2, 3, 4] {
            for mixed in [false, true] {
                let mut f = associated(false, version, mixed)?;
                prepare(&mut f, false)?;
                let owner = f.owner.as_mut().unwrap();
                let mut expected = [0; 208];
                expected[0] = 2;
                expected[16..22].fill(2);
                expected[24] = 8;
                for (index, fifo) in [2, 4, 8, 16].into_iter().enumerate() {
                    let at = 60 + index * 8;
                    expected[at..at + 6].copy_from_slice(&[
                        if mixed { 15 } else { 31 },
                        0,
                        255,
                        3,
                        2,
                        fifo,
                    ]);
                }
                if command(&f.trace, 9, 3, 13)? != expected {
                    return Err("DCF EDCA differs from literal Linux AC/FIFO units");
                }
                let mut tlc = vec![0; if version == 2 { 24 } else { 28 }];
                tlc[6] = 1;
                tlc[10] = if mixed { 17 } else { 1 };
                if command(&f.trace, 15, 5, 14)? != tlc {
                    return Err("TLC did not bind actual response rates/SISO/version extent");
                }
                let allocate = command(&f.trace, 0x17, 5, 15)?;
                let addresses = runtime::model::queue_dma_addresses(&owner.hardware, DATA_QUEUE)
                    .ok_or("data queue DMA absent")?;
                let mut expected = [0; 36];
                expected[4] = 1;
                // Native cb_size is log2(128)-3; this retained transport
                // owns128 descriptors, within the legacy firmware bounds.
                expected[16] = 4;
                expected[20..28].copy_from_slice(&addresses.0.to_le_bytes());
                expected[28..36].copy_from_slice(&addresses.1.to_le_bytes());
                if allocate != expected {
                    return Err("normal data allocation not station0/TID0/128 owned descriptors");
                }
                let mut enable = [0; 48];
                enable[0] = 1;
                enable[24] = 16;
                if command(&f.trace, 0x18, 1, 16)? != enable
                    || !owner
                        .data_ready(&policy())
                        .is_ok_and(|s| !s.protected && s.queue == DATA_QUEUE)
                {
                    return Err("Open port did not follow exact native peer enable");
                }
                {
                    let frame = ethernet(true);
                    let mut tx = pin!(owner.transmit_data_using(&frame, || Ok(policy())));
                    if !poll(tx.as_mut()).is_pending() {
                        return Err("Open packet skipped native TX receipt");
                    }
                    let seen = f
                        .trace
                        .take()
                        .ok_or("actual normal data packet DMA missing")?;
                    let mut expected = vec![0; 60];
                    // Initial absolute pointer0x91 selects native slot0x11
                    // in this128-entry ring; completion still advances0x92.
                    expected[..8].copy_from_slice(&[0x1c, 0, 0x11, 24, 36, 0, 0, 12]);
                    expected[8] = 2; // native TLC rate selection + plaintext, no invented key
                    expected[24..26].copy_from_slice(&[8, 1]);
                    expected[28..34].copy_from_slice(&AP);
                    expected[34..40].fill(2);
                    expected[40..46].copy_from_slice(&frame[..6]);
                    expected[48..].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]);
                    if seen.queue != DATA_QUEUE
                        || seen.pointer != POINTER + 1
                        || seen.bytes != expected
                    {
                        return Err("actual Open packet is not bound native v9/TID0 data");
                    }
                    f.firmware.tx_complete(DATA_QUEUE, POINTER + 1);
                    if poll(tx.as_mut()) != Poll::Ready(Ok(())) {
                        return Err("native data receipt did not retire exact packet");
                    }
                }
                let inbound = ethernet(false);
                f.firmware.inject(0xc1, 0, 0x8000, &rx(&inbound, 17));
                if owner.receive_data_using(|| Ok(policy()))?
                    != Some(LegacyReceive::Ethernet(inbound))
                {
                    return Err("actual native Open data did not reach bound Ethernet receiver");
                }
                {
                    let mut close = pin!(owner.release_legacy_data());
                    if !poll(close.as_mut()).is_pending() {
                        return Err("data close skipped disable receipt");
                    }
                    f.firmware.inject(0x18, 0, 17, &[1, 0, 0, 0]);
                    if !poll(close.as_mut()).is_pending() {
                        return Err("data close skipped native queue retirement");
                    }
                    f.firmware.inject(0x17, 5, 18, &queue_reply(DATA_QUEUE));
                    if poll(close.as_mut()) != Poll::Ready(Ok(())) {
                        return Err("data close not terminal after matching removal");
                    }
                }
                let mut disable = [0; 48];
                disable[0] = 1;
                disable[20] = 16;
                disable[24] = 16;
                let mut remove = [0; 36];
                remove[0] = 1;
                remove[4] = 1;
                if command(&f.trace, 0x18, 1, 17)? != disable
                    || command(&f.trace, 0x17, 5, 18)? != remove
                    || owner.phase() != Phase::Associated
                    || runtime::model::retained(&owner.hardware).1 != 1
                    || !owner.hardware.idle_tx_binding(23, 0, 15)
                {
                    return Err(
                        "data close freed management owner or skipped disable-before-remove",
                    );
                }
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_secured_port_cannot_be_faked_or_forward_plaintext() -> TestResult {
    check(|| {
        let mut f = associated(true, 3, false)?;
        prepare(&mut f, true)?;
        let owner = f.owner.as_mut().unwrap();
        if owner.prepared_legacy_data().is_none_or(|s| !s.protected)
            || owner
                .power
                .prepared
                .as_ref()
                .unwrap()
                .mlme
                .data
                .as_ref()
                .unwrap()
                .port_open
            || !matches!(
                poll(pin!(
                    owner.transmit_data_using(&ethernet(true), || Ok(policy()))
                )),
                Poll::Ready(Err(_))
            )
        {
            return Err("WPA2 association/queue metadata opened unauthenticated data port");
        }
        for _ in 0..3 {
            f.trace
                .take()
                .ok_or("secured preparation native command absent")?;
        }
        if f.trace.take().is_some() {
            return Err("secured preparation enabled peer or submitted ordinary data");
        }
        f.firmware.inject(0xc1, 0, 0x8000, &rx(&ethernet(false), 1));
        if owner.receive_data_using(|| Ok(policy()))?.is_some() {
            return Err("WPA2 plaintext escaped controlled port");
        }
        let mut eapol = vec![];
        eapol.extend_from_slice(&[2; 6]);
        eapol.extend_from_slice(&AP);
        eapol.extend_from_slice(&[0x88, 0x8e, 2, 0, 0, 2, 0x12, 0x34]);
        f.firmware.inject(0xc1, 0, 0x8000, &rx(&eapol, 2));
        if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Eapol(eapol)) {
            return Err("bound EAPOL not isolated from ordinary Ethernet");
        }
        if f.trace.take().is_some() || owner.phase() != Phase::DataPrepared {
            return Err("EAPOL observation fabricated crypto/native TX");
        }
        Ok(())
    })
}
fn smoke_gen2_data_prepare_cancel_at_every_native_wait_pins_ownership() -> TestResult {
    check(|| {
        for stage in 0..4 {
            let mut f = associated(false, 3, false)?;
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.prepare_data_using(|| Ok(policy())));
                until(stage, op.as_mut(), &mut f.firmware)?;
            }
            let retained = runtime::model::retained(&owner.hardware);
            if owner.phase() != Phase::PreparingData
                || owner.prepared_legacy_data().is_some()
                || retained.1 != if stage >= 2 { 2 } else { 1 }
                || retained.0 != 1
                || !matches!(
                    poll(pin!(owner.prepare_data_using(|| Ok(policy())))),
                    Poll::Ready(Err(_))
                )
                || !matches!(poll(pin!(owner.clear_association())), Poll::Ready(Err(_)))
                || !matches!(poll(pin!(owner.release_legacy_data())), Poll::Ready(Err(_)))
            {
                return Err(
                    "cancelled data preparation released DMA or reopened conflicting lifecycle",
                );
            }
            inject(stage, &mut f.firmware);
            owner.hardware.poll()?;
            if owner.prepared_legacy_data().is_some()
                || runtime::model::retained(&owner.hardware).1 != retained.1
            {
                return Err("late data control receipt reopened cancelled owner");
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_prepare_each_wait_rechecks_policy_and_qualification() -> TestResult {
    check(|| {
        for stage in 0..4 {
            for revoke in [false, true] {
                let mut f = associated(false, 3, false)?;
                let owner = f.owner.as_mut().unwrap();
                let source = retained_source(owner);
                let denied = Cell::new(false);
                {
                    let mut op = pin!(owner.prepare_data_using(|| if denied.get() {
                        Err("test policy lost")
                    } else {
                        Ok(policy())
                    }));
                    until(stage, op.as_mut(), &mut f.firmware)?;
                    if revoke {
                        source.revoke();
                    } else {
                        denied.set(true);
                    }
                    inject(stage, &mut f.firmware);
                    if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                        return Err("data native wait ignored current power authority");
                    }
                }
                if owner.phase() != Phase::Failed
                    || owner.prepared_legacy_data().is_some()
                    || runtime::model::retained(&owner.hardware).1 != if stage >= 2 { 2 } else { 1 }
                {
                    return Err("failed data qualification released uncertain owner");
                }
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_native_control_failures_preserve_allocations() -> TestResult {
    check(|| {
        for stage in 0..4 {
            let mut f = associated(false, 3, false)?;
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.prepare_data_using(|| Ok(policy())));
                until(stage, op.as_mut(), &mut f.firmware)?;
                match stage {
                    0 => f.firmware.inject(9, 3, 13, &[0]),
                    1 => f.firmware.inject(15, 5, 14, &[0]),
                    2 => f.firmware.inject(0x17, 5, 15, &queue_reply(23)), // retained management ID reuse
                    _ => f.firmware.inject(0x18, 0, 16, &[0; 4]),
                }
                if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                    return Err("malformed data control receipt admitted");
                }
            }
            if owner.phase() != Phase::Failed
                || runtime::model::retained(&owner.hardware).1 != if stage >= 2 { 2 } else { 1 }
            {
                return Err("malformed control receipt released queue DMA");
            }
        }
        for version in [0, 1, 5, 6, 255] {
            let mut f = associated(false, version, false)?;
            let owner = f.owner.as_mut().unwrap();
            if !matches!(
                poll(pin!(owner.prepare_data_using(|| Ok(policy())))),
                Poll::Ready(Err(_))
            ) || owner.phase() != Phase::Associated
                || f.trace.take().is_some()
            {
                return Err("unsupported TLC API published before preflight");
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_packet_cancel_failure_and_foreign_receipt_never_reopen() -> TestResult {
    check(|| {
        for case in 0..5 {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            while f.trace.take().is_some() {}
            let owner = f.owner.as_mut().unwrap();
            let before = runtime::model::retained(&owner.hardware);
            let source = retained_source(owner);
            let frame = ethernet(true);
            {
                let mut tx = pin!(owner.transmit_data_using(&frame, || Ok(policy())));
                if !poll(tx.as_mut()).is_pending() {
                    return Err("packet did not retain native receipt wait");
                }
                match case {
                    0 => {} // drop actual pending TX
                    1 => {
                        source.revoke();
                        if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                            return Err("TX ignored revoked qualification");
                        }
                    }
                    2 => {
                        f.firmware.tx_complete(DATA_QUEUE, POINTER + 2);
                        if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                            return Err("TX accepted out-of-window completion");
                        }
                    }
                    3 => {
                        let mut bad = [0; 48];
                        bad[0] = 1;
                        bad[36] = 24;
                        bad[40] = 0x82;
                        bad[44..48].copy_from_slice(&u32::from(POINTER + 1).to_le_bytes());
                        f.firmware.inject(0x1c, 0, 0x8000, &bad);
                        if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                            return Err("failed TX became successful data");
                        }
                    }
                    _ => {
                        // Another retained queue's receipt cannot retire
                        // this packet, even when it names a known queue.
                        f.firmware.tx_complete(23, POINTER + 1);
                        if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                            return Err("foreign management receipt completed normal data");
                        }
                    }
                }
            }
            let after = runtime::model::retained(&owner.hardware);
            if owner.prepared_legacy_data().is_some()
                || after.0 != before.0
                || after.1 != before.1
                || after.2 != if case == 3 { before.2 } else { before.2 + 1 }
                || !matches!(poll(pin!(owner.release_legacy_data())), Poll::Ready(Err(_)))
            {
                return Err("cancelled/failed packet released uncertain DMA or reopened teardown");
            }
        }
        Ok(())
    })
}

fn enable_lar(owner: &mut Owner) {
    let mut api = super::super::super::firmware_api::FirmwareApi::default();
    api.capabilities[0] = 1 << 1;
    owner.scan = super::super::scan::ScanContext::new(&api);
    owner.scan.ready = true;
    owner.scan.nvm_lar = true;
}
fn mcc(flags: u32) -> Vec<u8> {
    // Native v3 response containing channel1 only, with an exact count.
    let mut bytes = vec![0; 20];
    bytes[12] = 1;
    bytes[16..20].copy_from_slice(&flags.to_le_bytes());
    bytes
}
fn smoke_gen2_data_fresh_mcc_denial_and_cancel_fence_each_packet() -> TestResult {
    check(|| {
        for cancel in [false, true] {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            while f.trace.take().is_some() {}
            let owner = f.owner.as_mut().unwrap();
            enable_lar(owner);
            let frame = ethernet(true);
            {
                let mut tx = pin!(owner.transmit_data_using(&frame, || Ok(policy())));
                if !poll(tx.as_mut()).is_pending() {
                    return Err("data packet skipped fresh MCC wait");
                }
                let query = command(&f.trace, 0xc8, 1, 17)?;
                let mut expected = [0; 28];
                expected[..2].copy_from_slice(b"ZZ");
                if query != expected {
                    return Err("fresh data MCC query/header differs from native v1");
                }
                if !cancel {
                    // Valid receive-only flags omit ACTIVE: a former
                    // successful association/power receipt cannot override it.
                    f.firmware.inject(0xc8, 1, 17, &mcc(1 | (1 << 8)));
                    if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                        return Err("current firmware MCC denial still emitted native data");
                    }
                }
            }
            if cancel {
                f.firmware
                    .inject(0xc8, 1, 17, &mcc(1 | (1 << 3) | (1 << 8)));
                owner.hardware.poll()?;
            }
            if owner.prepared_legacy_data().is_some()
                || f.trace.take().is_some()
                || runtime::model::retained(&owner.hardware).1 != 2
                || runtime::model::retained(&owner.hardware).2 != 0
            {
                return Err("failed/cancelled MCC query reopened data or released queue lifetime");
            }
        }
        // The initial data preparation has its own fresh-MCC transaction.
        let mut f = associated(false, 3, false)?;
        let owner = f.owner.as_mut().unwrap();
        enable_lar(owner);
        {
            let mut prepare = pin!(owner.prepare_data_using(|| Ok(policy())));
            if !poll(prepare.as_mut()).is_pending() {
                return Err("initial data preparation skipped MCC");
            }
            f.firmware.inject(0xc8, 1, 13, &mcc(0));
            if !matches!(poll(prepare.as_mut()), Poll::Ready(Err(_))) {
                return Err("preparation ignored current firmware channel denial");
            }
        }
        if owner.phase() != Phase::Failed || runtime::model::retained(&owner.hardware).1 != 1 {
            return Err("MCC-denied preparation allocated a normal data queue");
        }
        Ok(())
    })
}

fn smoke_gen2_data_malformed_allocation_and_close_never_retire_other_owners() -> TestResult {
    check(|| {
        for case in 0..4 {
            let mut f = associated(false, 3, false)?;
            let owner = f.owner.as_mut().unwrap();
            {
                let mut prepare = pin!(owner.prepare_data_using(|| Ok(policy())));
                until(2, prepare.as_mut(), &mut f.firmware)?;
                let mut bad = queue_reply(DATA_QUEUE).to_vec();
                match case {
                    0 => bad.truncate(7),
                    1 => bad[2] = 1,
                    2 => bad[6] = 1,
                    _ => bad[..2].fill(0),
                }
                f.firmware.inject(0x17, 5, 15, &bad);
                if !matches!(poll(prepare.as_mut()), Poll::Ready(Err(_))) {
                    return Err("malformed allocation opened a data producer");
                }
            }
            if owner.phase() != Phase::Failed || runtime::model::retained(&owner.hardware).1 != 2 {
                return Err("malformed allocation dropped published DMA");
            }
        }
        for stage in 0..2 {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            let owner = f.owner.as_mut().unwrap();
            let management = runtime::model::queue_dma_addresses(&owner.hardware, 23);
            {
                let mut close = pin!(owner.release_legacy_data());
                if !poll(close.as_mut()).is_pending() {
                    return Err("close did not await disable");
                }
                f.firmware.inject(
                    0x18,
                    0,
                    17,
                    if stage == 0 {
                        &[0, 0, 0, 0]
                    } else {
                        &[1, 0, 0, 0]
                    },
                );
                if stage == 1 {
                    if !poll(close.as_mut()).is_pending() {
                        return Err("close skipped removal");
                    }
                    f.firmware.inject(0x17, 5, 18, &queue_reply(23));
                }
                if !matches!(poll(close.as_mut()), Poll::Ready(Err(_))) {
                    return Err("failed/foreign close receipt retired data lifetime");
                }
            }
            if owner.phase() != Phase::Failed
                || runtime::model::retained(&owner.hardware).1 != 2
                || management.is_none()
                || runtime::model::queue_dma_addresses(&owner.hardware, 23) != management
            {
                return Err("invalid close dropped another retained owner");
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_receive_strict_profile_and_live_policy_fence() -> TestResult {
    check(|| {
        for case in 0..16 {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            let owner = f.owner.as_mut().unwrap();
            let frame = ethernet(false);
            let mut bad = rx(&frame, 9);
            match case {
                0 => bad[34] = 2,
                1 => bad[58] ^= 2,
                2 => bad[52] = 4,
                3 => bad[49] |= 0x80,
                4 => bad[49] |= 4,
                5 => bad[70] |= 1,
                6 => bad[48] |= 0x80,
                7 => bad[49] |= 0x40,
                8 => bad[3] |= 0x40,
                9 => bad[13] |= 2,
                10 => bad[12] &= !1,
                11 => bad[14] |= 0x40,
                12 => bad[29] = 2, // HT modulation in actual rates-v2 field
                13 => bad[29] = 8, // 40MHz instead of legacy20
                14 => bad[28] = 1, // unnegotiated2Mbps
                _ => bad[28] = 16, // reserved/NSS indicator in legacy format
            }
            f.firmware.inject(0xc1, 0, 0x8000, &bad);
            f.firmware.inject(0xc1, 0, 0x8000, &rx(&frame, 10));
            if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Ethernet(frame)) {
                return Err(
                    "malformed/foreign RX escaped or swallowed following valid native frame",
                );
            }
        }
        for revoke in [false, true] {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            let owner = f.owner.as_mut().unwrap();
            f.firmware
                .inject(0xc1, 0, 0x8000, &rx(&ethernet(false), 10));
            if revoke {
                retained_source(owner).revoke();
            }
            let mut domain = policy();
            domain.rules[0].flags = RegFlags::NO_IR;
            if owner
                .receive_data_using(|| Ok(if revoke { policy() } else { domain.clone() }))
                .is_ok()
                || owner.phase() != Phase::Failed
                || owner.prepared_legacy_data().is_some()
            {
                return Err("current source/policy loss published queued Ethernet");
            }
        }
        Ok(())
    })
}
fn smoke_gen2_data_close_each_wait_and_revoked_source_keep_exact_owner() -> TestResult {
    check(|| {
        for stage in 0..2 {
            let mut f = associated(false, 3, false)?;
            prepare(&mut f, false)?;
            let owner = f.owner.as_mut().unwrap();
            retained_source(owner).revoke();
            let before = runtime::model::retained(&owner.hardware).1;
            {
                let mut close = pin!(owner.release_legacy_data());
                if !poll(close.as_mut()).is_pending() {
                    return Err("revoked data close skipped disable");
                }
                if stage == 1 {
                    f.firmware.inject(0x18, 0, 17, &[1, 0, 0, 0]);
                    if !poll(close.as_mut()).is_pending() {
                        return Err("revoked close skipped remove");
                    }
                }
            }
            if owner.phase() != Phase::ClosingData
                || runtime::model::retained(&owner.hardware).1 != before
                || !matches!(poll(pin!(owner.clear_association())), Poll::Ready(Err(_)))
            {
                return Err("cancelled close retired association/queue before receipt");
            }
        }
        let mut f = associated(false, 3, false)?;
        prepare(&mut f, false)?;
        let owner = f.owner.as_mut().unwrap();
        retained_source(owner).revoke();
        {
            let mut close = pin!(owner.release_legacy_data());
            if !poll(close.as_mut()).is_pending() {
                return Err("revoked source prevented close");
            }
            f.firmware.inject(0x18, 0, 17, &[1, 0, 0, 0]);
            if !poll(close.as_mut()).is_pending() {
                return Err("revoked close remove wait absent");
            }
            f.firmware.inject(0x17, 5, 18, &queue_reply(DATA_QUEUE));
            if poll(close.as_mut()) != Poll::Ready(Ok(())) {
                return Err("revoked close did not honor exact receipt");
            }
        }
        if owner.phase() != Phase::Associated || runtime::model::retained(&owner.hardware).1 != 1 {
            return Err("revoked close did not preserve association/management queue");
        }
        Ok(())
    })
}

fn smoke_gen2_data_rx_padding_retry_and_ap_close_keep_native_boundaries() -> TestResult {
    check(|| {
        let mut f = associated(false, 3, false)?;
        prepare(&mut f, false)?;
        let owner = f.owner.as_mut().unwrap();
        let frame = ethernet(false);
        let mut padded = rx(&frame, 33);
        // Actual API4 envelope declares two padding bytes after the MAC
        // header and a four-byte CRC trailer, neither Ethernet payload.
        padded[3] |= 0x20;
        padded[2] = 0x20;
        padded.splice(72..72, [0xa5, 0x5a]);
        padded.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let len = (padded.len() - 48) as u16;
        padded[..2].copy_from_slice(&len.to_le_bytes());
        f.firmware.inject(0xc1, 0, 0x8000, &padded);
        if owner.receive_data_using(|| Ok(policy()))?
            != Some(LegacyReceive::Ethernet(frame.clone()))
        {
            return Err("native padding/CRC bytes entered Ethernet payload");
        }
        let mut retry = rx(&frame, 33);
        retry[49] |= 8;
        f.firmware.inject(0xc1, 0, 0x8000, &retry);
        f.firmware.inject(0xc1, 0, 0x8000, &rx(&frame, 34));
        if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Ethernet(frame)) {
            return Err("retry duplicate replayed instead of next native packet");
        }
        let mut close = vec![0; 74];
        close[0] = 26;
        close[12] = 3;
        close[32] = 40;
        close[34] = 1;
        close[48] = 0xc0;
        close[52..58].fill(2);
        close[58..64].copy_from_slice(&AP);
        close[64..70].copy_from_slice(&AP);
        close[72] = 3;
        f.firmware.inject(0xc1, 0, 0x8000, &close);
        if owner.receive_data_using(|| Ok(policy())).is_ok()
            || owner.phase() != Phase::Failed
            || runtime::model::retained(&owner.hardware).1 != 2
        {
            return Err("current AP close kept host port or released live DMA");
        }
        Ok(())
    })
}

fn smoke_gen2_data_rejected_host_packets_and_queued_policy_loss_publish_nothing() -> TestResult {
    check(|| {
        let mut f = associated(false, 3, false)?;
        prepare(&mut f, false)?;
        while f.trace.take().is_some() {}
        let owner = f.owner.as_mut().unwrap();
        for case in 0..4 {
            let mut frame = ethernet(true);
            match case {
                0 => frame[6] ^= 2,
                1 => frame[12..14].copy_from_slice(&[0x88, 0x8e]),
                2 => frame.truncate(13),
                _ => frame.resize(1515, 0),
            }
            if !matches!(
                poll(pin!(owner.transmit_data_using(&frame, || Ok(policy())))),
                Poll::Ready(Err(_))
            ) || f.trace.take().is_some()
                || owner.phase() != Phase::DataPrepared
            {
                return Err("invalid/EAPOL caller packet entered native data queue or poisoned retryable owner");
            }
        }
        let frame = ethernet(true);
        let permitted = Cell::new(true);
        {
            let mut tx = pin!(owner.transmit_data_using(&frame, || if permitted.get() {
                Ok(policy())
            } else {
                Err("test policy removed")
            }));
            if !poll(tx.as_mut()).is_pending() {
                return Err("data packet did not reach native completion wait");
            }
            permitted.set(false);
            f.firmware.tx_complete(DATA_QUEUE, POINTER + 1);
            if !matches!(poll(tx.as_mut()), Poll::Ready(Err(_))) {
                return Err("queued TX success overrode current host policy loss");
            }
        }
        if owner.phase() != Phase::Failed
            || runtime::model::retained(&owner.hardware).1 != 2
            || runtime::model::retained(&owner.hardware).2 != 1
        {
            return Err(
                "policy loss dropped uncertain packet before consuming actual native receipt",
            );
        }
        Ok(())
    })
}

fn smoke_gen2_data_observed_port_restriction_cannot_reinstall_or_reopen() -> TestResult {
    check(|| {
        for protected in [false, true] {
            for case in 0..3 {
                let mut f = associated(protected, 3, false)?;
                prepare(&mut f, protected)?;
                while f.trace.take().is_some() {}
                let owner = f.owner.as_mut().unwrap();
                if owner.data_port_using(|| Ok(policy())) == protected {
                    return Err(
                        "controlled port did not reflect actual Open versus secured association",
                    );
                }
                let mut restricted = policy();
                restricted.rules.push(RegRule {
                    freq_start_mhz: 2413,
                    freq_end_mhz: 2415,
                    max_bandwidth_mhz: 20,
                    max_power_dbm: 10,
                    flags: RegFlags::NO_IR,
                });
                if case == 2 {
                    retained_source(owner).revoke();
                }
                if owner.data_port_using(|| {
                    if case == 0 {
                        Err("test policy cleared")
                    } else {
                        Ok(if case == 1 {
                            restricted.clone()
                        } else {
                            policy()
                        })
                    }
                }) || owner.phase() != Phase::Failed
                    || owner.data_port_using(|| Ok(policy()))
                    || f.trace.take().is_some()
                    || runtime::model::retained(&owner.hardware).1 != 2
                {
                    return Err("observed current source/policy restriction reopened port after reinstallation");
                }
            }
        }
        Ok(())
    })
}

kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_native_edca_tlc_queue_open_tx_rx_and_retirement
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_secured_port_cannot_be_faked_or_forward_plaintext
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_prepare_cancel_at_every_native_wait_pins_ownership
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_prepare_each_wait_rechecks_policy_and_qualification
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_native_control_failures_preserve_allocations
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_packet_cancel_failure_and_foreign_receipt_never_reopen
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_receive_strict_profile_and_live_policy_fence
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_close_each_wait_and_revoked_source_keep_exact_owner
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_fresh_mcc_denial_and_cancel_fence_each_packet
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_malformed_allocation_and_close_never_retire_other_owners
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_rx_padding_retry_and_ap_close_keep_native_boundaries
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_rejected_host_packets_and_queued_policy_loss_publish_nothing
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_data_observed_port_restriction_cannot_reinstall_or_reopen
);
