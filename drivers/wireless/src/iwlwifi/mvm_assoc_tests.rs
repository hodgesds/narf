use super::super::super::runtime;
use super::super::queue::tests::Fixture;
use super::super::{auth::tests::authenticated_fixture, power::tests::retained_source};
use super::*;
use alloc::vec;
use core::{
    cell::Cell,
    future::Future,
    pin::{pin, Pin},
    task::{Context as TaskContext, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};
const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
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
    let result = future.poll(&mut TaskContext::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn response(protected: bool) -> Vec<u8> {
    // RFH API4 and IEEE response with AID7, one supported/basic1Mbps rate.
    let mut bytes = vec![0; 81];
    bytes[0] = 33;
    bytes[12] = 3;
    bytes[32] = 40;
    bytes[34] = 1;
    bytes[48] = 0x10;
    bytes[52..58].fill(2);
    bytes[58..64].copy_from_slice(&AP);
    bytes[64..70].copy_from_slice(&AP);
    bytes[72] = if protected { 17 } else { 1 };
    bytes[76] = 7;
    bytes[77] = 0xc0;
    bytes[78..].copy_from_slice(&[1, 1, 0x82]);
    bytes
}
fn inject(stage: usize, fw: &mut runtime::model::Firmware, protected: bool) {
    match stage {
        0 => fw.inject(0x18, 0, 8, &[1, 0, 0, 0]),
        1 => fw.tx_complete(23, 0x47),
        2 => fw.inject(0xc1, 0, 0x8000, &response(protected)),
        3 => fw.inject(0x18, 0, 9, &[1, 0, 0, 0]),
        4 => fw.inject(0x18, 0, 10, &[1, 0, 0, 0]),
        5 => fw.inject(9, 3, 11, &[]),
        6 => fw.inject(8, 3, 12, &[]),
        _ => unreachable!(),
    }
}
fn until(
    stage: usize,
    op: Pin<&mut impl Future<Output = Result<AssociationStatus, &'static str>>>,
    fw: &mut runtime::model::Firmware,
    protected: bool,
) -> Result<(), &'static str> {
    let mut op = op;
    if !poll(op.as_mut()).is_pending() {
        return Err("association did not reserve initial native wait");
    }
    for step in 0..stage {
        inject(step, fw, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("association skipped a native prerequisite wait");
        }
    }
    Ok(())
}
fn cmd(
    trace: &runtime::model::TxTrace,
    opcode: u8,
    group: u8,
    seq: u16,
    body: &[u8],
) -> Result<(), &'static str> {
    let seen = trace
        .take()
        .ok_or("missing actual association control DMA")?;
    if seen.queue != 0
        || seen.bytes.len() != body.len() + 8
        || seen.bytes[..2] != [opcode, group]
        || seen.bytes[2..4] != seq.to_le_bytes()
        || seen.bytes[7] != 0
        || seen.bytes[8..] != *body
    {
        return Err("association control differs from literal header0/native payload");
    }
    Ok(())
}
fn peer_wire(aid: u8, enable: bool) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[0] = 1;
    bytes[20] = if enable { 0 } else { 16 };
    bytes[24] = 16;
    bytes[36] = aid;
    bytes
}
fn mac_wire(aid: u8) -> [u8; 52] {
    let mut bytes = [0; 52];
    bytes[4] = 2;
    bytes[8] = 5;
    bytes[12..18].fill(2);
    bytes[20] = if aid == 0 { 12 } else { 4 };
    bytes[36] = u8::from(aid != 0);
    bytes[40] = aid;
    bytes
}
fn link_wire(associated: bool) -> [u8; 208] {
    let mut bytes = [0; 208];
    bytes[0] = 2;
    bytes[16..22].fill(2);
    bytes[24] = 22;
    bytes[36] = 1;
    bytes[40] = 0x15;
    if associated {
        bytes[136] = 100;
        bytes[140] = 100;
    }
    bytes
}
fn success(protected: bool) -> Result<(), &'static str> {
    let mut f = authenticated_fixture(protected)?;
    let owner = f.owner.as_mut().unwrap();
    let expected = AssociationStatus {
        bssid: AP,
        channel: 1,
        aid: 7,
        supported_rates: 1,
        basic_rates: 1,
        protected,
        short_preamble: false,
        short_slot: false,
        erp_protection: false,
    };
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
            return Err("association enable wait");
        }
        cmd(&f.trace, 0x18, 1, 8, &peer_wire(0, true))?;
        inject(0, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("association packet wait");
        }
        let packet = f
            .trace
            .take()
            .ok_or("missing native association packet DMA")?;
        let mut frame = vec![0; 36];
        frame[4..10].copy_from_slice(&AP);
        frame[10..16].fill(2);
        frame[16..22].copy_from_slice(&AP);
        frame[22] = 16;
        frame[24..].copy_from_slice(&[
            if protected { 17 } else { 1 },
            0,
            5,
            0,
            0,
            3,
            b'n',
            b'e',
            b't',
            1,
            1,
            0x82,
        ]);
        if protected {
            frame.extend_from_slice(&[
                48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ]);
        }
        if packet.queue != 23
            || packet.pointer != 0x47
            || packet.bytes.len() != frame.len() + 24
            || packet.bytes[..4] != [0x1c, 0, 0x46, 0x17]
            || packet.bytes[4..6] != (frame.len() as u16).to_le_bytes()
            || packet.bytes[8] != 3
            || packet.bytes[20..24] != [0, 0x40, 0, 0]
            || packet.bytes[24..] != frame
        {
            return Err("association packet differs from actual offered legacy/RSN frame");
        }
        inject(1, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("TX ACK fabricated association response");
        }
        inject(2, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("AP response bypassed peer disable");
        }
        cmd(&f.trace, 0x18, 1, 9, &peer_wire(0, false))?;
        inject(3, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("disabled peer bypassed AID receipt");
        }
        cmd(&f.trace, 0x18, 1, 10, &peer_wire(7, false))?;
        inject(4, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("peer receipt bypassed associated LINK");
        }
        cmd(&f.trace, 9, 3, 11, &link_wire(true))?;
        inject(5, &mut f.firmware, protected);
        if !poll(op.as_mut()).is_pending() {
            return Err("LINK receipt bypassed associated MAC");
        }
        cmd(&f.trace, 8, 3, 12, &mac_wire(7))?;
        inject(6, &mut f.firmware, protected);
        if poll(op.as_mut()) != Poll::Ready(Ok(expected)) {
            return Err("native association receipts failed");
        }
    }
    if owner.associated_station() != Some(expected)
        || owner.phase() != Phase::Associated
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("associated metadata lost disabled queue/power ownership");
    }
    if !matches!(
        poll(pin!(owner.deactivate_link()).as_mut()),
        Poll::Ready(Err(_))
    ) || !matches!(
        poll(pin!(owner.release_management_queue()).as_mut()),
        Poll::Ready(Err(_))
    ) {
        return Err("associated owner bypassed local association close");
    }
    {
        let mut close = pin!(owner.clear_association());
        for (step, opcode, group, body) in [
            (0, 8, 3, mac_wire(0).to_vec()),
            (1, 0x18, 1, peer_wire(0, false).to_vec()),
            (2, 9, 3, link_wire(false).to_vec()),
        ] {
            if !poll(close.as_mut()).is_pending() {
                return Err("association close skipped native receipt");
            }
            cmd(&f.trace, opcode, group, 13 + step, &body)?;
            f.firmware.inject(
                opcode,
                if group == 1 { 0 } else { group },
                13 + step,
                if opcode == 0x18 { &[1, 0, 0, 0] } else { &[] },
            );
        }
        if poll(close.as_mut()) != Poll::Ready(Ok(())) {
            return Err("association close native receipts failed");
        }
    }
    if owner.phase() != Phase::LinkActive
        || owner.associated_station().is_some()
        || owner.prepared_active_link().is_none()
        || !owner.hardware.idle_tx_binding(23, 0, 15)
    {
        return Err("association close released active disabled prerequisites");
    }
    Ok(())
}
fn smoke_gen2_native_association_open_wpa2_receipts_and_ordered_close() -> TestResult {
    success(false)
        .and_then(|()| success(true))
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_gen2_association_cancel_at_each_wait_retains_exact_owner() -> TestResult {
    let result = (|| {
        for stage in 0..7 {
            let mut f = authenticated_fixture(false)?;
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op =
                    pin!(owner.associate_legacy_using(b"net", SecurityMode::Open, || Ok(policy())));
                until(stage, op.as_mut(), &mut f.firmware, false)?;
            }
            let expected = if stage == 1 {
                (0, 1, 1)
            } else if stage == 2 {
                (0, 1, 0)
            } else {
                (1, 1, 0)
            };
            if owner.phase() != Phase::Associating
                || runtime::model::retained(&owner.hardware) != expected
                || owner.associated_station().is_some()
            {
                return Err("cancelled association lost pending command/packet/peer ownership");
            }
            let before = f.firmware.tx_write();
            if !matches!(
                poll(pin!(owner.clear_association()).as_mut()),
                Poll::Ready(Err(_))
            ) || !matches!(
                poll(pin!(owner.deactivate_link()).as_mut()),
                Poll::Ready(Err(_))
            ) || f.firmware.tx_write() != before
            {
                return Err("cancelled association permitted replay or premature teardown");
            }
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_gen2_association_current_qualification_and_policy_each_wait() -> TestResult {
    let result = (|| {
        for stage in 0..7 {
            for revoke in [false, true] {
                let mut f = authenticated_fixture(false)?;
                let owner = f.owner.as_mut().unwrap();
                let source = retained_source(owner);
                let permitted = Cell::new(true);
                {
                    let mut op = pin!(owner.associate_legacy_using(
                        b"net",
                        SecurityMode::Open,
                        || if permitted.get() {
                            Ok(policy())
                        } else {
                            Err("test revoked policy")
                        }
                    ));
                    until(stage, op.as_mut(), &mut f.firmware, false)?;
                    if revoke {
                        source.revoke();
                    } else {
                        permitted.set(false);
                    }
                    // A closing disable still runs without TX permission.
                    if stage == 3 {
                        inject(3, &mut f.firmware, false);
                    }
                    if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                        return Err("association accepted lost current authority");
                    }
                }
                if owner.phase() != Phase::Failed || owner.associated_station().is_some() {
                    return Err("failed association authority reopened or published");
                }
            }
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_gen2_association_bound_aid_rate_status_and_header_validation() -> TestResult {
    let result = (|| {
        for fault in 0..5 {
            let mut f = authenticated_fixture(false)?;
            let owner = f.owner.as_mut().unwrap();
            let mut op =
                pin!(owner.associate_legacy_using(b"net", SecurityMode::Open, || Ok(policy())));
            until(2, op.as_mut(), &mut f.firmware, false)?;
            let mut bad = response(false);
            match fault {
                0 => bad[76] = 0,
                1 => bad[77] = 0,
                2 => bad[74] = 13,
                3 => bad[80] = 0x84,
                _ => bad[79] = 2,
            };
            f.firmware.inject(0xc1, 0, 0x8000, &bad);
            if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                return Err("invalid bound association AID/status/rates/IE accepted");
            }
        }
        let mut f = authenticated_fixture(false)?;
        let owner = f.owner.as_mut().unwrap();
        let mut op =
            pin!(owner.associate_legacy_using(b"net", SecurityMode::Open, || Ok(policy())));
        until(2, op.as_mut(), &mut f.firmware, false)?;
        for (offset, mask) in [(49, 128), (49, 4), (58, 1), (64, 1), (34, 1), (12, 1)] {
            let mut bad = response(false);
            bad[offset] ^= mask;
            f.firmware.inject(0xc1, 0, 0x8000, &bad);
            if !poll(op.as_mut()).is_pending() {
                return Err("foreign/protected/fragmented association response accepted");
            }
        }
        inject(2, &mut f.firmware, false);
        if !poll(op.as_mut()).is_pending() {
            return Err("valid association response failed after ignored foreign frames");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_gen2_association_native_control_faults_remain_terminal() -> TestResult {
    let result = (|| {
        for stage in [0, 3, 4, 5, 6] {
            let mut f = authenticated_fixture(false)?;
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op =
                    pin!(owner.associate_legacy_using(b"net", SecurityMode::Open, || Ok(policy())));
                until(stage, op.as_mut(), &mut f.firmware, false)?;
                let (cmd, group, seq) = match stage {
                    0 => (0x18, 0, 8),
                    3 => (0x18, 0, 9),
                    4 => (0x18, 0, 10),
                    5 => (9, 3, 11),
                    _ => (8, 3, 12),
                };
                f.firmware
                    .inject(cmd, group, seq, if cmd == 0x18 { &[] } else { &[1] });
                if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                    return Err("wrong native association peer/link/MAC receipt accepted");
                }
            }
            if owner.phase() != Phase::Failed || runtime::model::retained(&owner.hardware).1 != 1 {
                return Err("bad receipt released station queue");
            }
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}

fn associated_fixture() -> Result<Fixture, &'static str> {
    let mut f = authenticated_fixture(false)?;
    {
        let mut op = pin!(f.owner.as_mut().unwrap().associate_legacy_using(
            b"net",
            SecurityMode::Open,
            || Ok(policy())
        ));
        until(6, op.as_mut(), &mut f.firmware, false)?;
        inject(6, &mut f.firmware, false);
        if !matches!(poll(op.as_mut()), Poll::Ready(Ok(_))) {
            return Err("native associated prerequisite failed");
        }
    }
    while f.trace.take().is_some() {}
    Ok(f)
}
fn smoke_gen2_association_preflight_requires_actual_auth_security_and_ssid() -> TestResult {
    let result = (|| {
        for fault in 0..5 {
            let mut f = authenticated_fixture(false)?;
            let owner = f.owner.as_mut().unwrap();
            let (ssid, mode) = match fault {
                0 => (b"wrong".as_slice(), SecurityMode::Open),
                1 => (b"net".as_slice(), SecurityMode::Wpa2Psk),
                _ => (b"net".as_slice(), SecurityMode::Open),
            };
            if fault == 2 {
                owner.power.prepared.as_mut().unwrap().mlme.authenticated = None;
            }
            if fault == 3 {
                owner
                    .power
                    .prepared
                    .as_mut()
                    .unwrap()
                    .mlme
                    .authenticated
                    .as_mut()
                    .unwrap()
                    .status
                    .bssid[0] ^= 2;
            }
            if fault == 4 {
                retained_source(owner).revoke();
            }
            let before = f.firmware.tx_write();
            if !matches!(
                poll(pin!(owner.associate_legacy_using(ssid, mode, || Ok(policy()))).as_mut()),
                Poll::Ready(Err(_))
            ) || owner.phase() != Phase::LinkActive
                || f.firmware.tx_write() != before
                || !owner.hardware.idle_tx_binding(23, 0, 15)
            {
                return Err("invalid association preflight changed disabled native owner");
            }
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_gen2_association_close_cancel_fault_and_revocation_are_fenced() -> TestResult {
    let result = (|| {
        for stage in 0..3 {
            for cancel in [false, true] {
                let mut f = associated_fixture()?;
                let owner = f.owner.as_mut().unwrap();
                {
                    let mut close = pin!(owner.clear_association());
                    for step in 0..=stage {
                        if !poll(close.as_mut()).is_pending() {
                            return Err("association close skipped retained wait");
                        }
                        if step < stage {
                            let (cmd, group) = if step == 0 { (8, 3) } else { (0x18, 0) };
                            f.firmware.inject(
                                cmd,
                                group,
                                13 + step,
                                if step == 1 { &[1, 0, 0, 0] } else { &[] },
                            );
                        }
                    }
                    if !cancel {
                        let (cmd, group) = match stage {
                            0 => (8, 3),
                            1 => (0x18, 0),
                            _ => (9, 3),
                        };
                        f.firmware.inject(
                            cmd,
                            group,
                            13 + stage,
                            if stage == 1 { &[] } else { &[1] },
                        );
                        if !matches!(poll(close.as_mut()), Poll::Ready(Err(_))) {
                            return Err("malformed association close receipt accepted");
                        }
                    }
                }
                if owner.phase()
                    != if cancel {
                        Phase::ClearingAssociation
                    } else {
                        Phase::Failed
                    }
                    || runtime::model::retained(&owner.hardware).1 != 1
                    || owner.associated_station().is_some()
                {
                    return Err("uncertain close reopened metadata or released native queue");
                }
                if !matches!(
                    poll(pin!(owner.deactivate_link()).as_mut()),
                    Poll::Ready(Err(_))
                ) {
                    return Err("uncertain association close released active link");
                }
            }
        }
        let mut f = associated_fixture()?;
        let owner = f.owner.as_mut().unwrap();
        retained_source(owner).revoke();
        {
            let mut close = pin!(owner.clear_association());
            for (step, cmd, group) in [(0, 8, 3), (1, 0x18, 0), (2, 9, 3)] {
                if !poll(close.as_mut()).is_pending() {
                    return Err("revoked association close skipped native wait");
                }
                f.firmware.inject(
                    cmd,
                    group,
                    13 + step,
                    if step == 1 { &[1, 0, 0, 0] } else { &[] },
                );
            }
            if poll(close.as_mut()) != Poll::Ready(Ok(())) {
                return Err("qualification revocation prevented safe local close");
            }
        }
        if owner.phase() != Phase::LinkActive
            || owner.associated_station().is_some()
            || runtime::model::retained(&owner.hardware) != (0, 1, 0)
        {
            return Err("revoked local close changed retained queue lifetime");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_native_association_open_wpa2_receipts_and_ordered_close
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_cancel_at_each_wait_retains_exact_owner
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_current_qualification_and_policy_each_wait
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_bound_aid_rate_status_and_header_validation
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_native_control_faults_remain_terminal
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_preflight_requires_actual_auth_security_and_ssid
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_association_close_cancel_fault_and_revocation_are_fenced
);
