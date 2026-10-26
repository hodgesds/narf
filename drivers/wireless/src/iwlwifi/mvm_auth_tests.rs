use super::super::super::{firmware_parser_tests, runtime};
use super::super::{
    link::tests::activate,
    power::tests::{ready_link_fixture, retained_source},
    queue::tests::Fixture,
};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    cell::Cell,
    pin::Pin,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};

const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
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
fn fixture() -> Result<Fixture, &'static str> {
    let mut fixture = ready_link_fixture(false)?;
    activate(&mut fixture, false)?;
    let image = firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&image).unwrap();
    let mut versions = parsed.api.commands.to_vec();
    versions.extend_from_slice(&[0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3]);
    runtime::model::versions(&mut fixture.owner.as_mut().unwrap().hardware, &versions);
    Ok(fixture)
}
pub(in crate::iwlwifi::mvm_boot) fn authenticated_fixture(
    protected: bool,
) -> Result<Fixture, &'static str> {
    let mut f = fixture()?;
    if protected {
        let beacon = &mut f.owner.as_mut().unwrap().beacons[0];
        beacon.capabilities |= 16;
        beacon.privacy = true;
        beacon.information_elements.extend_from_slice(&[
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
        ]);
    }
    {
        let mut op = pin!(f
            .owner
            .as_mut()
            .unwrap()
            .authenticate_open_using(|| Ok(policy())));
        if !poll(op.as_mut()).is_pending() {
            return Err("association prerequisite peer enable");
        }
        f.firmware.inject(0x18, 0, 6, &[1, 0, 0, 0]);
        if !poll(op.as_mut()).is_pending() {
            return Err("association prerequisite native auth TX");
        }
        f.firmware.tx_complete(23, 0x46);
        f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(0));
        if !poll(op.as_mut()).is_pending() {
            return Err("association prerequisite native auth disable");
        }
        f.firmware.inject(0x18, 0, 7, &[1, 0, 0, 0]);
        if !matches!(
            poll(op.as_mut()),
            Poll::Ready(Ok(AuthenticationStatus { status: 0, .. }))
        ) {
            return Err("association prerequisite actual authentication");
        }
    }
    for _ in 0..3 {
        f.trace
            .take()
            .ok_or("association prerequisite native DMA trace")?;
    }
    Ok(f)
}

fn modify(
    trace: &runtime::model::TxTrace,
    sequence: u16,
    disabled: bool,
) -> Result<(), &'static str> {
    let observed = trace.take().ok_or("missing peer TX MODIFY DMA")?;
    let mut expected = [0; 48];
    expected[0] = 1;
    expected[20] = if disabled { 16 } else { 0 };
    expected[24] = 16;
    if observed.queue != 0
        || observed.bytes.len() != 56
        || observed.bytes[..2] != [0x18, 1]
        || observed.bytes[2..4] != sequence.to_le_bytes()
        || observed.bytes[7] != 0
        || observed.bytes[8..] != expected
    {
        return Err("peer enable/disable did not use exact header0/v12 masked MODIFY");
    }
    Ok(())
}
fn auth_rx(status: u16) -> Vec<u8> {
    // Authored RFH API4 + actual IEEE authentication response; no production
    // encoder supplies expected bytes.
    let mut bytes = vec![0; 78];
    bytes[..2].copy_from_slice(&30u16.to_le_bytes());
    bytes[12] = 3;
    bytes[32] = 40;
    bytes[34] = 1;
    bytes[48] = 0xb0;
    bytes[52..58].fill(2);
    bytes[58..64].copy_from_slice(&AP);
    bytes[64..70].copy_from_slice(&AP);
    bytes[74] = 2;
    bytes[76..78].copy_from_slice(&status.to_le_bytes());
    bytes
}
fn tx_wire(trace: &runtime::model::TxTrace) -> Result<(), &'static str> {
    let observed = trace
        .take()
        .ok_or("missing actual Gen2 authentication packet DMA")?;
    let mut expected = vec![0; 54];
    expected[..4].copy_from_slice(&[0x1c, 0, 0x45, 0x17]);
    expected[4] = 30;
    expected[7] = 12;
    expected[8] = 3;
    expected[21] = 0x40;
    expected[24] = 0xb0;
    expected[28..34].copy_from_slice(&AP);
    expected[34..40].fill(2);
    expected[40..46].copy_from_slice(&AP);
    expected[50] = 1;
    if observed.queue != 23 || observed.pointer != 0x46 || observed.bytes != expected {
        return Err(
            "actual authentication DMA differs from v9/legacy rates-v2/one NVM antenna wire",
        );
    }
    Ok(())
}
fn composed(status: u16) -> Result<(), &'static str> {
    let mut f = fixture()?;
    let owner = f.owner.as_mut().unwrap();
    {
        let mut operation = pin!(owner.authenticate_open_using(|| Ok(policy())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("auth did not await peer enable");
        }
        modify(&f.trace, 6, false)?;
        f.firmware.inject(0x18, 0, 6, &[1, 0, 0, 0]);
        if !poll(operation.as_mut()).is_pending() {
            return Err("auth bypassed native packet receipt");
        }
        tx_wire(&f.trace)?;
        // AP's response can precede the native TX notification. Neither alone
        // is a completed authentication exchange.
        let mut foreign = auth_rx(0);
        foreign[58] ^= 2;
        f.firmware.inject(0xc1, 0, 0x8000, &foreign);
        f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(status));
        if !poll(operation.as_mut()).is_pending() {
            return Err("RX alone fabricated a TX receipt");
        }
        f.firmware.tx_complete(23, 0x46);
        if !poll(operation.as_mut()).is_pending() {
            return Err("auth result bypassed peer re-disable");
        }
        modify(&f.trace, 7, true)?;
        f.firmware.inject(0x18, 0, 7, &[1, 0, 0, 0]);
        if poll(operation.as_mut())
            != Poll::Ready(Ok(AuthenticationStatus {
                bssid: AP,
                channel: 1,
                status,
            }))
        {
            return Err("native open authentication receipts not preserved");
        }
    }
    if owner.phase() != Phase::LinkActive
        || !owner.hardware.idle_tx_binding(23, 0, 15)
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("auth result released or enabled a station/packet producer");
    }
    Ok(())
}
fn smoke_gen2_authentication_native_exchange() -> TestResult {
    match composed(0).and_then(|()| composed(13)) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn fences() -> Result<(), &'static str> {
    for stage in 0..4 {
        let mut f = fixture()?;
        let owner = f.owner.as_mut().unwrap();
        {
            let mut operation = pin!(owner.authenticate_open_using(|| Ok(policy())));
            if !poll(operation.as_mut()).is_pending() {
                return Err("auth cancellation missed enable wait");
            }
            if stage > 0 {
                f.firmware.inject(0x18, 0, 6, &[1, 0, 0, 0]);
                if !poll(operation.as_mut()).is_pending() {
                    return Err("auth cancellation missed packet wait");
                }
            }
            if stage > 1 {
                f.firmware.tx_complete(23, 0x46);
                if !poll(operation.as_mut()).is_pending() {
                    return Err("auth cancellation missed RX wait");
                }
            }
            if stage > 2 {
                f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(0));
                if !poll(operation.as_mut()).is_pending() {
                    return Err("auth cancellation missed closing wait");
                }
            }
        }
        let retained = runtime::model::retained(&owner.hardware);
        let expected = match stage {
            0 | 3 => (1, 1, 0),
            1 => (0, 1, 1),
            _ => (0, 1, 0),
        };
        if owner.phase() != Phase::Authenticating || retained != expected {
            return Err("cancelled authentication lost exact pending command/packet ownership");
        }
        let before = f.firmware.tx_write();
        if !matches!(
            poll(pin!(owner.authenticate_open_using(|| Ok(policy()))).as_mut()),
            Poll::Ready(Err(_))
        ) || !matches!(
            poll(pin!(owner.deactivate_link()).as_mut()),
            Poll::Ready(Err(_))
        ) || !matches!(
            poll(pin!(owner.release_management_queue()).as_mut()),
            Poll::Ready(Err(_))
        ) || f.firmware.tx_write() != before
        {
            return Err("cancelled authentication permitted replay/teardown of an uncertain peer");
        }
    }
    Ok(())
}
fn smoke_gen2_authentication_cancellation_retains_native_owner() -> TestResult {
    match fences() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn authority() -> Result<(), &'static str> {
    for stage in 0..4 {
        for revoke in [false, true] {
            let mut f = fixture()?;
            let owner = f.owner.as_mut().unwrap();
            let cap = retained_source(owner);
            let permitted = Cell::new(true);
            {
                let mut operation = pin!(owner.authenticate_open_using(|| if permitted.get() {
                    Ok(policy())
                } else {
                    Err("test live policy revoked")
                }));
                if !poll(operation.as_mut()).is_pending() {
                    return Err("auth authority missed enable wait");
                }
                if stage > 0 {
                    f.firmware.inject(0x18, 0, 6, &[1, 0, 0, 0]);
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("auth authority missed TX wait");
                    }
                }
                if stage > 1 {
                    f.firmware.tx_complete(23, 0x46);
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("auth authority missed RX wait");
                    }
                }
                if stage > 2 {
                    f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(0));
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("auth authority missed closing wait");
                    }
                    // Closing remains allowed; authority is sampled before publication.
                    f.firmware.inject(0x18, 0, 7, &[1, 0, 0, 0]);
                }
                if revoke {
                    cap.revoke();
                } else {
                    permitted.set(false);
                }
                if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                    return Err("lost current authority left auth wait/publication open");
                }
            }
            if owner.phase() != Phase::Failed {
                return Err("auth authority failure was reusable");
            }
        }
    }
    Ok(())
}
fn smoke_gen2_authentication_current_authority_at_each_wait() -> TestResult {
    match authority() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn invalid_receipts() -> Result<(), &'static str> {
    for stage in [0, 1, 3] {
        let mut f = fixture()?;
        let owner = f.owner.as_mut().unwrap();
        {
            let mut operation = pin!(owner.authenticate_open_using(|| Ok(policy())));
            if !poll(operation.as_mut()).is_pending() {
                return Err("bad receipt fixture missing enable");
            }
            f.firmware.inject(
                0x18,
                0,
                6,
                if stage == 0 {
                    &[0, 0, 0, 0]
                } else {
                    &[1, 0, 0, 0]
                },
            );
            if stage > 0 {
                if !poll(operation.as_mut()).is_pending() {
                    return Err("bad receipt fixture missing TX");
                }
                let mut tx = [0; 48];
                tx[0] = 1;
                tx[36] = 23;
                tx[44] = 0x46;
                tx[40] = if stage == 1 { 0x82 } else { 1 };
                f.firmware.inject(0x1c, 0, 0x8000, &tx);
                if stage == 3 {
                    f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(0));
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("bad receipt fixture missing disable");
                    }
                    f.firmware.inject(0x18, 0, 7, &[]);
                }
            }
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("malformed/failed native auth receipt accepted");
            }
        }
        if owner.phase() != Phase::Failed || runtime::model::retained(&owner.hardware).1 != 1 {
            return Err("bad authentication receipt released queue/peer ownership");
        }
    }
    Ok(())
}
fn smoke_gen2_authentication_rejects_failed_native_receipts() -> TestResult {
    match invalid_receipts() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_native_exchange
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_cancellation_retains_native_owner
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_current_authority_at_each_wait
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_rejects_failed_native_receipts
);

fn smoke_gen2_authentication_rate_profile_and_preflight() -> TestResult {
    let result = (|| {
        let mut f = fixture()?;
        let owner = f.owner.as_mut().unwrap();
        for (ies, channel, expected) in [
            (&[1, 1, 0x82][..], 1, 0x4000),
            (&[1, 2, 0x8b, 0x8c][..], 1, 0x4002), // 5.5Mbps below 6Mbps
            (&[1, 2, 11, 0x8c][..], 36, 0x4100),  // ignore non-basic CCK on a non-CCK band
            (&[1, 1, 0x96][..], 14, 0x4003),
        ] {
            if owner.authentication_rate(ies, channel)? != expected {
                return Err("auth rate not minimum observed basic bitrate/NVM antenna");
            }
        }
        if owner.authentication_rate(&[1, 2, 0x8b, 0x8c], 36).is_ok() {
            return Err("5GHz authentication accepted a required CCK basic rate");
        }
        for versions in [
            &[0x1c, 0, 9, 0][..],
            &[0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 4][..],
        ] {
            runtime::model::versions(&mut owner.hardware, versions);
            if owner.authentication_rate(&[1, 1, 0x82], 1).is_ok() {
                return Err("inconsistent firmware rate indicators were accepted");
            }
            let before = f.firmware.tx_write();
            if !matches!(
                poll(pin!(owner.authenticate_open_using(|| Ok(policy()))).as_mut()),
                Poll::Ready(Err(_))
            ) || owner.phase() != Phase::LinkActive
                || f.firmware.tx_write() != before
            {
                return Err(
                    "unsupported authentication profile changed native link/peer ownership",
                );
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_gen2_authentication_filters_foreign_and_malformed_rx() -> TestResult {
    let result = (|| {
        let mut f = fixture()?;
        let owner = f.owner.as_mut().unwrap();
        let mut operation = pin!(owner.authenticate_open_using(|| Ok(policy())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("RX fixture enable wait");
        }
        f.firmware.inject(0x18, 0, 6, &[1, 0, 0, 0]);
        if !poll(operation.as_mut()).is_pending() {
            return Err("RX fixture TX wait");
        }
        f.firmware.tx_complete(23, 0x46);
        if !poll(operation.as_mut()).is_pending() {
            return Err("RX fixture response wait");
        }
        for (offset, mask) in [
            (12, 1),
            (34, 1),
            (48, 1),
            (49, 1),
            (49, 0x80),
            (52, 1),
            (58, 1),
            (64, 1),
            (70, 1),
            (72, 1),
            (74, 1),
        ] {
            let mut bad = auth_rx(0);
            bad[offset] ^= mask;
            f.firmware.inject(0xc1, 0, 0x8000, &bad);
            if !poll(operation.as_mut()).is_pending() {
                return Err("foreign/malformed AP auth response accepted");
            }
        }
        f.firmware.inject(0xc1, 0, 0x8000, &auth_rx(0));
        if !poll(operation.as_mut()).is_pending() {
            return Err("filtered RX skipped peer disable");
        }
        f.firmware.inject(0x18, 0, 7, &[1, 0, 0, 0]);
        if !matches!(poll(operation.as_mut()), Poll::Ready(Ok(_))) {
            return Err("valid RX after malformed frames failed");
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_rate_profile_and_preflight
);
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_authentication_filters_foreign_and_malformed_rx
);
