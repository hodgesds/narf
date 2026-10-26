use super::super::super::{firmware_parser_tests, runtime};
use super::super::queue::tests::Fixture;
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context as TaskContext, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};

const BINDING: [u8; 32] = [0x33; 32];
const NAME: &str = "narf-test/intel/mvm-power-v1";
// Explicit test-only qualification values; never used by platform discovery.
const SAR: [[u8; 5]; 2] = [[80, 81, 82, 83, 84], [72, 73, 74, 75, 76]];

fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut TaskContext::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn domain() -> RegulatoryDomain {
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
fn record() -> [u8; RECORD_LEN] {
    let mut bytes = [0; RECORD_LEN];
    bytes[..8].copy_from_slice(&[b'N', b'I', b'P', b'W', 1, 0, 64, 0]);
    bytes[8..40].copy_from_slice(&BINDING);
    bytes[40..46].copy_from_slice(&[2; 6]);
    bytes[46] = 1;
    bytes[48..53].copy_from_slice(&SAR[0]);
    bytes[53..58].copy_from_slice(&SAR[1]);
    bytes[58..60].copy_from_slice(&128i16.to_le_bytes());
    bytes[60..62].copy_from_slice(&16i16.to_le_bytes());
    bytes
}
fn source(bytes: &[u8], signed: bool) -> Result<Asset, &'static str> {
    let (write, read) = narf_firmware::bootstrap_authority();
    crate::firmware_asset::tests::install(&write, NAME, bytes, signed)
        .map_err(|_| "could not install private power qualification")?;
    // Unsigned input is copied only to exercise the owner's independent signer
    // fence. The production entry always requires a signer at load as well.
    crate::firmware_asset::load(&read, NAME, RECORD_LEN + 1, signed)
        .map_err(|_| "could not copy private power qualification")
}
fn copy(source: &Asset) -> Asset {
    Asset {
        bytes: source.bytes.clone(),
        cap: source.cap,
        signer: source.signer,
        digest: source.digest,
    }
}
fn fixture(lar: bool) -> Result<Fixture, &'static str> {
    let bytes = firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&bytes).unwrap();
    if parsed.api.versions(1, REDUCE_TX_POWER) != Some((5, 0))
        || parsed.api.api_changes[1] & (1 << 13) == 0
    {
        return Err("authored MVM table lacks the negotiated native v5 power profile");
    }
    let mut fixture = Fixture::new();
    let owner = fixture.owner.as_mut().unwrap();
    runtime::model::versions(&mut owner.hardware, parsed.api.commands);
    owner.power = Context::new(&parsed.api);
    owner.power.nvm_permissions = Some(vec![0x10b; 110]);
    fixture.prepare_peer()?;
    fixture.prepare_queue()?;
    fixture
        .trace
        .take()
        .ok_or("missing prerequisite queue ADD")?;
    if lar {
        // The shared prerequisite fixture has already acknowledged peer/queue
        // without LAR. Select LAR here so this test's next native publication
        // is the power attempt's fresh MCC query, never an earlier peer query.
        let mut api = FirmwareApi::default();
        api.capabilities[0] = 1 << 1;
        let owner = fixture.owner.as_mut().unwrap();
        owner.scan = super::super::scan::ScanContext::new(&api);
        owner.scan.ready = true;
        owner.scan.nvm_lar = true;
    }
    Ok(fixture)
}

/// Compose actual disabled peer/queue ADD and both signed power receipts for
/// the next native owner. No physical PCI function or global policy is used.
pub(in crate::iwlwifi::mvm_boot) fn ready_link_fixture(lar: bool) -> Result<Fixture, &'static str> {
    let mut fixture = fixture(false)?;
    {
        let owner = fixture.owner.as_mut().unwrap();
        let mut operation =
            pin!(owner.prepare_power_using(source(&record(), true)?, BINDING, || Ok(domain())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("link prerequisite did not await SAR receipt");
        }
        fixture.firmware.inject(REDUCE_TX_POWER, 1, 2, &[]);
        if !poll(operation.as_mut()).is_pending() {
            return Err("link prerequisite did not await link-power receipt");
        }
        fixture.firmware.inject(REDUCE_TX_POWER, 1, 3, &[]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("link prerequisite power receipts failed");
        }
    }
    for _ in 0..2 {
        fixture
            .trace
            .take()
            .ok_or("missing native power prerequisite DMA")?;
    }
    if lar {
        let mut api = FirmwareApi::default();
        api.capabilities[0] = 1 << 1;
        let owner = fixture.owner.as_mut().unwrap();
        owner.scan = super::super::scan::ScanContext::new(&api);
        owner.scan.ready = true;
        owner.scan.nvm_lar = true;
    }
    Ok(fixture)
}
pub(in crate::iwlwifi::mvm_boot) fn retained_source(
    owner: &Owner,
) -> narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read> {
    owner.power.prepared.as_ref().unwrap().source.cap
}
fn mcc(flags: u32) -> Vec<u8> {
    let mut bytes = vec![0; 16 + 110 * 4];
    bytes[12..16].copy_from_slice(&110u32.to_le_bytes());
    for word in bytes[16..].chunks_exact_mut(4) {
        word.copy_from_slice(&flags.to_le_bytes());
    }
    bytes
}
fn composed(lar: bool) -> Result<(), &'static str> {
    let mut fixture = fixture(lar)?;
    let asset = source(&record(), true)?;
    let digest = asset.digest;
    let owner = fixture.owner.as_mut().unwrap();
    let mut sequence = 2;
    {
        let mut operation = pin!(owner.prepare_power_using(asset, BINDING, || Ok(domain())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("power owner did not wait on actual native transport");
        }
        if lar {
            let observed = fixture
                .trace
                .take()
                .ok_or("missing fresh power MCC query")?;
            if observed.bytes[..2] != [0xc8, 1] || observed.bytes[8..10] != *b"ZZ" {
                return Err("power owner reused stale MCC permission without a native query");
            }
            // MCC/LAR requires ACTIVE and 20MHz, but not the NVM-only IBSS bit.
            fixture.firmware.inject(0xc8, 1, sequence, &mcc(0x109));
            sequence += 1;
            if !poll(operation.as_mut()).is_pending() {
                return Err("fresh firmware MCC did not lead to native SAR programming");
            }
        }
        // Borrow only the independent trace while the future owns the Owner.
        native_trace(&fixture.trace, 2, sequence, 0)?;
        fixture.firmware.inject(REDUCE_TX_POWER, 1, sequence, &[]);
        sequence += 1;
        if !poll(operation.as_mut()).is_pending() {
            return Err("SAR receipt bypassed distinct host link-power programming");
        }
        native_trace(&fixture.trace, 0, sequence, 64)?;
        fixture.firmware.inject(REDUCE_TX_POWER, 1, sequence, &[]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("native v5 power receipts did not complete retained preparation");
        }
    }
    let owner = fixture.owner.as_mut().unwrap();
    if owner.prepared_transmit_power()
        != Some(PowerStatus {
            channel: 1,
            conducted_eighth_dbm: 64,
            qualification_digest: digest,
        })
        || owner.prepared_management_queue() != Some(23)
        || owner.prepared_ap_peer().is_none()
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("power metadata lost the disabled peer, retained queue or exact ceiling");
    }
    let before = fixture.firmware.tx_write();
    {
        let mut removal = pin!(owner.release_management_queue());
        if !matches!(poll(removal.as_mut()), Poll::Ready(Err(_))) {
            return Err("queue removal bypassed retained power admission");
        }
    }
    owner.release_transmit_power()?;
    if owner.phase() != Phase::ManagementQueuePrepared
        || owner.prepared_transmit_power().is_some()
        || fixture.firmware.tx_write() != before
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("forgetting power admission sent a permissive command or released queue DMA");
    }
    {
        let mut removal = pin!(owner.release_management_queue());
        if !poll(removal.as_mut()).is_pending() {
            return Err("released power admission did not permit receipt-fenced queue retirement");
        }
        let mut receipt = [0; 8];
        receipt[..2].copy_from_slice(&23u16.to_le_bytes());
        fixture.firmware.inject(0x17, 5, sequence + 1, &receipt);
        if poll(removal.as_mut()) != Poll::Ready(Ok(())) {
            return Err("power continuation changed the native eight-byte queue REMOVE contract");
        }
    }
    if owner.phase() != Phase::PeerPrepared
        || runtime::model::retained(&owner.hardware) != (0, 0, 0)
    {
        return Err("power/queue ordered retirement lost its remaining disabled peer");
    }
    Ok(())
}

// Separate trace input avoids reborrowing the Owner held by the waiting future.
fn native_trace(
    trace: &runtime::model::TxTrace,
    mode: u8,
    sequence: u16,
    power: i16,
) -> Result<(), &'static str> {
    let observed = trace.take().ok_or("missing native power command DMA")?;
    let mut expected = [0; 44];
    expected[0] = mode;
    if mode == 2 {
        expected[16..36].copy_from_slice(&[
            80, 0, 81, 0, 82, 0, 83, 0, 84, 0, 72, 0, 73, 0, 74, 0, 75, 0, 76, 0,
        ]);
    } else {
        expected[8..10].copy_from_slice(&power.to_le_bytes());
    }
    if observed.queue != 0
        || observed.bytes.len() != 52
        || observed.bytes[..2] != [REDUCE_TX_POWER, 1]
        || observed.bytes[2..4] != sequence.to_le_bytes()
        || observed.bytes[7] != 0
        || observed.bytes[8..] != expected
        || observed.doorbell != u32::from(observed.pointer)
    {
        return Err("native power DMA differs from independent Linux-C wire fixture");
    }
    Ok(())
}
fn smoke_iwl_mvm_power_actual_api77_native_sar_link_and_fresh_mcc() -> TestResult {
    for lar in [false, true] {
        if let Err(error) = composed(lar) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_actual_api77_native_sar_link_and_fresh_mcc
);

fn cancellation(stage: u8) -> Result<(), &'static str> {
    let mut fixture = fixture(stage == 0)?;
    let asset = source(&record(), true)?;
    let cap = asset.cap;
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut operation = pin!(owner.prepare_power_using(asset, BINDING, || Ok(domain())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("power cancellation fixture did not publish");
        }
        if stage == 2 {
            fixture.firmware.inject(REDUCE_TX_POWER, 1, 2, &[]);
            if !poll(operation.as_mut()).is_pending() {
                return Err("power cancellation fixture did not reach link programming");
            }
        }
    }
    if owner.phase() != Phase::PreparingTransmitPower
        || owner.prepared_transmit_power().is_some()
        || owner
            .power
            .prepared
            .as_ref()
            .map(|p| p.source.bytes.as_slice())
            != Some(&record()[..])
        || runtime::model::retained(&owner.hardware) != (1, 1, 0)
        || owner.release_transmit_power().is_ok()
    {
        return Err("cancelled power preparation lost command, qualification or queue ownership");
    }
    if stage == 0 {
        fixture.firmware.inject(0xc8, 1, 2, &mcc(0x109));
    } else {
        fixture
            .firmware
            .inject(REDUCE_TX_POWER, 1, if stage == 1 { 2 } else { 3 }, &[]);
    }
    let before = fixture.firmware.tx_write();
    {
        let mut retry =
            pin!(owner.prepare_power_using(source(&record(), true)?, BINDING, || Ok(domain())));
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
            return Err("late power receipt reopened cancelled preparation");
        }
    }
    {
        let mut removal = pin!(owner.release_management_queue());
        if !matches!(poll(removal.as_mut()), Poll::Ready(Err(_))) {
            return Err("cancelled power transaction allowed queue identity reuse");
        }
    }
    if fixture.firmware.tx_write() != before || cap.invoke(narf_capabilities::NoopOp).is_err() {
        return Err("cancelled power retry published IO or discarded its authority");
    }
    Ok(())
}
fn smoke_iwl_mvm_power_cancel_at_each_native_boundary_retains_all_owners() -> TestResult {
    for stage in 0..3 {
        if let Err(error) = cancellation(stage) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_cancel_at_each_native_boundary_retains_all_owners
);

fn revoked(stage: u8) -> Result<(), &'static str> {
    let mut fixture = fixture(false)?;
    let asset = source(&record(), true)?;
    let cap = asset.cap;
    let owner = fixture.owner.as_mut().unwrap();
    if stage == 0 {
        cap.revoke();
    }
    {
        let mut operation = pin!(owner.prepare_power_using(asset, BINDING, || Ok(domain())));
        if stage == 0 {
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("revoked qualification published SAR DMA");
            }
        } else {
            if !poll(operation.as_mut()).is_pending() {
                return Err("revocation fixture did not wait on SAR");
            }
            fixture.firmware.inject(REDUCE_TX_POWER, 1, 2, &[]);
            if stage == 2 {
                if !poll(operation.as_mut()).is_pending() {
                    return Err("revocation fixture did not wait on link power");
                }
                fixture.firmware.inject(REDUCE_TX_POWER, 1, 3, &[]);
            }
            cap.revoke();
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err(
                    "revocation between native receipts published completed power admission",
                );
            }
        }
    }
    if owner.prepared_transmit_power().is_some()
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
        || owner.phase()
            != if stage == 0 {
                Phase::ManagementQueuePrepared
            } else {
                Phase::Failed
            }
        || fixture.firmware.tx_write() != if stage == 0 { 2 } else { u32::from(stage) + 2 }
    {
        return Err("revoked qualification released queue or programmed another command");
    }
    Ok(())
}
fn smoke_iwl_mvm_power_signed_source_revocation_fences_publication_and_completion() -> TestResult {
    for stage in 0..3 {
        if let Err(error) = revoked(stage) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_signed_source_revocation_fences_publication_and_completion
);

fn policy_changes(after_link: bool) -> Result<(), &'static str> {
    let mut fixture = fixture(false)?;
    let asset = source(&record(), true)?;
    let owner = fixture.owner.as_mut().unwrap();
    let mut calls = 0;
    {
        let mut operation = pin!(owner.prepare_power_using(asset, BINDING, || {
            calls += 1;
            let mut current = domain();
            if calls >= if after_link { 4 } else { 3 } {
                current.rules[0].max_power_dbm = 4;
            }
            Ok(current)
        }));
        if !poll(operation.as_mut()).is_pending() {
            return Err("power policy fixture did not reach SAR");
        }
        native_trace(&fixture.trace, 2, 2, 0)?;
        fixture.firmware.inject(REDUCE_TX_POWER, 1, 2, &[]);
        if !poll(operation.as_mut()).is_pending() {
            return Err("power policy fixture did not reach link command");
        }
        native_trace(&fixture.trace, 0, 3, if after_link { 64 } else { 16 })?;
        fixture.firmware.inject(REDUCE_TX_POWER, 1, 3, &[]);
        let result = poll(operation.as_mut());
        if if after_link {
            !matches!(result, Poll::Ready(Err(_)))
        } else {
            result != Poll::Ready(Ok(()))
        } {
            return Err("tightened policy was not enforced at the correct native boundary");
        }
    }
    if after_link {
        if owner.phase() != Phase::Failed || owner.prepared_transmit_power().is_some() {
            return Err("policy tighter than acknowledged link power published admission");
        }
    } else if owner
        .prepared_transmit_power()
        .map(|p| p.conducted_eighth_dbm)
        != Some(16)
    {
        return Err("link programming ignored current host policy minus certified radiated gain");
    }
    Ok(())
}
fn smoke_iwl_mvm_power_resamples_host_ceiling_before_link_and_final_publication() -> TestResult {
    for after_link in [false, true] {
        if let Err(error) = policy_changes(after_link) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_resamples_host_ceiling_before_link_and_final_publication
);

fn preflight() -> Result<(), &'static str> {
    let good = source(&record(), true)?;
    for case in 0..22 {
        let mut fixture = fixture(false)?;
        let owner = fixture.owner.as_mut().unwrap();
        let mut asset = copy(&good);
        let mut host = domain();
        match case {
            0 => asset.signer = None,
            1 => asset.bytes[0] ^= 1,
            2 => asset.bytes[4] = 2,
            3 => asset.bytes[6] = 63,
            4 => asset.bytes[8] ^= 1,
            5 => asset.bytes[40] ^= 2,
            6 => asset.bytes[46] = 0,
            7 => asset.bytes[47] = 1,
            8 => asset.bytes[62] = 1,
            9 => asset.bytes[58..60].copy_from_slice(&1017i16.to_le_bytes()),
            10 => asset.bytes[60..62].copy_from_slice(&(-1i16).to_le_bytes()),
            11 => {
                asset.bytes.pop();
            }
            12 => asset.bytes.push(0),
            13 => owner.power.reduced_v5 = false,
            14 => runtime::model::versions(&mut owner.hardware, &[REDUCE_TX_POWER, 1, 8, 0]),
            15 => owner.power.nvm_permissions = None,
            16 => host.country_code = *b"00",
            17 => host.rules.clear(),
            18 => host.rules[0].flags = RegFlags::NO_IR,
            19 => host.rules[0].max_bandwidth_mhz = 10,
            20 => host.rules[0].flags = RegFlags::DFS,
            21 => host.rules.push(RegRule {
                freq_start_mhz: 2403,
                freq_end_mhz: 2404,
                flags: RegFlags::NO_IR,
                ..host.rules[0]
            }),
            _ => unreachable!(),
        }
        {
            let mut operation =
                pin!(owner.prepare_power_using(asset, BINDING, || Ok(host.clone())));
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err(
                    "unqualified/mismatched power input or restrictive host policy published DMA",
                );
            }
        }
        if fixture.firmware.tx_write() != 2
            || owner.phase() != Phase::ManagementQueuePrepared
            || owner.power.prepared.is_some()
            || runtime::model::retained(&owner.hardware) != (0, 1, 0)
        {
            return Err("power preflight error changed retained queue or published a command");
        }
    }
    let (write, read) = narf_firmware::bootstrap_authority();
    match crate::firmware_asset::tests::install(&write, NAME, &record(), false) {
        Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
        Ok(()) => {
            let unsigned = crate::firmware_asset::load(&read, NAME, RECORD_LEN, false)
                .map_err(|_| "could not copy developer-build unsigned qualification")?;
            if unsigned.signer.is_some() || parse(unsigned, BINDING, [2; 6], 1).is_ok() {
                return Err("actual unsigned registry input admitted platform power");
            }
        }
        Err(_) => return Err("unexpected registry unsigned qualification failure"),
    }
    let requested = request(BINDING, [2, 3, 4, 5, 6, 7], Emission::Legacy);
    if requested.name != "iwlwifi/mvm-api77-power-v1-020304050607.bin"
        || requested.binding != BINDING
    {
        return Err("qualification provisioning request does not expose exact bound identity");
    }
    Ok(())
}
fn smoke_iwl_mvm_power_requires_signed_exact_platform_and_host_no_ir_intersection() -> TestResult {
    preflight().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_requires_signed_exact_platform_and_host_no_ir_intersection
);

fn firmware_policy() -> Result<(), &'static str> {
    let source = source(&record(), true)?;
    for lar in [false, true] {
        for flags in [0, 1, 0x101, 0x10b | (1 << 4), 0x10b & !(1 << 8), 0x109] {
            // LAR deliberately ignores the NVM-only IBSS bit; covered positive
            // by composed(). Non-LAR must reject it because that maps to NO_IR.
            if lar && flags == 0x109 {
                continue;
            }
            let mut fixture = fixture(lar)?;
            let owner = fixture.owner.as_mut().unwrap();
            owner.power.nvm_permissions.as_mut().unwrap()[0] = flags;
            {
                let mut operation =
                    pin!(owner.prepare_power_using(copy(&source), BINDING, || Ok(domain())));
                if lar {
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("power firmware-policy fixture did not refresh MCC");
                    }
                    fixture.firmware.inject(0xc8, 1, 2, &mcc(flags));
                }
                if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                    return Err("firmware receive-only/DFS/width policy admitted SAR programming");
                }
            }
            if owner.prepared_transmit_power().is_some()
                || runtime::model::retained(&owner.hardware) != (0, 1, 0)
                || fixture.firmware.tx_write() != if lar { 3 } else { 2 }
            {
                return Err("firmware prohibition published power DMA or released retained queue");
            }
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_power_intersects_actual_nvm_and_fresh_mcc_transmit_flags() -> TestResult {
    firmware_policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_intersects_actual_nvm_and_fresh_mcc_transmit_flags
);

fn malformed() -> Result<(), &'static str> {
    let source = source(&record(), true)?;
    for link in [false, true] {
        for case in 0..4 {
            let mut fixture = fixture(false)?;
            let owner = fixture.owner.as_mut().unwrap();
            {
                let mut operation =
                    pin!(owner.prepare_power_using(copy(&source), BINDING, || Ok(domain())));
                if !poll(operation.as_mut()).is_pending() {
                    return Err("power malformed fixture did not reach SAR");
                }
                if link {
                    fixture.firmware.inject(REDUCE_TX_POWER, 1, 2, &[]);
                    if !poll(operation.as_mut()).is_pending() {
                        return Err("power malformed fixture did not reach link command");
                    }
                }
                let sequence = if link { 3 } else { 2 };
                fixture.firmware.inject(
                    if case == 1 { 0x9e } else { REDUCE_TX_POWER },
                    if case == 2 { 2 } else { 1 },
                    if case == 3 { sequence + 1 } else { sequence },
                    if case == 0 { &[1, 0, 0, 0] } else { &[] },
                );
                if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                    return Err(
                        "malformed or foreign power receipt completed native power admission",
                    );
                }
            }
            if owner.phase() != Phase::Failed
                || owner.prepared_transmit_power().is_some()
                || owner.power.prepared.is_none()
                || runtime::model::retained(&owner.hardware).1 != 1
            {
                return Err("bad power receipt released retained qualification or queue DMA");
            }
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_power_native_receipts_are_correlated_and_extent_checked() -> TestResult {
    malformed().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_power_native_receipts_are_correlated_and_extent_checked
);
