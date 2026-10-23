use super::super::super::{gen2_profile, runtime, rx_rfh, station_api};
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Fixture {
    owner: Option<Owner>,
    firmware: runtime::model::Firmware,
}
impl Fixture {
    fn new() -> Self {
        let (mut hardware, firmware) =
            runtime::model::create_for_format(false, rx_rfh::CompletionFormat::Qu);
        runtime::model::versions(
            &mut hardware,
            &[
                0xd, 1, 15, 0, 0x18, 1, 12, 2, 0xc, 1, 5, 0, 8, 3, 1, 0, 0xd2, 1, 4, 0, 0xd1, 1, 3,
                0, 0xa9, 1, 1, 0, 0xc8, 1, 1, 5,
            ],
        );
        let mut nvm = vec![0; 28 + 110 * 4];
        nvm[12..16].copy_from_slice(&3u32.to_le_bytes());
        nvm[16..20].copy_from_slice(&3u32.to_le_bytes());
        nvm[24..28].copy_from_slice(&1u32.to_le_bytes());
        nvm[28] = 1;
        Self {
            owner: Some(Owner {
                hardware,
                firmware: vec![],
                profile: gen2_profile::select(0xa0f0, 0x351, 0x10c000).unwrap(),
                phase: Phase::Configured,
                mac: Some([2; 6]),
                nvm: Some(station_api::Nvm::parse(4, &nvm).unwrap()),
                beacons: vec![],
                channel: super::super::channel::ChannelContext::new(
                    &super::super::super::firmware_api::FirmwareApi::default(),
                ),
                scan: ScanContext {
                    dqa: false,
                    reduced: true,
                    lar: false,
                    mcc_he: false,
                    multi_mcc: false,
                    mld: true,
                    smart_fifo_offload: false,
                    beacon_filter_v4: true,
                    nvm_lar: false,
                    ready: false,
                    permissions: None,
                },
            }),
            firmware,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // SAFETY: this private RAM/DMA fixture never published to a device.
            unsafe { runtime::model::destroy(owner.hardware) };
        }
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
const PREPARATION: [(u16, u8, u8); 6] = [
    (0, 0xc, 1),
    (1, 8, 3),
    (2, 0xd2, 0),
    (3, 0xd1, 0),
    (4, 9, 3),
    (5, 0xa9, 0),
];
const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
fn policy() -> RegulatoryDomain {
    // Explicit injected deployment-policy fixture. It is passed through the
    // same private admission path used by the signed-policy registry entry;
    // no test mutates or authenticates the global production registry.
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
async fn scan_with_policy(owner: &mut Owner) -> Result<Vec<BssInfo>, &'static str> {
    let domain = policy();
    owner.passive_scan_in_domain(&[1], &domain).await
}
fn beacon() -> Vec<u8> {
    // Literal native48-byte RX_MPDU prefix + Beacon, no production builder.
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[32] = 100;
    frame[34] = 0x11;
    frame.extend_from_slice(&[
        0, 3, b'n', b'e', b't', 1, 1, 0x82, 3, 1, 1, 5, 4, 0, 1, 0, 0, 48, 20, 1, 0, 0, 15, 172, 4,
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
    ]);
    let mut bytes = vec![0; 48];
    bytes[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    bytes[12] = 3;
    bytes[32..35].copy_from_slice(&[50, 60, 1]);
    bytes.extend_from_slice(&frame);
    bytes
}
fn complete(uid: u8, status: u8) -> [u8; 16] {
    let mut b = [0; 16];
    b[0] = uid;
    b[6] = status;
    b
}
fn smoke_iwl_mvm_scan_actual_rfh_completion_before_ack_keeps_original_bss() -> TestResult {
    let mut f = Fixture::new();
    let owner = f.owner.as_mut().unwrap();
    {
        let mut scan = pin!(scan_with_policy(owner));
        if !poll(scan.as_mut()).is_pending() || f.firmware.tx_write() != 1 {
            return TestResult::Fail("MVM scan did not publish actual retained TFH request");
        }
        for (sequence, command, group) in PREPARATION {
            f.firmware.inject(command, group, sequence, &[]);
            if !poll(scan.as_mut()).is_pending() || f.firmware.tx_write() != u32::from(sequence) + 2
            {
                return TestResult::Fail("scan preparation did not retain actual command receipts");
            }
        }
        // Both data and terminal notification may precede the command ACK.
        f.firmware.inject(0xc1, 0, 0x8000, &beacon());
        f.firmware.inject(0xf, 0, 0x8000, &complete(0, 1));
        f.firmware.inject(0xd, 1, 6, &[]);
        let Poll::Ready(Ok(result)) = poll(scan.as_mut()) else {
            return TestResult::Fail("MVM scan lost data/terminal notification while awaiting ACK");
        };
        if result.len() != 1
            || result[0].bssid != AP
            || result[0].ssid != b"net"
            || result[0].channel != 1
            || result[0].frequency_mhz != 2412
            || result[0].rssi != -50
        {
            return TestResult::Fail("native RX48 beacon did not reach actual scan report");
        }
    }
    let original = beacon();
    if owner.phase() != Phase::Configured
        || owner.beacons.len() != 1
        || owner.beacons[0].rsn.as_deref() != Some(&original[103..123])
        || owner.beacons[0].information_elements != original[84..]
    {
        return TestResult::Fail("MVM scan cache changed original AP IEs or published too early");
    }
    let before = f.firmware.tx_write();
    let mut retry = pin!(scan_with_policy(owner));
    if !poll(retry.as_mut()).is_pending() || f.firmware.tx_write() != before + 1 {
        return TestResult::Fail("confirmed terminal scan did not permit native slot reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_actual_rfh_completion_before_ack_keeps_original_bss
);
fn smoke_iwl_mvm_scan_cancel_and_bad_terminal_keep_owner_closed() -> TestResult {
    for bad in [None, Some(complete(1, 1)), Some(complete(0, 2))] {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        {
            let mut scan = pin!(scan_with_policy(owner));
            if !poll(scan.as_mut()).is_pending() {
                return TestResult::Fail("scan completed without firmware");
            }
            if let Some(bad) = bad {
                for (sequence, command, group) in PREPARATION {
                    f.firmware.inject(command, group, sequence, &[]);
                    if !poll(scan.as_mut()).is_pending() {
                        return TestResult::Fail("premature scan preparation result");
                    }
                }
                f.firmware.inject(0xd, 1, 6, &[]);
                f.firmware.inject(0xf, 0, 0x8000, &bad);
                if !matches!(poll(scan.as_mut()), Poll::Ready(Err(_))) {
                    return TestResult::Fail(
                        "foreign/aborted terminal scan notification was accepted",
                    );
                }
            }
        }
        let before = f.firmware.tx_write();
        let mut retry = pin!(scan_with_policy(owner));
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) || f.firmware.tx_write() != before {
            return TestResult::Fail("cancelled/failed scan reused firmware ownership");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_cancel_and_bad_terminal_keep_owner_closed
);
fn smoke_iwl_mvm_scan_native_beacon_provenance_and_ie_bounds() -> TestResult {
    let bytes = beacon();
    if observed_beacon(&bytes, &[1], [2; 6]).is_none() {
        return TestResult::Fail("literal native beacon rejected");
    }
    for (offset, value) in [
        (48 + 1, 1),
        (48 + 1, 4),
        (48 + 1, 0x40),
        (48 + 22, 1),
        (48 + 10, 4),
        (48 + 4, 0),
        (34, 6),
        (12, 2),
        (13, 8),
        (3, 0x40),
        (48 + 36 + 6, 9),
        (48 + 36 + 10, 6),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        if observed_beacon(&bad, &[1], [2; 6]).is_some() {
            return TestResult::Fail("forged native beacon provenance/IE admitted");
        }
    }
    let mut truncated = bytes.clone();
    truncated.push(1);
    let len = truncated.len() - 48;
    truncated[..2].copy_from_slice(&(len as u16).to_le_bytes());
    if observed_beacon(&truncated, &[1], [2; 6]).is_some() {
        return TestResult::Fail("trailing partial IE admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_native_beacon_provenance_and_ie_bounds
);

fn hex_literal(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("fixture hex"),
            };
            nibble(pair[0]) * 16 + nibble(pair[1])
        })
        .collect()
}
fn smoke_iwl_mvm_scan_mac_and_mcc_match_actual_linux_packed_abi() -> TestResult {
    // Generated by the retained oracle compiled from actual local Linux
    // packed structs, independently of every Rust builder under test.
    if idle_mac([2; 6]).as_slice() != hex_literal("00000000010000000500000002020202020200000c00000000000000000000000000000000000000000000000000000000000000")
        || idle_link([2;6]).as_slice() != hex_literal("010000000000000000000000ffffffff020202020202000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        || smart_fifo().as_slice() != hex_literal("03000000001000000020000040420f0040420f0040420f0040420f0040420f0040420f0040420f0040420f0040420f0040420f0090010000a000000090010000a000000090010000a000000090010000a000000090010000a0000000")
        || awake_mac_power().as_slice() != hex_literal("00000000000019000000000000000000000000000000000000000000000000000000000000000000")
        || mcc_query(true).as_slice() != hex_literal("5a5a1000000000000000000000000000000000000000000000000000")
    {
        return TestResult::Fail("native API77 MAC/link/SF/power/MCC differs from Linux ABI");
    }
    for (version, channel) in [(15, "0000000001010100"), (17, "00000040017f0100")] {
        let request = scan_api::passive(version, 0, &[1]).unwrap();
        if request[48..56] != hex_literal(channel) {
            return TestResult::Fail("versioned native channel band/PSD differs from Linux");
        }
    }

    for (version, header, count_offset) in [(3, 16, 12), (4, 20, 16), (8, 24, 20)] {
        let mut literal = vec![0; header + 4];
        literal[count_offset] = 1;
        literal[header] = 1;
        if mcc_permissions(version, &literal) != Ok(vec![1]) {
            return TestResult::Fail("native MCC version/count offsets rejected");
        }
        let mut short = literal.clone();
        short.pop();
        if mcc_permissions(version, &short).is_ok() {
            return TestResult::Fail("short MCC map admitted");
        }
        literal[count_offset] = 111;
        if mcc_permissions(version, &literal).is_ok() {
            return TestResult::Fail("unbounded MCC map admitted");
        }
        literal[count_offset] = 1;
        literal[0] = 2;
        if mcc_permissions(version, &literal).is_ok() {
            return TestResult::Fail("rejected MCC status admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_mac_and_mcc_match_actual_linux_packed_abi
);

fn smoke_iwl_mvm_scan_waits_current_lar_profile_before_scan_publication() -> TestResult {
    for valid_channel in [false, true] {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        owner.scan.lar = true;
        owner.scan.nvm_lar = true;
        owner.scan.mcc_he = true;
        owner.scan.multi_mcc = true;
        let mut future = pin!(scan_with_policy(owner));
        if !poll(future.as_mut()).is_pending() || f.firmware.tx_write() != 1 {
            return TestResult::Fail("current LAR query was not first for native API77 profile");
        }
        let mut mcc = [0; 24];
        mcc[4..6].copy_from_slice(b"SU");
        mcc[16] = 1;
        mcc[20] = u8::from(valid_channel);
        f.firmware.inject(0xc8, 0, 0, &mcc);
        if !poll(future.as_mut()).is_pending() || f.firmware.tx_write() != 2 {
            return TestResult::Fail("scan config preceded current LAR receipt");
        }
        for &(index, command, group) in &PREPARATION {
            f.firmware.inject(command, group, index + 1, &[]);
            let result = poll(future.as_mut());
            if index < 5 {
                if !result.is_pending() || f.firmware.tx_write() != u32::from(index) + 3 {
                    return TestResult::Fail("native MAC/link prerequisite receipt skipped");
                }
            } else if valid_channel {
                if !result.is_pending() || f.firmware.tx_write() != 8 {
                    return TestResult::Fail("passive scan did not follow native prerequisites");
                }
            } else if !matches!(result, Poll::Ready(Err(_))) || f.firmware.tx_write() != 7 {
                return TestResult::Fail("scan published on channel absent from current MCC");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_waits_current_lar_profile_before_scan_publication
);

fn smoke_iwl_mvm_scan_policy_and_profile_reject_before_preparation() -> TestResult {
    for case in 0..11 {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        let mut domain = policy();
        let channels = match case {
            0 => &[][..],
            1 => &[1, 1][..],
            2 => &[6][..],
            _ => &[1][..],
        };
        match case {
            3 => domain.rules.clear(),
            4 => domain.rules[0].freq_start_mhz += 1,
            5 => domain.rules[0].freq_end_mhz -= 1,
            6 => domain.rules[0].max_bandwidth_mhz = 10,
            7 => owner.scan.mld = false,
            8 => owner.scan.reduced = false,
            9 => domain.rules.push(narf_wireless::reg::RegRule {
                freq_start_mhz: 2410,
                freq_end_mhz: 2414,
                max_bandwidth_mhz: 4,
                max_power_dbm: 0,
                flags: narf_wireless::reg::RegFlags::empty(),
            }),
            10 => domain.country_code = *b"us",
            _ => (),
        }
        let mut future = pin!(owner.passive_scan_in_domain(channels, &domain));
        if !matches!(poll(future.as_mut()), Poll::Ready(Err(_))) || f.firmware.tx_write() != 0 {
            return TestResult::Fail("MVM rejected policy/profile performed preparation I/O");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_policy_and_profile_reject_before_preparation
);

fn smoke_iwl_mvm_scan_each_published_prerequisite_cancel_stays_closed() -> TestResult {
    for acknowledged in 0..=PREPARATION.len() {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        let domain = policy();
        {
            let mut future = pin!(owner.passive_scan_in_domain(&[1], &domain));
            if !poll(future.as_mut()).is_pending() {
                return TestResult::Fail("scan prerequisite did not await firmware receipt");
            }
            for &(sequence, command, group) in PREPARATION.iter().take(acknowledged) {
                f.firmware.inject(command, group, sequence, &[]);
                if !poll(future.as_mut()).is_pending() {
                    return TestResult::Fail("scan preparation completed without terminal scan");
                }
            }
        }
        let before = f.firmware.tx_write();
        let mut retry = pin!(owner.passive_scan_in_domain(&[1], &domain));
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) || f.firmware.tx_write() != before {
            return TestResult::Fail("cancelled DQA/config/MAC/scan publication reopened owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_each_published_prerequisite_cancel_stays_closed
);

fn smoke_iwl_mvm_scan_requeries_lar_instead_of_reusing_cached_permissions() -> TestResult {
    let mut f = Fixture::new();
    let owner = f.owner.as_mut().unwrap();
    owner.scan.lar = true;
    owner.scan.nvm_lar = true;
    owner.scan.mcc_he = true;
    owner.scan.ready = true;
    owner.scan.permissions = Some(vec![1]);
    let mut future = pin!(scan_with_policy(owner));
    if !poll(future.as_mut()).is_pending() || f.firmware.tx_write() != 1 {
        return TestResult::Fail("repeated scan did not await fresh regulatory receipt");
    }
    let mut current_mcc = [0; 24];
    current_mcc[16] = 1; // same channel count, newly invalid channel1
    f.firmware.inject(0xc8, 0, 0, &current_mcc);
    if !matches!(
        poll(future.as_mut()),
        Poll::Ready(Err(
            "channel absent from current firmware regulatory profile"
        ))
    ) || f.firmware.tx_write() != 1
    {
        return TestResult::Fail("cached LAR permissions authorized a later scan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_requeries_lar_instead_of_reusing_cached_permissions
);

fn smoke_iwl_mvm_scan_actual_api77_metadata_and_optional_dqa() -> TestResult {
    // Literal installed cc-a0/Qu/QuZ API77 capability/API words (all seven
    // images share these relevant bits). DQA is absent; MLD MAC API is set.
    let api = FirmwareApi {
        capabilities: [0x9def037f, 0xbf7ffaee, 0xdb91eedb, 0x002052ae, 0, 0, 0, 0],
        api_changes: [0xfd9bfffb, 0xfff7ffff, 3, 0, 0, 0, 0, 0],
        ..FirmwareApi::default()
    };
    let profile = ScanContext::new(&api);
    if profile.dqa
        || !profile.mld
        || !profile.reduced
        || !profile.lar
        || !profile.mcc_he
        || !profile.beacon_filter_v4
        || profile.smart_fifo_offload
    {
        return TestResult::Fail("actual API77 metadata cannot select retained MLD scan");
    }
    // A different negotiated profile may retain DQA. Prove the conditional
    // command executes only when advertised, before all remaining receipts.
    let mut fixture = Fixture::new();
    let owner = fixture.owner.as_mut().unwrap();
    owner.scan.dqa = true;
    let mut future = pin!(scan_with_policy(owner));
    if !poll(future.as_mut()).is_pending() || fixture.firmware.tx_write() != 1 {
        return TestResult::Fail("advertised DQA command was not retained");
    }
    fixture.firmware.inject(0, 5, 0, &[]);
    if !poll(future.as_mut()).is_pending() || fixture.firmware.tx_write() != 2 {
        return TestResult::Fail("native scan prerequisites preceded DQA receipt");
    }
    for &(index, command, group) in &PREPARATION {
        fixture.firmware.inject(command, group, index + 1, &[]);
        if !poll(future.as_mut()).is_pending()
            || fixture.firmware.tx_write() != u32::from(index) + 3
        {
            return TestResult::Fail("conditional DQA displaced native MAC/link receipts");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_scan_actual_api77_metadata_and_optional_dqa
);
