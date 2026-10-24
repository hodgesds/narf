use super::*;
use crate::station_security::RawFrame;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
struct Frame {
    bytes: Vec<u8>,
    raw: bool,
}
impl RawFrame for Frame {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        self.raw
    }
}
fn frame(probe: bool, protected: bool) -> Frame {
    let mut bytes = vec![0; 36];
    bytes[0] = if probe { 0x50 } else { 0x80 };
    bytes[4..10].copy_from_slice(if probe { &OWN } else { &[255; 6] });
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes[32..34].copy_from_slice(&100u16.to_le_bytes());
    bytes[34] = if protected { 17 } else { 1 };
    bytes.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    if protected {
        let rsne = RsnIe::wpa2_psk_ccmp().encode_body();
        bytes.extend_from_slice(&[48, rsne.len() as u8]);
        bytes.extend_from_slice(&rsne);
        bytes.extend_from_slice(&[244, 1, 0]);
    }
    Frame { bytes, raw: true }
}
fn success() -> Result<(), &'static str> {
    for probe in [false, true] {
        for protected in [false, true] {
            let input = frame(probe, protected);
            let observed = observe(&input, 1, OWN, Some(-47)).map_err(|_| "observe")?;
            if observed.bss.bssid != AP
                || observed.bss.ssid != b"narf"
                || observed.bss.channel != 1
                || observed.bss.signal_dbm != Some(-47)
                || observed.bss.information_elements != input.bytes[36..]
                || observed.rates != 15
                || observed.basic_rates != 15
            {
                return Err("observed native facts changed");
            }
            let mode = if protected {
                SecurityMode::Wpa2Psk
            } else {
                SecurityMode::Open
            };
            let plan =
                JoinPlan::prepare(&observed.bss, OWN, b"narf", mode).map_err(|_| "shared join")?;
            if plan.phase() != Phase::Prepared
                || observed.ap_rsne.is_some() != protected
                || protected
                    && observed.ap_rsne.as_deref()
                        != Some(RsnIe::wpa2_psk_ccmp().encode_body().as_slice())
                || protected && observed.ap_rsnxe.as_deref() != Some(&[0])
            {
                return Err("observer granted state or changed AP security bodies");
            }
        }
    }
    Ok(())
}
fn negatives() -> Result<(), &'static str> {
    for (index, bit) in [
        (0, 0x10),
        (1, 1),
        (1, 2),
        (1, 4),
        (1, 0x40),
        (1, 0x80),
        (10, 1),
        (16, 4),
        (22, 1),
        (34, 2),
    ] {
        let mut input = frame(false, true);
        input.bytes[index] ^= bit;
        if observe(&input, 1, OWN, None).is_ok() {
            return Err("wrong native management/peer/fragment admitted");
        }
    }
    for (probe, index) in [(false, 4), (true, 5)] {
        let mut input = frame(probe, false);
        input.bytes[index] ^= 2;
        if observe(&input, 1, OWN, None).is_ok() {
            return Err("wrong management recipient admitted");
        }
    }
    let mut input = frame(false, false);
    input.raw = false;
    if observe(&input, 1, OWN, None).is_ok() {
        return Err("modified RX admitted");
    }
    for channel in [0, 6, 36, 255] {
        if observe(&frame(false, false), channel, OWN, None).is_ok() {
            return Err("DS IE replaced retained receive channel");
        }
    }
    for own in [[0; 6], [255; 6], AP] {
        if observe(&frame(false, false), 1, own, None).is_ok() {
            return Err("invalid local identity admitted");
        }
    }
    for bytes in [
        &[0, 1, b'x'][..],
        &[1, 1, 0x82],
        &[50, 1, 2, 50, 1, 4],
        &[3, 1, 1],
        &[48, 0],
        &[244, 0],
        &[221, 3, 1],
    ] {
        let mut input = frame(false, true);
        input.bytes.extend_from_slice(bytes);
        if observe(&input, 1, OWN, None).is_ok() {
            return Err("duplicate/malformed IE accepted");
        }
    }
    let mut input = frame(false, false);
    input.bytes.resize(2085, 0);
    if observe(&input, 1, OWN, None).is_ok() {
        return Err("unbounded management facts accepted");
    }
    Ok(())
}
fn smoke_shared_raw_observer_retains_native_facts_and_original_security() -> TestResult {
    match success() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_shared_raw_observer_rejects_modified_fragments_peers_channels_and_duplicate_ies(
) -> TestResult {
    match negatives() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_raw_observer_retains_native_facts_and_original_security
);
kernel_test_in!(
    "wireless/association",
    smoke_shared_raw_observer_rejects_modified_fragments_peers_channels_and_duplicate_ies
);
