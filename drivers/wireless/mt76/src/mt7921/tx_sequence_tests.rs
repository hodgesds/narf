//! Literal native TXS records and independent DMA/firmware/status proofs.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn report(pid: u8, tid: u8, wcid: u16, sequence: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0;40];
    bytes[..4].copy_from_slice(&(1u32 << 27 | 40).to_le_bytes());
    bytes[8..12].copy_from_slice(&(u32::from(tid) << 26 | 1 << 15).to_le_bytes());
    bytes[12..16].copy_from_slice(&(u32::from(sequence) << 20).to_le_bytes());
    bytes[16..20].copy_from_slice(&(u32::from(wcid) << 16).to_le_bytes());
    bytes[20..24].copy_from_slice(&(u32::from(pid) << 24).to_le_bytes());
    bytes
}
fn proofs() -> Result<(), &'static str> {
    for status_first in [false, true] {
        for tid in 0..8 {
            let mut owner = Owner::new();
            owner.arm(tid).map_err(|_| "native PID arm")?;
            let pid = owner
                .pid(tid)
                .map_err(|_| "prepared native PID")?
                .ok_or("prepared PID absent")?;
            if pid != 3 || owner.published(tid) || owner.take(tid) != Ok(None) {
                return Err("sample acquired invented sequence before publication");
            }
            owner.begin(tid, 7).map_err(|_| "native sample token")?;
            let txs = report(pid, tid, 1, 4095);
            if status_first {
                owner
                    .receive(&txs)
                    .map_err(|_| "native status before terminal")?;
            } else {
                owner.terminal(packet_tx::Completion {
                    token: 7,
                    status: 0,
                });
            }
            if owner.take(tid) != Ok(None) {
                return Err("single receipt manufactured a sequence sample");
            }
            if status_first {
                owner.terminal(packet_tx::Completion {
                    token: 7,
                    status: 0,
                });
            } else {
                owner
                    .receive(&txs)
                    .map_err(|_| "native status after terminal")?;
            }
            if owner.take(tid) != Ok(Some(4095)) {
                return Err("native sequence wrap observation");
            }
            owner.arm(tid).map_err(|_| "second sample arm")?;
            if owner.pid(tid) != Ok(Some(4)) {
                return Err("native PID was reused after completion");
            }
            owner.begin(tid, 8).map_err(|_| "second sample token")?;
            owner.terminal(packet_tx::Completion {
                token: 8,
                status: 0,
            });
            owner.receive(&txs).map_err(|_| "late old PID")?;
            if owner.take(tid) != Ok(None) {
                return Err("old status aliased a later sample");
            }
        }
    }
    let mut owner = Owner::new();
    for pid in 3..127 {
        owner.arm(5).map_err(|_| "bounded native PID exhaustion")?;
        if owner.pid(5) != Ok(Some(pid)) {
            return Err("PID high-water skipped/reused");
        }
        owner.begin(5, 1).map_err(|_| "ambiguous published PID")?;
        owner.clear_after_quiescence();
    }
    if owner.arm(5) != Err(Error::EventOverflow) {
        return Err("DMA reinit reused an ambiguous firmware PID");
    }
    owner.firmware_reset();
    for turn in 0..300u16 {
        owner.arm(5).map_err(|_| "exact terminal PID reuse")?;
        let pid = owner
            .pid(5)
            .map_err(|_| "reused PID owner")?
            .ok_or("reused PID absent")?;
        owner.begin(5, 1).map_err(|_| "reused native token")?;
        let bytes = report(pid, 5, 1, turn);
        owner.receive(&bytes).map_err(|_| "terminal native TXS")?;
        owner
            .receive(&bytes)
            .map_err(|_| "idempotent duplicate pre-retirement TXS")?;
        if owner.take(5) != Ok(None) {
            return Err("duplicate TXS replaced native packet retirement");
        }
        owner.terminal(packet_tx::Completion {
            token: 1,
            status: 0,
        });
        if owner.take(5) != Ok(Some(turn)) {
            return Err("exact terminal PID failed to retire/reuse");
        }
    }
    Ok(())
}
fn mt76_sequence_sample_needs_native_txs_and_dual_packet_retirement_with_exact_pid_retirement(
) -> TestResult {
    proofs().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_sequence_sample_needs_native_txs_and_dual_packet_retirement_with_exact_pid_retirement
);
fn invalid() -> Result<(), &'static str> {
    for fault in 0..8 {
        let mut owner = Owner::new();
        owner.arm(3).map_err(|_| "invalid TXS sample arm")?;
        owner.begin(3, 9).map_err(|_| "invalid TXS sample token")?;
        owner.terminal(packet_tx::Completion {
            token: 9,
            status: 0,
        });
        let mut bytes = report(3, 3, 1, 0x123);
        match fault {
            0 => bytes[19] = 1,
            1 => bytes[11] ^= 1 << 2,
            2 => bytes[11] |= 1 << 1,
            3 => bytes[11] |= 1,
            4 => bytes[0] = 39,
            5 => {
                bytes.pop();
            }
            6 => bytes[8..12].copy_from_slice(&((3u32 << 26) | (2 << 23)).to_le_bytes()),
            _ => bytes[10] |= 1,
        }
        let result = owner.receive(&bytes);
        if fault == 7 {
            if result.is_err() || owner.take(3) != Err(Error::Rejected(1)) {
                return Err("failed native TXS accepted as current sequence");
            }
        } else if result != Err(Error::MalformedEvent) || owner.take(3) != Ok(None) {
            return Err("malformed/cross-TID/WCID/aggregate TXS changed sample authority");
        }
    }
    let mut header = [0; packet_tx::HEADER];
    header[28..32].copy_from_slice(&(1u32 << 10 | 0x280000).to_le_bytes());
    request(&mut header, 3).map_err(|_| "native sample descriptor")?;
    if header[20..24] != [3, 4, 0, 0]
        || header[28..32] != [0, 0, 0x28, 0]
        || header[12..16] != [0, 0, 0, 0x10]
    {
        return Err("sample HOST/PID/non-AMSDU/non-BA descriptor mismatch");
    }
    Ok(())
}
fn mt76_sequence_sample_rejects_wrong_native_metadata_and_clears_only_sample_aggregation(
) -> TestResult {
    invalid().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_sequence_sample_rejects_wrong_native_metadata_and_clears_only_sample_aggregation
);

/// `report` with the TXS0 rate word and bandwidth (and optionally failed).
fn rate_report_bytes(pid: u8, wcid: u16, rate: u16, bw: u8, failed: bool) -> Vec<u8> {
    let mut bytes = report(pid, 0, wcid, 0);
    let mut r0 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    r0 |= u32::from(rate) | u32::from(bw) << 29;
    if failed {
        r0 |= 1 << 16;
    }
    bytes[8..12].copy_from_slice(&r0.to_le_bytes());
    bytes
}

/// Linux `mt7921e_tx_prepare_skb` + `mt76_connac2_mac_fill_txs`: the home
/// station's data asks for a TX status at most every HZ/4 on its own PID;
/// the matching report (PID and WCID) gives its rate and bandwidth and
/// counts failures; the PID is reused only after both the report and the
/// frame's retirement, or after a retired frame's status never came; an
/// unpublished reservation is reused; the BA-restart sample is untouched.
fn mt76_tx_status_rate_sampling() -> Result<(), &'static str> {
    let mut owner = Owner::new();
    let ms = 1_000_000;
    let pid = owner.rate_pid(1, 0).ok_or("no first rate sample")?;
    if owner.rate_pid(1, 10 * ms) != Some(pid) {
        return Err("unpublished reservation not reused");
    }
    owner.begin_rate(9);
    if owner.rate_pid(1, 100 * ms).is_some() {
        return Err("second sample while one is outstanding");
    }
    // VHT MCS9 2 SS at 80 MHz.
    let vht = 4 << 6 | 9 | 1 << 10;
    owner
        .receive(&rate_report_bytes(pid, 1, vht, 2, false))
        .map_err(|_| "rate report refused")?;
    let report = owner.rate_report().ok_or("no rate report")?;
    if (report.wcid, report.tx_rate, report.bw, report.failures) != (1, vht, 2, 0) {
        return Err("rate report fields");
    }
    // Another WCID's or PID's report is not this sample's.
    owner
        .receive(&rate_report_bytes(pid, 2, 0, 0, true))
        .map_err(|_| "foreign report")?;
    if owner.rate_report() != Some(report) {
        return Err("foreign report taken");
    }
    owner.terminal(packet_tx::Completion {
        token: 9,
        status: 0,
    });
    if owner.rate_pid(1, 200 * ms).is_some() {
        return Err("sampled before HZ/4");
    }
    let next = owner.rate_pid(1, 260 * ms).ok_or("no sample after HZ/4")?;
    owner.begin_rate(10);
    owner
        .receive(&rate_report_bytes(next, 1, vht, 2, true))
        .map_err(|_| "failed report refused")?;
    let failed = owner.rate_report().ok_or("no report")?;
    if failed.failures != 1 || failed.sequence != report.sequence + 1 {
        return Err("failure count or sequence");
    }
    owner.terminal(packet_tx::Completion {
        token: 10,
        status: 0,
    });
    // A retired frame whose status never comes is given up after 1 s.
    let lost = owner.rate_pid(1, 600 * ms).ok_or("no third sample")?;
    owner.begin_rate(11);
    owner.terminal(packet_tx::Completion {
        token: 11,
        status: 0,
    });
    if owner.rate_pid(1, 900 * ms).is_some() || owner.rate_pid(1, 1700 * ms) == Some(lost) {
        return Err("lost status not given up after a second, or PID reused at once");
    }
    // The BA-restart sample still arms beside a rate sample.
    if owner.arm(0).is_err() || owner.pid(0).ok().flatten().is_none() {
        return Err("BA sample blocked by rate sampling");
    }
    Ok(())
}
fn mt76_tx_status_rate_sampling_test() -> TestResult {
    match mt76_tx_status_rate_sampling() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mt76_tx_status_rate_sampling_test
);
