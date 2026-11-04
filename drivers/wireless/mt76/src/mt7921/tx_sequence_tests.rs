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
