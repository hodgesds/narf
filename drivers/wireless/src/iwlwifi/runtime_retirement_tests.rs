//! Native TVQM-v3 retirement on Qu/AX210/Bz. Raw RAM transport tests exercise
//! descriptor ownership only; they do not grant station, PHY or RF authority.
use super::*;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Transport {
    hw: Option<Hardware>,
    firmware: model::Firmware,
    trace: model::TxTrace,
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(hw) = self.hw.take() {
            // SAFETY: private RAM endpoints only; no future/device-side actor or
            // physical PCI function can access the fixture after this scope.
            unsafe { model::destroy(hw) };
        }
    }
}
fn poll<T>(f: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = f.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
impl Transport {
    fn new(format: rx_rfh::CompletionFormat) -> Self {
        let (mut hw, firmware, trace) = model::station_model_for_format(format);
        model::versions(&mut hw, &[0x17, 5, 3, 0]);
        Self {
            hw: Some(hw),
            firmware,
            trace,
        }
    }
    fn allocate(&mut self) -> Result<u16, &'static str> {
        let mut f = pin!(self.hw.as_mut().unwrap().allocate_tx(0, 0));
        if !poll(f.as_mut()).is_pending() {
            return Err("native queue ADD did not await receipt");
        }
        let p = self.trace.take().ok_or("native queue ADD trace absent")?;
        if p.bytes[7] != 0
            || p.bytes.len() != 44
            || p.bytes[8..12] != [0; 4]
            || p.bytes[12..16] != [1, 0, 0, 0]
        {
            return Err("native queue ADD header/geometry changed");
        }
        let sequence = u16::from_le_bytes([p.bytes[2], p.bytes[3]]);
        self.firmware
            .inject(0x17, 5, sequence, &[1, 1, 0, 0, 254, 0, 0, 0]);
        match poll(f.as_mut()) {
            Poll::Ready(Ok(257)) => Ok(257),
            _ => Err("native queue ADD exact receipt not owned"),
        }
    }
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn formats() -> [rx_rfh::CompletionFormat; 3] {
    [
        rx_rfh::CompletionFormat::Qu,
        rx_rfh::CompletionFormat::Ax210,
        rx_rfh::CompletionFormat::Bz,
    ]
}
fn smoke_iwl_native_queue_remove_requires_exact_id_status_and_reserved_receipt() -> TestResult {
    check(|| {
        for format in formats() {
            for fault in 0..7 {
                let mut t = Transport::new(format);
                let id = t.allocate()?;
                {
                    let mut f = pin!(t.hw.as_mut().unwrap().remove_tx(id, 0, 0));
                    if !poll(f.as_mut()).is_pending() {
                        return Err("queue REMOVE skipped native receipt");
                    }
                    let p = t.trace.take().ok_or("native queue REMOVE trace absent")?;
                    let mut expected = [0; 36];
                    expected[0] = 1;
                    expected[4] = 1;
                    if p.bytes[7] != 0 || p.bytes.get(8..) != Some(expected.as_slice()) {
                        return Err("queue REMOVE native station/TID/mask/header");
                    }
                    let mut receipt = vec![1, 1, 0, 0, 255, 255, 0, 0];
                    match fault {
                        0 => receipt.clear(),
                        1 => receipt[0] = 2,
                        2 => receipt[2] = 1,
                        3 => receipt[6] = 1,
                        4 => {
                            receipt.pop();
                        }
                        5 => receipt.push(0),
                        _ => {}
                    }
                    t.firmware.inject(
                        0x17,
                        5,
                        u16::from_le_bytes([p.bytes[2], p.bytes[3]]),
                        &receipt,
                    );
                    let result = poll(f.as_mut());
                    if fault == 6 {
                        if !matches!(result, Poll::Ready(Ok(()))) {
                            return Err("native REMOVE rejected valid ADD-only write-pointer bits");
                        }
                    } else if !matches!(result, Poll::Ready(Err(_))) {
                        return Err("native REMOVE accepted malformed/foreign/status failure");
                    }
                }
                let retained = model::retained(t.hw.as_ref().unwrap());
                if retained != (0, usize::from(fault != 6), 0) {
                    return Err("queue storage lifetime did not follow exact native REMOVE proof");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_queue_remove_requires_exact_id_status_and_reserved_receipt
);
fn smoke_iwl_native_queue_remove_cancellation_quarantines_until_real_reset() -> TestResult {
    check(|| {
        for format in formats() {
            let mut t = Transport::new(format);
            let id = t.allocate()?;
            let sequence;
            {
                let mut f = pin!(t.hw.as_mut().unwrap().remove_tx(id, 0, 0));
                if !poll(f.as_mut()).is_pending() {
                    return Err("cancel fixture skipped REMOVE publication");
                }
                let p = t.trace.take().ok_or("cancel REMOVE trace absent")?;
                sequence = u16::from_le_bytes([p.bytes[2], p.bytes[3]]);
            }
            let hw = t.hw.as_mut().unwrap();
            if hw.idle_tx_binding(id, 0, 0)
                || model::retained(hw) != (1, 1, 0)
                || hw.enqueue_transmit(id, &[0; 26], 26, None).is_ok()
            {
                return Err("dropped REMOVE waiter reopened packet/DMA owner");
            }
            {
                let mut again = pin!(hw.remove_tx(id, 0, 0));
                if !matches!(poll(again.as_mut()), Poll::Ready(Err(_))) {
                    return Err("cancelled REMOVE was replayed");
                }
            }
            if t.trace.take().is_some() {
                return Err("cancelled REMOVE published a second native producer");
            }
            t.firmware
                .inject(0x17, 5, sequence, &[1, 1, 0, 0, 0, 0, 0, 0]);
            hw.poll()?;
            if hw.idle_tx_binding(id, 0, 0) || model::retained(hw) != (0, 1, 0) {
                return Err("late receipt bypassed lost native owner/retirement validation");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_queue_remove_cancellation_quarantines_until_real_reset
);
fn smoke_iwl_native_queue_remove_foreign_owner_and_pending_packet_are_pre_io() -> TestResult {
    check(|| {
        for format in formats() {
            let mut t = Transport::new(format);
            let id = t.allocate()?;
            for (station, tid) in [(1, 0), (0, 15)] {
                {
                    let mut f = pin!(t.hw.as_mut().unwrap().remove_tx(id, station, tid));
                    if !matches!(poll(f.as_mut()), Poll::Ready(Err(_))) {
                        return Err("foreign station/TID could retire queue");
                    }
                }
                if t.trace.take().is_some() || !t.hw.as_ref().unwrap().idle_tx_binding(id, 0, 0) {
                    return Err("foreign REMOVE changed legitimate queue phase");
                }
            }
            t.hw.as_mut()
                .unwrap()
                .enqueue_transmit(id, &[0; 26], 26, None)?;
            t.trace.take().ok_or("pending native packet absent")?;
            {
                let mut f = pin!(t.hw.as_mut().unwrap().remove_tx(id, 0, 0));
                if !matches!(poll(f.as_mut()), Poll::Ready(Err(_))) {
                    return Err("REMOVE reclaimed a still-owned packet");
                }
            }
            if t.trace.take().is_some() || model::retained(t.hw.as_ref().unwrap()) != (0, 1, 1) {
                return Err("nonterminal native DMA was retired or command emitted");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_queue_remove_foreign_owner_and_pending_packet_are_pre_io
);

fn marker(cookie: u32, baid: u8) -> Vec<u8> {
    let mut b = vec![12, 0, 0, 0, 1, 0, 0, 0];
    b.extend_from_slice(&cookie.to_le_bytes());
    b.extend_from_slice(&u32::from(baid).to_le_bytes());
    b
}
fn smoke_iwl_native_mld_baid_fence_preserves_management_and_waits_for_actual_marker() -> TestResult
{
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let mut t = Transport::new(format);
            {
                let mut f = pin!(t.hw.as_mut().unwrap().synchronize_rx_baid(7));
                if !poll(f.as_mut()).is_pending() {
                    return Err("MLD RX fence skipped native command");
                }
                let p = t.trace.take().ok_or("MLD RX fence trace absent")?;
                if p.bytes[7] != 0
                    || p.bytes[8..]
                        != [
                            0, 0, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0,
                        ]
                {
                    return Err("MLD fence used MVM sync flag, wrong queue/cookie/BAID or header");
                }
                let mut data = vec![0; 64 + 26];
                data[..2].copy_from_slice(&26u16.to_le_bytes());
                data[12] = 3;
                data[64] = 8;
                t.firmware.inject(0xc1, 0, 0x8000, &data);
                let mut management = data.clone();
                management[64] = 0xc0;
                t.firmware.inject(0xc1, 0, 0x8000, &management);
                t.firmware.inject(2, 5, 0, &[]);
                if !poll(f.as_mut()).is_pending() {
                    return Err("command ACK alone retired RX BAID epoch");
                }
                t.firmware.inject(0xff, 5, 0x8000, &marker(0, 7));
                if !poll(f.as_mut()).is_pending() {
                    return Err("stale cookie retired RX BAID epoch");
                }
                t.firmware.inject(0xff, 5, 0x8000, &marker(1, 7));
                match poll(f.as_mut()) {
                    Poll::Ready(Ok(prefix))
                        if prefix.len() == 1 && prefix[0].payload == management => {}
                    _ => return Err("native marker lost management prefix or leaked retired data"),
                }
            }
            {
                let mut f = pin!(t.hw.as_mut().unwrap().synchronize_rx_baid(8));
                if !poll(f.as_mut()).is_pending() {
                    return Err("second proved RX epoch failed");
                }
                let p = t.trace.take().ok_or("second RX epoch trace absent")?;
                if p.bytes[24..28] != [2, 0, 0, 0] {
                    return Err("native RX epoch reused cookie");
                }
                t.firmware.inject(2, 5, 1, &[]);
                t.firmware.inject(0xff, 5, 0x8000, &marker(1, 7));
                t.firmware.inject(0xff, 5, 0x8000, &marker(2, 8));
                if !matches!(poll(f.as_mut()), Poll::Ready(Ok(_))) {
                    return Err("old marker blocked exact current RX epoch");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_mld_baid_fence_preserves_management_and_waits_for_actual_marker
);
fn smoke_iwl_native_mld_baid_fence_cancel_late_marker_never_reopens_owner() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let mut t = Transport::new(format);
            {
                let mut f = pin!(t.hw.as_mut().unwrap().synchronize_rx_baid(3));
                if !poll(f.as_mut()).is_pending() {
                    return Err("cancel RX epoch publication absent");
                }
                t.trace.take().ok_or("cancel RX epoch trace absent")?;
                t.firmware.inject(2, 5, 0, &[]);
                if !poll(f.as_mut()).is_pending() {
                    return Err("RX epoch skipped marker");
                }
            }
            t.firmware.inject(0xff, 5, 0x8000, &marker(1, 3));
            t.hw.as_mut().unwrap().poll()?;
            {
                let mut f = pin!(t.hw.as_mut().unwrap().synchronize_rx_baid(3));
                if !matches!(poll(f.as_mut()), Poll::Ready(Err(_))) {
                    return Err("cancelled RX epoch reconstructed native owner");
                }
            }
            if t.trace.take().is_some() {
                return Err("cancelled RX epoch published duplicate native command");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_mld_baid_fence_cancel_late_marker_never_reopens_owner
);
fn smoke_iwl_native_mld_baid_fence_malformed_marker_or_ack_stays_failed() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            for fault in 0..5 {
                let mut t = Transport::new(format);
                {
                    let mut f = pin!(t.hw.as_mut().unwrap().synchronize_rx_baid(3));
                    if !poll(f.as_mut()).is_pending() {
                        return Err("bad RX epoch publication absent");
                    }
                    t.trace.take().ok_or("bad RX epoch trace absent")?;
                    let ack = if fault == 4 { vec![0] } else { vec![] };
                    t.firmware.inject(2, 5, 0, &ack);
                    let mut b = marker(1, 3);
                    match fault {
                        0 => {
                            b.pop();
                        }
                        1 => b[6] = 1,
                        2 => b[12] = 4,
                        3 => b[4] = 0,
                        _ => {}
                    }
                    t.firmware.inject(0xff, 5, 0x8000, &b);
                    if !matches!(poll(f.as_mut()), Poll::Ready(Err(_))) {
                        return Err("bad native MLD RX proof accepted");
                    }
                }
                if !t.hw.as_ref().unwrap().is_failed() {
                    return Err("malformed RX epoch was recoverable without a hardware stop");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_mld_baid_fence_malformed_marker_or_ack_stays_failed
);

fn empty_marker(cookie: u32) -> [u8; 12] {
    let mut marker = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    marker[8..12].copy_from_slice(&cookie.to_le_bytes());
    marker
}
fn smoke_iwl_native_mld_empty_marker_preserves_copy_time_closed_epoch() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let mut t = Transport::new(format);
            let hw = t.hw.as_mut().unwrap();
            let epoch = hw.close_receive_epoch()?;
            if hw.commit_receive_epoch(epoch).is_ok() {
                return Err("receive generation opened without native marker");
            }
            t.firmware.inject(0xc1, 0, 0x8000, &[0x11]);
            hw.poll()?;
            let original = hw
                .notifications
                .pop_front()
                .ok_or("closed native capture missing")?;
            if original.receive_epoch.is_some() {
                return Err("closed native packet acquired receive authority");
            }
            {
                let mut f = pin!(hw.synchronize_receive_epoch());
                if !poll(f.as_mut()).is_pending() {
                    return Err("EMPTY fence skipped native publication");
                }
                let p = t.trace.take().ok_or("EMPTY native command absent")?;
                let expected = [0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
                if p.bytes.len() != 28
                    || p.bytes[0] != 2
                    || p.bytes[1] != 5
                    || p.bytes[6] != 0
                    || p.bytes.get(8..) != Some(expected.as_slice())
                {
                    return Err("EMPTY native command ID/geometry/cookie");
                }
                t.firmware.inject(2, 5, 0, &[]);
                t.firmware.inject(0xff, 5, 0x8000, &empty_marker(0));
                if !poll(f.as_mut()).is_pending() {
                    return Err("ACK or stale EMPTY marker opened generation");
                }
                t.firmware.inject(0xff, 5, 0x8000, &empty_marker(1));
                t.firmware.inject(0xc1, 0, 0x8000, &[0x22]);
                if !matches!(poll(f.as_mut()),Poll::Ready(Ok(prefix)) if prefix.is_empty()) {
                    return Err("actual EMPTY native marker did not complete");
                }
            }
            hw.commit_receive_epoch(epoch)?;
            let publication = hw
                .receive_publication()
                .ok_or("proved native receive publication absent")?;
            let suffix = hw
                .notifications
                .pop_front()
                .ok_or("same-batch closed suffix absent")?;
            if original.receive_epoch.is_some() || suffix.receive_epoch.is_some() {
                return Err("old original/suffix capture inherited new key generation");
            }
            t.firmware.inject(0xc1, 0, 0x8000, &[0x33]);
            hw.poll()?;
            let current = hw
                .notifications
                .pop_front()
                .ok_or("open native copy absent")?;
            if current.receive_epoch != Some(epoch) {
                return Err("new native copy lost proved generation");
            }
            let successor = hw.close_receive_epoch()?;
            if successor == epoch
                || current.receive_epoch != Some(epoch)
                || publication.current()
                || hw.commit_receive_epoch(successor).is_ok()
            {
                return Err("close rewrote captured epoch/reused old prefix proof");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_mld_empty_marker_preserves_copy_time_closed_epoch
);

fn smoke_iwl_native_mld_empty_fence_cancel_or_bad_proof_never_opens_receive() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            for fault in 0..6 {
                let mut t = Transport::new(format);
                let hw = t.hw.as_mut().unwrap();
                let epoch = hw.close_receive_epoch()?;
                {
                    let mut f = pin!(hw.synchronize_receive_epoch());
                    if !poll(f.as_mut()).is_pending() {
                        return Err("EMPTY failure fixture did not publish");
                    }
                    t.trace.take().ok_or("EMPTY failure command missing")?;
                    let ack = if fault == 4 { vec![0] } else { vec![] };
                    t.firmware.inject(2, 5, 0, &ack);
                    if fault != 5 {
                        let mut marker = empty_marker(1).to_vec();
                        match fault {
                            0 => {
                                marker.pop();
                            }
                            1 => marker[4] = 1,
                            2 => marker[6] = 1,
                            3 => marker.push(0),
                            _ => {}
                        }
                        t.firmware.inject(0xff, 5, 0x8000, &marker);
                        if !matches!(poll(f.as_mut()), Poll::Ready(Err(_))) {
                            return Err("malformed EMPTY fence accepted");
                        }
                    } else if !poll(f.as_mut()).is_pending() {
                        return Err("EMPTY fence did not retain uncertain marker wait");
                    }
                }
                if fault == 5 {
                    t.firmware.inject(0xff, 5, 0x8000, &empty_marker(1));
                    hw.poll()?;
                }
                if hw.commit_receive_epoch(epoch).is_ok() || hw.receive_capture_epoch().is_some() {
                    return Err("failed/cancelled EMPTY fence reopened receive");
                }
                let mut retry = pin!(hw.synchronize_receive_epoch());
                if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) || t.trace.take().is_some()
                {
                    return Err("failed/cancelled EMPTY fence replayed native command");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_mld_empty_fence_cancel_or_bad_proof_never_opens_receive
);

fn smoke_iwl_native_packed_rfh_prefix_overflow_never_evicts_peer_loss_or_opens_epoch() -> TestResult
{
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let mut t = Transport::new(format);
            let hw = t.hw.as_mut().unwrap();
            let epoch = hw.close_receive_epoch()?;
            {
                let mut f = pin!(hw.synchronize_receive_epoch());
                if !poll(f.as_mut()).is_pending() {
                    return Err("overflow EMPTY command absent");
                }
                t.trace.take().ok_or("overflow EMPTY trace missing")?;
                t.firmware.inject(2, 5, 0, &[]);
                let mut deauth = vec![0; 90];
                deauth[..2].copy_from_slice(&26u16.to_le_bytes());
                deauth[12] = 3;
                deauth[42] = 36;
                deauth[64] = 0xc0;
                deauth[68..74].copy_from_slice(&[2; 6]);
                deauth[74..80].copy_from_slice(&[4; 6]);
                deauth[80..86].copy_from_slice(&[4; 6]);
                deauth[88] = 3;
                // Six actual completed RFH buffers carry >256 notifications.
                // The AP loss precedes a later genuine matching EMPTY marker.
                for group in 0..5 {
                    let mut packets = vec![(0xab, 0, 0x8000, &[][..]); 60];
                    if group == 0 {
                        packets[0] = (0xc1, 0, 0x8000, &deauth);
                    }
                    t.firmware.inject_packed(&packets);
                }
                t.firmware.inject(0xff, 5, 0x8000, &empty_marker(1));
                if !matches!(
                    poll(f.as_mut()),
                    Poll::Ready(Err("native Intel notification ownership overflow"))
                ) {
                    return Err("packed native overflow silently discarded a prefix control");
                }
            }
            if !hw.is_failed()
                || hw.commit_receive_epoch(epoch).is_ok()
                || hw.receive_capture_epoch().is_some()
                || hw
                    .notifications
                    .front()
                    .is_none_or(|p| p.header.cmd != 0xc1 || p.payload[64] != 0xc0)
            {
                return Err("overflow marker reopened epoch or evicted original peer loss");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_packed_rfh_prefix_overflow_never_evicts_peer_loss_or_opens_epoch
);
