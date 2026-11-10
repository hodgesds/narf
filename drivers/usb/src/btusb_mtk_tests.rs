//! Wire conversations for the same USB WMT path used by native setup.
use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Replay {
    reads: IrqSafeSpinLock<VecDeque<(UsbRequest, Vec<u8>)>>,
    writes: IrqSafeSpinLock<Vec<(UsbRequest, Vec<u8>)>>,
    delays: IrqSafeSpinLock<Vec<u64>>,
}
impl Replay {
    fn new(reads: Vec<(UsbRequest, Vec<u8>)>) -> Self {
        Self {
            reads: IrqSafeSpinLock::new(reads.into()),
            writes: IrqSafeSpinLock::new(Vec::new()),
            delays: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
impl MtkUsb for Replay {
    async fn control_in<'a>(
        &'a self,
        request: UsbRequest,
        out: &'a mut [u8],
    ) -> Result<usize, MtkError> {
        let (expected, bytes) = self.reads.lock().pop_front().ok_or(MtkError::WmtEvent)?;
        if request != expected || bytes.len() > out.len() {
            return Err(MtkError::WmtEvent);
        }
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    async fn control_out<'a>(
        &'a self,
        request: UsbRequest,
        data: &'a [u8],
    ) -> Result<usize, MtkError> {
        self.writes.lock().push((request, data.to_vec()));
        Ok(data.len())
    }
    async fn delay_us(&self, us: u64) {
        self.delays.lock().push(us);
    }
}
fn response(op: u8, flag: u8) -> (UsbRequest, Vec<u8>) {
    // HCI event length5, WMT length1 (the flag), not total header size5.
    (WMT_REPLY, vec![0xe4, 5, 2, op, 1, 0, flag])
}
fn image() -> Vec<u8> {
    let mut image = vec![0; 800];
    image[44..48].copy_from_slice(&1u32.to_le_bytes());
    image[100..104].copy_from_slice(&200u32.to_le_bytes());
    image[112..116].copy_from_slice(&600u32.to_le_bytes());
    image[200..].fill(0xaa);
    image
}
fn smoke_mtk_usb_alias_identity_and_firmware() -> TestResult {
    use narf_bluetooth::btusb_quirks::{identify, Quirk};
    if identify(0x0e8d, 0x0616) != Some(Quirk::MediaTek) {
        return TestResult::Fail("0616 alias bypassed MediaTek firmware setup");
    }
    let reads = vec![
        (read_request(0x70010200), 0x7922u32.to_le_bytes().to_vec()),
        (read_request(0x80021004), 0u32.to_le_bytes().to_vec()),
        (read_request(0x70010020), 0u32.to_le_bytes().to_vec()),
    ];
    let io = Replay::new(reads);
    if narf_scheduler::block_on_spin(read_identity(&io, 0x0616)).as_deref()
        != Ok("mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin")
        || !io.reads.lock().is_empty()
    {
        return TestResult::Fail("USB ROM identity did not select the MT7922 firmware");
    }
    let io = Replay::new(vec![(
        read_request(0x70010200),
        0x7961u32.to_le_bytes().to_vec(),
    )]);
    if narf_scheduler::block_on_spin(read_identity(&io, 0x0616)) != Err(MtkError::UnsupportedDevice)
        || !io.writes.lock().is_empty()
    {
        return TestResult::Fail("USB alias accepted the wrong chip before firmware access");
    }
    if firmware_name(0x7961, 1, 0x80).as_deref() != Ok("mediatek/BT_RAM_CODE_MT7961_1a_2_hdr.bin")
        || firmware_name(0x7922, 0, 0x80).as_deref()
            != Ok("mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin")
    {
        return TestResult::Fail("ROM version/flavor suffix wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb/mediatek",
    smoke_mtk_usb_alias_identity_and_firmware
);

fn smoke_mtk_usb_patch_then_protocol_enable() -> TestResult {
    let io = Replay::new(vec![
        (WMT_REPLY, Vec::new()),
        response(1, 1),
        response(1, 0),
        response(1, 2),
        response(1, 2),
        response(1, 2),
        response(6, 0),
    ]);
    if narf_scheduler::block_on_spin(download_and_enable(&io, &image())).is_err() {
        return TestResult::Fail("native WMT conversation did not complete");
    }
    if !io.reads.lock().is_empty() || io.delays.lock().as_slice() != [500, 100_000] {
        return TestResult::Fail(
            "empty/progress WMT reply did not follow the USB polling protocol",
        );
    }
    let writes = io.writes.lock();
    if writes.len() != 7 {
        return TestResult::Fail("patch conversation lost a chunk or protocol enable");
    }
    for (i, flag, len) in [
        (0, 0, 53),
        (1, 0, 53),
        (2, 1, 250),
        (3, 2, 250),
        (4, 3, 100),
    ] {
        let (request, bytes) = &writes[i];
        if *request != HCI_COMMAND
            || bytes.len() != len + 8
            || bytes[..5] != [0x6f, 0xfc, (len + 5) as u8, 1, 1]
            || u16::from_le_bytes([bytes[5], bytes[6]]) != len as u16 + 1
            || bytes[7] != flag
        {
            return TestResult::Fail(
                "WMT command framing or section chunk flags diverged from USB protocol",
            );
        }
    }
    if writes[5]
        != (
            UsbRequest {
                rt: 0x5e,
                request: 2,
                value: 0x7401,
                index: 0x1890,
            },
            vec![1, 0, 1, 0],
        )
        || writes[6] != (HCI_COMMAND, vec![0x6f, 0xfc, 6, 1, 6, 2, 0, 0, 1])
    {
        return TestResult::Fail(
            "endpoint reset options and WMT function enable not ordered after patch download",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb/mediatek",
    smoke_mtk_usb_patch_then_protocol_enable
);

fn smoke_mtk_usb_loaded_patch_and_malformed_reply() -> TestResult {
    let io = Replay::new(vec![response(1, 2), response(6, 0)]);
    if narf_scheduler::block_on_spin(download_and_enable(&io, &image())).is_err()
        || io.writes.lock().len() != 3
    {
        return TestResult::Fail("raw DONE flag did not skip patch bytes and enable protocol");
    }
    for bytes in [
        vec![0xe4, 5, 2, 1, 5, 0, 0],
        vec![0xe4, 5, 2, 6, 1, 0, 0],
        vec![0xe4, 5, 1, 1, 1, 0, 0],
    ] {
        let io = Replay::new(vec![(WMT_REPLY, bytes)]);
        if narf_scheduler::block_on_spin(download_and_enable(&io, &image()))
            != Err(MtkError::WmtEvent)
            || io.writes.lock().len() != 1
        {
            return TestResult::Fail("malformed WMT reply allowed further firmware mutation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb/mediatek",
    smoke_mtk_usb_loaded_patch_and_malformed_reply
);

fn smoke_mtk_usb_patch_progress_has_bounded_attempts() -> TestResult {
    let io = Replay::new((0..20).map(|_| response(1, 1)).collect());
    if narf_scheduler::block_on_spin(download_and_enable(&io, &image()))
        != Err(MtkError::PatchStatus(1))
        || io.writes.lock().len() != 20
        || io.delays.lock().len() != 19
    {
        return TestResult::Fail("WMT PROGRESS did not terminate without enabling Bluetooth");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/btusb/mediatek",
    smoke_mtk_usb_patch_progress_has_bounded_attempts
);
