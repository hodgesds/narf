//! QCA9887 SI EEPROM register model. Register offsets/bits are the Linux
//! `hw.h` values cited in the parent module; the model answers each SI read
//! immediately so no timer is needed.
use super::*;
use crate::ath10k::hw::HwRev;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Si {
    eeprom: Vec<u8>,
    writes: Vec<(u64, u32)>,
    selected: Option<u16>,
    status: u32,
    error_at: Option<u16>,
    gone_at: Option<u16>,
    authorized: bool,
}
impl Si {
    fn new(eeprom: Vec<u8>) -> Self {
        Self {
            eeprom,
            writes: Vec::new(),
            selected: None,
            status: 0,
            error_at: None,
            gone_at: None,
            authorized: true,
        }
    }
}
impl Ath10kMmio for Si {
    fn authorized(&self) -> bool {
        self.authorized
    }
    fn read32(&mut self, offset: u64) -> u32 {
        match offset {
            o if o == SI_BASE + SI_CS => {
                if self.selected.is_some() && self.selected == self.gone_at {
                    return u32::MAX;
                }
                self.status
            }
            o if o == SI_BASE + SI_RX_DATA0 => {
                // Upper bits are not data; only the low byte is extracted.
                0xabcd_ef00 | u32::from(self.eeprom[usize::from(self.selected.unwrap())])
            }
            _ => 0,
        }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.writes.push((offset, value));
        if offset == SI_BASE + SI_TX_DATA0 {
            if value & 0xff00_00ff != 0xa100_00a0 {
                self.selected = None;
                return;
            }
            self.selected = Some((((value >> 8) & 0xff) << 8 | ((value >> 16) & 0xff)) as u16);
        } else if offset == SI_BASE + SI_CS && value == SI_CS_READ_ONE {
            self.status = SI_CS_DONE_INT
                | if self.selected == self.error_at {
                    SI_CS_DONE_ERR
                } else {
                    0
                };
        } else if offset == SI_BASE + SI_CS && value & SI_CS_DONE_INT != 0 {
            self.status = 0;
        }
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    match pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
/// Deterministic image whose 16-bit LE XOR is 0xffff.
pub(in crate::ath10k) fn calibration() -> Vec<u8> {
    let mut data: Vec<u8> = (0..QCA9887_CALIBRATION)
        .map(|i| (i * 7 + 3) as u8)
        .collect();
    let sum = data[..QCA9887_CALIBRATION - 2]
        .chunks_exact(2)
        .fold(0u16, |s, w| s ^ u16::from_le_bytes([w[0], w[1]]));
    let last = (sum ^ 0xffff).to_le_bytes();
    data[QCA9887_CALIBRATION - 2..].copy_from_slice(&last);
    data
}
fn registers() -> Registers {
    HwRev::Qca9887.registers().unwrap()
}

fn smoke_ath10k_qca9887_eeprom_si_sequence_reads_validated_calibration() -> TestResult {
    let image = calibration();
    if !valid(&image) || valid(&image[..QCA9887_CALIBRATION - 1]) {
        return TestResult::Fail("Linux 16-bit XOR calibration checksum");
    }
    let mut si = Si::new(image.clone());
    let Some(Ok(Some(read))) = ready(fetch(&mut si, registers(), QCA9887_CALIBRATION)) else {
        return TestResult::Fail("valid SI EEPROM calibration was not returned");
    };
    // ath10k_pci_enable_eeprom precedes the first SI transfer exactly.
    let enable = [
        (0x4000 + 0x28, 0),
        (0x14000 + 0x28 + 4 * 5, (3 << 11) | (1 << 5)),
        (0x14000 + 0x28 + 4 * 17, (3 << 11) | (1 << 5)),
        (0x14000 + 0x10, 1 << 17),
        (0x10000, 0x000d_00b8),
    ];
    if read != image || si.writes[..5] != enable {
        return TestResult::Fail("SI clock/GPIO/config sequence or byte data differs from Linux");
    }
    // Per byte: TX select (addr lo bits16..23, hi bits8..15), CS start with
    // RX=1/TX=4, then write-one clear of the observed DONE status.
    for address in [0u16, 1, 0x00ff, 0x0100, 0x0843] {
        let at = 5 + 3 * usize::from(address);
        let select =
            0xa100_00a0 | (u32::from(address & 0xff) << 16) | (u32::from(address >> 8) << 8);
        if si.writes[at..at + 3]
            != [
                (0x10008, select),
                (0x10004, 0x114),
                (0x10004, SI_CS_DONE_INT),
            ]
        {
            return TestResult::Fail("SI per-byte select/start/clear sequence differs from Linux");
        }
    }
    if si.writes.len() != 5 + 3 * QCA9887_CALIBRATION {
        return TestResult::Fail("SI EEPROM read touched unexpected registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/eeprom",
    smoke_ath10k_qca9887_eeprom_si_sequence_reads_validated_calibration
);

fn smoke_ath10k_qca9887_eeprom_failures_fall_back_or_stop() -> TestResult {
    let mut bad = calibration();
    bad[100] ^= 1;
    let mut si = Si::new(bad);
    if ready(fetch(&mut si, registers(), QCA9887_CALIBRATION)) != Some(Ok(None)) {
        return TestResult::Fail("checksum-invalid EEPROM was not a Linux fallback");
    }
    let mut si = Si::new(calibration());
    si.error_at = Some(9);
    if ready(fetch(&mut si, registers(), QCA9887_CALIBRATION)) != Some(Ok(None))
        || si.writes.len() != 5 + 3 * 10
    {
        return TestResult::Fail("SI DONE_ERR did not stop at the failing byte with fallback");
    }
    let mut si = Si::new(calibration());
    si.gone_at = Some(3);
    if ready(fetch(&mut si, registers(), QCA9887_CALIBRATION)) != Some(Err(BmiError::DeviceGone)) {
        return TestResult::Fail("absent device was mistaken for an EEPROM fallback");
    }
    let mut si = Si::new(calibration());
    si.authorized = false;
    if ready(fetch(&mut si, registers(), QCA9887_CALIBRATION)) != Some(Err(BmiError::Pci))
        || !si.writes.is_empty()
    {
        return TestResult::Fail("revoked PCI authority reached SI registers");
    }
    let mut si = Si::new(vec![0; 2048]);
    if ready(fetch(&mut si, registers(), 2048)) != Some(Ok(None)) || !si.writes.is_empty() {
        return TestResult::Fail("non-QCA9887 calibration length reached SI registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/eeprom",
    smoke_ath10k_qca9887_eeprom_failures_fall_back_or_stop
);
