use super::*;
use crate::rtw89::{
    power::Io,
    scheduler_mailbox::{Interface, Mailbox, State},
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    bytes: Vec<u8>,
    response: [u32; 4],
    authority: Cap<BusDeviceCap, Write>,
    hash: u64,
    count: u32,
    operations: usize,
    now: u64,
    closed: bool,
    hold: bool,
    pending: bool,
    busy: bool,
    stale_late: bool,
    no_consume: bool,
    ignore_clear: bool,
    revoke_delay: bool,
    close_delay: bool,
    oversleep: bool,
    requested: bool,
}
impl Model {
    fn new(seed: u8, response: [u32; 4]) -> Self {
        let (index, generation) = object_table::register(CapKind::BusDevice);
        // SAFETY: fresh exact inert BusDevice fixture object with Write rights.
        let authority = unsafe {
            Cap::mint(CapSlot::new(
                generation,
                index,
                Write::BITS,
                CapKind::BusDevice as u32,
            ))
        };
        let mut bytes = vec![seed; 65536];
        bytes[0x8160] = 0;
        bytes[0x8164] = 0;
        Self {
            bytes,
            response,
            authority,
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            now: 0,
            closed: false,
            hold: false,
            pending: false,
            busy: false,
            stale_late: false,
            no_consume: false,
            ignore_clear: false,
            revoke_delay: false,
            close_delay: false,
            oversleep: false,
            requested: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        self.operations += 1;
        crate::rtw88::pci_park::invoke(&self.authority, || ()).map_err(|_| Error::Access)
    }
    fn word(&self, a: usize) -> u32 {
        u32::from_le_bytes(self.bytes[a..a + 4].try_into().unwrap())
    }
    fn write(&mut self, a: u32, bytes: &[u8]) -> Result<(), Error> {
        self.access()?;
        self.count += 1;
        let mut value = [0; 4];
        value[..bytes.len()].copy_from_slice(bytes);
        for word in [bytes.len() as u32, a, u32::from_le_bytes(value)] {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
        if !(self.ignore_clear && a == 0x8164 && bytes == [0]) {
            self.bytes[a as usize..a as usize + bytes.len()].copy_from_slice(bytes);
        }
        Ok(())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.access()?;
        Ok(u16::from_le_bytes(
            self.bytes[a as usize..a as usize + 2].try_into().unwrap(),
        ))
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        Ok(self.word(a as usize))
    }
    fn write8(&mut self, a: u32, value: u8) -> Result<(), Error> {
        self.write(a, &[value])?;
        if a == 0x8160 && value == 1 {
            self.requested = true;
            if !self.hold {
                if !self.no_consume {
                    self.bytes[a as usize] = 0;
                }
                self.bytes[0x8164] = 1;
                if self.word(0x8140) & 127 == 3 {
                    for (index, word) in self.response.iter().enumerate() {
                        self.bytes[0x8150 + index * 4..0x8154 + index * 4]
                            .copy_from_slice(&word.to_le_bytes());
                    }
                } else {
                    self.bytes[0x8150..0x8154].copy_from_slice(&0x204u32.to_le_bytes());
                    let enable = self.bytes[0x8142..0x8144].to_vec();
                    self.bytes[0xc348..0xc34a].copy_from_slice(&enable);
                }
            }
        }
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.write(a, &v.to_le_bytes())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.write(a, &v.to_le_bytes())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += if self.oversleep { us.max(500_000) } else { us };
        if self.busy && !self.hold {
            self.bytes[0x8160] = 0;
        }
        if self.stale_late {
            self.bytes[0x8164] = 1;
        }
        if self.revoke_delay {
            self.authority.revoke();
        }
        if self.close_delay {
            self.closed = true;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Terminal);
        }
        crate::rtw88::pci_park::invoke(&self.authority, || ()).map_err(|_| Error::Access)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw8852b_firmware_phycap_and_shared_mailbox_match_original_linux() -> TestResult {
    for &(seed, words, expected, count, hash) in CASES {
        let mut model = Model::new(seed, words);
        let mut mailbox = Mailbox::default();
        let receipt = match ready(mailbox.phycap(&mut model)) {
            Some(Ok(value)) => value,
            _ => return TestResult::Fail("source PHY_CAP query failed"),
        };
        if receipt.words() != words
            || [
                receipt.tx_nss(),
                receipt.rx_nss(),
                receipt.tx_paths(),
                receipt.rx_paths(),
                u8::from(receipt.tx_diversity()),
            ] != expected
            || model.word(0x8140) != 0x103
            || !model.requested
        {
            return TestResult::Fail(
                "AX PHY_CAP part0 header/decoded NSS/antenna/diversity differs from original C",
            );
        }
        let admits = matches!(words[1] as u8, 0 | 2)
            && matches!((words[0] >> 16) as u8, 0 | 2)
            && matches!((words[3] >> 8) as u8, 0 | 2)
            && matches!((words[3] >> 16) as u8, 0 | 2);
        if receipt.initial_profile().is_ok() != admits {
            return TestResult::Fail("initial full RF profile admitted reserved/1NSS/RF-B/path-diversity firmware topology");
        }
        if ready(mailbox.scheduler(&mut model, 0)) != Some(Ok(()))
            || mailbox.state() != State::Idle
            || model.count != count
            || model.hash != hash
            || model.bytes[0x1f5] != 0x22
        {
            return TestResult::Fail(
                "PHY_CAP did not retain source shared register-mailbox counters/ownership",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852b_firmware_phycap_and_shared_mailbox_match_original_linux
);

fn smoke_rtw8852b_phycap_fresh_full_reply_consumption_and_current_epoch_required() -> TestResult {
    let valid = [0x04020403, 0x5a030302, 1, 0x03020200];
    for bad in [
        [valid[0] ^ 1, valid[1], valid[2], valid[3]],
        [valid[0] & !0xf00 | 0x300, valid[1], valid[2], valid[3]],
        [u32::MAX; 4],
    ] {
        let mut model = Model::new(0, bad);
        let mut mailbox = Mailbox::default();
        if !matches!(ready(mailbox.phycap(&mut model)), Some(Err(Error::Access)))
            || mailbox.state() != State::Pending
        {
            return TestResult::Fail(
                "foreign/truncated/allones PHY_CAP fabricated a capability receipt",
            );
        }
    }
    for scenario in 0..8 {
        let mut model = Model::new(0, valid);
        let mut mailbox = Mailbox::default();
        match scenario {
            0 => model.bytes[0x8164] = 1,
            1 => {
                model.bytes[0x8160] = 1;
                model.busy = true;
                model.stale_late = true;
            }
            2 => model.no_consume = true,
            3 => model.ignore_clear = true,
            4 => model.authority.revoke(),
            5 => model.closed = true,
            6 => {
                model.bytes[0x8160] = 1;
                model.busy = true;
                model.revoke_delay = true;
            }
            _ => {
                model.bytes[0x8160] = 1;
                model.busy = true;
                model.close_delay = true;
            }
        }
        if !matches!(ready(mailbox.phycap(&mut model)), Some(Err(_)))
            || mailbox.state() != State::Pending
            || (matches!(scenario, 0 | 1 | 4 | 5 | 6 | 7) && model.requested)
        {
            return TestResult::Fail(
                "stale/unconsumed/uncleared/revoked/closed mailbox earned PHY_CAP",
            );
        }
        let operations = model.operations;
        if !matches!(
            ready(mailbox.phycap(&mut model)),
            Some(Err(Error::Terminal))
        ) || operations != model.operations
        {
            return TestResult::Fail("uncertain PHY_CAP register mailbox replayed");
        }
    }
    let first = Receipt::decode(valid).unwrap();
    let mut other = valid;
    other[2] ^= 1;
    if first.fingerprint() == Receipt::decode(other).unwrap().fingerprint() {
        return TestResult::Fail("PHY capability board binding omitted actual words");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852b_phycap_fresh_full_reply_consumption_and_current_epoch_required
);

fn smoke_rtw8852b_phycap_wait_timeout_and_cancellation_keep_mailbox_terminal() -> TestResult {
    let valid = [0x04020403, 0x5a030302, 1, 0x03020200];
    for before_trigger in [false, true] {
        let mut model = Model::new(0, valid);
        model.hold = true;
        model.oversleep = true;
        if before_trigger {
            model.bytes[0x8160] = 1;
        }
        let mut mailbox = Mailbox::default();
        if !matches!(ready(mailbox.phycap(&mut model)), Some(Err(Error::Timeout)))
            || mailbox.state() != State::Pending
            || model.requested == before_trigger
        {
            return TestResult::Fail("busy/absent PHY_CAP bypassed real bounded mailbox waits");
        }
        let mut model = Model::new(0, valid);
        model.hold = true;
        model.pending = true;
        if before_trigger {
            model.bytes[0x8160] = 1;
        }
        let mut mailbox = Mailbox::default();
        {
            let mut future = pin!(mailbox.phycap(&mut model));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail(
                    "PHY_CAP cancellation did not reach actual awaited mailbox",
                );
            }
        }
        let before = model.operations;
        if mailbox.state() != State::Pending
            || !matches!(
                ready(mailbox.phycap(&mut model)),
                Some(Err(Error::Terminal))
            )
            || model.operations != before
        {
            return TestResult::Fail("cancelled PHY_CAP owner forgot pending mailbox or replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852b_phycap_wait_timeout_and_cancellation_keep_mailbox_terminal
);
