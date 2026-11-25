//! I2C-HID as a transport of the HID device registry
//! ([`narf_input::hid_device`]): the `hid_ll_driver` half of Linux's
//! `drivers/hid/i2c-hid/i2c-hid-core.c`, so a bound HID-over-I2C device —
//! the P14s Gen 5's SYNA8018 06CB:CE67 touchpad — appears as
//! `/dev/hidrawN` with the identity Linux gives it.
//!
//! - [`I2cHidTransport`] implements `output_report` (`i2c_hid_output_report`:
//!   a plain output report to `wOutputRegister`, `-ENOSYS` without one) and
//!   `raw_request` (`i2c_hid_raw_request`: GET/SET_REPORT through the
//!   command and data registers, for all three report types as i2c-hid
//!   allows them).
//! - [`hid_info`] is the identity `__i2c_hid_core_probe` sets: `BUS_I2C`,
//!   the HID descriptor's vendor/product, `bcdVersion` as the version, the
//!   name `"<ACPI name> VVVV:PPPP"` and the phys `"i2c-<ACPI name>"`.
//! - [`bufsize_for`] is `i2c_hid_start`'s transfer-buffer size.
//!
//! LINUX-GAP: `HidIoError` has no `EREMOTEIO`, `EAGAIN`, `EBUSY`,
//! `EOPNOTSUPP` or `EPROTO`, so an I2C NAK, arbitration loss, busy host,
//! unsupported transfer or protocol error reaches a raw user as `EIO`
//! rather than the adapter's own errno.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use async_trait::async_trait;
use narf_drivers_i2c::I2cError;
use narf_input::hid_device::{HidInfo, HidIoError, HidTransport, ReportType};

use crate::i2c_hid::{HidDescriptor, I2cHidDriver, I2cHidError, HID_MIN_BUFFER_SIZE};

/// The errno i2c-hid's path returns, as `hid_hw_*` hands it on.
pub fn hid_io_error(e: I2cHidError) -> HidIoError {
    match e {
        I2cHidError::Bus(I2cError::Timeout) => HidIoError::Timeout,
        I2cHidError::Bus(I2cError::InvalidArgs) => HidIoError::InvalidArgs,
        I2cHidError::Bus(_) => HidIoError::Io,
        I2cHidError::NoOutputRegister => HidIoError::Unsupported,
        I2cHidError::InvalidRequest | I2cHidError::BufferTooSmall | I2cHidError::BadPowerState => {
            HidIoError::InvalidArgs
        }
        I2cHidError::NotInitialised => HidIoError::NoDevice,
        I2cHidError::ShortReport | I2cHidError::BadDescriptor => HidIoError::Io,
    }
}

/// One bound I2C-HID device as a [`HidTransport`]. Owns its own
/// [`I2cHidDriver`] over the device's bus and descriptor, as the
/// system-PM snapshot does: the pump owns the pump's driver, and the bus
/// serialises transfers between the two.
#[derive(Debug)]
pub struct I2cHidTransport {
    driver: I2cHidDriver,
}

impl I2cHidTransport {
    pub fn new(driver: I2cHidDriver) -> Self {
        Self { driver }
    }
}

#[async_trait]
impl HidTransport for I2cHidTransport {
    /// `i2c_hid_output_report` (`i2c-hid-core.c:722`).
    async fn output_report(&self, data: &[u8]) -> Result<usize, HidIoError> {
        self.driver
            .output_raw_report(ReportType::Output, data, false)
            .await
            .map_err(hid_io_error)
    }

    /// `i2c_hid_raw_request` (`i2c-hid-core.c:728`).
    async fn raw_request(
        &self,
        id: u8,
        buf: &mut [u8],
        kind: ReportType,
        set: bool,
    ) -> Result<usize, HidIoError> {
        let r = if set {
            if buf.first() != Some(&id) {
                return Err(HidIoError::InvalidArgs);
            }
            self.driver.output_raw_report(kind, buf, true).await
        } else {
            self.driver.get_raw_report(kind, id, buf).await
        };
        r.map_err(hid_io_error)
    }
}

/// `i2c_hid_start` (`i2c-hid-core.c:810`): `HID_MIN_BUFFER_SIZE`, grown to
/// the longest report of any type — `i2c_hid_get_report_length`'s
/// `((size - 1) >> 3) + 1 + numbered + 2` bytes.
pub fn bufsize_for(parsed: &narf_hid::ReportDescriptor) -> usize {
    use narf_hid::FieldKind;
    let mut bufsize = HID_MIN_BUFFER_SIZE;
    for f in &parsed.fields {
        for kind in [FieldKind::Input, FieldKind::Output, FieldKind::Feature] {
            if f.kind != kind {
                continue;
            }
            let bits = parsed.report_body_bits(f.report_id, kind) as usize;
            if bits == 0 {
                continue;
            }
            let len = ((bits - 1) >> 3) + 1 + usize::from(f.report_id != 0) + 2;
            bufsize = bufsize.max(len);
        }
    }
    bufsize
}

/// The name ACPI gives the device and the I2C core gives its client:
/// `"<_HID>:<instance>"` (`acpi_device_set_name`, `"%s:%02x"`), the
/// instance counting devices with the same `_HID` in namespace order.
pub fn acpi_device_name(path: &str, acpi_hid: &str) -> String {
    let instance = narf_aml::find_all_devices_by_hid(acpi_hid)
        .iter()
        .position(|n| n.path == path)
        .unwrap_or(0);
    format!("{acpi_hid}:{instance:02x}")
}

/// The `struct hid_device` identity `__i2c_hid_core_probe`
/// (`i2c-hid-core.c:1040`) gives a device named `client_name` by ACPI.
pub fn hid_info(client_name: &str, desc: &HidDescriptor, report_descriptor: Vec<u8>) -> HidInfo {
    HidInfo {
        bus: narf_input::evdev::bus::I2C,
        vendor: u32::from(desc.w_vendor_id),
        product: u32::from(desc.w_product_id),
        version: u32::from(desc.bcd_version),
        // HID-over-I2C has no country code.
        country: 0,
        name: format!(
            "{} {:04X}:{:04X}",
            client_name, desc.w_vendor_id, desc.w_product_id
        ),
        phys: format!("i2c-{client_name}"),
        uniq: String::new(),
        report_descriptor,
        // No I2C sysfs tree yet: the publisher's platform parent.
        sysfs_parent: String::new(),
    }
}

mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use narf_drivers_i2c::{I2cBus, I2cOp};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    /// One recorded op of a transfer.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Op {
        Write(Vec<u8>),
        Read(usize),
    }

    /// Records every transfer as its op list; answers reads from a queue.
    #[derive(Debug)]
    struct RecBus {
        transfers: IrqSafeSpinLock<Vec<Vec<Op>>>,
        reads: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        fail: IrqSafeSpinLock<Option<I2cError>>,
    }

    impl RecBus {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                transfers: IrqSafeSpinLock::new(Vec::new()),
                reads: IrqSafeSpinLock::new(VecDeque::new()),
                fail: IrqSafeSpinLock::new(None),
            })
        }
        fn take(&self) -> Vec<Vec<Op>> {
            core::mem::take(&mut *self.transfers.lock())
        }
    }

    #[async_trait]
    impl I2cBus for RecBus {
        async fn transfer(&self, _addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
            let fail = *self.fail.lock();
            if let Some(e) = fail {
                return Err(e);
            }
            let mut rec = Vec::new();
            for op in ops.iter_mut() {
                match op {
                    I2cOp::Write(data) => rec.push(Op::Write(data.to_vec())),
                    I2cOp::Read(buf) => {
                        rec.push(Op::Read(buf.len()));
                        let canned = self.reads.lock().pop_front().unwrap_or_default();
                        let n = canned.len().min(buf.len());
                        buf[..n].copy_from_slice(&canned[..n]);
                        buf[n..].fill(0);
                    }
                }
            }
            self.transfers.lock().push(rec);
            Ok(())
        }
        fn name(&self) -> &str {
            "rec-i2c"
        }
    }

    fn now<F: Future>(f: F) -> Option<F::Output> {
        let mut f = pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    /// Command register 0x0005, data 0x0006, output 0x0004.
    fn desc(max_output: u16) -> HidDescriptor {
        HidDescriptor {
            w_hid_desc_length: 30,
            bcd_version: 0x0100,
            w_report_desc_length: 0,
            w_report_desc_register: 0x0002,
            w_input_register: 0x0003,
            w_max_input_length: 32,
            w_output_register: 0x0004,
            w_max_output_length: max_output,
            w_command_register: 0x0005,
            w_data_register: 0x0006,
            w_vendor_id: 0x06cb,
            w_product_id: 0xce67,
            w_version_id: 0x0001,
        }
    }

    fn transport(bus: &Arc<RecBus>, max_output: u16) -> I2cHidTransport {
        let dyn_bus: Arc<dyn I2cBus> = bus.clone();
        I2cHidTransport::new(I2cHidDriver::from_descriptor(
            dyn_bus,
            0x2c,
            0x0020,
            desc(max_output),
        ))
    }

    fn smoke_i2c_hid_set_report_framing_and_id_encoding() -> TestResult {
        let bus = RecBus::new();
        let t = transport(&bus, 32);
        // SET_REPORT(Feature, id 3): ID nibble, length 2 + 1 + 2, ID byte.
        if now(t.raw_request(3, &mut [3, 0xaa, 0xbb], ReportType::Feature, true)) != Some(Ok(3))
            || bus.take()
                != vec![vec![Op::Write(vec![
                    0x05, 0x00, 0x33, 0x03, 0x06, 0x00, 0x05, 0x00, 0x03, 0xaa, 0xbb,
                ])]]
        {
            return TestResult::Fail("SET_REPORT(Feature, 3) frame wrong");
        }
        // Report ID 15 and up: the 0x0F sentinel and a third byte.
        if now(t.raw_request(0x2f, &mut [0x2f, 0x01], ReportType::Output, true)) != Some(Ok(2))
            || bus.take()
                != vec![vec![Op::Write(vec![
                    0x05, 0x00, 0x2f, 0x03, 0x2f, 0x06, 0x00, 0x04, 0x00, 0x2f, 0x01,
                ])]]
        {
            return TestResult::Fail("report ID >= 15 not sentinel-encoded");
        }
        if now(t.raw_request(15, &mut [15, 0x01], ReportType::Feature, true)) != Some(Ok(2))
            || bus.take()[0][0]
                != Op::Write(vec![
                    0x05, 0x00, 0x3f, 0x03, 0x0f, 0x06, 0x00, 0x04, 0x00, 0x0f, 0x01,
                ])
        {
            return TestResult::Fail("report ID 15 not sentinel-encoded");
        }
        // Report ID 0: no ID byte, length 2 + data.
        if now(t.raw_request(0, &mut [0, 0x05], ReportType::Output, true)) != Some(Ok(2))
            || bus.take()[0][0]
                != Op::Write(vec![0x05, 0x00, 0x20, 0x03, 0x06, 0x00, 0x03, 0x00, 0x05])
        {
            return TestResult::Fail("unnumbered SET_REPORT carried an ID byte");
        }
        // i2c_hid_raw_request: buf[0] must be the report ID; SET of an
        // Input report is EINVAL. Neither reaches the bus.
        if now(t.raw_request(4, &mut [3, 1], ReportType::Feature, true))
            != Some(Err(HidIoError::InvalidArgs))
            || now(t.raw_request(0, &mut [0, 1], ReportType::Input, true))
                != Some(Err(HidIoError::InvalidArgs))
            || !bus.take().is_empty()
        {
            return TestResult::Fail("invalid SET reached the bus");
        }
        // Data longer than the transfer buffer is EINVAL.
        let mut long = vec![1u8; HID_MIN_BUFFER_SIZE + 2];
        if now(t.raw_request(1, &mut long, ReportType::Feature, true))
            != Some(Err(HidIoError::InvalidArgs))
            || !bus.take().is_empty()
        {
            return TestResult::Fail("over-long SET_REPORT not EINVAL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-transport",
        smoke_i2c_hid_set_report_framing_and_id_encoding
    );

    fn smoke_i2c_hid_output_report_uses_output_register() -> TestResult {
        let bus = RecBus::new();
        let t = transport(&bus, 32);
        // A plain output report: [wOutputRegister][len][id?][data].
        if now(t.output_report(&[2, 0x10, 0x20])) != Some(Ok(3))
            || bus.take()
                != vec![vec![Op::Write(vec![
                    0x04, 0x00, 0x05, 0x00, 0x02, 0x10, 0x20,
                ])]]
        {
            return TestResult::Fail("output report not written to wOutputRegister");
        }
        if now(t.output_report(&[0, 0x10])) != Some(Ok(2))
            || bus.take()[0][0] != Op::Write(vec![0x04, 0x00, 0x03, 0x00, 0x10])
        {
            return TestResult::Fail("unnumbered output report framing wrong");
        }
        // wMaxOutputLength == 0: -ENOSYS, so hidraw falls back.
        let none = transport(&bus, 0);
        if now(none.output_report(&[0, 0x10])) != Some(Err(HidIoError::Unsupported))
            || !bus.take().is_empty()
        {
            return TestResult::Fail("no output register is not ENOSYS");
        }
        // Bus errors: a timeout is ETIMEDOUT, anything else EIO.
        *bus.fail.lock() = Some(I2cError::Timeout);
        let r1 = now(t.output_report(&[0, 1]));
        *bus.fail.lock() = Some(I2cError::Nack);
        let r2 = now(t.output_report(&[0, 1]));
        *bus.fail.lock() = None;
        if r1 != Some(Err(HidIoError::Timeout)) || r2 != Some(Err(HidIoError::Io)) {
            return TestResult::Fail("bus errors not mapped to the transport errno");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-transport",
        smoke_i2c_hid_output_report_uses_output_register
    );

    fn smoke_i2c_hid_get_report_is_one_transaction() -> TestResult {
        let bus = RecBus::new();
        let t = transport(&bus, 32);
        // Numbered feature report 5: the response carries the ID.
        bus.reads
            .lock()
            .push_back(vec![0x05, 0x00, 0x05, 0xa1, 0xa2]);
        let mut buf = [0u8; 8];
        buf[0] = 5;
        if now(t.raw_request(5, &mut buf, ReportType::Feature, false)) != Some(Ok(3))
            || buf[..3] != [5, 0xa1, 0xa2]
        {
            return TestResult::Fail("numbered GET_REPORT result wrong");
        }
        // One transaction: command write, then the repeated-START read of
        // length + report, sized to the caller's buffer.
        if bus.take()
            != vec![vec![
                Op::Write(vec![0x05, 0x00, 0x35, 0x02, 0x06, 0x00]),
                Op::Read(8 + 2),
            ]]
        {
            return TestResult::Fail("GET_REPORT is not one write+read transaction");
        }
        // Unnumbered input report: buf[0] = 0 stashed, the count includes it.
        bus.reads.lock().push_back(vec![0x04, 0x00, 0x77, 0x88]);
        let mut buf = [0xeeu8; 4];
        if now(t.raw_request(0, &mut buf, ReportType::Input, false)) != Some(Ok(3))
            || buf != [0, 0x77, 0x88, 0xee]
            || bus.take()
                != vec![vec![
                    Op::Write(vec![0x05, 0x00, 0x10, 0x02, 0x06, 0x00]),
                    Op::Read(3 + 2),
                ]]
        {
            return TestResult::Fail("unnumbered GET_REPORT did not stash report ID 0");
        }
        // Report ID >= 15 in a GET: sentinel + third byte before the data
        // register.
        bus.reads.lock().push_back(vec![0x03, 0x00, 0x20]);
        let mut buf = [0x20u8; 4];
        if now(t.raw_request(0x20, &mut buf, ReportType::Feature, false)) != Some(Ok(1))
            || bus.take()[0][0] != Op::Write(vec![0x05, 0x00, 0x3f, 0x02, 0x20, 0x06, 0x00])
        {
            return TestResult::Fail("GET_REPORT ID >= 15 not sentinel-encoded");
        }
        // The device answering with another report is EINVAL.
        bus.reads.lock().push_back(vec![0x04, 0x00, 0x06, 0x01]);
        if now(t.raw_request(5, &mut [5, 0, 0, 0], ReportType::Feature, false))
            != Some(Err(HidIoError::InvalidArgs))
        {
            return TestResult::Fail("mismatched report ID not EINVAL");
        }
        // An empty response (length <= 2) is 0 bytes.
        bus.reads.lock().push_back(vec![0x02, 0x00]);
        if now(t.raw_request(5, &mut [5, 0, 0], ReportType::Feature, false)) != Some(Ok(0)) {
            return TestResult::Fail("empty GET_REPORT response not 0");
        }
        // A length longer than asked is cut to the buffer.
        bus.reads
            .lock()
            .push_back(vec![0x10, 0x00, 5, 1, 2, 3, 4, 5, 6]);
        let mut buf = [5u8, 0, 0];
        if now(t.raw_request(5, &mut buf, ReportType::Feature, false)) != Some(Ok(3))
            || buf != [5, 1, 2]
        {
            return TestResult::Fail("GET_REPORT not cut to the buffer");
        }
        // No GET for an Output report (i2c_hid_get_raw_report).
        let _ = bus.take();
        if now(t.raw_request(0, &mut [0, 0], ReportType::Output, false))
            != Some(Err(HidIoError::InvalidArgs))
            || !bus.take().is_empty()
        {
            return TestResult::Fail("GET of an Output report not EINVAL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-transport",
        smoke_i2c_hid_get_report_is_one_transaction
    );

    fn smoke_i2c_hid_identity_and_bufsize() -> TestResult {
        let info = hid_info("SYNA8018:00", &desc(32), vec![1, 2, 3]);
        // What a P14s Gen 5 reports: HID_NAME=SYNA8018:00 06CB:CE67,
        // HID_PHYS=i2c-SYNA8018:00, version = bcdVersion.
        if info.bus != 0x18
            || info.vendor != 0x06cb
            || info.product != 0xce67
            || info.version != 0x0100
            || info.name != "SYNA8018:00 06CB:CE67"
            || info.phys != "i2c-SYNA8018:00"
            || !info.uniq.is_empty()
            || info.report_descriptor != [1, 2, 3]
            || !info.sysfs_parent.is_empty()
        {
            return TestResult::Fail("I2C-HID identity differs from __i2c_hid_core_probe");
        }
        // A 256-byte feature report on ID 5 grows the buffer to
        // 255/8+1... = 256 + 1 + 2.
        let blob = [
            0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x85, 0x05, 0x09, 0xc5, 0x75, 0x08, 0x96,
            0x00, 0x01, 0xb1, 0x02, 0xc0,
        ];
        let parsed = match narf_hid::parse(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("fixture descriptor did not parse"),
        };
        if bufsize_for(&parsed) != 256 + 1 + 2 {
            return TestResult::Fail("bufsize is not the longest report + ID + length");
        }
        // Small reports keep HID_MIN_BUFFER_SIZE.
        let small = [
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x75, 0x08, 0x95, 0x03, 0x81, 0x02, 0xc0,
        ];
        match narf_hid::parse(&small) {
            Ok(p) if bufsize_for(&p) == HID_MIN_BUFFER_SIZE => TestResult::Pass,
            _ => TestResult::Fail("small descriptor did not keep HID_MIN_BUFFER_SIZE"),
        }
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-transport",
        smoke_i2c_hid_identity_and_bufsize
    );
}
