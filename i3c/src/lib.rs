#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::task::Waker;
use narf_capabilities::{CapKind, CapType};

pub mod registry;
pub mod types;

pub use types::{
    CccDest, CommonCommandCode, I3cDevice, I3cError, I3cOp, IbiHandler, IbiPayload,
};

/// A specialized capability for I3C operations.
#[derive(Debug)]
pub enum I3cRight {
    /// Allows reading from a specific device.
    Read(u8),
    /// Allows writing to a specific device.
    Write(u8),
    /// Allows receiving In-Band Interrupts.
    Notify(u8),
    /// Full bus management (Dynamic Address Assignment, etc.)
    Admin,
}

#[derive(Copy, Clone, Debug)]
pub struct I3cCapType;

impl CapType for I3cCapType {
    const KIND: CapKind = CapKind::I3cBus;
}

/// A specialized I3C bus interface.
///
/// Implementors handle low-level frame construction; callers use the
/// higher-level `ccc()` and `enter_daa()` helpers instead of crafting
/// raw `I3cOp` sequences.
///
/// Spec ref: I3C Basic rev 1.1 §5.
/// Linux ref: include/linux/i3c/master.h i3c_master_controller_ops.
#[async_trait]
pub trait I3cBus: Send + Sync {
    /// Performs a raw SDR transfer to/from a specific target device.
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError>;

    /// Sends a Common Command Code to the bus.
    ///
    /// Broadcast CCCs use address `0x7E` (I3C reserved); directed CCCs
    /// address the `dest` field.  The `payload` slice is sent after the
    /// opcode for write-type CCCs; for read-type CCCs the caller passes
    /// a zero-length slice and inspects the return payload out-of-band
    /// (Stage 3 extension point).
    ///
    /// Linux ref: drivers/i3c/master/dw-i3c-master.c
    ///            dw_i3c_master_send_ccc_cmd()
    async fn ccc(
        &self,
        ccc: CommonCommandCode,
        dest: CccDest,
        payload: &[u8],
    ) -> Result<(), I3cError>;

    /// Dynamic Address Assignment procedure (ENTDAA).
    ///
    /// Issues RSTDAA then ENTDAA as per I3C spec rev 1.1 §5.1.9.3.
    /// Returns the list of devices that responded and were assigned
    /// a dynamic address.
    ///
    /// Linux ref: drivers/i3c/master/dw-i3c-master.c
    ///            dw_i3c_master_daa()
    async fn enter_daa(&self) -> Result<Vec<I3cDevice>, I3cError>;

    /// HDR-DDR write to a target device.
    ///
    /// Broadcasts ENTHDR0 to place the bus in HDR-DDR mode, then sends
    /// a DDR command token (address + R/W=0 + command code) followed by
    /// the data words.  Each word is 16 bits; DDR clocks both edges so
    /// the raw bit rate doubles vs SDR at the same clock frequency.
    ///
    /// I3C spec rev 1.1 §5.2.3; Linux dw-i3c-master.c COMMAND_PORT_SPEED.
    async fn hdr_ddr_write(&self, addr: u8, command: u8, data: &[u16])
        -> Result<(), I3cError>;

    /// HDR-DDR read from a target device.
    ///
    /// Like `hdr_ddr_write` but sets the R/W bit in the command token
    /// and reads back the data words from the bus.
    ///
    /// I3C spec rev 1.1 §5.2.3.
    async fn hdr_ddr_read(&self, addr: u8, command: u8, data: &mut [u16])
        -> Result<(), I3cError>;

    /// Registers an async waker for an In-Band Interrupt (IBI).
    fn register_ibi_waker(&self, addr: u8, waker: Waker);

    /// Unregisters an async waker.
    fn unregister_ibi_waker(&self, addr: u8);

    /// Register a handler invoked when the named slave device fires an IBI.
    ///
    /// Sends ENEC (directed, enable SIR events) to `dev_addr`, then stores
    /// `handler` so the ISR/drain loop can call `on_ibi()` when the IBI
    /// ring has data for that address.
    ///
    /// I3C spec rev 1.1 §5.1.6; Linux i3c_master_enable_ibi().
    async fn register_ibi_handler(
        &self,
        dev_addr: u8,
        handler: Arc<dyn IbiHandler>,
    ) -> Result<(), I3cError>;
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    struct MockI3c {
        transfers: IrqSafeSpinLock<Vec<u8>>,
        /// Last CCC sent: (opcode, dest_addr_or_0xFF_for_broadcast, payload_byte_0).
        last_ccc: IrqSafeSpinLock<Option<(u8, u8, u8)>>,
    }

    #[async_trait]
    impl I3cBus for MockI3c {
        async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError> {
            self.transfers.lock().push(addr);
            for op in ops {
                match op {
                    I3cOp::Write(data) => self.transfers.lock().extend_from_slice(data),
                    I3cOp::Read(buf) => {
                        for i in 0..buf.len() {
                            buf[i] = 0x55;
                        }
                    }
                }
            }
            Ok(())
        }

        async fn ccc(
            &self,
            ccc: CommonCommandCode,
            dest: CccDest,
            payload: &[u8],
        ) -> Result<(), I3cError> {
            let dest_byte = match dest {
                CccDest::Broadcast => 0xFF,
                CccDest::Address(a) => a,
            };
            let p0 = payload.first().copied().unwrap_or(0);
            *self.last_ccc.lock() = Some((ccc.opcode(), dest_byte, p0));
            Ok(())
        }

        async fn enter_daa(&self) -> Result<Vec<I3cDevice>, I3cError> {
            // Synthetic DAA: return one fake device.
            let raw: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xC4, 0x11];
            Ok(alloc::vec![I3cDevice::from_daa_response(&raw, 0x08)])
        }

        async fn hdr_ddr_write(
            &self,
            _addr: u8,
            _command: u8,
            _data: &[u16],
        ) -> Result<(), I3cError> {
            Ok(())
        }

        async fn hdr_ddr_read(
            &self,
            _addr: u8,
            _command: u8,
            data: &mut [u16],
        ) -> Result<(), I3cError> {
            for w in data.iter_mut() {
                *w = 0xA55A;
            }
            Ok(())
        }

        fn register_ibi_waker(&self, _addr: u8, _waker: Waker) {}
        fn unregister_ibi_waker(&self, _addr: u8) {}

        async fn register_ibi_handler(
            &self,
            _dev_addr: u8,
            _handler: Arc<dyn IbiHandler>,
        ) -> Result<(), I3cError> {
            Ok(())
        }
    }

    fn make_mock() -> Arc<MockI3c> {
        Arc::new(MockI3c {
            transfers: IrqSafeSpinLock::new(Vec::new()),
            last_ccc: IrqSafeSpinLock::new(None),
        })
    }

    fn smoke_i3c_transfer() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = make_mock();
        let success = Arc::new(core::sync::atomic::AtomicU32::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let mut data = [0u8; 4];
            let mut ops = [I3cOp::Write(&[0x1, 0x2]), I3cOp::Read(&mut data)];
            m.transfer(0x08, &mut ops).await.expect("transfer failed");
            if data[0] == 0x55 {
                s.store(1, core::sync::atomic::Ordering::SeqCst);
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(core::sync::atomic::Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("transfer check failed")
        }
    }
    kernel_test_in!("i3c", smoke_i3c_transfer);

    fn smoke_i3c_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(I3cCapType::KIND, CapKind::I3cBus) {
            TestResult::Pass
        } else {
            TestResult::Fail("cap kind mismatch")
        }
    }
    kernel_test_in!("i3c", smoke_i3c_cap_kind);

    fn smoke_i3c_error_variants_distinct() -> TestResult {
        let all = [
            I3cError::NoDevice,
            I3cError::BusBusy,
            I3cError::Timeout,
            I3cError::Nack,
            I3cError::CrcError,
            I3cError::Denied,
            I3cError::InvalidArgs,
            I3cError::HardwareError,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("I3cError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_error_variants_distinct);

    fn smoke_i3c_mock_read_op_fills_buf_from_mock() -> TestResult {
        // The MockI3c here writes 0x55 to every Read byte. Exercise
        // an end-to-end Write-then-Read transfer and assert the
        // Write tail landed in `transfers` while the Read buf was
        // populated.
        narf_scheduler::__reset_queues_for_test();
        let mock = make_mock();
        let ok = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let m = mock.clone();
        let o = ok.clone();
        narf_scheduler::spawn(async move {
            let mut rbuf = [0u8; 3];
            let mut ops = [I3cOp::Write(&[0xAB, 0xCD]), I3cOp::Read(&mut rbuf)];
            if m.transfer(0x42, &mut ops).await.is_ok() && rbuf == [0x55, 0x55, 0x55] {
                o.store(true, core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if !ok.load(core::sync::atomic::Ordering::SeqCst) {
            return TestResult::Fail("Write-Read round-trip didn't complete");
        }
        // Mock pushed addr then write bytes into transfers.
        let log = mock.transfers.lock();
        if log.len() < 3 || log[0] != 0x42 || log[1] != 0xAB || log[2] != 0xCD {
            return TestResult::Fail("Write tail not recorded by mock");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_mock_read_op_fills_buf_from_mock);

    fn smoke_i3c_ibi_payload_field_round_trip() -> TestResult {
        let p = IbiPayload {
            addr: 0x3C,
            data: alloc::vec![0xDE, 0xAD],
        };
        if p.addr != 0x3C {
            return TestResult::Fail("IbiPayload.addr round-trip");
        }
        if p.data != alloc::vec![0xDE, 0xAD] {
            return TestResult::Fail("IbiPayload.data round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_ibi_payload_field_round_trip);

    // ── CCC opcode encoding smoke ──────────────────────────────────
    // Verifies the exact wire values mandated by I3C spec rev 1.1
    // Table 11 and Linux include/linux/i3c/ccc.h.
    fn smoke_i3c_ccc_opcode_encoding() -> TestResult {
        let cases: &[(CommonCommandCode, u8, bool)] = &[
            (CommonCommandCode::EnecBc, 0x00, false),
            (CommonCommandCode::DisecBc, 0x01, false),
            (CommonCommandCode::RstdaaBc, 0x06, false),
            (CommonCommandCode::Entdaa, 0x07, false),
            (CommonCommandCode::SetmwlBc, 0x09, false),
            (CommonCommandCode::SetmrlBc, 0x0A, false),
            (CommonCommandCode::EnecDir, 0x80, true),
            (CommonCommandCode::DisecDir, 0x81, true),
            (CommonCommandCode::Setdasa, 0x87, true),
            (CommonCommandCode::Getpid, 0x8D, true),
            (CommonCommandCode::Getbcr, 0x8E, true),
            (CommonCommandCode::Getdcr, 0x8F, true),
        ];
        for &(ccc, expected_opcode, expected_directed) in cases {
            if ccc.opcode() != expected_opcode {
                return TestResult::Fail("CCC opcode mismatch");
            }
            if ccc.is_directed() != expected_directed {
                return TestResult::Fail("CCC directed flag mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_ccc_opcode_encoding);

    // ── ENTHDR CCC opcode encoding smoke ──────────────────────────
    // ENTHDR(n) = 0x20 + n (broadcast).  I3C spec rev 1.1 §5.2.3.
    // Linux: include/linux/i3c/ccc.h I3C_CCC_ENTHDR(x) = 0x20 + x.
    fn smoke_i3c_enthdr_ccc_encoding() -> TestResult {
        if CommonCommandCode::Enthdr0.opcode() != 0x20 {
            return TestResult::Fail("ENTHDR0 opcode should be 0x20");
        }
        if CommonCommandCode::Enthdr1.opcode() != 0x21 {
            return TestResult::Fail("ENTHDR1 opcode should be 0x21");
        }
        if CommonCommandCode::Enthdr2.opcode() != 0x22 {
            return TestResult::Fail("ENTHDR2 opcode should be 0x22");
        }
        // All ENTHDR CCCs are broadcast (bit 7 = 0).
        if CommonCommandCode::Enthdr0.is_directed() {
            return TestResult::Fail("ENTHDR0 must be broadcast (bit 7 = 0)");
        }
        if CommonCommandCode::Enthdr1.is_directed() {
            return TestResult::Fail("ENTHDR1 must be broadcast (bit 7 = 0)");
        }
        if CommonCommandCode::Enthdr2.is_directed() {
            return TestResult::Fail("ENTHDR2 must be broadcast (bit 7 = 0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_enthdr_ccc_encoding);

    // ── HDR-DDR read mock round-trip ──────────────────────────────
    fn smoke_i3c_hdr_ddr_read_via_mock() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = make_mock();
        let ok = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let m = mock.clone();
        let o = ok.clone();
        narf_scheduler::spawn(async move {
            let mut words = [0u16; 4];
            if m.hdr_ddr_read(0x08, 0x01, &mut words).await.is_ok()
                && words[0] == 0xA55A
                && words[3] == 0xA55A
            {
                o.store(true, core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if ok.load(core::sync::atomic::Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("hdr_ddr_read mock round-trip failed")
        }
    }
    kernel_test_in!("i3c", smoke_i3c_hdr_ddr_read_via_mock);

    // ── CCC dispatch smoke — mock receives correct opcode ──────────
    fn smoke_i3c_ccc_dispatch_via_mock() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = make_mock();
        let ok = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let m = mock.clone();
        let o = ok.clone();
        narf_scheduler::spawn(async move {
            // Broadcast DISEC with payload 0x01 (disable SIR events).
            let r = m
                .ccc(CommonCommandCode::DisecBc, CccDest::Broadcast, &[0x01])
                .await;
            if r.is_ok() {
                o.store(true, core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if !ok.load(core::sync::atomic::Ordering::SeqCst) {
            return TestResult::Fail("ccc() returned error");
        }
        let recorded = mock.last_ccc.lock();
        match *recorded {
            Some((op, dest, p0)) => {
                if op != CommonCommandCode::DisecBc.opcode() {
                    return TestResult::Fail("wrong CCC opcode recorded");
                }
                if dest != 0xFF {
                    return TestResult::Fail("wrong CCC dest recorded");
                }
                if p0 != 0x01 {
                    return TestResult::Fail("wrong CCC payload byte recorded");
                }
            }
            None => return TestResult::Fail("no CCC recorded"),
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_ccc_dispatch_via_mock);

    // ── DAA payload decode smoke ───────────────────────────────────
    // Verifies I3cDevice::from_daa_response() per spec rev 1.1 §5.1.9.3.
    fn smoke_i3c_daa_payload_decode() -> TestResult {
        // Construct a synthetic 8-byte DAA response.
        // PID = 0xAABBCCDDEEFF (big-endian bytes 0-5)
        // BCR = 0xC4, DCR = 0x11
        let raw: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xC4, 0x11];
        let dev = I3cDevice::from_daa_response(&raw, 0x42);
        if dev.pid != 0x00AABBCCDDEEFF {
            return TestResult::Fail("DAA PID decode wrong");
        }
        if dev.bcr != 0xC4 {
            return TestResult::Fail("DAA BCR decode wrong");
        }
        if dev.dcr != 0x11 {
            return TestResult::Fail("DAA DCR decode wrong");
        }
        if dev.dynamic_addr != 0x42 {
            return TestResult::Fail("DAA dynamic_addr wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_daa_payload_decode);

    // ── enter_daa returns device list from mock ────────────────────
    fn smoke_i3c_enter_daa_returns_devices() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = make_mock();
        let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let m = mock.clone();
        let c = count.clone();
        narf_scheduler::spawn(async move {
            if let Ok(devs) = m.enter_daa().await {
                c.store(devs.len(), core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if count.load(core::sync::atomic::Ordering::SeqCst) != 1 {
            return TestResult::Fail("enter_daa did not return 1 device");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_enter_daa_returns_devices);
}
