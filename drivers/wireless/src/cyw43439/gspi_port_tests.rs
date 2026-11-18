// SPDX-License-Identifier: MIT
//! Native protocol regressions with literal source wire vectors. These model
//! the exclusive host boundary; they do not qualify an actual SPI controller.
use super::*;
use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Exchange {
    write: Vec<u8>,
    read: usize,
}
#[derive(Debug)]
struct Model {
    claimed: AtomicBool,
    config: IrqSafeSpinLock<Option<SpiDeviceConfig>>,
    replies: IrqSafeSpinLock<VecDeque<Result<Vec<u8>, SpiError>>>,
    log: IrqSafeSpinLock<Vec<Exchange>>,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            config: IrqSafeSpinLock::new(None),
            replies: IrqSafeSpinLock::new(VecDeque::new()),
            log: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
#[derive(Debug)]
struct Bus(Arc<Model>);
#[derive(Debug)]
struct Device(Arc<Model>);
impl SpiDevice for Device {
    fn transaction(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), SpiError> {
        self.0.log.lock().push(Exchange {
            write: write.to_vec(),
            read: read.len(),
        });
        let next = self
            .0
            .replies
            .lock()
            .pop_front()
            .expect("one scripted result per whole transaction")?;
        if read.len() != next.len() {
            return Err(SpiError::BadHardware);
        }
        read.copy_from_slice(&next);
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        self.0.claimed.store(false, Ordering::Release);
    }
}
impl SpiBus for Bus {
    fn claim_device(&self, config: SpiDeviceConfig) -> Result<Box<dyn SpiDevice>, SpiClaimError> {
        if self.0.claimed.swap(true, Ordering::AcqRel) {
            return Err(SpiClaimError::Busy);
        }
        *self.0.config.lock() = Some(config);
        Ok(Box::new(Device(self.0.clone())))
    }
    fn transfer(&self, _: &[u8], _: &mut [u8]) -> Result<(), SpiError> {
        panic!("legacy transfer must never be used")
    }
    fn transfer_full_duplex(&self, _: &mut [u8], _: &mut [u8]) -> Result<(), SpiError> {
        panic!("legacy full duplex")
    }
    fn set_mode(&self, _: SpiMode) -> Result<(), SpiError> {
        panic!("configuration must be atomic with claim")
    }
    fn set_freq(&self, _: u32) -> Result<(), SpiError> {
        panic!("configuration must be atomic with claim")
    }
    fn set_cs(&self, _: u8) -> Result<(), SpiError> {
        panic!("split CS operation")
    }
    fn name(&self) -> &str {
        "gspi-model"
    }
}
fn cold(extra: &[Result<Vec<u8>, SpiError>]) -> (GspiTransport, Arc<Model>) {
    let model = Arc::new(Model::default());
    model.replies.lock().extend(extra.iter().cloned());
    let port =
        GspiTransport::new(Arc::new(Bus(model.clone())), 2, SpiMode::Mode0, 1_000_000).unwrap();
    (port, model)
}
fn startup() -> Vec<Result<Vec<u8>, SpiError>> {
    alloc::vec![
        Ok(alloc::vec![0xbe, 0xad, 0xfe, 0xed]),
        Ok(Vec::new()),
        Ok(alloc::vec![0xad, 0xbe, 0xed, 0xfe]),
        Ok(alloc::vec![0xb3, 4, 2, 0]),
        Ok(Vec::new()),
        Ok(Vec::new()),
        Ok(Vec::new()),
    ]
}
fn ready(extra: &[Result<Vec<u8>, SpiError>]) -> (GspiTransport, Arc<Model>) {
    let mut script = startup();
    script.extend(extra.iter().cloned());
    let (mut port, model) = cold(&script);
    port.initialize_link().unwrap();
    (port, model)
}
fn packets(extra: &[Result<Vec<u8>, SpiError>]) -> (GspiTransport, Arc<Model>) {
    let mut script = alloc::vec![Ok(Vec::new()), Ok(alloc::vec![0x20, 0, 0, 0])];
    script.extend(extra.iter().cloned());
    let (mut port, model) = ready(&script);
    port.finish_gspi_boot().unwrap();
    (port, model)
}
fn frame() -> Vec<u8> {
    alloc::vec![12, 0, 0xf3, 0xff, 0, 0, 0, 12, 0, 0, 0, 0]
}

fn smoke_bootstrap_and_normal_literal_wire() -> TestResult {
    let (mut port, model) = ready(&[]);
    let log = model.log.lock();
    if log[0]
        != (Exchange {
            write: alloc::vec![0xa0, 4, 0x40, 0],
            read: 4,
        })
        || log[1].write != [0, 4, 0xc0, 0, 4, 0xb3, 0, 2]
        || log[2].write != [4, 0xa0, 0, 0x40]
        || log[4].write != [1, 0xe8, 0, 0xc0, 16, 0, 0, 0]
        || log[5].write != [1, 0x20, 0, 0xc0, 0x99, 0, 0, 0]
        || log[6].write != [2, 0x30, 0, 0xc0, 0xbe, 0, 0, 0]
    {
        return TestResult::Fail("bootstrap/normal literal wire mismatch");
    }
    drop(log);
    if port.initialize_link() != Err(TransportError::NotReady) || model.log.lock().len() != 7 {
        return TestResult::Fail("startup replay emitted hardware work");
    }
    let config = model.config.lock().unwrap();
    if config.cs != 2 || config.wiring != SpiWiring::SharedData || config.post_cs_delay_ns != 100 {
        return TestResult::Fail("exclusive shared-pad/settle contract missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_bootstrap_and_normal_literal_wire
);

fn smoke_bad_bootstrap_is_terminal() -> TestResult {
    let (mut port, model) = cold(&[Ok(alloc::vec![0; 4])]);
    if port.initialize_link() != Err(TransportError::BadFraming)
        || port.initialize_link() != Err(TransportError::NotReady)
        || port.write32(Function::Bus, 0, 0) != Err(TransportError::NotReady)
        || model.log.lock().len() != 1
    {
        return TestResult::Fail("bad bootstrap was retried or enabled traffic");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_bad_bootstrap_is_terminal
);

fn smoke_f1_read_dummy_and_upload_tail() -> TestResult {
    let mut read = alloc::vec![0xcc; 20];
    read[16] = 0x80;
    let (mut port, model) = ready(&[Ok(read), Ok(Vec::new()), Ok(Vec::new())]);
    let mut value = [0];
    if port
        .read_burst(Function::Backplane, 0x1000e, &mut value)
        .is_err()
        || value != [0x80]
    {
        return TestResult::Fail("F1 delay leaked into data");
    }
    let payload = alloc::vec![0x5a; 67];
    if port.write_burst(Function::Backplane, 0, &payload).is_err() {
        return TestResult::Fail("F1 upload failed");
    }
    let log = model.log.lock();
    if log[7]
        != (Exchange {
            write: alloc::vec![1, 0x70, 0, 0x58],
            read: 20,
        })
        || log[8].write[..4] != [64, 0, 0, 0xd4]
        || log[8].write[4..] != payload[..64]
        || log[9].write != [3, 0, 2, 0xd4, 0x5a, 0x5a, 0x5a, 0]
    {
        return TestResult::Fail("F1 64-byte/raw payload/zero-tail framing mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f1_read_dummy_and_upload_tail
);

fn smoke_f2_whole_packet_busy_and_padding() -> TestResult {
    let (mut port, model) = packets(&[
        Ok(alloc::vec![0; 4]),
        Ok(alloc::vec![0x20, 0, 0, 0]),
        Ok(Vec::new()),
    ]);
    let packet = alloc::vec![0xa5; 13];
    if port.transmit_packet_inner(&packet) != Err(TransportError::Busy)
        || port.transmit_packet_inner(&packet).is_err()
    {
        return TestResult::Fail("F2 readiness handling");
    }
    let log = model.log.lock();
    if log.len() != 12
        || log[11].write[..4] != [13, 0, 0, 0xe0]
        || log[11].write[4..17] != packet
        || log[11].write[17..] != [0, 0, 0]
    {
        return TestResult::Fail("F2 packet split, consumed while busy or incorrectly padded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f2_whole_packet_busy_and_padding
);

fn smoke_f2_irq_ack_and_drain_multiple() -> TestResult {
    let pending = alloc::vec![0, 0x19, 0, 0]; // packet bit8 + 12<<9.
    let (mut port, model) = packets(&[
        Ok(alloc::vec![0x20, 0, 0, 0]),
        Ok(Vec::new()),
        Ok(pending.clone()),
        Ok(frame()),
        Ok(pending),
        Ok(frame()),
        Ok(alloc::vec![0; 4]),
    ]);
    let mut buffer = [0; 12];
    if port.receive_packet_inner(&mut buffer) != Ok(12)
        || buffer != frame()[..]
        || port.receive_packet_inner(&mut buffer) != Ok(12)
        || port.receive_packet_inner(&mut buffer) != Ok(0)
    {
        return TestResult::Fail("IRQ/continuation packet draining failed");
    }
    let log = model.log.lock();
    if log[10].write != [2, 0x20, 0, 0xc0, 0x20, 0, 0, 0]
        || log[12]
            != (Exchange {
                write: alloc::vec![12, 0, 0, 0x60],
                read: 12,
            })
        || log[14] != log[12]
    {
        return TestResult::Fail(
            "sampled IRQ not acked or F2 read not whole address-zero transaction",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f2_irq_ack_and_drain_multiple
);

fn smoke_f2_bad_length_abort_and_no_replay() -> TestResult {
    let (mut port, model) = packets(&[
        Ok(alloc::vec![0x20, 0, 0, 0]),
        Ok(Vec::new()),
        Ok(alloc::vec![0, 1, 0, 0]),
        Ok(Vec::new()),
    ]);
    let mut buffer = [0; 16];
    if port.receive_packet_inner(&mut buffer) != Err(TransportError::BadFraming)
        || port.receive_packet_inner(&mut buffer) != Err(TransportError::NotReady)
    {
        return TestResult::Fail("invalid pending length not terminal");
    }
    if model.log.lock().last().unwrap().write != [1, 0x68, 0, 0xd8, 1, 0, 0, 0] {
        return TestResult::Fail("source F1 frame abort missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f2_bad_length_abort_and_no_replay
);

fn smoke_f2_partial_write_error_is_terminal() -> TestResult {
    let (mut port, model) = packets(&[Ok(alloc::vec![0x20, 0, 0, 0]), Err(SpiError::Timeout)]);
    if port.transmit_packet_inner(&frame()) != Err(TransportError::Timeout)
        || port.transmit_packet_inner(&frame()) != Err(TransportError::NotReady)
        || model.log.lock().len() != 11
    {
        return TestResult::Fail("partial F2 write replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f2_partial_write_error_is_terminal
);

fn smoke_packet_constructor_requires_real_boot_ready() -> TestResult {
    let (port, _) = ready(&[]);
    if port.into_booted_runtime().is_ok() {
        return TestResult::Fail("control credit before F2 boot readiness");
    }
    let (port, _) = packets(&[]);
    if port.into_booted_runtime().is_err() {
        return TestResult::Fail("boot-ready consumed owner refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_packet_constructor_requires_real_boot_ready
);

fn smoke_claim_excludes_second_session_and_invalid_windows_do_no_io() -> TestResult {
    let (mut port, model) = ready(&[]);
    if !matches!(
        GspiTransport::new(Arc::new(Bus(model.clone())), 2, SpiMode::Mode0, 1_000_000),
        Err(PortError::BusClaimed)
    ) || port.write_burst(Function::Backplane, 0x7fff, &[1, 2])
        != Err(TransportError::AddressOverflow)
        || port.write_burst(Function::Wlan, 0, &frame()) != Err(TransportError::NotReady)
        || port.read32(Function::Bus, ADDR_MASK) != Err(TransportError::AddressOverflow)
        || model.log.lock().len() != 7
    {
        return TestResult::Fail("second claim or invalid/FIFO register window reached wire");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_claim_excludes_second_session_and_invalid_windows_do_no_io
);

fn smoke_flagged_ram_window_preflight_preserves_local_register_range() -> TestResult {
    let (mut port, model) = ready(&[Ok(Vec::new()), Ok(Vec::new())]);
    let mut output = [0; 128];
    if port.write_burst(Function::Backplane, 0xffc0, &[0xa5; 128])
        != Err(TransportError::AddressOverflow)
        || port.read_burst(Function::Backplane, 0xffc0, &mut output)
            != Err(TransportError::AddressOverflow)
        || port.write_burst(Function::Backplane, 0xffff, &[1, 2])
            != Err(TransportError::AddressOverflow)
        || model.log.lock().len() != 7
    {
        return TestResult::Fail("flagged RAM crossed into F1 registers before full preflight");
    }
    if port
        .write_burst(Function::Backplane, 0xffc0, &[0xa5; 64])
        .is_err()
        || port
            .write_burst(Function::Backplane, 0x10000, &[0x5a; 64])
            .is_err()
    {
        return TestResult::Fail("valid flagged RAM boundary or genuine local registers refused");
    }
    let log = model.log.lock();
    if log.len() != 9
        || log[7].write[..4] != [64, 0, 0xfe, 0xd7]
        || log[8].write[..4] != [64, 0, 0, 0xd8]
    {
        return TestResult::Fail("flagged RAM/local register command boundary differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_flagged_ram_window_preflight_preserves_local_register_range
);

fn smoke_loader_rejects_actual_gspi_mode_mismatch_before_any_followup_wire() -> TestResult {
    use crate::cyw43439::firmware::{build_nvram_blob, FirmwareLoader, LoadError, LoadStep};
    for initialized in [false, true] {
        let (port, model) = if initialized { ready(&[]) } else { cold(&[]) };
        let before = model.log.lock().len();
        let nvram = build_nvram_blob("ccode=US\n").unwrap();
        let mut loader = FirmwareLoader::new(port, &[0xa5; 64], &nvram, 0, false);
        if loader.run() != Err(LoadError::Transport(TransportError::NotReady))
            || loader.execute_step(LoadStep::VerifyEndian) != Err(LoadError::InvalidState)
            || model.log.lock().len() != before
        {
            return TestResult::Fail(
                "actual gSPI diagnostic port accepted SDIO loader/CCCR aliases",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_loader_rejects_actual_gspi_mode_mismatch_before_any_followup_wire
);

fn smoke_f2_short_buffer_underflow_and_all_ones_fail_closed() -> TestResult {
    for (status, capacity, error, abort) in [
        ([0, 0x19, 0, 0], 8, TransportError::LengthOverflow, true),
        ([2, 0x19, 0, 0], 16, TransportError::ChipFlowError, true),
        ([0xff; 4], 16, TransportError::NotReady, false),
    ] {
        let mut script = alloc::vec![
            Ok(alloc::vec![0x20, 0, 0, 0]),
            Ok(Vec::new()),
            Ok(status.to_vec())
        ];
        if abort {
            script.push(Ok(Vec::new()));
        }
        let (mut port, model) = packets(&script);
        let mut buffer = alloc::vec![0; capacity];
        if port.receive_packet_inner(&mut buffer) != Err(error)
            || port.receive_packet_inner(&mut buffer) != Err(TransportError::NotReady)
            || model.log.lock().len() != if abort { 13 } else { 12 }
        {
            return TestResult::Fail("bad pending frame partially consumed or retried");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_f2_short_buffer_underflow_and_all_ones_fail_closed
);
