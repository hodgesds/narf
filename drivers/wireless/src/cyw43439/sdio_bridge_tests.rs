use super::*;
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use narf_kernel_test::{kernel_test_in, TestResult};
const CORE: u32 = 0x18011000;
#[derive(Default)]
struct Host {
    window: u32,
    words: BTreeMap<u32, u32>,
    ops: Vec<(u8, u8, u32, usize)>,
    rx: VecDeque<u8>,
    enabled: u8,
    fail_write: bool,
    reassert_change: bool,
    /// Host has a card-interrupt line; records the claim and rearms.
    line: bool,
    claimed: Option<u8>,
    notify: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
    rearmed: u32,
    /// CMD52 register model for save-restore sleep (SLEEPCSR mirrors DEVON
    /// from KSO; CHIPCLKCSR reports HT/ALP available).
    sleep_model: bool,
    regs: BTreeMap<(u8, u32), u8>,
}
impl SdioFunction for Host {
    fn enable_card_interrupt(
        &mut self,
        functions: u8,
        notify: alloc::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Result<bool, SdioError> {
        if !self.line {
            return Ok(false);
        }
        self.claimed = Some(functions);
        self.notify = Some(notify);
        Ok(true)
    }
    fn rearm_card_interrupt(&mut self) {
        self.rearmed += 1;
    }
    fn cmd52_read(&mut self, f: u8, a: u32) -> Result<u8, SdioError> {
        self.ops.push((52, f, a, 0));
        if !self.sleep_model {
            return Ok(0);
        }
        let value = self.regs.get(&(f, a)).copied().unwrap_or(0);
        Ok(if (f, a) == (1, 0x1000e) {
            value | 0xc0
        } else {
            value
        })
    }
    fn cmd52_write(&mut self, f: u8, a: u32, v: u8) -> Result<(), SdioError> {
        self.ops.push((52, f, a, 1));
        if self.sleep_model {
            let stored = if (f, a) == (1, 0x1001f) {
                v | ((v & 1) << 1)
            } else {
                v
            };
            self.regs.insert((f, a), stored);
        }
        let shift = match a {
            0x1000a => Some(8),
            0x1000b => Some(16),
            0x1000c => Some(24),
            _ => None,
        };
        if let Some(shift) = shift {
            self.window = (self.window & !(255 << shift)) | (u32::from(v) << shift);
        }
        Ok(())
    }
    fn cmd53_read(&mut self, f: u8, a: u32, b: &mut [u8]) -> Result<(), SdioError> {
        self.ops.push((53, f, a, b.len()));
        if f != 1 || a & 0x8000 == 0 || b.len() != 4 {
            return Err(SdioError::HostError);
        }
        b.copy_from_slice(
            &self
                .words
                .get(&(self.window | (a & 0x7fff)))
                .copied()
                .unwrap_or(0)
                .to_le_bytes(),
        );
        Ok(())
    }
    fn cmd53_write(&mut self, f: u8, a: u32, b: &[u8]) -> Result<(), SdioError> {
        self.ops.push((53, f, a, b.len()));
        if self.fail_write {
            return Err(SdioError::HostError);
        }
        if f == 1 && b.len() == 4 && a & 0x8000 != 0 {
            let address = self.window | (a & 0x7fff);
            let value = u32::from_le_bytes(b.try_into().unwrap());
            if address == CORE + 0x20 {
                let old = self.words.get(&address).copied().unwrap_or(0);
                let raced = if value == 0x20 && self.reassert_change {
                    0x20
                } else {
                    0
                };
                self.words.insert(address, (old & !value) | raced);
            } else {
                self.words.insert(address, value);
            }
        }
        Ok(())
    }
    fn cmd53_read_fixed(&mut self, f: u8, a: u32, b: &mut [u8]) -> Result<(), SdioError> {
        self.ops.push((54, f, a, b.len()));
        if f != 2 || a != 0x8000 {
            return Err(SdioError::HostError);
        }
        for byte in b {
            *byte = self.rx.pop_front().unwrap_or(0);
        }
        Ok(())
    }
    fn cmd53_block_read(
        &mut self,
        _: u8,
        _: u32,
        _: u16,
        _: u16,
        _: &mut [u8],
    ) -> Result<(), SdioError> {
        Err(SdioError::Unsupported)
    }
    fn cmd53_block_write(
        &mut self,
        _: u8,
        _: u32,
        _: u16,
        _: u16,
        _: &[u8],
    ) -> Result<(), SdioError> {
        Err(SdioError::Unsupported)
    }
    fn enable_func(&mut self, f: u8) -> Result<(), SdioError> {
        self.enabled |= 1 << f;
        Ok(())
    }
    fn set_block_size(&mut self, f: u8, size: u16) -> Result<(), SdioError> {
        self.ops.push((55, f, 0, usize::from(size)));
        Ok(())
    }
}
fn smoke_cyw_sdio_bridge_real_backplane_and_burst() -> TestResult {
    let mut transport = SdioTransport::new(Host::default());
    if transport.prepare().is_err()
        || transport.write_backplane(CORE + 0x48, 0x12345678).is_err()
        || transport.read_backplane(CORE + 0x48) != Ok(0x12345678)
    {
        return TestResult::Fail("backplane CMD53 register access failed");
    }
    if transport.func.words.get(&(CORE + 0x48)) != Some(&0x12345678)
        || !transport.func.ops.contains(&(53, 1, 0x9048, 4))
    {
        return TestResult::Fail("backplane word flag/window missing");
    }
    transport.func.ops.clear();
    if transport
        .write_burst(Function::Backplane, 0, &[1; 1025])
        .is_err()
        || transport.func.ops.len() != 17
        || transport.func.ops[0] != (53, 1, 0, 64)
        || transport.func.ops[15] != (53, 1, 960, 64)
        || transport.func.ops[16] != (53, 1, 1024, 1)
        || transport.func.ops.iter().any(|op| op.3 > 64)
    {
        return TestResult::Fail("RAM burst not split within host byte count");
    }
    if transport.func.enabled != 2 {
        return TestResult::Fail("F1 preparation enabled wrong function");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_bridge_real_backplane_and_burst
);

fn smoke_cyw_sdio_fifo_readiness_padding_and_flow() -> TestResult {
    let mut transport = SdioTransport::new(Host::default());
    if transport.prepare().is_err() || transport.initialize_packets(CORE).is_err() {
        return TestResult::Fail("packet init");
    }
    let mut bytes = vec![0; super::super::runtime::MAX_PACKET];
    if transport.receive_packet(&mut bytes) != Ok(0) || transport.func.ops.iter().any(|v| v.0 == 54)
    {
        return TestResult::Fail("empty RX performed a FIFO command");
    }
    let mut frame = vec![0x55; 600];
    frame[..4].copy_from_slice(&[0x58, 2, 0xa7, 0xfd]);
    transport.func.rx.extend(frame.iter().copied());
    transport.func.words.insert(CORE + 0x20, 1 << 6);
    if transport.receive_packet(&mut bytes) != Ok(600) || bytes[..600] != frame {
        return TestResult::Fail("F2 header/remainder copied wrong extent");
    }
    if transport
        .func
        .ops
        .iter()
        .filter(|v| v.0 == 54)
        .copied()
        .collect::<Vec<_>>()
        != vec![
            (54, 2, 0x8000, 64),
            (54, 2, 0x8000, 512),
            (54, 2, 0x8000, 24),
        ]
    {
        return TestResult::Fail("RX did not use bounded fixed-address commands");
    }
    if transport.receive_packet(&mut bytes) != Ok(0) || transport.rx_pending {
        return TestResult::Fail("zero header did not drain indication");
    }
    transport.func.words.insert(CORE + 0x20, 0x30);
    let before = transport.func.ops.iter().filter(|v| v.1 == 2).count();
    if transport.transmit_packet(&frame) != Err(TransportError::Busy)
        || transport.failed
        || transport.func.ops.iter().filter(|v| v.1 == 2).count() != before
    {
        return TestResult::Fail("global flow control submitted data or poisoned retry");
    }
    transport.func.words.insert(CORE + 0x20, 0x20);
    transport.func.reassert_change = true;
    if transport.transmit_packet(&frame) != Err(TransportError::Busy)
        || transport.failed
        || transport.func.ops.iter().filter(|v| v.1 == 2).count() != before
    {
        return TestResult::Fail("raced flow-change ACK allowed FIFO TX before debounce");
    }
    transport.func.reassert_change = false;
    if transport.transmit_packet(&frame).is_err() {
        return TestResult::Fail("unblocked packet not sent");
    }
    let tx = transport
        .func
        .ops
        .iter()
        .filter(|v| v.0 == 53 && v.1 == 2)
        .copied()
        .collect::<Vec<_>>();
    if tx != vec![(53, 2, 0x8000, 512), (53, 2, 0x8200, 88)] {
        return TestResult::Fail("TX incremental CMD53 extent differs from Linux");
    }
    transport.func.fail_write = true;
    if transport.transmit_packet(&frame).is_ok() || !transport.failed {
        return TestResult::Fail("ambiguous TX failure permitted replay");
    }
    let count = transport.func.ops.len();
    if transport.transmit_packet(&frame) != Err(TransportError::NotReady)
        || transport.func.ops.len() != count
    {
        return TestResult::Fail("failed FIFO owner reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_fifo_readiness_padding_and_flow
);

fn smoke_cyw_sdio_claims_f1_f2_interrupts_and_rearms_after_service() -> TestResult {
    // No host line: the transport keeps polling.
    let mut polled = SdioTransport::new(Host::default());
    if polled.prepare().is_err()
        || polled.initialize_packets(CORE).is_err()
        || polled.interrupt().is_some()
    {
        return TestResult::Fail("interrupt wake without a host line");
    }
    // brcmf_sdiod_intr_register: claim F1 and F2 after hostintmask.
    let mut transport = SdioTransport::new(Host {
        line: true,
        ..Host::default()
    });
    if transport.prepare().is_err() || transport.initialize_packets(CORE).is_err() {
        return TestResult::Fail("packet init");
    }
    let Some(signal) = transport.interrupt() else {
        return TestResult::Fail("host line did not produce a wake source");
    };
    if transport.func.claimed != Some(0b110) {
        return TestResult::Fail("F1/F2 card interrupts not claimed");
    }
    let seen = signal.count();
    (transport.func.notify.as_ref().unwrap())();
    if signal.count() != seen + 1 {
        return TestResult::Fail("card interrupt did not raise the owner wake");
    }
    transport.interrupt_serviced();
    if transport.func.rearmed != 1 {
        return TestResult::Fail("serviced interrupt was not rearmed");
    }
    transport.failed = true;
    transport.interrupt_serviced();
    if transport.func.rearmed != 1 {
        return TestResult::Fail("failed transport rearmed its line");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_claims_f1_f2_interrupts_and_rearms_after_service
);

fn sleep_host(sr_control1: u32) -> Host {
    let mut host = Host {
        line: true,
        sleep_model: true,
        ..Host::default()
    };
    host.words.insert(0x1800_0604, 0x14); // PMU rev 20
    host.words.insert(0x1800_0508, sr_control1);
    host
}
fn spin_ms(ms: u64) {
    narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
}
fn smoke_cyw_sdio_save_restore_idle_sleep_matches_linux() -> TestResult {
    // Not SR-capable (sr_control1 0), KSO-less core, or no card interrupt.
    let mut plain = SdioTransport::new(sleep_host(0));
    if plain.prepare().is_err()
        || plain.initialize_packets(CORE).is_err()
        || plain.initialize_sleep(13) != Ok(false)
    {
        return TestResult::Fail("non-SR chip enabled idle sleep");
    }
    let mut old = SdioTransport::new(sleep_host(1));
    if old.prepare().is_err()
        || old.initialize_packets(CORE).is_err()
        || old.initialize_sleep(11) != Ok(false)
    {
        return TestResult::Fail("pre-KSO SDIO core enabled idle sleep");
    }
    let mut polled = SdioTransport::new(Host {
        line: false,
        ..sleep_host(1)
    });
    if polled.prepare().is_err()
        || polled.initialize_packets(CORE).is_err()
        || polled.initialize_sleep(13) != Ok(false)
    {
        return TestResult::Fail("polled bus enabled idle sleep");
    }
    // brcmf_sdio_kso_init + brcmf_sdio_sr_init.
    let mut transport = SdioTransport::new(sleep_host(1));
    if transport.prepare().is_err()
        || transport.initialize_packets(CORE).is_err()
        || transport.initialize_sleep(13) != Ok(true)
    {
        return TestResult::Fail("SR-capable chip did not enable idle sleep");
    }
    let reg =
        |t: &SdioTransport<Host>, f: u8, a: u32| t.func.regs.get(&(f, a)).copied().unwrap_or(0);
    if reg(&transport, 1, 0x1001f) & 1 == 0
        || reg(&transport, 1, 0x1001e) & 2 == 0
        || reg(&transport, 0, 0xf0) != 6
        || reg(&transport, 1, 0x1000e) != 2
    {
        return TestResult::Fail("KSO/WAKEUPCTRL/CMD14/FORCE_HT setup differs from Linux");
    }
    // Not yet idle for BRCMF_WD_POLL x 2.
    transport.idle();
    if transport.asleep() {
        return TestResult::Fail("dongle slept before the idle timeout");
    }
    spin_ms(25);
    transport.idle();
    if !transport.asleep() || reg(&transport, 1, 0x1001f) & 1 != 0 {
        return TestResult::Fail("idle bus did not clear KSO");
    }
    // A backstop poll without a card interrupt must not wake the dongle.
    let mut bytes = vec![0; super::super::runtime::MAX_PACKET];
    let before = transport.func.ops.len();
    if transport.receive_packet(&mut bytes) != Ok(0)
        || !transport.asleep()
        || transport.func.ops.len() != before
    {
        return TestResult::Fail("backstop poll woke a sleeping dongle");
    }
    // A card interrupt wakes it (KSO + DEVON, HT available).
    (transport.func.notify.as_ref().unwrap())();
    if transport.receive_packet(&mut bytes) != Ok(0)
        || transport.asleep()
        || reg(&transport, 1, 0x1001f) & 3 != 3
    {
        return TestResult::Fail("card interrupt did not wake the dongle");
    }
    // Transmit always wakes.
    spin_ms(25);
    transport.idle();
    let mut frame = vec![0; 64];
    frame[..4].copy_from_slice(&[64, 0, !64u8, 0xff]);
    if !transport.asleep() || transport.transmit_packet(&frame).is_err() || transport.asleep() {
        return TestResult::Fail("transmit did not wake the dongle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_save_restore_idle_sleep_matches_linux
);
