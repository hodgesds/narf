//! Full command/PCM paths against a memory-backed HDA controller.
use super::*;
use alloc::boxed::Box;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_drivers_sound::hardware::PcmDevice;
use narf_kernel_test::{kernel_test_in, TestResult};

static MODEL: IrqSafeSpinLock<usize> = IrqSafeSpinLock::new(0);
static REGISTERED: AtomicBool = AtomicBool::new(false);
struct Model {
    mmio: bar::MmioRegion,
    corb: u16,
    rirb: u16,
    cpu: usize,
    commands: usize,
    verbs: Vec<u32>,
    stall: bool,
    supports_32: bool,
    /// Answer as an AMD GPU HDMI codec instead of the Realtek analog one.
    ati: bool,
    /// ATI: a surround monitor is on pin 3 (presence and ELD valid).
    sink: bool,
    /// ATI: pin 5 is a connected (but empty) second port.
    second_port: bool,
    /// ATI ELD emulation indices last written by 0x780 / 0x776.
    sink_index: u32,
    descriptor: u32,
    /// ATI HBR control on pin 3: capable, initially enabled.
    hbr: u32,
    /// Answer as the RX 6750 XT's codec (`navi22_response`) instead.
    navi22: bool,
    /// Navi22: the port (Azalia endpoint) whose sink the display enabled.
    sink_port: u8,
}
impl Model {
    fn step(&mut self) {
        if self.stall {
            return;
        }
        // SAFETY: all MMIO and DMA addresses here belong to the fixture.
        unsafe {
            self.mmio.write8(REG_RIRBSTS, 0);
            self.mmio.write8(REG_CORBSTS, 0);
            let cp = (self.mmio.read32(REG_CORBUBASE) as u64) << 32
                | self.mmio.read32(REG_CORBLBASE) as u64;
            let rp = (self.mmio.read32(REG_RIRBUBASE) as u64) << 32
                | self.mmio.read32(REG_RIRBLBASE) as u64;
            if cp == 0 || rp == 0 || self.mmio.read8(REG_CORBCTL) & 2 == 0 {
                return;
            }
            let wp = self.mmio.read16(REG_CORBWP) & 255;
            while self.corb != wp {
                self.corb = (self.corb + 1) & 255;
                let command = narf_memory::PhysAddr::new(cp)
                    .kernel_ptr::<u32>()
                    .add(self.corb as usize)
                    .read_volatile();
                self.commands += 1;
                self.verbs.push(command);
                // Interleave an unsolicited jack event with every reply. The
                // completion ring must not be indexed with the CORB pointer.
                let mut reply = if self.navi22 {
                    self.navi22_response(command)
                } else if self.ati {
                    self.ati_response(command)
                } else {
                    response(command)
                };
                if command == make_verb(0, 1, VERB_GET_PARAMETER | 0xa) && !self.supports_32 {
                    reply &= !(1 << 20);
                }
                for (reply, extra) in [(0xdeadbeef, 0x10), (reply, 0)] {
                    self.rirb = (self.rirb + 1) & 255;
                    let p = narf_memory::PhysAddr::new(rp)
                        .kernel_mut_ptr::<u32>()
                        .add(self.rirb as usize * 2);
                    p.write_volatile(reply);
                    p.add(1).write_volatile(extra);
                }
                self.mmio.write16(REG_RIRBWP, self.rirb);
                self.mmio.write16(REG_CORBRP, self.corb);
            }
        }
    }
}
fn response(command: u32) -> u32 {
    let nid = (command >> 20) as u8;
    let verb = (command >> 8) & 0xfff;
    let param = command as u8;
    match (nid, verb, param) {
        (0, 0xf00, 0) => 0x10ec0287,
        (0, 0xf00, 2) => 1,
        (0, 0xf00, 4) => 0x00010001,
        (1, 0xf00, 5) => 1,
        (1, 0xf00, 4) => 0x00020007,
        (1, 0xf00, 0xa) => (1 << 6) | (1 << 17) | (1 << 20),
        (1, 0xf00, 0xb) => 1,
        (_, 0xf00, 0xd | 0x12) => 0x80002010,
        (2, 0xf00, 9) => 1 | 4,
        (3, 0xf00, 9) => (1 << 20) | 0x101 | 2,
        (4, 0xf00, 9) => (2 << 20) | 0x101 | 6,
        (5..=7, 0xf00, 9) => (4 << 20) | 0x101 | 4,
        (8, 0xf00, 9) => (3 << 20) | 0x101 | 2,
        (3..=6, 0xf00, 0xe) => 1,
        (8, 0xf00, 0xe) => 2,
        (3, 0xf02, _) => 8,
        (8, 0xf02, _) => 0x0708, // cyclic first edge, then microphone
        (4, 0xf02, _) => 2,
        (5, 0xf02, _) => 4,
        (6, 0xf02, _) => 2,
        (5, 0xf00, 0xc) => 0x10010,
        (6, 0xf00, 0xc) => 0x1001c,
        (7, 0xf00, 0xc) => 0x1020,
        (5, 0xf1c, _) => (2 << 30) | (1 << 20) | 0x10,
        (6, 0xf1c, _) => (2 << 20) | 0x20,
        (7, 0xf1c, _) => (0xa << 20) | 0x30,
        _ => 0,
    }
}
impl Model {
    /// AMD GPU HDMI codec 0x1002aa01, revision 0x0700 (rev3+): AFG 1, ports
    /// as converter/pin pairs 2/3 and 4/5; pin 5 has no physical connection
    /// unless `second_port`. With `sink`, pin 3 carries a monitor whose
    /// Azalia endpoint the display driver filled: 7.1 LPCM (16/20/24-bit,
    /// stereo at more rates), 5.1 AC-3, FL/FR LFE FC RL/RR RLC/RRC, named
    /// "DELL", video 40 ms behind audio.
    fn ati_response(&mut self, command: u32) -> u32 {
        let nid = (command >> 20) as u8;
        let verb = (command >> 8) & 0xfff;
        let param = command as u8;
        match (nid, verb, param) {
            (0, 0xf00, 0) => 0x1002aa01,
            (0, 0xf00, 2) => 0x0010_0700,
            (0, 0xf00, 4) => 0x00010001,
            (1, 0xf00, 5) => 1,
            (1, 0xf00, 4) => 0x00020004,
            (2 | 4, 0xf00, 9) => 0x201, // digital stereo Audio Output
            (3 | 5, 0xf00, 9) => (4 << 20) | 0x301 | 4, // digital pin, out amp
            (3 | 5, 0xf00, 0xc) => 0x94, // HDMI, output, presence detect
            (3 | 5, 0xf00, 0xe) => 1,
            (3, 0xf02, _) => 2,
            (5, 0xf02, _) => 4,
            (_, 0xf00, 0x12) => 0x80000000,    // mute-only output amp
            (3, 0xf1c, _) => (5 << 20) | 0x10, // Digital Other Out, jack
            (5, 0xf1c, _) if self.second_port => (5 << 20) | 0x20,
            (5, 0xf1c, _) => (1 << 30) | (5 << 20) | 0x20, // no physical connection
            (3, 0xf7c, _) => self.hbr,
            (3, 0x77c, value) => {
                self.hbr = u32::from(value);
                0
            }
            (2, 0xf0d, _) => 0x0200,
            (3, 0xf09, _) if self.sink => 0xc000_0000,
            (3, 0xf70, _) if self.sink => 0x100 | 0x4f,
            (3, 0x780, index) => {
                self.sink_index = u32::from(index);
                0
            }
            (3, 0xf81, _) if self.sink => match self.sink_index {
                0 => 0x10ac,
                1 => 0x4321,
                2 => 4,
                3 => 0x1122_3344,
                4 => 0x5566_7788,
                i @ 5..=8 => u32::from(b"DELL"[i as usize - 5]),
                _ => 0,
            },
            (3, 0x776, coding) => {
                self.descriptor = u32::from(coding >> 3);
                0
            }
            (3, 0xf76, _) if self.sink => match self.descriptor {
                1 => 0x7f07_070f,
                2 => 0x0050_0715,
                _ => 0,
            },
            (3, 0xf7b, _) if self.sink => 0x0b15,
            _ => 0,
        }
    }
}
/// The Azalia endpoint words `amdgpu_dcn30_audio` writes for a 7.1 LPCM +
/// 5.1 AC-3 "DELL" sink at 1080p (its register-model test asserts the same
/// values): AUDIO_DESCRIPTOR0..13, LIPSYNC, SINK_INFO0..8.
const DCN30_DESCRIPTORS: [u32; 14] = [0x7f07_7f07, 0x0050_0705, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DCN30_LIPSYNC: u32 = 21 | 1 << 8;
const DCN30_SINK_INFO: [u32; 9] = [
    0xac10 | 0x4321 << 16,
    5,
    0x5558_859e,
    0x0d98_9449,
    0x4c4c_4544, // "DELL"
    0,
    0,
    0,
    0,
];
impl Model {
    /// The ATI R6xx HDMI codec on the RX 6750 XT's 03:00.1 as the host
    /// reports it (/proc/asound codec#0): 0x1002aa01 revision 0x100800, AFG
    /// 1, six ports as converter/pin pairs 2/3 .. 0xc/0xd (wcaps 0x221 and
    /// 0x400381, pincap 0x94, one connection each, Pin Default 0x185600f0:
    /// a jack, Digital Out, HDMI). Pin `3 + 2 * e` is Azalia endpoint `e`.
    /// With `sink`, endpoint `sink_port` carries what DCN3.0 programmed:
    /// sense presence + ELD valid, and the ATI ELD verbs reflect the
    /// endpoint registers (each descriptor word gains its coding type in
    /// bits 3..6, as the codec reports a SAD).
    fn navi22_response(&mut self, command: u32) -> u32 {
        let nid = (command >> 20) as u8;
        let verb = (command >> 8) & 0xfff;
        let param = command as u8;
        let pin = matches!(nid, 3..=0xd) && nid % 2 == 1;
        let converter = matches!(nid, 2..=0xc) && nid % 2 == 0;
        let live = self.sink && pin && nid == 3 + 2 * self.sink_port;
        match (nid, verb, param) {
            (0, 0xf00, 0) => 0x1002aa01,
            (0, 0xf00, 2) => 0x0010_0800,
            (0, 0xf00, 4) => 0x00010001,
            (1, 0xf00, 5) => 1,
            (1, 0xf00, 4) => 0x0002_000c,
            (_, 0xf00, 9) if converter => 0x221,
            (_, 0xf00, 9) if pin => 0x40_0381,
            (_, 0xf00, 0xc) if pin => 0x94,
            (_, 0xf00, 0xe) if pin => 1,
            (_, 0xf02, _) if pin => u32::from(nid - 1),
            (_, 0xf1c, _) if pin => 0x1856_00f0,
            (_, 0xf0d, _) if converter => 0x0200,
            (_, 0xf09, _) if live => 0xc000_0000,
            (_, 0xf70, _) if live => 0x100 | 0x4f,
            (_, 0x780, index) if pin => {
                self.sink_index = u32::from(index);
                0
            }
            (_, 0xf81, _) if live => match self.sink_index {
                0 => DCN30_SINK_INFO[0] & 0xffff,
                1 => DCN30_SINK_INFO[0] >> 16,
                2 => DCN30_SINK_INFO[1],
                3 => DCN30_SINK_INFO[2],
                4 => DCN30_SINK_INFO[3],
                i @ 5..=22 => {
                    let byte = (i - 5) as usize;
                    DCN30_SINK_INFO[4 + byte / 4] >> (8 * (byte % 4)) & 0xff
                }
                _ => 0,
            },
            (_, 0x776, coding) if pin => {
                self.descriptor = u32::from(coding >> 3);
                0
            }
            (_, 0xf76, _) if live => match self.descriptor {
                c @ 1..=14 if DCN30_DESCRIPTORS[c as usize - 1] != 0 => {
                    DCN30_DESCRIPTORS[c as usize - 1] | c << 3
                }
                _ => 0,
            },
            (_, 0xf7b, _) if live => DCN30_LIPSYNC,
            (_, 0xf7c, _) if pin => self.hbr,
            (_, 0x77c, value) if pin => {
                self.hbr = u32::from(value);
                0
            }
            _ => 0,
        }
    }
}
fn pump() {
    let model = MODEL.lock();
    if *model != 0 {
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        let model = unsafe { &mut *(*model as *mut Model) };
        if model.cpu == narf_lib::percpu::current_cpu() {
            model.step();
        }
    }
}
struct Fixture {
    controller: Option<Arc<IntelHda>>,
    model: Box<Model>,
    _mmio: DmaBuffer,
}
impl Fixture {
    fn new() -> Result<Self, &'static str> {
        Self::new_with(false)
    }
    fn new_with(noncoherent: bool) -> Result<Self, &'static str> {
        Self::with(noncoherent, false)
    }
    fn with(noncoherent: bool, ati: bool) -> Result<Self, &'static str> {
        Self::build(noncoherent, ati, false)
    }
    /// The AMD codec with both ports physically connected.
    fn two_ports() -> Result<Self, &'static str> {
        Self::build(true, true, true)
    }
    fn build(noncoherent: bool, ati: bool, second_port: bool) -> Result<Self, &'static str> {
        Self::build_model(noncoherent, ati, second_port, false)
    }
    /// The RX 6750 XT's HD-Audio function: 1002:ab28 runs without snoop.
    fn navi22() -> Result<Self, &'static str> {
        Self::build_model(
            super::super::ati_hdmi_noncoherent(0x1002, 0xab28),
            true,
            false,
            true,
        )
    }
    fn build_model(
        noncoherent: bool,
        ati: bool,
        second_port: bool,
        navi22: bool,
    ) -> Result<Self, &'static str> {
        let memory = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "mmio alloc")?;
        let mmio = bar::MmioRegion {
            phys: memory.phys_addr(),
            virt: memory.cpu_mut_ptr::<u8>() as u64,
            len: 4096,
            kind: bar::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            mmio.write16(REG_GCAP, 0x1101);
            mmio.write16(REG_STATESTS, 1);
            mmio.write8(REG_CORBSIZE, 0x40);
            mmio.write8(REG_RIRBSIZE, 0x40);
        }
        let mut fixture = Self {
            controller: None,
            _mmio: memory,
            model: Box::new(Model {
                mmio,
                corb: 0,
                rirb: 0,
                cpu: narf_lib::percpu::current_cpu(),
                commands: 0,
                verbs: Vec::new(),
                stall: false,
                supports_32: true,
                ati,
                sink: false,
                second_port,
                sink_index: 0,
                descriptor: 0,
                hbr: 0x11,
                navi22,
                sink_port: 0,
            }),
        };
        *MODEL.lock() = &mut *fixture.model as *mut Model as usize;
        if !REGISTERED.swap(true, Ordering::AcqRel) {
            narf_scheduler::sleep_pumps::register_nested_only(pump);
        }
        fixture.controller = Some(Arc::new(
            // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
            unsafe { IntelHda::initialize(mmio, noncoherent) }.map_err(|_| "controller init")?,
        ));
        Ok(fixture)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.controller.take();
        *MODEL.lock() = 0;
    }
}
fn native_hda_pcm_and_unsolicited() -> TestResult {
    pcm_case(false)
}
kernel_test_in!("audio/hda", native_hda_pcm_and_unsolicited);
/// AMD GPU HD-Audio does not snoop: the same command, playback and capture
/// paths with explicit cache maintenance must behave identically.
fn native_hda_noncoherent_pcm_matches_coherent() -> TestResult {
    pcm_case(true)
}
kernel_test_in!("audio/hda", native_hda_noncoherent_pcm_matches_coherent);
fn pcm_case(noncoherent: bool) -> TestResult {
    let mut fixture = match Fixture::new_with(noncoherent) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    if dev.codecs()[0].vendor_id != 0x10ec0287 || dev.outputs.len() != 2 || dev.input.is_none() {
        return TestResult::Fail("codec discovery and reverse ADC path");
    }
    if dev.input.as_ref().unwrap().nodes.chain != alloc::vec![8] {
        return TestResult::Fail("ADC selector path and cycle rejection");
    }
    let card = super::super::stream::Card(dev.clone());
    let mut playback = match card.open(false, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("open"),
    };
    if card.open(false, 0).is_ok() {
        return TestResult::Fail("exclusive lease");
    }
    fixture.model.supports_32 = false;
    let mut unsupported = super::super::stream::default_params();
    unsupported.format = narf_drivers_sound::format::SampleFormat::S32LE;
    if playback.configure(unsupported).is_ok() || playback.prepare().is_ok() {
        return TestResult::Fail("codec format rejection must not leave a startable stream");
    }
    if playback
        .configure(super::super::stream::default_params())
        .is_err()
        || playback.prepare().is_err()
    {
        return TestResult::Fail("configure playback");
    }
    if dev.streams[0].lock().ring.as_ref().map(|r| r.noncoherent) != Some(noncoherent) {
        return TestResult::Fail("ring coherency follows the controller");
    }
    use narf_drivers_sound::mixer::{ControlId, ControlKind, ControlValue};
    let mute = ControlId {
        index: 1,
        kind: ControlKind::MasterMute,
    };
    if card
        .set_control(mute, ControlValue::boolean(false))
        .is_err()
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 5, VERB_SET_PIN_WIDGET_CONTROL))
        || card.get_control(mute) != Ok(ControlValue::boolean(false))
        || card.set_control(mute, ControlValue::boolean(true)).is_err()
    {
        return TestResult::Fail("master control must program physical speaker pins");
    }
    let data = alloc::vec![0x5a; 16384];
    if playback.write(&data) != Ok(data.len())
        || playback.write(&[0; 4]) != Ok(0)
        || playback.start().is_err()
    {
        return TestResult::Fail("DMA start or ring backpressure");
    }
    // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
    unsafe {
        dev.bar0
            .write32(sd_base(dev.output_stream_idx()) + SD_LPIB, 512);
    }
    if playback.pointer() != 128 || playback.write(&[0x6b; 512]) != Ok(512) {
        return TestResult::Fail("DMA reclaim");
    }
    if playback.stop().is_err() {
        return TestResult::Fail("DMA stop");
    }
    drop(playback);
    let mut capture = match card.open(true, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("capture open"),
    };
    if capture
        .configure(super::super::stream::default_params())
        .is_err()
        || capture.prepare().is_err()
        || capture.start().is_err()
    {
        return TestResult::Fail("capture configure");
    }
    {
        let state = dev.streams[1].lock();
        let ring = state.ring.as_ref().unwrap();
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            core::ptr::write_bytes(ring.data.cpu_mut_ptr::<u8>(), 0x31, 512);
            dev.bar0.write32(sd_base(0) + SD_LPIB, 512);
        }
    }
    let mut out = [0; 512];
    if capture.read(&mut out) != Ok(512) || out != [0x31; 512] || capture.read(&mut out) != Ok(0) {
        return TestResult::Fail("capture only reports completed bytes");
    }
    TestResult::Pass
}

fn native_hda_command_cancellation() -> TestResult {
    let mut fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    fixture.model.stall = true;
    {
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        let mut future = pin!(unsafe { dev.send_verb_async(make_verb(0, 0, VERB_GET_PARAMETER)) });
        let mut cx = Context::from_waker(Waker::noop());
        if !matches!(future.as_mut().poll(&mut cx), Poll::Pending) {
            return TestResult::Fail("command should wait");
        }
    }
    if !dev.irq.failed.load(Ordering::Acquire)
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        || unsafe { dev.send_verb(0) } != Err(HdaError::DeviceFailed)
    {
        return TestResult::Fail("cancelled command must poison transport");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_command_cancellation);

fn native_hda_ati_hdmi_controllers_run_without_snoop() -> TestResult {
    use super::super::ati_hdmi_noncoherent;
    // Linux's ATI HDMI NS preset; the generic-class Radeon 0x1640 and Intel
    // controllers keep snooping.
    if !ati_hdmi_noncoherent(0x1002, 0xab40)
        || !ati_hdmi_noncoherent(0x1002, 0xaaa0)
        || ati_hdmi_noncoherent(0x1002, 0x1640)
        || ati_hdmi_noncoherent(0x8086, 0xab40)
    {
        return TestResult::Fail("ATI HDMI NS table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_ati_hdmi_controllers_run_without_snoop
);

fn native_hda_ati_hdmi_port_streams_stereo_like_atihdmi() -> TestResult {
    let fixture = match Fixture::with(true, true) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    // One connected HDMI port (pin 3 via converter 2); no analog paths.
    if dev.codecs()[0].vendor_id != 0x1002aa01
        || dev.outputs.len() != 1
        || dev.outputs[0].nodes.pin_nid != 3
        || dev.outputs[0].nodes.converter_nid != 2
        || dev.input.is_some()
    {
        return TestResult::Fail("HDMI port discovery");
    }
    let card = super::super::stream::Card(dev.clone());
    let Ok(mut playback) = card.open(false, 0) else {
        return TestResult::Fail("open");
    };
    let first = fixture.model.verbs.len();
    if playback
        .configure(super::super::stream::default_params())
        .is_err()
        || playback.prepare().is_err()
    {
        return TestResult::Fail("configure HDMI playback");
    }
    let verbs = &fixture.model.verbs[first..];
    let at = |v: u32| verbs.iter().position(|x| *x == v);
    let expected = [
        make_verb(0, 3, 0x77200), // downmix info 0
        make_verb(0, 3, 0x78901), // per-channel remap mode
        make_verb(0, 2, 0x72d01), // two channels
        make_verb(0, 3, 0x77701), // slot 0 <- channel 0
        make_verb(0, 3, 0x78511), // slot 1 <- channel 1
        make_verb(0, 3, 0x77800), // slot 2 off
        make_verb(0, 3, 0x78800), // slot 7 off
        make_verb(0, 3, 0x77100), // channel allocation 0 (FL FR)
        make_verb(0, 2, 0x770b4), // ramp rate 180
        make_verb(0, 3, 0x77c01), // HBR off, capability kept
        make_verb(0, 2, 0x70d01), // DIGEN
    ];
    let positions: Vec<Option<usize>> = expected.iter().map(|v| at(*v)).collect();
    if positions.iter().any(Option::is_none)
        || at(make_verb(0, 3, VERB_SET_PIN_WIDGET_CONTROL | 0x40)).is_none()
    {
        return TestResult::Fail("atihdmi prepare verbs");
    }
    // Channel allocation precedes the stream format and tag, as Linux's
    // prepare runs the infoframe setup before setup_stream.
    let format = verbs
        .iter()
        .position(|v| *v >> 20 == 2 && (*v >> 16) & 0xf == 2);
    if format.is_none_or(|f| positions[7].is_some_and(|ca| ca > f)) {
        return TestResult::Fail("allocation before format");
    }
    if dev.streams[0].lock().ring.as_ref().map(|r| r.noncoherent) != Some(true) {
        return TestResult::Fail("ATI ring is non-snooping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_ati_hdmi_port_streams_stereo_like_atihdmi
);

/// The ELD a 7.1 "DELL" sink's Azalia endpoint produces through the ATI
/// emulation (get_eld_ati layout): 20 fixed bytes, the name, then the LPCM
/// SAD, its stereo-rate companion and the AC-3 SAD, padded to 4 bytes.
const DELL_ELD: [u8; 36] = [
    0x10, 0, 8, 0, 4, 0x30, 0x0a, 0x4f, //
    0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, //
    0xac, 0x10, 0x21, 0x43, b'D', b'E', b'L', b'L', //
    0x0f, 0x07, 0x07, 0x09, 0x7f, 0x07, 0x15, 0x07, 0x50, 0, 0, 0,
];

fn native_hda_hdmi_eld_and_channel_allocation_match_linux() -> TestResult {
    use super::super::hdmi::{
        active_channels, ati_slot_verb, channel_allocation, channel_mapping, parse_eld,
    };
    let Some(sink) = parse_eld(&DELL_ELD) else {
        return TestResult::Fail("parse a valid ELD");
    };
    if sink.spk_alloc != 0x4f || sink.channels_max != 8 || !sink.s32 {
        return TestResult::Fail("ELD speaker allocation, channels and sample size");
    }
    let mut eld = DELL_ELD;
    eld[7] = 0;
    if parse_eld(&eld).map(|s| s.spk_alloc) != Some(0xffff) {
        return TestResult::Fail("missing speaker allocation assumes every speaker");
    }
    for (byte, value) in [(0, 3 << 3), (4, 17), (5, 0)] {
        let mut eld = DELL_ELD;
        eld[byte] = value;
        if parse_eld(&eld).is_some() {
            return TestResult::Fail("bad version, name length or no SAD is invalid");
        }
    }
    if parse_eld(&DELL_ELD[..30]).is_some() {
        return TestResult::Fail("SAD past the buffer is invalid");
    }
    // hdmi_channel_allocation_spk_alloc_blk picks.
    for (spk, channels, ca) in [
        (0x4f, 2, 0x00),
        (0x09, 4, 0x08), // FL/FR RL/RR: surround40
        (0x07, 4, 0x03), // FL/FR LFE FC
        (0x0f, 6, 0x0b), // surround51
        (0x00, 6, 0x0b), // nothing matches: first 6-channel layout
        (0x4f, 8, 0x13), // surround71
        (0x2f, 8, 0x1f), // front-centre pair instead of rear-centre
    ] {
        if channel_allocation(spk, channels) != ca || active_channels(ca) != channels.max(2) {
            return TestResult::Fail("CEA channel allocation");
        }
    }
    // Linux's fixed table, and the generated map for a CA outside it.
    if channel_mapping(0x13) != [0x00, 0x11, 0x26, 0x37, 0x43, 0x52, 0x64, 0x75]
        || channel_mapping(0x04) != [0x00, 0x11, 0x24, 0xf2, 0xf3, 0xf5, 0xf6, 0xf7]
        || channel_mapping(0x1f) != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
    {
        return TestResult::Fail("slot mapping");
    }
    // atihdmi_pin_set_slot_channel, per-slot and paired.
    if ati_slot_verb(0x24, true) != Some((0x779, 0x21))
        || ati_slot_verb(0x37, true) != Some((0x788, 0x31))
        || ati_slot_verb(0xf5, true) != Some((0x787, 0))
        || ati_slot_verb(0x52, false) != Some((0x778, 0x41))
        || ati_slot_verb(0xf3, false) != Some((0x778, 0))
        || ati_slot_verb(0xf5, false).is_some()
    {
        return TestResult::Fail("ATI slot verbs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_hdmi_eld_and_channel_allocation_match_linux
);

fn native_hda_hdmi_sink_drives_eld_routing_and_surround() -> TestResult {
    use narf_drivers_sound::{
        format::{ChannelCount, SampleFormat},
        mixer::{ControlId, ControlKind, ControlValue},
    };
    let mut fixture = match Fixture::two_ports() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    if dev.outputs.len() != 2 || dev.hdmi.lock().len() != 2 {
        return TestResult::Fail("two HDMI ports");
    }
    let card = super::super::stream::Card(dev.clone());
    let jack = ControlId {
        index: 3,
        kind: ControlKind::HdmiJack,
    };
    let eld = ControlId {
        index: 4,
        kind: ControlKind::Eld,
    };
    if !card.controls().contains(&jack) || !card.controls().contains(&eld) {
        return TestResult::Fail("HDMI jack and ELD controls");
    }
    // No monitor yet: the converter's own limits.
    let Ok(playback) = card.open(false, 0) else {
        return TestResult::Fail("open without a sink");
    };
    if card.get_control(jack) != Ok(ControlValue::boolean(false))
        || card.get_control(eld) != Ok(ControlValue::bytes(&[]))
        || card.capabilities(false).channels.len() != 4
    {
        return TestResult::Fail("no sink: jack off, empty ELD, 8 channels");
    }
    drop(playback);
    fixture.model.sink = true;
    let Ok(mut playback) = card.open(false, 0) else {
        return TestResult::Fail("open with a sink");
    };
    if card.get_control(jack) != Ok(ControlValue::boolean(true))
        || card.get_control(eld) != Ok(ControlValue::bytes(&DELL_ELD))
        || card.control_info(eld).map(|i| i.channels) != Ok(DELL_ELD.len() as u8)
    {
        return TestResult::Fail("sink: jack on and the emulated ELD");
    }
    let caps = card.capabilities(false);
    if caps.channels
        != [
            ChannelCount::Stereo,
            ChannelCount::Quad,
            ChannelCount::Surround51,
            ChannelCount::Surround71,
        ]
        || !caps.formats.contains(&SampleFormat::S32LE)
    {
        return TestResult::Fail("7.1 sink capabilities");
    }
    // A steady sense does not re-read the ELD every poll.
    let reads = |m: &Model| {
        m.verbs
            .iter()
            .filter(|v| (*v >> 8) & 0xfff == 0xf70)
            .count()
    };
    let before = reads(&fixture.model);
    if dev.refresh_jacks().is_err() || reads(&fixture.model) != before {
        return TestResult::Fail("steady sense re-read the ELD");
    }
    let first = fixture.model.verbs.len();
    let mut params = super::super::stream::default_params();
    params.channels = ChannelCount::Surround71;
    if playback.configure(params).is_err() || playback.prepare().is_err() {
        return TestResult::Fail("configure 7.1");
    }
    let verbs = &fixture.model.verbs[first..];
    let expected = [
        make_verb(0, 2, 0x72d07), // eight channels
        // ALSA's 7.1 order FL FR RL RR FC LFE SL SR into CEA CA 0x13.
        make_verb(0, 3, 0x77701), // ch 0 -> slot 0
        make_verb(0, 3, 0x78511), // ch 1 -> slot 1
        make_verb(0, 3, 0x77a21), // ch 2 -> slot 6
        make_verb(0, 3, 0x78831), // ch 3 -> slot 7
        make_verb(0, 3, 0x78641), // ch 4 -> slot 3
        make_verb(0, 3, 0x77851), // ch 5 -> slot 2
        make_verb(0, 3, 0x77961), // ch 6 -> slot 4
        make_verb(0, 3, 0x78771), // ch 7 -> slot 5
        make_verb(0, 3, 0x77113), // CA 0x13
    ];
    let positions: Vec<Option<usize>> = expected
        .iter()
        .map(|v| verbs.iter().position(|x| x == v))
        .collect();
    if positions.iter().any(Option::is_none) || !positions.is_sorted() {
        return TestResult::Fail("7.1 channel count, slot map and allocation");
    }
    // The format carries eight channels; only the live port takes the
    // stream, the empty one is detached.
    if !verbs
        .iter()
        .any(|v| *v >> 20 == 2 && (*v >> 16) & 0xf == 2 && v & 0xf == 7)
        || !verbs.contains(&make_verb(0, 2, VERB_SET_CONVERTER_STREAM | 0x10))
        || !verbs.contains(&make_verb(0, 4, VERB_SET_CONVERTER_STREAM))
        || verbs.contains(&make_verb(0, 4, VERB_SET_CONVERTER_STREAM | 0x10))
    {
        return TestResult::Fail("7.1 format on the plugged port only");
    }
    // Unplug clears the jack and the ELD.
    fixture.model.sink = false;
    if dev.refresh_jacks().is_err()
        || card.get_control(jack) != Ok(ControlValue::boolean(false))
        || card.get_control(eld) != Ok(ControlValue::bytes(&[]))
    {
        return TestResult::Fail("unplug");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_hdmi_sink_drives_eld_routing_and_surround
);

fn native_hda_hdmi_chmap_and_iec958_helpers_match_linux() -> TestResult {
    use super::super::hdmi::{
        chmap_tlv, default_chmap, manual_allocation, paired_chmap_valid, parse_eld, slot_entries,
        spdif_ctls, spdif_status, Playback,
    };
    // snd_hdmi_eld_update_pcm_info's rate union over every SAD.
    let mut eld = DELL_ELD;
    if parse_eld(&eld).map(|s| s.rates) != Some(0x7f) {
        return TestResult::Fail("ELD rate union");
    }
    eld[28] = 0x07; // the stereo companion's rates
    if parse_eld(&eld).map(|s| s.rates) != Some(0x07) {
        return TestResult::Fail("ELD rates follow the SADs");
    }
    // convert_from_spdif_status / convert_to_spdif_status.
    for (status, ctls) in [
        (0x06, 0x20),     // non-audio, not copyright
        (0x0204, 0x0200), // category 2
        (0x8200, 0x0290), // copyright, original (LEVEL)
        (0x0d, 0x48),     // professional, 50/15 us
        (0x0f, 0x68),     // professional non-audio
    ] {
        if spdif_ctls(status) != ctls {
            return TestResult::Fail("IEC958 status -> DIG1/DIG2");
        }
    }
    if spdif_status(0x0200) != 0x0204
        || spdif_status(0x0290) != 0x8200
        || spdif_status(0x68) != 0x0f
        || Playback::from_converter(0x0200).status != 0x0204
        || Playback::from_converter(0x0200).ctls != 0x0201
    {
        return TestResult::Fail("DIG1/DIG2 -> IEC958 status");
    }
    // hdmi_manual_channel_allocation: ALSA positions FL=3 FR=4 RL=5 RR=6
    // FC=7 LFE=8 RLC=14 RRC=15; SL/SR (9/10) are not HDMI speakers.
    let surround = [3, 4, 5, 6, 7, 8, 14, 15];
    if manual_allocation(8, &surround) != Some(0x13)
        || manual_allocation(8, &[3, 4, 5, 6, 7, 8, 9, 10]) != Some(0x0b)
        || manual_allocation(8, &[3, 4, 0, 0, 0, 0, 0, 0]) != Some(0x00)
        || manual_allocation(8, &[3, 4, 21, 24, 0, 0, 0, 0]).is_some()
    {
        return TestResult::Fail("manual channel allocation");
    }
    let user = Playback {
        chmap: [4, 3, 5, 6, 7, 8, 14, 15],
        chmap_set: true,
        ..Playback::from_converter(0)
    };
    // hdmi_manual_setup_channel_mapping: each slot takes the stream
    // channel naming its speaker (slot 0 FL, 1 FR, 2 LFE, 3 FC, 4 RL, ...).
    if slot_entries(0x13, 8, &user) != [0x10, 0x01, 0x52, 0x43, 0x24, 0x35, 0x66, 0x77] {
        return TestResult::Fail("manual slot mapping");
    }
    // Non-PCM keeps stream order and ignores a user map.
    let raw = Playback {
        non_pcm: true,
        ..user
    };
    if slot_entries(0x13, 8, &raw) != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        || slot_entries(0x00, 2, &raw) != [0x00, 0x11, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]
    {
        return TestResult::Fail("non-PCM slot mapping");
    }
    // hdmi_setup_fake_chmap from the standard layouts.
    if default_chmap(0x13) != [3, 4, 14, 15, 7, 8, 5, 6]
        || default_chmap(0x00) != [3, 4, 0, 0, 0, 0, 0, 0]
        || default_chmap(0x0b) != [3, 4, 5, 6, 7, 8, 0, 0]
    {
        return TestResult::Fail("default channel map");
    }
    // atihdmi_paired_chmap_validate: whole pairs only, FC/LFE swapped.
    if !paired_chmap_valid(0x0b, &[3, 4, 5, 6, 7, 8, 0, 0])
        || paired_chmap_valid(0x0b, &[3, 4, 5, 6, 8, 7, 0, 0])
        || paired_chmap_valid(0x0b, &[4, 3, 5, 6, 7, 8, 0, 0])
        || !paired_chmap_valid(0x0b, &[5, 6, 3, 4, 7, 8, 0, 0])
    {
        return TestResult::Fail("paired channel-map validation");
    }
    // hdmi_chmap_ctl_tlv: FL/FR only, then FL/FR + LFE; pre-rev3 refuses
    // a three-channel layout (-ENODEV) and pairs the stereo one.
    if chmap_tlv(0x01, false) != Some(alloc::vec![0, 16, 0x102, 8, 3, 4])
        || chmap_tlv(0x03, false) != Some(alloc::vec![0, 36, 0x102, 8, 3, 4, 0x102, 12, 3, 4, 8])
        || chmap_tlv(0x01, true) != Some(alloc::vec![0, 16, 0x103, 8, 3, 4])
        || chmap_tlv(0x03, true).is_some()
    {
        return TestResult::Fail("channel-map TLV");
    }
    // Paired 4.0: RL/RR follow FL/FR with no N/A filler.
    if chmap_tlv(0x09, true) != Some(alloc::vec![0, 40, 0x103, 8, 3, 4, 0x103, 16, 3, 4, 5, 6]) {
        return TestResult::Fail("paired 4.0 TLV");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_hdmi_chmap_and_iec958_helpers_match_linux
);

/// Compressed passthrough the way Linux's ATI HDMI codec does it: the
/// IEC958 non-audio bit makes the next prepare an IEC 61937 stream (stream-
/// order slots, sink CA, no ramp, HBR for eight channels, TYPE bit in both
/// the converter and stream formats), and the channel map follows
/// hdmi_chmap_ctl_put's state rules.
fn native_hda_hdmi_passthrough_and_channel_map() -> TestResult {
    use narf_drivers_sound::{
        format::{pack_sdfmt, ChannelCount, SampleFormat, SampleRate},
        mixer::{ControlId, ControlKind, ControlValue},
        SoundError,
    };
    let mut fixture = match Fixture::two_ports() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    fixture.model.sink = true;
    fixture.model.hbr = 0x01;
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let id = |index, kind| ControlId { index, kind };
    let con = id(5, ControlKind::Iec958ConMask);
    let pro = id(6, ControlKind::Iec958ProMask);
    let status = id(7, ControlKind::Iec958Default);
    let switch = id(8, ControlKind::Iec958Switch);
    let chmap = id(9, ControlKind::ChannelMap);
    if [con, pro, status, switch, chmap]
        .iter()
        .any(|c| !card.controls().contains(c))
    {
        return TestResult::Fail("IEC958 and channel-map controls");
    }
    // The converter's DIG2 category 2, consumer, not copyright; enabled.
    if card.get_control(status) != Ok(ControlValue::iec958(&[0x04, 0x02]))
        || card.get_control(switch) != Ok(ControlValue::boolean(true))
        || card.get_control(con) != Ok(ControlValue::iec958(&[0x0f, 0xff]))
        || card.get_control(pro) != Ok(ControlValue::iec958(&[0x0f]))
        || card.set_control(con, ControlValue::iec958(&[0])).is_ok()
    {
        return TestResult::Fail("initial IEC958 state");
    }
    // The switch is DIGEN on every port's converter.
    let first = fixture.model.verbs.len();
    if card
        .set_control(switch, ControlValue::boolean(false))
        .is_err()
        || !fixture.model.verbs[first..].contains(&make_verb(0, 2, 0x70d00))
        || !fixture.model.verbs[first..].contains(&make_verb(0, 4, 0x70d00))
        || card.get_control(switch) != Ok(ControlValue::boolean(false))
        || card
            .set_control(switch, ControlValue::boolean(true))
            .is_err()
    {
        return TestResult::Fail("IEC958 switch");
    }
    // Non-audio status: DIG1 NONAUDIO | DIGEN and DIG2 category.
    let first = fixture.model.verbs.len();
    if card
        .set_control(status, ControlValue::iec958(&[0x06, 0x02]))
        .is_err()
        || !fixture.model.verbs[first..].contains(&make_verb(0, 2, 0x70d21))
        || !fixture.model.verbs[first..].contains(&make_verb(0, 2, 0x70e02))
        || card.get_control(status) != Ok(ControlValue::iec958(&[0x06, 0x02]))
    {
        return TestResult::Fail("IEC958 non-audio status");
    }
    // Without an open stream a channel map is accepted and ignored.
    if card
        .set_control(chmap, ControlValue::integers(&[4, 3, 0, 0, 0, 0, 0, 0]))
        .is_err()
        || card.get_control(chmap) != Ok(ControlValue::integers(&[0; 8]))
    {
        return TestResult::Fail("channel map without a stream");
    }
    let Ok(mut playback) = card.open(false, 0) else {
        return TestResult::Fail("open");
    };
    if card.capabilities(false).rates
        != [
            SampleRate::R44100,
            SampleRate::R48000,
            SampleRate::R88200,
            SampleRate::R96000,
            SampleRate::R176400,
            SampleRate::R192000,
        ]
    {
        return TestResult::Fail("HDMI rates from the ELD");
    }
    // HBR: 7.1 IEC 61937 at 192 kHz (TrueHD / DTS-HD MA framing).
    let mut params = super::super::stream::default_params();
    params.channels = ChannelCount::Surround71;
    params.rate = SampleRate::R192000;
    params.format = SampleFormat::S16LE;
    let first = fixture.model.verbs.len();
    if playback.configure(params).is_err() {
        return TestResult::Fail("configure passthrough");
    }
    let middle = fixture.model.verbs.len();
    if playback.prepare().is_err() {
        return TestResult::Fail("prepare passthrough");
    }
    // hw_params sets the codec up; prepare repeats it with HBR already on.
    if fixture.model.verbs[middle..]
        .iter()
        .any(|v| *v >> 20 == 3 && (*v >> 8) & 0xfff == 0x77c)
    {
        return TestResult::Fail("HBR rewritten unchanged");
    }
    let verbs = &fixture.model.verbs[first..middle];
    let expected = [
        make_verb(0, 2, 0x72d07),
        make_verb(0, 3, 0x77701), // ch 0 -> slot 0 ... in stream order
        make_verb(0, 3, 0x78511),
        make_verb(0, 3, 0x77821),
        make_verb(0, 3, 0x78631),
        make_verb(0, 3, 0x77941),
        make_verb(0, 3, 0x78751),
        make_verb(0, 3, 0x77a61),
        make_verb(0, 3, 0x78871),
        make_verb(0, 3, 0x77113), // the sink's 7.1 CA
        make_verb(0, 2, 0x77000), // no ramp for non-PCM
        make_verb(0, 3, 0x77c11), // HBR on
        make_verb(0, 2, 0x70d21),
    ];
    let positions: Vec<Option<usize>> = expected
        .iter()
        .map(|v| verbs.iter().position(|x| x == v))
        .collect();
    if positions.iter().any(Option::is_none) || !positions.is_sorted() {
        return TestResult::Fail("passthrough codec setup");
    }
    let verbs = &fixture.model.verbs[first..];
    let format = 0x8000 | u32::from(pack_sdfmt(params.format, params.rate, params.channels));
    // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
    let sd_fmt = unsafe { dev.bar0.read16(sd_base(dev.output_stream_idx()) + SD_FMT) };
    if !verbs.contains(&make_verb(0, 2, VERB_SET_CONVERTER_FORMAT | format))
        || u32::from(sd_fmt) != format
        || verbs.contains(&make_verb(0, 4, VERB_SET_CONVERTER_STREAM | 0x10))
    {
        return TestResult::Fail("non-PCM converter and stream format");
    }
    if card.get_control(chmap) != Ok(ControlValue::integers(&[3, 4, 14, 15, 7, 8, 5, 6])) {
        return TestResult::Fail("default 7.1 channel map");
    }
    // Back to LPCM at the next prepare: HBR off, ramp, PCM format.
    if card
        .set_control(status, ControlValue::iec958(&[0x04, 0x02]))
        .is_err()
    {
        return TestResult::Fail("IEC958 audio status");
    }
    params.rate = SampleRate::R48000;
    let first = fixture.model.verbs.len();
    if playback.configure(params).is_err() || playback.prepare().is_err() {
        return TestResult::Fail("configure LPCM");
    }
    let verbs = &fixture.model.verbs[first..];
    let format = u32::from(pack_sdfmt(params.format, params.rate, params.channels));
    // SAFETY: as above.
    let sd_fmt = unsafe { dev.bar0.read16(sd_base(dev.output_stream_idx()) + SD_FMT) };
    if !verbs.contains(&make_verb(0, 3, 0x77c01))
        || !verbs.contains(&make_verb(0, 2, 0x770b4))
        || !verbs.contains(&make_verb(0, 2, VERB_SET_CONVERTER_FORMAT | format))
        || u32::from(sd_fmt) != format
    {
        return TestResult::Fail("LPCM after passthrough");
    }
    // A prepared stream takes a user map at once (FL/FR swapped).
    let swapped = [4, 3, 5, 6, 7, 8, 14, 15];
    let first = fixture.model.verbs.len();
    if card
        .set_control(chmap, ControlValue::integers(&swapped))
        .is_err()
        || card.get_control(chmap) != Ok(ControlValue::integers(&swapped))
    {
        return TestResult::Fail("set channel map");
    }
    let verbs = &fixture.model.verbs[first..];
    for v in [
        0x77711, 0x78501, 0x77851, 0x78641, 0x77921, 0x78731, 0x77113,
    ] {
        if !verbs.contains(&make_verb(0, 3, v)) {
            return TestResult::Fail("user channel map slots");
        }
    }
    // No CA names top-centre plus front-centre-high alone.
    if card.set_control(chmap, ControlValue::integers(&[3, 4, 21, 24, 0, 0, 0, 0]))
        != Err(SoundError::OutOfRange)
        || card.set_control(chmap, ControlValue::integers(&[3, 4, 37, 0, 0, 0, 0, 0]))
            != Err(SoundError::OutOfRange)
        || card.get_control(chmap) != Ok(ControlValue::integers(&swapped))
    {
        return TestResult::Fail("invalid channel maps");
    }
    let Some(tlv) = card.control_tlv(chmap).ok() else {
        return TestResult::Fail("channel-map TLV");
    };
    let surround71 = [0x102, 32, 3, 4, 8, 7, 5, 6, 14, 15];
    if tlv[..2] != [0, (tlv.len() as u32 - 2) * 4]
        || tlv[2..6] != [0x102, 8, 3, 4]
        || !tlv.windows(10).any(|w| w == surround71)
    {
        return TestResult::Fail("7.1 sink channel-map TLV");
    }
    // Running: busy. Closing forgets the map.
    let data = alloc::vec![0; 16384];
    if playback.write(&data).is_err() || playback.start().is_err() {
        return TestResult::Fail("start");
    }
    if card.set_control(chmap, ControlValue::integers(&[3, 4, 5, 6, 7, 8, 14, 15]))
        != Err(SoundError::DeviceBusy)
    {
        return TestResult::Fail("channel map while running");
    }
    drop(playback);
    if card.get_control(chmap) != Ok(ControlValue::integers(&[0; 8])) {
        return TestResult::Fail("close resets the channel map");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_hdmi_passthrough_and_channel_map);

fn native_hda_navi22_binds_ab28_and_routes_the_dcn30_endpoint() -> TestResult {
    use super::super::{ati_hdmi_noncoherent, HDA_ATI_HDMI_NS_DEVICES};
    // 03:00.1 is bound as Linux binds it: AZX_DRIVER_ATIHDMI_NS, no snoop.
    if !HDA_ATI_HDMI_NS_DEVICES.contains(&0xab28) || !ati_hdmi_noncoherent(0x1002, 0xab28) {
        return TestResult::Fail("1002:ab28 ATI HDMI NS");
    }
    let mut fixture = match Fixture::navi22() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let codec = &dev.graphs[0];
    if dev.codecs()[0].vendor_id != 0x1002aa01
        || !crate::hda_codec::is_ati_hdmi(codec)
        || !crate::hda_codec::ati_hdmi_rev3(codec)
        || dev.input.is_some()
    {
        return TestResult::Fail("R6xx HDMI rev3+ codec");
    }
    // Six ports, pin 3 + 2e on converter 2 + 2e.
    let pins: Vec<(u8, u8)> = dev
        .outputs
        .iter()
        .map(|o| (o.nodes.pin_nid, o.nodes.converter_nid))
        .collect();
    let expected: Vec<(u8, u8)> = (0..6u8).map(|e| (3 + 2 * e, 2 + 2 * e)).collect();
    if pins != expected || dev.hdmi.lock().len() != 6 {
        return TestResult::Fail("six HDMI/DP ports");
    }
    // The display enabled endpoint 2 (DIG2): only pin 7 reports a monitor,
    // with the ELD built from DCN3.0's endpoint registers.
    fixture.model.sink_port = 2;
    fixture.model.sink = true;
    if dev.refresh_jacks().is_err() {
        return TestResult::Fail("jack refresh");
    }
    {
        let ports = dev.hdmi.lock();
        for (k, port) in ports.iter().enumerate() {
            if (k == 2) != (port.present && port.sink.is_some()) {
                return TestResult::Fail("presence on the endpoint's pin only");
            }
        }
        let Some(sink) = ports[2].sink.as_ref() else {
            return TestResult::Fail("ELD");
        };
        // 7.1 LPCM at every rate with 20/24-bit samples, FL/FR LFE FC
        // RL/RR RLC/RRC, "DELL" plus the NUL Linux counts, video 40 ms late.
        if sink.channels_max != 8
            || !sink.s32
            || sink.rates != 0x7f
            || sink.spk_alloc != 0x4f
            || sink.eld[4] & 0x1f != 5
            || sink.eld[20..24] != *b"DELL"
            || sink.eld[6] != 20
        {
            return TestResult::Fail("ELD contents");
        }
    }
    if dev.routed_outputs() != [2] {
        return TestResult::Fail("routing to the live port");
    }
    // Playback goes to converter 6 only.
    let card = super::super::stream::Card(dev.clone());
    let Ok(mut playback) = card.open(false, 0) else {
        return TestResult::Fail("open");
    };
    let first = fixture.model.verbs.len();
    if playback
        .configure(super::super::stream::default_params())
        .is_err()
        || playback.prepare().is_err()
    {
        return TestResult::Fail("prepare");
    }
    let verbs = &fixture.model.verbs[first..];
    if !verbs.contains(&make_verb(0, 6, VERB_SET_CONVERTER_STREAM | 0x10))
        || verbs.contains(&make_verb(0, 2, VERB_SET_CONVERTER_STREAM | 0x10))
        || verbs.contains(&make_verb(0, 0xc, VERB_SET_CONVERTER_STREAM | 0x10))
    {
        return TestResult::Fail("stream on the endpoint's converter only");
    }
    drop(playback);
    // The display disables the endpoint: the jack and ELD go away.
    fixture.model.sink = false;
    if dev.refresh_jacks().is_err() || dev.hdmi.lock().iter().any(|p| p.present) {
        return TestResult::Fail("unplug");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_navi22_binds_ab28_and_routes_the_dcn30_endpoint
);
