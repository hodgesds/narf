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
                let mut reply = if self.ati {
                    ati_response(command)
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
/// AMD GPU HDMI codec 0x1002aa01, revision 0x0700 (rev3+): AFG 1, ports as
/// converter/pin pairs 2/3 and 4/5; pin 5 has no physical connection.
fn ati_response(command: u32) -> u32 {
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
        (5, 0xf1c, _) => (1 << 30) | (5 << 20) | 0x20, // no physical connection
        (3, 0xf7c, _) => 0x11,             // HBR capable, left enabled
        (2, 0xf0d, _) => 0x0200,
        _ => 0,
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
