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
    /// Analog variant: add a line-in pin (nid 9) beside the mic pin
    /// and give the mic pin presence capability, so jack-driven
    /// capture-source switching has two sources to switch between.
    /// False keeps the default fixture byte-identical.
    line_in: bool,
    /// Analog variant: pin sense for the mic (7) / line-in (9) pins.
    mic_plugged: bool,
    line_plugged: bool,
    /// Analog variant: answer as an ALC256 codec (vendor
    /// 0x10ec0256) with codec subsystem id 0x10280d76 — the
    /// subsystem Linux itself matches on in
    /// `alc256_fixup_chromebook` — so the #776 coef-init path has
    /// a Realtek chip to fix up. The widget model stays the
    /// ALC287-shaped one; the fixture proves verb traffic +
    /// CodecInfo, not widget semantics.
    alc256: bool,
    /// Analog variant: answer as an ALC282 codec (vendor
    /// 0x10ec0282) so the #1496 full-table coef-init path has a
    /// chip to fix up.
    alc282: bool,
    /// Analog variant: answer as the given codec vendor id
    /// (0 = the default 0x10ec0287) — for the #776 remainder
    /// fixtures (ALC274/ALC700 parse-time updates, same-arm
    /// sibling IDs). The widget model stays the ALC287-shaped
    /// one; the fixture proves verb traffic + CodecInfo, not
    /// widget semantics.
    codec_id: u32,
    /// Analog variant: the default model's HP pin (nid 6) reports
    /// a plug present on GET_PIN_SENSE — for the #776 HP-tail
    /// tests' sense-plugged branch.
    hp_plugged: bool,
    /// Analog variant: answer as a Lenovo Yoga 7 2-in-1 16AKP10
    /// (ALC287, codec subsystem id 0x17aa391d — the subsystem
    /// Linux itself matches on in
    /// `alc287_fixup_yoga9_14iap7_bass_spk_pin`) with the Yoga's
    /// widget model, so the #1496 verified-quirk path has a
    /// machine to fix up.
    yoga9: bool,
    /// Last SET_COEF_INDEX payload per coef nid (0x20 / 0x53).
    coef_index: [(u8, u8); 2],
    /// Coef register file: (nid, index, value). Every coef reads
    /// 0 until written — like a codec fresh out of reset — unless
    /// the fixture pre-seeds it.
    coef: Vec<(u8, u16, u16)>,
}
impl Model {
    fn step(&mut self) {
        if self.stall {
            return;
        }
        // SAFETY: all MMIO and DMA addresses here belong to the fixture.
        unsafe {
            // A controller reset (reinit) leaves RIRBWP's reset bit
            // set in this plain-memory BAR until the model overwrites
            // it: the hardware CORB/RIRB pointers restarted at 0, so
            // the model's cursors must restart with them, or
            // post-reset verbs replay stale CORB slots and stale RIRB
            // replies. Real hardware resets its pointers on
            // controller reset; the model must observe the same.
            if self.mmio.read16(REG_RIRBWP) & (1 << 15) != 0 {
                self.corb = 0;
                self.rirb = 0;
            }
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
                } else if self.yoga9 {
                    self.yoga9_response(command)
                } else {
                    response(command)
                };
                if self.line_in && !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    let param = command as u8;
                    match (nid, verb, param) {
                        // Eight widgets (2..=9) instead of seven.
                        (1, 0xf00, 4) => reply = 0x00020008,
                        // Mic pin gains an input amp (Mic Boost) and
                        // presence capability; its sense follows the flag.
                        (7, 0xf00, 9) => reply = (4 << 20) | 0x101 | 6,
                        (7, 0xf00, 0xc) => reply = 0x1024,
                        (7, 0xf09, _) if self.mic_plugged => reply = 0xc000_0000,
                        // Line-in pin 9: input + presence caps, line
                        // class config, one connection (to the ADC
                        // selector), sense follows the flag.
                        (9, 0xf00, 9) => reply = (4 << 20) | 0x101 | 4,
                        (9, 0xf00, 0xc) => reply = 0x1024,
                        (9, 0xf00, 0xe) => reply = 1,
                        (9, 0xf1c, _) => reply = (0x8 << 20) | 0x40,
                        (9, 0xf02, _) => reply = 8,
                        (9, 0xf09, _) if self.line_plugged => reply = 0xc000_0000,
                        // The ADC selector reaches the line pin too,
                        // appended last so the mic trace is unchanged.
                        // Its list length is 3: the word below carries
                        // three entries, and length 2 would drop the
                        // line pin from the enumerated graph.
                        (8, 0xf00, 0xe) => reply = 3,
                        (8, 0xf02, _) => reply = 0x090708,
                        _ => {}
                    }
                }
                if self.alc256 && !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    let param = command as u8;
                    match (nid, verb, param) {
                        // ALC256 codec id + the Dell codec subsystem
                        // id Linux matches on in
                        // alc256_fixup_chromebook.
                        (0, 0xf00, 0) => reply = 0x10ec0256,
                        (0, 0xf00, 1) => reply = 0x10280d76,
                        _ => {}
                    }
                }
                if self.alc282 && !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    let param = command as u8;
                    // ALC282 codec id; the subsystem read stays
                    // 0 (unknown) — `alc282_init` is keyed on
                    // the chip, not on a subsystem id.
                    if (nid, verb, param) == (0, 0xf00, 0) {
                        reply = 0x10ec0282;
                    }
                }
                if self.codec_id != 0 && !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    let param = command as u8;
                    if (nid, verb, param) == (0, 0xf00, 0) {
                        reply = self.codec_id;
                    }
                }
                // Default-model HP pin (nid 6, HP Out with
                // presence capability) reports a plug present.
                if self.hp_plugged && !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    if nid == 6 && verb == 0xf09 {
                        reply = 0x8000_0000;
                    }
                }
                // Realtek coef registers (#1496): SET_COEF_INDEX
                // selects the index for the next SET_PROC_COEF
                // write / GET_PROC_COEF read on the same nid
                // (Linux `alc_read_coef_idx` /
                // `alc_write_coef_idx`). The model keeps the
                // selected index per nid and the written values,
                // so a masked read-modify-write update is
                // observable both in the recorded verbs and in
                // the register file it leaves behind. The 16-bit
                // coef value spans the verb field's low byte and
                // the payload byte, so the verb match masks to
                // the 4-bit verb id (0x500 / 0x400).
                if !self.ati && !self.navi22 {
                    let nid = (command >> 20) as u8;
                    let verb = (command >> 8) & 0xfff;
                    let payload = command as u8;
                    if verb & 0xf00 == 0x500 {
                        let index = (u16::from(verb as u8) << 8) | u16::from(payload);
                        self.set_coef_index(nid, index);
                    } else if verb & 0xf00 == 0x400 {
                        let value = (u16::from(verb as u8) << 8) | u16::from(payload);
                        self.write_coef(nid, value);
                    } else if verb == 0xc00 {
                        reply = u32::from(self.read_coef(nid));
                    }
                }
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
    /// Selected coef index for `nid` (0 if never selected).
    fn coef_selected(&self, nid: u8) -> u16 {
        self.coef_index
            .iter()
            .find(|(n, _)| *n == nid)
            .map(|(_, i)| u16::from(*i))
            .unwrap_or(0)
    }
    /// Read the coef value SET_COEF_INDEX last selected for `nid`.
    fn read_coef(&self, nid: u8) -> u16 {
        let index = self.coef_selected(nid);
        self.coef
            .iter()
            .find(|(n, i, _)| *n == nid && *i == index)
            .map(|(_, _, v)| *v)
            .unwrap_or(0)
    }
    /// Write `value` to the coef SET_COEF_INDEX last selected for `nid`.
    fn write_coef(&mut self, nid: u8, value: u16) {
        let index = self.coef_selected(nid);
        if let Some(slot) = self
            .coef
            .iter_mut()
            .find(|(n, i, _)| *n == nid && *i == index)
        {
            slot.2 = value;
        } else {
            self.coef.push((nid, index, value));
        }
    }
    /// Select the coef index for `nid`. Unknown coef nids keep
    /// index 0: the driver only ever indexes 0x20/0x53.
    fn set_coef_index(&mut self, nid: u8, index: u16) {
        if let Some(slot) = self.coef_index.iter_mut().find(|(n, _)| *n == nid) {
            slot.1 = index as u8;
        }
    }

    /// Lenovo Yoga 7 2-in-1 16AKP10 (ALC287, codec subsystem
    /// 0x17aa391d): the fixup's model, self-contained — it answers
    /// every verb `enumerate` and the probe path send, and 0 for
    /// the rest. The widget model is the fixup's own shape: DACs
    /// 0x02/0x03/0x06/0x08, speaker pins 0x14/0x17, HP pin 0x21.
    /// Model choices, not hardware facts (documented because the
    /// fixture must not be mistaken for a dump):
    /// - Pin 0x17's hardware list is {0x06, 0x08, 0x02, 0x03} —
    ///   DAC 0x06 first, matching the Linux reports that without
    ///   the fixup pin 0x17 lands on DAC 0x06 (which has no volume
    ///   control); pins 0x14/0x21 list their preferred DAC second,
    ///   so the preference machinery is load-bearing.
    /// - Pin 0x17's hardware config 0x411111f0 IS the real BIOS
    ///   value from the Linux patch description (reported as
    ///   unconnected); the quirk overrides it to 0x90170121.
    /// - The 0x06/0x08 "no volume" property is not modeled: no
    ///   NARF code reads it, so it cannot affect the assertions.
    /// - All other widget nids read caps 0 (phantom Audio Output
    ///   widgets with no connections); they create no paths.
    fn yoga9_response(&mut self, command: u32) -> u32 {
        let nid = (command >> 20) as u8;
        let verb = (command >> 8) & 0xfff;
        let param = command as u8;
        match (nid, verb, param) {
            (0, 0xf00, 0) => 0x10ec0287,
            (0, 0xf00, 1) => 0x17aa391d,
            (0, 0xf00, 2) => 1,
            (0, 0xf00, 4) => 0x00010001,
            (1, 0xf00, 5) => 1,
            (1, 0xf00, 4) => 0x00020020,
            (1, 0xf00, 0xa) => (1 << 6) | (1 << 17) | (1 << 20),
            (1, 0xf00, 0xb) => 1,
            (_, 0xf00, 0xd | 0x12) => 0x80002010,
            // DACs: stereo Audio Output with an output amp.
            (0x02 | 0x03 | 0x06 | 0x08, 0xf00, 9) => 1 | 4,
            // Speaker pins 0x14/0x17 and HP pin 0x21.
            (0x14 | 0x17 | 0x21, 0xf00, 9) => (4 << 20) | 0x101 | 4,
            (0x14 | 0x17 | 0x21, 0xf00, 0xc) => 0x10010,
            (0x14, 0xf00, 0xe) => 2,
            (0x17, 0xf00, 0xe) => 4,
            (0x21, 0xf00, 0xe) => 2,
            (0x14, 0xf02, _) => 0x0203,
            (0x17, 0xf02, _) => 0x03020806,
            (0x21, 0xf02, _) => 0x0302,
            (0x14, 0xf1c, _) => (2 << 30) | (1 << 20) | 0x10,
            (0x17, 0xf1c, _) => 0x411111f0,
            (0x21, 0xf1c, _) => (2 << 20) | 0x20,
            _ => 0,
        }
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
#[derive(Default)]
struct FixtureConfig {
    noncoherent: bool,
    ati: bool,
    second_port: bool,
    navi22: bool,
    line_in: bool,
    alc256: bool,
    alc282: bool,
    yoga9: bool,
    seed_alc256_coef: bool,
    codec_id: u32,
    hp_plugged: bool,
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
        Self::build_model(FixtureConfig {
            noncoherent,
            ati,
            second_port,
            ..Default::default()
        })
    }
    /// The analog codec with a line-in pin beside the mic pin, for
    /// jack-driven capture-source switching tests.
    fn line_in() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            line_in: true,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC256 (#776 coef-init fixture).
    fn alc256() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            alc256: true,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC256 with coef 0x46 pre-seeded to
    /// 0xF5A5 (#1496 RMW fixture): the masked update must preserve
    /// the bits outside its mask.
    fn alc256_seeded() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            alc256: true,
            seed_alc256_coef: true,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC282 (#1496 full-table coef-init fixture).
    fn alc282() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            alc282: true,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC282 with a headphone plugged
    /// (#776 HP-tail sense-plugged branch).
    fn alc282_plugged() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            alc282: true,
            hp_plugged: true,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC283 (#776 HP-tail fixture).
    fn alc283() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            codec_id: 0x10ec0283,
            ..Default::default()
        })
    }
    /// The analog codec as an ALC283 with a headphone plugged
    /// (#776 HP-tail sense-plugged branch).
    fn alc283_plugged() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            codec_id: 0x10ec0283,
            hp_plugged: true,
            ..Default::default()
        })
    }
    /// The analog codec as the given Realtek codec vendor id
    /// (#776 remainder fixtures: parse-time updates, sibling IDs).
    fn with_codec(codec_id: u32) -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            codec_id,
            ..Default::default()
        })
    }
    /// The analog codec as a Lenovo Yoga 7 2-in-1 16AKP10 (ALC287,
    /// subsystem 0x17aa391d; #1496 verified-quirk fixture).
    fn yoga9() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            yoga9: true,
            ..Default::default()
        })
    }
    /// The RX 6750 XT's HD-Audio function: 1002:ab28 runs without snoop.
    fn navi22() -> Result<Self, &'static str> {
        Self::build_model(FixtureConfig {
            noncoherent: super::super::ati_hdmi_noncoherent(0x1002, 0xab28),
            ati: true,
            navi22: true,
            ..Default::default()
        })
    }
    fn build_model(config: FixtureConfig) -> Result<Self, &'static str> {
        let FixtureConfig {
            noncoherent,
            ati,
            second_port,
            navi22,
            line_in,
            alc256,
            alc282,
            yoga9,
            seed_alc256_coef,
            codec_id,
            hp_plugged,
        } = config;
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
                line_in,
                mic_plugged: false,
                line_plugged: false,
                alc256,
                alc282,
                yoga9,
                codec_id,
                hp_plugged,
                coef_index: [(0x20, 0), (0x53, 0)],
                coef: if seed_alc256_coef {
                    alloc::vec![(crate::hda::quirks::COEF_NODE, 0x46, 0xF5A5)]
                } else {
                    Vec::new()
                },
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
    if dev.codecs()[0].vendor_id != 0x10ec0287
        || dev.outputs.len() != 2
        || dev.input.lock().is_none()
    {
        return TestResult::Fail("codec discovery and reverse ADC path");
    }
    if dev.input.lock().as_ref().unwrap().nodes.chain != alloc::vec![8] {
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
        || dev.input.lock().is_some()
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

/// A display publication hand-built to the ELD layout
/// `drivers/sound/src/display_audio.rs` documents (CEA-861-D §7.5):
/// version 2, no monitor name, one SAD, DisplayPort connection type.
/// Returns the valid ELD bytes plus the publication carrying them
/// (the LPCM summary fields are filled consistently, though the
/// consumer under test re-parses the ELD bytes rather than trusting
/// them).
fn display_publication(
    sad: [u8; 3],
    spk: u8,
    port_id: u64,
    lpcm: (u8, u8, u8),
) -> (
    Vec<u8>,
    narf_drivers_sound::display_audio::DisplayAudioPublication,
) {
    use narf_drivers_sound::display_audio::{DisplayAudioPublication, ELD_MAX_BYTES};
    let mut eld = [0u8; ELD_MAX_BYTES];
    eld[0] = 0x10; // ELD version 2, CEA-861-D
    eld[2] = 6; // (20 fixed + 0 name + 3 SAD) / 4 rounded up
    eld[4] = 0x60; // CEA-EDID version 3, MNL 0
    eld[5] = (1 << 4) | (1 << 2); // 1 SAD, DisplayPort
    eld[7] = spk;
    eld[8..16].copy_from_slice(&port_id.to_le_bytes());
    eld[16..20].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    eld[20..23].copy_from_slice(&sad);
    let bytes = eld[..23].to_vec();
    (
        bytes,
        DisplayAudioPublication {
            eld,
            eld_len: 23,
            lpcm_max_channels: lpcm.0,
            lpcm_sample_rates: lpcm.1,
            lpcm_bit_depths: lpcm.2,
            sad_count: 1,
        },
    )
}

fn native_hda_display_eld_exposes_jack_eld_and_limits() -> TestResult {
    use narf_drivers_sound::{
        display_audio::{clear_display_audio, publish_display_audio, DisplaySinkId},
        format::{ChannelCount, SampleFormat, SampleRate},
        mixer::{ControlId, ControlKind, ControlValue},
    };
    let fixture = match Fixture::two_ports() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let jack = ControlId {
        index: 3,
        kind: ControlKind::HdmiJack,
    };
    let eld = ControlId {
        index: 4,
        kind: ControlKind::Eld,
    };
    let id = DisplaySinkId(0xD1319);
    clear_display_audio(id);
    // Baseline: no monitor, no publication.
    if card.get_control(jack) != Ok(ControlValue::boolean(false))
        || card.get_control(eld) != Ok(ControlValue::bytes(&[]))
        || card.capabilities(false).channels.len() != 4
    {
        return TestResult::Fail("no sink: jack off, empty ELD, 8 channels");
    }
    // Publish one 2-channel / 48 kHz / 16-bit display ELD.
    let (eld_bytes, publication) = display_publication(
        [0x09, 0x04, 0x01],
        0x01,
        0x1111_2222_3333_4444,
        (2, 0x04, 0x01),
    );
    publish_display_audio(id, publication);
    if card.get_control(jack) != Ok(ControlValue::boolean(true))
        || card.get_control(eld) != Ok(ControlValue::bytes(&eld_bytes))
    {
        return TestResult::Fail("published ELD must drive jack and ELD controls");
    }
    let caps = card.capabilities(false);
    if caps.channels != [ChannelCount::Stereo]
        || caps.formats.contains(&SampleFormat::S32LE)
        || caps.rates != [SampleRate::R48000]
    {
        return TestResult::Fail("published ELD must gate channels, formats and rates");
    }
    // Clearing the publication restores the no-sink state.
    clear_display_audio(id);
    if card.get_control(jack) != Ok(ControlValue::boolean(false))
        || card.get_control(eld) != Ok(ControlValue::bytes(&[]))
        || card.capabilities(false).channels.len() != 4
    {
        return TestResult::Fail("cleared publication must restore the no-sink state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_display_eld_exposes_jack_eld_and_limits
);

fn native_hda_display_eld_does_not_override_live_codec_sink() -> TestResult {
    use narf_drivers_sound::{
        display_audio::{clear_display_audio, publish_display_audio, DisplaySinkId},
        mixer::{ControlId, ControlKind, ControlValue},
    };
    let mut fixture = match Fixture::two_ports() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let jack = ControlId {
        index: 3,
        kind: ControlKind::HdmiJack,
    };
    let eld = ControlId {
        index: 4,
        kind: ControlKind::Eld,
    };
    let id = DisplaySinkId(0xD131A);
    clear_display_audio(id);
    // A live codec sink drives jack and ELD first.
    fixture.model.sink = true;
    if dev.refresh_jacks().is_err()
        || card.get_control(jack) != Ok(ControlValue::boolean(true))
        || card.get_control(eld) != Ok(ControlValue::bytes(&DELL_ELD))
    {
        return TestResult::Fail("codec sink must drive jack and ELD first");
    }
    // An unrelated display publication must not override it: the
    // published bytes differ from the codec ELD, so a naive
    // display-first implementation would flip the ELD control here.
    let (_, publication) = display_publication(
        [0x09, 0x04, 0x01],
        0x01,
        0x1111_2222_3333_4444,
        (2, 0x04, 0x01),
    );
    publish_display_audio(id, publication);
    if card.get_control(eld) != Ok(ControlValue::bytes(&DELL_ELD))
        || card.capabilities(false).channels.len() != 4
    {
        return TestResult::Fail("unrelated publication must not override the codec sink");
    }
    clear_display_audio(id);
    if card.get_control(eld) != Ok(ControlValue::bytes(&DELL_ELD)) {
        return TestResult::Fail(
            "clearing the unrelated publication must not disturb the codec sink",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_display_eld_does_not_override_live_codec_sink
);

fn native_hda_display_eld_lowest_sink_id_wins() -> TestResult {
    use narf_drivers_sound::{
        display_audio::{clear_display_audio, publish_display_audio, DisplaySinkId},
        mixer::{ControlId, ControlKind, ControlValue},
    };
    let fixture = match Fixture::two_ports() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let eld = ControlId {
        index: 4,
        kind: ControlKind::Eld,
    };
    let hi = DisplaySinkId(0xD131A);
    let lo = DisplaySinkId(0xD1319);
    clear_display_audio(hi);
    clear_display_audio(lo);
    // Higher id published first, 2 channels; lower id second, 6.
    let (_, pub_2ch) = display_publication(
        [0x09, 0x04, 0x01],
        0x01,
        0x1111_2222_3333_4444,
        (2, 0x04, 0x01),
    );
    let (eld_6ch, pub_6ch) = display_publication(
        [0x0D, 0x14, 0x04],
        0x0F,
        0x5555_6666_7777_8888,
        (6, 0x14, 0x04),
    );
    publish_display_audio(hi, pub_2ch);
    publish_display_audio(lo, pub_6ch);
    if card.get_control(eld) != Ok(ControlValue::bytes(&eld_6ch)) {
        return TestResult::Fail("lowest sink id must win without a codec anchor");
    }
    clear_display_audio(hi);
    clear_display_audio(lo);
    if card.get_control(eld) != Ok(ControlValue::bytes(&[])) {
        return TestResult::Fail("clearing both publications must empty the ELD");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_display_eld_lowest_sink_id_wins);

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
        || dev.input.lock().is_some()
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

// ── Power management (#779) ──────────────────────────────────────────

fn native_hda_pm_quiesce_reinit_parks_and_restores() -> TestResult {
    let fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().iter().find(|c| c.afg_node_id.is_some()) else {
        return TestResult::Fail("fixture has no AFG codec");
    };
    let (addr, nid) = (codec.addr, codec.afg_node_id.unwrap());
    let d3 = make_verb(addr, nid, crate::hda_codec::verb::SET_POWER_STATE | 3);
    let d0 = make_verb(addr, nid, crate::hda_codec::verb::SET_POWER_STATE);
    let base = fixture.model.verbs.len();
    if dev.quiesce().is_err() {
        return TestResult::Fail("quiesce idle controller");
    }
    // SAFETY: Fixture owns the fake MMIO until all test leases drop.
    let (gctl, corbctl, rirbctl) = unsafe {
        (
            dev.bar0.read32(REG_GCTL),
            dev.bar0.read8(REG_CORBCTL),
            dev.bar0.read8(REG_RIRBCTL),
        )
    };
    if !dev.suspended.load(Ordering::Acquire)
        || gctl != 0
        || corbctl != 0
        || rirbctl != 0
        || !fixture.model.verbs[base..].contains(&d3)
    {
        return TestResult::Fail("quiesce parks engines and sends D3");
    }
    // Idempotent: a second quiesce is Ok and changes nothing.
    if dev.quiesce().is_err() || !dev.suspended.load(Ordering::Acquire) {
        return TestResult::Fail("quiesce idempotent");
    }
    let base = fixture.model.verbs.len();
    if dev.reinit().is_err() {
        return TestResult::Fail("reinit parked controller");
    }
    // SAFETY: Fixture owns the fake MMIO until all test leases drop.
    let (gctl, corbctl, rirbctl) = unsafe {
        (
            dev.bar0.read32(REG_GCTL),
            dev.bar0.read8(REG_CORBCTL),
            dev.bar0.read8(REG_RIRBCTL),
        )
    };
    if dev.suspended.load(Ordering::Acquire)
        || gctl & 1 == 0
        || corbctl != CORBCTL_RUN | CORBCTL_CMEIE
        || rirbctl != RIRBCTL_RUN | RIRBCTL_RINTCTL | RIRBCTL_OIC
        || !fixture.model.verbs[base..].contains(&d0)
    {
        return TestResult::Fail("reinit restores engines and sends D0");
    }
    if dev.reinit().is_err() || dev.suspended.load(Ordering::Acquire) {
        return TestResult::Fail("reinit idempotent");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_pm_quiesce_reinit_parks_and_restores);

fn native_hda_pm_busy_while_stream_runs_or_prepared() -> TestResult {
    let fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let mut playback = match card.open(false, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("open"),
    };
    if playback
        .configure(super::super::stream::default_params())
        .is_err()
        || playback.prepare().is_err()
    {
        return TestResult::Fail("configure/prepare playback");
    }
    // Prepared-but-idle still blocks quiesce: the BDL is published.
    if dev.quiesce().is_ok() {
        return TestResult::Fail("quiesce must refuse a prepared stream");
    }
    if playback.write(&[0x5a; 512]) != Ok(512) || playback.start().is_err() {
        return TestResult::Fail("start playback");
    }
    if dev.quiesce().is_ok() {
        return TestResult::Fail("quiesce must refuse a running stream");
    }
    // Layer 1: the PCM stop path parks the controller itself.
    if playback.stop().is_err() || !dev.suspended.load(Ordering::Acquire) {
        return TestResult::Fail("stop parks the controller");
    }
    // And the next start transparently re-inits it.
    if playback
        .configure(super::super::stream::default_params())
        .is_err()
        || playback.prepare().is_err()
        || playback.start().is_err()
        || dev.suspended.load(Ordering::Acquire)
    {
        return TestResult::Fail("start re-inits a parked controller");
    }
    if playback.stop().is_err() || !dev.suspended.load(Ordering::Acquire) {
        return TestResult::Fail("second stop re-parks the controller");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_pm_busy_while_stream_runs_or_prepared
);

fn native_hda_pm_system_fanout_suspends_and_resumes() -> TestResult {
    let _pm = narf_power::device_pm::__test_isolate_registry();
    let fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    // Restore the controller table on every exit, including early
    // failure returns: other smokes share this global.
    struct ControllersGuard {
        len: usize,
    }
    impl Drop for ControllersGuard {
        fn drop(&mut self) {
            CONTROLLERS.lock().truncate(self.len);
        }
    }
    let _cguard = ControllersGuard {
        len: CONTROLLERS.lock().len(),
    };
    CONTROLLERS.lock().push((
        narf_bus::BusAddr::Mmio(narf_memory::PhysAddr::new(0xFEDC_0000)),
        dev.clone(),
        0,
    ));
    narf_power::device_pm::register_device_pm_ops("hda", Arc::new(HdaSystemPm));
    if !narf_power::device_pm::suspend_all_devices().ok() || !dev.suspended.load(Ordering::Acquire)
    {
        return TestResult::Fail("fanout suspend parks the controller");
    }
    if !narf_power::device_pm::resume_all_devices().ok() || dev.suspended.load(Ordering::Acquire) {
        return TestResult::Fail("fanout resume re-inits the controller");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_pm_system_fanout_suspends_and_resumes
);

/// Minimal PCI power-state model for the `PciRuntimePm` wrapper
/// test: no real config space, and the settle delay completes
/// immediately (the default delay awaits a timer, which the
/// spin-driven test loop must not depend on).
struct FakePciPmIo {
    state: IrqSafeSpinLock<narf_bus::pci::PciPowerState>,
    saved: AtomicBool,
    restored: AtomicBool,
}
impl narf_power::runtime_pm_pci::PciPmIo for FakePciPmIo {
    fn power_state(&self) -> Result<Option<narf_bus::pci::PciPowerState>, narf_bus::pci::PciError> {
        Ok(Some(*self.state.lock()))
    }
    fn set_power_state(
        &self,
        state: narf_bus::pci::PciPowerState,
    ) -> Result<(), narf_bus::pci::PciError> {
        *self.state.lock() = state;
        Ok(())
    }
    fn save_state(&self) -> Result<(), narf_bus::pci::PciError> {
        self.saved.store(true, Ordering::Release);
        Ok(())
    }
    fn restore_state(&self) -> Result<(), narf_bus::pci::PciError> {
        self.restored.store(true, Ordering::Release);
        Ok(())
    }
    fn delay_ms(&self, _ms: u64) -> core::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

fn native_hda_pm_runtime_ops_and_pci_wrapper() -> TestResult {
    use narf_power::runtime_pm::RuntimePmOps;
    let fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let ops = HdaRuntimePm { dev: dev.clone() };
    if narf_scheduler::block_on_spin(ops.runtime_suspend()).is_err()
        || !dev.suspended.load(Ordering::Acquire)
    {
        return TestResult::Fail("runtime suspend parks the controller");
    }
    if narf_scheduler::block_on_spin(ops.runtime_resume()).is_err()
        || dev.suspended.load(Ordering::Acquire)
    {
        return TestResult::Fail("runtime resume re-inits the controller");
    }
    // The PCI wrapper moves the function state around the same
    // driver core: suspend saves config and lands in D3hot,
    // resume restores config, returns to D0, and re-inits.
    let io = Arc::new(FakePciPmIo {
        state: IrqSafeSpinLock::new(narf_bus::pci::PciPowerState::D0),
        saved: AtomicBool::new(false),
        restored: AtomicBool::new(false),
    });
    let pci = narf_power::runtime_pm_pci::PciRuntimePm::new(
        io.clone(),
        Some(Arc::new(HdaRuntimePm { dev: dev.clone() })),
        None,
    );
    if narf_scheduler::block_on_spin(pci.runtime_suspend()).is_err()
        || !dev.suspended.load(Ordering::Acquire)
        || *io.state.lock() != narf_bus::pci::PciPowerState::D3Hot
        || !io.saved.load(Ordering::Acquire)
    {
        return TestResult::Fail("wrapper suspend saves and moves to D3hot");
    }
    if narf_scheduler::block_on_spin(pci.runtime_resume()).is_err()
        || dev.suspended.load(Ordering::Acquire)
        || *io.state.lock() != narf_bus::pci::PciPowerState::D0
        || !io.restored.load(Ordering::Acquire)
    {
        return TestResult::Fail("wrapper resume restores and returns to D0");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_pm_runtime_ops_and_pci_wrapper);

fn native_hda_route_and_capture_controls() -> TestResult {
    use narf_drivers_sound::mixer::{ControlId, ControlKind, ControlValue};
    let mut fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    let controls = card.controls();
    let has = |index: u32, kind: ControlKind| controls.contains(&ControlId { index, kind });
    // Both output converters have output amps, so both route pairs
    // publish; the ADC has an input amp, so Capture Volume does.
    // The mic pin has no input amp in the default fixture, so Mic
    // Boost does not publish there (the line-in variant adds one).
    if !has(10, ControlKind::HeadphoneVolume)
        || !has(11, ControlKind::HeadphoneMute)
        || !has(12, ControlKind::SpeakerVolume)
        || !has(13, ControlKind::SpeakerMute)
        || !has(14, ControlKind::CaptureVolume)
        || has(15, ControlKind::MicBoost)
    {
        return TestResult::Fail("route/capture control publication");
    }
    // Headphone trim (40, 50) over the 87 master: converter 2 is
    // shared by both output paths in this fixture, so the verbs
    // carry the speaker defaults (16 steps) and then the headphone
    // values (7 left, 9 right) — the last write wins on the shared
    // amp, which separate converters would not share.
    let hp = ControlId {
        index: 10,
        kind: ControlKind::HeadphoneVolume,
    };
    if card.set_control(hp, ControlValue::integer(40, 50)).is_err()
        || card.get_control(hp) != Ok(ControlValue::integer(40, 50))
    {
        return TestResult::Fail("headphone volume round-trip");
    }
    let amp = VERB_SET_AMP_GAIN_MUTE;
    if !fixture
        .model
        .verbs
        .contains(&make_verb(0, 2, amp | 0x8000 | 0x2000 | 7))
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 2, amp | 0x8000 | 0x1000 | 9))
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 2, amp | 0x8000 | 0x2000 | 16))
    {
        return TestResult::Fail("headphone trim programs the converter amp");
    }
    // Route mute ANDs with the master: muting the speaker route
    // writes the mute bit for the shared converter.
    let sp_mute = ControlId {
        index: 13,
        kind: ControlKind::SpeakerMute,
    };
    if card
        .set_control(sp_mute, ControlValue::boolean(false))
        .is_err()
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 2, amp | 0x8000 | 0x2000 | 16 | 0x80))
        || card
            .set_control(sp_mute, ControlValue::boolean(true))
            .is_err()
    {
        return TestResult::Fail("speaker route mute programs the mute bit");
    }
    // Capture gain programs the ADC input amp at the selected input
    // (converter 3, input 0, 16 steps at unity, 7 at 43).
    let cap = ControlId {
        index: 14,
        kind: ControlKind::CaptureVolume,
    };
    if card
        .set_control(cap, ControlValue::integer(43, 43))
        .is_err()
        || card.get_control(cap) != Ok(ControlValue::integer(43, 43))
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 3, amp | 0x7000 | 7))
    {
        return TestResult::Fail("capture volume programs the ADC input amp");
    }
    // And a capture configure re-applies it after the path setup
    // itself wrote unity (16 steps) to the same amp.
    let mut capture = match card.open(true, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("capture open"),
    };
    fixture.model.verbs.clear();
    if capture
        .configure(super::super::stream::default_params())
        .is_err()
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 3, amp | 0x7000 | 7))
    {
        return TestResult::Fail("capture configure re-applies the stored gain");
    }
    drop(capture);
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_route_and_capture_controls);

fn native_hda_jack_driven_capture_switch() -> TestResult {
    use narf_drivers_sound::mixer::{ControlId, ControlKind};
    let mut fixture = match Fixture::line_in() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let card = super::super::stream::Card(dev.clone());
    if dev.inputs.len() != 2 || dev.input.lock().as_ref().map(|p| p.nodes.pin_nid) != Some(7) {
        return TestResult::Fail("mic preferred before any jack state");
    }
    // Line plugged, mic not: the line source wins.
    fixture.model.mic_plugged = false;
    fixture.model.line_plugged = true;
    if dev.refresh_jacks().is_err() || dev.input.lock().as_ref().map(|p| p.nodes.pin_nid) != Some(9)
    {
        return TestResult::Fail("plugged line displaces the mic");
    }
    // Mic plugged beats line: back to the mic.
    fixture.model.mic_plugged = true;
    if dev.refresh_jacks().is_err() || dev.input.lock().as_ref().map(|p| p.nodes.pin_nid) != Some(7)
    {
        return TestResult::Fail("plugged mic retakes the source");
    }
    // Nothing plugged: preference order falls back to the mic.
    fixture.model.mic_plugged = false;
    fixture.model.line_plugged = false;
    if dev.refresh_jacks().is_err() || dev.input.lock().as_ref().map(|p| p.nodes.pin_nid) != Some(7)
    {
        return TestResult::Fail("unplugged fallback is the preference order");
    }
    // The published capture controls follow the selected source:
    // the mic pin has an input amp (Mic Boost), the line pin does not.
    let boost = ControlId {
        index: 15,
        kind: ControlKind::MicBoost,
    };
    if !card.controls().contains(&boost) {
        return TestResult::Fail("mic boost publishes for the mic source");
    }
    fixture.model.line_plugged = true;
    if dev.refresh_jacks().is_err() || card.controls().contains(&boost) {
        return TestResult::Fail("mic boost withdraws for the line source");
    }
    // Mic Boost at full writes the mic pin's input amp from its
    // 0 dB offset (16) to its maximum step (32).
    fixture.model.mic_plugged = true;
    if dev.refresh_jacks().is_err() {
        return TestResult::Fail("reselect mic");
    }
    use narf_drivers_sound::mixer::ControlValue;
    if card
        .set_control(boost, ControlValue::integer(87, 87))
        .is_err()
        || !fixture
            .model
            .verbs
            .contains(&make_verb(0, 7, VERB_SET_AMP_GAIN_MUTE | 0x7000 | 32))
    {
        return TestResult::Fail("mic boost programs the mic pin input amp");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_jack_driven_capture_switch);

// ── #776: live-path vendor codec fixups ─────────────────────────────
// The expected verbs come from Linux `alc256_init`
// (`alc_write_coef_idx(codec, 0x36, 0x5757)`), not from the
// implementation: SET_COEF_INDEX (4-bit verb 0x5 + 16-bit payload)
// then SET_PROC_COEF (0x4) to the Realtek coef node 0x20.

/// The ALC256 coef-init pair the probe path must emit, as encoded
/// verb words.
fn coef_init_pair() -> (u32, u32) {
    (
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_COEF_INDEX | 0x36,
        ),
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_PROC_COEF | 0x5757,
        ),
    )
}

/// #776: an ALC256 codec gets its verified init coef sequence on
/// the live probe path, before the widget graph is built, and its
/// subsystem id is recorded on CodecInfo.
fn native_hda_realtek256_coef_init_applied() -> TestResult {
    let fixture = match Fixture::alc256() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0256 {
        return TestResult::Fail("fixture codec must be ALC256");
    }
    if codec.subsystem_id != Some(0x1028_0d76) {
        return TestResult::Fail("codec subsystem id must be recorded");
    }
    let (set_idx, set_coef) = coef_init_pair();
    let verbs = &fixture.model.verbs;
    if verbs.iter().filter(|v| **v == set_idx).count() != 1
        || verbs.iter().filter(|v| **v == set_coef).count() != 1
    {
        return TestResult::Fail("ALC256 coef init must run exactly once at probe");
    }
    let at_idx = verbs.iter().position(|v| *v == set_idx).unwrap();
    let at_coef = verbs.iter().position(|v| *v == set_coef).unwrap();
    if at_idx + 1 != at_coef {
        return TestResult::Fail("coef index must be immediately followed by its value");
    }
    // The fixups run before the graph build: the first
    // GET_CONFIG_DEFAULT the enumerator sends for a pin must come
    // after both coef verbs.
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    match first_pincfg {
        Some(at) if at_coef < at => {}
        _ => return TestResult::Fail("coef init must precede enumeration"),
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_realtek256_coef_init_applied);

/// #776: an unknown (zero) subsystem id fails open — the codec
/// still enumerates and routes generically, and a chip whose
/// rescued rows stay unwired (ALC287) gets no coef verbs at all.
fn native_hda_unknown_subsystem_fails_open() -> TestResult {
    let fixture = match Fixture::new() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0287 {
        return TestResult::Fail("fixture codec must be ALC287");
    }
    if codec.subsystem_id.is_some() {
        return TestResult::Fail("zero subsystem id must read as unknown");
    }
    // No verb may target the Realtek coef node: ALC287's rescued
    // rows stay unwired.
    if fixture
        .model
        .verbs
        .iter()
        .any(|v| (*v >> 20) & 0xff == u32::from(crate::hda::quirks::COEF_NODE))
    {
        return TestResult::Fail("unwired chip must get no coef verbs");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("generic routing must survive unknown subsystem");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_unknown_subsystem_fails_open);

/// #776: a non-Realtek codec is untouched — no subsystem-driven
/// fixups, no coef verbs.
fn native_hda_non_realtek_gets_no_fixups() -> TestResult {
    let fixture = match Fixture::with(false, true) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x1002aa01 {
        return TestResult::Fail("fixture codec must be the ATI HDMI codec");
    }
    if codec.subsystem_id.is_some() {
        return TestResult::Fail("ATI codec must report no subsystem id");
    }
    if fixture
        .model
        .verbs
        .iter()
        .any(|v| (*v >> 20) & 0xff == u32::from(crate::hda::quirks::COEF_NODE))
    {
        return TestResult::Fail("non-Realtek codec must get no coef verbs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_non_realtek_gets_no_fixups);

/// #776: a controller reset drops the codec's coef state, so
/// resume re-applies the probe-time init (Linux re-runs its init
/// hook on resume for the same reason).
fn native_hda_pm_reinit_reapplies_coef_init() -> TestResult {
    let fixture = match Fixture::alc256() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let (set_idx, _) = coef_init_pair();
    let count = || {
        fixture
            .model
            .verbs
            .iter()
            .filter(|v| **v == set_idx)
            .count()
    };
    if count() != 1 {
        return TestResult::Fail("probe must apply coef init once");
    }
    if dev.quiesce().is_err() {
        return TestResult::Fail("quiesce idle controller");
    }
    if dev.reinit().is_err() {
        return TestResult::Fail("reinit parked controller");
    }
    if count() != 2 {
        return TestResult::Fail("reinit must re-apply coef init");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_pm_reinit_reapplies_coef_init);

// ── #1496: re-derived pin quirks + RMW coef ────────────────────────
// The expected verbs come from Linux `alc256_init`
// (`alc_update_coef_idx(codec, 0x46, 3 << 12, 0)` etc.) and from
// `alc282_coefs` / `alc287_fixup_yoga9_14iap7_bass_spk_pin`, not
// from the implementation.

/// #1496: the ALC256 init's masked rows are real
/// read-modify-write updates (Linux `alc_update_coef_idx`), not
/// plain writes: coef 0x46 is pre-seeded to 0xF5A5, so the
/// (0x46, mask 0x3000, value 0) update must write back 0xC5A5 —
/// the bits outside the mask preserved — and each update must be
/// preceded by a GET_PROC_COEF read of the same index.
fn native_hda_alc256_coef_rmw_update_applied() -> TestResult {
    let fixture = match Fixture::alc256_seeded() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0256 {
        return TestResult::Fail("fixture codec must be ALC256");
    }
    let verbs = &fixture.model.verbs;
    let idx =
        |nid: u8, index: u32| make_verb(0, nid, crate::hda_codec::verb::SET_COEF_INDEX | index);
    let get = |nid: u8| make_verb(0, nid, crate::hda_codec::verb::GET_PROC_COEF);
    let set =
        |nid: u8, value: u32| make_verb(0, nid, crate::hda_codec::verb::SET_PROC_COEF | value);
    // Linux `alc256_init`'s unconditional tail, in Linux's order:
    // masked 0x46 update, 0x53 set/clear pulse (nid 0x53, not
    // the coef node), then the plain 0x36 write.
    let expected: [u32; 14] = [
        idx(0x20, 0x46),
        get(0x20),
        idx(0x20, 0x46),
        set(0x20, 0xC5A5),
        idx(0x53, 0x02),
        get(0x53),
        idx(0x53, 0x02),
        set(0x53, 0x8000),
        idx(0x53, 0x02),
        get(0x53),
        idx(0x53, 0x02),
        set(0x53, 0x0000),
        idx(0x20, 0x36),
        set(0x20, 0x5757),
    ];
    // The coef verbs are the only traffic on nids 0x20/0x53, and
    // must be exactly this sequence.
    let coef_verbs: Vec<u32> = verbs
        .iter()
        .copied()
        .filter(|v| matches!((*v >> 20) & 0xff, 0x20 | 0x53))
        .collect();
    if coef_verbs[..] != expected[..] {
        return TestResult::Fail("ALC256 init must run its 4-op tail in Linux order");
    }
    // The register file the updates leave behind: the mask
    // preserved 0xF5A5's bits outside 0x3000, the pulse cleared.
    let coef = |nid: u8, index: u16| {
        fixture
            .model
            .coef
            .iter()
            .find(|(n, i, _)| *n == nid && *i == index)
            .map(|(_, _, v)| *v)
    };
    if coef(0x20, 0x46) != Some(0xC5A5)
        || coef(0x53, 0x02) != Some(0x0000)
        || coef(0x20, 0x36) != Some(0x5757)
    {
        return TestResult::Fail("ALC256 coef state must hold the masked updates");
    }
    // The init runs before enumeration.
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let last_coef = verbs
        .iter()
        .rposition(|v| matches!((*v >> 20) & 0xff, 0x20 | 0x53));
    match (first_pincfg, last_coef) {
        (Some(at), Some(last)) if last < at => {}
        _ => return TestResult::Fail("ALC256 init must precede enumeration"),
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc256_coef_rmw_update_applied);

/// #1496: an ALC282 codec gets the full verified `alc282_coefs`
/// table on the live probe path, in Linux's order — 17 plain
/// writes and 12 masked updates, every masked update preceded by
/// a GET_PROC_COEF read.
fn native_hda_alc282_coef_table_applied() -> TestResult {
    let fixture = match Fixture::alc282() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0282 {
        return TestResult::Fail("fixture codec must be ALC282");
    }
    if codec.subsystem_id.is_some() {
        return TestResult::Fail("ALC282 fixture must report no subsystem id");
    }
    let verbs = &fixture.model.verbs;
    let coef_node = u32::from(crate::hda::quirks::COEF_NODE);
    // The HP tail (#776 remainders) issues its own coef verbs on
    // the same node after enumeration — count only the
    // pre-enumeration traffic for the table.
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let coef_verbs: Vec<u32> = verbs
        .iter()
        .take(first_pincfg.unwrap_or(verbs.len()))
        .copied()
        .filter(|v| (*v >> 20) & 0xff == coef_node)
        .collect();
    // 17 plain writes (2 verbs each) + 12 masked updates
    // (4 verbs each) = 82 verbs, all on the coef node.
    if coef_verbs.len() != 82 {
        return TestResult::Fail("ALC282 init must issue 82 coef verbs");
    }
    let gets = coef_verbs
        .iter()
        .filter(|v| (**v >> 8) & 0xfff == 0xc00)
        .count();
    if gets != 12 {
        return TestResult::Fail("ALC282 init must read before each masked update");
    }
    let idx = |index: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_COEF_INDEX | index,
        )
    };
    let set = |value: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_PROC_COEF | value,
        )
    };
    // First op (0x03, 0x0002) and last op (0x6c, 0xfc06).
    if coef_verbs[0] != idx(0x03) || coef_verbs[1] != set(0x0002) {
        return TestResult::Fail("ALC282 init must start with the 0x03 write");
    }
    if coef_verbs[80] != idx(0x6c) || coef_verbs[81] != set(0xfc06) {
        return TestResult::Fail("ALC282 init must end with the 0x6c write");
    }
    // The table runs before enumeration.
    let last_coef = verbs
        .iter()
        .take(first_pincfg.unwrap_or(verbs.len()))
        .rposition(|v| (*v >> 20) & 0xff == coef_node);
    match (first_pincfg, last_coef) {
        (Some(at), Some(last)) if last < at => {}
        _ => return TestResult::Fail("ALC282 init must precede enumeration"),
    }
    // Spot-check the register file: a plain write and a masked
    // update (0x05, mask 0xff3f, value 0x0700).
    let coef = |index: u16| {
        fixture
            .model
            .coef
            .iter()
            .find(|(n, i, _)| *n == crate::hda::quirks::COEF_NODE && *i == index)
            .map(|(_, _, v)| *v)
    };
    if coef(0x03) != Some(0x0002) || coef(0x05) != Some(0x0700) || coef(0x6c) != Some(0xfc06) {
        return TestResult::Fail("ALC282 coef state must hold the applied table");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc282_coef_table_applied);

/// #1496: a Lenovo Yoga 7 2-in-1 16AKP10 (ALC287, codec subsystem
/// 0x17aa391d) gets the verified YOGA9 fixup on the live probe
/// path: the 44-verb bass-speaker coef sequence before
/// enumeration, pin 0x17's config override (without it the pin
/// reads as unconnected and routes nothing), the connection-list
/// override (pin 0x17's SET_CONNECTION_SELECT is index 0 — DAC
/// 0x02 is first in the overridden list, third in the hardware
/// list), and the preferred DACs (speakers on 0x02, headphones
/// on 0x03, even though neither preferred DAC is first in its
/// pin's hardware list).
fn native_hda_yoga9_bass_speaker_quirk_applied() -> TestResult {
    let fixture = match Fixture::yoga9() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0287 {
        return TestResult::Fail("fixture codec must be ALC287");
    }
    if codec.subsystem_id != Some(0x17aa_391d) {
        return TestResult::Fail("codec subsystem id must be recorded");
    }
    let verbs = &fixture.model.verbs;
    // The 44-verb bass-speaker sequence, verbatim and in order,
    // is the only coef traffic: ALC287 has no init coef table.
    let coef_node = u32::from(crate::hda::quirks::COEF_NODE);
    let coef_verbs: Vec<u32> = verbs
        .iter()
        .copied()
        .filter(|v| (*v >> 20) & 0xff == coef_node)
        .collect();
    if coef_verbs.len() != 44 {
        return TestResult::Fail("YOGA9 quirk must issue exactly its 44-verb sequence");
    }
    let expected: Vec<u32> = crate::hda::quirks::QUIRK_YOGA9_BASS_SPK_SEQ
        .iter()
        .map(|step| make_verb(0, step.nid, step.verb))
        .collect();
    if coef_verbs != expected {
        return TestResult::Fail("YOGA9 coef sequence must run verbatim in Linux order");
    }
    // The sequence runs before enumeration.
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let last_coef = verbs.iter().rposition(|v| (*v >> 20) & 0xff == coef_node);
    match (first_pincfg, last_coef) {
        (Some(at), Some(last)) if last < at => {}
        _ => return TestResult::Fail("YOGA9 coef sequence must precede enumeration"),
    }
    // Exactly the three quirk pins route, each to its preferred DAC.
    if dev.outputs.len() != 3 {
        return TestResult::Fail("YOGA9 fixture must route exactly three outputs");
    }
    let out = |pin: u8| dev.outputs.iter().find(|p| p.nodes.pin_nid == pin);
    let Some(bass) = out(0x17) else {
        return TestResult::Fail("bass pin must route after the pin override");
    };
    if bass.nodes.converter_nid != 0x02 {
        return TestResult::Fail("bass pin must use its preferred DAC 0x02, not 0x06");
    }
    let Some(tweeter) = out(0x14) else {
        return TestResult::Fail("tweeter pin must route");
    };
    if tweeter.nodes.converter_nid != 0x02 {
        return TestResult::Fail("tweeter pin must use its preferred DAC 0x02, not 0x03");
    }
    let Some(hp) = out(0x21) else {
        return TestResult::Fail("headphone pin must route");
    };
    if hp.nodes.converter_nid != 0x03 {
        return TestResult::Fail("headphone pin must use its preferred DAC 0x03, not 0x02");
    }
    // Configure the default output path: the connection-select
    // index pin 0x17 sends is the index into the OVERRIDDEN
    // list ([0x02, 0x03] → 0), not the hardware list
    // ([0x06, 0x08, 0x02, 0x03] → 2).
    // SAFETY: The fixture exclusively owns this controller and no
    // output stream has been started in this test, so the
    // `setup_default_output_path` precondition holds (caller owns
    // this controller and has stopped its output stream).
    if unsafe { dev.setup_default_output_path() }.is_err() {
        return TestResult::Fail("configure default output path");
    }
    let select = make_verb(0, 0x17, 0x701 << 8);
    if !fixture.model.verbs.contains(&select) {
        return TestResult::Fail("bass pin must select index 0 of its overridden list");
    }
    let wrong = make_verb(0, 0x17, (0x701 << 8) | 2);
    if fixture.model.verbs.contains(&wrong) {
        return TestResult::Fail("bass pin must not select the hardware-list index");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_yoga9_bass_speaker_quirk_applied);

// ── #776 remainders: ALC282/283 HP-pin tails + parse-time coef ──
// The expected verbs come from Linux `alc282_init` /
// `alc283_init` and `patch_alc269` (`alc269.c`), not from the
// implementation.

/// #776 remainders: the verbs a probe issues after the last
/// GET_CONFIG_DEFAULT on the coef node / the default model's HP
/// pin (nid 6) — exactly the HP tail's traffic, since the
/// post-enumeration probe path (`discover_paths`, `hdmi_ports`,
/// `initial_hdmi_playback`) issues no verbs on those nids and
/// `query_supported_formats` only reads the AFG.
fn post_enumeration_tail_verbs(verbs: &[u32]) -> Vec<u32> {
    let last_pincfg = verbs
        .iter()
        .rposition(|v| (*v >> 8) & 0xfff == 0xf1c)
        .unwrap_or(0);
    verbs
        .iter()
        .skip(last_pincfg + 1)
        .copied()
        .filter(|v| matches!((*v >> 20) & 0xff, 0x20 | 6))
        .collect()
}

/// #776 remainders: an ALC282 codec gets the `alc282_init`
/// HP-pin tail after enumeration — sense the HP pin (nid 6 in
/// the default model), read coef 0x78, drive it to high-power
/// mode (0x9004), mute the HP amp, set PIN_OUT, restore 0x78.
/// Unplugged, so the sleeps are skipped but every verb is still
/// issued, in Linux's order.
fn native_hda_alc282_hp_tail_applied() -> TestResult {
    let fixture = match Fixture::alc282() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0282 {
        return TestResult::Fail("fixture codec must be ALC282");
    }
    let Some(graph) = dev.graphs.first() else {
        return TestResult::Fail("fixture has no graph");
    };
    if graph.hp_pin() != Some(6) {
        return TestResult::Fail("default model HP pin must be nid 6");
    }
    let verbs = &fixture.model.verbs;
    let idx = |index: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_COEF_INDEX | index);
    let get = make_verb(0, 0x20, crate::hda_codec::verb::GET_PROC_COEF);
    let set = |value: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_PROC_COEF | value);
    let sense = make_verb(0, 6, crate::hda_codec::verb::GET_PIN_SENSE);
    let mute = make_verb(0, 6, crate::hda_codec::verb::SET_AMP_GAIN_MUTE | 0xB080);
    let pin_out = make_verb(0, 6, crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL | 0x40);
    let expected: [u32; 9] = [
        sense,
        idx(0x78),
        get,
        idx(0x78),
        set(0x9004),
        mute,
        pin_out,
        idx(0x78),
        set(0x0000),
    ];
    if post_enumeration_tail_verbs(verbs)[..] != expected[..] {
        return TestResult::Fail("ALC282 HP tail must run in Linux order after enumeration");
    }
    let coef78 = fixture
        .model
        .coef
        .iter()
        .find(|(n, i, _)| *n == crate::hda::quirks::COEF_NODE && *i == 0x78)
        .map(|(_, _, v)| *v);
    if coef78 != Some(0x0000) {
        return TestResult::Fail("ALC282 coef 0x78 must be restored after the tail");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc282_hp_tail_applied);

/// #776 remainders: an ALC283 codec gets the `alc283_init`
/// HP-pin tail after enumeration — 30 ms settle, sense the HP
/// pin, drive coef 0x43 to high-power mode (0x9004), mute the HP
/// amp, set PIN_OUT, the 0x46 3k pull-low update, back to normal
/// mode (0x43 = 0x9614). The full 33-op table still runs before
/// enumeration (96 verbs, 15 GET_PROC_COEF reads).
fn native_hda_alc283_hp_tail_applied() -> TestResult {
    let fixture = match Fixture::alc283() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0283 {
        return TestResult::Fail("fixture codec must be ALC283");
    }
    if codec.subsystem_id.is_some() {
        return TestResult::Fail("ALC283 fixture must report no subsystem id");
    }
    let verbs = &fixture.model.verbs;
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let table_verbs: Vec<u32> = verbs
        .iter()
        .take(first_pincfg.unwrap_or(verbs.len()))
        .copied()
        .filter(|v| matches!((*v >> 20) & 0xff, 0x20 | 0x53))
        .collect();
    // 18 plain writes (2 verbs each) + 15 masked updates
    // (4 verbs each) = 96 verbs.
    if table_verbs.len() != 96 {
        return TestResult::Fail("ALC283 init must issue 96 coef verbs");
    }
    let gets = table_verbs
        .iter()
        .filter(|v| (**v >> 8) & 0xfff == 0xc00)
        .count();
    if gets != 15 {
        return TestResult::Fail("ALC283 init must read before each masked update");
    }
    let idx = |index: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_COEF_INDEX | index);
    let get = make_verb(0, 0x20, crate::hda_codec::verb::GET_PROC_COEF);
    let set = |value: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_PROC_COEF | value);
    if table_verbs[0] != idx(0x03) || table_verbs[1] != set(0x0002) {
        return TestResult::Fail("ALC283 init must start with the 0x03 write");
    }
    if table_verbs[92] != idx(0x1b)
        || table_verbs[93] != get
        || table_verbs[94] != idx(0x1b)
        || table_verbs[95] != set(0x0000)
    {
        return TestResult::Fail("ALC283 init must end with the 0x1b update");
    }
    let sense = make_verb(0, 6, crate::hda_codec::verb::GET_PIN_SENSE);
    let mute = make_verb(0, 6, crate::hda_codec::verb::SET_AMP_GAIN_MUTE | 0xB080);
    let pin_out = make_verb(0, 6, crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL | 0x40);
    let expected: [u32; 11] = [
        sense,
        idx(0x43),
        set(0x9004),
        mute,
        pin_out,
        idx(0x46),
        get,
        idx(0x46),
        set(0x0000),
        idx(0x43),
        set(0x9614),
    ];
    if post_enumeration_tail_verbs(verbs)[..] != expected[..] {
        return TestResult::Fail("ALC283 HP tail must run in Linux order after enumeration");
    }
    let coef = |index: u16| {
        fixture
            .model
            .coef
            .iter()
            .find(|(n, i, _)| *n == crate::hda::quirks::COEF_NODE && *i == index)
            .map(|(_, _, v)| *v)
    };
    if coef(0x43) != Some(0x9614) || coef(0x46) != Some(0x0000) {
        return TestResult::Fail("ALC283 coef state must hold the tail's final values");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc283_hp_tail_applied);

/// #776 remainders: the HP tail's sense-plugged branch issues
/// the same verbs as the unplugged branch — Linux only gates the
/// sleeps on sense, never the verbs — so a plugged ALC282 runs
/// the identical 9-verb tail.
fn native_hda_alc282_hp_tail_plugged() -> TestResult {
    let fixture = match Fixture::alc282_plugged() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0282 {
        return TestResult::Fail("fixture codec must be ALC282");
    }
    let verbs = &fixture.model.verbs;
    let idx = |index: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_COEF_INDEX | index);
    let get = make_verb(0, 0x20, crate::hda_codec::verb::GET_PROC_COEF);
    let set = |value: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_PROC_COEF | value);
    let sense = make_verb(0, 6, crate::hda_codec::verb::GET_PIN_SENSE);
    let mute = make_verb(0, 6, crate::hda_codec::verb::SET_AMP_GAIN_MUTE | 0xB080);
    let pin_out = make_verb(0, 6, crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL | 0x40);
    let expected: [u32; 9] = [
        sense,
        idx(0x78),
        get,
        idx(0x78),
        set(0x9004),
        mute,
        pin_out,
        idx(0x78),
        set(0x0000),
    ];
    if post_enumeration_tail_verbs(verbs)[..] != expected[..] {
        return TestResult::Fail("plugged ALC282 HP tail must issue the same verbs");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc282_hp_tail_plugged);

/// #776 remainders: the ALC283 tail's sense-plugged branch
/// issues the same 11 verbs as the unplugged branch — Linux
/// only gates the 85 ms sleeps on sense, never the verbs.
fn native_hda_alc283_hp_tail_plugged() -> TestResult {
    let fixture = match Fixture::alc283_plugged() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture codec must be ALC283");
    };
    if codec.vendor_id != 0x10ec0283 {
        return TestResult::Fail("fixture codec must be ALC283");
    }
    let verbs = &fixture.model.verbs;
    let idx = |index: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_COEF_INDEX | index);
    let get = make_verb(0, 0x20, crate::hda_codec::verb::GET_PROC_COEF);
    let set = |value: u32| make_verb(0, 0x20, crate::hda_codec::verb::SET_PROC_COEF | value);
    let sense = make_verb(0, 6, crate::hda_codec::verb::GET_PIN_SENSE);
    let mute = make_verb(0, 6, crate::hda_codec::verb::SET_AMP_GAIN_MUTE | 0xB080);
    let pin_out = make_verb(0, 6, crate::hda_codec::verb::SET_PIN_WIDGET_CONTROL | 0x40);
    let expected: [u32; 11] = [
        sense,
        idx(0x43),
        set(0x9004),
        mute,
        pin_out,
        idx(0x46),
        get,
        idx(0x46),
        set(0x0000),
        idx(0x43),
        set(0x9614),
    ];
    if post_enumeration_tail_verbs(verbs)[..] != expected[..] {
        return TestResult::Fail("plugged ALC283 HP tail must issue the same verbs");
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc283_hp_tail_plugged);

/// #776 remainders: an ALC274 codec gets the ALC294-arm
/// parse-time coef update at probe — `alc_update_coef_idx(codec,
/// 0x6b, 0x0018, 0x0018)` (Linux `patch_alc269`, "UAJ MIC Vref
/// control by verb") — a masked RMW update before enumeration.
/// ALC274 has no init table, so this is the only coef traffic.
fn native_hda_alc274_parse_coef_applied() -> TestResult {
    let fixture = match Fixture::with_codec(0x10ec0274) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0274 {
        return TestResult::Fail("fixture codec must be ALC274");
    }
    let verbs = &fixture.model.verbs;
    let coef_node = u32::from(crate::hda::quirks::COEF_NODE);
    let coef_verbs: Vec<u32> = verbs
        .iter()
        .copied()
        .filter(|v| (*v >> 20) & 0xff == coef_node)
        .collect();
    let idx = |index: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_COEF_INDEX | index,
        )
    };
    let get = make_verb(
        0,
        crate::hda::quirks::COEF_NODE,
        crate::hda_codec::verb::GET_PROC_COEF,
    );
    let set = |value: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_PROC_COEF | value,
        )
    };
    let expected: [u32; 4] = [idx(0x6b), get, idx(0x6b), set(0x0018)];
    if coef_verbs[..] != expected[..] {
        return TestResult::Fail("ALC274 parse update must be the 0x6b masked update");
    }
    let coef6b = fixture
        .model
        .coef
        .iter()
        .find(|(n, i, _)| *n == crate::hda::quirks::COEF_NODE && *i == 0x6b)
        .map(|(_, _, v)| *v);
    if coef6b != Some(0x0018) {
        return TestResult::Fail("ALC274 coef 0x6b must hold the parsed update");
    }
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let last_coef = verbs.iter().rposition(|v| (*v >> 20) & 0xff == coef_node);
    match (first_pincfg, last_coef) {
        (Some(at), Some(last)) if last < at => {}
        _ => return TestResult::Fail("ALC274 parse update must precede enumeration"),
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc274_parse_coef_applied);

/// #776 remainders: an ALC700 codec gets the ALC700-arm
/// parse-time coef update at probe — `alc_update_coef_idx(codec,
/// 0x4a, 1 << 15, 0)` (Linux `patch_alc269`, "Combo jack auto
/// trigger control") — a masked RMW update before enumeration.
/// ALC700 has no init table, so this is the only coef traffic.
fn native_hda_alc700_parse_coef_applied() -> TestResult {
    let fixture = match Fixture::with_codec(0x10ec0700) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let Some(codec) = dev.codecs().first() else {
        return TestResult::Fail("fixture has no codec");
    };
    if codec.vendor_id != 0x10ec0700 {
        return TestResult::Fail("fixture codec must be ALC700");
    }
    let verbs = &fixture.model.verbs;
    let coef_node = u32::from(crate::hda::quirks::COEF_NODE);
    let coef_verbs: Vec<u32> = verbs
        .iter()
        .copied()
        .filter(|v| (*v >> 20) & 0xff == coef_node)
        .collect();
    let idx = |index: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_COEF_INDEX | index,
        )
    };
    let get = make_verb(
        0,
        crate::hda::quirks::COEF_NODE,
        crate::hda_codec::verb::GET_PROC_COEF,
    );
    let set = |value: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_PROC_COEF | value,
        )
    };
    let expected: [u32; 4] = [idx(0x4a), get, idx(0x4a), set(0x0000)];
    if coef_verbs[..] != expected[..] {
        return TestResult::Fail("ALC700 parse update must be the 0x4a masked update");
    }
    let coef4a = fixture
        .model
        .coef
        .iter()
        .find(|(n, i, _)| *n == crate::hda::quirks::COEF_NODE && *i == 0x4a)
        .map(|(_, _, v)| *v);
    if coef4a != Some(0x0000) {
        return TestResult::Fail("ALC700 coef 0x4a must hold the parsed update");
    }
    let first_pincfg = verbs.iter().position(|v| (*v >> 8) & 0xfff == 0xf1c);
    let last_coef = verbs.iter().rposition(|v| (*v >> 20) & 0xff == coef_node);
    match (first_pincfg, last_coef) {
        (Some(at), Some(last)) if last < at => {}
        _ => return TestResult::Fail("ALC700 parse update must precede enumeration"),
    }
    if dev.outputs.is_empty() {
        return TestResult::Fail("fixed-up codec must still route outputs");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc700_parse_coef_applied);

/// #776 remainders: the same-arm sibling IDs dispatch to the same
/// parse tables — ALC234 to the ALC294 arm (0x6b), ALC701/703/711
/// to the ALC700 arm (0x4a) — and ALC222 identifies with no coef
/// traffic at all (its `alc222_init` has no coef writes).
fn native_hda_alc_sibling_ids_parse_and_identify() -> TestResult {
    let idx = |index: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_COEF_INDEX | index,
        )
    };
    let get = make_verb(
        0,
        crate::hda::quirks::COEF_NODE,
        crate::hda_codec::verb::GET_PROC_COEF,
    );
    let set = |value: u32| {
        make_verb(
            0,
            crate::hda::quirks::COEF_NODE,
            crate::hda_codec::verb::SET_PROC_COEF | value,
        )
    };
    let coef_verbs = |fixture: &Fixture| {
        fixture
            .model
            .verbs
            .iter()
            .copied()
            .filter(|v| (*v >> 20) & 0xff == u32::from(crate::hda::quirks::COEF_NODE))
            .collect::<Vec<u32>>()
    };
    {
        let fixture = match Fixture::with_codec(0x10ec0234) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let dev = fixture.controller.as_ref().unwrap().clone();
        if dev.codecs().first().map_or(0, |c| c.vendor_id) != 0x10ec0234 {
            return TestResult::Fail("fixture codec must be ALC234");
        }
        let expected: [u32; 4] = [idx(0x6b), get, idx(0x6b), set(0x0018)];
        if coef_verbs(&fixture)[..] != expected[..] {
            return TestResult::Fail("ALC234 must run the ALC294-arm parse update");
        }
        if dev.outputs.is_empty() {
            return TestResult::Fail("ALC234 codec must still route outputs");
        }
    }
    for vendor in [0x10ec0701u32, 0x10ec0703, 0x10ec0711] {
        let fixture = match Fixture::with_codec(vendor) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let dev = fixture.controller.as_ref().unwrap().clone();
        if dev.codecs().first().map_or(0, |c| c.vendor_id) != vendor {
            return TestResult::Fail("fixture codec must be the ALC700-arm sibling");
        }
        let expected: [u32; 4] = [idx(0x4a), get, idx(0x4a), set(0x0000)];
        if coef_verbs(&fixture)[..] != expected[..] {
            return TestResult::Fail("ALC701/703/711 must run the ALC700-arm parse update");
        }
        if dev.outputs.is_empty() {
            return TestResult::Fail("ALC700-arm sibling must still route outputs");
        }
    }
    {
        let fixture = match Fixture::with_codec(0x10ec0222) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let dev = fixture.controller.as_ref().unwrap().clone();
        if dev.codecs().first().map_or(0, |c| c.vendor_id) != 0x10ec0222 {
            return TestResult::Fail("fixture codec must be ALC222");
        }
        if !coef_verbs(&fixture).is_empty() {
            return TestResult::Fail("ALC222 must issue no coef verbs");
        }
        if dev.outputs.is_empty() {
            return TestResult::Fail("ALC222 codec must still route outputs");
        }
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_alc_sibling_ids_parse_and_identify);

/// #776 remainders: reinit re-applies the HP-pin tail (it is part
/// of the init hook, which Linux re-runs on resume) — the HP amp
/// mute verb on pin 6 goes from one occurrence at probe to two
/// after a quiesce/reinit cycle.
fn native_hda_pm_reinit_reapplies_hp_tail() -> TestResult {
    let fixture = match Fixture::alc282() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let mute = make_verb(0, 6, crate::hda_codec::verb::SET_AMP_GAIN_MUTE | 0xB080);
    let count = || fixture.model.verbs.iter().filter(|v| **v == mute).count();
    if count() != 1 {
        return TestResult::Fail("probe must run the HP tail once");
    }
    if dev.quiesce().is_err() {
        return TestResult::Fail("quiesce idle controller");
    }
    if dev.reinit().is_err() {
        return TestResult::Fail("reinit parked controller");
    }
    if count() != 2 {
        return TestResult::Fail("reinit must re-apply the HP tail");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", native_hda_pm_reinit_reapplies_hp_tail);

/// #776 remainders: reinit does NOT re-apply the parse-time coef
/// update — Linux's patch dispatch runs once, at probe, and the
/// init hook (what re-runs on resume) never contained it. The
/// SET_COEF_INDEX|0x6b verb occurs twice at probe (read + write)
/// and stays at two after a quiesce/reinit cycle.
fn native_hda_pm_reinit_does_not_reapply_parse_coef() -> TestResult {
    let fixture = match Fixture::with_codec(0x10ec0274) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let dev = fixture.controller.as_ref().unwrap().clone();
    let idx6b = make_verb(
        0,
        crate::hda::quirks::COEF_NODE,
        crate::hda_codec::verb::SET_COEF_INDEX | 0x6b,
    );
    let count = || fixture.model.verbs.iter().filter(|v| **v == idx6b).count();
    if count() != 2 {
        return TestResult::Fail("probe must apply the parse update once (read + write)");
    }
    if dev.quiesce().is_err() {
        return TestResult::Fail("quiesce idle controller");
    }
    if dev.reinit().is_err() {
        return TestResult::Fail("reinit parked controller");
    }
    if count() != 2 {
        return TestResult::Fail("reinit must not re-apply the parse-time update");
    }
    TestResult::Pass
}
kernel_test_in!(
    "audio/hda",
    native_hda_pm_reinit_does_not_reapply_parse_coef
);
