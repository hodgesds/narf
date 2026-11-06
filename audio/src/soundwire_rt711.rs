//! Realtek RT711 SoundWire headset codec: HDA-verb transport,
//! attach-time init, jack-detect enable and polled jack detection.
//!
//! Grounding: Linux `sound/soc/codecs/rt711.c` (`rt711_io_init`,
//! `rt711_jack_init`, `rt711_headset_detect`,
//! `rt711_jack_detect_handler`, `rt711_index_write` /
//! `rt711_index_read` / `rt711_index_update_bits`, `rt711_reset`,
//! `rt711_clock_config`), `rt711-sdw.c` (`rt711_sdw_read` /
//! `rt711_sdw_write`, `rt711_read_prop`,
//! `rt711_interrupt_callback`) and `rt711.h` (verb, NID and index
//! constants), torvalds/linux master `f66469d`. Every register
//! address, verb and value below is transcribed from those files;
//! nothing is invented.
//!
//! The codec is programmed with HDA verbs transported as SoundWire
//! byte writes (`rt711_sdw_write`'s encoding) plus indexed vendor
//! registers behind NID 0x20 (`rt711_index_write`). A verb or index
//! read issues the verb, then assembles the 32-bit response from
//! the HDA data registers 0x2012..0x2015 (`rt711_sdw_read`).
//!
//! Boundaries, stated plainly:
//! - Jack detection here is the polled half: pin sense + the
//!   combo-jack auto-detect status. In Linux the trigger is the
//!   SoundWire impl-def interrupt (SCP INT1 bit 2, `0x04`) firing
//!   `rt711_jack_detect_handler` 250 ms later; NARF has no SDW
//!   interrupt dispatch yet, so the consumer polls `jack_detect`
//!   instead. Button detection (`rt711_button_detect`, IRQ flag
//!   tables 0x80/0x81) needs an ALSA jack reporting consumer and is
//!   not implemented.
//! - DAC DC-offset calibration (`rt711_calibration`: FSM control,
//!   vendor-calibration NID 0x58 trigger + poll, depop mode) runs
//!   as deferred work in Linux and is not part of attach-time init
//!   here; it is a follow-up.
//! - `clock_config` is a pure mapping (`rt711_clock_config`); wiring
//!   it into stream setup needs the manager's current data rate and
//!   is a follow-up.

use crate::soundwire::{Bus, SdwError, Transport};
use narf_time::Deadline;

/// Vendor-register node (`RT711_VENDOR_REG`).
const VENDOR_REG: u8 = 0x20;

/// HDA function-group node (`RT711_AUDIO_FUNCTION_GROUP`).
const AUDIO_FUNCTION_GROUP: u16 = 0x01;
/// Headphone-out pin node (`RT711_HP_OUT`).
const HP_OUT: u16 = 0x21;
/// Analog mic-in pin node (`RT711_MIC2`).
const MIC2: u16 = 0x19;
/// Digital mic 1 pin node (`RT711_DMIC1`).
const DMIC1: u16 = 0x12;
/// Digital mic 2 pin node (`RT711_DMIC2`).
const DMIC2: u16 = 0x13;
/// Line-in 1 pin node (`RT711_LINE1`).
const LINE1: u16 = 0x1a;
/// Line-in 2 pin node (`RT711_LINE2`).
const LINE2: u16 = 0x1b;
/// ADC-in 1 node (`RT711_ADC_IN1`).
const ADC_IN1: u16 = 0x09;
/// ADC-in 2 node (`RT711_ADC_IN2`).
const ADC_IN2: u16 = 0x08;

/// Vendor index: jack-detect control 1 (`RT711_JD_CTL1`).
const JD_CTL1: u8 = 0x08;
/// Vendor index: jack-detect control 2 (`RT711_JD_CTL2`).
const JD_CTL2: u8 = 0x09;
/// Vendor index: jack-detect control 4 (`RT711_JD_CTL4`).
const JD_CTL4: u8 = 0x0b;
/// Vendor index: CC detect 1 (`RT711_CC_DET1`).
const CC_DET1: u8 = 0x11;
/// Vendor index: parameter & verb control (`RT711_PARA_VERB_CTL`).
const PARA_VERB_CTL: u8 = 0x1a;
/// Vendor index: combo-jack auto control 1
/// (`RT711_COMBO_JACK_AUTO_CTL1`).
const COMBO_JACK_AUTO_CTL1: u8 = 0x45;
/// Vendor index: combo-jack auto control 2
/// (`RT711_COMBO_JACK_AUTO_CTL2`).
const COMBO_JACK_AUTO_CTL2: u8 = 0x46;
/// Vendor index: inline-command control (`RT711_INLINE_CMD_CTL`).
const INLINE_CMD_CTL: u8 = 0x48;
/// Vendor index: digital misc control 4
/// (`RT711_DIGITAL_MISC_CTRL4`).
const DIGITAL_MISC_CTRL4: u8 = 0x4a;
/// Vendor index: VREF-out control (`RT711_VREFOUT_CTL`).
const VREFOUT_CTL: u8 = 0x6b;
/// Vendor index: TX/RX mux control (`RT711_TX_RX_MUX_CTL`).
const TX_RX_MUX_CTL: u8 = 0x91;

/// HDA data-register bytes of a verb/index response
/// (`RT711_READ_HDA_3..0`): the codec places the 32-bit response
/// here after the verb is issued, most-significant byte first.
const READ_HDA_3: u32 = 0x2012;
const READ_HDA_2: u32 = 0x2013;
const READ_HDA_1: u32 = 0x2014;
const READ_HDA_0: u32 = 0x2015;

/// Private index-write high byte (`RT711_PRIV_INDEX_W_H`).
const PRIV_INDEX_W_H: u32 = 0x7500;
/// Private data-write high byte (`RT711_PRIV_DATA_W_H`).
const PRIV_DATA_W_H: u32 = 0x7400;
/// Private data-read high byte (`RT711_PRIV_DATA_R_H`).
const PRIV_DATA_R_H: u32 = 0x9c00;

/// HDA verb: set power state (`RT711_VERB_SET_POWER_STATE`).
const VERB_SET_POWER_STATE: u16 = 0x3500;
/// HDA verb: set pin-widget control
/// (`RT711_VERB_SET_PIN_WIDGET_CONTROL`).
const VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x3700;
/// HDA verb: set unsolicited enable
/// (`RT711_VERB_SET_UNSOLICITED_ENABLE`).
const VERB_SET_UNSOLICITED_ENABLE: u16 = 0x3800;
/// HDA verb: set amp gain/mute, high byte
/// (`RT711_SET_AMP_GAIN_MUTE_H`).
const SET_AMP_GAIN_MUTE_H: u16 = 0x7300;
/// HDA verb: get pin sense (`RT711_VERB_GET_PIN_SENSE`).
const VERB_GET_PIN_SENSE: u16 = 0xb900;
/// HDA verb: function reset (`RT711_FUNC_RESET`).
const FUNC_RESET: u16 = 0xff01;

/// Set-audio-power-state verb for the audio function group.
const SET_AUDIO_POWER_STATE: u16 = VERB_SET_POWER_STATE | AUDIO_FUNCTION_GROUP;
/// Set-pin-widget-control verbs, by node.
const SET_PIN_MIC2: u16 = VERB_SET_PIN_WIDGET_CONTROL | MIC2;
const SET_PIN_HP: u16 = VERB_SET_PIN_WIDGET_CONTROL | HP_OUT;
const SET_PIN_DMIC1: u16 = VERB_SET_PIN_WIDGET_CONTROL | DMIC1;
const SET_PIN_DMIC2: u16 = VERB_SET_PIN_WIDGET_CONTROL | DMIC2;
const SET_PIN_LINE1: u16 = VERB_SET_PIN_WIDGET_CONTROL | LINE1;
const SET_PIN_LINE2: u16 = VERB_SET_PIN_WIDGET_CONTROL | LINE2;
/// Set-unsolicited-enable verbs, by node.
const SET_MIC2_UNSOLICITED_ENABLE: u16 = VERB_SET_UNSOLICITED_ENABLE | MIC2;
const SET_HP_UNSOLICITED_ENABLE: u16 = VERB_SET_UNSOLICITED_ENABLE | HP_OUT;
const SET_INLINE_UNSOLICITED_ENABLE: u16 = VERB_SET_UNSOLICITED_ENABLE | 0x55;
/// Set-amp-gain/mute high-byte verbs, by node.
const SET_GAIN_HP_H: u16 = SET_AMP_GAIN_MUTE_H | HP_OUT;
const SET_GAIN_ADC1_H: u16 = SET_AMP_GAIN_MUTE_H | ADC_IN1;
const SET_GAIN_ADC2_H: u16 = SET_AMP_GAIN_MUTE_H | ADC_IN2;
/// Get-pin-sense verb for the headphone pin.
const GET_PIN_SENSE_HP: u16 = VERB_GET_PIN_SENSE | HP_OUT;

/// HDA power states (`AC_PWRST_D0` / `AC_PWRST_D3`).
const PWRST_D0: u16 = 0x00;
const PWRST_D3: u16 = 0x03;

/// Pin-sense response bit: the pin is attached (jack in).
const PIN_ATTACHED: u32 = 1 << 31;

/// Combo-jack auto-detect status bits
/// (`RT711_COMBOJACK_AUTO_DET_*`).
const AUTO_DET_STATUS: u32 = 0x1 << 11;
const AUTO_DET_TRS: u32 = 0x1 << 10;
const AUTO_DET_CTIA: u32 = 0x1 << 9;
const AUTO_DET_OMTP: u32 = 0x1 << 8;

/// Hidden software-reset bit in `PARA_VERB_CTL`
/// (`RT711_HIDDEN_REG_SW_RESET`).
const HIDDEN_REG_SW_RESET: u16 = 0x1 << 14;

/// Configuration-default writes from `rt711_io_init`: plain
/// registers (`< 0x4fff`) and their reset values, in Linux order.
const CONFIG_DEFAULTS: &[(u16, u8)] = &[
    (0x4f12, 0x91),
    (0x4e12, 0xd6),
    (0x4d12, 0x11),
    (0x4c12, 0x20),
    (0x4f13, 0x91),
    (0x4e13, 0xd6),
    (0x4d13, 0x11),
    (0x4c13, 0x21),
    (0x4c21, 0xf0),
    (0x4d21, 0x11),
    (0x4e21, 0x11),
    (0x4f21, 0x01),
];

/// Jack-detect source (`rt711_jd_src` in `rt711.h`): which physical
/// jack-detect circuit the board wires. The codec default is JD2
/// (`rt711_init`); the AMD legacy machine driver defaults to JD1
/// (`sound/soc/amd/acp/acp-sdw-legacy-mach.c`, `soc_sdw_quirk =
/// RT711_JD1`), and the `realtek,jd-src` device-tree property
/// overrides it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JdSrc {
    /// JD1: the codec's default settings already select it; the
    /// init sequence writes no JD control bits.
    Jd1,
    /// JD2, 200 kΩ decode (the codec default).
    Jd2,
    /// JD2, 100 kΩ decode.
    Jd2_100k,
    /// JD2, 1.8 V single-port mode.
    Jd2_1p8v_1port,
}

/// What the jack-detect poll found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JackState {
    /// No jack present (or pulled mid-detect).
    Out,
    /// Headphone (TRS) plugged in.
    Headphone,
    /// Headset (CTIA or OMTP) plugged in.
    Headset,
}

/// Write one HDA verb (`verb` is the full 16-bit verb+NID word)
/// with a 16-bit `value`, encoded onto SoundWire byte writes
/// exactly as Linux's `rt711_sdw_write` does:
///
/// - plain registers (`< 0x4fff`) and `FUNC_RESET`: one byte write;
/// - `0x7000` verbs (amp gain/mute high): high byte, then low byte
///   at `(reg + 0x1000) | 0x80`;
/// - `0x83xx` verbs (amp gain/mute low, R channel): high byte at
///   `(reg - 0x1000) & !0x80`, then low byte at `reg`.
///
/// Verbs outside that map (notably the `0xbxxx` GET verbs, which
/// are reads) are rejected: Linux's write path silently drops
/// them, and a silent drop is a lie this driver will not tell.
/// Use [`verb_read32`] for GET verbs.
pub fn verb_write<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    verb: u16,
    value: u16,
) -> Result<(), SdwError> {
    let reg = verb as u32;
    let mask = reg & 0xf000;
    if reg < 0x4fff || reg == FUNC_RESET as u32 {
        bus.write_reg(dev, reg, (value & 0xff) as u8)
    } else if mask == 0x7000 {
        bus.write_reg(dev, reg, (value >> 8) as u8)?;
        bus.write_reg(dev, (reg + 0x1000) | 0x80, (value & 0xff) as u8)
    } else if (reg & 0xff00) == 0x8300 {
        bus.write_reg(dev, (reg - 0x1000) & !0x80, (value >> 8) as u8)?;
        bus.write_reg(dev, reg, (value & 0xff) as u8)
    } else {
        Err(SdwError::InvalidAddress)
    }
}

/// Issue a GET verb (`0xbxxx`) and read back the 32-bit response
/// from the HDA data registers, as Linux's `rt711_sdw_read` does
/// for the `0xb000` mask: the verb is issued as a single write,
/// then 0x2012..0x2015 assemble the response, most-significant
/// byte first.
pub fn verb_read32<T: Transport>(bus: &Bus<T>, dev: u8, verb: u16) -> Result<u32, SdwError> {
    let reg = verb as u32;
    if reg & 0xf000 != 0xb000 {
        return Err(SdwError::InvalidAddress);
    }
    bus.write_reg(dev, reg, 0)?;
    read_hda_response(bus, dev)
}

fn read_hda_response<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<u32, SdwError> {
    let d3 = bus.read_reg(dev, READ_HDA_3)? as u32;
    let d2 = bus.read_reg(dev, READ_HDA_2)? as u32;
    let d1 = bus.read_reg(dev, READ_HDA_1)? as u32;
    let d0 = bus.read_reg(dev, READ_HDA_0)? as u32;
    Ok((d3 << 24) | (d2 << 16) | (d1 << 8) | d0)
}

/// Write a 16-bit value to a vendor index register behind `nid`
/// (`rt711_index_write`): the 24-bit index address
/// `((PRIV_INDEX_W_H | nid) << 8) | index` expands to four SDW
/// byte writes — index-high 0, index-low, data-high, data-low.
pub fn index_write<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    nid: u8,
    index: u8,
    value: u16,
) -> Result<(), SdwError> {
    let index_h = PRIV_INDEX_W_H | nid as u32;
    let index_l = (index_h + 0x1000) | 0x80;
    let data_h = PRIV_DATA_W_H | nid as u32;
    let data_l = (data_h + 0x1000) | 0x80;
    bus.write_reg(dev, index_h, 0)?;
    bus.write_reg(dev, index_l, index)?;
    bus.write_reg(dev, data_h, (value >> 8) as u8)?;
    bus.write_reg(dev, data_l, (value & 0xff) as u8)
}

/// Read a vendor index register behind `nid`
/// (`rt711_index_read`): issue the index read (four byte writes,
/// the data-read registers carrying zero), then assemble the
/// 32-bit response from the HDA data registers.
pub fn index_read<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    nid: u8,
    index: u8,
) -> Result<u32, SdwError> {
    let index_h = PRIV_INDEX_W_H | nid as u32;
    let index_l = (index_h + 0x1000) | 0x80;
    let data_r_h = PRIV_DATA_R_H | nid as u32;
    let data_r_l = (data_r_h + 0x1000) | 0x80;
    bus.write_reg(dev, index_h, 0)?;
    bus.write_reg(dev, index_l, index)?;
    bus.write_reg(dev, data_r_h, 0)?;
    bus.write_reg(dev, data_r_l, 0)?;
    read_hda_response(bus, dev)
}

/// Read-modify-write one vendor index register
/// (`rt711_index_update_bits`): read the current value, apply
/// `mask`/`value`, and write the result back unconditionally.
pub fn index_update_bits<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    nid: u8,
    index: u8,
    mask: u16,
    value: u16,
) -> Result<(), SdwError> {
    let orig = index_read(bus, dev, nid, index)?;
    let tmp = (orig & !(mask as u32)) | (value as u32 & mask as u32);
    index_write(bus, dev, nid, index, tmp as u16)
}

/// Attach-time codec init (`rt711_io_init`, minus the deferred
/// DAC DC-offset calibration, which is a follow-up): reset, power
/// D0, pin widgets, gain mutes, configuration defaults, data-port
/// arrangement and index settings, then power D3. Runs at attach
/// (Linux `update_status` → `io_init`); the ACP binding calls it
/// for every enumerated RT711.
pub fn io_init<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<(), SdwError> {
    // Reset: function reset + hidden software reset (`rt711_reset`).
    verb_write(bus, dev, FUNC_RESET, 0)?;
    index_update_bits(
        bus,
        dev,
        VENDOR_REG,
        PARA_VERB_CTL,
        HIDDEN_REG_SW_RESET,
        HIDDEN_REG_SW_RESET,
    )?;
    // Power on.
    verb_write(bus, dev, SET_AUDIO_POWER_STATE, PWRST_D0)?;
    // Set pin widgets.
    verb_write(bus, dev, SET_PIN_MIC2, 0x25)?;
    verb_write(bus, dev, SET_PIN_HP, 0xc0)?;
    verb_write(bus, dev, SET_PIN_DMIC1, 0x20)?;
    verb_write(bus, dev, SET_PIN_DMIC2, 0x20)?;
    verb_write(bus, dev, SET_PIN_LINE1, 0x20)?;
    verb_write(bus, dev, SET_PIN_LINE2, 0x20)?;
    // Mute HP/ADC1/ADC2.
    verb_write(bus, dev, SET_GAIN_HP_H, 0xa080)?;
    verb_write(bus, dev, SET_GAIN_HP_H, 0x9080)?;
    verb_write(bus, dev, SET_GAIN_ADC2_H, 0x6080)?;
    verb_write(bus, dev, SET_GAIN_ADC2_H, 0x5080)?;
    verb_write(bus, dev, SET_GAIN_ADC1_H, 0x6080)?;
    verb_write(bus, dev, SET_GAIN_ADC1_H, 0x5080)?;
    // Set configuration defaults.
    for &(reg, value) in CONFIG_DEFAULTS {
        verb_write(bus, dev, reg, value)?;
    }
    // Data-port arrangement.
    index_write(bus, dev, VENDOR_REG, TX_RX_MUX_CTL, 0x0154)?;
    // Set index registers.
    index_write(bus, dev, VENDOR_REG, DIGITAL_MISC_CTRL4, 0x201b)?;
    index_write(bus, dev, VENDOR_REG, COMBO_JACK_AUTO_CTL1, 0x5089)?;
    index_write(bus, dev, VENDOR_REG, VREFOUT_CTL, 0x5064)?;
    index_write(bus, dev, VENDOR_REG, INLINE_CMD_CTL, 0xd249)?;
    // Finish initial settings, set power to D3.
    verb_write(bus, dev, SET_AUDIO_POWER_STATE, PWRST_D3)
}

/// Arm jack detection (`rt711_jack_init`): power D0, enable
/// unsolicited responses on the mic/headphone/inline-command pins,
/// write the combo-jack index registers, program the JD source's
/// control bits, then power D3. The JD source is a board property:
/// JD1 on the AMD legacy machine driver, JD2 by codec default.
/// The caller runs this once the jack consumer exists (Linux
/// `set_jack` → `jack_init`); it is not part of attach-time init.
pub fn jack_init<T: Transport>(bus: &Bus<T>, dev: u8, jd_src: JdSrc) -> Result<(), SdwError> {
    // Power on.
    verb_write(bus, dev, SET_AUDIO_POWER_STATE, PWRST_D0)?;
    // Unsolicited response & IRQ control.
    verb_write(bus, dev, SET_MIC2_UNSOLICITED_ENABLE, 0x82)?;
    verb_write(bus, dev, SET_HP_UNSOLICITED_ENABLE, 0x81)?;
    verb_write(bus, dev, SET_INLINE_UNSOLICITED_ENABLE, 0x83)?;
    index_write(bus, dev, VENDOR_REG, 0x10, 0x2420)?;
    index_write(bus, dev, VENDOR_REG, 0x19, 0x2e11)?;
    match jd_src {
        JdSrc::Jd1 => {
            // Default settings are already JD1.
        }
        JdSrc::Jd2 => {
            // JD_CTL2: 200 kΩ HP decode + JD2 select.
            index_update_bits(bus, dev, VENDOR_REG, JD_CTL2, 0x2002, 0x2002)?;
            // CC_DET1: final result from JD1/JD2.
            index_update_bits(bus, dev, VENDOR_REG, CC_DET1, 0x0400, 0x0400)?;
        }
        JdSrc::Jd2_100k => {
            index_update_bits(bus, dev, VENDOR_REG, JD_CTL2, 0x1c03, 0x0402)?;
            index_update_bits(bus, dev, VENDOR_REG, CC_DET1, 0x0400, 0x0400)?;
        }
        JdSrc::Jd2_1p8v_1port => {
            index_update_bits(bus, dev, VENDOR_REG, JD_CTL1, 0x0002, 0x0000)?;
            index_update_bits(bus, dev, VENDOR_REG, JD_CTL2, 0x0c02, 0x0402)?;
            index_update_bits(bus, dev, VENDOR_REG, JD_CTL4, 0x000b, 0x000a)?;
            index_update_bits(bus, dev, VENDOR_REG, CC_DET1, 0x0400, 0x0400)?;
        }
    }
    // Power off.
    verb_write(bus, dev, SET_AUDIO_POWER_STATE, PWRST_D3)
}

#[derive(Debug)]
enum DetectStep {
    /// Auto-detect status not set yet; keep polling.
    Waiting,
    /// Jack pulled while detecting.
    Removed,
    /// Detection finished.
    Done(JackState),
}

fn pin_sense<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<u32, SdwError> {
    verb_read32(bus, dev, GET_PIN_SENSE_HP)
}

/// One headset-detect poll step (`rt711_headset_detect`): read the
/// combo-jack auto-detect status; while it is clear, re-check pin
/// sense (a jack pulled mid-detect reports removal); once set,
/// decode TRS as headphone, CTIA/OMTP as headset, and no type bit
/// as no jack (Linux leaves `jack_type` 0 there).
fn headset_detect_step<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<DetectStep, SdwError> {
    let auto = index_read(bus, dev, VENDOR_REG, COMBO_JACK_AUTO_CTL2)?;
    if auto & AUTO_DET_STATUS == 0 {
        let sense = pin_sense(bus, dev)?;
        if sense & PIN_ATTACHED == 0 {
            return Ok(DetectStep::Removed);
        }
        return Ok(DetectStep::Waiting);
    }
    if auto & AUTO_DET_TRS != 0 {
        return Ok(DetectStep::Done(JackState::Headphone));
    }
    if auto & (AUTO_DET_CTIA | AUTO_DET_OMTP) != 0 {
        return Ok(DetectStep::Done(JackState::Headset));
    }
    Ok(DetectStep::Done(JackState::Out))
}

/// Polled jack detection (`rt711_jack_detect_handler` +
/// `rt711_headset_detect`, without the interrupt trigger): read
/// pin sense — a detached pin is `Out` — then poll the combo-jack
/// auto-detect status until it sets. `timeout_ms` bounds the poll:
/// Linux allows up to 500 iterations ~10 ms apart (~5 s); pass
/// that budget in production, a smaller one in tests. A transport
/// failure aborts with its error; a poll that never completes
/// fails `Timeout` — never a phantom jack state.
pub fn jack_detect<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    timeout_ms: u64,
) -> Result<JackState, SdwError> {
    let sense = pin_sense(bus, dev)?;
    if sense & PIN_ATTACHED == 0 {
        return Ok(JackState::Out);
    }
    let mut state = None;
    let mut failure = None;
    let finished = narf_scheduler::responsive_spin_until(
        || match headset_detect_step(bus, dev) {
            Ok(DetectStep::Done(detected)) => {
                state = Some(detected);
                true
            }
            Ok(DetectStep::Removed) => {
                state = Some(JackState::Out);
                true
            }
            Ok(DetectStep::Waiting) => false,
            Err(error) => {
                failure = Some(error);
                true
            }
        },
        Deadline::after_ms(timeout_ms),
    );
    if let Some(error) = failure {
        return Err(error);
    }
    if !finished {
        return Err(SdwError::Timeout);
    }
    Ok(state.unwrap_or(JackState::Out))
}

/// Map a bus data-rate frequency to the clock-select value written
/// to registers 0xe0/0xf0 (`rt711_clock_config`: the value selects
/// on `curr_dr_freq >> 1`). Unknown rates fail `InvalidParams`
/// rather than programming a wrong clock.
pub fn clock_value(dr_freq_hz: u32) -> Result<u8, SdwError> {
    match dr_freq_hz >> 1 {
        12_000_000 => Ok(0x0),
        6_000_000 => Ok(0x1),
        9_600_000 => Ok(0x2),
        4_800_000 => Ok(0x3),
        2_400_000 => Ok(0x4),
        12_288_000 => Ok(0x5),
        _ => Err(SdwError::InvalidParams),
    }
}

/// Program the bus-clock select registers for `dr_freq_hz`
/// (`rt711_clock_config`). Wiring this into stream setup needs the
/// manager's current data rate, so no in-tree caller uses it yet.
pub fn clock_config<T: Transport>(bus: &Bus<T>, dev: u8, dr_freq_hz: u32) -> Result<(), SdwError> {
    let value = clock_value(dr_freq_hz)?;
    bus.write_reg(dev, 0xe0, value)?;
    bus.write_reg(dev, 0xf0, value)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    /// One transfer on the model bus, recorded for framing assertions.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Xfer {
        dev: u8,
        addr: u32,
        write: Option<u8>,
    }

    fn w(dev: u8, addr: u32, value: u8) -> Xfer {
        Xfer {
            dev,
            addr,
            write: Some(value),
        }
    }

    fn r(dev: u8, addr: u32) -> Xfer {
        Xfer {
            dev,
            addr,
            write: None,
        }
    }

    /// A modelled RT711: plain registers in a map, plus the HDA
    /// response mechanism the real codec implements — after a GET
    /// verb is issued, reads of 0x2012..0x2015 return the pending
    /// response; after an index read is issued (its last write
    /// lands on the data-read low register), they return the
    /// programmed value of that index. This is the behaviour
    /// Linux's `rt711_sdw_read` relies on, modelled from the
    /// driver, not from this module's code: the pending response
    /// is set by the *operation issued*, and the per-index values
    /// are test inputs.
    #[derive(Debug)]
    struct FakeTransport {
        regs: IrqSafeSpinLock<BTreeMap<u32, u8>>,
        log: IrqSafeSpinLock<Vec<Xfer>>,
        pin_sense: IrqSafeSpinLock<u32>,
        pin_sense_after_first: IrqSafeSpinLock<Option<u32>>,
        pin_sense_reads: IrqSafeSpinLock<u32>,
        index_values: IrqSafeSpinLock<BTreeMap<u8, u32>>,
        pending: IrqSafeSpinLock<u32>,
        last_index: IrqSafeSpinLock<u8>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                regs: IrqSafeSpinLock::new(BTreeMap::new()),
                log: IrqSafeSpinLock::new(Vec::new()),
                pin_sense: IrqSafeSpinLock::new(0),
                pin_sense_after_first: IrqSafeSpinLock::new(None),
                pin_sense_reads: IrqSafeSpinLock::new(0),
                index_values: IrqSafeSpinLock::new(BTreeMap::new()),
                pending: IrqSafeSpinLock::new(0),
                last_index: IrqSafeSpinLock::new(0),
            }
        }
        fn log(&self) -> Vec<Xfer> {
            self.log.lock().clone()
        }
        /// Collect the (index, value) pairs of every index write
        /// in the log, in order: an index write is the four-transfer
        /// pattern [W(0x7520,0), W(0x8520,idx), W(0x7420,hi),
        /// W(0x8420,lo)].
        fn index_writes(&self) -> Vec<(u8, u16)> {
            let log = self.log();
            let mut out = Vec::new();
            let mut i = 0;
            while i + 3 < log.len() {
                if log[i] == w(1, 0x7520, 0)
                    && log[i + 1].addr == 0x8520
                    && log[i + 1].write.is_some()
                    && log[i + 2].addr == 0x7420
                    && log[i + 2].write.is_some()
                    && log[i + 3].addr == 0x8420
                    && log[i + 3].write.is_some()
                {
                    let idx = log[i + 1].write.unwrap();
                    let hi = log[i + 2].write.unwrap() as u16;
                    let lo = log[i + 3].write.unwrap() as u16;
                    out.push((idx, (hi << 8) | lo));
                    i += 4;
                } else {
                    i += 1;
                }
            }
            out
        }
    }

    impl Transport for FakeTransport {
        fn xfer(&self, dev: u8, addr: u32, write: Option<u8>) -> Result<Option<u8>, SdwError> {
            {
                let mut log = self.log.lock();
                if log.len() < 1024 {
                    log.push(Xfer { dev, addr, write });
                }
            }
            if let Some(value) = write {
                if addr == 0x8520 {
                    *self.last_index.lock() = value;
                }
                if addr == 0xaca0 {
                    let idx = *self.last_index.lock();
                    let response = self.index_values.lock().get(&idx).copied().unwrap_or(0);
                    *self.pending.lock() = response;
                }
                if addr == 0xb921 {
                    let mut reads = self.pin_sense_reads.lock();
                    let response = if *reads == 0 {
                        *self.pin_sense.lock()
                    } else {
                        self.pin_sense_after_first
                            .lock()
                            .unwrap_or(*self.pin_sense.lock())
                    };
                    *reads += 1;
                    *self.pending.lock() = response;
                }
                self.regs.lock().insert(addr, value);
                return Ok(None);
            }
            match addr {
                READ_HDA_3 => Ok(Some((*self.pending.lock() >> 24) as u8)),
                READ_HDA_2 => Ok(Some((*self.pending.lock() >> 16) as u8)),
                READ_HDA_1 => Ok(Some((*self.pending.lock() >> 8) as u8)),
                READ_HDA_0 => Ok(Some(*self.pending.lock() as u8)),
                _ => Ok(Some(self.regs.lock().get(&addr).copied().unwrap_or(0))),
            }
        }
        fn bus_reset(&self) -> Result<(), SdwError> {
            Ok(())
        }
        fn frame_shape(&self) -> (u32, u32) {
            (50, 10)
        }
    }

    fn verb_write_encodings() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        // Plain verb: one byte write at its own address.
        if verb_write(&bus, 1, 0x3721, 0xc0) != Ok(()) {
            return TestResult::Fail("plain verb write failed");
        }
        // 0x7000 verb: high byte, then low byte at +0x1000|0x80.
        if verb_write(&bus, 1, 0x7321, 0xa080) != Ok(()) {
            return TestResult::Fail("0x7000 verb write failed");
        }
        // 0x83xx verb (R channel): high byte at -0x1000 & !0x80,
        // then low byte at the verb address.
        if verb_write(&bus, 1, 0x83a1, 0xa080) != Ok(()) {
            return TestResult::Fail("0x83xx verb write failed");
        }
        // Function reset: one byte write.
        if verb_write(&bus, 1, 0xff01, 0x00) != Ok(()) {
            return TestResult::Fail("reset verb write failed");
        }
        // GET verbs are reads, not writes; verbs outside the map
        // fail closed instead of being silently dropped.
        if verb_write(&bus, 1, 0xb921, 0x00) != Err(SdwError::InvalidAddress) {
            return TestResult::Fail("GET verb write must be rejected");
        }
        if verb_write(&bus, 1, 0x6000, 0x00) != Err(SdwError::InvalidAddress) {
            return TestResult::Fail("unmapped verb write must be rejected");
        }
        if verb_read32(&bus, 1, 0x3721) != Err(SdwError::InvalidAddress) {
            return TestResult::Fail("non-GET verb read must be rejected");
        }
        let expected = [
            w(1, 0x3721, 0xc0),
            w(1, 0x7321, 0xa0),
            w(1, 0x83a1, 0x80),
            w(1, 0x7321, 0xa0),
            w(1, 0x83a1, 0x80),
            w(1, 0xff01, 0x00),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("verb write framing mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", verb_write_encodings);

    fn index_read_write_update_bits() -> TestResult {
        let transport = FakeTransport::new();
        transport.index_values.lock().insert(0x09, 0x0000_2002);
        let bus = Bus::new(transport);
        // One index write: index-high 0, index-low, data-high,
        // data-low.
        if index_write(&bus, 1, VENDOR_REG, 0x91, 0x0154) != Ok(()) {
            return TestResult::Fail("index write failed");
        }
        // One index read: the same four writes (data-read
        // registers carrying zero), then the HDA data registers.
        if index_read(&bus, 1, VENDOR_REG, 0x09) != Ok(0x2002) {
            return TestResult::Fail("index read mismatch");
        }
        // Update-bits on a zeroed register lands the value itself.
        if index_update_bits(&bus, 1, VENDOR_REG, 0x09, 0x2002, 0x2002) != Ok(()) {
            return TestResult::Fail("index update-bits failed");
        }
        let expected = [
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x91),
            w(1, 0x7420, 0x01),
            w(1, 0x8420, 0x54),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x09),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x09),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x09),
            w(1, 0x7420, 0x20),
            w(1, 0x8420, 0x02),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("index conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", index_read_write_update_bits);

    fn io_init_conversation() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        if io_init(&bus, 1) != Ok(()) {
            return TestResult::Fail("io_init failed");
        }
        // The full attach-time conversation from `rt711_io_init`,
        // hand-derived from the Linux sequence through the
        // verb/index encodings above: reset (1) + hidden-reset
        // update (12) + power D0 (1) + pins (6) + gain mutes (12)
        // + config defaults (12) + index writes (20) + power D3 (1).
        let expected = [
            w(1, 0xff01, 0x00),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x1a),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x1a),
            w(1, 0x7420, 0x40),
            w(1, 0x8420, 0x00),
            w(1, 0x3501, 0x00),
            w(1, 0x3719, 0x25),
            w(1, 0x3721, 0xc0),
            w(1, 0x3712, 0x20),
            w(1, 0x3713, 0x20),
            w(1, 0x371a, 0x20),
            w(1, 0x371b, 0x20),
            w(1, 0x7321, 0xa0),
            w(1, 0x83a1, 0x80),
            w(1, 0x7321, 0x90),
            w(1, 0x83a1, 0x80),
            w(1, 0x7308, 0x60),
            w(1, 0x8388, 0x80),
            w(1, 0x7308, 0x50),
            w(1, 0x8388, 0x80),
            w(1, 0x7309, 0x60),
            w(1, 0x8389, 0x80),
            w(1, 0x7309, 0x50),
            w(1, 0x8389, 0x80),
            w(1, 0x4f12, 0x91),
            w(1, 0x4e12, 0xd6),
            w(1, 0x4d12, 0x11),
            w(1, 0x4c12, 0x20),
            w(1, 0x4f13, 0x91),
            w(1, 0x4e13, 0xd6),
            w(1, 0x4d13, 0x11),
            w(1, 0x4c13, 0x21),
            w(1, 0x4c21, 0xf0),
            w(1, 0x4d21, 0x11),
            w(1, 0x4e21, 0x11),
            w(1, 0x4f21, 0x01),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x91),
            w(1, 0x7420, 0x01),
            w(1, 0x8420, 0x54),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x4a),
            w(1, 0x7420, 0x20),
            w(1, 0x8420, 0x1b),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x45),
            w(1, 0x7420, 0x50),
            w(1, 0x8420, 0x89),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x6b),
            w(1, 0x7420, 0x50),
            w(1, 0x8420, 0x64),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x48),
            w(1, 0x7420, 0xd2),
            w(1, 0x8420, 0x49),
            w(1, 0x3501, 0x03),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("io_init conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", io_init_conversation);

    fn jack_init_jd1_conversation() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        if jack_init(&bus, 1, JdSrc::Jd1) != Ok(()) {
            return TestResult::Fail("jack_init JD1 failed");
        }
        // JD1 writes no JD control bits: power D0 (1) +
        // unsolicited enables (3) + index writes (8) + power D3 (1).
        let expected = [
            w(1, 0x3501, 0x00),
            w(1, 0x3819, 0x82),
            w(1, 0x3821, 0x81),
            w(1, 0x3855, 0x83),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x10),
            w(1, 0x7420, 0x24),
            w(1, 0x8420, 0x20),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x19),
            w(1, 0x7420, 0x2e),
            w(1, 0x8420, 0x11),
            w(1, 0x3501, 0x03),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("jack_init JD1 conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", jack_init_jd1_conversation);

    fn jack_init_jd2_conversation() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        if jack_init(&bus, 1, JdSrc::Jd2) != Ok(()) {
            return TestResult::Fail("jack_init JD2 failed");
        }
        // JD1 prefix (12) + JD_CTL2 update (12) + CC_DET1
        // update (12) + power D3 (1).
        let expected = [
            w(1, 0x3501, 0x00),
            w(1, 0x3819, 0x82),
            w(1, 0x3821, 0x81),
            w(1, 0x3855, 0x83),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x10),
            w(1, 0x7420, 0x24),
            w(1, 0x8420, 0x20),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x19),
            w(1, 0x7420, 0x2e),
            w(1, 0x8420, 0x11),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x09),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x09),
            w(1, 0x7420, 0x20),
            w(1, 0x8420, 0x02),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x11),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x11),
            w(1, 0x7420, 0x04),
            w(1, 0x8420, 0x00),
            w(1, 0x3501, 0x03),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("jack_init JD2 conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", jack_init_jd2_conversation);

    fn jack_init_other_jd_sources() -> TestResult {
        // The 100 kΩ and 1.8 V variants differ from JD2 only in
        // the index-write values they land; assert those pairs in
        // order (the shared prefix is pinned by the JD1/JD2
        // exact-log tests above).
        let bus = Bus::new(FakeTransport::new());
        if jack_init(&bus, 1, JdSrc::Jd2_100k) != Ok(()) {
            return TestResult::Fail("jack_init JD2_100k failed");
        }
        if bus.transport().index_writes()
            != [
                (0x10, 0x2420),
                (0x19, 0x2e11),
                (0x09, 0x0402),
                (0x11, 0x0400),
            ]
        {
            return TestResult::Fail("JD2_100k index writes mismatch");
        }
        let bus = Bus::new(FakeTransport::new());
        if jack_init(&bus, 1, JdSrc::Jd2_1p8v_1port) != Ok(()) {
            return TestResult::Fail("jack_init JD2_1p8v failed");
        }
        if bus.transport().index_writes()
            != [
                (0x10, 0x2420),
                (0x19, 0x2e11),
                (0x08, 0x0000),
                (0x09, 0x0402),
                (0x0b, 0x000a),
                (0x11, 0x0400),
            ]
        {
            return TestResult::Fail("JD2_1p8v index writes mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", jack_init_other_jd_sources);

    fn jack_detect_headset_headphone_out() -> TestResult {
        // Headset: pin sense attached, auto-detect status +
        // CTIA set.
        let transport = FakeTransport::new();
        *transport.pin_sense.lock() = 0x8000_0000;
        transport.index_values.lock().insert(0x46, 0x0000_0a00);
        let bus = Bus::new(transport);
        if jack_detect(&bus, 1, 5000) != Ok(JackState::Headset) {
            return TestResult::Fail("headset detect mismatch");
        }
        let expected = [
            w(1, 0xb921, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
            w(1, 0x7520, 0x00),
            w(1, 0x8520, 0x46),
            w(1, 0x9c20, 0x00),
            w(1, 0xaca0, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("headset detect conversation mismatch");
        }
        // Headphone: status + TRS set.
        let transport = FakeTransport::new();
        *transport.pin_sense.lock() = 0x8000_0000;
        transport.index_values.lock().insert(0x46, 0x0000_0c00);
        let bus = Bus::new(transport);
        if jack_detect(&bus, 1, 5000) != Ok(JackState::Headphone) {
            return TestResult::Fail("headphone detect mismatch");
        }
        // Out: pin sense detached, no auto-detect poll at all.
        let transport = FakeTransport::new();
        *transport.pin_sense.lock() = 0x0000_0000;
        let bus = Bus::new(transport);
        if jack_detect(&bus, 1, 5000) != Ok(JackState::Out) {
            return TestResult::Fail("jack-out detect mismatch");
        }
        let expected_out = [
            w(1, 0xb921, 0x00),
            r(1, 0x2012),
            r(1, 0x2013),
            r(1, 0x2014),
            r(1, 0x2015),
        ];
        if bus.transport().log() != expected_out {
            return TestResult::Fail("jack-out conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", jack_detect_headset_headphone_out);

    fn jack_detect_removal_and_timeout() -> TestResult {
        // Removal mid-detect: attached on the first pin sense,
        // detached on the re-check after a clear status read.
        let transport = FakeTransport::new();
        *transport.pin_sense.lock() = 0x8000_0000;
        *transport.pin_sense_after_first.lock() = Some(0x0000_0000);
        transport.index_values.lock().insert(0x46, 0x0000_0000);
        let bus = Bus::new(transport);
        if jack_detect(&bus, 1, 5000) != Ok(JackState::Out) {
            return TestResult::Fail("mid-detect removal must report Out");
        }
        // Timeout: attached, but the auto-detect status never sets.
        let transport = FakeTransport::new();
        *transport.pin_sense.lock() = 0x8000_0000;
        transport.index_values.lock().insert(0x46, 0x0000_0000);
        let bus = Bus::new(transport);
        if jack_detect(&bus, 1, 10) != Err(SdwError::Timeout) {
            return TestResult::Fail("stuck auto-detect must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", jack_detect_removal_and_timeout);

    fn clock_config_mapping() -> TestResult {
        // `rt711_clock_config`'s table, keyed on `curr_dr_freq`:
        // the value selects on the halved rate.
        if clock_value(24_000_000) != Ok(0x0)
            || clock_value(12_000_000) != Ok(0x1)
            || clock_value(19_200_000) != Ok(0x2)
            || clock_value(9_600_000) != Ok(0x3)
            || clock_value(4_800_000) != Ok(0x4)
            || clock_value(24_576_000) != Ok(0x5)
            || clock_value(1_000_000) != Err(SdwError::InvalidParams)
        {
            return TestResult::Fail("clock value mapping mismatch");
        }
        let bus = Bus::new(FakeTransport::new());
        if clock_config(&bus, 1, 9_600_000) != Ok(()) {
            return TestResult::Fail("clock config failed");
        }
        if bus.transport().log() != [w(1, 0x00e0, 0x03), w(1, 0x00f0, 0x03)] {
            return TestResult::Fail("clock config framing mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt711", clock_config_mapping);
}
