//! HFP — Hands-Free Profile (audio gateway + hands-free roles).
//!
//! The AT command codec lives in [`crate::hfp`].  This module adds:
//!
//! - Service-Level Connection (SLC) state machine (§4.2).
//! - SCO codec negotiation: CVSD (narrow-band, mandatory) and mSBC
//!   (wide-band, optional HFP 1.6+, §4.34 codec-negotiation feature).
//! - SCO setup parameter selection per HFP §4.11 / Core spec §7.1.26.
//!
//! ## SLC establishment sequence (HFP 1.8 §4.2)
//!
//! ```text
//!  Idle
//!   └─ L2CAP RFCOMM connected
//!       └─ HF sends AT+BRSF=<hf_features>
//!           └─ AG responds +BRSF:<ag_features>  OK
//!               └─ codec negotiation (if both sides set HF_FEAT_CODEC_NEGOTIATION)
//!               └─ HF sends AT+CIND=?
//!                   └─ AG responds +CIND:… OK
//!                       └─ HF sends AT+CIND?
//!                           └─ AG responds +CIND:… OK
//!                               └─ HF sends AT+CMER=3,0,0,1
//!                                   └─ AG responds OK
//!                                       └─ SLC Established
//! ```
//!
//! References:
//! - "Hands-Free Profile, Version 1.8" — Bluetooth SIG.
//!   §4.2 (SLC establishment), §4.11 (SCO/eSCO setup),
//!   §4.34 (BRSF bits), table 5.1 (HF + AG features).
//! - "Bluetooth Core Specification 5.3, Vol 4 Part E §7.1.26"
//!   (`HCI_Setup_Synchronous_Connection` parameter table).
//! - Linux `net/bluetooth/sco.c` and BlueZ `profiles/audio/hfp.c`
//!   consulted for SCO parameter layout
//!   (GPL-2.0-or-later, NARF relicense 2026-05-20).

use alloc::vec::Vec;

use crate::hfp::{
    brsf_command, cind_read_command, cind_test_command, cmer_enable_command, parse_at, AtForm,
};

use narf_audio::msbc::{Msbc, MSBC_FRAME_BYTES, MSBC_PCM_SAMPLES};

// ── ScoStream — SCO audio encode/decode with codec dispatch ──────────

/// Error from [`ScoStream`] encode/decode operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScoStreamError {
    /// Output buffer too small.
    OutputTooSmall,
    /// Input PCM length mismatch.
    BadInputLength,
    /// Codec-specific decode error (CRC, sync, …).
    CodecError,
    /// Codec is CVSD — mSBC path not active.
    NotMsbc,
}

/// Active SCO audio stream.  Dispatches PCM ↔ SCO-bytes encoding
/// through either CVSD (pass-through) or mSBC depending on which
/// codec was negotiated during SLC establishment.
///
/// HFP 1.8 §11.1: mSBC frames are 57 bytes per 7.5 ms SCO interval.
/// CVSD is a transparent air-coding; no frame-level codec is applied
/// here — the HCI voice-setting selects it at the controller.
///
/// Reference: HFP 1.8 §4.11 / §11.1 / BlueZ `audio/hfp.c`
/// (GPL-2.0-or-later, NARF relicense 2026-05-20).
#[derive(Debug)]
pub struct ScoStream {
    /// Codec negotiated for this SCO connection.
    pub codec: u8,
    /// mSBC codec state (valid only when `codec == CODEC_MSBC`).
    msbc: Msbc,
}

impl ScoStream {
    /// Create a new SCO stream for the given negotiated codec.
    pub fn new(codec: u8) -> Self {
        Self {
            codec,
            msbc: Msbc::new(),
        }
    }

    /// Encode 60 mono i16 PCM samples (16 kHz) into a 57-byte mSBC frame.
    ///
    /// Returns [`ScoStreamError::NotMsbc`] when the negotiated codec is
    /// CVSD — CVSD samples are delivered transparently by the HCI layer.
    pub fn encode_pcm(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, ScoStreamError> {
        match self.codec {
            CODEC_MSBC => {
                if out.len() < MSBC_FRAME_BYTES {
                    return Err(ScoStreamError::OutputTooSmall);
                }
                if pcm.len() != MSBC_PCM_SAMPLES {
                    return Err(ScoStreamError::BadInputLength);
                }
                self.msbc
                    .encode(pcm, out)
                    .map_err(|_| ScoStreamError::CodecError)
            }
            _ => Err(ScoStreamError::NotMsbc),
        }
    }

    /// Decode a 57-byte mSBC SCO packet into 60 mono i16 PCM samples.
    ///
    /// Returns [`ScoStreamError::NotMsbc`] when codec is CVSD.
    pub fn decode_sco(&mut self, sco: &[u8], pcm: &mut [i16]) -> Result<usize, ScoStreamError> {
        match self.codec {
            CODEC_MSBC => {
                if sco.len() < MSBC_FRAME_BYTES {
                    return Err(ScoStreamError::OutputTooSmall);
                }
                if pcm.len() < MSBC_PCM_SAMPLES {
                    return Err(ScoStreamError::OutputTooSmall);
                }
                self.msbc
                    .decode(sco, pcm)
                    .map_err(|_| ScoStreamError::CodecError)
            }
            _ => Err(ScoStreamError::NotMsbc),
        }
    }
}

// ── SCO codec identifiers (HFP §4.34 / Assigned Numbers) ─────────────

/// SCO codec ID: CVSD (narrow-band, 8 kHz).  Mandatory.
pub const CODEC_CVSD: u8 = 0x01;
/// SCO codec ID: mSBC (wide-band, 16 kHz).  Optional; requires codec
/// negotiation feature on both sides.
pub const CODEC_MSBC: u8 = 0x02;

// ── SCO parameter sets ────────────────────────────────────────────────

/// Parameters for `HCI_Setup_Synchronous_Connection` (Core spec 5.3
/// Vol 4 Part E §7.1.26, table 7.26).  Only the fields relevant to
/// HFP are exposed here; the rest default to "don't care" (0xFFFF /
/// controller-decided).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScoParams {
    /// Transmit bandwidth in bytes per second (8000 for 8 kHz CVSD,
    /// 16000 for 16 kHz mSBC).
    pub tx_bandwidth: u32,
    /// Receive bandwidth in bytes per second.
    pub rx_bandwidth: u32,
    /// Maximum transmit latency in milliseconds.  0xFFFF = don't care.
    pub max_latency: u16,
    /// Voice setting bitmap (Core §6.12).
    /// - 0x0060 → CVSD, 16-bit input, linear PCM.
    /// - 0x0063 → mSBC (transparent, no air-coding).
    pub voice_setting: u16,
    /// Retransmission effort.  0x02 = quality optimised (HFP preferred).
    pub retransmission_effort: u8,
    /// Allowed packet types bitmask (Core §7.1.26).
    /// 0x03C8 = EV3|EV4|EV5|2-EV3 (eSCO).  0x0007 = HV1|HV2|HV3 (SCO).
    pub packet_types: u16,
}

/// CVSD SCO parameters (HFP §4.11, narrow-band voice).
pub const SCO_PARAMS_CVSD: ScoParams = ScoParams {
    tx_bandwidth: 8_000,
    rx_bandwidth: 8_000,
    max_latency: 0xFFFF,
    voice_setting: 0x0060,
    retransmission_effort: 0x02,
    packet_types: 0x03C8, // eSCO EV3..EV5 / 2-EV3
};

/// mSBC eSCO parameters (HFP §4.11, wide-band voice).
pub const SCO_PARAMS_MSBC: ScoParams = ScoParams {
    tx_bandwidth: 8_000, // mSBC frames are 60 bytes @ 133.3 fps ≈ 8000 B/s
    rx_bandwidth: 8_000,
    max_latency: 0x000D, // 13 ms — from HFP 1.8 table 5.10
    voice_setting: 0x0063,
    retransmission_effort: 0x02,
    packet_types: 0x03C8,
};

/// Select the SCO parameters for the negotiated codec.
pub fn sco_params_for_codec(codec: u8) -> Option<&'static ScoParams> {
    match codec {
        CODEC_CVSD => Some(&SCO_PARAMS_CVSD),
        CODEC_MSBC => Some(&SCO_PARAMS_MSBC),
        _ => None,
    }
}

// ── SLC state machine ─────────────────────────────────────────────────

/// State of the HFP Service Level Connection establishment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlcState {
    /// No RFCOMM connection.
    Idle,
    /// RFCOMM connected; sent AT+BRSF; waiting for +BRSF response.
    WaitBrsf,
    /// +BRSF received; sent AT+CIND=?; waiting for +CIND test response.
    WaitCindTest,
    /// +CIND test received; sent AT+CIND?; waiting for +CIND read response.
    WaitCindRead,
    /// +CIND read received; sent AT+CMER; waiting for OK.
    WaitCmer,
    /// SLC established.
    Established,
}

/// Error type for [`SlcMachine::feed`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlcError {
    /// Parser error.
    Parse,
    /// Received ERROR from AG.
    AgError,
    /// Unexpected response in current state.
    Protocol,
}

/// HFP Service Level Connection state machine (HF role).
#[derive(Debug)]
pub struct SlcMachine {
    pub state: SlcState,
    /// AG feature bitmap received via +BRSF.
    pub ag_features: u32,
    /// HF feature bitmap we announce.
    pub hf_features: u32,
    /// Codec negotiated for SCO (if codec negotiation is active).
    pub sco_codec: u8,
}

impl SlcMachine {
    /// Create a new SLC machine.  `hf_features` should include
    /// `HF_FEAT_CODEC_NEGOTIATION` if mSBC wide-band is desired.
    pub fn new(hf_features: u32) -> Self {
        Self {
            state: SlcState::Idle,
            ag_features: 0,
            hf_features,
            sco_codec: CODEC_CVSD, // safe default
        }
    }

    /// Begin SLC establishment after RFCOMM connects.
    /// Returns the AT command bytes to send.
    pub fn on_connected(&mut self) -> Vec<u8> {
        self.state = SlcState::WaitBrsf;
        brsf_command(self.hf_features).into_bytes()
    }

    /// Feed one RFCOMM line (e.g. `+BRSF: 123\r\nOK\r\n` split by the
    /// caller into individual `\r\n`-framed lines) into the machine.
    ///
    /// Returns `Some(bytes_to_send)` when a follow-up command must be
    /// written to the RFCOMM channel, or `None` when the line was
    /// consumed without a response.  Returns `Err` on protocol error.
    ///
    /// Caller should call this once per logical response line extracted
    /// from the RFCOMM byte stream.
    pub fn feed_line(&mut self, line: &str) -> Result<Option<Vec<u8>>, SlcError> {
        let trimmed = line.trim();
        if trimmed == "ERROR" {
            return Err(SlcError::AgError);
        }

        match self.state {
            SlcState::WaitBrsf => {
                if trimmed.starts_with("+BRSF:") {
                    // Parse AG features from "+BRSF: <n>".
                    let n = trimmed
                        .trim_start_matches("+BRSF:")
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| SlcError::Parse)?;
                    self.ag_features = n;
                    Ok(None)
                } else if trimmed == "OK" {
                    // OK after +BRSF received → send AT+CIND=?
                    self.state = SlcState::WaitCindTest;
                    Ok(Some(cind_test_command().into_bytes()))
                } else {
                    Ok(None) // absorb unknown URC
                }
            }
            SlcState::WaitCindTest => {
                if trimmed.starts_with("+CIND:") {
                    Ok(None) // payload parsed by caller if needed
                } else if trimmed == "OK" {
                    self.state = SlcState::WaitCindRead;
                    Ok(Some(cind_read_command().into_bytes()))
                } else {
                    Ok(None)
                }
            }
            SlcState::WaitCindRead => {
                if trimmed.starts_with("+CIND:") {
                    Ok(None)
                } else if trimmed == "OK" {
                    self.state = SlcState::WaitCmer;
                    Ok(Some(cmer_enable_command().into_bytes()))
                } else {
                    Ok(None)
                }
            }
            SlcState::WaitCmer => {
                if trimmed == "OK" {
                    self.state = SlcState::Established;
                    Ok(None)
                } else {
                    Ok(None)
                }
            }
            SlcState::Idle | SlcState::Established => Ok(None),
        }
    }
}

// ── AT command dispatch helpers ───────────────────────────────────────

/// Known HFP AT command names (sent by the HF to the AG).
pub const AT_BRSF: &str = "+BRSF";
pub const AT_CIND: &str = "+CIND";
pub const AT_CMER: &str = "+CMER";
pub const AT_CHLD: &str = "+CHLD";
pub const AT_CLIP: &str = "+CLIP";
pub const AT_CLCC: &str = "+CLCC";
pub const AT_CHUP: &str = "+CHUP";
pub const AT_VGS: &str = "+VGS";
pub const AT_VGM: &str = "+VGM";
pub const AT_BCS: &str = "+BCS"; // codec connection setup
pub const AT_BAC: &str = "+BAC"; // available codecs

/// A decoded, classified HFP command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HfpCommand {
    /// `AT+BRSF=<n>` — HF feature exchange.
    Brsf(u32),
    /// `AT+CIND=?` — indicator catalogue test.
    CindTest,
    /// `AT+CIND?` — indicator value read.
    CindRead,
    /// `AT+CMER=…` — enable indicator events.
    Cmer,
    /// `AT+CHLD=?` — call hold capability test.
    ChldTest,
    /// `AT+BAC=<codec_ids…>` — available codecs list.
    Bac(Vec<u8>),
    /// `AT+BCS=<codec_id>` — codec connection confirm.
    Bcs(u8),
    /// `ATA` — answer call.
    Answer,
    /// `AT+CHUP` — hang up.
    Hangup,
    /// Unknown / unsupported.
    Unknown,
}

/// Parse a single AT command line into an [`HfpCommand`].
///
/// Wraps [`crate::hfp::parse_at`] and adds HFP-specific parameter
/// extraction.
pub fn classify_at(line: &str) -> HfpCommand {
    let at = match parse_at(line) {
        Ok(a) => a,
        Err(_) => return HfpCommand::Unknown,
    };

    match at.name.as_str() {
        _ if at.name.eq_ignore_ascii_case(AT_BRSF) && at.form == AtForm::Write => {
            let n = at.params.trim().parse::<u32>().unwrap_or(0);
            HfpCommand::Brsf(n)
        }
        _ if at.name.eq_ignore_ascii_case(AT_CIND) && at.form == AtForm::Test => {
            HfpCommand::CindTest
        }
        _ if at.name.eq_ignore_ascii_case(AT_CIND) && at.form == AtForm::Read => {
            HfpCommand::CindRead
        }
        _ if at.name.eq_ignore_ascii_case(AT_CMER) && at.form == AtForm::Write => HfpCommand::Cmer,
        _ if at.name.eq_ignore_ascii_case(AT_CHLD) && at.form == AtForm::Test => {
            HfpCommand::ChldTest
        }
        _ if at.name.eq_ignore_ascii_case(AT_BAC) && at.form == AtForm::Write => {
            let codecs: Vec<u8> = at
                .params
                .split(',')
                .filter_map(|t| t.trim().parse::<u8>().ok())
                .collect();
            HfpCommand::Bac(codecs)
        }
        _ if at.name.eq_ignore_ascii_case(AT_BCS) && at.form == AtForm::Write => {
            let n = at.params.trim().parse::<u8>().unwrap_or(0);
            HfpCommand::Bcs(n)
        }
        _ if at.name.eq_ignore_ascii_case("+CHUP") || at.name.eq_ignore_ascii_case("CHUP") => {
            HfpCommand::Hangup
        }
        _ if at.name.eq_ignore_ascii_case("A") && at.form == AtForm::Basic => HfpCommand::Answer,
        _ => HfpCommand::Unknown,
    }
}

/// `AT+BAC=1,2\r` — announce available codecs to AG (HFP 1.6+, §4.2).
/// `codecs`: slice of codec IDs (1 = CVSD, 2 = mSBC).
pub fn bac_command(codecs: &[u8]) -> Vec<u8> {
    let mut s = alloc::string::String::from("AT+BAC=");
    for (i, c) in codecs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        crate::hfp::push_decimal_pub(&mut s, *c as u64);
    }
    s.push('\r');
    s.into_bytes()
}

/// `AT+BCS=<codec>\r` — confirm the codec selected by the AG.
pub fn bcs_reply_command(codec: u8) -> Vec<u8> {
    let mut s = alloc::string::String::from("AT+BCS=");
    crate::hfp::push_decimal_pub(&mut s, codec as u64);
    s.push('\r');
    s.into_bytes()
}
