//! Hands-Free Profile — AT command codec (clean-room).
//!
//! References (public-only):
//! - "Hands-Free Profile, Version 1.8" — Bluetooth SIG. Public adopted
//!   profile. §4.2 (HFP service-level connection establishment),
//!   §4.34 (BRSF feature bit table), §4.4 (CIND / CMER indicator
//!   negotiation), §4.6 (in-band ringtone), §4.13 (call list / CLCC),
//!   table 5.1 (HF + AG feature bits).
//! - ITU-T Recommendation V.250 — public AT command syntax baseline
//!   (lexer / line termination, basic + extended formats).
//! - 3GPP TS 27.007 — public AT command set for the GSM modem
//!   reference (CIND / CIEV / CHUP / +CME ERROR responses reused
//!   verbatim by HFP).
//!
//! No GPL Linux source consulted.
//!
//! ## AT command line syntax (V.250 §5.2.1)
//!
//! Command lines start with the literal `AT` (case-insensitive),
//! contain one or more commands separated by `;`, and end with `\r`.
//! Extended commands begin with `+` and may take parameters after
//! `=` (write) or `?` (read) or `=?` (test).
//!
//! Response lines are framed by `\r\n` on both ends:
//! `\r\n+CIND: 1,0,1,0,0\r\n` is one well-formed unsolicited result.
//!
//! HFP mandates a small subset of commands; this codec covers the
//! ones a kernel HFP audio gateway needs to negotiate and steer a
//! call: BRSF, CIND test/read, CMER, CHLD test, CLCC, ATA, AT+CHUP,
//! +CIEV unsolicited indicator updates, +BSIR (in-band ringtone).

use alloc::string::String;
use alloc::vec::Vec;

// ── HF (hands-free) feature bits — sent to AG via AT+BRSF=N (§5.1). ─

pub const HF_FEAT_EC_NR: u32 = 1 << 0; // EC and/or NR function
pub const HF_FEAT_THREE_WAY_CALLING: u32 = 1 << 1;
pub const HF_FEAT_CLI: u32 = 1 << 2; // CLI presentation
pub const HF_FEAT_VOICE_RECOGNITION: u32 = 1 << 3;
pub const HF_FEAT_VOLUME_CONTROL: u32 = 1 << 4;
pub const HF_FEAT_ENHANCED_CALL_STATUS: u32 = 1 << 5;
pub const HF_FEAT_ENHANCED_CALL_CONTROL: u32 = 1 << 6;
pub const HF_FEAT_CODEC_NEGOTIATION: u32 = 1 << 7;
pub const HF_FEAT_HF_INDICATORS: u32 = 1 << 8;
pub const HF_FEAT_ESCO_S4_SETTINGS: u32 = 1 << 9;
pub const HF_FEAT_ENHANCED_VOICE_RECOGNITION: u32 = 1 << 10;
pub const HF_FEAT_VOICE_RECOGNITION_TEXT: u32 = 1 << 11;

// ── AG (audio-gateway) feature bits — sent to HF via +BRSF: N (§5.1). ─

pub const AG_FEAT_THREE_WAY_CALLING: u32 = 1 << 0;
pub const AG_FEAT_EC_NR: u32 = 1 << 1;
pub const AG_FEAT_VOICE_RECOGNITION: u32 = 1 << 2;
pub const AG_FEAT_INBAND_RINGTONE: u32 = 1 << 3;
pub const AG_FEAT_VOICE_TAG: u32 = 1 << 4;
pub const AG_FEAT_REJECT_CALL: u32 = 1 << 5;
pub const AG_FEAT_ENHANCED_CALL_STATUS: u32 = 1 << 6;
pub const AG_FEAT_ENHANCED_CALL_CONTROL: u32 = 1 << 7;
pub const AG_FEAT_EXTENDED_ERROR: u32 = 1 << 8;
pub const AG_FEAT_CODEC_NEGOTIATION: u32 = 1 << 9;
pub const AG_FEAT_HF_INDICATORS: u32 = 1 << 10;
pub const AG_FEAT_ESCO_S4_SETTINGS: u32 = 1 << 11;
pub const AG_FEAT_ENHANCED_VOICE_RECOGNITION: u32 = 1 << 12;
pub const AG_FEAT_VOICE_RECOGNITION_TEXT: u32 = 1 << 13;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HfpError {
    /// Line didn't start with the literal "AT" prefix.
    NotAtCommand,
    /// Couldn't tokenize a numeric parameter.
    BadParam,
    /// Buffer empty / no terminator.
    Short,
}

// ── Tokeniser ──────────────────────────────────────────────────────

/// One parsed AT command line. The body is everything between the
/// `AT` prefix and the trailing `\r` — extended commands keep their
/// leading `+`. Raw parameters are kept as a single string for the
/// caller to slice; specific HFP commands have their own decoders
/// below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtCommand {
    /// e.g. "+BRSF", "+CIND", "A" (for the literal "ATA"),
    /// "+CHUP", "+VGS", "+VGM".
    pub name: String,
    /// "=" (write), "?" (read), "=?" (test), "" (basic).
    pub form: AtForm,
    /// Raw parameter string after the form indicator (no leading
    /// "=", trailing `\r` already stripped). Empty when `form == Basic`.
    pub params: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtForm {
    Basic,
    Write,
    Read,
    Test,
}

/// Parse one AT command line. Caller is expected to have already
/// extracted a `\r`-terminated logical line from the RFCOMM stream.
pub fn parse_at(line: &str) -> Result<AtCommand, HfpError> {
    let s = line.trim_end_matches('\r');
    if s.len() < 2 {
        return Err(HfpError::Short);
    }
    let prefix = &s[..2];
    if !prefix.eq_ignore_ascii_case("AT") {
        return Err(HfpError::NotAtCommand);
    }
    let body = &s[2..];
    if body.is_empty() {
        // Bare "AT\r" — used by some hosts as a probe.
        return Ok(AtCommand {
            name: String::new(),
            form: AtForm::Basic,
            params: String::new(),
        });
    }
    // Find separator characters.
    if let Some(eq_pos) = body.find('=') {
        let name = body[..eq_pos].into();
        let after = &body[eq_pos + 1..];
        if let Some(stripped) = after.strip_prefix('?') {
            return Ok(AtCommand {
                name,
                form: AtForm::Test,
                params: stripped.into(),
            });
        }
        return Ok(AtCommand {
            name,
            form: AtForm::Write,
            params: after.into(),
        });
    }
    if let Some(q_pos) = body.find('?') {
        return Ok(AtCommand {
            name: body[..q_pos].into(),
            form: AtForm::Read,
            params: body[q_pos + 1..].into(),
        });
    }
    Ok(AtCommand {
        name: body.into(),
        form: AtForm::Basic,
        params: String::new(),
    })
}

// ── HF → AG command builders ───────────────────────────────────────

/// `AT+BRSF=<features>\r` — HF announces its feature bitmap.
pub fn brsf_command(hf_features: u32) -> String {
    let mut s = String::from("AT+BRSF=");
    push_decimal(&mut s, hf_features as u64);
    s.push('\r');
    s
}

/// `AT+CIND=?\r` — request indicator catalogue.
pub fn cind_test_command() -> String {
    String::from("AT+CIND=?\r")
}

/// `AT+CIND?\r` — request current indicator values.
pub fn cind_read_command() -> String {
    String::from("AT+CIND?\r")
}

/// `AT+CMER=3,0,0,1\r` — enable indicator-event reporting.
/// Per HFP §4.2.1.5 those four parameters are the only legal values.
pub fn cmer_enable_command() -> String {
    String::from("AT+CMER=3,0,0,1\r")
}

/// `AT+CHLD=?\r` — request supported call-hold options.
pub fn chld_test_command() -> String {
    String::from("AT+CHLD=?\r")
}

/// `AT+CLCC\r` — list current calls.
pub fn clcc_command() -> String {
    String::from("AT+CLCC\r")
}

/// `ATA\r` — answer the active incoming call.
pub fn answer_command() -> String {
    String::from("ATA\r")
}

/// `AT+CHUP\r` — hang up / reject.
pub fn hangup_command() -> String {
    String::from("AT+CHUP\r")
}

// ── AG → HF response builders ──────────────────────────────────────

/// `\r\n+BRSF: <features>\r\n` — AG response to AT+BRSF.
pub fn brsf_response(ag_features: u32) -> String {
    let mut s = String::from("\r\n+BRSF: ");
    push_decimal(&mut s, ag_features as u64);
    s.push_str("\r\n");
    s
}

/// `\r\nOK\r\n`.
pub fn ok_response() -> String {
    String::from("\r\nOK\r\n")
}

/// `\r\nERROR\r\n`.
pub fn error_response() -> String {
    String::from("\r\nERROR\r\n")
}

/// `\r\n+CIEV: <index>,<value>\r\n` — unsolicited indicator update.
pub fn ciev_unsolicited(index: u8, value: u8) -> String {
    let mut s = String::from("\r\n+CIEV: ");
    push_decimal(&mut s, index as u64);
    s.push(',');
    push_decimal(&mut s, value as u64);
    s.push_str("\r\n");
    s
}

/// `\r\n+BSIR: <0|1>\r\n` — toggle in-band ringtone.
pub fn bsir_unsolicited(in_band: bool) -> String {
    if in_band {
        String::from("\r\n+BSIR: 1\r\n")
    } else {
        String::from("\r\n+BSIR: 0\r\n")
    }
}

/// `\r\nRING\r\n` — alert the HF that a call is incoming.
pub fn ring_unsolicited() -> String {
    String::from("\r\nRING\r\n")
}

// ── Helpers ────────────────────────────────────────────────────────

pub fn push_decimal_pub(out: &mut String, v: u64) {
    push_decimal(out, v);
}

fn push_decimal(out: &mut String, mut v: u64) {
    if v == 0 {
        out.push('0');
        return;
    }
    // Up to 20 decimal digits for a u64.
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out.push_str(core::str::from_utf8(&buf[i..]).unwrap());
}

/// Parse a comma-separated list of unsigned integers into a `Vec<u32>`.
/// Empty fields decode to 0. Useful for `+CIND:`/`+CIEV:` payloads.
pub fn parse_csv_numbers(params: &str) -> Result<Vec<u32>, HfpError> {
    let mut out = Vec::new();
    for tok in params.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            out.push(0);
            continue;
        }
        let mut v = 0u32;
        for b in t.bytes() {
            if b.is_ascii_digit() {
                v = v.wrapping_mul(10).wrapping_add((b - b'0') as u32);
            } else {
                return Err(HfpError::BadParam);
            }
        }
        out.push(v);
    }
    Ok(out)
}
