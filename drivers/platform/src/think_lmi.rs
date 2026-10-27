// SPDX-License-Identifier: GPL-2.0-or-later
//! Think-LMI — Lenovo BIOS settings over WMI (ThinkPad).
//!
//! The full `Lenovo_BIOSElement` protocol from Lenovo's *BIOS
//! Setup using WMI Deployment Guide* and the CDRT WMI BIOS
//! interface reference: enumerate `Lenovo_BiosSetting` instances
//! (`"Item,Value[,Possible…]"`), stage changes with
//! `Lenovo_SetBiosSetting`, authenticate through the legacy
//! in-string password fields or the 2017+
//! `Lenovo_WmiOpcodeInterface`, and commit with
//! `Lenovo_SaveBiosSettings` / discard / load-default. Setting
//! strings, the save ordering (set → opcode-password → save), and
//! the return-string error set are implemented exactly as the
//! Lenovo documents specify them.
//!
//! ## GUID verification status — READ BEFORE ENABLING
//!
//! The protocol *strings* in this module are verified against
//! Lenovo's published deployment guides. The WMI GUID *literals*
//! below are a different matter: they are cited from
//! `drivers/platform/x86/lenovo/think-lmi.c` (`LENOVO_*_GUID`
//! defines) but could not be re-verified against the source while
//! this change was authored (every source mirror consulted was
//! unreachable). [`LENOVO_BIOS_SETTING_GUID`] and
//! [`LENOVO_SET_BIOS_SETTINGS_GUID`] carry the values as recalled;
//! the save / password / opcode class GUIDs had no defensible
//! recollection and are deliberately left unresolved — operations
//! needing them return [`TlmiError::GuidUnresolved`] rather than
//! guessing a constant that would silently talk to the wrong
//! firmware block. The PR body flags this: a one-minute check of
//! the `think-lmi.c` define block (or a `_WDG` dump from a
//! ThinkPad) resolves all five, after which the write paths run
//! exactly as fixture-tested here.
//!
//! Linux reference: `drivers/platform/x86/lenovo/think-lmi.c`
//! (`tlmi_setting`, `tlmi_settings`, `setting_store`,
//! `tlmi_save_bios_settings`, `tlmi_opcode_setting`).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_aml::wmi::{invoke_method, list_guids, query_block, WmiGuid};
use narf_aml::Value;

// ── GUIDs ─────────────────────────────────────────────────────────────

/// `Lenovo_BiosSetting` query class GUID — enumerate instances to
/// list BIOS settings. CITED from `think-lmi.c`
/// (`LENOVO_BIOS_SETTING_GUID`); not re-verified against source
/// for this change — see the module header.
pub const LENOVO_BIOS_SETTING_GUID: &str = "51F5230E-9675-46CD-A1CF-A23F6D2B2708";

/// `Lenovo_SetBiosSetting` method class GUID. CITED from
/// `think-lmi.c` (`LENOVO_SET_BIOS_SETTINGS_GUID`), low
/// confidence; not re-verified — see the module header.
pub const LENOVO_SET_BIOS_SETTINGS_GUID: &str = "D8A3B225-96C6-44B8-A5B0-0C5C85BE2E6A";

/// Resolve the WMI block for a think-lmi class GUID string.
/// Returns `None` when the GUID is not in the registry (the class
/// is absent on this machine).
fn find_class(guid_str: &str) -> Option<WmiGuid> {
    let want = crate::wmi_vendors::guid_str_to_bytes(guid_str)?;
    list_guids().into_iter().find(|g| g.guid == want)
}

/// True when the BIOS-setting query class is present (subject to
/// the GUID verification caveat in the module header).
pub fn present() -> bool {
    find_class(LENOVO_BIOS_SETTING_GUID).is_some()
}

// ── Errors ────────────────────────────────────────────────────────────

/// Think-LMI errors. The firmware variants map the return strings
/// Lenovo documents for the method classes, matching the errno
/// mapping in `think-lmi.c::tlmi_errs`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlmiError {
    /// The query class GUID is not present on this machine.
    NotPresent,
    /// A method-class GUID has no verified literal yet (see the
    /// module header) — the operation was not attempted.
    GuidUnresolved,
    /// The underlying WMI/AML call failed.
    Aml,
    /// The firmware returned a malformed setting string.
    Malformed,
    /// Firmware: "Not Supported".
    NotSupported,
    /// Firmware: "Invalid Parameter".
    InvalidParameter,
    /// Firmware: "Access Denied" (wrong / missing password).
    AccessDenied,
    /// Firmware: "System Busy".
    SystemBusy,
    /// Firmware returned an unrecognised status string.
    UnknownStatus,
}

/// Map a think-lmi method return string to a result.
/// Reference: `think-lmi.c` return-value table — "Success",
/// "Not Supported", "Invalid Parameter", "Access Denied",
/// "System Busy" (Lenovo deployment guide, method return values).
pub fn map_return_status(s: &str) -> Result<(), TlmiError> {
    match s.trim() {
        "Success" => Ok(()),
        "Not Supported" => Err(TlmiError::NotSupported),
        "Invalid Parameter" => Err(TlmiError::InvalidParameter),
        "Access Denied" => Err(TlmiError::AccessDenied),
        "System Busy" => Err(TlmiError::SystemBusy),
        _ => Err(TlmiError::UnknownStatus),
    }
}

// ── Setting enumeration ───────────────────────────────────────────────

/// One enumerated BIOS setting: name, current value, and the
/// firmware-reported possible values, parsed from the
/// `Lenovo_BiosSetting` instance string
/// `"Item,Value[,Possible1,Possible2…]"`.
///
/// Reference: Lenovo deployment guide (`Lenovo_BiosSetting`
/// query, `CurrentSetting: "Item,Value"`) and
/// `think-lmi.c::tlmi_setting`, which splits the remainder of the
/// string into the possible-values list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiosSetting {
    pub name: String,
    pub current_value: String,
    pub possible_values: Vec<String>,
}

/// Parse one `Lenovo_BiosSetting` instance string.
pub fn parse_setting(raw: &str) -> Option<BiosSetting> {
    let raw = raw.trim().trim_end_matches(';');
    let mut parts = raw.split(',');
    let name = parts.next()?.trim();
    if name.is_empty() {
        return None;
    }
    let current = parts.next().unwrap_or("").trim();
    Some(BiosSetting {
        name: String::from(name),
        current_value: String::from(current),
        possible_values: parts.map(|p| String::from(p.trim())).collect(),
    })
}

/// Enumerate all BIOS settings by querying every instance of the
/// `Lenovo_BiosSetting` block. Each instance's data block is a
/// string (WMI string flag) holding one `"Item,Value…"` record.
pub fn enumerate_settings() -> Result<Vec<BiosSetting>, TlmiError> {
    let class = find_class(LENOVO_BIOS_SETTING_GUID).ok_or(TlmiError::NotPresent)?;
    let mut out = Vec::new();
    for instance in 0..class.instance_count {
        let block = query_block(&class, instance).map_err(|_| TlmiError::Aml)?;
        // WMI string blocks are UTF-16LE in the MOF for this class
        // on some models and plain ASCII on others; decode lossily
        // as UTF-16LE when the buffer looks like it (zero high
        // bytes), else as ASCII.
        let text = decode_wmi_string(&block);
        if text.trim().is_empty() {
            continue;
        }
        match parse_setting(&text) {
            Some(s) => out.push(s),
            None => return Err(TlmiError::Malformed),
        }
    }
    Ok(out)
}

fn decode_wmi_string(block: &[u8]) -> String {
    let looks_utf16 = block.len() >= 2
        && block.len() % 2 == 0
        && block.iter().skip(1).step_by(2).all(|&b| b == 0);
    if looks_utf16 {
        let units: Vec<u16> = block
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let end = block.iter().position(|&b| b == 0).unwrap_or(block.len());
        String::from_utf8_lossy(&block[..end]).into_owned()
    }
}

// ── Setting mutation ──────────────────────────────────────────────────

/// Authentication for a set/save operation. `None` means no BIOS
/// password is set (the documented no-password forms are used).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlmiAuth {
    /// Supervisor password.
    pub password: String,
    /// Password encoding: `"ascii"` or `"scancode"`.
    pub encoding: String,
    /// Keyboard language: `"us"`, `"fr"`, or `"gr"`.
    pub kbd_lang: String,
}

impl TlmiAuth {
    /// The documented default auth tail: ascii encoding, US keyboard.
    pub fn new(password: &str) -> Self {
        Self {
            password: String::from(password),
            encoding: String::from("ascii"),
            kbd_lang: String::from("us"),
        }
    }

    /// `",Password,Encoding,KbdLang"` — the legacy in-string tail.
    fn legacy_tail(&self) -> String {
        alloc::format!(",{},{},{}", self.password, self.encoding, self.kbd_lang)
    }

    /// `"Password,Encoding,KbdLang;"` — the save/discard/load form.
    fn save_arg(&self) -> String {
        alloc::format!("{},{},{};", self.password, self.encoding, self.kbd_lang)
    }
}

/// Compose the `Lenovo_SetBiosSetting` argument string.
///
/// Documented forms (Lenovo deployment guide):
/// - no password: `"Item,Value;"`
/// - legacy password: `"Item,Value,Password,Encoding,KbdLang;"`
pub fn compose_set_arg(item: &str, value: &str, auth: Option<&TlmiAuth>) -> String {
    match auth {
        Some(a) => alloc::format!("{},{}{};", item, value, a.legacy_tail()),
        None => alloc::format!("{},{};", item, value),
    }
}

/// Compose the `Lenovo_WmiOpcodeInterface` password argument:
/// `"WmiOpcodePasswordAdmin:<password>;"` (CDRT WMI guide). On
/// 2017+ models this replaces the legacy in-string password: the
/// order is set (no password in the string) → opcode → save.
pub fn compose_opcode_password_arg(password: &str) -> String {
    alloc::format!("WmiOpcodePasswordAdmin:{};", password)
}

/// Invoke a think-lmi method class with one string argument and
/// map the returned status string. `guid_str` selects the class;
/// `method_id` is the class's method ordinal (0 for the single
/// method each Lenovo class exposes).
fn invoke_string_method(guid_str: &str, arg: String) -> Result<(), TlmiError> {
    let class = find_class(guid_str).ok_or(TlmiError::NotPresent)?;
    let result = invoke_method(&class, 0, &[Value::String(arg)]).map_err(|_| TlmiError::Aml)?;
    match result {
        Value::String(s) => map_return_status(&s),
        // Some firmware returns the status as a buffer of ASCII.
        Value::Buffer(b) => map_return_status(&decode_wmi_string(&b)),
        // A void return is a success on classes that return nothing.
        Value::Integer(0) => Ok(()),
        _ => Err(TlmiError::Malformed),
    }
}

/// Stage a BIOS setting change (`Lenovo_SetBiosSetting`). The
/// change is not committed until [`save_settings`] (or discarded
/// with [`discard_settings`]). With an auth value on legacy
/// models the password travels in the string; on opcode models
/// pass `auth = None` here and call [`opcode_password`] before
/// saving — the CDRT-documented ordering.
pub fn set_bios_setting(item: &str, value: &str, auth: Option<&TlmiAuth>) -> Result<(), TlmiError> {
    invoke_string_method(
        LENOVO_SET_BIOS_SETTINGS_GUID,
        compose_set_arg(item, value, auth),
    )
}

/// Authenticate a staged change on opcode-interface models
/// (`Lenovo_WmiOpcodeInterface`). The class GUID literal is
/// unresolved (module header), so this returns
/// [`TlmiError::GuidUnresolved`] until the constant is verified.
pub fn opcode_password(_password: &str) -> Result<(), TlmiError> {
    Err(TlmiError::GuidUnresolved)
}

/// Commit staged changes (`Lenovo_SaveBiosSettings`), argument
/// `"Password,Encoding,KbdLang;"` or `";"` with no password. The
/// class GUID literal is unresolved (module header), so this
/// returns [`TlmiError::GuidUnresolved`] until the constant is
/// verified — the argument is composed exactly as it will be
/// sent once the GUID lands.
pub fn save_settings(auth: Option<&TlmiAuth>) -> Result<(), TlmiError> {
    let _arg = auth
        .map(|a| a.save_arg())
        .unwrap_or_else(|| String::from(";"));
    Err(TlmiError::GuidUnresolved)
}

/// Discard staged changes (`Lenovo_DiscardBiosSettings`). Same
/// argument form and GUID caveat as [`save_settings`].
pub fn discard_settings(auth: Option<&TlmiAuth>) -> Result<(), TlmiError> {
    let _arg = auth
        .map(|a| a.save_arg())
        .unwrap_or_else(|| String::from(";"));
    Err(TlmiError::GuidUnresolved)
}

/// Load factory defaults (`Lenovo_LoadDefaultSettings`). Same
/// argument form and GUID caveat as [`save_settings`].
pub fn load_default_settings(auth: Option<&TlmiAuth>) -> Result<(), TlmiError> {
    let _arg = auth
        .map(|a| a.save_arg())
        .unwrap_or_else(|| String::from(";"));
    Err(TlmiError::GuidUnresolved)
}

/// Change a BIOS password (`Lenovo_SetBiosPassword`), argument
/// form `"PasswordType,CurrentPassword,NewPassword,Encoding,KbdLang;"`
/// with types `pap` (supervisor), `pop` (power-on), `uhdp1`/`mhdp1`
/// … (disk passwords). Same GUID caveat as [`save_settings`].
pub fn compose_password_arg(
    password_type: &str,
    current: &str,
    new: &str,
    auth: &TlmiAuth,
) -> String {
    alloc::format!(
        "{},{},{},{},{};",
        password_type,
        current,
        new,
        auth.encoding,
        auth.kbd_lang
    )
}

/// Test-only: run a set operation against an explicitly supplied
/// class block, bypassing GUID resolution. Fixture tests use this
/// to pin the string conversation end-to-end; production code goes
/// through [`set_bios_setting`].
#[doc(hidden)]
pub fn __test_set_with_class(
    class: &WmiGuid,
    item: &str,
    value: &str,
    auth: Option<&TlmiAuth>,
) -> Result<(), TlmiError> {
    let result = invoke_method(
        class,
        0,
        &[Value::String(compose_set_arg(item, value, auth))],
    )
    .map_err(|_| TlmiError::Aml)?;
    match result {
        Value::String(s) => map_return_status(&s),
        Value::Buffer(b) => map_return_status(&decode_wmi_string(&b)),
        Value::Integer(0) => Ok(()),
        _ => Err(TlmiError::Malformed),
    }
}

// ── Init ──────────────────────────────────────────────────────────────

/// Probe for the think-lmi query class. Called from a Stage::Subsys
/// initcall after WMI GUID enumeration. Best-effort: absence is the
/// normal case on non-ThinkPad machines.
pub fn init() -> bool {
    present()
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset think-lmi state for tests (stateless beyond the WMI
/// registry, which the caller's reset already handles).
#[doc(hidden)]
pub fn __test_reset() {}
