//! Canonical RDNA2 boot options and compatibility with their Navi22 names.
//!
//! Every functionally complete feature is on by default: native display
//! (retiring the GOP for the native HDMI/DP modeset), the DCN3.0 hardware
//! cursor, native client submission (`accel`), power saving and automatic
//! GPU recovery after a hang. Each has an off switch
//! (`amdgpu.rdna2_accel=0`, `amdgpu.native_display=0`,
//! `amdgpu.gpu_recovery=0`, ...).
//! Multi-display stays opt-in: secondary CRTCs light but cannot present or
//! deliver vblank yet.
//!
//! None of this has run on RX 6000 silicon. Power saving still passes every
//! display-admission and driver prerequisite through
//! `Policy::request_opted_in`; the default list is the implicit opt-in that
//! waives only the hardware-validation facts.

/// Power-saving features requested when `amdgpu.rdna2_pg=` is absent. Each is
/// still refused unless its display admission and driver prerequisites hold.
pub const DEFAULT_POWER_SAVING: &str = "gfxoff,cg,gfxcg,hubpg,memdpm,fclkdpm,ds,wm";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootOptions<'a> {
    pub native_display: bool,
    pub accel: bool,
    pub multi: bool,
    pub hw_cursor: bool,
    /// Linux `amdgpu.gpu_recovery`: automatic recovery after a detected hang
    /// (`-1` auto and `1` enable it, `0` disables it).
    pub gpu_recovery: bool,
    /// The power-saving list to apply; `None` applies nothing.
    pub power_saving: Option<&'a str>,
}
impl Default for BootOptions<'_> {
    fn default() -> Self {
        BootOptions::parse("")
    }
}
impl<'a> BootOptions<'a> {
    pub fn parse(raw: &'a str) -> Self {
        let value = |key: &str| {
            raw.split_ascii_whitespace()
                .find_map(|t| match t.split_once('=') {
                    Some((k, v)) => (k == key).then_some(Some(v)),
                    None => (t == key).then_some(None),
                })
        };
        // A bare flag or `=1`/`on` enables, `=0`/`off` disables, anything
        // else (a typo) keeps the default. The canonical name wins.
        let switch = |new: &str, old: Option<&str>, default: bool| match value(new)
            .or_else(|| old.and_then(value))
        {
            None => default,
            Some(None | Some("1" | "on" | "y" | "yes" | "true")) => true,
            Some(Some("0" | "off" | "n" | "no" | "false")) => false,
            Some(Some(_)) => default,
        };
        // An explicit canonical value wins, including an empty or invalid
        // value: a typo must not fall back to enabling legacy power flags.
        let power_saving = match value("amdgpu.rdna2_pg").or_else(|| value("amdgpu.navi22_pg")) {
            None => Some(DEFAULT_POWER_SAVING),
            Some(None | Some("" | "0" | "off" | "none")) => None,
            Some(Some(list)) => Some(list),
        };
        Self {
            native_display: switch("amdgpu.native_display", None, true),
            accel: switch("amdgpu.rdna2_accel", Some("amdgpu.navi22_accel"), true),
            multi: switch("amdgpu.rdna2_multi", Some("amdgpu.navi22_multi"), false),
            hw_cursor: switch(
                "amdgpu.rdna2_hw_cursor",
                Some("amdgpu.navi22_hw_cursor"),
                true,
            ),
            gpu_recovery: switch("amdgpu.gpu_recovery", None, true),
            power_saving,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatibility_and_precedence() {
        let old = BootOptions::parse("amdgpu.navi22_accel amdgpu.navi22_multi amdgpu.navi22_hw_cursor amdgpu.navi22_pg=cg,wm");
        let new = BootOptions::parse(
            "amdgpu.rdna2_accel amdgpu.rdna2_multi amdgpu.rdna2_hw_cursor amdgpu.rdna2_pg=cg,wm",
        );
        assert_eq!(old, new);
        assert!(new.accel && new.multi && new.hw_cursor);
        assert_eq!(new.power_saving, Some("cg,wm"));
        // An explicit canonical value wins over the legacy one, even when
        // it disables or is malformed.
        assert_eq!(
            BootOptions::parse("amdgpu.navi22_pg=cg amdgpu.rdna2_pg=").power_saving,
            None
        );
        assert_eq!(
            BootOptions::parse("amdgpu.rdna2_pg=bad amdgpu.navi22_pg=cg").power_saving,
            Some("bad")
        );
        assert!(!BootOptions::parse("amdgpu.navi22_accel=1 amdgpu.rdna2_accel=0").accel);
    }
    #[test]
    fn complete_features_default_on_with_off_switches() {
        let default = BootOptions::parse("quiet");
        assert_eq!(default, BootOptions::default());
        assert!(
            default.native_display && default.accel && default.hw_cursor && default.gpu_recovery
        );
        assert!(BootOptions::parse("amdgpu.gpu_recovery=-1").gpu_recovery);
        assert!(!BootOptions::parse("amdgpu.gpu_recovery=0").gpu_recovery);
        assert!(!default.multi);
        assert_eq!(default.power_saving, Some(DEFAULT_POWER_SAVING));
        let off = BootOptions::parse(
            "amdgpu.native_display=0 amdgpu.rdna2_accel=0 amdgpu.navi22_hw_cursor=off \
             amdgpu.rdna2_pg=none amdgpu.rdna2_multix",
        );
        assert!(!off.native_display && !off.accel && !off.hw_cursor && !off.multi);
        assert_eq!(off.power_saving, None);
        // A typo neither enables an opt-in feature nor disables a default.
        let typo = BootOptions::parse("amdgpu.rdna2_multi=maybe amdgpu.rdna2_accel=nope");
        assert!(!typo.multi && typo.accel);
    }
}
