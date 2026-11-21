//! Canonical RDNA2 boot options and compatibility with their Navi22 names.
//!
//! Every functionally complete feature is on by default: native display
//! (retiring the GOP for the native HDMI/DP modeset), the DCN3.0 hardware
//! cursor, native client submission (`accel`), power saving (except GFXOFF;
//! see [`DEFAULT_POWER_SAVING`]) and automatic
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
///
/// Every feature except GFXOFF (`amdgpu.rdna2_pg=gfxoff,...` opts in). Linux
/// enables SMU_FEATURE_GFXOFF in `EnableAllSmuFeatures` at SMU hw_init,
/// before any ring exists and together with DS_GFXCLK, GFX_ULV, DPM_GFX_GPO
/// and GFX_DCS. NARF enables it alone, late, with the CP already running:
/// a firmware configuration Linux never exercises. It stays opt-in until it
/// is enabled with that set or validated on silicon as it is.
pub const DEFAULT_POWER_SAVING: &str = "cg,gfxcg,hubpg,memdpm,fclkdpm,ds,wm";

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
    /// `amdgpu.rdna2_dmub_tables=0` runs the DCN3.0 display VBIOS tables
    /// (SetPixelClock, DIG encoder/transmitter control, pipe power gating)
    /// in NARF's ATOM interpreter even while DMCUB runs. Diagnostic: Linux
    /// always sends them to DMCUB (`debug.dmub_command_table`).
    pub dmub_tables: bool,
    /// `amdgpu.rdna2_atom_pixclk=1` runs SetPixelClock alone in the ATOM
    /// interpreter while every other display table still goes to DMCUB
    /// (DMCUB implements the tables itself; its golden init does more than
    /// the bytecode). Diagnostic.
    pub atom_pixclk: bool,
    /// `amdgpu.rdna2_vcn_smu_pg=1` allows the board's MM_DPM_PG, and the VCN
    /// start powers the media islands up through PMFW (PowerUpVcn,
    /// PowerUpJpeg), as Linux's default Navi22 configuration does.
    /// Diagnostic.
    pub vcn_smu_pg: bool,
    /// `amdgpu.rdna2_vcn_dpg=0` starts VCN on Linux's static path (power
    /// gating off, every register written directly) instead of DPG with the
    /// PSP-loaded register list. Diagnostic.
    pub vcn_dpg: bool,
    /// `amdgpu.rdna2_connector=dp|hdmi`: the output the single-display boot
    /// modeset lights when both kinds have a sink (Linux's order, HDMI
    /// first, otherwise). Diagnostic: lets either output be tested with
    /// both cables attached.
    pub connector: Connector,
    /// Linux `amdgpu.ppfeaturemask`'s `PP_GFXOFF_MASK` (bit 15): Raphael's
    /// GFXOFF. Linux's default mask, `0xfff7bfff`, sets it; a mask without it
    /// keeps GFX powered. Navi22's GFXOFF follows `amdgpu.rdna2_pg` instead.
    pub gfxoff: bool,
    /// Linux `amdgpu.cg_mask`: the clock-gating flags Raphael keeps
    /// (`cg_flags &= amdgpu_cg_mask`). Every bit by default.
    pub cg_mask: u32,
}
/// `amdgpu_pp_feature_mask`'s default (amdgpu_drv.c).
// linux-lit: 0xfff7bfff=amdgpu_pp_feature_mask default
const PP_FEATURE_MASK: u32 = 0xfff7_bfff;
const PP_GFXOFF_MASK: u32 = 0x8000; // linux: PP_GFXOFF_MASK
/// A `uint` module parameter (`kstrtouint` base 0): `0x` hex, a leading `0`
/// octal, else decimal.
fn parse_uint(v: &str) -> Option<u32> {
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if v.len() > 1 && v.starts_with('0') {
        u32::from_str_radix(&v[1..], 8).ok()
    } else {
        v.parse().ok()
    }
}
/// [`BootOptions::connector`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Connector {
    #[default]
    Any,
    Hdmi,
    DisplayPort,
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
            dmub_tables: switch("amdgpu.rdna2_dmub_tables", None, true),
            atom_pixclk: switch("amdgpu.rdna2_atom_pixclk", None, false),
            vcn_smu_pg: switch("amdgpu.rdna2_vcn_smu_pg", None, false),
            vcn_dpg: switch("amdgpu.rdna2_vcn_dpg", None, true),
            connector: match value("amdgpu.rdna2_connector") {
                Some(Some("dp" | "DP" | "displayport")) => Connector::DisplayPort,
                Some(Some("hdmi" | "HDMI")) => Connector::Hdmi,
                _ => Connector::Any,
            },
            // A malformed mask keeps Linux's default, as a failed parse
            // leaves the module parameter at its default.
            gfxoff: match value("amdgpu.ppfeaturemask") {
                Some(Some(v)) => parse_uint(v).unwrap_or(PP_FEATURE_MASK),
                _ => PP_FEATURE_MASK,
            } & PP_GFXOFF_MASK
                != 0,
            cg_mask: match value("amdgpu.cg_mask") {
                Some(Some(v)) => parse_uint(v).unwrap_or(u32::MAX),
                _ => u32::MAX,
            },
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
        // GFXOFF is opt-in until it is enabled with Linux's SMU-init set.
        assert!(!DEFAULT_POWER_SAVING.split(',').any(|t| t == "gfxoff"));
        assert_eq!(
            BootOptions::parse("amdgpu.rdna2_pg=gfxoff,cg").power_saving,
            Some("gfxoff,cg")
        );
        let off = BootOptions::parse(
            "amdgpu.native_display=0 amdgpu.rdna2_accel=0 amdgpu.navi22_hw_cursor=off \
             amdgpu.rdna2_pg=none amdgpu.rdna2_multix",
        );
        assert!(!off.native_display && !off.accel && !off.hw_cursor && !off.multi);
        assert_eq!(off.power_saving, None);
        // A typo neither enables an opt-in feature nor disables a default.
        let typo = BootOptions::parse("amdgpu.rdna2_multi=maybe amdgpu.rdna2_accel=nope");
        assert!(!typo.multi && typo.accel);
        assert_eq!(default.connector, Connector::Any);
        // Raphael's GFXOFF follows Linux's feature mask, on by default.
        assert!(default.gfxoff);
        for (raw, want) in [
            ("amdgpu.ppfeaturemask=0xffff7fff", false),
            ("amdgpu.ppfeaturemask=0x8000", true),
            ("amdgpu.ppfeaturemask=32768", true),
            ("amdgpu.ppfeaturemask=0100000", true),
            ("amdgpu.ppfeaturemask=0", false),
            ("amdgpu.ppfeaturemask=bad", true),
        ] {
            assert_eq!(BootOptions::parse(raw).gfxoff, want, "{raw}");
        }
        assert_eq!(default.cg_mask, u32::MAX);
        assert_eq!(BootOptions::parse("amdgpu.cg_mask=0xfffffffb").cg_mask, !4);
        assert_eq!(BootOptions::parse("amdgpu.cg_mask=nope").cg_mask, u32::MAX);
        for (raw, want) in [
            ("amdgpu.rdna2_connector=dp", Connector::DisplayPort),
            ("amdgpu.rdna2_connector=hdmi", Connector::Hdmi),
            ("amdgpu.rdna2_connector=vga", Connector::Any),
            ("amdgpu.rdna2_connector", Connector::Any),
        ] {
            assert_eq!(BootOptions::parse(raw).connector, want);
        }
    }
}
