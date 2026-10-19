//! Canonical RDNA2 boot options and compatibility with their Navi22 names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootOptions<'a> {
    pub accel: bool,
    pub multi: bool,
    pub hw_cursor: bool,
    pub power_saving: Option<&'a str>,
}
impl<'a> BootOptions<'a> {
    pub fn parse(raw: &'a str) -> Self {
        let flag = |new, old| raw.split_ascii_whitespace().any(|t| t == new || t == old);
        let value = |key| {
            raw.split_ascii_whitespace()
                .find_map(|t| t.split_once('=').and_then(|(k, v)| (k == key).then_some(v)))
        };
        Self {
            accel: flag("amdgpu.rdna2_accel", "amdgpu.navi22_accel"),
            multi: flag("amdgpu.rdna2_multi", "amdgpu.navi22_multi"),
            hw_cursor: flag("amdgpu.rdna2_hw_cursor", "amdgpu.navi22_hw_cursor"),
            // An explicit canonical value wins, including an empty or invalid
            // value: a typo must not fall back to enabling legacy power flags.
            power_saving: value("amdgpu.rdna2_pg").or_else(|| value("amdgpu.navi22_pg")),
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
        assert_eq!(
            BootOptions::parse("amdgpu.navi22_pg=cg amdgpu.rdna2_pg=").power_saving,
            Some("")
        );
        assert_eq!(
            BootOptions::parse("amdgpu.rdna2_pg=bad amdgpu.navi22_pg=cg").power_saving,
            Some("bad")
        );
        assert_eq!(
            BootOptions::parse("amdgpu.rdna2_accel=0 amdgpu.rdna2_multix"),
            BootOptions::default()
        );
    }
}
