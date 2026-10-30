//! Linux pp_power_profile_mode, serialized and bound to the admitted owner.
use super::*;
use smu::PowerProfile;
static CONTROL: Mutex<()> = Mutex::new(());
static REQUEST: AtomicU64 = AtomicU64::new(0);
pub(super) fn parse(text: &str) -> Result<PowerProfile, FsError> {
    let text = text.trim();
    if text == "6" || text.split_whitespace().next() == Some("6") {
        return Err(FsError::Unsupported);
    }
    if text.len() != 1 {
        return Err(FsError::InvalidData);
    }
    PowerProfile::ALL
        .into_iter()
        .find(|p| text.as_bytes()[0] == b'0' + *p as u8)
        .ok_or(FsError::InvalidData)
}
pub(super) fn show(profile: PowerProfile) -> String {
    use core::fmt::Write as _;
    let mut text = String::from("PROFILE_INDEX(NAME)\n");
    for p in PowerProfile::ALL {
        let _ = writeln!(
            text,
            "{:2} {:>14}{}:",
            p as u8,
            p.name(),
            if p == profile { "*" } else { " " }
        );
    }
    text
}
pub fn profiles() -> String {
    show(snapshot().map_or(PowerProfile::BootupDefault, |s| s.profile))
}
pub(crate) fn applied(profile: PowerProfile) {
    if let Some(s) = SNAPSHOT.lock().as_mut() {
        s.profile = profile;
    }
}
pub fn request_profile(text: &str) -> Result<(), FsError> {
    let profile = parse(text)?;
    let generation = GENERATION.load(Ordering::Acquire);
    if !controls_live(snapshot()) {
        return Err(FsError::NoDevice);
    }
    let request = REQUEST.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    narf_scheduler::spawn(async move {
        let result = run_level_request(
            &CONTROL,
            &REQUEST,
            request,
            crate::amdgpu_navi48_platform::set_power_profile_current(profile, generation),
        )
        .await;
        if let Some(Err(error)) = result {
            let _ = core::fmt::Write::write_fmt(
                &mut narf_console::Writer,
                format_args!("amdgpu: rdna4 workload profile {profile:?} failed: {error:?}\n"),
            );
        }
    });
    Ok(())
}
