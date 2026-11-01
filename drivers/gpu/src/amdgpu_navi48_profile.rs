//! Linux pp_power_profile_mode, serialized and bound to the admitted owner.
use super::*;
use alloc::collections::VecDeque;
use smu::PowerProfile;
struct Requests {
    running: bool,
    pending: VecDeque<(u64, ProfileRequest)>,
}
static REQUESTS: IrqSafeSpinLock<Requests> = IrqSafeSpinLock::new(Requests {
    running: false,
    pending: VecDeque::new(),
});
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProfileRequest {
    pub profile: PowerProfile,
    pub custom: smu::CustomCoefficients,
}
pub(super) fn parse(text: &str) -> Result<ProfileRequest, FsError> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let id = *fields.first().ok_or(FsError::InvalidData)?;
    if id.len() != 1 {
        return Err(FsError::InvalidData);
    }
    let profile = PowerProfile::ALL
        .into_iter()
        .find(|p| id.as_bytes()[0] == b'0' + *p as u8)
        .ok_or(FsError::InvalidData)?;
    let mut request = ProfileRequest {
        profile,
        custom: [None; 2],
    };
    if fields.len() == 1 {
        return Ok(request);
    }
    if profile != PowerProfile::Custom || fields.len() != 10 {
        return Err(FsError::InvalidData);
    }
    let numbers: Vec<u32> = fields[1..]
        .iter()
        .map(|s| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(FsError::InvalidData);
            }
            s.parse().map_err(|_| FsError::InvalidData)
        })
        .collect::<Result<_, _>>()?;
    let clock = numbers[0] as usize;
    if clock >= 2 {
        return Err(FsError::InvalidData);
    }
    request.custom[clock] = Some(smu::ActivityCoefficients {
        fps: numbers[1].try_into().map_err(|_| FsError::InvalidData)?,
        min_type: numbers[2].try_into().map_err(|_| FsError::InvalidData)?,
        min_mhz: numbers[3].try_into().map_err(|_| FsError::InvalidData)?,
        booster_type: numbers[4].try_into().map_err(|_| FsError::InvalidData)?,
        booster_mhz: numbers[5].try_into().map_err(|_| FsError::InvalidData)?,
        limit: numbers[6],
        error: numbers[7],
        error_rate: numbers[8],
    });
    Ok(request)
}
pub(super) fn show(
    profile: PowerProfile,
    coefficients: Option<smu::ProfileCoefficients>,
) -> String {
    use core::fmt::Write as _;
    let mut text = String::from("PROFILE_INDEX(NAME) CLOCK_TYPE(NAME) FPS MinActiveFreqType MinActiveFreq BoosterFreqType BoosterFreq PD_Data_limit_c PD_Data_error_coeff PD_Data_error_rate_coeff\n");
    for p in PowerProfile::ALL {
        let _ = writeln!(
            text,
            "{:2} {:>14}{}:",
            p as u8,
            p.name(),
            if p == profile { "*" } else { " " }
        );
        if let Some(coefficients) = coefficients {
            for (clock, c) in coefficients[p as usize].into_iter().enumerate() {
                let name = if clock == 0 { "GFXCLK" } else { "FCLK" };
                let _ = writeln!(text, "                    {clock}({name:>13}) {:7} {:7} {:7} {:7} {:7} {:7} {:7} {:7}",
                    c.fps, c.min_type, c.min_mhz, c.booster_type, c.booster_mhz, c.limit, c.error, c.error_rate);
            }
        }
    }
    text
}
pub fn profiles() -> String {
    let state = snapshot();
    show(
        state.map_or(PowerProfile::BootupDefault, |s| s.profile),
        state.and_then(|s| s.coefficients),
    )
}
pub(crate) fn applied(profile: PowerProfile, coefficients: Option<smu::ProfileCoefficients>) {
    if let Some(s) = SNAPSHOT.lock().as_mut() {
        s.profile = profile;
        s.coefficients = coefficients;
    }
}
pub fn request_profile(text: &str) -> Result<(), FsError> {
    let selection = parse(text)?;
    let generation = GENERATION.load(Ordering::Acquire);
    if !controls_live(snapshot()) {
        return Err(FsError::NoDevice);
    }
    let start = {
        let mut requests = REQUESTS.lock();
        if requests.pending.len() >= 64 {
            return Err(FsError::Busy);
        }
        requests.pending.push_back((generation, selection));
        let start = !requests.running;
        requests.running = true;
        start
    };
    if start {
        narf_scheduler::spawn(worker());
    }
    Ok(())
}
async fn worker() {
    loop {
        let next = {
            let mut requests = REQUESTS.lock();
            let next = requests.pending.pop_front();
            if next.is_none() {
                requests.running = false;
            }
            next
        };
        let Some((generation, selection)) = next else {
            return;
        };
        // One consumer preserves store order, including same-clock edits and
        // factory selection following custom tuning. Reset generations are
        // checked under OWNER before any firmware write.
        if let Err(error) =
            crate::amdgpu_navi48_platform::set_power_profile_current(selection, generation).await
        {
            let _ = core::fmt::Write::write_fmt(
                &mut narf_console::Writer,
                format_args!("amdgpu: rdna4 workload profile {selection:?} failed: {error:?}\n"),
            );
        }
    }
}
