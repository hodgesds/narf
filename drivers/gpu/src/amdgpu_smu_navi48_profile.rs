//! SMU14 workload profiles and owner-admitted low-power features.
use super::*;

pub(super) const DS_DCFCLK: u64 = 1 << 14;
pub(super) const GFX_ULV: u64 = 1 << 16;
pub(super) const SLEEP: u64 =
    (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | DS_DCFCLK | (1 << 15) | GFX_ULV | (1 << 44);

/// amdgpu_pm.h's factory profiles mapped by smu_v14_0_2_workload_map.
/// Custom tuning uses TABLE_ACTIVITY_MONITOR_COEFF, never the board PPT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerProfile {
    #[default]
    BootupDefault = 0,
    Fullscreen3d = 1,
    PowerSaving = 2,
    Video = 3,
    Vr = 4,
    Compute = 5,
    Custom = 6,
    Window3d = 7,
}
impl PowerProfile {
    pub const ALL: [Self; 8] = [
        Self::BootupDefault,
        Self::Fullscreen3d,
        Self::PowerSaving,
        Self::Video,
        Self::Vr,
        Self::Compute,
        Self::Custom,
        Self::Window3d,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::BootupDefault => "BOOTUP_DEFAULT",
            Self::Fullscreen3d => "3D_FULL_SCREEN",
            Self::PowerSaving => "POWER_SAVING",
            Self::Video => "VIDEO",
            Self::Vr => "VR",
            Self::Compute => "COMPUTE",
            Self::Custom => "CUSTOM",
            Self::Window3d => "WINDOW_3D",
        }
    }
    pub(crate) fn compute(self) -> bool {
        self == Self::Compute
    }
    fn mask(self) -> u32 {
        1 << self as u8
    }
}
/// The eight Linux custom-profile values, in their sysfs order. Integer
/// widths are firmware ABI widths; PMFW remains responsible for policy ranges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityCoefficients {
    pub fps: u8,
    pub min_type: u8,
    pub min_mhz: u16,
    pub booster_type: u8,
    pub booster_mhz: u16,
    pub limit: u32,
    pub error: u32,
    pub error_rate: u32,
}
pub type ProfileCoefficients = [[ActivityCoefficients; 2]; 8];
pub type CustomCoefficients = [Option<ActivityCoefficients>; 2];
const ACTIVITY_BYTES: usize = 140;
const ACTIVITY_TABLE: u32 = 7;
impl ActivityCoefficients {
    fn read(b: &[u8], base: usize) -> Self {
        Self {
            fps: b[base + 2],
            min_type: b[base + 3],
            min_mhz: u16_at(b, base + 6),
            booster_type: b[base + 4],
            booster_mhz: u16_at(b, base + 8),
            limit: u32_at(b, base + 20),
            error: u32_at(b, base + 24),
            error_rate: u32_at(b, base + 28),
        }
    }
    fn write(self, b: &mut [u8], base: usize) {
        b[base + 2] = self.fps;
        b[base + 3] = self.min_type;
        b[base + 4] = self.booster_type;
        for (offset, value) in [(6, self.min_mhz), (8, self.booster_mhz)] {
            b[base + offset..base + offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, self.limit), (24, self.error), (28, self.error_rate)] {
            b[base + offset..base + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
}
impl<I: Io> Engine<I> {
    async fn activity(&mut self, profile: PowerProfile) -> Result<[u8; ACTIVITY_BYTES], Error> {
        self.access(|io| {
            io.write_buffer(0, &[0; ACTIVITY_BYTES]);
            io.flush()
        })??;
        self.transfer(0x12, ((profile as u32) << 16) | ACTIVITY_TABLE)
            .await?;
        self.access(|io| io.flush())??;
        let mut bytes = [0; ACTIVITY_BYTES];
        self.access(|io| io.read_buffer(0, &mut bytes))?;
        Ok(bytes)
    }
    pub(super) async fn read_profiles(&mut self) -> Result<(), Error> {
        let resume = self.begin_runtime()?;
        let result = async {
            let mut profiles = [[ActivityCoefficients::default(); 2]; 8];
            for profile in PowerProfile::ALL {
                let bytes = self.activity(profile).await?;
                profiles[profile as usize] = [
                    ActivityCoefficients::read(&bytes, 0),
                    ActivityCoefficients::read(&bytes, 32),
                ];
            }
            self.coefficients = Some(profiles);
            Ok(())
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }

    /// The caller already owns Runtime. Restrict changes to admitted sleep
    /// bits, preserve every other running feature, and check fresh protection.
    async fn sleep_features(
        &mut self,
        admitted: u64,
        compute: bool,
        modified: &mut bool,
    ) -> Result<PowerStatus, Error> {
        let previous = self.power.ok_or(Error::Invalid)?;
        let allowed = previous.allowed | (admitted & self.features & SLEEP);
        let running = self.running().await?;
        if !self.protected(running) || running & !allowed != 0 {
            return Err(Error::Features(running));
        }
        let managed = allowed & self.features & SLEEP;
        let wanted = if compute { 0 } else { managed };
        if allowed != previous.allowed {
            self.command(5, (allowed >> 32) as u32).await?;
            *modified = true;
            self.command(4, allowed as u32).await?;
        }
        let disable = running & managed & !wanted;
        let enable = wanted & !running;
        for (message, bits) in [
            (0xa, disable as u32),
            (0xb, (disable >> 32) as u32),
            (8, enable as u32),
            (9, (enable >> 32) as u32),
        ] {
            if bits == 0 {
                continue;
            }
            self.command(message, bits).await?;
            *modified = true;
        }
        let enabled = self.running().await?;
        if enabled & managed != wanted
            || enabled & (running & !managed) != running & !managed
            || enabled & !allowed != 0
            || !self.protected(enabled)
        {
            return Err(Error::Features(enabled));
        }
        Ok(PowerStatus {
            allowed,
            enabled,
            ..previous
        })
    }
    pub(super) async fn admit_sleep(&mut self, bits: u64) -> Result<PowerStatus, Error> {
        if bits & !(DS_DCFCLK | GFX_ULV) != 0 {
            return Err(Error::Invalid);
        }
        if bits & DS_DCFCLK != 0 && self.state != State::DisplayPowerReady {
            return Err(Error::Busy);
        }
        let resume = self.begin_runtime()?;
        let mut modified = false;
        let result = async {
            self.access(|io| io.check_policy())??;
            self.sleep_features(bits, self.profile.compute(), &mut modified)
                .await
        }
        .await;
        self.end_runtime(resume, &result);
        if result.is_err() && modified {
            self.state = State::Failed;
        }
        if let Ok(power) = result {
            self.power = Some(power);
        }
        result
    }
    #[cfg(feature = "kernel-test")]
    pub(super) async fn set_power_profile(&mut self, profile: PowerProfile) -> Result<(), Error> {
        self.set_profile_tuned(profile, [None; 2]).await
    }
    pub(super) async fn set_profile_tuned(
        &mut self,
        profile: PowerProfile,
        custom: CustomCoefficients,
    ) -> Result<(), Error> {
        if profile != PowerProfile::Custom && custom.iter().any(Option::is_some) {
            return Err(Error::Invalid);
        }
        let resume = self.begin_runtime()?;
        let mut modified = false;
        let result = async {
            self.access(|io| io.check_policy())??;
            let power = self
                .sleep_features(0, profile.compute(), &mut modified)
                .await?;
            let mut updated = None;
            if profile == PowerProfile::Custom {
                // Read PMFW's current custom table; preserve hysteresis, PD a/b,
                // time constants, memory policy and firmware padding verbatim.
                let mut bytes = self.activity(profile).await?;
                for (clock, values) in custom.into_iter().enumerate() {
                    if let Some(values) = values {
                        values.write(&mut bytes, clock * 32);
                    }
                }
                self.access(|io| {
                    io.write_buffer(0, &bytes);
                    io.flush()
                })??;
                self.transfer(0x13, (6 << 16) | ACTIVITY_TABLE).await?;
                modified = true;
                // Publish only acknowledged, read-back values. A mismatch leaves
                // the owner failed; the retained reset policy is still the old one.
                let readback = self.activity(profile).await?;
                if [0, 32].into_iter().any(|base| {
                    ActivityCoefficients::read(&readback, base)
                        != ActivityCoefficients::read(&bytes, base)
                }) {
                    return Err(Error::Invalid);
                }
                updated = Some([
                    ActivityCoefficients::read(&bytes, 0),
                    ActivityCoefficients::read(&bytes, 32),
                ]);
            }
            // smu_v14_0_2_set_power_profile_mode: policy before workload.
            self.command(0x24, profile.mask()).await?;
            self.access(|_| ())?;
            self.power = Some(power);
            self.profile = profile;
            self.custom_coefficients = updated;
            if let (Some(cache), Some(values)) = (self.coefficients.as_mut(), updated) {
                cache[PowerProfile::Custom as usize] = values;
            }
            Ok(())
        }
        .await;
        self.end_runtime(resume, &result);
        if result.is_err() && modified {
            self.state = State::Failed;
        }
        result
    }
}
impl Smu {
    pub fn power_profile(&self) -> PowerProfile {
        self.engine.profile
    }
    pub(crate) async fn set_profile_tuned(
        &mut self,
        profile: PowerProfile,
        custom: CustomCoefficients,
    ) -> Result<(), Error> {
        self.engine.set_profile_tuned(profile, custom).await
    }
    pub(crate) async fn read_profiles(&mut self) -> Result<(), Error> {
        self.engine.read_profiles().await
    }
    pub(crate) fn custom_coefficients(&self) -> CustomCoefficients {
        self.engine
            .custom_coefficients
            .map_or([None; 2], |values| values.map(Some))
    }
    pub(crate) fn profile_coefficients(&self) -> Option<ProfileCoefficients> {
        self.engine.coefficients
    }
    /// # Safety
    /// GFX: native GC/RLC/IRQ proofs completed. DCF: the display clock owner
    /// acknowledged watermarks and a valid DML deep-sleep DCFCLK floor.
    pub(crate) async unsafe fn admit_sleep(
        &mut self,
        gfx: bool,
        dcf: bool,
    ) -> Result<PowerStatus, Error> {
        self.engine
            .admit_sleep(if gfx { GFX_ULV } else { 0 } | if dcf { DS_DCFCLK } else { 0 })
            .await
    }
}
