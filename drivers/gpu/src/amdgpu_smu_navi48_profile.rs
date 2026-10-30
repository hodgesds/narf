//! SMU14 factory workload profiles and owner-admitted low-power features.
use super::*;

pub(super) const DS_DCFCLK: u64 = 1 << 14;
pub(super) const GFX_ULV: u64 = 1 << 16;
pub(super) const SLEEP: u64 =
    (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | DS_DCFCLK | (1 << 15) | GFX_ULV | (1 << 44);

/// amdgpu_pm.h's factory profiles mapped by smu_v14_0_2_workload_map.
/// Custom coefficients require a separate board-table tuning interface.
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
    Window3d = 7,
}
impl PowerProfile {
    pub const ALL: [Self; 7] = [
        Self::BootupDefault,
        Self::Fullscreen3d,
        Self::PowerSaving,
        Self::Video,
        Self::Vr,
        Self::Compute,
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
impl<I: Io> Engine<I> {
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
    pub(super) async fn set_power_profile(&mut self, profile: PowerProfile) -> Result<(), Error> {
        let resume = self.begin_runtime()?;
        let mut modified = false;
        let result = async {
            self.access(|io| io.check_policy())??;
            let power = self
                .sleep_features(0, profile.compute(), &mut modified)
                .await?;
            // smu_v14_0_2_set_power_profile_mode: policy before workload.
            self.command(0x24, profile.mask()).await?;
            self.access(|_| ())?;
            self.power = Some(power);
            self.profile = profile;
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
    pub(crate) async fn set_power_profile(&mut self, profile: PowerProfile) -> Result<(), Error> {
        self.engine.set_power_profile(profile).await
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
