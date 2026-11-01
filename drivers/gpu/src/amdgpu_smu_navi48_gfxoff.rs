//! SMU14 GFXOFF policy and mailbox, shared by GC12.0.0 and GC12.0.1.
use super::*;
const FEATURE: u64 = 1 << 18; // FEATURE_GFXOFF_BIT
impl<I: Io> Engine<I> {
    pub(super) async fn configure_gfxoff(&mut self) -> Result<bool, Error> {
        if self.features & FEATURE == 0 {
            self.access(|_| ())?;
            return Ok(false);
        }
        let previous = self.power.ok_or(Error::Invalid)?;
        let resume = self.begin_runtime()?;
        let result = async {
            self.access(|io| io.check_policy())??;
            let running = self.running().await?;
            if !self.protected(running) {
                return Err(Error::Features(running));
            }
            let allowed = previous.allowed | FEATURE;
            self.command(5, (allowed >> 32) as u32).await?;
            self.command(4, allowed as u32).await?;
            self.command(8, FEATURE as u32).await?; // EnableSmuFeaturesLow
            self.command(9, 0).await?;
            let enabled = self.running().await?;
            if enabled & (previous.enabled | FEATURE) != previous.enabled | FEATURE
                || !self.protected(enabled)
            {
                return Err(Error::Features(enabled));
            }
            self.command(0x29, 0).await?; // PPSMC_MSG_DisallowGfxOff
            self.power = Some(PowerStatus {
                allowed,
                enabled,
                ..previous
            });
            Ok(true)
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    pub(super) async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        if self.power.is_none_or(|p| p.enabled & FEATURE == 0) {
            return Err(Error::Invalid);
        }
        let resume = self.begin_runtime()?;
        let result = async {
            let enabled = self.running().await?;
            if enabled & FEATURE == 0 || !self.protected(enabled) {
                return Err(Error::Features(enabled));
            }
            self.command(if allow { 0x28 } else { 0x29 }, 0).await?;
            Ok(())
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
}
impl Smu {
    pub(crate) fn gfxoff_supported(&self) -> bool {
        self.engine.features & FEATURE != 0
    }
    pub(crate) async fn configure_gfxoff(&mut self) -> Result<bool, Error> {
        self.engine.configure_gfxoff().await
    }
    pub(crate) async fn gfx_off_control(&mut self, allow: bool) -> Result<(), Error> {
        self.engine.gfx_off_control(allow).await
    }
}
