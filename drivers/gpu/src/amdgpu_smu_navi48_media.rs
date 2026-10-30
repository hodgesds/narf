//! Board-admitted media clock DPM and DS_VCN, after the DPG owner is ready.
use super::*;
use crate::amdgpu_navi48_media_power::FEATURES;
impl<I: Io> Engine<I> {
    pub(super) async fn configure_media_power(
        &mut self,
        enable: bool,
    ) -> Result<PowerStatus, Error> {
        let previous = self.power.ok_or(Error::Invalid)?;
        let bits = if enable { self.features & FEATURES } else { 0 };
        let resume = self.begin_runtime()?;
        let result = async {
            self.access(|io| io.check_policy())??;
            let running = self.running().await?;
            if !self.protected(running) {
                return Err(Error::Features(running));
            }
            let allowed = (previous.allowed & !FEATURES) | bits;
            if enable {
                self.command(5, (allowed >> 32) as u32).await?;
                self.command(4, allowed as u32).await?;
                self.command(8, bits as u32).await?;
                self.command(9, (bits >> 32) as u32).await?;
            } else {
                self.command(0xa, (running & FEATURES) as u32).await?;
                self.command(0xb, ((running & FEATURES) >> 32) as u32)
                    .await?;
            }
            let enabled = self.running().await?;
            let required = (running & !FEATURES) | bits;
            if enabled & required != required
                || enabled & FEATURES != bits
                || !self.protected(enabled)
                || enabled & !allowed != 0
            {
                return Err(Error::Features(enabled));
            }
            if !enable {
                self.command(5, (allowed >> 32) as u32).await?;
                self.command(4, allowed as u32).await?;
            }
            Ok(PowerStatus {
                allowed,
                enabled,
                ..previous
            })
        }
        .await;
        self.end_runtime(resume, &result);
        if let Ok(power) = result {
            self.power = Some(power);
        }
        result
    }
}
impl Smu {
    /// # Safety
    /// Enable only under an exclusive, proved VCN5 DPG owner. Disable before
    /// static re-proof; retain ownership through failures and cancellation.
    pub(crate) async unsafe fn configure_media_power(
        &mut self,
        enable: bool,
    ) -> Result<PowerStatus, Error> {
        self.engine.configure_media_power(enable).await
    }
}
