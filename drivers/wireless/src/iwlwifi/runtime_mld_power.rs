//! Optional BIOS power preparation for the current native MLD firmware owner.
//! Every command uses the ordinary correlated RFH/TFH path. Once publishing
//! begins, cancellation/errors require reset; a new read cannot erase limits.
use super::super::mld_power::{Inputs, Ppag};
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Initial,
    Publishing,
    Ready,
    Failed,
}

#[cfg(feature = "kernel-test")]
#[path = "runtime_mld_power_tests.rs"]
mod tests;
#[derive(Default, Debug)]
pub(super) struct State {
    phase: Phase,
    pub(super) inputs: Option<Inputs>,
    pub(super) receipts: Vec<(u8, u8, u16)>,
}
impl Hardware {
    pub(in crate::iwlwifi) fn current_policy_domain(
        &self,
    ) -> Result<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>, &'static str> {
        self.rf_policy
            .as_ref()
            .ok_or("Intel power update has no current RF authority")?
            .domain()
    }
    pub(in crate::iwlwifi) async fn ensure_platform_power(&mut self) -> Result<(), &'static str> {
        match self.platform_power.phase {
            Phase::Ready => return Ok(()),
            Phase::Publishing | Phase::Failed => {
                return Err("MLD platform power requires a fresh native generation")
            }
            Phase::Initial => {}
        }
        if self.format == rx_rfh::CompletionFormat::Qu {
            return Err("MLD platform owner cannot replace Gen2 signed power preparation");
        }
        self.source_fence()?.invoke(|| Ok(()))?;
        #[cfg(any(test, feature = "kernel-test"))]
        let input = if model::is_model(self) {
            // This explicit RAM backend has no physical BIOS companion.
            // Native BIOS/receipt tests supply their real fixture snapshot.
            Inputs::unavailable(super::super::mld_power::InputStatus::Unavailable)
        } else {
            super::super::mld_platform::read(self.device, &self.cap)
        };
        #[cfg(not(any(test, feature = "kernel-test")))]
        let input = super::super::mld_platform::read(self.device, &self.cap);
        self.prepare_platform_power_using(input).await
    }

    fn bios_revision(&self, source: u8, group: u8, command: u8, default: u8) -> u8 {
        let api = super::super::firmware_api::FirmwareApi {
            bios_commands: Some(&self.bios_versions),
            ..Default::default()
        };
        api.bios_revision(source, group, command, default)
    }
    pub(in crate::iwlwifi) async fn prepare_platform_power_using(
        &mut self,
        input: Inputs,
    ) -> Result<(), &'static str> {
        if self.platform_power.phase != Phase::Initial || self.failed {
            return Err("MLD platform power is already applied, pending or failed");
        }
        if self.format == rx_rfh::CompletionFormat::Qu {
            return Err("MLD platform owner on the signed Gen2 profile");
        }
        let mut commands: Vec<(u8, u8, Vec<u8>)> = Vec::new();
        // Linux mld/fw.c applies optional PPAG before SAR and geographic SAR.
        if input.ppag_approved {
            let ppag = input.ppag.clone().unwrap_or_else(Ppag::disabled);
            let version = self.version(4, 7).ok_or("missing MLD PPAG command ABI")?.0;
            let maximum = if version == 5 {
                u8::MAX
            } else {
                self.bios_revision(ppag.source(), 4, 7, if version == 7 { 4 } else { 5 })
            };
            if let Some(body) = ppag.command(version, maximum)? {
                commands.push((4, 7, body));
            }
        }
        if let Some(sar) = &input.sar {
            let version = self
                .version(1, 0x9f)
                .ok_or("missing MLD TX-power command ABI")?
                .0;
            if let Some(body) = sar.command(version)? {
                commands.push((1, 0x9f, body));
                if let Some(geo) = &input.geo {
                    let version = self
                        .version(4, 5)
                        .ok_or("missing MLD geographic SAR command ABI")?
                        .0;
                    commands.push((4, 5, geo.command(version)?));
                }
            }
        }
        self.source_fence()?.invoke(|| Ok(()))?;
        self.platform_power.inputs = Some(input);
        self.platform_power.phase = Phase::Publishing;
        for (group, command, body) in commands {
            let receipt = match self.command(group, command, &body).await {
                Ok(receipt) if receipt.payload.is_empty() => receipt,
                Ok(_) => {
                    self.platform_power.phase = Phase::Failed;
                    self.fail();
                    return Err("unexpected MLD platform-power receipt payload");
                }
                Err(reason) => {
                    self.platform_power.phase = Phase::Failed;
                    self.fail();
                    return Err(reason);
                }
            };
            self.platform_power
                .receipts
                .push((group, command, receipt.header.sequence));
        }
        let final_proof = self
            .source_fence()
            .and_then(|fence| fence.invoke(|| Ok(())));
        if let Err(reason) = final_proof {
            self.platform_power.phase = Phase::Failed;
            self.fail();
            return Err(reason);
        }
        self.platform_power.phase = Phase::Ready;
        Ok(())
    }
}
