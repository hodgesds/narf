//! Tag7 AP qualification: a planned ceiling is not an installed receipt.
//! Only the native two-command transaction marks this power owner ready.
use super::power;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::RegulatoryDomain;

pub(in crate::iwlwifi) struct Fence {
    emission: power::Emission,
    cap: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    maximum: i16,
    gain: i16,
    channel: u8,
    planned: i16,
    ready: AtomicBool,
}
impl Fence {
    pub(in crate::iwlwifi) fn check(&self, domain: &RegulatoryDomain) -> Result<(), &'static str> {
        use narf_capabilities::{Cap, CapError, CapOp, Read};
        struct Check<'a>(&'a Fence, &'a RegulatoryDomain);
        impl CapOp<narf_firmware::FirmwareBlob, Read> for Check<'_> {
            type Output = Result<(), &'static str>;
            fn execute(
                self,
                _: &Cap<narf_firmware::FirmwareBlob, Read>,
            ) -> Result<Self::Output, CapError> {
                Ok((|| {
                    if !self.1.country_code.iter().all(u8::is_ascii_uppercase) {
                        return Err("MVM AP current host country unavailable");
                    }
                    if self.0.emission == power::Emission::P2pGo
                        && !super::super::p2p_go::host_allows(
                            self.1,
                            super::super::native_band::Channel::legacy(self.0.channel)
                                .ok_or("MVM GO native channel absent")?,
                        )
                    {
                        return Err("MVM GO current host NO_P2P prohibits initiation");
                    }
                    let power =
                        super::super::connection::host_channel_power(self.1, self.0.channel, true)
                            .ok_or("MVM AP current host initiation/power prohibited")?;
                    let ceiling = (i16::from(power) * 8 - self.0.gain).min(self.0.maximum);
                    if ceiling < self.0.planned {
                        return Err("MVM AP qualified/current ceiling tightened");
                    }
                    Ok(())
                })())
            }
        }
        self.cap
            .invoke(Check(self, domain))
            .map_err(|_| "MVM AP signed tag7 source retired")?
    }
    pub(in crate::iwlwifi) fn check_role(&self, go: bool) -> Result<(), &'static str> {
        if self.emission
            != if go {
                power::Emission::P2pGo
            } else {
                power::Emission::ApLegacy
            }
        {
            return Err("MVM AP/GO signed emission purpose differs from actual role");
        }
        Ok(())
    }
    pub(in crate::iwlwifi) fn ready(&self) -> Result<(), &'static str> {
        self.ready
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or("MVM AP native power receipts absent")
    }
    pub(in crate::iwlwifi) fn radiated_dbm(&self) -> Result<i8, &'static str> {
        i8::try_from(
            (self.planned + self.gain).div_euclid(8)
                + i16::from((self.planned + self.gain).rem_euclid(8) != 0),
        )
        .map_err(|_| "MVM AP radiated bound overflow")
    }
}
pub(in crate::iwlwifi) struct Plan {
    pub(super) fence: Arc<Fence>,
    prepared: power::Prepared,
}
impl Plan {
    pub(super) fn new(
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
        own: [u8; 6],
        channel: u8,
        domain: &RegulatoryDomain,
    ) -> Result<Self, &'static str> {
        Self::new_role(source, binding, own, channel, domain, false)
    }
    pub(super) fn new_go(
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
        own: [u8; 6],
        channel: u8,
        domain: &RegulatoryDomain,
    ) -> Result<Self, &'static str> {
        Self::new_role(source, binding, own, channel, domain, true)
    }
    fn new_role(
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
        own: [u8; 6],
        channel: u8,
        domain: &RegulatoryDomain,
        go: bool,
    ) -> Result<Self, &'static str> {
        let emission = if go {
            power::Emission::P2pGo
        } else {
            power::Emission::ApLegacy
        };
        let prepared = power::parse_for(source, binding, own, channel, emission)?;
        let planned = prepared.host_ceiling(domain)?;
        let (cap, maximum, gain) = prepared.ap_source();
        let fence = Arc::new(Fence {
            emission,
            cap,
            maximum,
            gain,
            channel,
            planned,
            ready: AtomicBool::new(false),
        });
        fence.check(domain)?;
        Ok(Self { fence, prepared })
    }
    pub(in crate::iwlwifi) async fn apply(
        self,
        hw: &mut super::super::runtime::Hardware,
    ) -> Result<power::Prepared, &'static str> {
        let (chains, link) = self.prepared.ap_commands(self.fence.planned);
        for body in [chains, link] {
            let response = hw.command(1, 0x9f, &body).await?;
            if !response.payload.is_empty() {
                return Err("MVM AP SAR/link native receipt invalid");
            }
        }
        hw.source_fence()?.invoke(|| Ok(()))?;
        let mut prepared = self.prepared;
        prepared.ap_acknowledge(self.fence.planned);
        self.fence.ready.store(true, Ordering::Release);
        Ok(prepared)
    }
}

impl super::Owner {
    /// Metadata only, with a fresh purpose9 and exact actual GO identity.
    /// The original native owner reconstructs it before accepting any record.
    pub(in crate::iwlwifi) fn go_power_request(
        &mut self,
        identity: super::super::p2p_go::Identity,
        channel: super::super::native_band::Channel,
    ) -> Result<power::PowerRequest, &'static str> {
        use alloc::{format, string::String};
        let own = self.mac.ok_or("MVM GO physical MAC absent")?;
        if !self.ap_capable()
            || !matches!(
                self.hardware.version(3, 0xfc).map(|version| version.1),
                None | Some(1 | 99)
            )
            || channel.band == super::super::native_band::Band::Six
            || channel.number == 14
            || !self
                .nvm
                .as_ref()
                .is_some_and(|nvm| nvm.channels.contains(&channel.number))
        {
            return Err("MVM GO qualification lacks actual profile/channel/NoA contract");
        }
        let base = self.transmit_power_request_for(power::Emission::P2pGo)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF Intel MVM exact GO physical identity and native-NoA program v9");
        hash.update(&base.binding);
        hash.update(&identity.binding(own, channel));
        let binding = hash.finalize();
        let digest: String = binding.iter().map(|b| format!("{b:02x}")).collect();
        Ok(power::PowerRequest {
            name: format!("iwlwifi/mvm-api77-p2p-go-{digest}.bin"),
            binding,
        })
    }
}
