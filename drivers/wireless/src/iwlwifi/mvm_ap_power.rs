//! Tag7 AP qualification: a planned ceiling is not an installed receipt.
//! Only the native two-command transaction marks this power owner ready.
use super::power;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::RegulatoryDomain;

pub(in crate::iwlwifi) struct Fence {
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
        let prepared = power::parse_for(source, binding, own, channel, power::Emission::ApLegacy)?;
        let planned = prepared.host_ceiling(domain)?;
        let (cap, maximum, gain) = prepared.ap_source();
        let fence = Arc::new(Fence {
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
