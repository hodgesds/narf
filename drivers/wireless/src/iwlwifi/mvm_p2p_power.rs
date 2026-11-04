//! Tag8 DEVICE qualification is distinct from station1/scan6/AP7. The
//! source, original radio facts, actual child MAC and channel are bound;
//! native SAR/device receipts must precede SESSION1 emission.
use super::{power, Owner};
use alloc::{format, string::String, sync::Arc};
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
                        return Err("MVM P2P current host country unavailable");
                    }
                    let host =
                        super::super::connection::host_channel_power(self.1, self.0.channel, true)
                            .ok_or("MVM P2P current host initiation prohibited")?;
                    if (i16::from(host) * 8 - self.0.gain).min(self.0.maximum) < self.0.planned {
                        return Err("MVM P2P qualified/current power ceiling tightened");
                    }
                    Ok(())
                })())
            }
        }
        self.cap
            .invoke(Check(self, domain))
            .map_err(|_| "MVM P2P original signed tag8 source retired")?
    }
    pub(in crate::iwlwifi) fn ready(&self) -> Result<(), &'static str> {
        self.ready
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or("MVM P2P actual SAR/device receipts absent")
    }
    pub(in crate::iwlwifi) fn radiated_dbm(&self) -> Result<i8, &'static str> {
        i8::try_from(
            (self.planned + self.gain).div_euclid(8)
                + i16::from((self.planned + self.gain).rem_euclid(8) != 0),
        )
        .map_err(|_| "MVM P2P radiated power overflow")
    }
}
pub(in crate::iwlwifi) struct Plan {
    pub(super) fence: Arc<Fence>,
    prepared: power::Prepared,
}
impl Plan {
    pub(in crate::iwlwifi) fn new(
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
        own: [u8; 6],
        channel: u8,
        domain: &RegulatoryDomain,
    ) -> Result<Self, &'static str> {
        let prepared = power::parse_for(source, binding, own, channel, power::Emission::P2pDevice)?;
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
    ) -> Result<(), &'static str> {
        let chains = self.prepared.scan_chain_command();
        let mut device = [0; 44];
        super::super::boot_context::put32(&mut device, 0, 1);
        device[8..10].copy_from_slice(&self.fence.planned.to_le_bytes());
        for body in [chains, device] {
            if !hw.command(1, 0x9f, &body).await?.payload.is_empty() {
                return Err("MVM P2P SAR/device native receipt extent invalid");
            }
        }
        hw.source_fence()?.invoke(|| Ok(()))?;
        self.fence.ready.store(true, Ordering::Release);
        Ok(())
    }
}
impl Owner {
    /// Metadata alone grants no child/role or transmit permission. The
    /// current native owner later reconstructs and checks this exact binding.
    pub(in crate::iwlwifi) fn p2p_power_request(
        &mut self,
        own: [u8; 6],
        channel: u8,
    ) -> Result<power::PowerRequest, &'static str> {
        if !self.p2p_capable()
            || own == [0; 6]
            || own[0] & 1 != 0
            || self.mac == Some(own)
            || channel == 14
            || !self
                .nvm
                .as_ref()
                .is_some_and(|nvm| nvm.channels.contains(&channel))
        {
            return Err("MVM P2P qualification lacks actual child/NVM geometry");
        }
        let base = self.transmit_power_request_for(power::Emission::P2pDevice)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF Intel MVM exact P2P DEVICE child/channel program v8");
        hash.update(&base.binding);
        hash.update(&own);
        hash.update(&[channel]);
        let binding = hash.finalize();
        let digest: String = binding.iter().map(|b| format!("{b:02x}")).collect();
        Ok(power::PowerRequest {
            name: format!("iwlwifi/mvm-api77-p2p-device-{digest}.bin"),
            binding,
        })
    }
}
