// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware bytes only behind native SDHCI/F1/F2/SDPCM/BCDC. This adapter
//! never replaces the host Fullmac/Station/Device or mints source authority.
use super::{ap_model, Firmware as Base};
use alloc::vec::Vec;
pub(crate) struct Firmware(Base, Vec<u8>);
impl Firmware {
    pub(crate) fn new() -> Self {
        let mut firmware = Base::new(false);
        firmware.ap = Some(ap_model::Profile::default());
        Self(firmware, b"ap sta wme\0".to_vec())
    }
    pub(crate) fn capability(&mut self, bytes: &[u8]) {
        self.1 = bytes.to_vec();
    }
    /// One BCDC IOCTL; `ifidx` is its `BCDC_DCMD_IF_SHIFT` field.
    pub(crate) fn command(
        &mut self,
        ifidx: u8,
        id: u32,
        input: &[u8],
        maximum: u16,
    ) -> Option<(Vec<u8>, i16)> {
        if id == 262 && input.starts_with(b"cap\0") {
            let mut response = alloc::vec![0;usize::from(maximum)];
            let caps = self.1.as_slice();
            let length = response.len().min(caps.len());
            response[..length].copy_from_slice(&caps[..length]);
            return Some((response, 0));
        }
        let response = self.0.command_on(ifidx, id, input, maximum);
        if ifidx == 0 && id == 26 && self.0.ap.as_ref().is_some_and(|profile| profile.formed) {
            let profile = self.0.ap.as_mut().unwrap();
            profile.event(16, super::OWN, &[]);
            profile.events.back_mut().unwrap()[26..28].copy_from_slice(&1u16.to_be_bytes());
        }
        if self.0.hold_mfp_reply(id, input) {
            return None;
        }
        Some((response, self.0.status(id)))
    }
    pub(crate) fn outputs(&mut self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut events: Vec<_> = self.0.events.drain(..).collect();
        let mut data: Vec<_> = self.0.downlink.drain(..).collect();
        let ap = self.0.ap.as_mut().unwrap();
        events.extend(ap.events.drain(..));
        data.extend(ap.downlink.drain(..));
        // The secondary AP's SME events come from ifidx/bsscfg 1.
        if let Some(vif) = self.0.vif.ap.as_mut() {
            for mut event in vif.events.drain(..) {
                event[70] = 1;
                event[71] = 1;
                events.push(event);
            }
        }
        (events, data)
    }
    /// One BDC data frame; `ifidx` is its `flags2` interface.
    pub(crate) fn transmit(&mut self, ifidx: u8, bytes: &[u8]) {
        if ifidx == 0 {
            self.0.ap.as_mut().unwrap().transmit(bytes);
        } else if let Some(vif) = self.0.vif.ap.as_mut() {
            vif.transmit(bytes);
        }
    }
    /// Create ifidx 1 as a firmware-SME AP (as the PCIe model's
    /// `Handle::enable_vif_ap`).
    pub(crate) fn enable_vif_ap(&mut self) {
        let mut ap = ap_model::Profile::default();
        ap.own = super::VIF;
        self.0.vif.ap = Some(ap);
    }
    pub(crate) fn vif_profile(&mut self) -> &mut ap_model::Profile {
        self.0.vif.ap.as_mut().unwrap()
    }
    pub(crate) fn profile(&mut self) -> &mut ap_model::Profile {
        self.0.ap.as_mut().unwrap()
    }
}
