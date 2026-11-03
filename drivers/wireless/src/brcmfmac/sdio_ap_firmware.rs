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
    pub(crate) fn command(
        &mut self,
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
        let response = self.0.command(id, input, maximum);
        if id == 26 && self.0.ap.as_ref().is_some_and(|profile| profile.formed) {
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
        (events, data)
    }
    pub(crate) fn transmit(&mut self, bytes: &[u8]) {
        self.0.ap.as_mut().unwrap().transmit(bytes);
    }
    pub(crate) fn profile(&mut self) -> &mut ap_model::Profile {
        self.0.ap.as_mut().unwrap()
    }
}
