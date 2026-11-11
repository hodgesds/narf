//! Current authenticated RSNA -> firmware GTK offload handoff.

use super::StationSecurity;
use crate::mt7921::firmware_transport::Error;
use zeroize::Zeroizing;

impl StationSecurity {
    pub(in crate::mt7921::firmware_transport) fn validate_wow_gtk_data(
        &self,
        data: &narf_wireless::GtkRekeyData,
    ) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let body = self.wow_gtk_update()?;
        let keys_match = body[8..24].ct_eq(&data.kek[..]) & body[24..40].ct_eq(&data.kck[..]);
        let replay_matches = body[40..48] == data.replay_counter;
        let akm_matches = data.akm.is_none_or(|akm| {
            akm == 0x000f_ac00 | u32::from(self.supplicant.key_mgmt().suite_type())
        });
        if bool::from(keys_match) && replay_matches && akm_matches {
            Ok(())
        } else {
            Err(Error::Bounds)
        }
    }

    pub(in crate::mt7921::firmware_transport) fn wow_gtk_update(
        &self,
    ) -> Result<Zeroizing<[u8; 76]>, Error> {
        use narf_wireless::eapol::FourWayState;
        if !self.port_open()
            || !self.ptk_installed
            || !self.supplicant.ptk_installed
            || !self.supplicant.rx_replay_counter_set
            || self.supplicant.state != FourWayState::PtkDone
            || self
                .supplicant
                .gtk
                .as_ref()
                .is_none_or(|gtk| gtk.len() != self.ciphers.group_key_len())
        {
            return Err(Error::Busy);
        }
        let ptk = self.supplicant.ptk.as_ref().ok_or(Error::Busy)?;
        // Borrow current authenticated keys directly into a zeroizing native
        // body. No generic key-data Copy or debug representation is made.
        crate::mt7921::wowlan::gtk_update(&ptk.kek, &ptk.kck, self.supplicant.last_replay_counter)
    }
}
