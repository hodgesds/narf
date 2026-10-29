// SPDX-License-Identifier: GPL-2.0-or-later
//! Separately qualified RTL8188EE DATA rate fallback (`NEFB` v1).
//!
//! Linux v7.2 sources:
//! - `rtlwifi/base.c::rtl_get_tcb_desc`: ordinary station DATA (non-zero
//!   rix) leaves `disable_ratefallback` clear and takes
//!   `sta_entry->ratr_index` as `ratr_index`.
//! - `rtl8188ee/trx.c::rtl88ee_tx_fill_desc`: 88EE forces
//!   `use_driver_rate`, writes `TX_DESC DISABLE_FB` (DW4 bit 10) from
//!   `disable_ratefallback` and `RATE_ID` (DW1 16..19) from `ratr_index`,
//!   so the firmware falls back from the highest rate within the mask
//!   sent by `rtl8188ee/hw.c::rtl88ee_update_hal_rate_mask`
//!   (`H2C_88E_RA_MASK`).
//!
//! The base legacy (NEPC) and HT20 (NEHT) programs qualify a fixed-rate
//! emission profile: every DATA frame is `USE_RATE | DISFB` at one rate.
//! Letting the firmware step down changes the emitted rate sequence over
//! time, so it is a separate signed continuation bound to the exact
//! retained calibration record, factory identity and firmware image.
//! Without a current grant DATA stays fixed-rate; the RA mask H2C is
//! still sent (Linux sends it from `rtl_op_sta_add`/BSS_CHANGED_ASSOC and
//! the DM watchdog independently of the TX descriptor) but with DISFB set
//! the firmware never applies it to a DATA frame.
use super::{channel_power::Calibration, prepare::Error};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
pub(super) const LENGTH: usize = 128;
const SOURCE: &[u8] = b"source base.c rtl_get_tcb_desc station DATA rix!=0 disable_ratefallback=0 ratr_index=sta_entry->ratr_index; rtl8188ee trx.c rtl88ee_tx_fill_desc use_driver_rate forced USE_RATE DW4.8 DISABLE_FB DW4.10 clear RATE_ID DW1.16-19=ratr_index MACID0; mgmt/control/EAPOL/report/BA keep USE_RATE DISFB; hw.c rtl88ee_update_hal_rate_mask H2C_88E_RA_MASK 0x84 levels INIT/HIGH/MIDDLE/LOW; firmware RA falls back within the bound mask; payload byte0 1, others zero";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
pub(super) fn request(
    base: &Calibration,
    firmware: super::firmware_transport::Identity,
) -> Request {
    let f = base.factory();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTL8188EE PCI8179 DATA rate fallback continuation v1");
    h.update(&super::radio::factory_identity(f));
    h.update(&base.digest);
    h.update(super::fw::FW_8188EE.as_bytes());
    h.update(&firmware.digest);
    h.update(SOURCE);
    Request {
        name: format!(
            "rtlwifi/rtl8188ee-fallback-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            f.mac[0], f.mac[1], f.mac[2], f.mac[3], f.mac[4], f.mac[5]
        ),
        binding: h.finalize(),
    }
}
/// A current `NEFB` grant over one retained calibration and firmware.
pub(crate) struct Grant {
    base: Arc<Calibration>,
    cap: Cap<FirmwareBlob, Read>,
    firmware: super::firmware_transport::Identity,
}
impl Grant {
    pub(super) fn matches(&self, base: &Arc<Calibration>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }
    pub(super) fn registered(
        base: Arc<Calibration>,
        firmware: super::firmware_transport::Identity,
    ) -> Result<Option<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source = match crate::firmware_asset::load(
            &authority,
            &request(&base, firmware).name,
            LENGTH,
            true,
        ) {
            Ok(s) => s,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Power(super::channel_power::Error::Firmware(e))),
        };
        Self::parse(base, firmware, &source.bytes, source.signer, source.cap)
            .map(|g| Some(Arc::new(g)))
    }
    pub(super) fn parse(
        base: Arc<Calibration>,
        firmware: super::firmware_transport::Identity,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        let f = base.factory();
        if b.len() != LENGTH
            || b[..4] != *b"NEFB"
            || b[4..8] != [1, 0, LENGTH as u8, 0]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48] != request(&base, firmware).binding
            || b[48..80] != super::radio::factory_identity(f)
            || b[80..112] != base.digest
            || b[112..118] != f.mac
            || b[118] != 1
            || b[119..].iter().any(|v| *v != 0)
        {
            return Err(Error::Power(super::channel_power::Error::Format));
        }
        let grant = Self {
            base,
            cap,
            firmware,
        };
        grant.invoke(|| Ok(()))?;
        Ok(grant)
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.firmware.invoke(|| {
            self.base.with_current(|| {
                self.cap
                    .invoke(Live(operation))
                    .map_err(|_| Error::Power(super::channel_power::Error::Authority))?
            })
        })
    }
    /// Whether the record, its calibration and its firmware are all still
    /// current (`Cap::invoke` proves current validity, not the held handle).
    pub(super) fn current(&self) -> bool {
        self.invoke(|| Ok(())).is_ok()
    }
}
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;
    /// The one admissible `NEFB` v1 body for `base` and `firmware`.
    pub(crate) fn artifact(
        base: &Calibration,
        firmware: super::super::firmware_transport::Identity,
    ) -> Vec<u8> {
        let mut b = alloc::vec![0; LENGTH];
        b[..4].copy_from_slice(b"NEFB");
        b[4..8].copy_from_slice(&[1, 0, LENGTH as u8, 0]);
        b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
        b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
        b[16..48].copy_from_slice(&request(base, firmware).binding);
        b[48..80].copy_from_slice(&super::super::radio::factory_identity(base.factory()));
        b[80..112].copy_from_slice(&base.digest);
        b[112..118].copy_from_slice(&base.factory().mac);
        b[118] = 1;
        b
    }
}
