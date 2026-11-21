// SPDX-License-Identifier: GPL-2.0-or-later
//! Distinct full-program N46P/N48P/N65P measurements. No A/S/D upgrade.
use super::Settings;
use crate::ath9k::{admission, calibration::Permission, packet::Error};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
const RECIPE:&[u8]=b"AR9003 native legacy20 ANI P1; distinct complete measured immutable original A/report/EEPROM/PCI/host/INI+44MHz full-rate20 program, actual MIB/listen/cycle and OFDM/CCK PHY-error counts, exact ar9003 table-relative/clamped spur and firstep, source AR9462/9565 weak threshold skip, USE_SELF_CORR_LOW and AR9462 multichain MRC only; source AR9003 dynamic3500/1000,900/400 OFDM and600/300 CCK thresholds, levels and RSSI gates, source fixedpoint peer beacon RSSI; actual retained NF/IQ and MCI all coex/concurrent/BT/automatic response states covered together with every ANI level+transition under unchanged source TX powers; start before packet effects, eligible idle1000ms polls, no invented observations; current P/A/host/PCI and original physical readbacks cover every scalar/DMA/IRQ/copy/ring/callback via stable physical latch; no S sleep or D manual combination, reset/retune/suspend/removal terminal retained source/address/DMA uncertainty, no plain A rebuild";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone)]
pub(in crate::ath9k) struct Base {
    grant: Arc<admission::Grant>,
    permission: Permission,
    frequency: u16,
    device: u16,
    rx: u8,
    tx: u8,
    pub(super) ini: Settings,
    request: Request,
}
impl Base {
    pub(in crate::ath9k) fn new(
        grant: Arc<admission::Grant>,
        permission: Permission,
        report: &crate::ath9k::ar9003::calib::Report,
        plan: &crate::ath9k::ar9003::power::Plan,
        ini: Settings,
    ) -> Result<Self, Error> {
        let r = grant.request();
        if !matches!(r.device, 0x0032 | 0x0034 | 0x0036)
            || r.frequency_mhz != report.frequency_mhz
            || r.frequency_mhz != plan.frequency
            || report.rx_chainmask == 0
            || report.tx_chainmask != plan.tx_chainmask
            || plan.max_power_level > permission.budget()
        {
            return Err(Error::State);
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(RECIPE);
        for source in [
            include_bytes!("../ani.rs").as_slice(),
            include_bytes!("qualification.rs").as_slice(),
            include_bytes!("../calib.rs").as_slice(),
            include_bytes!("../power.rs").as_slice(),
            include_bytes!("../../packet_native.rs").as_slice(),
            include_bytes!("../../packet_native/ani.rs").as_slice(),
            include_bytes!("../packet.rs").as_slice(),
            include_bytes!("../packet/engine.rs").as_slice(),
            include_bytes!("../antenna/manual.rs").as_slice(),
            include_bytes!("../../ar9300_owner.rs").as_slice(),
            include_bytes!("../../interface.rs").as_slice(),
        ] {
            h.update(&(source.len() as u64).to_le_bytes());
            h.update(source);
        }
        h.update(&r.identity);
        h.update(&r.mac);
        // The complete field-by-field Debug representations are part of
        // this explicitly source-bound format, never memory/padding bytes.
        // Both derive bodies are included above, so any format change needs
        // a fresh measurement record and request identity.
        let actual = format!("report={report:?};plan={plan:?}");
        h.update(&(actual.len() as u64).to_le_bytes());
        h.update(actual.as_bytes());
        for word in ini.0 {
            h.update(&word.to_le_bytes());
        }
        h.update(&[44, permission.budget(), grant.antenna, grant.ceiling]);
        h.update(&crate::ath9k::ar9003::btcoex::concurrent::plan(plan, true).targets);
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        h.update(&domain.country_code);
        let frequency = r.frequency_mhz;
        let device = r.device;
        let mac = r.mac;
        let base = Self {
            grant,
            permission,
            frequency,
            device,
            rx: report.rx_chainmask,
            tx: report.tx_chainmask,
            ini,
            request: Request {
                identity: h.finalize(),
                mac,
                filename: format!(
                    "ath9k/{}-ani-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    match device {
                        0x0032 => "ar9485",
                        0x0034 => "ar9462",
                        _ => "ar9565",
                    },
                    frequency,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                ),
            },
        };
        base.invoke(|| Ok(()))?;
        Ok(base)
    }
    pub(in crate::ath9k) fn request(&self) -> Request {
        self.request.clone()
    }
    fn magic(&self) -> [u8; 4] {
        match self.device {
            0x0032 => *b"N48P",
            0x0034 => *b"N46P",
            _ => *b"N65P",
        }
    }
    fn invoke<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.grant
            .invoke(|| {
                let domain = narf_wireless::reg::db::snapshot()
                    .ok_or(crate::ath9k::identity::BringUpError::Policy)?;
                if !self.permission.current_dual_in(&domain) {
                    return Err(crate::ath9k::identity::BringUpError::Policy);
                }
                action().map_err(|_| crate::ath9k::identity::BringUpError::BadState)
            })
            .map_err(|_| Error::Access)
    }
}
pub(in crate::ath9k) struct Grant {
    base: Base,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    peak: i16,
    ceiling: i16,
}
impl Grant {
    pub(in crate::ath9k) fn optional(base: Base) -> Result<Option<Arc<Self>>, Error> {
        struct Decode(Base);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(self.0, v.bytes, v.signer, *cap)
                })())
            }
        }
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Access)?;
        let cap = match narf_firmware::open(&base.request.filename, &loader) {
            Ok(v) => v,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(_) => return Err(Error::Access),
        };
        let grant = cap.invoke(Decode(base)).map_err(|_| Error::Access)??;
        grant.invoke(|| Ok(()))?;
        Ok(Some(Arc::new(grant)))
    }
    fn decode(
        base: Base,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none()
            || b.len() != 128
            || b[..4] != base.magic()
            || b[4..8] != [1, 0, 128, 0]
            || b[8..12] != 128u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, base.device as u8, 0]
            || b[16..48] != base.request.identity
            || b[48..54] != base.request.mac
            || b[54..58]
                != [
                    crate::ath9k::channels::channel(base.frequency).map_err(|_| Error::State)?,
                    20,
                    base.rx,
                    base.tx,
                ]
            || b[64..] != [0; 64]
        {
            return Err(Error::Packet);
        }
        let s = |n| i16::from_le_bytes([b[n], b[n + 1]]);
        let g = Self {
            base,
            cap,
            antenna: s(58),
            peak: s(60),
            ceiling: s(62),
        };
        if !(i16::from(g.base.grant.antenna)..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.peak)
            || !(0..=40).contains(&g.ceiling)
        {
            return Err(Error::Packet);
        }
        Ok(g)
    }
    pub(in crate::ath9k) fn ini(&self) -> Settings {
        self.base.ini
    }
    pub(in crate::ath9k) fn invoke<T>(
        &self,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.base.invoke(|| {
            let host = narf_wireless::reg::db::snapshot()
                .and_then(|d| Permission::from_domain_dual(&d, self.base.frequency).ok())
                .ok_or(Error::Access)?;
            if i32::from(self.peak) + i32::from(self.antenna)
                > i32::from(host.budget().min(self.ceiling as u8))
            {
                return Err(Error::Access);
            }
            self.cap.invoke(Live(action)).map_err(|_| Error::Access)?
        })
    }
}

#[cfg(feature = "kernel-test")]
pub(super) fn synthetic(base: Base, cap: Cap<FirmwareBlob, Read>) -> Result<Arc<Grant>, Error> {
    let mut b = [0; 128];
    b[..4].copy_from_slice(&base.magic());
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, base.device as u8, 0]);
    b[16..48].copy_from_slice(&base.request.identity);
    b[48..54].copy_from_slice(&base.request.mac);
    b[54..58].copy_from_slice(&[
        crate::ath9k::channels::channel(base.frequency).map_err(|_| Error::State)?,
        20,
        base.rx,
        base.tx,
    ]);
    b[58..60].copy_from_slice(&128i16.to_le_bytes());
    b[60..62].copy_from_slice(&(-256i16).to_le_bytes());
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    Grant::decode(base, &b, Some([0x50; 32]), cap).map(Arc::new)
}
