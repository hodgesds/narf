// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9462 legacy20 station autosleep. N46S is a separate measured program,
//! bound to the actual N46A preparation, completed calibration and selected
//! power tables. It neither borrows AR9285 HT authority nor supplies any
//! board measurement or signed record.
use super::{btcoex, calib, power};
use crate::ath9k::{
    admission,
    calibration::Permission,
    packet::{Error, Port},
    ps::Request,
};
use alloc::{format, sync::Arc};
pub(in crate::ath9k) mod hardware;

pub(in crate::ath9k) const RECIPE: &[u8] = b"NARF AR9462 N46S legacy20 station autosleep v1; original exact N46A factory/preparation plus actual calibration report, selected original and capped HT20 power tables; no HT packets/HT40/BA/QoS or N85S alias; measured complete temperature/supply/antenna/BT/posture envelope includes automatic legacy responses, original host encrypted DATA, plain PMNull/PSPoll, AWAKE<->NETWORK_SLEEP WA/MCI/RTC and concurrent-power transitions; real original peer ACK/native QCU0 terminal+allQCUidle+actual RXidle receipt before PMstate commit; unique current BSSID/AID TIM/DTIM/TSF hardware64 sample and epoch resets; autosleep beaconTimeout80/CAB80/3TUslop/2+6TUresponse/bmiss10/TSFOOR4240, S2TIM/DTIM/CAB/TSFOOR current IRQ or 1ms poll; TX/key/rekey/queuedcontrol/receive/CAB/PMNotice/PSPoll flags keepawake; source current before every PCI operation, noSHUTDOWN-preservation/coldreset fiction; exact WA before wake, ForceWakeEN+50us actualON, MCI LNA workaround then STA_PWR_SAV clear, original physical plan before ordinary I/O; NETWORK_SLEEP sets STA_PWR_SAV, masks MCI RX_HW0x23e, clearsForceWakeEN,30us, WA&~D3_L1_DISABLE then bounded actualSLEEP4; no RXabort for autosleep; failed effect terminal/pins retained DMA; noWoWmix; reset changed calibration needs fresh generation/record; source/current peer/request cancellation cannot publish old control/data authority; FTP only source period callbacks whose retained real sleep owner was observed before wake, strict wait>100ms and validated DATApresent count<5, eligible PAN/otherACL and NeedFtpStomp; no awake-elapsed substitute";

pub(in crate::ath9k) struct Base {
    grant: Arc<admission::Grant>,
    permission: Permission,
    request: Request,
    digest: [u8; 32],
    body: [u8; 4],
    wa: u32,
    frequency: u16,
    report: calib::Report,
    plan: power::Plan,
}

impl Base {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::ath9k) fn new(
        device: u16,
        grant: Arc<admission::Grant>,
        permission: Permission,
        report: &calib::Report,
        plan: &power::Plan,
        wa: u32,
        mci_enabled: bool,
    ) -> Result<Option<Arc<Self>>, Error> {
        if device != 0x0034 || report.frequency_mhz >= 4000 || !mci_enabled {
            return Ok(None);
        }
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        let r = grant.request();
        let exact_permission = Permission::from_domain_dual(&domain, report.frequency_mhz)
            .map_err(|_| Error::Access)?
            .with_ceiling(permission.budget());
        if r.device != device
            || r.frequency_mhz != report.frequency_mhz
            || plan.frequency != report.frequency_mhz
            || report.five_ghz
            || report.tx_chainmask != plan.tx_chainmask
            || plan.max_power_level > permission.budget()
            || !permission.current_dual_in(&domain)
            || permission != exact_permission
            || !(1..=3).contains(&report.rx_chainmask)
            || !(1..=3).contains(&report.tx_chainmask)
        {
            return Err(Error::State);
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(&r.identity);
        h.update(&r.mac);
        h.update(&domain.country_code);
        h.update(&[permission.budget(), grant.antenna, grant.ceiling]);
        h.update(&wa.to_le_bytes());
        h.update(&report.frequency_mhz.to_le_bytes());
        h.update(&[
            report.rx_chainmask,
            report.tx_chainmask,
            u8::from(report.tx_iq_cal_enabled),
        ]);
        for peak in report.peak_caldac {
            h.update(&[u8::from(peak.is_some()), peak.unwrap_or(0)]);
        }
        h.update(&[report.carrier_leak.map_or(0, |v| if v { 2 } else { 1 })]);
        for nf in report.default_nf {
            h.update(&nf.to_le_bytes());
        }
        h.update(&[u8::from(report.tx_iq_cal.is_some())]);
        if let Some(iq) = report.tx_iq_cal {
            for count in iq.num_measures {
                h.update(&(count as u32).to_le_bytes());
            }
            for row in iq.tx_corr_coeff {
                for coefficient in row {
                    h.update(&coefficient.to_le_bytes());
                }
            }
        }
        h.update(&[u8::from(report.tx_clcal.is_some())]);
        if let Some(cl) = report.tx_clcal {
            for row in cl.table {
                for value in row {
                    h.update(&value.to_le_bytes());
                }
            }
        }
        for p in [*plan, btcoex::concurrent::plan(plan, true)] {
            h.update(&p.targets);
            h.update(&[p.max_power_level, p.tx_chainmask]);
            for values in [p.correction, p.temperature, p.voltage, p.nf_cal, p.nf_power] {
                for value in values {
                    h.update(&value.to_le_bytes());
                }
            }
            h.update(&p.temp_slope.to_le_bytes());
        }
        let digest = h.finalize();
        let mut identity = narf_crypto::sha256::Sha256::new();
        identity.update(RECIPE);
        identity.update(&digest);
        let channel =
            crate::ath9k::channels::channel(report.frequency_mhz).map_err(|_| Error::State)?;
        let mac = r.mac;
        let base = Self {
            grant,
            permission,
            request: Request {
                identity: identity.finalize(),
                mac,
                filename: format!(
                    "ath9k/ar9462-sta-ps-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    channel, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ),
            },
            digest,
            body: [channel, 20, report.rx_chainmask, report.tx_chainmask],
            wa,
            frequency: report.frequency_mhz,
            report: *report,
            plan: *plan,
        };
        base.invoke(|| Ok(()))?;
        Ok(Some(Arc::new(base)))
    }
    pub(in crate::ath9k) fn request(&self) -> Request {
        self.request.clone()
    }
    pub(in crate::ath9k) fn matches_report(&self, report: &calib::Report) -> bool {
        *report == self.report
    }
    pub(in crate::ath9k) fn recalibrated(
        &self,
        report: &calib::Report,
    ) -> Result<Option<Arc<Self>>, Error> {
        Self::new(
            0x0034,
            self.grant.clone(),
            self.permission,
            report,
            &self.plan,
            self.wa,
            true,
        )
    }
    pub(in crate::ath9k) fn body(&self) -> [u8; 4] {
        self.body
    }
    pub(in crate::ath9k) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(in crate::ath9k) fn wa(&self) -> u32 {
        self.wa
    }
    pub(in crate::ath9k) fn limits(&self) -> (i16, i16) {
        (
            i16::from(self.grant.antenna),
            i16::from(self.permission.budget()),
        )
    }
    pub(in crate::ath9k) fn span(&self) -> (u32, u32) {
        (
            u32::from(self.frequency) - 10,
            u32::from(self.frequency) + 10,
        )
    }
    pub(in crate::ath9k) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.grant
            .invoke(|| {
                Ok((|| {
                    let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    if !self.permission.current_dual_in(&domain)
                        || self.grant.ceiling < self.permission.budget()
                    {
                        return Err(Error::Access);
                    }
                    operation()
                })())
            })
            .map_err(|_| Error::Access)?
    }
    pub(in crate::ath9k) fn readback(&self, port: &impl Port) -> Result<(), Error> {
        self.invoke(|| port.transmit_allowed())
    }
}

/// A one-use observation of the actual retained N46S NETWORK_SLEEP owner.
/// It carries no MMIO privilege; the next awake transition still invokes
/// the original Native/PCI owner. The constructor requires real raw RTC,
/// self-generated PM and ForceWake state under the current sleep source.
pub(in crate::ath9k) struct NetworkSleep {
    source: Arc<crate::ath9k::ps::Grant>,
}
impl NetworkSleep {
    pub(in crate::ath9k) fn observe(
        source: Arc<crate::ath9k::ps::Grant>,
        raw: &impl crate::ath9k::ps::hardware::Raw,
    ) -> Result<Self, Error> {
        let wa = source.ar9003_wa().ok_or(Error::Access)?;
        source.invoke(|| {
            if !matches!(raw.read(0x7044)? & 15, 2 | 4)
                || raw.read(0x8004)? & 0x40000 == 0
                || raw.read(0x704c)? & 1 != 0
                || raw.read(0x4004)? != wa & !0x4000
                || raw.read(0x183c)? & 0x23e != 0
            {
                return Err(Error::State);
            }
            Ok(Self {
                source: source.clone(),
            })
        })
    }
    pub(in crate::ath9k) fn invoke(
        self,
        action: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.source.invoke(action)
    }
}
