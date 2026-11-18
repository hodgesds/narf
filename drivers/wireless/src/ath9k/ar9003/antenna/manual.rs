// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit AR9485 manual sharing. N48D is a separate measured complete
//! program, never an upgrade of N48A or an inference from PCI flags.
use super::Profile;
use crate::ath9k::{
    admission,
    calibration::Permission,
    identity::{BringUpError, RegisterIo},
    packet::Error,
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;
use narf_lib::sync::IrqSafeSpinLock;

const RECIPE: &[u8] = b"N48D AR9485 explicit manual WLAN/BT RX sharing v1; original N48A actual completed report and immutable power/EEPROM/PCI; exact source BT-capable0032 only, never0037; CONTROL+Owner+radio serialized explicit setter, paused EDMA+retained buffers and receive epoch withdrawal; source3WIRE GPIO5 plain output mux, MODE quiet+disabled1c00, MODE2/WL0/WL1/BT0..3 zero with full receipts, no absent-MCI proof; original ar9003_hw_set_bt_ant_diversity enable/disable switchCOM2 EEPROM or exact canonical config mask, rawLNA/gain, LNADIV+fastdiv and capable LNA1/LNA2; source group2 scanner enabled only by explicit request, scanner rebase and current source readbacks; all scalar/DMA/IRQ/copy/ring/callback publications use the same dynamic physical latch even tokens captured before request; complete enabled+disabled+manual transient, original periodic NF/IQ, retry/automatic response and EDMA pause/resume program worstcase static conducted peak and antenna gain, original power unchanged; companion remains mandatory after disable or uncertainty; reset/retune/system suspend terminally retire actualDMA under current old lease then park, never plain-source rebuild or unqualified report replay, removal keeps physical address/source reserved; no TX-chain-mask alias, no AR9565/MCI/group3 admission";
const N65_RECIPE:&[u8]=b"N65D AR9565 explicit manual sharing v1; exact current original N65A completed report/power/EEPROM/PCI with canonical BT_ANT_DIV and combining, fixed raw0xc9 and13 exact suppression rows; separate sealed actual live MCI config/GPM/schedule facts; CONTROL+Owner+radio serialized explicit setter and native EDMA pause, static measured full antenna/power/BT/transition envelope covers both original concurrent and uncapped powers, every group3 LNA/bias/combination, periodic NF/IQ, retry/automatic response, pending MCI messages/timeouts and remote BT still active or unknown; no assumed RF sleep; current joint-source uncapped power restoration before priority withdrawal; permanently retire every GPM/duty/IRQ/reset/re-enable producer, source actual live addresses/MCI_MODE verified, stop_bt(false) exact mute/LNA-update-disable/LNA_TAKE/SYS_SLEEPING and cleanup CTRL0+interrupt masks0 receipts establish LOCALcoex-off only, never DMA-idle/reset/remote RF-stop; retain original GPM buffer/link/IRQ/source on success or uncertainty forever; source AR9565 manual rawLNA then LNADIV,RX_PROTECT,CCK fastdiv,RESTART M2FLAG,WL_LNADIV force-on in exact enable/disable order, no AR9485 switch write; distinct group3 early -3/+3, scan-9, final +3 and source bias table; shared dynamic counted latch covers previously captured scalar/DMA/IRQ/copy/ring/carrier/callback tokens, disable retainsN65D, reset/retune/suspend/removal terminal park/reserve no plainN65A or MCI restart";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ar9485,
    Ar9565,
}
impl Kind {
    fn device(self) -> u16 {
        match self {
            Self::Ar9485 => 0x0032,
            Self::Ar9565 => 0x0036,
        }
    }
    fn magic(self) -> [u8; 4] {
        match self {
            Self::Ar9485 => *b"N48D",
            Self::Ar9565 => *b"N65D",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ar9485 => "ar9485",
            Self::Ar9565 => "ar9565",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}

#[derive(Clone)]
pub(in crate::ath9k) struct Base {
    kind: Kind,
    mci: Option<super::super::btcoex::ManualMciFacts>,
    grant: Arc<admission::Grant>,
    permission: Permission,
    request: Request,
    inputs: Inputs,
    frequency: u16,
}
#[derive(Clone, Copy)]
struct Inputs {
    raw: u8,
    ordinary: u32,
    sharing: u32,
}
impl Base {
    pub(in crate::ath9k) fn new(
        grant: Arc<admission::Grant>,
        permission: Permission,
        report: &super::super::calib::Report,
        plan: &super::super::power::Plan,
        profile: Profile,
        image: &super::super::power::Image,
        config: super::super::board::Config,
    ) -> Result<Self, Error> {
        Self::new_inner(
            grant, permission, report, plan, profile, image, config, None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::ath9k) fn new_mci(
        grant: Arc<admission::Grant>,
        permission: Permission,
        report: &super::super::calib::Report,
        plan: &super::super::power::Plan,
        profile: Profile,
        image: &super::super::power::Image,
        config: super::super::board::Config,
        mci: super::super::btcoex::ManualMciFacts,
    ) -> Result<Self, Error> {
        Self::new_inner(
            grant,
            permission,
            report,
            plan,
            profile,
            image,
            config,
            Some(mci),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        grant: Arc<admission::Grant>,
        permission: Permission,
        report: &super::super::calib::Report,
        plan: &super::super::power::Plan,
        profile: Profile,
        image: &super::super::power::Image,
        config: super::super::board::Config,
        mci: Option<super::super::btcoex::ManualMciFacts>,
    ) -> Result<Self, Error> {
        let kind = if mci.is_some() {
            Kind::Ar9565
        } else {
            Kind::Ar9485
        };
        let r = grant.request();
        if !profile.manual_capable()
            || r.device != kind.device()
            || report.five_ghz
            || report.frequency_mhz != r.frequency_mhz
            || plan.frequency != r.frequency_mhz
            || report.rx_chainmask != 1
            || report.tx_chainmask != 1
            || plan.tx_chainmask != 1
            || plan.max_power_level > permission.budget()
        {
            return Err(Error::State);
        }
        if super::super::mac::rf_silent(image)
            .map_err(|_| Error::State)?
            .is_some_and(|kill| kind == Kind::Ar9485 && kill.gpio == 5)
        {
            return Err(Error::State);
        }
        let m =
            super::super::eeprom::field::MODAL_2G + super::super::eeprom::modal::ANT_CTRL_COMMON2;
        let inputs = Inputs {
            raw: profile.raw,
            ordinary: u32::from_le_bytes(image[m..m + 4].try_into().map_err(|_| Error::State)?),
            sharing: config.manual_switch(),
        };
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(match kind {
            Kind::Ar9485 => RECIPE,
            Kind::Ar9565 => N65_RECIPE,
        });
        for source in [
            include_bytes!("manual.rs").as_slice(),
            include_bytes!("../antenna.rs").as_slice(),
            include_bytes!("scanner.rs").as_slice(),
            include_bytes!("../btcoex.rs").as_slice(),
            include_bytes!("../mci.rs").as_slice(),
            include_bytes!("../../packet_native/coex.rs").as_slice(),
            include_bytes!("../board/config.rs").as_slice(),
            include_bytes!("../../packet_native.rs").as_slice(),
            include_bytes!("../../interface.rs").as_slice(),
            include_bytes!("../../ar9300_owner.rs").as_slice(),
        ] {
            h.update(&(source.len() as u64).to_le_bytes());
            h.update(source);
        }
        h.update(&r.identity);
        h.update(&r.mac);
        h.update(&profile.identity_bytes());
        h.update(&config.identity_bytes());
        h.update(&inputs.ordinary.to_le_bytes());
        h.update(&inputs.sharing.to_le_bytes());
        if let Some(mci) = mci {
            h.update(&mci.bytes());
            h.update(&super::super::btcoex::concurrent::plan(plan, true).targets);
        }
        h.update(&report.frequency_mhz.to_le_bytes());
        h.update(&[
            permission.budget(),
            grant.antenna,
            grant.ceiling,
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
            for n in iq.num_measures {
                h.update(&(n as u32).to_le_bytes());
            }
            for row in iq.tx_corr_coeff {
                for c in row {
                    h.update(&c.to_le_bytes());
                }
            }
        }
        h.update(&[u8::from(report.tx_clcal.is_some())]);
        if let Some(cl) = report.tx_clcal {
            for row in cl.table {
                for c in row {
                    h.update(&c.to_le_bytes());
                }
            }
        }
        h.update(&plan.targets);
        h.update(&[plan.max_power_level, plan.tx_chainmask]);
        for row in [
            plan.correction,
            plan.temperature,
            plan.voltage,
            plan.nf_cal,
            plan.nf_power,
        ] {
            for c in row {
                h.update(&c.to_le_bytes());
            }
        }
        h.update(&plan.temp_slope.to_le_bytes());
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        h.update(&domain.country_code);
        let mac = r.mac;
        let base = Self {
            kind,
            mci,
            grant,
            permission,
            inputs,
            frequency: r.frequency_mhz,
            request: Request {
                identity: h.finalize(),
                mac,
                filename: format!(
                    "ath9k/{}-bt-sharing-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    kind.name(),
                    r.frequency_mhz,
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
    fn invoke<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.grant
            .invoke(|| {
                let domain = narf_wireless::reg::db::snapshot().ok_or(BringUpError::Policy)?;
                if !self.permission.current_dual_in(&domain) {
                    return Err(BringUpError::Policy);
                }
                action().map_err(|_| BringUpError::BadState)
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
    pub(in crate::ath9k) fn load(base: Base) -> Result<Arc<Self>, Error> {
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
        let cap =
            narf_firmware::open(&base.request.filename, &loader).map_err(|_| Error::Access)?;
        let grant = cap.invoke(Decode(base)).map_err(|_| Error::Access)??;
        grant.invoke(|| Ok(()))?;
        Ok(Arc::new(grant))
    }
    fn decode(
        base: Base,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none()
            || b.len() != 128
            || b[..4] != base.kind.magic()
            || b[4..8] != [1, 0, 128, 0]
            || b[8..12] != 128u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, base.kind.device() as u8, 0]
            || b[16..48] != base.request.identity
            || b[48..54] != base.request.mac
            || b[54..58]
                != [
                    crate::ath9k::channels::channel(base.frequency).map_err(|_| Error::State)?,
                    20,
                    1,
                    1,
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
        if !(0..=128).contains(&g.antenna)
            || g.antenna < i16::from(g.base.grant.antenna)
            || !(-512..=256).contains(&g.peak)
            || !(0..=40).contains(&g.ceiling)
        {
            return Err(Error::Packet);
        }
        Ok(g)
    }
    pub(in crate::ath9k) fn invoke<T>(
        &self,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.base.invoke(|| {
            struct Live<F>(F);
            impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
                type Output = Result<T, Error>;
                fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                    Ok((self.0)())
                }
            }
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

struct State {
    source: Option<Arc<Grant>>,
    ani: Option<Arc<super::super::ani::Grant>>,
    retained: Vec<Arc<Grant>>,
    flights: usize,
    closing: bool,
    ready: bool,
    failed: bool,
    desired: bool,
    expected: Option<[u32; 5]>,
}
/// Stable across every Native and host publication token of this physical
/// owner. Reentrant callbacks take counted scopes, never a held spin lock.
pub(in crate::ath9k) struct Latch(IrqSafeSpinLock<State>);
impl Latch {
    pub(in crate::ath9k) fn new() -> Arc<Self> {
        Arc::new(Self(IrqSafeSpinLock::new(State {
            source: None,
            ani: None,
            retained: Vec::new(),
            flights: 0,
            closing: false,
            ready: true,
            failed: false,
            desired: false,
            expected: None,
        })))
    }
    pub(in crate::ath9k) fn bound(&self) -> bool {
        self.0.lock().source.is_some()
    }
    pub(in crate::ath9k) fn ani_bound(&self) -> bool {
        self.0.lock().ani.is_some()
    }
    /// Any separately qualified irreversible complete-program continuation.
    pub(in crate::ath9k) fn retained(&self) -> bool {
        let s = self.0.lock();
        s.source.is_some() || s.ani.is_some()
    }
    /// The unique cold Native installs P before any publication token or
    /// packet effect. It cannot be added to a live S/D generation.
    pub(in crate::ath9k) fn install_ani(
        &self,
        source: Arc<super::super::ani::Grant>,
    ) -> Result<(), Error> {
        source.invoke(|| {
            let mut s = self.0.lock();
            if s.failed || s.closing || s.flights != 0 || s.source.is_some() || s.ani.is_some() {
                return Err(Error::State);
            }
            s.ani = Some(source.clone());
            Ok(())
        })
    }
    pub(in crate::ath9k) fn desired(&self) -> bool {
        self.0.lock().desired
    }
    pub(in crate::ath9k) fn mci_facts(&self) -> Option<super::super::btcoex::ManualMciFacts> {
        self.0.lock().source.as_ref().and_then(|g| g.base.mci)
    }
    pub(in crate::ath9k) fn fail(&self) {
        let mut s = self.0.lock();
        s.failed = true;
        s.ready = false;
    }
    pub(in crate::ath9k) fn hardware(&self) -> Result<(), Error> {
        let mut s = self.0.lock();
        if s.failed || s.closing {
            return Err(Error::Access);
        }
        s.ready = false;
        Ok(())
    }
    pub(in crate::ath9k) fn ready(&self, desired: bool) -> Result<(), Error> {
        self.current(false, || {
            let mut s = self.0.lock();
            if s.source.is_some() && s.expected.is_none() {
                return Err(Error::State);
            }
            s.ready = true;
            s.desired = desired;
            Ok(())
        })
    }
    pub(in crate::ath9k) fn current<T>(
        &self,
        packet: bool,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (source, ani) = {
            let mut s = self.0.lock();
            if s.failed || s.closing || packet && !s.ready {
                return Err(Error::Access);
            }
            s.flights = s.flights.checked_add(1).ok_or(Error::State)?;
            (s.source.clone(), s.ani.clone())
        };
        struct Flight<'a>(&'a Latch);
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                self.0 .0.lock().flights -= 1;
            }
        }
        let _flight = Flight(self);
        let qualified = source.is_some() || ani.is_some();
        let action = || match ani {
            Some(ref p) => p.invoke(action),
            None => action(),
        };
        let result = match source {
            Some(g) => g.invoke(action),
            None => action(),
        };
        if qualified && result.is_err() {
            self.fail();
        }
        result
    }
    pub(in crate::ath9k) async fn replace(&self, source: Arc<Grant>) -> Result<(), Error> {
        {
            let mut s = self.0.lock();
            if s.failed || s.closing || s.ani.is_some() {
                return Err(Error::Access);
            }
            s.closing = true;
        }
        struct Attempt<'a> {
            latch: &'a Latch,
            armed: bool,
        }
        impl Drop for Attempt<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.latch.fail();
                }
            }
        }
        let mut attempt = Attempt {
            latch: self,
            armed: true,
        };
        loop {
            let pending = { self.0.lock().flights != 0 };
            if !pending {
                break;
            }
            narf_scheduler::yield_now().await;
        }
        source.invoke(|| {
            let mut s = self.0.lock();
            if s.failed || !s.closing {
                return Err(Error::Access);
            }
            if let Some(old) = s.source.replace(source.clone()) {
                s.retained.push(old);
            }
            s.ready = false;
            s.closing = false;
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    pub(in crate::ath9k) fn program(
        &self,
        io: &mut impl RegisterIo,
        enabled: bool,
    ) -> Result<(), BringUpError> {
        self.current(false, || {
            self.program_inner(io, enabled).map_err(|_| Error::Access)
        })
        .map_err(|_| BringUpError::Policy)
    }
    fn program_inner(&self, io: &mut impl RegisterIo, enabled: bool) -> Result<(), BringUpError> {
        let (kind, inputs) = self
            .0
            .lock()
            .source
            .as_ref()
            .map(|g| (g.base.kind, g.base.inputs))
            .ok_or(BringUpError::Policy)?;
        match kind {
            Kind::Ar9485 => {
                // Source canonical 3WIRE disable, not absent-owner evidence.
                let mut bt = super::super::btcoex::Btcoex::new(super::super::Chip::Ar9485);
                super::super::btcoex::init_scheme(&mut bt, true, 0);
                super::super::btcoex::btcoex_disable(io, &mut bt)?;
                check_off(io)?;
                apply(io, inputs, enabled)?;
            }
            Kind::Ar9565 => {
                // The serialized real live MCI owner has already run stop
                // and cleanup. These are local off receipts, not DMA/RF idle.
                check_mci_off(io)?;
                apply_9565(io, inputs.raw, enabled)?;
            }
        }
        let expected = [
            if kind == Kind::Ar9485 {
                io.read32(0xa28c)
            } else {
                0
            },
            io.read32(0x9e28) & !super::OWNED,
            io.read32(0x9fc0) & 0x2000,
            if kind == Kind::Ar9565 {
                io.read32(0x9e24) & 0x0020_0000
            } else {
                0
            },
            if kind == Kind::Ar9565 {
                io.read32(0x1a64) & 0x8000
            } else {
                0
            },
        ];
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        self.0.lock().expected = Some(expected);
        Ok(())
    }
    pub(in crate::ath9k) fn readback(
        &self,
        mut read: impl FnMut(u64) -> Result<u32, Error>,
    ) -> Result<(), Error> {
        let kind = self
            .0
            .lock()
            .source
            .as_ref()
            .map(|g| g.base.kind)
            .ok_or(Error::State)?;
        match kind {
            Kind::Ar9485 => check_off_read(&mut read)?,
            Kind::Ar9565 => check_mci_off_read(&mut read)?,
        }
        let expected = self.0.lock().expected.ok_or(Error::State)?;
        if kind == Kind::Ar9485 && read(0xa28c)? != expected[0]
            || read(0x9e28)? & !super::OWNED != expected[1]
            || read(0x9fc0)? & 0x2000 != expected[2]
            || kind == Kind::Ar9565
                && (read(0x9e24)? & 0x0020_0000 != expected[3]
                    || read(0x1a64)? & 0x8000 != expected[4])
        {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "manual_tests.rs"]
mod tests;

/// Full source writes and immediate preserved-bit receipts. Every scalar is
/// supplied by a current original Native/PCI or lifecycle adapter.
fn write(io: &mut impl RegisterIo, r: u64, v: u32) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(r, v);
    if !io.authorized() || io.read32(r) != v {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
fn rmw(io: &mut impl RegisterIo, r: u64, clear: u32, set: u32) -> Result<(), BringUpError> {
    let old = io.read32(r);
    if matches!(old, u32::MAX | 0xdeadbeef) {
        return Err(BringUpError::DeviceGone);
    }
    write(io, r, (old & !clear) | set)
}
fn apply(io: &mut impl RegisterIo, p: Inputs, enabled: bool) -> Result<(), BringUpError> {
    rmw(
        io,
        0xa28c,
        0x00ff_ffff,
        if enabled { p.sharing } else { p.ordinary } & 0x00ff_ffff,
    )?;
    rmw(io, 0x9e28, 0x7e00_0000, u32::from(p.raw & 63) << 25)?;
    rmw(
        io,
        0x9e28,
        0x0100_0000,
        (u32::from((p.raw >> 6) & 1) | u32::from(enabled)) << 24,
    )?;
    rmw(
        io,
        0x9fc0,
        0x2000,
        (u32::from((p.raw >> 7) & 1) | u32::from(enabled)) << 13,
    )?;
    rmw(io, 0x9e28, 0x7e00_0000, (2 << 27) | (1 << 25))
}
fn apply_9565(io: &mut impl RegisterIo, raw: u8, enabled: bool) -> Result<(), BringUpError> {
    rmw(io, 0x9e28, 0x7e00_0000, u32::from(raw & 63) << 25)?;
    for (r, bit) in [
        (0x9e28, 0x0100_0000),
        (0x9e28, 0x0080_0000),
        (0x9fc0, 0x2000),
        (0x9e24, 0x0020_0000),
        (0x1a64, 0x8000),
    ] {
        rmw(io, r, bit, if enabled { bit } else { 0 })?;
    }
    if !enabled {
        rmw(io, 0x9e28, 0x7e00_0000, (2 << 27) | (1 << 25))?;
    }
    Ok(())
}
pub(in crate::ath9k) fn check_mci_off(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    check_mci_off_read(|r| {
        let v = io.read32(r);
        if io.authorized() {
            Ok(v)
        } else {
            Err(Error::Access)
        }
    })
    .map_err(|_| BringUpError::DeviceGone)
}
fn check_mci_off_read(mut read: impl FnMut(u64) -> Result<u32, Error>) -> Result<(), Error> {
    for (r, mask, want) in [
        (0x18ac, u32::MAX, 0),
        (0x182c, u32::MAX, 0),
        (0x183c, u32::MAX, 0),
        (0x1810, 4, 4),
    ] {
        let v = read(r)?;
        if matches!(v, u32::MAX | 0xdeadbeef) || v & mask != want {
            return Err(Error::Descriptor);
        }
    }
    Ok(())
}
pub(in crate::ath9k) fn check_off(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    check_off_read(|r| {
        let v = io.read32(r);
        if io.authorized() {
            Ok(v)
        } else {
            Err(Error::Access)
        }
    })
    .map_err(|_| BringUpError::DeviceGone)
}
pub(in crate::ath9k) fn check_off_read(
    mut read: impl FnMut(u64) -> Result<u32, Error>,
) -> Result<(), Error> {
    // GPIO5 driveALL/plain output, source 3WIRE mode DISABLED and weights.
    for (r, mask, want) in [
        (0x4050, 3 << 10, 3 << 10),
        (0x4068, 31 << 25, 0),
        (0x8170, u32::MAX, 0x1c00),
        (0x817c, u32::MAX, 0),
        (0x8174, u32::MAX, 0),
        (0x81c4, u32::MAX, 0),
        (0x83ac, u32::MAX, 0),
        (0x83b0, u32::MAX, 0),
        (0x83b4, u32::MAX, 0),
        (0x83b8, u32::MAX, 0),
    ] {
        let v = read(r)?;
        if matches!(v, u32::MAX | 0xdeadbeef) || v & mask != want {
            return Err(Error::Descriptor);
        }
    }
    Ok(())
}

/// The physical owner's lifecycle registers retain N48D even after the
/// station/DMA generation is retired. No old plain-source rebuild fallback.
pub(in crate::ath9k) struct Registers {
    raw: crate::ath9k::identity::Registers,
    latch: Arc<Latch>,
}
impl Registers {
    pub(in crate::ath9k) fn new(
        mmio: narf_bus::MmioRegion,
        cap: Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        latch: Arc<Latch>,
    ) -> Self {
        Self {
            raw: crate::ath9k::identity::Registers::new(mmio, cap),
            latch,
        }
    }
}
impl RegisterIo for Registers {
    fn authorized(&self) -> bool {
        self.latch
            .current(false, || {
                if self.raw.authorized() {
                    Ok(())
                } else {
                    Err(Error::Access)
                }
            })
            .is_ok()
    }
    fn read32(&mut self, r: u64) -> u32 {
        self.latch
            .current(false, || Ok(self.raw.read32(r)))
            .unwrap_or(u32::MAX)
    }
    fn write32(&mut self, r: u64, v: u32) {
        let _ = self.latch.current(false, || {
            self.raw.write32(r, v);
            Ok(())
        });
    }
}
impl crate::ath9k::calibration::Io for Registers {
    fn now_us(&self) -> u64 {
        crate::ath9k::calibration::Io::now_us(&self.raw)
    }
    async fn settle(&mut self, microseconds: u64) {
        // The original scheduler-backed wait has no register effect.
        // Every resumed calibration poll and subsequent scalar still
        // invokes the same joint latch through this adapter.
        crate::ath9k::calibration::Io::settle(&mut self.raw, microseconds).await;
    }
}
