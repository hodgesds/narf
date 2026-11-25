// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained AR9485/AR1111 and AR9565 legacy20 RX antenna program. The raw EEPROM
//! capability and exact PCI board flags are immutable factory facts. Manual
//! sharing needs the separate explicit N48D owner; baseline profiles keep it off.
//! `Binding` exposes no unchecked MMIO, borrowed RX status or fresh grant.
use super::{eeprom::field, power::Image, Chip};
#[cfg(feature = "module")]
use crate::ath9k::platform::compat::{narf_bus, narf_io, narf_lib};
use crate::ath9k::{
    admission::Grant,
    identity::BringUpError,
    packet::{Error, Port},
};
use alloc::sync::Arc;
use narf_bus::DeviceId;
use narf_lib::sync::IrqSafeSpinLock;
pub(in crate::ath9k) mod manual;
mod scanner;
use scanner::Scanner;

const CONTROL: u64 = 0x9e28;
const DEFAULT: u64 = 0x8058;
const OWNED: u32 = 0x7e00 | 0x7e00_0000;
/// Register-only continuation under the retained qualification's real
/// CapOp. Production IO is the existing Native Port, which still invokes
/// current PCI and physical checks at each access; this wrapper keeps the
/// actual read/write INSIDE the N48A/N65A invocation instead of checking then
/// returning before Native performs its access. No DMA or BME authority.
pub(in crate::ath9k) struct Qualified<'a, P> {
    io: &'a P,
    grant: &'a Grant,
}
impl<'a, P: Port> Qualified<'a, P> {
    pub(in crate::ath9k) fn new(io: &'a P, grant: &'a Grant) -> Self {
        Self { io, grant }
    }
    pub(in crate::ath9k) fn capture_default(&self) -> Result<u32, Error> {
        let saved = self.read(DEFAULT)?;
        if saved > 7 {
            return Err(Error::Descriptor);
        }
        Ok(saved)
    }
    pub(in crate::ath9k) fn prepare_mac(
        &self,
        identity: &super::eeprom::Identity,
        image: &[u8],
        own: [u8; 6],
        five_ghz: bool,
        saved: Option<u32>,
    ) -> Result<Option<super::mac::RfKill>, Error> {
        super::mac::prepare_with_antenna(self, identity, image, own, five_ghz, saved)
    }

    fn invoke<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.grant
            .invoke(|| action().map_err(|_| BringUpError::BadState))
            .map_err(|_| Error::Access)
    }
}
impl<P: Port> Port for Qualified<'_, P> {
    fn transmit_allowed(&self) -> Result<(), Error> {
        self.invoke(|| self.io.transmit_allowed())
    }
    fn access<T>(
        &self,
        active: bool,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.invoke(|| self.io.access(active, action))
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.invoke(|| self.io.read(reg))
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.invoke(|| self.io.write(reg, value))
    }
    fn allocate(&self, _: usize) -> Result<narf_io::DmaBuffer, Error> {
        Err(Error::Memory)
    }
    fn master(&self, _: bool) -> Result<(), Error> {
        Err(Error::State)
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
}

/// The generation reset has already retired its Native/DMA owner. Its
/// fixed capture is non-emitting and invokes the OLD retained record around
/// the actual PCI-backed Registers read, before replacing the grant or reset.
pub(in crate::ath9k) fn capture_parked_default(
    grant: &Grant,
    io: &mut impl crate::ath9k::identity::RegisterIo,
) -> Result<u32, BringUpError> {
    grant.invoke(|| {
        let saved = io.read32(DEFAULT);
        if saved > 7 {
            return Err(BringUpError::DeviceGone);
        }
        Ok(saved)
    })
}

/// Exact validated EDMA status, retained only alongside its admitted MPDU
/// within one receive call. Never queues a descriptor pointer or raw borrow.
#[derive(Clone, Copy, Debug)]
pub(in crate::ath9k) struct Observation {
    pub(super) ctl: [u8; 3],
    pub(super) antenna: u8,
    pub(super) more_aggr: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Config {
    main: u8,
    alt: u8,
    bias: u8,
    main_gain: bool,
    alt_gain: bool,
}
impl Config {
    fn read(word: u32) -> Self {
        Self {
            main: ((word >> 27) & 3) as u8,
            alt: ((word >> 25) & 3) as u8,
            bias: ((word >> 9) & 63) as u8,
            main_gain: word & (1 << 30) != 0,
            alt_gain: word & (1 << 29) != 0,
        }
    }
    fn word(self, before: u32) -> u32 {
        (before & !OWNED)
            | (u32::from(self.main) << 27)
            | (u32::from(self.alt) << 25)
            | (u32::from(self.bias) << 9)
            | (u32::from(self.main_gain) << 30)
            | (u32::from(self.alt_gain) << 29)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Profile {
    pci: [u16; 4],
    raw: u8,
    bt_capable: bool,
    low: u8,
    bias: u8,
}
impl Profile {
    pub(in crate::ath9k) fn for_device(id: &DeviceId, image: &Image) -> Option<Self> {
        if id.vendor != 0x168c
            || !matches!(
                Chip::for_device(id.device),
                Some(Chip::Ar9485 | Chip::Ar9565)
            )
        {
            return None;
        }
        let board = super::board::Config::for_pci(id);
        if id.device == 0x0036 {
            // Source EEP_ANT_DIV_CTL1 is fixed0xc9 on AR9565. Its generic
            // PCI row carries BT_ANT_DIV; exact WB335 exceptions suppress
            // combining, otherwise default tracking precedes the still-closed
            // manual BT-sharing scanner gate (recv.c:965..987).
            return Some(Self {
                pci: [id.vendor, id.device, id.subsystem_vendor, id.subsystem_id],
                raw: 0xc9,
                bt_capable: !board.suppress_9565_combining(),
                low: 0,
                bias: 0,
            });
        }
        let cus = board != super::board::Config::default();
        let bt_capable = id.device == 0x0032
            && (cus
                || matches!(
                    (id.subsystem_vendor, id.subsystem_id),
                    (0x168c, 0x3119 | 0x3122)
                        | (0x185f, 0x3119 | 0x3027)
                        | (
                            0x144d,
                            0x4105 | 0x4106 | 0x410d | 0x410e | 0x410f | 0xc706 | 0xc680 | 0xc708
                        )
                        | (0x17aa, 0x3218 | 0x3219)
                ));
        Some(Self {
            pci: [id.vendor, id.device, id.subsystem_vendor, id.subsystem_id],
            raw: image[field::EXT1 + field::EXT1_ANT_DIV_CONTROL],
            bt_capable,
            low: if cus { 20 } else { 0 },
            bias: if cus { 3 } else { 0 },
        })
    }
    fn capable(self) -> bool {
        self.raw >> 6 == 3 && (self.pci[1] != 0x0036 || self.bt_capable)
    }
    fn scan(self) -> bool {
        self.capable() && !self.bt_capable
    }
    pub(in crate::ath9k) fn manual_capable(self) -> bool {
        matches!(self.pci[1], 0x0032 | 0x0036) && self.bt_capable && self.capable()
    }
    fn scanner(self) -> Scanner {
        if self.pci[1] == 0x0036 {
            Scanner::new_9565()
        } else {
            Scanner::new(self.low, self.bias)
        }
    }
    fn base(self) -> Config {
        // The AR9485 core writes0x12ef0200; AR9565 writes0x126f0600.
        // Source board control and capability select the LNA/gain fields,
        // retaining bias1/bias3 respectively with manual BT still closed.
        Config {
            main: if self.capable() {
                2
            } else {
                (self.raw >> 2) & 3
            },
            alt: if self.capable() { 1 } else { self.raw & 3 },
            bias: if self.pci[1] == 0x0036 { 3 } else { 1 },
            main_gain: !self.capable() && self.raw & 32 != 0,
            alt_gain: !self.capable() && self.raw & 16 != 0,
        }
    }
    pub(in crate::ath9k) fn identity_bytes(self) -> [u8; 20] {
        let mut out = [0; 20];
        for (i, value) in self.pci.iter().enumerate() {
            out[i * 2..i * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        out[8..16].copy_from_slice(&[
            self.raw,
            u8::from(self.capable()),
            u8::from(self.bt_capable),
            u8::from(self.scan()),
            self.low,
            self.bias,
            if self.pci[1] == 0x0036 { 3 } else { 2 },
            0,
        ]); // Exact source group; manual request absent.
        out[16..20].copy_from_slice(&[if self.pci[1] == 0x0036 { 3 } else { 255 }, 247, 0, 1]); // switch -1/+3, scan -9, no established BT-off owner, recipe version
        out
    }
}
/// A new identity is required for the whole reachable receive program, not
/// an initial LNA state. N48A's single gain/power envelope must bound every
/// intermediate default/LNA/bias/gain-table state this recipe can publish.
pub(in crate::ath9k) const RECIPE: &[u8] = b"AR9485/AR1111 RX antenna v1; raw EEPROM[124]>>6==3; exact CUS+WB225 BT flags; manual BT closed without explicit requested/coex-off ownership; verified base ar9485_1_1 core0x9e28=0x12ef0200 plus EEPROM board fields, combining LNA1/LNA2 gain0 and bias1; legacy20 descriptor-admitted EDMA RSSI_ctl/antenna/moreaggr only; Linux antenna.c complete group2 signed-RSSI scanner, count95/100, 512/256 packets, >50ms, ratio30/20 or50/50, delta-1/-9, normal and three-stage quick scan, A+B/A-B, gain0 and source bias; three consecutive default mismatches; preserve scan/logical history across association/retune/reset/suspend; save actual AR_DEF_ANTENNA immediately before reset and restore(nonzero or1), not pre-suspend hardware continuity; capture and MAC-tail effects inside actual retained N48A CapOp plus Native/PCI access; checked arithmetic terminal refusal; current N48A CapOp around each PCI access, expected owned fields and full preserved-bit readback, commit-after-receipt; no HT/AMPDU profile promotion";

#[derive(Clone)]
pub(in crate::ath9k) struct Shared(Arc<IrqSafeSpinLock<State>>);
/// Source correction is explicit in N48A identity: the scan admission
/// delta is -9, while both final LNA-selection switch deltas are -1.
pub(in crate::ath9k) const SOURCE_DELTAS: &[u8] =
    b"AR9485 source delta correction v2: antenna.c809 gate -9;335/621 switch -1";
pub(in crate::ath9k) const AR9565_RECIPE: &[u8] = b"AR9565 N65A retained default RX antenna v1: source EEP_ANT_DIV_CTL1 fixed0xc9; canonical pci.c generic0036 BT_ANT_DIV with13 exact WB3351ANT noDIV exceptions; default capability true only outside those exceptions; original1p0/1p1 MC_GAIN_CTRL0x126f0600 bias3, source no-manual-BT board order clears LNADIV+RX_PROTECT and WL_LNADIV_FORCE_ON, keeps fixed fastdiv; plain legacy20 admitted native EDMA observations may change DEF_ANTENNA only after3 consecutive mismatches, source scanner remains closed because every combining-capable0036 has BT_ANT_DIV and no explicit manual request/coex-off owner exists; retained current N65A+Native+PCI per effect, expected config/default and preserved-bit readback, fail/pin uncertainty, old generation retired before reset, save actual default and restore(nonzero or1), no source group2 scanner alias/HT/AMPDU/BT sharing promotion";
#[derive(Clone, Copy)]
struct State {
    profile: Profile,
    scanner: Scanner,
    logical: u8,
    other: u8,
    generation: u64,
    active: bool,
    failed: bool,
    installed: Option<(Config, u32)>,
    manual: bool,
}
#[derive(Clone)]
pub(in crate::ath9k) struct Binding {
    shared: Shared,
    generation: u64,
    grant: Arc<Grant>,
}
impl Shared {
    pub(in crate::ath9k) fn new(profile: Profile) -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(State {
            profile,
            scanner: profile.scanner(),
            logical: 0,
            other: 0,
            generation: 0,
            active: false,
            failed: false,
            installed: None,
            manual: false,
        })))
    }
    /// Same physical state, fresh independently qualified hardware generation.
    /// No await/callback occurs under this short lock. Packet pause has already
    /// closed observations and discarded old DMA heads before reset.
    pub(in crate::ath9k) fn bind(
        &self,
        port: &impl Port,
        grant: Arc<Grant>,
        profile: Profile,
    ) -> Result<Binding, Error> {
        let mut state = self.0.lock();
        if state.active || state.profile != profile {
            return Err(Error::State);
        }
        let generation = state.generation.checked_add(1).ok_or(Error::State)?;
        let binding = Binding {
            shared: self.clone(),
            generation,
            grant,
        };
        // Reserve before the first new-generation read. Even a refused
        // rebind must never let a copied older binding adopt reset hardware.
        state.generation = generation;
        state.failed = true;
        state.installed = None;
        let config = Config::read(binding.read(port, CONTROL)?);
        let default = binding.read(port, DEFAULT)?;
        if config != profile.base() || default > 7 || default == 0 {
            return Err(Error::Descriptor);
        }
        state.generation = generation;
        state.active = false;
        state.failed = false;
        state.installed = Some((config, default));
        Ok(binding)
    }
}
impl Binding {
    pub(in crate::ath9k) fn check_manual_start(&self, port: &impl Port) -> Result<(), Error> {
        let mut state = self.shared.0.lock();
        if state.generation != self.generation || state.active || state.failed {
            return Err(Error::State);
        }
        let expected = state.installed.ok_or(Error::State)?;
        let result = (|| {
            if Config::read(self.read(port, CONTROL)?) != expected.0
                || self.read(port, DEFAULT)? != expected.1
            {
                return Err(Error::Descriptor);
            }
            Ok(())
        })();
        if result.is_err() {
            state.failed = true;
        }
        result
    }
    /// Only the serialized physical owner calls this after the source
    /// manual program and full register receipts, with EDMA paused.
    pub(in crate::ath9k) fn rebase_manual(
        &self,
        port: &impl Port,
        enabled: bool,
    ) -> Result<(), Error> {
        let mut state = self.shared.0.lock();
        if state.generation != self.generation || state.active || !state.profile.manual_capable() {
            return Err(Error::State);
        }
        let config = Config::read(self.read(port, CONTROL)?);
        let default = self.read(port, DEFAULT)?;
        let mut expected = state.profile.base();
        expected.bias = state.installed.ok_or(Error::State)?.0.bias;
        if config != expected || default == 0 || default > 7 {
            state.failed = true;
            return Err(Error::Descriptor);
        }
        state.installed = Some((config, default));
        state.scanner = state.profile.scanner();
        state.manual = enabled;
        Ok(())
    }
    fn qualified<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.grant
            .invoke(|| action().map_err(|_| BringUpError::BadState))
            .map_err(|_| Error::Access)
    }
    fn read(&self, port: &impl Port, register: u64) -> Result<u32, Error> {
        self.qualified(|| port.read(register))
    }
    fn write(&self, port: &impl Port, register: u64, value: u32) -> Result<(), Error> {
        self.qualified(|| port.write(register, value))
    }
    pub(in crate::ath9k) fn pause(&self) {
        let mut state = self.shared.0.lock();
        if state.generation == self.generation {
            state.active = false;
        }
    }
    pub(in crate::ath9k) fn resume(&self, port: &impl Port) -> Result<(), Error> {
        let mut state = self.shared.0.lock();
        if state.generation != self.generation || state.failed {
            return Err(Error::State);
        }
        let (config, default) = state.installed.ok_or(Error::State)?;
        let current = (|| {
            if Config::read(self.read(port, CONTROL)?) != config
                || self.read(port, DEFAULT)? != default
            {
                return Err(Error::Descriptor);
            }
            Ok(())
        })();
        if let Err(error) = current {
            state.failed = true;
            state.active = false;
            return Err(error);
        }
        state.active = true;
        Ok(())
    }
    pub(in crate::ath9k) fn observe(
        &self,
        port: &impl Port,
        observation: Observation,
    ) -> Result<(), Error> {
        let mut state = self.shared.0.lock();
        if state.generation != self.generation || state.failed || !state.active {
            return Err(Error::State);
        }
        if !state.profile.capable() {
            return Ok(());
        }
        let mut next = *state;
        let (mut config, mut default) = next.installed.ok_or(Error::State)?;
        let mut antenna = None;
        if observation.antenna != next.logical {
            next.other = next.other.checked_add(1).ok_or(Error::Descriptor)?;
            if next.other >= 3 {
                antenna = Some(u32::from(observation.antenna & 7));
                next.logical = observation.antenna & 7;
                next.other = 0;
            }
        } else {
            next.other = 0;
        }
        let selected = if next.profile.scan() || next.manual {
            match next
                .scanner
                .observe(config, observation, port.now_us() / 1000)
            {
                Ok(selected) => selected,
                Err(error) => {
                    state.failed = true;
                    state.active = false;
                    return Err(error);
                }
            }
        } else {
            None
        };
        // Verify old expected fields before any new write. The first write
        // makes an error ambiguous: close this owner until signed reset.
        let result = (|| {
            let control = self.read(port, CONTROL)?;
            if Config::read(control) != config || self.read(port, DEFAULT)? != default {
                return Err(Error::Descriptor);
            }
            if let Some(value) = antenna {
                self.write(port, DEFAULT, value)?;
                if self.read(port, DEFAULT)? != value {
                    return Err(Error::Descriptor);
                }
                default = value;
            }
            if let Some(value) = selected {
                let word = value.word(control);
                self.write(port, CONTROL, word)?;
                if self.read(port, CONTROL)? != word {
                    return Err(Error::Descriptor);
                }
                config = value;
            }
            Ok(())
        })();
        if let Err(error) = result {
            state.failed = true;
            state.active = false;
            return Err(error);
        }
        next.installed = Some((config, default));
        *state = next;
        Ok(())
    }
}
#[cfg(feature = "kernel-test")]
#[path = "antenna/tests.rs"]
pub(in crate::ath9k) mod tests;
