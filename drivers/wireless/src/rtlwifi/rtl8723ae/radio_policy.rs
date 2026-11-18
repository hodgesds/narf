// SPDX-License-Identifier: GPL-2.0-or-later
//! NAQR1 exact-program companion and factory-capped native preparation plans.
//!
//! NAQR is a new NARF-local wire contract. Old NAPC v1/v2 remains unchanged
//! and grants no new physical-fuse/calibration meaning. This module has no
//! packet caller. Its native ColdBinding constructor
//! requires the exact original-box Bound from the registered capsule.
use super::{adapter, envelope, factory, phy::PgStore, tables, txpower, version};
use crate::rtlwifi::{channel_power, firmware_transport::Identity, prepare::Error};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::boxed::Box;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::RegulatoryDomain;

const LENGTH: usize = 256;
const RECIPE: &[u8] = b"NARF RTL8723AE NAQR1 retained native preparation only; Linux7.3-rc4 AE cold retained original LLT/MAC->selected8723fw->AE MAC PHY PG AGC RF-A UMC fixups; live Version and RF18=f401/MAC20/BB20/analog884.10; current named wiphy rfkill and sourceGPIO62inputbit1/PIN60bit1 with actual Version polarity before every RF-stage poll; actual IRQ3a8/3ac masked, MAC factory identity readback, ASPM disabled; exact source RF-main IQK1T trials/backups/matrix, no-candidate/zero-TX refuses, tracking no-op, LCK then byte1fa reread equality, PA RF15low4=5 if!bit0, reg16low4|80 delay10us low4|90 if!bit4; EFUSE read-only bank0 exact16-bitSYS gates; mapDWORD1+10000 ready plus50ussettle, PA BYTE1+1000, native100msrefusal, ready DATAff valid/loststatus refuses; currentPCI ACCESS0/readback receipt retained throughErr; raw power required areas noff/base<=63; AE RF6052 PG/UMC/u32 math, Normal not BT1/BT2 or scan turbo; independent per-rate measured index search within actual factory cap, CCK A11Mforced0, preserve source pathB/MCS8..15 effects without emission authority, tails from actual MCS7highbyte; independent complete TXAGC readbacks, calibrated power then source RF channel then bandwidth, final parked CR/IRQ/security and channel/BW readbacks; full actual transition/calibration conducted upper bound plus antenna across cold1/20 and target geometry/supply; no interpolation or monotonicity, no packet ACK CTS retry station PS coex watchdog grant; per-access current firmware+NAPC+NAQR+PCI invocation; original cold owner/version/history fixed; dropped ticket drains current stage only under live authority, any helper error/uncertain restore/reset-only quarantine with no assumed helper-local backups or stop/reclaim proof";

/// Draft original-handoff prerequisite: Native retains the original Box via
/// Bound and borrows its PG, while synthetic fixture history stays test-only.
/// This is preparation metadata, never a live-width/calibration-stop receipt.
#[derive(Debug)]
pub(super) struct ColdBinding {
    version: version::Version,
    warm: bool,
    ephy_retries: u16,
    chnlval: [u32; 2],
    /// Actual currently checked PCI VID/DID/subsystem VID/ID from the
    /// retained function, NOT the adapter EEPROM's separately bound IDs.
    pci: [u16; 4],
    pg: PgOwner,
}
#[derive(Debug)]
enum PgOwner {
    Native(super::cold_storage::Bound),
    #[cfg(any(test, feature = "kernel-test"))]
    Fixture(Box<PgStore>),
}
impl ColdBinding {
    pub(super) fn from_native(bound: super::cold_storage::Bound) -> Self {
        Self {
            version: bound.version(),
            warm: bound.warm(),
            ephy_retries: bound.ephy_retries(),
            chnlval: bound.chnlval(),
            pci: bound.pci(),
            pg: PgOwner::Native(bound),
        }
    }
    fn pg(&self) -> &PgStore {
        match &self.pg {
            PgOwner::Native(bound) => bound.pg(),
            #[cfg(any(test, feature = "kernel-test"))]
            PgOwner::Fixture(pg) => pg,
        }
    }
    fn digest(&self) -> [u8; 32] {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"AE original cold history v1");
        h.update(&self.version.raw().to_le_bytes());
        h.update(&[u8::from(self.warm)]);
        h.update(&self.ephy_retries.to_le_bytes());
        for field in self.pci {
            h.update(&field.to_le_bytes());
        }
        for channel in self.chnlval {
            h.update(&channel.to_le_bytes());
        }
        h.update(&[self.pg().pwrgroup_cnt]);
        for word in self.pg().origoffset.iter().flatten() {
            h.update(&word.to_le_bytes());
        }
        h.finalize()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    // Explicit inert fixture history, NEVER native observations. Release
    // code has no constructor and cannot assume warm=false/retry1/path-B0.
    fn fixture(inputs: &factory::Inputs, pg: PgStore) -> Self {
        Self {
            version: inputs.adapter().version,
            warm: false,
            ephy_retries: 1,
            chnlval: [0xf401, 0],
            pci: [0x10ec, 0x8723, inputs.adapter().svid, inputs.adapter().smid],
            pg: PgOwner::Fixture(Box::new(pg)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}

/// Fixed actual inputs/sources; caller cannot substitute a fresh borrowed
/// calibration or an arbitrary public Efuse/PgStore for native provenance.
#[derive(Clone)]
pub(super) struct Program {
    inputs: Arc<factory::Inputs>,
    base: Arc<envelope::Calibration>,
    firmware: Identity,
    cold: Arc<ColdBinding>,
    op: envelope::Operating,
}
impl Program {
    pub(super) fn bind(
        inputs: Arc<factory::Inputs>,
        base: Arc<envelope::Calibration>,
        firmware: Identity,
        cold: Arc<ColdBinding>,
        op: envelope::Operating,
    ) -> Result<Self, Error> {
        if base.board_identity() != crate::rtlwifi::radio::factory_identity(inputs.factory())
            || inputs.adapter().version != cold.version
            || cold.chnlval[0] != 0xf401
            || !(1..100).contains(&cold.ephy_retries)
            || cold.pci[..2] != [0x10ec, 0x8723]
            || op.center_mhz().is_none()
        {
            return Err(power(channel_power::Error::Identity));
        }
        Ok(Self {
            inputs,
            base,
            firmware,
            cold,
            op,
        })
    }
    fn geometry(&self) -> [u8; 6] {
        let (width, secondary, center) = match self.op.width {
            envelope::Width::W20 => (20, 0, self.op.channel),
            envelope::Width::W40Above => (40, self.op.channel + 4, self.op.channel + 2),
            envelope::Width::W40Below => (40, self.op.channel - 4, self.op.channel - 2),
        };
        [self.op.channel, width, secondary, center, 1, 0] // profile0: preparation only
    }
    fn facts(&self) -> [u8; 6] {
        let a = self.inputs.adapter();
        [
            u8::from(a.bt.coexistence),
            a.bt.kind,
            u8::from(a.bt.ant_num == adapter::AntNum::X1),
            a.bt.ant_isolation,
            a.bt.radio_shared,
            self.inputs.efuse().regulatory,
        ]
    }
    fn invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.firmware.invoke(|| self.base.with_current(operation))
    }
    pub(super) fn request(&self) -> Request {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF RTL8723AE NAQR1 exact preparation companion");
        h.update(&self.base.board_identity());
        h.update(&self.base.digest);
        h.update(&self.firmware.digest);
        h.update(&recipe_digest());
        h.update(&self.cold.digest());
        h.update(&self.geometry());
        h.update(&self.facts());
        for raw in self.inputs.observed() {
            h.update(&raw.to_le_bytes());
        }
        h.update(&[self.inputs.pa()]);
        let m = self.inputs.factory().mac;
        Request {
            name: format!(
                "rtlwifi/rtl8723ae-radio-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}.bin",
                m[0],
                m[1],
                m[2],
                m[3],
                m[4],
                m[5],
                self.op.channel,
                self.geometry()[2]
            ),
            binding: h.finalize(),
        }
    }
    pub(super) fn operating(&self) -> envelope::Operating {
        self.op
    }
}

fn recipe_digest() -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(RECIPE);
    for table in [
        &tables::MAC[..],
        &tables::PHY_REG_1T[..],
        &tables::PHY_REG_PG[..],
        &tables::AGCTAB_1T[..],
        &tables::RADIOA_1T[..],
    ] {
        h.update(&(table.len() as u32).to_le_bytes());
        for value in table {
            h.update(&value.to_le_bytes());
        }
    }
    h.finalize()
}
fn power(error: channel_power::Error) -> Error {
    Error::Power(error)
}

/// Source-selected bounded words plus measured indices. This is not a
/// station/packet grant and has no hardware programming method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PowerGrant {
    permission: envelope::Permission,
    plan: txpower::Plan,
    measurement: [u8; 32],
}
impl PowerGrant {
    pub(super) fn permission(&self) -> envelope::Permission {
        self.permission
    }
    pub(super) fn plan(&self) -> &txpower::Plan {
        &self.plan
    }
}

pub(super) struct QualifiedProgram {
    program: Program,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    qualified: i16,
    calibration_peak: i16,
    measurement: [u8; 32],
}
impl core::fmt::Debug for QualifiedProgram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8723aeQualifiedPreparation")
            .field("operating", &self.program.op)
            .field("pa_observed", &self.program.inputs.pa())
            .finish_non_exhaustive()
    }
}
impl QualifiedProgram {
    pub(super) fn base(&self) -> &Arc<envelope::Calibration> {
        &self.program.base
    }
    pub(super) fn inputs(&self) -> &Arc<factory::Inputs> {
        &self.program.inputs
    }
    pub(super) fn firmware(&self) -> Identity {
        self.program.firmware
    }
    pub(super) fn operating(&self) -> envelope::Operating {
        self.program.op
    }
    pub(super) fn measurement(&self) -> [u8; 32] {
        self.measurement
    }
    pub(super) fn antenna(&self) -> i16 {
        self.antenna
    }
    pub(super) fn source_plan(&self) -> Result<txpower::Plan, Error> {
        self.invoke(|| {
            txpower::Plan::for_channel(
                &self.program.inputs.efuse(),
                self.program.cold.pg(),
                self.program.geometry()[3],
                self.program.op.width != envelope::Width::W20,
                false,
                txpower::DynamicPower::Normal,
            )
        })
    }
    /// Bound recipe loader used by the retained native preparation supervisor.
    pub(super) fn registered(program: Program) -> Result<Self, Error> {
        program.invoke(|| Ok(()))?;
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or_else(|| power(channel_power::Error::Authority))?;
        let source = crate::firmware_asset::load(&authority, &program.request().name, LENGTH, true)
            .map_err(|e| power(channel_power::Error::Firmware(e)))?;
        Self::parse(program, &source.bytes, source.signer, source.cap)
    }
    pub(super) fn parse(
        program: Program,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(power(channel_power::Error::Unsigned));
        }
        let bad = || power(channel_power::Error::Format);
        let i = &program.inputs;
        let a = i.adapter();
        let polarity = u8::from(a.version.polarity() == version::Polarity::HighActive);
        if bytes.len() != LENGTH
            || &bytes[..4] != b"NAQR"
            || bytes[4..8] != [1, 0, 0, 1]
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != LENGTH as u32
            || bytes[12..16] != [0xec, 0x10, 0x23, 0x87]
            || bytes[16..48] != program.request().binding
            || bytes[48..80] != program.base.board_identity()
            || bytes[80..112] != program.base.digest
            || bytes[112..144] != program.firmware.digest
            || bytes[144..176] != recipe_digest()
            || bytes[176..182] != i.factory().mac
            || bytes[182..188] != program.geometry()
            || bytes[188..190] != a.version.raw().to_le_bytes()
            || bytes[190..194] != [polarity, i.pa(), 0, 1]
            || bytes[194..196] != program.cold.pci[2].to_le_bytes()
            || bytes[196..198] != program.cold.pci[3].to_le_bytes()
            || bytes[198..204] != program.facts()
            || bytes[210..] != [0; 46]
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(bytes[204..206].try_into().unwrap());
        let qualified = i16::from_le_bytes(bytes[206..208].try_into().unwrap());
        let calibration_peak = i16::from_le_bytes(bytes[208..210].try_into().unwrap());
        if !(program.base.antenna()..=128).contains(&antenna)
            || !(-512..=80).contains(&qualified)
            || !(-512..=256).contains(&calibration_peak)
        {
            return Err(bad());
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(bytes);
        Ok(Self {
            program,
            cap,
            antenna,
            qualified,
            calibration_peak,
            measurement: h.finalize(),
        })
    }
    /// The closure executes under EACH source, not after a prior Noop check.
    /// Future native IO must call this for every access AND resumed poll.
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
        self.program.invoke(|| {
            self.cap
                .invoke(Live(operation))
                .map_err(|_| power(channel_power::Error::Authority))?
        })
    }
    pub(super) fn grant_for(&self, domain: &RegulatoryDomain) -> Result<PowerGrant, Error> {
        self.invoke(|| {
            let ceiling = envelope::span_ceiling(domain, self.program.op)
                .map_err(power)?
                .min(
                    envelope::span_ceiling(domain, envelope::Operating::twenty(1))
                        .map_err(power)?,
                )
                .min(self.qualified)
                .min(self.program.base.qualified());
            if i32::from(self.calibration_peak) + i32::from(self.antenna) > i32::from(ceiling) {
                return Err(power(channel_power::Error::Policy));
            }
            let op = self.program.op;
            let wide = self.program.geometry()[3];
            let source = txpower::Plan::for_channel(
                &self.program.inputs.efuse(),
                self.program.cold.pg(),
                wide,
                op.width != envelope::Width::W20,
                false,
                txpower::DynamicPower::Normal,
            )?;
            let actual = source.indices()[0];
            let caps: [u8; 20] = actual[..20]
                .try_into()
                .map_err(|_| power(channel_power::Error::FactoryPower))?;
            let permission = self
                .program
                .base
                .factory_permission(domain, op, &caps, self.antenna, self.qualified)
                .map_err(power)?;
            let selected = core::array::from_fn(|r| permission.index(r as u8));
            let plan = source.bounded(selected)?;
            Ok(PowerGrant {
                permission,
                plan,
                measurement: self.measurement,
            })
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy_tests.rs"]
pub(super) mod tests;
