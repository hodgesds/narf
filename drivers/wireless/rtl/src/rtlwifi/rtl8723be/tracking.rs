// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2012 Realtek Corporation.
//! Separately signed RTL8723BE BBSWING/LCK/IQK continuation (NBTH1).
//! Exact signed measurements authorize every physical program state; table
//! indices never imply conducted power. Ordinary NAPC and EE NETH remain distinct.
use super::{
    envelope::{Calibration, Operating, Permission},
    init::Radio,
    iqk,
};
use crate::platform::capabilities::{Cap, CapError, CapOp, Read};
use crate::platform::firmware::{FirmwareBlob, FirmwareError};
use crate::rtlwifi::{
    channel_power,
    firmware_transport::{Identity, Io},
    prepare::Error,
};
use alloc::{format, string::String, sync::Arc};
use narf_wireless::reg::RegulatoryDomain;
pub(crate) mod source;
mod tables;
pub(crate) type BaseCalibration = Calibration;
const HEADER: usize = 320;
const CELLS: usize = 4 * 34 + 16 * 44;
const LENGTH: usize = HEADER + 64 * CELLS * 2;
const UNKNOWN: i16 = i16::MAX;
const RECIPE:&[u8]=b"NARF RTL8723BE NBTH1: Linux7.3-rc4 dm.c01dfabc7f1e37f898c366487bf73d35af1023dcb45904e8abbed0ef5e56b1c9b phy.c17d4e7e97901ad0d301ed76c4416ece9792e100dbe6d9051d1d32e76249d9147; RF-A42 trigger17:16=3/read15:10 on alternating2000ms watchdogs, nonzero average4, original nonerased factory thermal1..63, BE thirty-entry asymmetric up/down deltas, source signed8/unsigned8 copied-before-clamp history, default CCK20/OFDM30, physical CCK0..32/OFDM0..42, actual CCKa22..a29 plus c80/c94top4/c4c24 IQK matrix, LCK then BBSWING then unconditional-ant-count IQK at averaged drift>=8, retained original IQK backups and live subsequent matrix, no EE RF calibration or TXAGC tracking alias; serialized idle SCH_TX_CMD pauseff CR-TX/RX0; bind original Radio RF18 and require actual equality before calibration, restore that actual admitted RF18 after source LCK/IQK before MAC opens, retain distinct original IQK backups and exact original BB program until full rebuild, exact source helpers under all retained current caps and current PCI each access/poll, terminal on cancellation/partial effect, no callback-local rollback; every one of64 raw thermal states x20 rates x33CCK/43OFDM literal indices plus original/calibration column has measured conducted upper bound over ALL other swing selections, valid ten-bit IQK coefficient outcomes, LCK/IQK emission/retry/failure/intermediate states, actual S0/S1/static antenna/BT-coex/supply, all original firmware rates/retry/response/protection/SGI20/HT20/40/wide+narrow fallback/BA programs; unknown ANY temperature/state refuses before trigger; no inference/interpolation from indices; joint original factory/radio/NAPC/firmware/Permission identity; physical measurements external";
fn bad() -> Error {
    Error::Power(channel_power::Error::Format)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(bytes);
    h.finalize()
}
/// Actual retained BB baseline, not a synthetic table-index estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(super) cck: [u8; 8],
    pub(super) iqk: [u32; 9],
}
impl Snapshot {
    pub(crate) fn read(io: &impl Io) -> Result<Self, Error> {
        let mut out = Self {
            cck: [0; 8],
            iqk: [0; 9],
        };
        for (i, b) in out.cck.iter_mut().enumerate() {
            *b = io.read8(0xa22 + i as u16)?;
        }
        for (r, b) in iqk::RESULT_REGS.into_iter().zip(&mut out.iqk) {
            *b = io.read32(r)?;
        }
        Ok(out)
    }
    pub(crate) fn restore(self, io: &impl Io) -> Result<(), Error> {
        for (i, b) in self.cck.iter().enumerate() {
            io.write8(0xa22 + i as u16, *b)?;
        }
        iqk::recover(io, &self.iqk)?;
        if Self::read(io)? != self {
            return Err(Error::Readback);
        }
        Ok(())
    }
    /// Only thermal-owned IQK fields: ATC/coex retain unrelated bits.
    pub(crate) fn check(self, io: &impl Io) -> Result<(), Error> {
        for (i, b) in self.cck.iter().enumerate() {
            if io.read8(0xa22 + i as u16)? != *b {
                return Err(Error::Readback);
            }
        }
        if io.read32(0xc80)? != self.iqk[4]
            || io.read32(0xc94)? & 0xf0000000 != self.iqk[6] & 0xf0000000
            || io.read32(0xc4c)? & (1 << 24) != self.iqk[2] & (1 << 24)
        {
            return Err(Error::Readback);
        }
        Ok(())
    }
}
/// Native owner captures these original facts before installing a continuation.
/// Private fields prevent caller-supplied thermal/IQK booleans from admitting RF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    factory: [u8; 32],
    mac: [u8; 6],
    radio: [u8; 32],
    permission: Permission,
    original: Snapshot,
    original_iqk: Option<iqk::Report>,
    expected_rf: u32,
    matrix: [u32; 8],
    thermal: u8,
}
impl Facts {
    pub(crate) fn capture(
        identity: [u8; 32],
        radio: &Radio,
        permission: Permission,
        io: &impl Io,
    ) -> Result<Self, Error> {
        let a = &radio.adapter;
        if identity != permission.identity()
            || radio.chnlval[0] & 0x3ff
                != u32::from(permission.operating().grant_channel().ok_or(Error::State)?)
            || radio.chnlval[0] & (1 << 10) == 0
            || (radio.chnlval[0] & (1 << 11) == 0) != permission.operating().forty()
            || a.thermal_ignore
            || !(1..=63).contains(&a.thermal_meter)
        {
            return Err(Error::State);
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(&identity);
        h.update(&a.version.raw().to_le_bytes());
        for v in [a.vid, a.did, a.svid, a.smid, a.eeprom_version] {
            h.update(&v.to_le_bytes());
        }
        h.update(&[
            a.eeprom_channel_plan,
            a.customer_id,
            a.crystal_cap,
            a.thermal_meter,
            u8::from(a.thermal_ignore),
            a.regulatory,
            u8::from(a.bt_coexist),
            a.ant_num as u8,
            a.single_ant_path as u8,
            a.board_type,
            a.package_type,
            a.oem as u8,
            u8::from(radio.cck_high_power),
        ]);
        for v in radio.chnlval {
            h.update(&v.to_le_bytes());
        }
        h.update(&radio.efuse.cck_base);
        h.update(&radio.efuse.bw40_base);
        h.update(&[
            radio.efuse.ht20_diff,
            radio.efuse.ht40_diff,
            radio.efuse.legacy_ht_diff,
        ]);
        for value in radio.by_rate.offset.iter().flatten() {
            h.update(&value.to_le_bytes());
        }
        // Bind the actual configured by-rate store and IQK outcome too.
        h.update(&[u8::from(radio.iqk.is_some())]);
        if let Some(q) = radio.iqk {
            h.update(&[q.final_candidate]);
            for v in q.result.iter().flatten() {
                h.update(&v.to_le_bytes());
            }
            for v in [q.reg_e94, q.reg_e9c, q.reg_eb4, q.reg_ebc] {
                h.update(&v.to_le_bytes());
            }
            for v in q.saved {
                h.update(&v.to_le_bytes());
            }
        }
        let out = Self {
            factory: identity,
            mac: a.mac,
            radio: h.finalize(),
            permission,
            original: Snapshot::read(io)?,
            original_iqk: radio.iqk,
            expected_rf: radio.chnlval[0],
            matrix: radio.iqk.and_then(|q| q.matrix).unwrap_or([0; 8]),
            thermal: a.thermal_meter,
        };
        out.check_txagc(io)?;
        Ok(out)
    }
    pub(crate) fn permission(self) -> Permission {
        self.permission
    }
    pub(crate) fn original(self) -> Snapshot {
        self.original
    }
    pub(crate) fn expected_rf(self) -> u32 {
        self.expected_rf
    }
    pub(crate) fn original_iqk(self) -> Option<[u32; 9]> {
        self.original_iqk.map(|q| q.saved)
    }
    pub(crate) fn original_report(self) -> Option<iqk::Report> {
        self.original_iqk
    }
    pub(crate) fn matrix(self) -> [u32; 8] {
        self.matrix
    }
    pub(crate) fn thermal(self) -> u8 {
        self.thermal
    }
    pub(crate) fn check_txagc(self, io: &impl Io) -> Result<(), Error> {
        let mut actual = [0u8; 20];
        actual[0] = ((io.read32(0xe08)? >> 8) & 255) as u8;
        let c = io.read32(0x86c)?.to_le_bytes();
        actual[1..4].copy_from_slice(&c[1..4]);
        for (i, r) in [0xe00, 0xe04, 0xe10, 0xe14].into_iter().enumerate() {
            actual[4 + i * 4..8 + i * 4].copy_from_slice(&io.read32(r)?.to_le_bytes());
        }
        if (0..20).any(|i| actual[i] != self.permission.index(i as u8)) {
            return Err(Error::Readback);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
fn op_bytes(p: Permission) -> [u8; 8] {
    let o = p.operating();
    [
        o.channel,
        if o.forty() { 40 } else { 20 },
        o.grant_prime_sc(),
        o.grant_channel().unwrap_or(0),
        64,
        4,
        33,
        43,
    ]
}
pub(crate) fn request(base: &Calibration, firmware: Identity, facts: Facts) -> Request {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(RECIPE);
    h.update(&base.measurement_digest());
    h.update(&firmware.digest);
    h.update(&facts.factory);
    h.update(&facts.radio);
    h.update(&op_bytes(facts.permission));
    for r in 0..20 {
        h.update(&[facts.permission.index(r)]);
    }
    h.update(&facts.permission.eirp_limit_qdbm().to_le_bytes());
    h.update(&[facts.thermal]);
    h.update(&facts.original.cck);
    for v in facts.original.iqk.into_iter().chain(facts.matrix) {
        h.update(&v.to_le_bytes());
    }
    Request {
        name: format!(
            "rtlwifi/rtl8723be-thermal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-w{}-s{}.bin",
            facts.mac[0],
            facts.mac[1],
            facts.mac[2],
            facts.mac[3],
            facts.mac[4],
            facts.mac[5],
            facts.permission.channel(),
            op_bytes(facts.permission)[1],
            op_bytes(facts.permission)[2]
        ),
        binding: h.finalize(),
    }
}
/// Whole-program authority, retaining each original source. No public minting
/// from a normal NAPC or a source-free metadata fixture.
pub(crate) struct Grant {
    base: Arc<Calibration>,
    firmware: Identity,
    cap: Cap<FirmwareBlob, Read>,
    facts: Facts,
    antenna: i16,
    ceiling: i16,
    measurement: [u8; 32],
    worst: [i16; 20],
}
impl Grant {
    pub(crate) fn base(&self) -> &Arc<Calibration> {
        &self.base
    }
    pub(crate) fn facts(&self) -> Facts {
        self.facts
    }
    pub(crate) fn measurement_digest(&self) -> [u8; 32] {
        self.measurement
    }
    pub(crate) fn registered(
        base: Arc<Calibration>,
        firmware: Identity,
        facts: Facts,
    ) -> Result<Option<Arc<Self>>, Error> {
        let loader = crate::platform::firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(channel_power::Error::Authority))?;
        let asset = match crate::firmware_asset::load(
            &loader,
            &request(&base, firmware, facts).name,
            LENGTH,
            true,
        ) {
            Ok(s) => s,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Power(channel_power::Error::Firmware(e))),
        };
        Self::parse(base, firmware, facts, &asset.bytes, asset.signer, asset.cap)
            .map(|q| Some(Arc::new(q)))
    }
    pub(crate) fn parse(
        base: Arc<Calibration>,
        firmware: Identity,
        facts: Facts,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Power(channel_power::Error::Unsigned));
        }
        if b.len() != LENGTH
            || b[..4] != *b"NBTH"
            || b[4..8] != [1, 0, 64, 1]
            || b[8..12] != (LENGTH as u32).to_le_bytes()
            || b[12..16] != [0xec, 0x10, 0x23, 0xb7]
            || b[16..48] != request(&base, firmware, facts).binding
            || b[48..80] != facts.factory
            || b[80..112] != base.measurement_digest()
            || b[112..144] != firmware.digest
            || b[144..176] != facts.radio
            || b[176..184] != op_bytes(facts.permission)
            || (0..20).any(|i| b[184 + i] != facts.permission.index(i as u8))
            || b[204..212] != facts.original.cck
            || (0..9).any(|i| b[212 + i * 4..216 + i * 4] != facts.original.iqk[i].to_le_bytes())
            || (0..8).any(|i| b[248 + i * 4..252 + i * 4] != facts.matrix[i].to_le_bytes())
            || b[284..292] != [facts.thermal, 64, 4, 16, 34, 44, 8, 4]
            || b[292..HEADER] != [0; 28]
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(b[280..282].try_into().unwrap());
        let ceiling = i16::from_le_bytes(b[282..284].try_into().unwrap());
        if !(base.antenna_qdbi()..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(bad());
        }
        let mut worst = [-512i16; 20];
        let mut at = HEADER;
        for _ in 0..64 {
            for (r, max) in worst.iter_mut().enumerate() {
                for _ in 0..if r < 4 { 34 } else { 44 } {
                    let value = i16::from_le_bytes(b[at..at + 2].try_into().unwrap());
                    at += 2;
                    if value != UNKNOWN && !(-512..=256).contains(&value) {
                        return Err(bad());
                    }
                    *max = (*max).max(value);
                }
            }
        }
        let out = Self {
            base,
            firmware,
            cap,
            facts,
            antenna,
            ceiling,
            measurement: hash(b),
            worst,
        };
        out.with_current(|| Ok(()))?;
        Ok(out)
    }
    /// Full64-temperature/physical-index coverage is required before the first
    /// thermal trigger, even if the current sample could select a lower index.
    pub(crate) fn permission_for(
        &self,
        domain: &RegulatoryDomain,
        op: Operating,
    ) -> Result<Permission, channel_power::Error> {
        self.with_current(|| Ok(()))
            .map_err(|_| channel_power::Error::Authority)?;
        let p = self.base.permission_for(domain, op)?;
        if p != self.facts.permission
            || self.worst.iter().any(|v| {
                *v == UNKNOWN
                    || i32::from(*v) + i32::from(self.antenna)
                        > i32::from(self.ceiling.min(p.eirp_limit_qdbm()))
            })
        {
            return Err(channel_power::Error::NoMeasuredGain);
        }
        Ok(p)
    }
    pub(crate) fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Invoke<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Invoke<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.cap
            .invoke(Invoke(|| {
                self.base.with_current(|| self.firmware.invoke(operation))
            }))
            .map_err(|_| Error::Power(channel_power::Error::Authority))?
    }
}
/// Retains both original calibration backups and actual later IQK output;
/// cancellation/partial effects close this state rather than rolling it back.
pub(crate) struct State {
    pub(crate) grant: Arc<Grant>,
    pub(crate) history: source::History,
    pub(crate) matrix: [u32; 8],
    pub(crate) expected: Snapshot,
    pub(crate) last: Option<u64>,
    pub(crate) uncertain: bool,
}
impl State {
    pub(crate) fn new(grant: Arc<Grant>) -> Self {
        let facts = grant.facts;
        Self {
            grant,
            history: source::History::default(),
            matrix: facts.matrix,
            expected: facts.original,
            last: None,
            uncertain: false,
        }
    }
    pub(crate) fn due(&self, now: u64) -> bool {
        self.last.is_none_or(|old| now.wrapping_sub(old) >= 2000)
    }
}

/// Synthetic qualification bytes for native models; never physical measurements.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn artifact(
    base: &Calibration,
    firmware: Identity,
    facts: Facts,
) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8;LENGTH];
    b[..4].copy_from_slice(b"NBTH");
    b[4..8].copy_from_slice(&[1, 0, 64, 1]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x23, 0xb7]);
    b[16..48].copy_from_slice(&request(base, firmware, facts).binding);
    b[48..80].copy_from_slice(&facts.factory);
    b[80..112].copy_from_slice(&base.measurement_digest());
    b[112..144].copy_from_slice(&firmware.digest);
    b[144..176].copy_from_slice(&facts.radio);
    b[176..184].copy_from_slice(&op_bytes(facts.permission));
    for r in 0..20 {
        b[184 + r] = facts.permission.index(r as u8);
    }
    b[204..212].copy_from_slice(&facts.original.cck);
    for (i, v) in facts.original.iqk.iter().enumerate() {
        b[212 + i * 4..216 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    for (i, v) in facts.matrix.iter().enumerate() {
        b[248 + i * 4..252 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    b[280..282].copy_from_slice(&base.antenna_qdbi().to_le_bytes());
    b[282..284].copy_from_slice(&facts.permission.eirp_limit_qdbm().to_le_bytes());
    b[284..292].copy_from_slice(&[facts.thermal, 64, 4, 16, 34, 44, 8, 4]);
    for cell in b[HEADER..].chunks_exact_mut(2) {
        cell.copy_from_slice(&(-40i16).to_le_bytes());
    }
    b
}
