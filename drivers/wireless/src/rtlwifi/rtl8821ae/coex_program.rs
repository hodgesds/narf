// SPDX-License-Identifier: GPL-2.0-or-later
//! Optional, separately signed RTL8821A complete coexistence program.
//! N21C is a measured worst-case conducted peak over every admitted rate,
//! complete source algorithm state and transition at one exact programmed
//! 20 MHz operating point. A NAPC Normal curve is not that measurement.
//! No example record or measured value is supplied by this source.

use super::envelope::{Calibration, Permission, Width};
use crate::rtlwifi::{
    channel_power::Error as PowerError, efuse::Factory, firmware_transport::Identity,
    prepare::Error,
};
use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};

const LENGTH: usize = 256;
const RECIPE: &[u8] = b"NARF RTL8821AE N21C1 original linked DMA owner, MACID0, actual EFUSE C3 BIT0 antenna1/2 and MULTI_FUNC_CTRL18; actual shared 8821 byte H2C/EXT box first; source halbtc8821a1ant 20130816/41 and halbtc8821a2ant 20130618/5050 complete non-debug notifications, Ctx common exact; own 8821 RF1T1R pathA LSSI/HSSI, BT RF RPC via actual C2H BT_MP, no 8723 hardware recipe; actual single original RX ring, complete18byte C2H, arrival/deferred separated, ordinary RX bytes/PHY retained without PN consumption during MP wait; actual BT patch version/nonzero and build observed by GET_BT_VERSION before grant; all source antenna/RF LPF/AGC/BB/DAC/TXlimit/TDMA/LPS/static/transition emissions and every rate in exact permission measured together; 20MHz exact primary and immutable selected NAPC gain indices/swing, softwareCCMP, existing RA/HT20 admission only, no wider channel, no coex WoW or reset replay; partial/cancel is terminal, original history/backups/DMA retained";

/// Only the real C2H GET_BT_VERSION observation constructs this token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtIdentity {
    version: u16,
    build: u8,
}
impl BtIdentity {
    pub(in crate::rtlwifi) fn observed(version: u16, build: u8) -> Result<Self, Error> {
        if version == 0 {
            return Err(Error::State);
        }
        Ok(Self { version, build })
    }
}

/// Filename and binding retained from a prior actual native BT observation.
/// Historical provisioning metadata alone grants no current RF authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}

pub struct Program {
    poisoned: AtomicBool,
    base: Arc<Calibration>,
    firmware: Identity,
    source: Cap<FirmwareBlob, Read>,
    permission: Permission,
    antenna: i16,
    ceiling: i16,
    peak: i16,
    bt: BtIdentity,
    raw_c3: u8,
}
impl core::fmt::Debug for Program {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8821aeJointCoexProgram")
            .field("operating", &self.permission.operating())
            .finish_non_exhaustive()
    }
}

fn power(error: PowerError) -> Error {
    Error::Power(error)
}
pub(super) fn recipe_digest() -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(RECIPE);
    h.update(&super::coex_source::digest());
    // Exact primary Linux7.3-rc4 source C/H contents. The native composition
    // is versioned above; table/handler changes must revise this recipe.
    for source in [
        b"23c8404d08aa96913e722205362a5925fb2ba1d2d0812051365901782fda23d8".as_slice(),
        b"0626a9a0b0dbe8f38fa218c6076460695133615aa61d322583328d0245b3b1dd".as_slice(),
        b"ffbdd27e82137e67073afbdd2218d2f89de0c3628d24ec5701b94d0920611390".as_slice(),
        b"1fb4358c5c31931dcd7ce52473ae54e8c85477a043afd77329b196dd7b1433c7".as_slice(),
    ] {
        h.update(source);
    }
    h.finalize()
}
fn permission_digest(permission: Permission) -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    let op = permission.operating();
    h.update(&permission.identity());
    h.update(&[op.band as u8, op.channel, 20, 0]);
    h.update(&permission.admitted_rates().to_le_bytes());
    for rate in 0..48 {
        h.update(&[permission.index(rate)]);
    }
    h.update(&permission.swing().to_le_bytes());
    h.update(&permission.eirp_limit_qdbm().to_le_bytes());
    h.finalize()
}
pub(in crate::rtlwifi) fn request(
    base: &Calibration,
    firmware: Identity,
    factory: &Factory,
    p: Permission,
    bt: BtIdentity,
) -> Result<Request, Error> {
    if p.operating().width != Width::W20
        || p.identity() != crate::rtlwifi::radio::factory_identity(factory)
    {
        return Err(Error::State);
    }
    let raw = *factory.logical.get(0xc3).ok_or(Error::State)?;
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF N21C1 actual RTL8821AE full coexistence program");
    h.update(&p.identity());
    h.update(&base.digest());
    h.update(&firmware.digest);
    h.update(&recipe_digest());
    h.update(&permission_digest(p));
    h.update(&[raw, if raw & 1 != 0 { 1 } else { 2 }, bt.build]);
    h.update(&bt.version.to_le_bytes());
    let m = factory.mac;
    Ok(Request {
        name: format!(
            "rtlwifi/rtl8821ae-coex-v1-p{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            p.channel(),
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        ),
        binding: h.finalize(),
    })
}

impl Program {
    /// RAM-only framing fixture. These synthetic numbers are never a
    /// supplied measurement, trusted asset, or path to physical PCI.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture_record(
        base: &Calibration,
        firmware: Identity,
        factory: &Factory,
        permission: Permission,
        bt: BtIdentity,
    ) -> Result<[u8; LENGTH], Error> {
        let req = request(base, firmware, factory, permission, bt)?;
        let op = permission.operating();
        let raw = factory.logical[0xc3];
        let mut bytes = [0; LENGTH];
        bytes[..4].copy_from_slice(b"N21C");
        bytes[4..8].copy_from_slice(&[1, 0, 0, 1]);
        bytes[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0x88]);
        bytes[16..48].copy_from_slice(&req.binding);
        bytes[48..80].copy_from_slice(&permission.identity());
        bytes[80..112].copy_from_slice(&base.digest());
        bytes[112..144].copy_from_slice(&firmware.digest);
        bytes[144..176].copy_from_slice(&recipe_digest());
        bytes[176..208].copy_from_slice(&permission_digest(permission));
        bytes[208..214].copy_from_slice(&factory.mac);
        bytes[214..220].copy_from_slice(&[
            raw,
            if raw & 1 != 0 { 1 } else { 2 },
            op.band as u8,
            op.channel,
            20,
            0,
        ]);
        bytes[220..222].copy_from_slice(&bt.version.to_le_bytes());
        bytes[222..224].copy_from_slice(&[bt.build, 1]);
        bytes[224..226].copy_from_slice(&base.antenna_qdb().to_le_bytes());
        bytes[226..228].copy_from_slice(&base.qualified_qdbm().to_le_bytes());
        bytes[228..230].copy_from_slice(&12i16.to_le_bytes());
        Ok(bytes)
    }

    /// Exercise the unmodified parser and actual nested current-cap closure
    /// using inert data and separately bootstrapped test capabilities.
    #[cfg(any(test, feature = "kernel-test"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse_fixture(
        base: Arc<Calibration>,
        firmware: Identity,
        factory: &Factory,
        permission: Permission,
        bt: BtIdentity,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        source: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        Self::parse(
            base, firmware, factory, permission, bt, bytes, signer, source,
        )
    }

    pub(crate) fn check_bt_report(&self, packet: &[u8]) -> Result<(), Error> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(power(PowerError::Identity));
        }
        if let Ok(super::c2h::Event::BtMp(body)) = super::c2h::parse(packet) {
            if let Some((version, build)) = super::btc::version_report(body)? {
                if version != self.bt.version || build != self.bt.build {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(power(PowerError::Identity));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn base(&self) -> &Arc<Calibration> {
        &self.base
    }
    pub(crate) async fn wait<F: core::future::Future<Output = Result<(), Error>>>(
        &self,
        future: F,
    ) -> Result<(), Error> {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| match self.invoke(|| Ok(future.as_mut().poll(cx))) {
            Ok(poll) => poll,
            Err(error) => core::task::Poll::Ready(Err(error)),
        })
        .await
    }
    /// Native caller supplies the identity of its original retained CPU
    /// owner and the real C2H patch observation. Missing data grants nothing.
    pub(crate) fn registered(
        base: Arc<Calibration>,
        firmware: Identity,
        factory: &Factory,
        permission: Permission,
        bt: BtIdentity,
    ) -> Result<Option<Arc<Self>>, Error> {
        let req = request(&base, firmware, factory, permission, bt)?;
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(power(PowerError::Authority))?;
        let asset = match crate::firmware_asset::load(&loader, &req.name, LENGTH, true) {
            Ok(asset) => asset,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(error) => return Err(power(PowerError::Firmware(error))),
        };
        Self::parse(
            base,
            firmware,
            factory,
            permission,
            bt,
            &asset.bytes,
            asset.signer,
            asset.cap,
        )
        .map(|program| Some(Arc::new(program)))
    }
    // Keep observed device/program inputs separate from the record's bytes,
    // signer and source capability at this single format-validation boundary.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn parse(
        base: Arc<Calibration>,
        firmware: Identity,
        factory: &Factory,
        permission: Permission,
        bt: BtIdentity,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        source: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(power(PowerError::Unsigned));
        }
        let req = request(&base, firmware, factory, permission, bt)?;
        let op = permission.operating();
        let raw = factory.logical[0xc3];
        if bytes.len() != LENGTH
            || bytes[..4] != *b"N21C"
            || bytes[4..8] != [1, 0, 0, 1]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..16] != [0xec, 0x10, 0x21, 0x88]
            || bytes[16..48] != req.binding
            || bytes[48..80] != permission.identity()
            || bytes[80..112] != base.digest()
            || bytes[112..144] != firmware.digest
            || bytes[144..176] != recipe_digest()
            || bytes[176..208] != permission_digest(permission)
            || bytes[208..214] != factory.mac
            || bytes[214..220]
                != [
                    raw,
                    if raw & 1 != 0 { 1 } else { 2 },
                    op.band as u8,
                    op.channel,
                    20,
                    0,
                ]
            || bytes[220..222] != bt.version.to_le_bytes()
            || bytes[222..224] != [bt.build, 1]
            || bytes[230..] != [0; 26]
        {
            return Err(power(PowerError::Format));
        }
        let at = |n| i16::from_le_bytes(bytes[n..n + 2].try_into().unwrap());
        let (antenna, ceiling, peak) = (at(224), at(226), at(228));
        if !(base.antenna_qdb()..=128).contains(&antenna)
            || !(-512..=base.qualified_qdbm()).contains(&ceiling)
            || !(-512..=256).contains(&peak)
        {
            return Err(power(PowerError::Format));
        }
        let program = Self {
            poisoned: AtomicBool::new(false),
            base,
            firmware,
            source,
            permission,
            antenna,
            ceiling,
            peak,
            bt,
            raw_c3: raw,
        };
        program.invoke(|| Ok(()))?;
        Ok(program)
    }
    pub(crate) fn permission(&self) -> Permission {
        self.permission
    }
    pub(crate) fn wifi_version(&self) -> Result<(u16, u8), Error> {
        self.firmware.version.ok_or(Error::State)
    }
    pub(crate) fn matches(&self, bt: BtIdentity, raw: u8, permission: Permission) -> bool {
        self.bt == bt && self.raw_c3 == raw && self.permission == permission
    }
    /// All actual native MMIO, descriptor/payload access and async polls run
    /// inside the original NAPC, selected image and this separate asset cap.
    pub(crate) fn invoke<T>(
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
        self.base.with_current(|| {
            self.firmware.invoke(|| {
                self.source
                    .invoke(Live(|| {
                        if self.poisoned.load(Ordering::Acquire) {
                            return Err(power(PowerError::Identity));
                        }
                        let domain =
                            narf_wireless::reg::db::snapshot().ok_or(power(PowerError::Policy))?;
                        if self
                            .base
                            .permission_for(&domain, self.permission.operating())
                            .map_err(power)?
                            != self.permission
                        {
                            return Err(power(PowerError::Policy));
                        }
                        if i32::from(self.peak) + i32::from(self.antenna)
                            > i32::from(self.ceiling.min(self.permission.eirp_limit_qdbm()))
                        {
                            return Err(power(PowerError::NoMeasuredGain));
                        }
                        operation()
                    }))
                    .map_err(|_| power(PowerError::Authority))?
            })
        })
    }
}
