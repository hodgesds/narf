// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed awake channel1/20MHz CCK1, TX-A/RX-AB radio continuation.
//! Linux rtw8822c.c: TRX selection, channel, factory trim and RF calibration.
use super::chip_bridge::bridge;
use super::{
    band5::Width,
    efuse::Factory,
    firmware_transport::{Error, Io},
    power_policy,
};
use alloc::boxed::Box;
use narf_drivers_wireless_rtl_chip::radio::c22;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub channel: u8,
    pub gains: [u8; 2],
    pub adc_dc: [u32; 2],
    pub residual: [[u16; 2]; 2],
    pub cck_gi: [u8; 2],
}
pub(super) async fn prepare(
    io: &mut impl Io,
    factory: &Factory,
    mac: super::mac::Info,
    phy: super::phy::Info,
    gain: [u8; 2],
    gate: power_policy::Gate,
) -> Result<Info, Error> {
    trx(io).await?;
    channel(io).await?;
    gains(io, gain).await?;
    let dack = super::dack::calibrate(io).await?;
    x2(io).await?;
    trims(io, factory).await?;
    // Fixed CCK1 operation disables the source low-rate DPD path entirely.
    // Unlike wideband GAPK/DPK, DACK and IQK run on the retained channel only.
    for path in 0..2 {
        mask(io, 0x1b00, 6, path).await?;
        mask(io, 0x1b08, 1 << 31, 0).await?;
    }
    mask(io, 0xa70, 0x3ff, 0x3ff).await?;
    let cck_gi = [
        (((read(io, 0x1a98).await? >> 6) & 3) << 4 | ((read(io, 0x1a70).await? >> 24) & 15)) as u8,
        ((((read(io, 0x1a98).await? >> 14) & 3) << 4) | ((read(io, 0x1aa8).await? >> 16) & 15))
            as u8,
    ];
    receive_policy(io).await?;
    software_crypto(io).await?;
    awake(io).await?;
    io.begin_commands()?;
    super::command::send(io, &super::command::general(mac, 0)?).await?;
    super::command::send(io, &super::command::phydm(phy, 1)?).await?;
    // RPT_CIP has no source host reset operation. Refuse a stale done value
    // before submission instead of manufacturing an acknowledgement.
    let before = io.read8(0x2d9c).await?;
    if before == 255 {
        return Err(Error::Gone);
    }
    if before == 0xaa {
        return Err(Error::Prerequisite);
    }
    rfk_power(io, true).await?;
    super::command::send(io, &super::command::iqk(2)).await?;
    let mut complete = false;
    for attempt in 0..=15 {
        let value = io.read8(0x2d9c).await?;
        if value == 255 {
            return Err(Error::Gone);
        }
        if value == 0xaa {
            complete = true;
            break;
        }
        if attempt < 15 {
            io.delay_us(20000).await;
        }
    }
    if !complete {
        return Err(Error::Timeout);
    }
    io.write8(0x1b10, 0).await?;
    rfk_power(io, false).await?;
    // IQK must not silently reopen optional DPD or alter selected gains.
    for path in 0..2 {
        mask(io, 0x1b00, 6, path).await?;
        mask(io, 0x1b08, 1 << 31, 0).await?;
    }
    mask(io, 0xa70, 0x3ff, 0x3ff).await?;
    gains(io, gain).await?;
    verify(io, gain).await?;
    io.finish_radio(gate)?;
    Ok(Info {
        channel: 1,
        gains: gain,
        adc_dc: dack.adc,
        residual: dack.residual,
        cck_gi,
    })
}
pub(super) async fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
pub(super) async fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = read(io, reg).await?;
    io.write32(reg, old & !bits | value << bits.trailing_zeros())
        .await
}
pub(super) async fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
    let base = match path {
        0 => 0x3c00,
        1 => 0x4c00,
        _ => return Err(Error::Unsupported),
    };
    Ok(read(io, base + u16::from(address) * 4).await? & 0xfffff)
}
pub(super) async fn rf(
    io: &mut impl Io,
    path: u8,
    address: u8,
    bits: u32,
    value: u32,
) -> Result<(), Error> {
    if path > 1 || bits == 0 || bits & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    if address == 0 {
        let shifted = value
            .checked_shl(bits.trailing_zeros())
            .ok_or(Error::Unsupported)?;
        if shifted & !bits != 0 {
            return Err(Error::Unsupported);
        }
        let data = if bits == 0xfffff {
            value
        } else {
            rf_read(io, path, 0).await? & !bits | shifted
        };
        io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data)
            .await?;
        io.delay_us(13).await;
    } else {
        mask(
            io,
            (if path == 0 { 0x3c00 } else { 0x4c00 }) + u16::from(address) * 4,
            bits,
            value,
        )
        .await?;
        io.delay_us(1).await;
    }
    Ok(())
}
// ── channel / TRX programming: bridge `Io` -> `RegIo` and delegate to the
//    shared `radio::c22` core. The DACK/IQK, gain, trim and firmware-command
//    steps of the bring-up stay native (below) and call these over the bridge.
#[cfg(feature = "kernel-test")]
pub(super) use c22::rf18_8822c;

/// `rtw8822c_bb_reset`.
pub(super) async fn bb_reset(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::bb_reset(&mut b).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_toggle_igi`.
pub(super) async fn toggle_igi(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::toggle_igi(&mut b).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_config_trx_mode` TRX-path selection.
pub(super) async fn trx(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::trx(&mut b).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_set_channel` ch1/20.
pub(super) async fn channel(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::channel(&mut b).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_set_channel` for a 2.4GHz/20MHz primary.
pub(super) async fn channel_to(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::channel_to(&mut b, ch).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_set_channel(center, BW40, sc)` on 2.4GHz.
pub(super) async fn width40(io: &mut impl Io, center: u8, sc: u8) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::width40(&mut b, center, sc).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_set_channel` for a 5GHz/20MHz primary.
pub(super) async fn channel5_to(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::channel5_to(&mut b, ch).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822c_set_channel(center, BW40|BW80, sc)` on 5GHz.
pub(super) async fn wide5_to(io: &mut impl Io, center: u8, width: Width) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::wide5_to(&mut b, center, width).await;
    r.map_err(|e| b.err(e))
}
/// Readback of [`channel5_to`].
pub(super) async fn verify_channel5(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::verify_channel5(&mut b, ch).await;
    r.map_err(|e| b.err(e))
}
/// Readback of [`wide5_to`].
pub(super) async fn verify_wide5(io: &mut impl Io, center: u8, width: Width) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::verify_wide5(&mut b, center, width).await;
    r.map_err(|e| b.err(e))
}
/// Readback of [`width40`].
pub(super) async fn verify_width40(
    io: &mut impl Io,
    center: u8,
    sc: u8,
    gains: [u8; 2],
) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::verify_width40(&mut b, center, sc, gains).await;
    r.map_err(|e| b.err(e))
}

pub(super) async fn trims(io: &mut impl Io, factory: &Factory) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::trims(&mut b, factory.trims()).await;
    r.map_err(|e| b.err(e))
}
pub(super) async fn gains(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::gains(&mut b, gains).await;
    r.map_err(|e| b.err(e))
}
/// 5GHz counterpart of [`gains`] for one N2xO record
/// (`rtw8822c_set_write_tx_power_ref` + `rtw8822c_set_tx_power_diff`): CCK
/// references zero (`rtw_phy_set_tx_power_level_by_path` skips CCK on
/// 5GHz), per-path OFDM references, CCK differences zero, the two OFDM
/// difference words, and `RRSR_INIT_5G & phy_get_rrsr_mask(DESC_RATE6M)`
/// = 0x10 (OFDM6 response only).
pub(super) async fn ofdm5(io: &mut impl Io, ofdm: [u8; 2], diffs: [u32; 2]) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::ofdm5(&mut b, ofdm, diffs).await;
    r.map_err(|e| b.err(e))
}
pub(super) use c22::RRSR_OFDM6_5G;
/// Readback of [`ofdm5`].
pub(super) async fn verify_ofdm5(
    io: &mut impl Io,
    ofdm: [u8; 2],
    diffs: [u32; 2],
) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::verify_ofdm5(&mut b, ofdm, diffs).await;
    r.map_err(|e| b.err(e))
}
pub(super) async fn rfk_power(io: &mut impl Io, active: bool) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::rfk_power(&mut b, active).await;
    r.map_err(|e| b.err(e))
}
/// Recheck current board authority and policy before each hardware write.
/// Native passes the current authenticated database; model tests pass an
/// isolated policy closure. No default or country is inferred here.
pub(super) struct Checked<'a, I, F> {
    pub io: &'a mut I,
    pub calibration: &'a power_policy::Calibration,
    pub permission: power_policy::Permission,
    pub policy: F,
}
pub(super) async fn x2(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::x2(&mut b).await;
    r.map_err(|e| b.err(e))
}
pub(super) async fn software_crypto(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::software_crypto(&mut b).await;
    r.map_err(|e| b.err(e))
}
pub(super) async fn awake(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::awake(&mut b).await;
    r.map_err(|e| b.err(e))
}
impl<I, F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error>> Checked<'_, I, F> {
    fn check(&self) -> Result<(), Error> {
        self.calibration
            .validate(self.permission, &(self.policy)()?)
            .map_err(Error::Power)
    }
}
#[async_trait::async_trait]
// SAFETY: this adapter retains the original exclusive owner; it only narrows
// writes with current calibration/policy checks and never creates DMA authority.
unsafe impl<I: Io, F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync> Io
    for Checked<'_, I, F>
{
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read8(&mut self, r: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        async move { self.io.read8(r).await }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read16(&mut self, r: u16) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        async move { self.io.read16(r).await }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read32(&mut self, r: u16) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        async move { self.io.read32(r).await }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write8(
        &mut self,
        r: u16,
        v: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.check()?;
            self.io.write8(r, v).await
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write16(
        &mut self,
        r: u16,
        v: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.check()?;
            self.io.write16(r, v).await
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write32(
        &mut self,
        r: u16,
        v: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.check()?;
            self.io.write32(r, v).await
        }
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::State)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::State)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.check()?;
        self.io.begin_commands()
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn submit_h2c(
        &mut self,
        p: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.check()?;
            self.io.submit_h2c(p).await
        }
    }
    fn poll_h2c(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        self.io.poll_h2c()
    }
    fn finish_radio(&mut self, gate: power_policy::Gate) -> Result<(), Error> {
        self.check()?;
        self.io.finish_radio(gate)
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await
    }
}

pub(super) async fn receive_policy(io: &mut impl Io) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::receive_policy(&mut b).await;
    r.map_err(|e| b.err(e))
}

async fn verify(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = c22::verify(&mut b, gains).await;
    r.map_err(|e| b.err(e))
}
