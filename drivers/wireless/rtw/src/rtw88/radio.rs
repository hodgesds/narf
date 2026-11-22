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
    let t = factory.trims();
    // Preserve Linux's erased-cell semantics without substituting calibration
    // values. The signed board identity includes all original erased bytes.
    for (path, raw) in t[..2].iter().copied().enumerate() {
        if raw == 255 {
            break;
        }
        rf(
            io,
            path as u8,
            0x43,
            0xf0000,
            u32::from((raw >> 1) & 7 | (raw & 1) << 3),
        )
        .await?;
    }
    let mut gain = [[0u32; 8]; 2];
    let mut any = false;
    for (index, raw) in t[2..5].iter().copied().enumerate() {
        if raw != 255 {
            any = true;
            gain[0][index] = u32::from(raw & 15);
            gain[1][index] = u32::from(raw >> 4);
        }
    }
    for path in 0..2 {
        for index in 0..5 {
            let raw = t[5 + path * 5 + index];
            if raw != 255 {
                any = true;
                gain[path][index + 3] = u32::from(raw & 31);
            }
        }
    }
    if any {
        let indices = [0, 1, 2, 2, 3, 4, 5, 6, 7, 3, 4, 5, 6, 7, 7];
        for path in 0..2 {
            rf(io, path, 0xee, 1 << 19, 1).await?;
            for (sequence, index) in indices.iter().copied().enumerate() {
                rf(io, path, 0x33, 0xfffff, sequence as u32).await?;
                rf(io, path, 0x3f, 0xfffff, gain[usize::from(path)][index]).await?;
            }
            rf(io, path, 0xee, 1 << 19, 0).await?;
        }
    }
    mask(io, 0xa70, 0x3ff, 0x3ff).await?;
    for (path, raw) in t[15..17].iter().copied().enumerate() {
        if raw == 255 {
            return Ok(());
        }
        rf(io, path as u8, 0x60, 0xf000, u32::from(raw & 15)).await?;
    }
    for (path, raw) in t[17..19].iter().copied().enumerate() {
        // Linux does not skip erased5G PA bytes in this final loop.
        rf(io, path as u8, 0x60, 0xf0000, u32::from(raw & 15)).await?;
    }
    Ok(())
}
pub(super) async fn gains(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        mask(io, 0x1c90, 1 << 15, 0).await?;
        mask(
            io,
            if path == 0 { 0x18a0 } else { 0x41a0 },
            0x7f0000,
            u32::from(gain),
        )
        .await?;
    }
    for path in 0..2 {
        // No OFDM/HT/VHT descriptor is admitted by this profile. Zero their
        // reference, and use zero relative difference for the four CCK slots.
        mask(io, 0x1c90, 1 << 15, 0).await?;
        mask(io, if path == 0 { 0x18e8 } else { 0x41e8 }, 0x1fc00, 0).await?;
    }
    for reg in [0x3a00, 0x3a04, 0x3a08] {
        mask(io, 0x1c90, 1 << 15, 0).await?;
        io.write32(reg, 0).await?;
    }
    // Original phy_get_rrsr_mask(DESC_RATE1M) &RRSR_INIT_2G. This admits
    // mandatory CCK/OFDM control responses; their full RF envelope is measured
    // separately in N22Cv2. Host RX rejection cannot suppress hardware ACKs.
    io.write32(0x440, 0x1f).await
}
/// 5GHz counterpart of [`gains`] for one N2xO record
/// (`rtw8822c_set_write_tx_power_ref` + `rtw8822c_set_tx_power_diff`): CCK
/// references zero (`rtw_phy_set_tx_power_level_by_path` skips CCK on
/// 5GHz), per-path OFDM references, CCK differences zero, the two OFDM
/// difference words, and `RRSR_INIT_5G & phy_get_rrsr_mask(DESC_RATE6M)`
/// = 0x10 (OFDM6 response only).
pub(super) async fn ofdm5(io: &mut impl Io, ofdm: [u8; 2], diffs: [u32; 2]) -> Result<(), Error> {
    for path in 0..2 {
        mask(io, 0x1c90, 1 << 15, 0).await?;
        mask(io, if path == 0 { 0x18a0 } else { 0x41a0 }, 0x7f0000, 0).await?;
    }
    for (path, reference) in ofdm.into_iter().enumerate() {
        mask(io, 0x1c90, 1 << 15, 0).await?;
        mask(
            io,
            if path == 0 { 0x18e8 } else { 0x41e8 },
            0x1fc00,
            u32::from(reference),
        )
        .await?;
    }
    for (reg, value) in [(0x3a00, 0), (0x3a04, diffs[0]), (0x3a08, diffs[1])] {
        mask(io, 0x1c90, 1 << 15, 0).await?;
        io.write32(reg, value).await?;
    }
    io.write32(0x440, RRSR_OFDM6_5G).await
}
/// `RRSR_INIT_5G` (0x150) masked to the OFDM6 response order.
pub(super) const RRSR_OFDM6_5G: u32 = 0x150 & 0x1f;
/// Readback of [`ofdm5`].
pub(super) async fn verify_ofdm5(
    io: &mut impl Io,
    ofdm: [u8; 2],
    diffs: [u32; 2],
) -> Result<(), Error> {
    for (path, reference) in ofdm.into_iter().enumerate() {
        let (cck, ofdm) = if path == 0 {
            (0x18a0, 0x18e8)
        } else {
            (0x41a0, 0x41e8)
        };
        if read(io, cck).await? & 0x7f0000 != 0
            || read(io, ofdm).await? & 0x1fc00 != u32::from(reference) << 10
        {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x3a00).await? != 0
        || read(io, 0x3a04).await? != diffs[0]
        || read(io, 0x3a08).await? != diffs[1]
        || read(io, 0x440).await? != RRSR_OFDM6_5G
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
pub(super) async fn rfk_power(io: &mut impl Io, active: bool) -> Result<(), Error> {
    for path in 0..2 {
        mask(io, 0x1b00, 6, path).await?;
        mask(io, 0x1b08, 1 << 7, u32::from(active)).await?;
    }
    Ok(())
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
    io.delay_us(1000).await;
    if rf_read(io, 0, 0xb8).await? & (1 << 15) != 0 {
        for (reg, value) in [(0xb8, 0xc4440), (0xba, 0x6840d), (0xb8, 0x80440)] {
            rf(io, 0, reg, 0xfffff, value).await?;
        }
        io.delay_us(1000).await;
        if rf_read(io, 0, 0xb8).await? & (1 << 15) != 0 {
            return Err(Error::Prerequisite);
        }
    }
    Ok(())
}
pub(super) async fn software_crypto(io: &mut impl Io) -> Result<(), Error> {
    // Invalidate each original32-entry CAM slot, then demand the actual
    // command engine finish. No cached valid/default key can decrypt RX.
    for index in 0..32 {
        let mut done = false;
        for _ in 0..1000 {
            if read(io, 0x670).await? & (1 << 31) == 0 {
                done = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !done {
            return Err(Error::Timeout);
        }
        io.write32(0x674, 0).await?;
        io.write32(0x670, 1 << 31 | 1 << 16 | index << 3).await?;
    }
    let mut done = false;
    for _ in 0..1000 {
        if read(io, 0x670).await? & (1 << 31) == 0 {
            done = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !done {
        return Err(Error::Timeout);
    }
    let cr = io.read16(0x100).await?;
    if cr == u16::MAX {
        return Err(Error::Gone);
    }
    io.write16(0x100, cr & !(1 << 9)).await?;
    let security = io.read16(0x680).await?;
    if security == u16::MAX {
        return Err(Error::Gone);
    }
    io.write16(0x680, security & !0xcf).await?;
    // Native MPDU with PHY status+FCS; no TCP offload/header conversion,
    // ICV/MIC stripping or BSSID filtering before host association admission.
    let rcr = read(io, 0x608).await?;
    let clear = (1 << 30)
        | (1 << 29)
        | (1 << 25)
        | (1 << 24)
        | (1 << 18)
        | (1 << 15)
        | (1 << 12)
        | (1 << 9)
        | (1 << 8)
        | (1 << 7)
        | (1 << 6);
    io.write32(0x608, (rcr & !clear) | 1 << 31 | 1 << 28 | 1 << 10 | 15)
        .await?;
    if io.read16(0x680).await? & 0xcf != 0 || io.read16(0x100).await? & (1 << 9) != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
pub(super) async fn awake(io: &mut impl Io) -> Result<(), Error> {
    let request = io.read8(0x3d9).await?;
    let confirm = io.read8(0x3da).await?;
    if request == 255 || confirm == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x3d9, (!request & 0x80) | 0x40).await?;
    for _ in 0..150 {
        io.delay_us(100).await;
        let value = io.read8(0x3da).await?;
        if value == 255 {
            return Err(Error::Gone);
        }
        if (value ^ confirm) & 0x80 != 0 {
            return Ok(());
        }
    }
    Err(Error::Timeout)
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
    // Source phy_init starts EDCCA at a disabled sentinel and its watchdog
    // later programs a real threshold. Keep the source maximum-coverage IGI
    // and the stricter adaptive40/33 threshold at that IGI; no disabled
    // sentinel or missing watchdog may leave unbounded energy detection.
    mask(io, 0x1d70, 0x7f, 0x1c).await?;
    mask(io, 0x1d70, 0x7f00, 0x1c).await?;
    mask(io, 0x84c, 0x00ff0000, 40 + 0x80).await?;
    mask(io, 0x84c, 0xff000000, 33 + 0x80).await?;
    mask(io, 0x520, 1 << 15, 0).await?;
    mask(io, 0x524, 1 << 11, 1).await?;
    mask(io, 0x844, 3 << 29, 0).await?;
    Ok(())
}

async fn verify(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        if (read(io, if path == 0 { 0x18a0 } else { 0x41a0 }).await? >> 16) & 127 != u32::from(gain)
            || read(io, if path == 0 { 0x18e8 } else { 0x41e8 }).await? & 0x1fc00 != 0
            || rf_read(io, path as u8, 0x18).await? & 0x733ff != 0x3001
        {
            return Err(Error::Prerequisite);
        }
    }
    for reg in [0x3a00, 0x3a04, 0x3a08] {
        if read(io, reg).await? & 0x7f7f7f7f != 0 {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x440).await? != 0x1f
        || read(io, 0x1a04).await? & 0xff000000 != 0x81000000
        || read(io, 0x820).await? & 255 != 0x11
        || read(io, 0x1d70).await? & 0x7f7f != 0x1c1c
        || read(io, 0x84c).await? & 0xffff0000 != (168 << 16 | 161 << 24)
        || io.read16(0x680).await? & 0xcf != 0
        || io.read16(0x100).await? & (1 << 9) != 0
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
