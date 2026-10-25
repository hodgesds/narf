// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed awake channel1/20MHz CCK1, TX-A/RX-AB radio continuation.
//! Linux rtw8822c.c: TRX selection, channel, factory trim and RF calibration.
use super::{
    efuse::Factory,
    firmware_transport::{Error, Io},
    power_policy,
};
use alloc::boxed::Box;
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
    trx(io)?;
    channel(io).await?;
    gains(io, gain)?;
    let dack = super::dack::calibrate(io).await?;
    x2(io).await?;
    trims(io, factory).await?;
    // Fixed CCK1 operation disables the source low-rate DPD path entirely.
    // Unlike wideband GAPK/DPK, DACK and IQK run on the retained channel only.
    for path in 0..2 {
        mask(io, 0x1b00, 6, path)?;
        mask(io, 0x1b08, 1 << 31, 0)?;
    }
    mask(io, 0xa70, 0x3ff, 0x3ff)?;
    let cck_gi = [
        (((read(io, 0x1a98)? >> 6) & 3) << 4 | ((read(io, 0x1a70)? >> 24) & 15)) as u8,
        ((((read(io, 0x1a98)? >> 14) & 3) << 4) | ((read(io, 0x1aa8)? >> 16) & 15)) as u8,
    ];
    receive_policy(io)?;
    software_crypto(io).await?;
    awake(io).await?;
    io.begin_commands()?;
    super::command::send(io, &super::command::general(mac, 0)?).await?;
    super::command::send(io, &super::command::phydm(phy, 1)?).await?;
    // RPT_CIP has no source host reset operation. Refuse a stale done value
    // before submission instead of manufacturing an acknowledgement.
    let before = io.read8(0x2d9c)?;
    if before == 255 {
        return Err(Error::Gone);
    }
    if before == 0xaa {
        return Err(Error::Prerequisite);
    }
    rfk_power(io, true)?;
    super::command::send(io, &super::command::iqk(2)).await?;
    let mut complete = false;
    for attempt in 0..=15 {
        let value = io.read8(0x2d9c)?;
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
    io.write8(0x1b10, 0)?;
    rfk_power(io, false)?;
    // IQK must not silently reopen optional DPD or alter selected gains.
    for path in 0..2 {
        mask(io, 0x1b00, 6, path)?;
        mask(io, 0x1b08, 1 << 31, 0)?;
    }
    mask(io, 0xa70, 0x3ff, 0x3ff)?;
    gains(io, gain)?;
    verify(io, gain)?;
    io.finish_radio(gate)?;
    Ok(Info {
        channel: 1,
        gains: gain,
        adc_dc: dack.adc,
        residual: dack.residual,
        cck_gi,
    })
}
pub(super) fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
pub(super) fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = read(io, reg)?;
    io.write32(reg, old & !bits | value << bits.trailing_zeros())
}
pub(super) fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
    let base = match path {
        0 => 0x3c00,
        1 => 0x4c00,
        _ => return Err(Error::Unsupported),
    };
    Ok(read(io, base + u16::from(address) * 4)? & 0xfffff)
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
            rf_read(io, path, 0)? & !bits | shifted
        };
        io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data)?;
        io.delay_us(13).await;
    } else {
        mask(
            io,
            (if path == 0 { 0x3c00 } else { 0x4c00 }) + u16::from(address) * 4,
            bits,
            value,
        )?;
        io.delay_us(1).await;
    }
    Ok(())
}
fn reset(io: &mut impl Io) -> Result<(), Error> {
    let old = io.read16(2)?;
    if old == u16::MAX {
        return Err(Error::Gone);
    }
    for value in [old | 1, old & !1, old | 1] {
        io.write16(2, value)?;
    }
    Ok(())
}
fn toggle_igi(io: &mut impl Io) -> Result<(), Error> {
    let igi = read(io, 0x1d70)? & 0x7f;
    let lower = igi.checked_sub(2).ok_or(Error::Prerequisite)?;
    for value in [lower, igi] {
        mask(io, 0x1d70, 0x7f, value)?;
        mask(io, 0x1d70, 0x7f00, value)?;
    }
    Ok(())
}
pub(super) fn trx(io: &mut impl Io) -> Result<(), Error> {
    for reg in [0x1800, 0x4100] {
        mask(io, reg, 0xfffff, 0x33312)?;
    }
    // Source config_rx_path(AB), config_tx_path(A,A,A,false).
    for (reg, bits, value) in [
        (0x1a2c, 0x00600000, 1),
        (0x1a2c, 0x00060000, 1),
        (0x1a04, 0x0f000000, 1),
        (0x1d30, 0x300, 1),
        (0x1d30, 0x600000, 1),
        (0xc44, 1 << 17, 1),
        (0xc54, 1 << 20, 1),
        (0xc38, 1 << 24, 1),
        (0x824, 0x0f000000, 3),
        (0x824, 0x000f0000, 3),
        (0x1a04, 0xf0000000, 8),
    ] {
        mask(io, reg, bits, value)?;
    }
    reset(io)?;
    mask(io, 0x820, 0xff, 0x11)?;
    mask(io, 0x1e2c, 0xff, 0)?;
    reset(io)?;
    reset(io)?;
    toggle_igi(io)
}
pub(super) async fn channel(io: &mut impl Io) -> Result<(), Error> {
    for (reg, bits, value) in [
        (0x1a14, 0x300, 0),
        (0x1a9c, 1 << 20, 1),
        (0x454, 1 << 7, 0),
        (0x1a80, 1 << 18, 0),
        (0x1c80, 0x3f000000, 15),
        (0x18ac, 0xf000, 5),
        (0x41ac, 0xf000, 5),
        (0x18ac, 0x1f0, 6),
        (0x41ac, 0x1f0, 6),
        (0xc30, 0xfff, 0x9aa),
        (0x1a20, 0xffff0000, 0x5284),
        (0x1a24, u32::MAX, 0x3e18fec8),
        (0x1a28, 0xffff, 0x0a88),
        (0x1a98, 0xffff0000, 0xacc4),
        (0x1a9c, 0xffff, 0xc8b2),
        (0x1aa0, u32::MAX, 0x00faf0de),
        (0x1aac, u32::MAX, 0x00122344),
        (0x1ab0, u32::MAX, 0x0fffffff),
        (0x808, 0x70, 1),
        (0x810, 0x3ff0, 0x19b),
        (0x9b0, 15, 0),
        (0x9b0, 0xffc0, 0),
        (0x9b4, 0x700, 7),
        (0x9b4, 0x700000, 6),
        (0x1abc, 1 << 30, 0),
        (0x88c, 0xf000, 1),
        (0xcbc, 1 << 21, 0),
    ] {
        mask(io, reg, bits, value)?;
    }
    io.write8(0x483, 0)?;
    mask(io, 0x668, 0x180, 0)?;
    mask(io, 0x24, 3 << 20, 0)?;
    io.write8(0x55c, 80)?;
    io.write8(0x638, 80)?;
    let check = io.read8(0x454)?;
    if check == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x454, check & !(1 << 7))?;
    let reg18 = (rf_read(io, 0, 0x18)?
        & !((1 << 16) | (1 << 9) | (1 << 8) | 255 | (3 << 17) | (3 << 12)))
        | 1
        | 3 << 12;
    mask(io, 0x1c90, 1 << 8, 0)?;
    for path in 0..2 {
        rf(io, path, 0xee, 4, 1).await?;
        rf(io, path, 0x33, 31, 0x12).await?;
        rf(io, path, 0x3f, 0xfffff, 0x18).await?;
        rf(io, path, 0xee, 4, 0).await?;
    }
    for path in 0..2 {
        rf(io, path, 0x18, 0xfffff, reg18).await?;
    }
    mask(io, 0x1c90, 1 << 8, 1)?;
    mask(io, 0x1830, 1 << 29, 1)?;
    mask(io, 0x4130, 1 << 29, 1)?;
    toggle_igi(io)
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
    mask(io, 0xa70, 0x3ff, 0x3ff)?;
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
pub(super) fn gains(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        mask(io, 0x1c90, 1 << 15, 0)?;
        mask(
            io,
            if path == 0 { 0x18a0 } else { 0x41a0 },
            0x7f0000,
            u32::from(gain),
        )?;
    }
    for path in 0..2 {
        // No OFDM/HT/VHT descriptor is admitted by this profile. Zero their
        // reference, and use zero relative difference for the four CCK slots.
        mask(io, 0x1c90, 1 << 15, 0)?;
        mask(io, if path == 0 { 0x18e8 } else { 0x41e8 }, 0x1fc00, 0)?;
    }
    for reg in [0x3a00, 0x3a04, 0x3a08] {
        mask(io, 0x1c90, 1 << 15, 0)?;
        io.write32(reg, 0)?;
    }
    // Original phy_get_rrsr_mask(DESC_RATE1M) &RRSR_INIT_2G. This admits
    // mandatory CCK/OFDM control responses; their full RF envelope is measured
    // separately in N22Cv2. Host RX rejection cannot suppress hardware ACKs.
    io.write32(0x440, 0x1f)
}
pub(super) fn rfk_power(io: &mut impl Io, active: bool) -> Result<(), Error> {
    for path in 0..2 {
        mask(io, 0x1b00, 6, path)?;
        mask(io, 0x1b08, 1 << 7, u32::from(active))?;
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
    if rf_read(io, 0, 0xb8)? & (1 << 15) != 0 {
        for (reg, value) in [(0xb8, 0xc4440), (0xba, 0x6840d), (0xb8, 0x80440)] {
            rf(io, 0, reg, 0xfffff, value).await?;
        }
        io.delay_us(1000).await;
        if rf_read(io, 0, 0xb8)? & (1 << 15) != 0 {
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
            if read(io, 0x670)? & (1 << 31) == 0 {
                done = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !done {
            return Err(Error::Timeout);
        }
        io.write32(0x674, 0)?;
        io.write32(0x670, 1 << 31 | 1 << 16 | index << 3)?;
    }
    let mut done = false;
    for _ in 0..1000 {
        if read(io, 0x670)? & (1 << 31) == 0 {
            done = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !done {
        return Err(Error::Timeout);
    }
    let cr = io.read16(0x100)?;
    if cr == u16::MAX {
        return Err(Error::Gone);
    }
    io.write16(0x100, cr & !(1 << 9))?;
    let security = io.read16(0x680)?;
    if security == u16::MAX {
        return Err(Error::Gone);
    }
    io.write16(0x680, security & !0xcf)?;
    // Native MPDU with PHY status+FCS; no TCP offload/header conversion,
    // ICV/MIC stripping or BSSID filtering before host association admission.
    let rcr = read(io, 0x608)?;
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
    io.write32(0x608, (rcr & !clear) | 1 << 31 | 1 << 28 | 1 << 10 | 15)?;
    if io.read16(0x680)? & 0xcf != 0 || io.read16(0x100)? & (1 << 9) != 0 {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
pub(super) async fn awake(io: &mut impl Io) -> Result<(), Error> {
    let request = io.read8(0x3d9)?;
    let confirm = io.read8(0x3da)?;
    if request == 255 || confirm == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x3d9, (!request & 0x80) | 0x40)?;
    for _ in 0..150 {
        io.delay_us(100).await;
        let value = io.read8(0x3da)?;
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
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        self.io.read8(r)
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        self.io.read16(r)
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        self.io.read32(r)
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.check()?;
        self.io.write8(r, v)
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        self.check()?;
        self.io.write16(r, v)
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.check()?;
        self.io.write32(r, v)
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
    fn submit_h2c(&mut self, p: &[u8; 32]) -> Result<(), Error> {
        self.check()?;
        self.io.submit_h2c(p)
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
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

pub(super) fn receive_policy(io: &mut impl Io) -> Result<(), Error> {
    // Source phy_init starts EDCCA at a disabled sentinel and its watchdog
    // later programs a real threshold. Keep the source maximum-coverage IGI
    // and the stricter adaptive40/33 threshold at that IGI; no disabled
    // sentinel or missing watchdog may leave unbounded energy detection.
    mask(io, 0x1d70, 0x7f, 0x1c)?;
    mask(io, 0x1d70, 0x7f00, 0x1c)?;
    mask(io, 0x84c, 0x00ff0000, 40 + 0x80)?;
    mask(io, 0x84c, 0xff000000, 33 + 0x80)?;
    mask(io, 0x520, 1 << 15, 0)?;
    mask(io, 0x524, 1 << 11, 1)?;
    mask(io, 0x844, 3 << 29, 0)?;
    Ok(())
}

fn verify(io: &mut impl Io, gains: [u8; 2]) -> Result<(), Error> {
    for (path, gain) in gains.into_iter().enumerate() {
        if (read(io, if path == 0 { 0x18a0 } else { 0x41a0 })? >> 16) & 127 != u32::from(gain)
            || read(io, if path == 0 { 0x18e8 } else { 0x41e8 })? & 0x1fc00 != 0
            || rf_read(io, path as u8, 0x18)? & 0x733ff != 0x3001
        {
            return Err(Error::Prerequisite);
        }
    }
    for reg in [0x3a00, 0x3a04, 0x3a08] {
        if read(io, reg)? & 0x7f7f7f7f != 0 {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x440)? != 0x1f
        || read(io, 0x1a04)? & 0xff000000 != 0x81000000
        || read(io, 0x820)? & 255 != 0x11
        || read(io, 0x1d70)? & 0x7f7f != 0x1c1c
        || read(io, 0x84c)? & 0xffff0000 != (168 << 16 | 161 << 24)
        || io.read16(0x680)? & 0xcf != 0
        || io.read16(0x100)? & (1 << 9) != 0
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
