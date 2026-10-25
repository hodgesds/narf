// SPDX-License-Identifier: GPL-2.0-or-later
//! C21 calibration-only ch1/20 continuation: Linux rtw8821c.c/fw.c/mac.c.
//! Firmware IQK is authorized by a measured envelope; this grants no packets.
use super::{
    calibration8821c::Envelope,
    efuse::Factory8821c,
    firmware_transport::{Error, Io},
    mac, phy8821c,
};
use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub channel: u8,
    pub bandwidth_mhz: u8,
    pub thermal_before: u8,
    pub thermal_after: u8,
    pub swing: u16,
    pub iqk_status: u32,
}
// rtw8821c_set_tx_power_index_by_rate: CCK, OFDM, HT1S and VHT1S words.
// Minimum coded indices are a deterministic calibration setup, never a dBm
// claim. The measured envelope must cover the firmware's own IQK power too.
const TXAGC: [u16; 8] = [
    0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
];
const BB_2G: [(u16, u32, u32); 6] = [
    (0x808, 1 << 28, 1),
    (0x454, 1 << 7, 0),
    (0xa80, 1 << 18, 0),
    (0x814, 0xfc00, 15),
    (0xc1c, 0xf00, 0),
    (0x860, 0x1ffe0000, 0x96a),
];
const DFIR: [(u16, u32, u32); 4] = [
    (0x948, 3 << 28, 2),
    (0x94c, 3 << 28, 2),
    (0xc20, 1 << 31, 1),
    (0x8f0, 1 << 31, 0),
];
pub(super) fn bind_recipe(hash: &mut narf_crypto::sha256::Sha256) {
    hash.update(b"US non-SRRC; C21 RF-A SIPI c90 direct-read2800; source switch/calibration v1");
    for (reg, mask, value) in BB_2G.into_iter().chain(DFIR) {
        hash.update(&reg.to_le_bytes());
        hash.update(&mask.to_le_bytes());
        hash.update(&value.to_le_bytes());
    }
    for reg in TXAGC {
        hash.update(&reg.to_le_bytes());
        hash.update(&0u32.to_le_bytes());
    }
    hash.update(&[0, 3, 6, 9]); // raw factory swing bins; no erased fallback.
    hash.update(&[0x00, 0x02, 0x6a, 0x01, 0x01, 0x01, 0xb6, 0x00]); // 0x200,16a,101,b6
}
fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = read(io, reg)?;
    io.write32(reg, (old & !bits) | (value << bits.trailing_zeros()))
}
fn rf_read(io: &mut impl Io, address: u8) -> Result<u32, Error> {
    Ok(read(io, 0x2800 + u16::from(address) * 4)? & 0xfffff)
}
async fn rf(io: &mut impl Io, address: u8, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || bits & !0xfffff != 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let data = if bits == 0xfffff {
        value
    } else {
        (rf_read(io, address)? & !bits) | (value << bits.trailing_zeros())
    };
    io.write32(0xc90, (u32::from(address) << 20) | data)?;
    io.delay_us(13).await;
    // These channel/XTAL/control registers have stable fields. SIPI issuance
    // alone cannot establish that the chosen channel/calibration setup stuck.
    if rf_read(io, address)? & bits != data & bits {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
fn temperature(io: &mut impl Io, envelope: &Envelope) -> Result<u8, Error> {
    let value = ((rf_read(io, 0x42)? & 0xfc00) >> 10) as u8;
    envelope
        .temperature(value)
        .map_err(Error::Calibration8821c)?;
    Ok(value)
}
async fn channel(
    io: &mut impl Io,
    factory: &Factory8821c,
    phy: phy8821c::Info,
) -> Result<u16, Error> {
    for (reg, bits, value) in BB_2G {
        mask(io, reg, bits, value)?;
    }
    io.write32(0xa24, phy.channel_filters[0])?;
    mask(io, 0xa28, 0xffff, phy.channel_filters[1] & 0xffff)?;
    io.write32(0xaac, phy.channel_filters[2])?;
    let adc = read(io, 0x8ac)?;
    io.write32(0x8ac, (adc & 0xffcffc00) | 0x10010000)?;
    mask(io, 0x8c4, 1 << 30, 1)?;
    let swing = [0x200u16, 0x16a, 0x101, 0xb6][usize::from(factory.swing_2g() / 3)];
    mask(io, 0xc1c, 0xffe00000, u32::from(swing))?;
    // rtw_set_channel_mac: no sideband for20MHz, source80MHz MAC clock.
    io.write8(0x483, 0)?;
    mask(io, 0x668, 0x180, 0)?;
    mask(io, 0x24, 3 << 20, 0)?;
    io.write8(0x55c, 80)?;
    io.write8(0x638, 80)?;
    let cck = io.read8(0x454)?;
    if cck == 255 {
        return Err(Error::Gone);
    }
    io.write8(0x454, cck & !0x80)?;
    let rf18 = (rf_read(io, 0x18)? & !0x70fff) | 0xc01;
    mask(io, 0x1080, 1 << 16, 1)?;
    mask(io, 0, 1 << 26, 1)?;
    let btg = matches!(phy.rfe, 2 | 4);
    mask(io, 0xa84, 0xff0000, if btg { 0x0e } else { 0x12 })?;
    mask(io, 0xa80, 0xffff, if btg { 0xfc84 } else { 0x7532 })?;
    mask(io, 0xcb8, 0xf50000, if btg { 1 } else { 0x70 })?;
    rf(io, 0xdf, 1 << 6, 1).await?;
    rf(io, 0x64, 15, 15).await?;
    rf(io, 0x18, 0xfffff, rf18).await?;
    rf(io, 0xb8, 1 << 19, 0).await?;
    rf(io, 0xb8, 1 << 19, 1).await?;
    for (reg, bits, value) in DFIR {
        mask(io, reg, bits, value)?;
    }
    for reg in TXAGC {
        io.write32(reg, 0)?;
    }
    verify_channel(io, swing, btg)?;
    Ok(swing)
}
fn verify_channel(io: &mut impl Io, swing: u16, btg: bool) -> Result<(), Error> {
    if rf_read(io, 0x18)? & 0x70fff != 0xc01
        || read(io, 0xc1c)? >> 21 != u32::from(swing)
        || read(io, 0x8ac)? & (!0xffcffc00 | 0x10010000) != 0x10010000
        || read(io, 0xcb8)? & 0xf50000 != if btg { 0x10000 } else { 0x700000 }
        || read(io, 0xa84)? & 0xff0000 != if btg { 0xe0000 } else { 0x120000 }
        || read(io, 0xa80)? & 0xffff != if btg { 0xfc84 } else { 0x7532 }
        || io.read8(0x100)? & 0xcc != 0
        || io.read8(0x522)? != 255
    {
        return Err(Error::Prerequisite);
    }
    for reg in TXAGC {
        if read(io, reg)? != 0 {
            return Err(Error::Prerequisite);
        }
    }
    Ok(())
}
pub(super) async fn prepare(
    io: &mut impl Io,
    factory: &Factory8821c,
    mac: mac::Info,
    phy: phy8821c::Info,
    envelope: &Envelope,
) -> Result<Info, Error> {
    io.begin_calibration8821c()?;
    let cfg = read(io, 0xf0)?;
    if cfg & (1 << 27) != 0 || (cfg >> 12) & 15 != u32::from(phy.cut) {
        return Err(Error::Unsupported);
    }
    let thermal_before = temperature(io, envelope)?;
    let swing = channel(io, factory, phy).await?;
    // A stale marker cannot establish this attempt's completion. Source C21
    // clear=0 is retained; do not clear a stale done receipt to make it fresh.
    if rf_read(io, 8)? == 0xabcde {
        return Err(Error::Prerequisite);
    }
    io.begin_commands()?;
    super::command::send(io, &super::command::general(mac, 0)?).await?;
    super::command::send(io, &super::command::phydm8821c(phy, 1)?).await?;
    super::command::send(io, &super::command::iqk8821c(2)).await?;
    let mut completed = false;
    for attempt in 0..300 {
        temperature(io, envelope)?;
        if rf_read(io, 8)? == 0xabcde {
            completed = true;
            break;
        }
        if attempt < 299 {
            io.delay_us(20000).await;
        }
    }
    if !completed {
        return Err(Error::Timeout);
    }
    rf(io, 8, 0xfffff, 0).await?;
    let status = read(io, 0x1bf0)?;
    // Linux reports these diagnostics; this initial hardware-testing profile
    // additionally refuses failed or reloaded results as a fresh IQK receipt.
    if status & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    let thermal_after = temperature(io, envelope)?;
    verify_channel(io, swing, matches!(phy.rfe, 2 | 4))?;
    io.park_radio()?;
    io.finish_calibration8821c()?;
    Ok(Info {
        channel: 1,
        bandwidth_mhz: 20,
        thermal_before,
        thermal_after,
        swing,
        iqk_status: status,
    })
}

pub(super) struct Checked<'a, I, F> {
    pub io: &'a mut I,
    pub envelope: &'a Envelope,
    pub policy: F,
}
#[async_trait::async_trait]
// SAFETY: current measured authority/policy encloses every underlying native
// operation; the retained backend alone owns DMA and its terminal receipts.
unsafe impl<I: Io, F> Io for Checked<'_, I, F>
where
    F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
{
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        self.envelope.invoke(&self.policy, || self.io.read8(r))
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        self.envelope.invoke(&self.policy, || self.io.read16(r))
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        self.envelope.invoke(&self.policy, || self.io.read32(r))
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.envelope.invoke(&self.policy, || self.io.write8(r, v))
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        self.envelope.invoke(&self.policy, || self.io.write16(r, v))
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.envelope.invoke(&self.policy, || self.io.write32(r, v))
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
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.begin_calibration8821c())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.begin_commands())
    }
    fn submit_h2c(&mut self, p: &[u8; 32]) -> Result<(), Error> {
        self.envelope.invoke(&self.policy, || self.io.submit_h2c(p))
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        self.envelope.invoke(&self.policy, || self.io.poll_h2c())
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        self.envelope.invoke(&self.policy, || self.io.park_radio())
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.envelope
            .invoke(&self.policy, || self.io.finish_calibration8821c())
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
}
