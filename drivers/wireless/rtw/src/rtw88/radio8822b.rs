// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") BB/RF programs after the PHY tables.
//!
//! The pure-register sequences — the `rtw8822b_phy_set_param` tail
//! (`finish_set_param`), `rtw8822b_set_channel` and the measured readback
//! checks — live in `narf-drivers-wireless-rtl-chip` (`radio::b22`, generic
//! over `RegIo`), shared by the builtin driver and the loadable `.ko`. This
//! shim bridges the native `Io`, keeps the native RF read/write helpers used by
//! external callers and the command/mailbox/envelope-coupled calibration and
//! station steps, which `RegIo` cannot express. No step here opens MAC TX/RX,
//! releases TXPAUSE or submits H2C.
use super::chip_bridge::bridge;
use super::radio::read;
use super::{
    band5::Width,
    firmware_transport::{Error, Io},
    phy8822b::{self, Info},
};
#[cfg(feature = "module")]
#[allow(unused_imports)]
use crate::rtw88::platform::narf_wireless;
use narf_drivers_wireless_rtl_chip::radio::b22;

pub(super) use b22::{rf18, Init, TXSCALE};
#[cfg(feature = "kernel-test")]
pub(super) use b22::{rf_be, valid_channel};

fn params(info: Info) -> b22::B22Params {
    b22::B22Params {
        cut: info.cut,
        rfe: info.rfe,
    }
}

// ── native RF access (`rtw_phy_read_rf` / `rtw_phy_write_rf_reg_sipi`) over the
//    8822B direct window, kept here for the command/envelope-coupled steps and
//    the external callers that pass the native `Io` ──

/// `rtw_phy_read_rf` over `rf_base_addr` with the full `RFREG_MASK`.
pub(super) async fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
    let base: u16 = match path {
        0 => 0x2800,
        1 => 0x2c00,
        _ => return Err(Error::Unsupported),
    };
    Ok(read(io, base + (u16::from(address) << 2)).await? & 0xfffff)
}
/// `rtw_phy_write_rf_reg_sipi`: a partial mask merges the direct readback.
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
    let shifted = value
        .checked_shl(bits.trailing_zeros())
        .ok_or(Error::Unsupported)?;
    if shifted & !bits != 0 {
        return Err(Error::Unsupported);
    }
    let data = if bits == 0xfffff {
        value
    } else {
        rf_read(io, path, address).await? & !bits | shifted
    };
    phy8822b::rf_write(io, path, u16::from(address), data).await
}

// ── pure-register sequences: bridge `Io` -> `RegIo` and delegate to the core ──

/// The `rtw8822b_phy_set_param` tail (`radio::b22::finish_set_param`).
pub(super) async fn finish_set_param(io: &mut impl Io, info: Info) -> Result<Init, Error> {
    let mut b = bridge(io);
    let r = b22::finish_set_param(&mut b, params(info)).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822b_pwrtrack_init` default OFDM swing index.
pub(super) async fn pwrtrack_init(io: &mut impl Io) -> Result<u8, Error> {
    let mut b = bridge(io);
    let r = b22::pwrtrack_init(&mut b).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822b_set_channel(center, bw, primary_chan_idx)` for 2T2R.
pub(super) async fn set_channel(
    io: &mut impl Io,
    info: Info,
    center: u8,
    width: Width,
) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = b22::set_channel(&mut b, params(info), center, width).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822b_set_tx_power_index_by_rate` words for one path.
pub(super) async fn write_txagc(
    io: &mut impl Io,
    path: u8,
    indices: &[u8; 64],
) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = b22::write_txagc(&mut b, path, indices).await;
    r.map_err(|e| b.err(e))
}
/// 20MHz `rtw8822b_set_channel` readback.
pub(super) async fn verify_channel20(io: &mut impl Io, ch: u8) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = b22::verify_channel20(&mut b, ch).await;
    r.map_err(|e| b.err(e))
}
/// `rtw8822b_set_channel(center, BW, sc)` readback.
pub(super) async fn verify_channel(io: &mut impl Io, ch: u8, width: Width) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = b22::verify_channel(&mut b, ch, width).await;
    r.map_err(|e| b.err(e))
}
/// Both paths' measured `N2BP` TXAGC words.
pub(super) async fn verify_txagc(io: &mut impl Io, tables: [[u8; 64]; 2]) -> Result<(), Error> {
    let mut b = bridge(io);
    let r = b22::verify_txagc(&mut b, tables).await;
    r.map_err(|e| b.err(e))
}

// ── native IQK + station bring-up (H2C commands, envelope and policy) ──

/// One completed B22 calibration-only IQK receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibration {
    pub channel: u8,
    pub bandwidth_mhz: u8,
    pub thermal_before: u8,
    pub thermal_after: u8,
    /// `REG_IQKFAILMSK` (0x1bf0) after completion.
    pub iqk_status: u32,
}

/// RF-A `RF_T_METER` (0x42) bits 15:10, checked against the envelope.
async fn temperature(
    io: &mut impl Io,
    envelope: &super::calibration8822b::Envelope,
) -> Result<u8, Error> {
    let value = ((rf_read(io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
    envelope
        .temperature(value)
        .map_err(Error::Calibration8822b)?;
    Ok(value)
}
/// `rtw8822b_pwr_track` triggers RF42[17:16]=3 on one watchdog pass and reads
/// the meter on the next (2 s `RTW_WATCH_DOG_DELAY_TIME`); there is no done bit.
async fn convert_temperature(
    io: &mut impl Io,
    envelope: &super::calibration8822b::Envelope,
) -> Result<u8, Error> {
    rf(io, 0, 0x42, 3 << 16, 3).await?;
    io.delay_us(2_000_000).await;
    temperature(io, envelope).await
}

/// `rtw8822b_phy_calibration` = `rtw8822b_do_iqk` (`rtw_fw_do_iqk` clear 0,
/// segment 0; 300 × 20 ms RF08 `0xabcde` poll; RF08 cleared; 0x1bf0
/// reload/fail mask) on ch1/20 at all-zero coded TXAGC, after the source
/// `rtw_fw_send_general_info`/`rtw_fw_send_phydm_info`. Linux only logs the
/// fail mask; this calibration-only receipt refuses failed or reloaded IQK and
/// a stale pre-existing done marker. The radio is parked afterwards.
pub(super) async fn calibrate(
    io: &mut impl Io,
    mac: super::mac::Info,
    info: Info,
    envelope: &super::calibration8822b::Envelope,
) -> Result<Calibration, Error> {
    io.begin_calibration8821c()?;
    if (read(io, 0xf0).await? >> 12) & 15 != u32::from(info.cut) {
        return Err(Error::Unsupported);
    }
    let thermal_before = convert_temperature(io, envelope).await?;
    set_channel(io, info, 1, Width::Twenty).await?;
    for path in 0..2 {
        write_txagc(io, path, &[0; 64]).await?;
    }
    if rf_read(io, 0, 0x08).await? == 0xabcde {
        return Err(Error::Prerequisite);
    }
    io.begin_commands()?;
    super::command::send(io, &super::command::general(mac, 0)?).await?;
    super::command::send(io, &super::command::phydm8822b(info, 1)?).await?;
    super::command::send(io, &super::command::iqk8821c(2)).await?;
    let mut completed = false;
    for attempt in 0..300 {
        temperature(io, envelope).await?;
        if rf_read(io, 0, 0x08).await? == 0xabcde {
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
    rf(io, 0, 0x08, 0xfffff, 0).await?;
    let status = read(io, 0x1bf0).await?;
    if status & 0x100ff != 0 {
        return Err(Error::Prerequisite);
    }
    let thermal_after = convert_temperature(io, envelope).await?;
    io.park_radio().await?;
    io.finish_calibration8821c()?;
    Ok(Calibration {
        channel: 1,
        bandwidth_mhz: 20,
        thermal_before,
        thermal_after,
        iqk_status: status,
    })
}

/// B22 ch1/20 geometry retained from the `N2BQ` IQK channel program
/// (`rtw8822b_set_channel_rf` RF18 on both paths, `_bb` 20 MHz 0x8ac) with the
/// MAC still closed (CR TX/RX DMA and MAC TX/RX clear, TXPAUSE 0xff).
async fn verify_station_geometry(io: &mut impl Io) -> Result<(), Error> {
    let rf18 = rf18(0, 1, Width::Twenty) & 0x70fff;
    for path in 0..2 {
        if rf_read(io, path, 0x18).await? & 0x70fff != rf18 {
            return Err(Error::Prerequisite);
        }
    }
    if read(io, 0x8ac).await? & !0xffcffc00 != 0
        || io.read8(0x100).await? & 0xcc != 0
        || io.read8(0x522).await? != 255
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// B22 awake-station radio program, the counterpart of
/// `radio8821c::prepare_station`, entirely inside `N2BQ` + `N2BP` + `N2BS` and
/// current policy. It keeps the IQK channel/RFE program (`rtw8822b_set_channel`
/// is not replayed: it would not restore the measured TXAGC), re-checks the cut,
/// RF08/0x1bf0 IQK receipts and both paths' measured TXAGC, takes a fresh
/// RF42 conversion (`rtw8822b_pwr_track` trigger + 2 s interval), programs the
/// conservative CCK response mask 0x1f, invalidates the 32 CAM entries with
/// host-only crypto (`radio::software_crypto`), wakes firmware through
/// RPWM/CPWM (`radio::awake`, `ps.c::rtw_power_mode_change` active), and hands
/// the PCI transport the B22 packet gate with every MAC/DMA/IRQ gate still
/// closed. Linux `rtw_core_start` opens those later through mac80211.
pub(super) async fn prepare_station<F>(
    io: &mut impl Io,
    factory: &super::efuse8822b::Factory8822b,
    phy: Info,
    grant: alloc::sync::Arc<super::operating8822b::Grant>,
    policy: F,
) -> Result<super::radio8821c::StationInfo, Error>
where
    F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
{
    let mut io = super::radio8821c::Checked {
        io,
        envelope: &*grant,
        policy,
    };
    io.begin_station8821c()?;
    verify_station_geometry(&mut io).await?;
    if (read(&mut io, 0xf0).await? >> 12) & 15 != u32::from(phy.cut)
        || rf_read(&mut io, 0, 0x08).await? != 0
        || read(&mut io, 0x1bf0).await? & 0x100ff != 0
        || factory.mac() != grant.own()
    {
        return Err(Error::Prerequisite);
    }
    let tables = [grant.power().txagc(0), grant.power().txagc(1)];
    verify_txagc(&mut io, tables).await?;
    rf(&mut io, 0, 0x42, 3 << 16, 3).await?;
    io.delay_us(2_000_000).await;
    let thermal = ((rf_read(&mut io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
    grant.temperature(thermal)?;
    io.write32(0x440, 0x1f).await?;
    super::radio::software_crypto(&mut io).await?;
    super::radio::awake(&mut io).await?;
    verify_station_geometry(&mut io).await?;
    verify_txagc(&mut io, tables).await?;
    if read(&mut io, 0x440).await? != 0x1f
        || io.read8(0x303).await? & 0xf7 != 0xf7
        || io.read32(0xb0).await.ok() != Some(0)
        || io.read32(0xb8).await.ok() != Some(0)
        || io.read32(0x10b8).await.ok() != Some(0)
    {
        return Err(Error::Prerequisite);
    }
    grant.temperature(((rf_read(&mut io, 0, 0x42).await? & 0xfc00) >> 10) as u8)?;
    io.finish_station8821c(super::power_policy::Gate::b22(grant.clone(), phy))?;
    Ok(super::radio8821c::StationInfo {
        channel: 1,
        bandwidth_mhz: 20,
        thermal,
        response_rates: 0x1f,
        identity: grant.identity(),
    })
}
