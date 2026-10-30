//! Passive native monitor ownership, from Linux mt7921/mcu.c sniffer TLVs
//! and mac.c RXD groups. No station peer, key, injection or Ethernet owner.
use super::{station::Command, Backend, Error, RadioInfo, Session, Stage, State};
use crate::mt7921::channel::{self, Band};
use alloc::vec::Vec;
pub use narf_wireless::monitor::Channel;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    pub frames: Vec<Vec<u8>>,
    pub ignored: u32,
}

/// Validate all occupied twenty-MHz constituents against actual silicon and
/// the current receive policy. NO_IR/DFS are allowed: capture emits no RF.
pub fn validate_channel(
    info: RadioInfo,
    domain: &narf_wireless::reg::RegulatoryDomain,
    config: Channel,
) -> Result<(), Error> {
    let (band, primary) = geometry(info, config)?;
    let width = match config.width {
        0 | 1 => 20,
        2 => 40,
        3 => 80,
        5 => 160,
        _ => return Err(Error::Bounds),
    };
    let first = config
        .center1_mhz
        .checked_sub(width / 2 - 10)
        .ok_or(Error::Bounds)?;
    for freq in (first..=first + width - 20).step_by(20) {
        let (actual, number) =
            narf_wireless::association::channel::from_frequency_band(freq).ok_or(Error::Bounds)?;
        let expected = match band {
            Band::Ghz2 => narf_wireless::association::channel::Band::Ghz2,
            Band::Ghz5 => narf_wireless::association::channel::Band::Ghz5,
            Band::Ghz6 => narf_wireless::association::channel::Band::Ghz6,
        };
        if actual != expected || channel::rx_channel(band, number).is_none() {
            return Err(Error::Bounds);
        }
        let rule = domain.rule_for(freq).ok_or(Error::Authority)?;
        if rule.max_bandwidth_mhz < width
            || freq.saturating_sub(10) < rule.freq_start_mhz
            || freq + 10 > rule.freq_end_mhz
        {
            return Err(Error::Authority);
        }
    }
    if channel::rx_channel(band, primary).is_none() {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn geometry(info: RadioInfo, config: Channel) -> Result<(Band, u8), Error> {
    if config.center2_mhz != 0 {
        return Err(Error::Bounds);
    }
    let (common, primary) =
        narf_wireless::association::channel::from_frequency_band(config.frequency_mhz)
            .ok_or(Error::Bounds)?;
    let band = match common {
        narf_wireless::association::channel::Band::Ghz2 => Band::Ghz2,
        narf_wireless::association::channel::Band::Ghz5 => Band::Ghz5,
        narf_wireless::association::channel::Band::Ghz6 => Band::Ghz6,
    };
    if band == Band::Ghz6 {
        if !crate::mt7921::six_ghz::qualified(info) || primary % 4 != 1 {
            return Err(Error::UnsupportedFirmware);
        }
    } else if info.capabilities.phy.bands & band.capability() == 0 {
        return Err(Error::UnsupportedFirmware);
    }
    let base = match band {
        Band::Ghz2 => 2407,
        Band::Ghz5 => 5000,
        Band::Ghz6 => 5950,
    };
    let center = config
        .center1_mhz
        .checked_sub(base)
        .filter(|n| n % 5 == 0)
        .and_then(|n| u8::try_from(n / 5).ok())
        .ok_or(Error::Bounds)?;
    let valid = match config.width {
        0 | 1 => center == primary,
        2 => info.capabilities.phy.ht && primary.abs_diff(center) == 2,
        3 => {
            band != Band::Ghz2
                && (info.capabilities.phy.vht || band == Band::Ghz6)
                && match band {
                    Band::Ghz5 => channel::block80(primary, center).is_some(),
                    Band::Ghz6 => {
                        center >= 7 && (center - 7) % 16 == 0 && primary.abs_diff(center) <= 6
                    }
                    _ => false,
                }
        }
        5 => {
            band != Band::Ghz2
                && info.chip_id == 0x7922
                && (info.capabilities.phy.vht || band == Band::Ghz6)
                && match band {
                    Band::Ghz5 => channel::block160(primary, center).is_some(),
                    Band::Ghz6 => {
                        center >= 15 && (center - 15) % 32 == 0 && primary.abs_diff(center) <= 14
                    }
                    _ => false,
                }
        }
        _ => false,
    };
    if !valid {
        return Err(Error::Bounds);
    }
    if config.width == 2 {
        let other = if primary < center {
            primary.checked_add(4)
        } else {
            primary.checked_sub(4)
        }
        .ok_or(Error::Bounds)?;
        if channel::rx_channel(band, other).is_none() {
            return Err(Error::Bounds);
        }
    }
    Ok((band, primary))
}

fn enable(on: bool) -> [u8; 12] {
    let mut body = [0; 12];
    body[6] = 8;
    body[8] = u8::from(on);
    body
}
fn config_request(info: RadioInfo, config: Channel) -> Result<[u8; 20], Error> {
    let (band, primary) = geometry(info, config)?;
    let base = match band {
        Band::Ghz2 => 2407,
        Band::Ghz5 => 5000,
        Band::Ghz6 => 5950,
    };
    let center = ((config.center1_mhz - base) / 5) as u8;
    let mut body = [0; 20];
    body[4] = 1;
    body[6] = 16;
    body[10] = band.scan_tag();
    body[11] = match config.width {
        3 => 1,
        5 => 2,
        _ => 0,
    };
    body[12] = primary;
    body[13] = if primary < center {
        1
    } else if primary > center {
        3
    } else {
        0
    };
    body[14] = center;
    body[16] = 1;
    Ok(body)
}
fn filter(monitor: bool) -> [u8; 68] {
    let mut body = [0; 68];
    body[4] = 1;
    body[8..12].copy_from_slice(&(0x8000_0000u32 | if monitor { 0x60 } else { 0 }).to_le_bytes());
    body
}
fn bss(active: bool) -> [u8; 36] {
    let mut body = super::scan::station_bss_record(active);
    body[12..16].copy_from_slice(&0x10002u32.to_le_bytes());
    body
}

impl<B: Backend> Session<B> {
    pub(super) async fn start_monitor_with_policy(
        &mut self,
        config: Channel,
        mut policy: impl FnMut() -> Result<narf_wireless::reg::RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        let (info, existing) = match self.state {
            State::RadioReady(info) => (info, false),
            State::ScanReady(info) => (info, true),
            _ => return Err(Error::Busy),
        };
        validate_channel(info, &policy()?, config)?;
        self.renew_receive_epoch()?;
        self.stage(Stage::MonitorStart);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            if existing {
                self.monitor_device(info, false, false).await?;
            }
            self.monitor_device(info, true, true).await?;
            let domain = if crate::mt7921::six_ghz::qualified(info) {
                super::scan::passive_domain_6ghz(info)
            } else {
                super::scan::passive_domain(info)
            };
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;
            self.notify(
                Command::Ce {
                    id: 0xca,
                    query: false,
                },
                &super::system_pm::deep_sleep_config(false),
            )
            .await?;
            self.exchange(
                Command::Extended {
                    id: 0x46,
                    query: false,
                },
                &[1, 0, 0, 0],
            )
            .await?;
            let mut rx = [0; 76];
            rx[0] = 1;
            rx[1] = 1;
            rx[3] = info.capabilities.phy.spatial_streams;
            rx[4] = (1 << rx[3]) - 1;
            self.exchange(
                Command::Extended {
                    id: 0x4e,
                    query: false,
                },
                &rx,
            )
            .await?;
            self.notify(
                Command::Ce {
                    id: 0x0a,
                    query: false,
                },
                &filter(true),
            )
            .await?;
            self.confirm_command_progress().await?;
            validate_channel(info, &policy()?, config)?;
            self.exchange(Command::Unified { id: 0x24 }, &enable(true))
                .await?;
            self.exchange(
                Command::Unified { id: 0x24 },
                &config_request(info, config)?,
            )
            .await?;
            validate_channel(info, &policy()?, config)?;
            // Native completed-prefix drain: frames copied before the new
            // capture generation are never published under its token.
            self.wait(1000, |backend| {
                for _ in 0..16 {
                    if backend.receive_data()?.is_none() {
                        break;
                    }
                }
                backend.receive_idle().map(|idle| idle.then_some(()))
            })
            .await?;
            Ok(())
        }
        .await;
        self.boot_started = None;
        self.state = match result {
            Ok(()) => State::Monitor {
                info,
                channel: config,
            },
            Err(error) => State::Failed {
                stage: Stage::MonitorStart,
                error,
            },
        };
        result
    }
    async fn monitor_device(
        &mut self,
        info: RadioInfo,
        active: bool,
        monitor: bool,
    ) -> Result<(), Error> {
        let mut dev = [0; 16];
        crate::mt7921::cmd::encode_uni_dev_info_update(
            0,
            0,
            active,
            info.capabilities.mac,
            &mut dev,
        )
        .ok_or(Error::Bounds)?;
        let bss = if monitor {
            bss(active)
        } else {
            super::scan::station_bss_record(active)
        };
        if active {
            self.exchange(Command::Unified { id: 1 }, &dev).await?;
            self.exchange(Command::Unified { id: 2 }, &bss).await?;
        } else {
            self.exchange(Command::Unified { id: 2 }, &bss).await?;
            self.exchange(Command::Unified { id: 1 }, &dev).await?;
        }
        Ok(())
    }
    pub(super) async fn stop_monitor(&mut self) -> Result<(), Error> {
        let State::Monitor { info, .. } = self.state else {
            return Err(Error::Busy);
        };
        self.stage(Stage::MonitorStop);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.exchange(Command::Unified { id: 0x24 }, &enable(false))
                .await?;
            self.notify(
                Command::Ce {
                    id: 0x0a,
                    query: false,
                },
                &filter(false),
            )
            .await?;
            self.confirm_command_progress().await?;
            self.monitor_device(info, false, true).await?;
            self.exchange(
                Command::Extended {
                    id: 0x46,
                    query: false,
                },
                &[0, 0, 0, 0],
            )
            .await?;
            Ok(())
        }
        .await;
        self.boot_started = None;
        self.state = match result {
            Ok(()) => State::RadioReady(info),
            Err(error) => State::Failed {
                stage: Stage::MonitorStop,
                error,
            },
        };
        result
    }
    pub(super) fn step_monitor(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Capture, Error> {
        let State::Monitor { info, channel } = self.state else {
            return Err(Error::Busy);
        };
        self.backend.check()?;
        if let Err(error) = validate_channel(info, domain, channel) {
            self.state = State::Failed {
                stage: Stage::MonitorStart,
                error,
            };
            return Err(error);
        }
        let mut report = Capture {
            frames: Vec::new(),
            ignored: 0,
        };
        for _ in 0..16 {
            let Some(packet) = self.backend.receive_data()? else {
                break;
            };
            if let Some(frame) = decode(&packet, info.capabilities.phy.spatial_streams)
                .filter(|(metadata, _)| metadata.frequency_mhz == channel.frequency_mhz)
            {
                if let Ok(bytes) = narf_wireless::monitor::encode(frame.1, frame.0) {
                    report.frames.push(bytes);
                    continue;
                }
            }
            report.ignored += 1;
        }
        self.backend.check()?;
        Ok(report)
    }
}

/// Preserve the original MPDU. Translated, already decrypted/stripped or
/// hardware-split A-MSDU data is never disguised as an on-air capture.
fn decode(packet: &[u8], nss: u8) -> Option<(narf_wireless::monitor::Metadata, &[u8])> {
    let word = |offset| {
        Some(u32::from_le_bytes(
            packet.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let r0 = word(0)?;
    let len = (r0 & 0xffff) as usize;
    if !(r0 >> 27 == 2 || r0 >> 27 == 7 && (r0 >> 16) & 15 == 1) || len < 24 || len > packet.len() {
        return None;
    }
    let packet = &packet[..len];
    let word = |offset| {
        Some(u32::from_le_bytes(
            packet.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let r1 = word(4)?;
    let r2 = word(8)?;
    if r1 & ((7 << 25) | (1 << 28)) != 0 || r2 & ((1 << 13) | (7 << 23)) != 0 || word(16)? & 3 != 0
    {
        return None;
    }
    // Linux marks decrypted only when SEC_MODE !=0 and neither CM nor CLM.
    if r1 & (31 << 16) != 0 && r1 & (3 << 23) == 0 {
        return None;
    }
    let (band, channel) = channel::from_rx_channel(u8::try_from((word(12)? >> 8) & 0x1ff).ok()?)?;
    let frequency_mhz = channel::frequency_in(band, channel)?;
    let mut offset = 24usize;
    for (flag, size) in [(14, 16), (11, 16), (12, 8)] {
        if r1 & (1 << flag) != 0 {
            packet.get(offset..offset + size)?;
            offset += size;
        }
    }
    let mut signal_dbm = None;
    if r1 & (1 << 13) != 0 {
        packet.get(offset..offset + 8)?;
        let mut rcpi = word(offset + 4)?;
        offset += 8;
        if r1 & (1 << 15) != 0 {
            packet.get(offset..offset + 72)?;
            rcpi = word(offset + 24)?;
            offset += 72;
        }
        for chain in 0..nss.min(2) {
            let value = ((rcpi >> (chain * 8)) & 255) as i16;
            if (1..220).contains(&value) {
                let dbm = (value / 2 - 110) as i8;
                signal_dbm = Some(signal_dbm.map_or(dbm, |old: i8| old.max(dbm)));
            }
        }
    } else if r1 & (1 << 15) != 0 {
        return None;
    }
    offset += 2 * ((r2 >> 14) & 3) as usize;
    let frame = packet.get(offset..)?;
    narf_wireless::monitor::header_len(frame)?;
    Some((
        narf_wireless::monitor::Metadata {
            frequency_mhz,
            signal_dbm,
        },
        frame,
    ))
}
