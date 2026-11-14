//! Associated scans retain station RX, key/control work and packet retirement.
//! Firmware owns off-channel dwell and returns to the operating channel
//! (Linux mt7921_hw_scan / mt76_connac_mcu_hw_scan).
use super::*;

/// Keep the live occupied-channel grant alongside the temporary probe grant.
/// Other advertised channels remain NO_IR, including passive six-GHz scans.
pub(super) fn associated_domain(
    info: RadioInfo,
    permission: crate::mt7921::association::TxPermission,
    active: Option<&ActiveScan>,
    channels: &[u8],
    six: bool,
) -> Result<Vec<u8>, Error> {
    let band = permission.band().ok_or(Error::Bounds)?;
    let mut domain = if six || band == crate::mt7921::channel::Band::Ghz6 {
        passive_domain_6ghz(info)
    } else {
        passive_domain(info)
    };
    domain[..2].copy_from_slice(&permission.country);
    domain[3 + usize::from(band.scan_tag())] = permission.domain_width();
    let occupied = permission.channels();
    let mut entry = 12;
    for channel_band in [
        crate::mt7921::channel::Band::Ghz2,
        crate::mt7921::channel::Band::Ghz5,
        crate::mt7921::channel::Band::Ghz6,
    ] {
        let count = domain[7 + usize::from(channel_band.scan_tag())];
        for _ in 0..count {
            let number = u16::from_le_bytes([domain[entry], domain[entry + 1]]);
            let operating = band == channel_band && occupied.contains(&(number as u8));
            let probing = active.is_some()
                && channels.iter().any(|&id| {
                    crate::mt7921::channel::from_rx_channel(id)
                        == Some((channel_band, number as u8))
                });
            if operating || probing {
                domain[entry + 4..entry + 8].fill(0);
            }
            entry += 8;
        }
    }
    Ok(domain)
}

impl<B: Backend> Session<B> {
    /// Every iteration runs the production station parsers against original
    /// copy-time RX epochs. Ordinary data is retained separately until the
    /// scan completes; key changes invalidate older retained data.
    pub(super) async fn wait_associated_scan(
        &mut self,
        associated: State,
        sequence: u8,
        channels: &[u8],
        active: Option<&ActiveScan>,
        policy: &mut impl FnMut() -> Result<narf_wireless::reg::RegulatoryDomain, Error>,
        report: &mut ScanReport,
    ) -> Result<(), Error> {
        let State::Associated { info, channel, .. } = associated else {
            return Err(Error::Busy);
        };
        let started = self.backend.now_ns();
        let mut delivered = VecDeque::new();
        let mut done = false;
        loop {
            self.backend.check()?;
            self.check_station_tx()?;
            if self.backend.now_ns().saturating_sub(started) >= 15_000_000_000 {
                return Err(Error::Timeout);
            }
            if let Some(active) = active {
                active.current(&policy()?, channels)?;
            }
            for _ in 0..16 {
                let Some(packet) = self.backend.receive_data_captured()? else {
                    break;
                };
                report.received = report.received.saturating_add(1);
                if let Some(bss) = beacon(&packet.bytes, info.capabilities.phy.spatial_streams) {
                    if scan_id(&bss).is_some_and(|id| channels.contains(&id)) {
                        report.note_beacon(&packet.bytes, &bss);
                        if let Some(old) = report.bss.iter_mut().find(|old| {
                            old.bssid == bss.bssid
                                && old.channel == bss.channel
                                && old.band == bss.band
                        }) {
                            if !bss.ssid.is_empty() || old.ssid.is_empty() {
                                *old = bss;
                            }
                        } else if report.bss.len() < 64 {
                            report.bss.push(bss);
                        } else {
                            report.truncated = true;
                        }
                    }
                } else {
                    report.ignored = report.ignored.saturating_add(1);
                }
                // Off-channel observations do not enter the operating
                // station's reorder/key state. Its own beacons still do.
                if rx_native_with_amsdu(&packet.bytes).is_some_and(|rx| rx.channel == channel) {
                    if self.scan_packets.len() == 64 {
                        return Err(Error::EventOverflow);
                    }
                    self.scan_packets.push_back(packet);
                }
            }
            // No producer can acquire this exclusively borrowed owner over
            // these temporary states; every await retains Running on cancel.
            self.state = associated;
            for _ in 0..32 {
                if let Some(frame) = self.receive_ethernet()? {
                    if delivered.len() < 64 {
                        delivered.push_back((self.receive_epoch, frame));
                    }
                } else {
                    break;
                }
            }
            self.poll_data_tx()?;
            self.state = State::Running(Stage::ScanWait);

            // Key and control waits may also receive the scan-done event.
            // Handle the saved event queue as well as the native MCU ring.
            let event = match self.events.pop_front() {
                Some(event) => Some(event),
                None => self.backend.receive()?,
            };
            if let Some(event) = event {
                if event.len() < 36 {
                    return Err(Error::MalformedEvent);
                }
                let length = usize::from(u16::from_le_bytes([event[24], event[25]])) + 24;
                if length < 36 || length > event.len() {
                    return Err(Error::MalformedEvent);
                }
                if event[28] == 0x0d {
                    if length < 44 {
                        return Err(Error::MalformedEvent);
                    }
                    done |= event[36] == sequence;
                } else {
                    report.ignored = report.ignored.saturating_add(1);
                }
            }

            // BA timeouts, SA Query and EAPOL continue while firmware scans.
            // The saved association is explicit input: public state stays
            // Running throughout each nested firmware/native receipt wait.
            self.service_keys_during_scan(associated).await?;
            if done
                && self.scan_packets.is_empty()
                && self.backend.receive_idle()?
                && self.data_pending.is_empty()
            {
                break;
            }
            narf_scheduler::yield_now().await;
        }
        self.state = associated;
        for (epoch, frame) in delivered {
            if self.receive_current(epoch)? {
                self.station.received_msdu.push_back(frame);
            }
        }
        self.state = State::Running(Stage::ScanWait);
        Ok(())
    }

    /// Restore all occupied-channel rate rows after the scan's 20MHz rows,
    /// then restore the operating domain. The PSE read orders the batch just
    /// as in station startup; a failed restore leaves the station terminal.
    pub(super) async fn restore_associated_scan_power(
        &mut self,
        info: RadioInfo,
        permission: crate::mt7921::association::TxPermission,
    ) -> Result<(), Error> {
        self.check_station_tx()?;
        let limits = permission
            .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
            .ok_or(Error::Bounds)?;
        self.notify(
            Command::Ce {
                id: 0x5d,
                query: false,
            },
            &limits,
        )
        .await?;
        self.confirm_command_progress().await?;
        self.check_station_tx()?;
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &associated_domain(info, permission, None, &[], false)?,
        )
        .await?;
        self.check_station_tx()
    }
}
