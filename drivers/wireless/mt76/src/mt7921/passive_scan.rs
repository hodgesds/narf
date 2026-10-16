//! Receive-only CONNAC2 scan. Reference: Linux ecd997b0189a
//! mt76_connac_mcu.{c,h}, mt7921/{mac,mcu}.c and mt792x.h.
use super::{station::Command, *};

/// One validated beacon/probe response, retaining original IEs for the SME.
#[derive(Clone, Debug)]
pub struct ScanBss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub signal_dbm: Option<i8>,
    pub capability: u16,
    pub beacon_interval: u16,
    pub information_elements: Vec<u8>,
}
/// A completed hardware scan; an empty result is not a fabricated network.
#[derive(Clone, Debug)]
pub struct ScanReport {
    pub bss: Vec<ScanBss>,
    pub received: u32,
    pub ignored: u32,
    pub truncated: bool,
}

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

// Parse only native management RX here. Translated/aggregated/protected data
// cannot become scan results. Every group and padding extent is checked.
pub(super) fn beacon(packet: &[u8], nss: u8) -> Option<ScanBss> {
    let r0 = word(packet, 0)?;
    let len = (r0 & 0xffff) as usize;
    let normal = r0 >> 27 == 2 || r0 >> 27 == 7 && (r0 >> 16) & 15 == 1;
    if !normal || len < 24 || len > packet.len() {
        return None;
    }
    let packet = &packet[..len];
    let r1 = word(packet, 4)?;
    let r2 = word(packet, 8)?;
    let r3 = word(packet, 12)?;
    let r4 = word(packet, 16)?;
    if r1 & ((0x1f << 16) | (0x3f << 23)) != 0
        || r2 & ((1 << 13) | (7 << 23) | (1 << 27)) != 0
        || r4 & 3 != 0
    {
        return None;
    }
    let channel = ((r3 >> 8) & 255) as u8;
    if !(1..=11).contains(&channel) {
        return None;
    }
    let mut offset = 24usize;
    let mut signal = None;
    for (flag, size) in [(14, 16), (11, 16), (12, 8)] {
        if r1 & (1 << flag) != 0 {
            packet.get(offset..offset + size)?;
            offset += size;
        }
    }
    if r1 & (1 << 13) != 0 {
        packet.get(offset..offset + 8)?;
        let mut rcpi = word(packet, offset + 4)?;
        offset += 8;
        if r1 & (1 << 15) != 0 {
            packet.get(offset..offset + 72)?;
            rcpi = word(packet, offset + 24)?;
            offset += 72;
        }
        for chain in 0..nss.min(2) {
            let value = ((rcpi >> (chain * 8)) & 255) as i16;
            if (1..220).contains(&value) {
                let dbm = (value / 2 - 110) as i8;
                signal = Some(signal.map_or(dbm, |old: i8| old.max(dbm)));
            }
        }
    } else if r1 & (1 << 15) != 0 {
        return None;
    }
    offset += 2 * ((r2 >> 14) & 3) as usize;
    let frame = packet.get(offset..)?;
    if frame.len() < 36 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if !matches!(fc & 0x00ff, 0x0080 | 0x0050) || fc & 0xc700 != 0 {
        return None;
    }
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;
    if bssid == [0; 6] || bssid[0] & 1 != 0 || frame[10..16] != bssid {
        return None;
    }
    let ies = &frame[36..];
    if ies.len() > 2048 {
        return None;
    }
    let mut rest = ies;
    let mut ssid = None;
    let mut ds = None;
    while !rest.is_empty() {
        let header = rest.get(..2)?;
        let len = usize::from(header[1]);
        let data = rest.get(2..2 + len)?;
        match header[0] {
            0 => {
                if len > 32 || ssid.is_some() {
                    return None;
                }
                ssid = Some(data.to_vec());
            }
            3 => {
                if len != 1 || ds.is_some() || data[0] != channel {
                    return None;
                }
                ds = Some(data[0]);
            }
            48 => {
                narf_wireless::rsn::RsnIe::decode_body(data)?;
            }
            _ => {}
        }
        rest = &rest[2 + len..];
    }
    Some(ScanBss {
        bssid,
        ssid: ssid?,
        channel,
        signal_dbm: signal,
        capability: u16::from_le_bytes([frame[34], frame[35]]),
        beacon_interval: u16::from_le_bytes([frame[32], frame[33]]),
        information_elements: ies.to_vec(),
    })
}

pub(super) fn scan_request(sequence: u8, channels: &[u8]) -> Result<Vec<u8>, Error> {
    if sequence == 0
        || sequence > 127
        || channels.is_empty()
        || channels.len() > 11
        || channels.iter().any(|ch| !(1..=11).contains(ch))
        || channels
            .iter()
            .enumerate()
            .any(|(i, ch)| channels[..i].contains(ch))
    {
        return Err(Error::Bounds);
    }
    // Packed mt76_connac_hw_scan_req: four SSIDs, 32 channels, 600 IE bytes,
    // version-1 extension containing another 32 channels and six SSIDs.
    let mut body = vec![0u8; 1186];
    body[0] = sequence;
    body[3] = 1; // wildcard; scan_type=PASSIVE, no SSIDs or probes.
    body[6] = 1 << 5; // CONNAC2 split scan.
    body[7] = 1;
    body[158] = 4;
    body[159] = channels.len() as u8;
    for (i, channel) in channels.iter().enumerate() {
        body[160 + 2 * i] = 1;
        body[161 + 2 * i] = *channel;
    }
    body[1110..1116].fill(255);
    Ok(body)
}

impl<B: Backend> Session<B> {
    async fn notify(&mut self, command: Command, body: &[u8]) -> Result<(), Error> {
        self.seq = self.seq % 15 + 1;
        self.send(false, &command.encode(self.seq, body)?).await
    }
    async fn scan_setup(&mut self, info: RadioInfo) -> Result<(), Error> {
        // Publish a single unassociated station VIF, not a host netdev.
        let mut dev = [0u8; 16];
        super::super::cmd::encode_uni_dev_info_update(0, 0, true, info.capabilities.mac, &mut dev)
            .ok_or(Error::Bounds)?;
        self.exchange(Command::Unified { id: 1 }, &dev).await?;
        let mut bss = [0u8; 36];
        bss[6..8].copy_from_slice(&32u16.to_le_bytes());
        bss[8] = 1; // active
        bss[12..16].copy_from_slice(&0x10001u32.to_le_bytes()); // station/infra
        bss[16] = 1; // initial connection state
        bss[24..26].copy_from_slice(&19u16.to_le_bytes()); // reserved BMC WCID
        bss[30..32].copy_from_slice(&19u16.to_le_bytes());
        self.exchange(Command::Unified { id: 2 }, &bss).await?;
        // Limit firmware to passive world 2.4 GHz channels, 20 MHz. No active
        // probes or packet TX API is exposed by this scan path.
        let mut domain = vec![0u8; 12 + 11 * 8];
        domain[..2].copy_from_slice(b"00");
        domain[4..7].fill(1); // 20 MHz only
        domain[8] = 11;
        for i in 0..11 {
            domain[12 + i * 8..14 + i * 8].copy_from_slice(&((i + 1) as u16).to_le_bytes());
            domain[16 + i * 8..20 + i * 8].copy_from_slice(&2u32.to_le_bytes());
            // NO_IR
        }
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &domain,
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
        let mut rx = [0u8; 76];
        rx[0] = 1;
        rx[1] = 1;
        rx[3] = info.capabilities.phy.spatial_streams;
        rx[4] = (1 << info.capabilities.phy.spatial_streams) - 1;
        self.exchange(
            Command::Extended {
                id: 0x4e,
                query: false,
            },
            &rx,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn scan_passive(&mut self, channels: &[u8]) -> Result<ScanReport, Error> {
        let sequence = self.scan_seq % 127 + 1;
        let request = scan_request(sequence, channels)?; // No writes on invalid input.
        let (info, setup) = match self.state {
            State::RadioReady(info) => (info, true),
            State::ScanReady(info) => (info, false),
            _ => return Err(Error::Busy),
        };
        if info.capabilities.phy.bands & 1 == 0 {
            return Err(Error::InvalidIdentity);
        }
        self.scan_seq = sequence;
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            if setup {
                self.stage(Stage::ScanSetup);
                self.scan_setup(info).await?;
            }
            // Discard bounded stale completions before this scan's command.
            self.events.retain(|event| event.get(28) != Some(&0x0d));
            self.stage(Stage::ScanWait);
            self.notify(
                Command::Ce {
                    id: 3,
                    query: false,
                },
                &request,
            )
            .await?;
            let mut report = ScanReport {
                bss: Vec::new(),
                received: 0,
                ignored: 0,
                truncated: false,
            };
            self.wait(15_000, |backend| {
                // Bound work per poll even if the device continuously receives.
                for _ in 0..16 {
                    let Some(packet) = backend.receive_data()? else {
                        break;
                    };
                    report.received = report.received.saturating_add(1);
                    let Some(bss) = beacon(&packet, info.capabilities.phy.spatial_streams) else {
                        report.ignored = report.ignored.saturating_add(1);
                        continue;
                    };
                    if !channels.contains(&bss.channel) {
                        continue;
                    }
                    if let Some(old) = report
                        .bss
                        .iter_mut()
                        .find(|old| old.bssid == bss.bssid && old.channel == bss.channel)
                    {
                        if !bss.ssid.is_empty() || old.ssid.is_empty() {
                            *old = bss;
                        }
                    } else if report.bss.len() < 64 {
                        report.bss.push(bss);
                    } else {
                        report.truncated = true;
                    }
                }
                if let Some(event) = backend.receive()? {
                    if event.len() < 36 {
                        return Err(Error::MalformedEvent);
                    }
                    let len = usize::from(u16::from_le_bytes([event[24], event[25]])) + 24;
                    if len < 36 || len > event.len() {
                        return Err(Error::MalformedEvent);
                    }
                    if event[28] == 0x0d {
                        if len < 44 {
                            return Err(Error::MalformedEvent);
                        }
                        if event[36] == sequence {
                            return Ok(Some(()));
                        }
                    }
                    // Scan owns no command waiter here; bounded diagnostics
                    // count unrelated notifications without growing a queue.
                    report.ignored = report.ignored.saturating_add(1);
                }
                Ok(None)
            })
            .await?;
            Ok(report)
        }
        .await;
        match result {
            Ok(report) => {
                self.state = State::ScanReady(info);
                Ok(report)
            }
            Err(error) => {
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::ScanWait,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }
}
