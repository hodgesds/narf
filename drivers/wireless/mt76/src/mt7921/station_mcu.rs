//! Post-ROM CONNAC2 command formats and radio identity.
//! Reference: local Linux ecd997b0189a, mt76_connac_mcu.{c,h}, mt7921/mcu.c.
use super::*;

/// Firmware-reported PHY fields, without inferred capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhyCapabilities {
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    pub max_bandwidth: u8,
    pub spatial_streams: u8,
    pub bands: u8,
    pub tx_ldpc: bool,
    pub rx_ldpc: bool,
    pub tx_stbc: bool,
    pub rx_stbc: bool,
}

/// Validated capability response; no fabricated MAC or PHY fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NicCapabilities {
    pub mac: [u8; 6],
    pub phy: PhyCapabilities,
    pub has_6ghz: bool,
    pub chip_capabilities: u64,
}
impl NicCapabilities {
    /// Parse Linux's count + (u32 type, u32 payload length, payload) table.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::MalformedEvent);
        }
        let count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if count > 128 {
            return Err(Error::MalformedEvent);
        }
        let mut offset = 4usize;
        let mut mac = None;
        let mut phy = None;
        let mut has_6ghz = None;
        let mut chip = None;
        for _ in 0..count {
            let header = bytes.get(offset..offset + 8).ok_or(Error::MalformedEvent)?;
            let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
            let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
            offset += 8;
            let end = offset.checked_add(len).ok_or(Error::MalformedEvent)?;
            let value = bytes.get(offset..end).ok_or(Error::MalformedEvent)?;
            match kind {
                7 => {
                    if value.len() < 6 || mac.is_some() {
                        return Err(Error::MalformedEvent);
                    }
                    let address: [u8; 6] = value[..6].try_into().unwrap();
                    if address == [0; 6] || address[0] & 1 != 0 {
                        return Err(Error::InvalidIdentity);
                    }
                    mac = Some(address);
                }
                8 => {
                    if value.len() < 12 || phy.is_some() {
                        return Err(Error::MalformedEvent);
                    }
                    if !(1..=2).contains(&value[4]) || value[10] & 3 == 0 {
                        return Err(Error::InvalidIdentity);
                    }
                    phy = Some(PhyCapabilities {
                        ht: value[0] != 0,
                        vht: value[1] != 0,
                        he: value[11] != 0,
                        max_bandwidth: value[3],
                        spatial_streams: value[4],
                        bands: value[10] & 3,
                        tx_ldpc: value[6] != 0,
                        rx_ldpc: value[7] != 0,
                        tx_stbc: value[8] != 0,
                        rx_stbc: value[9] != 0,
                    });
                }
                0x18 => {
                    if value.is_empty() || has_6ghz.is_some() {
                        return Err(Error::MalformedEvent);
                    }
                    has_6ghz = Some(value[0] != 0);
                }
                0x20 => {
                    if value.len() < 8 || chip.is_some() {
                        return Err(Error::MalformedEvent);
                    }
                    chip = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
                }
                _ => {}
            }
            offset = end;
        }
        // Firmware may append reserved bytes after its counted table.
        Ok(Self {
            mac: mac.ok_or(Error::InvalidIdentity)?,
            phy: phy.ok_or(Error::InvalidIdentity)?,
            has_6ghz: has_6ghz.unwrap_or(false),
            chip_capabilities: chip.unwrap_or(0),
        })
    }
}

/// MCU identity, world limits and MAC initialization completed.
/// Packet queues, radio enable and association are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioInfo {
    pub firmware: Report,
    pub capabilities: NicCapabilities,
    pub hardware_type: u8,
    pub world_limit_commands: u16,
    pub channel_configuration: Option<u8>,
}

pub(super) fn validate_clc_tables(mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(Error::InvalidFirmware);
        }
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if len < 16 || len > bytes.len() {
            return Err(Error::InvalidFirmware);
        }
        if bytes[4] > 3 || bytes[5] != 1 {
            return Err(Error::UnsupportedFirmware);
        }
        bytes = &bytes[len..];
    }
    Ok(())
}

impl Firmware {
    // Choose the first table for each index, matching the power table's
    // package type to EFUSE, as mt7921_load_clc does. Validate every selected
    // command before posting the first one; vendor rule bytes stay opaque.
    pub(super) fn world_limits(
        &self,
        hardware_type: u8,
        response: bool,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut selected = [false; 4];
        let mut commands = Vec::new();
        for region in &self.clc_regions {
            let mut tables = &self.ram[region.clone()];
            validate_clc_tables(tables)?;
            while !tables.is_empty() {
                let len = u32::from_le_bytes(tables[..4].try_into().unwrap()) as usize;
                let table = &tables[..len];
                tables = &tables[len..];
                let index = usize::from(table[4]);
                if selected[index] || (index == 0 && table[7] & 1 != hardware_type & 1) {
                    continue;
                }
                selected[index] = true;
                let mut rules = &table[16..];
                let before = commands.len();
                // Some vendor tables append opaque data after the country
                // records. Linux stops at the first non-fitting record.
                while rules.len() > 16 {
                    let size = usize::from(u16::from_le_bytes([rules[4], rules[5]]));
                    let Some(rule) = rules.get(..6 + size) else {
                        break;
                    };
                    rules = &rules[6 + size..];
                    if &rule[..2] != b"00" {
                        continue;
                    }
                    if size + 76 > MAX_FRAME - 64 || commands.len() >= 64 {
                        return Err(Error::UnsupportedFirmware);
                    }
                    let mut body = vec![0u8; 76 + size];
                    let length = body.len() as u16;
                    body[0] = 1;
                    body[2..4].copy_from_slice(&length.to_le_bytes());
                    body[4] = index as u8;
                    body[5] = 1; // ENVIRON_INDOOR, world fallback.
                    body[7] = u8::from(response);
                    body[8..12].copy_from_slice(&rule[..4]);
                    body[76..].copy_from_slice(&rule[6..]);
                    commands.push(body);
                }
                if commands.len() == before {
                    return Err(Error::UnsupportedFirmware);
                }
            }
        }
        Ok(commands)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Command {
    Ce { id: u8, query: bool },
    Extended { id: u8, query: bool },
    Unified { id: u16 },
}
impl Command {
    pub(super) fn encode(self, seq: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
        let header = if matches!(self, Self::Unified { .. }) {
            48
        } else {
            64
        };
        if seq == 0 || seq > 15 || body.len() > MAX_FRAME - header {
            return Err(Error::Bounds);
        }
        let mut frame = vec![0; header + body.len()];
        let len = frame.len();
        frame[..4].copy_from_slice(&((len as u32) | 0x41000000).to_le_bytes());
        frame[4..8].copy_from_slice(&0x80010000u32.to_le_bytes());
        frame[32..34].copy_from_slice(&((len - 32) as u16).to_le_bytes());
        frame[37] = 0xa0;
        frame[39] = seq;
        match self {
            Self::Ce { id, query } | Self::Extended { id, query } => {
                frame[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
                frame[38] = u8::from(!query); // MCU_Q_QUERY=0, MCU_Q_SET=1.
                if matches!(self, Self::Extended { .. }) {
                    frame[36] = 0xed;
                    frame[41] = id;
                    frame[43] = 1;
                } else {
                    frame[36] = id;
                }
            }
            Self::Unified { id } => {
                frame[34..36].copy_from_slice(&id.to_le_bytes());
                frame[43] = 7; // ACK | unified | set.
            }
        }
        frame[header..].copy_from_slice(body);
        Ok(frame)
    }
}

fn unsolicited(frame: &[u8]) -> bool {
    frame[29] == 0
        || frame[30] & 4 != 0
        || frame[32] == 0x87
        || matches!(
            frame[28],
            0x07 | 0x0d | 0x0f | 0x13 | 0x23 | 0x27 | 0x96 | 0xf0
        )
}

impl<B: Backend> Session<B> {
    pub(super) async fn exchange(
        &mut self,
        command: Command,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.seq = self.seq % 15 + 1;
        let seq = self.seq;
        self.send(false, &command.encode(seq, body)?).await?;
        let start = self.backend.now_ns();
        loop {
            let left = (TIMEOUT_MS * 1_000_000)
                .saturating_sub(self.backend.now_ns().saturating_sub(start));
            if left < 1_000_000 {
                return Err(Error::Timeout);
            }
            let mut event = self.wait(left / 1_000_000, Backend::receive).await?;
            if event.len() < 36 {
                return Err(Error::MalformedEvent);
            }
            let len = usize::from(u16::from_le_bytes([event[24], event[25]])) + 24;
            if len < 36 || len > event.len() {
                return Err(Error::MalformedEvent);
            }
            event.truncate(len);
            if event[29] != seq || unsolicited(&event) {
                if self.events.len() == MAX_EVENTS {
                    return Err(Error::EventOverflow);
                }
                self.events.push_back(event);
                continue;
            }
            match command {
                Command::Ce {
                    id: 0xc0,
                    query: true,
                } => {
                    if event[28] != 5 || len != 44 {
                        return Err(Error::MalformedEvent);
                    }
                }
                Command::Extended { id, query: true } => {
                    if event[28] != 0xed || event[32] != id {
                        return Err(Error::MalformedEvent);
                    }
                }
                Command::Unified { id } => {
                    if event[28] != 1 || len < 44 || u16::from(event[36]) != id {
                        return Err(Error::MalformedEvent);
                    }
                    let status = u32::from_le_bytes(event[40..44].try_into().unwrap());
                    if status != 0 {
                        return Err(Error::RejectedCommand(status));
                    }
                }
                // CE and extended-set responses follow Linux's sequence match.
                _ => {}
            }
            return Ok(event.split_off(36));
        }
    }

    pub(super) async fn efuse_block(&mut self, address: u32) -> Result<[u8; 16], Error> {
        if address & 15 != 0 || address > 0xff0 {
            return Err(Error::Bounds);
        }
        let mut request = [0; 24];
        request[..4].copy_from_slice(&address.to_le_bytes());
        let response = self
            .exchange(Command::Extended { id: 1, query: true }, &request)
            .await?;
        if response.len() < 24
            || response[..4] != address.to_le_bytes()
            || u32::from_le_bytes(response[4..8].try_into().unwrap()) != 1
        {
            return Err(Error::InvalidIdentity);
        }
        Ok(response[8..24].try_into().unwrap())
    }

    pub(super) async fn initialize_radio(&mut self) -> Result<RadioInfo, Error> {
        let State::Ready(firmware) = self.state else {
            return Err(Error::Busy);
        };
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.stage(Stage::NicCapabilities);
            let response = self
                .exchange(
                    Command::Ce {
                        id: 0x8a,
                        query: false,
                    },
                    &[],
                )
                .await?;
            let capabilities = NicCapabilities::parse(&response)?;
            self.stage(Stage::Efuse);
            let block = self.efuse_block(0x550).await?;
            self.stage(Stage::CountryLimits);
            let responses = capabilities.chip_capabilities & 1 != 0;
            let commands = self.firmware.world_limits(block[11], responses)?;
            let mut channel_configuration = None;
            for body in &commands {
                let command = Command::Ce {
                    id: 0x5c,
                    query: false,
                };
                if responses {
                    let reply = self.exchange(command, body).await?;
                    // Four-byte prefix then mt7921_clc_info_tlv.
                    if reply.len() < 12 {
                        return Err(Error::MalformedEvent);
                    }
                    let size = usize::from(u16::from_le_bytes([reply[6], reply[7]]));
                    if size < 5 || size + 4 > reply.len() {
                        return Err(Error::MalformedEvent);
                    }
                    channel_configuration = Some(reply[8]);
                } else {
                    self.seq = self.seq % 15 + 1;
                    self.send(false, &command.encode(self.seq, body)?).await?;
                }
            }
            self.stage(Stage::EepromMode);
            // EE_MODE_EFUSE=0, EE_FORMAT_WHOLE=1, len=0.
            self.exchange(
                Command::Extended {
                    id: 0x21,
                    query: false,
                },
                &[0, 1, 0, 0],
            )
            .await?;
            self.stage(Stage::MacInitialize);
            self.backend.configure_mac()?;
            for index in 0..20 {
                self.backend.clear_wtbl(index)?;
                self.wait(5, |backend| {
                    backend.wtbl_idle().map(|idle| idle.then_some(()))
                })
                .await?;
            }
            let mut rts = [0u8; 12];
            rts[0] = 1;
            rts[4..8].copy_from_slice(&0x92bu32.to_le_bytes());
            rts[8..12].copy_from_slice(&2u32.to_le_bytes());
            self.exchange(
                Command::Extended {
                    id: 0x3e,
                    query: false,
                },
                &rts,
            )
            .await?;
            Ok(RadioInfo {
                firmware,
                capabilities,
                hardware_type: block[11],
                world_limit_commands: commands.len() as u16,
                channel_configuration,
            })
        }
        .await;
        match result {
            Ok(info) => {
                self.state = State::RadioReady(info);
                Ok(info)
            }
            Err(error) => {
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::NicCapabilities,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }
}
