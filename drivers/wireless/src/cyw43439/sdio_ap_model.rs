// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal AI/F1/F2 device behind actual SDHCI Card and SDPCM/BCDC. Only
//! firmware bytes are modeled; no host Fullmac/Device/source method replaced.
use crate::brcmfmac::runtime_tests::station_model::{ap_model::Profile, sdio_ap::Firmware};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec,
    vec::Vec,
};
use narf_drivers_sdio::{card::tests::endpoint::Endpoint, SdioError};
use narf_lib::sync::IrqSafeSpinLock;
const CORE: u32 = 0x18011000;
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
struct State {
    firmware: Firmware,
    window: u32,
    registers: BTreeMap<u32, u32>,
    direct: BTreeMap<u32, u8>,
    receive: VecDeque<Vec<u8>>,
    read: usize,
    transmit: Vec<u8>,
    sequence: u8,
    credit: u8,
    drops: usize,
    commands: Vec<(u32, Vec<u8>)>,
    /// BCDC ifidx of each entry of `commands`.
    command_ifidx: Vec<u8>,
    packets: usize,
    revoke_after_chunk: Option<Arc<crate::brcmfmac::provision::Proof>>,
    revoke_before_command: Option<Arc<crate::brcmfmac::provision::Proof>>,
    loss_before_command: Option<[u8; 6]>,
    physical_packets: Vec<Vec<u8>>,
}
impl State {
    fn packet(&mut self, channel: u8, payload: &[u8]) {
        let length = 12 + payload.len();
        let mut bytes = vec![0; length.max(64).next_multiple_of(4)];
        bytes[..2].copy_from_slice(&(length as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(!(length as u16)).to_le_bytes());
        bytes[4] = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        bytes[5] = channel;
        bytes[7] = 12;
        bytes[9] = self.credit;
        bytes[12..12 + payload.len()].copy_from_slice(payload);
        self.receive.push_back(bytes);
    }
    fn outputs(&mut self) {
        let (events, data) = self.firmware.outputs();
        for (channel, outputs) in [(1, events), (2, data)] {
            for body in outputs {
                let mut payload = vec![0x20, 0, 0, 0];
                payload.extend(body);
                self.packet(channel, &payload);
            }
        }
    }
    fn consume(&mut self, packet: &[u8]) -> Result<(), SdioError> {
        if packet.len() < 12 || packet[7] != 12 || packet[5] & 0xf0 != 0 {
            return Err(SdioError::HostError);
        }
        self.credit = packet[4].wrapping_add(16);
        match packet[5] {
            0 => {
                if packet.len() < 28 {
                    return Err(SdioError::HostError);
                }
                let id = word(packet, 12);
                let maximum = word(packet, 16);
                let flags = word(packet, 20);
                // BCDC_DCMD_IF_SHIFT: ifidx 0 or the modeled secondary 1.
                let ifidx = (flags >> 12) & 0xf;
                if ifidx > 1 || maximum > 8192 {
                    return Err(SdioError::HostError);
                }
                let input = &packet[28..];
                self.commands.push((id, input.to_vec()));
                self.command_ifidx.push(ifidx as u8);
                if let Some((response, status)) =
                    self.firmware
                        .command(ifidx as u8, id, input, maximum as u16)
                {
                    if response.len() > maximum as usize {
                        return Err(SdioError::HostError);
                    }
                    let mut payload = Vec::new();
                    payload.extend(id.to_le_bytes());
                    payload.extend((response.len() as u32).to_le_bytes());
                    payload.extend(((flags & !1) | u32::from(status != 0)).to_le_bytes());
                    payload.extend((i32::from(status) as u32).to_le_bytes());
                    payload.extend(response);
                    self.packet(0, &payload);
                }
            }
            2 => {
                // BDC flags2 carries the interface (0 or 1).
                if packet.len() < 30 || packet[12] != 0x20 || packet[14] > 1 || packet[15] != 0 {
                    return Err(SdioError::HostError);
                }
                self.firmware.transmit(packet[14], &packet[16..]);
                self.packets += 1;
                self.packet(0, &[]); // real flow-control credit, never air ACK.
            }
            _ => return Err(SdioError::Unsupported),
        }
        self.outputs();
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct Handle(Arc<IrqSafeSpinLock<State>>);
impl Handle {
    pub(super) fn change<T>(&self, action: impl FnOnce(&mut Profile) -> T) -> T {
        let mut state = self.0.lock();
        let result = action(state.firmware.profile());
        state.outputs();
        result
    }
    pub(super) fn capability(&self, bytes: &[u8]) {
        self.0.lock().firmware.capability(bytes);
    }
    pub(super) fn commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.0.lock().commands.clone()
    }
    /// BCDC ifidx of each IOCTL, parallel to [`Self::commands`].
    pub(super) fn command_ifidx(&self) -> Vec<u8> {
        self.0.lock().command_ifidx.clone()
    }
    /// Create ifidx 1 as a firmware-SME AP.
    pub(super) fn enable_vif_ap(&self) {
        self.0.lock().firmware.enable_vif_ap();
    }
    /// Apply `action` to the secondary AP model.
    pub(super) fn vif_change<T>(&self, action: impl FnOnce(&mut Profile) -> T) -> T {
        let mut state = self.0.lock();
        let result = action(state.firmware.vif_profile());
        state.outputs();
        result
    }
    pub(super) fn physical_packets(&self) -> Vec<Vec<u8>> {
        self.0.lock().physical_packets.clone()
    }
    pub(super) fn loss_before_command(&self, peer: [u8; 6]) {
        self.0.lock().loss_before_command = Some(peer);
    }
    pub(super) fn revoke_before_command(&self, proof: Arc<crate::brcmfmac::provision::Proof>) {
        self.0.lock().revoke_before_command = Some(proof);
    }
    pub(super) fn packets(&self) -> usize {
        self.0.lock().packets
    }
    pub(super) fn drops(&self) -> usize {
        self.0.lock().drops
    }
    pub(super) fn partial(&self) -> usize {
        self.0.lock().transmit.len()
    }
    pub(super) fn revoke_after_chunk(&self, proof: Arc<crate::brcmfmac::provision::Proof>) {
        self.0.lock().revoke_after_chunk = Some(proof);
    }
}
pub(super) struct Device(Arc<IrqSafeSpinLock<State>>);
impl Drop for Device {
    fn drop(&mut self) {
        self.0.lock().drops += 1;
    }
}
impl Device {
    pub(super) fn new() -> (Self, Handle) {
        let mut state = State {
            firmware: Firmware::new(),
            window: 0,
            registers: BTreeMap::new(),
            direct: BTreeMap::new(),
            receive: VecDeque::new(),
            read: 0,
            transmit: Vec::new(),
            sequence: 0,
            credit: 16,
            drops: 0,
            commands: Vec::new(),
            command_ifidx: Vec::new(),
            packets: 0,
            revoke_after_chunk: None,
            revoke_before_command: None,
            loss_before_command: None,
            physical_packets: Vec::new(),
        };
        state.registers.insert(0x18000000, 0x1000a9af);
        state.registers.insert(0x180000fc, 0x18100000);
        let descriptors = [
            0x4bf80001, 0x18080001, 0x18000005, 0x18110085, 0x4bf82a01, 0x07080001, 0x18002005,
            0x18114085, 0x4bf80e01, 0x18080001, 0x18004005, 0x18116085, 0x4bf81201, 0x18080001,
            0x18003005, 0x18118085, 0x4bf82901, 0x18080001, 0x18011005, 0x1811a085, 0xf,
        ];
        for (index, value) in descriptors.into_iter().enumerate() {
            state.registers.insert(0x18100000 + index as u32 * 4, value);
        }
        state.registers.insert(0x18004000, 0x40);
        state.registers.insert(0x18004040, 7);
        state.packet(0, &[]);
        let state = Arc::new(IrqSafeSpinLock::new(state));
        (Self(state.clone()), Handle(state))
    }
}
impl Endpoint for Device {
    fn pending(&self) -> bool {
        !self.0.lock().receive.is_empty()
    }
    fn prepare_write(&mut self, function: u8) {
        if function == 2 {
            let mut state = self.0.lock();
            if let Some(peer) = state.loss_before_command.take() {
                state.firmware.profile().remove(peer);
                state.outputs();
            }
            if let Some(proof) = state.revoke_before_command.take() {
                crate::brcmfmac::provision::tests::revoke_fixture_calibration(&proof);
            }
        }
    }
    fn read52(&mut self, function: u8, address: u32) -> Result<u8, SdioError> {
        if function != 1 {
            return Err(SdioError::BadFunction);
        }
        let state = self.0.lock();
        let value = state.direct.get(&address).copied().unwrap_or(0);
        Ok(if address == 0x1000e {
            value | 0xc0
        } else {
            value
        })
    }
    fn write52(&mut self, function: u8, address: u32, value: u8) -> Result<(), SdioError> {
        if function != 1 {
            return Err(SdioError::BadFunction);
        }
        let mut state = self.0.lock();
        state.direct.insert(
            address,
            if address == 0x1001f {
                value | ((value & 1) << 1)
            } else {
                value
            },
        );
        let shift = match address {
            0x1000a => Some(8),
            0x1000b => Some(16),
            0x1000c => Some(24),
            _ => None,
        };
        if let Some(shift) = shift {
            state.window = (state.window & !(255 << shift)) | (u32::from(value) << shift);
        }
        Ok(())
    }
    fn read53(
        &mut self,
        function: u8,
        address: u32,
        increment: bool,
        length: usize,
    ) -> Result<Vec<u8>, SdioError> {
        let mut state = self.0.lock();
        state.outputs();
        if function == 2 {
            if address != 0x8000 || increment {
                return Err(SdioError::AddressOverflow);
            }
            let mut out = vec![0; length];
            if let Some(packet) = state.receive.front() {
                let end = state
                    .read
                    .checked_add(length)
                    .ok_or(SdioError::LengthOverflow)?;
                if end > packet.len() {
                    return Err(SdioError::LengthOverflow);
                }
                out.copy_from_slice(&packet[state.read..end]);
                state.read = end;
                if state
                    .receive
                    .front()
                    .is_some_and(|packet| state.read == packet.len())
                {
                    state.receive.pop_front();
                    state.read = 0;
                }
            }
            return Ok(out);
        }
        if function != 1 || length != 4 {
            return Err(SdioError::Unsupported);
        }
        let physical = state.window | (address & 0x7fff);
        let mut value = state.registers.get(&physical).copied().unwrap_or(0);
        if physical == CORE + 0x20 && !state.receive.is_empty() {
            value |= 1 << 6;
        }
        Ok(value.to_le_bytes().to_vec())
    }
    fn write53(
        &mut self,
        function: u8,
        address: u32,
        increment: bool,
        bytes: &[u8],
    ) -> Result<(), SdioError> {
        let mut state = self.0.lock();
        if function == 2 {
            if !increment || address != 0x8000 + state.transmit.len() as u32 {
                return Err(SdioError::AddressOverflow);
            }
            state.transmit.extend(bytes);
            if let Some(proof) = state.revoke_after_chunk.take() {
                crate::brcmfmac::provision::tests::revoke_fixture_calibration(&proof);
            }
            if state.transmit.len() >= 4 {
                let length =
                    usize::from(u16::from_le_bytes(state.transmit[..2].try_into().unwrap()));
                let inverse = u16::from_le_bytes(state.transmit[2..4].try_into().unwrap());
                if length < 12 || !(length as u16) != inverse {
                    return Err(SdioError::HostError);
                }
                let physical = length.next_multiple_of(4);
                let block_extent = length.next_multiple_of(512);
                if state.transmit.len() >= physical {
                    if (state.transmit.len() != physical && state.transmit.len() != block_extent)
                        || state.transmit[length..].iter().any(|byte| *byte != 0)
                    {
                        return Err(SdioError::LengthOverflow);
                    }
                    let packet = core::mem::take(&mut state.transmit);
                    state.physical_packets.push(packet.clone());
                    state.consume(&packet[..length])?;
                }
            }
            return Ok(());
        }
        if function != 1 || !increment || bytes.len() % 4 != 0 {
            return Err(SdioError::Unsupported);
        }
        let physical = state.window | (address & 0x7fff);
        for (index, bytes) in bytes.chunks_exact(4).enumerate() {
            let at = physical + index as u32 * 4;
            let value = u32::from_le_bytes(bytes.try_into().unwrap());
            if at == CORE + 0x20 {
                let previous = state.registers.get(&at).copied().unwrap_or(0);
                state.registers.insert(at, previous & !value);
            } else {
                state.registers.insert(at, value);
            }
        }
        Ok(())
    }
}
