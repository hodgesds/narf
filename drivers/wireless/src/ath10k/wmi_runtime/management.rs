// SPDX-License-Identifier: GPL-2.0-or-later
//! Initial station MLME transport. A CE receipt never retires referenced DMA.
use super::{wire, Error};
use crate::ath10k::{
    dma::{barrier, Memory},
    htt_runtime::Error as DmaError,
    wmi_boot::{Capabilities, Dialect},
};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Path {
    Htt,
    Inline(u32),
    Reference,
}
pub(super) fn path(dialect: Dialect, features: u64, caps: &Capabilities) -> Result<Path, Error> {
    // mac.c::ath10k_mac_tx_h_get_txpath; MGMT_TX_WMI is TLV wire service76.
    if features & (1 << 2) == 0 && !(dialect == Dialect::Tlv && caps.service(dialect, 76)) {
        return Ok(Path::Htt);
    }
    if features & (1 << 18) != 0 {
        return if dialect == Dialect::Tlv {
            Ok(Path::Reference)
        } else {
            Err(Error::Unsupported)
        };
    }
    Ok(Path::Inline(match dialect {
        Dialect::Main => 0x7006,
        Dialect::TenOne => 0x9028,
        Dialect::TenTwo | Dialect::TenTwoFour => 0x9029,
        Dialect::TenFour => 0x9031,
        // Linux has no TLV gen_mgmt_tx operation; it uses HTT or by-reference.
        Dialect::Tlv => return Err(Error::Unsupported),
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub token: Token,
    /// Inline WMI reports only transport submission. No fabricated air ACK.
    pub terminal_expected: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Inline,
    Htt(u16),
    Wmi(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub id: u32,
    pub status: u32,
}
pub(super) fn validate(frame: &[u8], own: [u8; 6], bssid: [u8; 6]) -> Result<(), Error> {
    if !(24..=2304).contains(&frame.len())
        || frame[1] != 0
        || frame[22] & 15 != 0
        || frame[4..10] != bssid
        || frame[10..16] != own
        || frame[16..22] != bssid
    {
        return Err(Error::Malformed);
    }
    match frame[0] {
        // Initial unprotected Open-System Authentication, transaction1 only.
        0xb0 if frame.len() == 30 && frame[24..30] == [0, 0, 1, 0, 0, 0] => Ok(()),
        // Association Request fixed capability/listen interval followed by IEs.
        0 if frame.len() >= 28 => {
            let mut ies = &frame[28..];
            let mut ssid = false;
            let mut rates = false;
            while !ies.is_empty() {
                let h = ies.get(..2).ok_or(Error::Malformed)?;
                let n = usize::from(h[1]);
                match h[0] {
                    0 => {
                        if ssid || n > 32 {
                            return Err(Error::Malformed);
                        }
                        ssid = true;
                    }
                    1 => {
                        if rates || n == 0 || n > 8 {
                            return Err(Error::Malformed);
                        }
                        rates = true;
                    }
                    _ => {}
                }
                ies = ies.get(2 + n..).ok_or(Error::Malformed)?;
            }
            if ssid && rates {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
        }
        _ => Err(Error::Unsupported),
    }
}
pub(super) fn inline(command: u32, frame: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = wire::packet(command, 24 + frame.len().div_ceil(4) * 4)?;
    out[8..14].copy_from_slice(&frame[4..10]); // padded wmi_mac_addr after vdev0.
    wire::put(&mut out, 24, frame.len() as u32);
    out[28..28 + frame.len()].copy_from_slice(frame);
    Ok(out)
}
pub(super) fn reference(id: u32, address: u64, frame: &[u8]) -> Result<Vec<u8>, Error> {
    if address == 0
        || address
            .checked_add(frame.len() as u64)
            .is_none_or(|end| end > 1 << 32)
    {
        return Err(Error::Malformed);
    }
    let prefix = frame.len().min(64).div_ceil(4) * 4;
    let mut out = wire::packet(0x7008, 36 + prefix)?;
    wire::put(&mut out, 4, (422 << 16) | 28);
    wire::put(&mut out, 12, id);
    wire::put(&mut out, 20, address as u32);
    wire::put(&mut out, 24, (address >> 32) as u32);
    wire::put(&mut out, 28, frame.len() as u32);
    wire::put(&mut out, 32, prefix as u32);
    wire::put(&mut out, 36, (17 << 16) | prefix as u32);
    let copy = frame.len().min(64);
    out[40..40 + copy].copy_from_slice(&frame[..copy]);
    Ok(out)
}
/// The firmware uses repeated ARRAY_UINT32 tags in the bundled event. Decode
/// every length/status before any ID can retire memory.
pub(super) fn completions(event: &[u8]) -> Result<Option<Vec<Completion>>, Error> {
    let id = wire::word(event, 0)? & 0xffffff;
    if !matches!(id, 0x7006 | 0x7007) {
        return Ok(None);
    }
    let mut input = &event[4..];
    let mut fixed = None;
    let mut arrays = [None; 4];
    let mut count = 0;
    while !input.is_empty() {
        let h = wire::word(input, 0)?;
        let len = (h & 0xffff) as usize;
        let body = input.get(4..4 + len).ok_or(Error::Malformed)?;
        input = input.get(4 + len..).ok_or(Error::Malformed)?;
        if len & 3 != 0 {
            return Err(Error::Malformed);
        }
        match h >> 16 {
            423 if id == 0x7006 => {
                if fixed.replace(body).is_some() {
                    return Err(Error::Malformed);
                }
            }
            552 if id == 0x7007 => {
                if fixed.replace(body).is_some() {
                    return Err(Error::Malformed);
                }
            }
            16 if id == 0x7007 => {
                if count == 4 {
                    return Err(Error::Malformed);
                }
                arrays[count] = Some(body);
                count += 1;
            }
            _ => {}
        }
    }
    let fixed = fixed.ok_or(Error::Malformed)?;
    let mut result = Vec::new();
    if id == 0x7006 {
        if !matches!(fixed.len(), 16 | 20) {
            return Err(Error::Malformed);
        }
        result.try_reserve_exact(1).map_err(|_| Error::NoMemory)?;
        result.push(Completion {
            id: wire::word(fixed, 0)?,
            status: wire::word(fixed, 4)?,
        });
    } else {
        if fixed.len() != 4 || count < 2 {
            return Err(Error::Malformed);
        }
        let n = wire::word(fixed, 0)? as usize;
        if n == 0
            || n > 128
            || arrays[..count]
                .iter()
                .any(|a| a.is_none_or(|a| a.len() != n * 4))
        {
            return Err(Error::Malformed);
        }
        result.try_reserve_exact(n).map_err(|_| Error::NoMemory)?;
        for i in 0..n {
            result.push(Completion {
                id: wire::word(arrays[0].unwrap(), i * 4)?,
                status: wire::word(arrays[1].unwrap(), i * 4)?,
            });
        }
    }
    if result
        .iter()
        .enumerate()
        .any(|(i, r)| result[..i].iter().any(|prior| prior.id == r.id))
    {
        return Err(Error::Malformed);
    }
    Ok(Some(result))
}
#[derive(Debug)]
struct Pending<B> {
    id: u32,
    _payload: B,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Pool<B> {
    slots: Vec<Option<Pending<B>>>,
    next: u32,
}
impl<B: Memory> Pool<B> {
    pub fn new() -> Result<Self, DmaError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(128)
            .map_err(|_| DmaError::NoMemory)?;
        slots.extend(core::iter::repeat_with(|| None).take(128));
        Ok(Self { slots, next: 0 })
    }
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|p| p.is_some()).count()
    }
    /// The mission owner retains a newly copied payload even if authority
    /// disappears during allocation/copy. Its address never escapes then.
    pub fn prepare_authorized(
        &mut self,
        frame: &[u8],
        mut authorized: impl FnMut() -> bool,
        allocate: impl FnMut(usize) -> Result<B, DmaError>,
    ) -> Result<(u32, u64), DmaError> {
        if !authorized() {
            return Err(DmaError::Memory);
        }
        let result = self.prepare(frame, allocate)?;
        if !authorized() {
            return Err(DmaError::Memory);
        }
        Ok(result)
    }
    pub fn prepare(
        &mut self,
        frame: &[u8],
        mut allocate: impl FnMut(usize) -> Result<B, DmaError>,
    ) -> Result<(u32, u64), DmaError> {
        if !(24..=2304).contains(&frame.len()) {
            return Err(DmaError::Malformed);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(DmaError::Busy)?;
        let next = self.next.checked_add(1).ok_or(DmaError::Busy)?;
        let size = frame.len().max(frame.len().min(64).div_ceil(4) * 4);
        let mut payload = allocate(size)?;
        if payload.len() < size
            || payload.dma_address() == 0
            || payload
                .dma_address()
                .checked_add(size as u64)
                .is_none_or(|a| a > 1 << 32)
        {
            return Err(DmaError::Memory);
        }
        for i in 0..size {
            payload.write(i, frame.get(i).copied().unwrap_or(0));
        }
        let address = payload.dma_address();
        self.slots[slot] = Some(Pending {
            id: self.next,
            _payload: payload,
        });
        let id = self.next;
        self.next = next;
        barrier();
        Ok((id, address))
    }
    pub fn complete(&mut self, ids: &[u32]) -> Result<(), DmaError> {
        if ids.is_empty()
            || ids.len() > 128
            || ids.iter().enumerate().any(|(i, id)| {
                ids[..i].contains(id)
                    || !self
                        .slots
                        .iter()
                        .any(|s| s.as_ref().is_some_and(|p| p.id == *id))
            })
        {
            return Err(DmaError::Malformed);
        }
        barrier();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|p| ids.contains(&p.id)) {
                *slot = None;
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "management_tests.rs"]
mod tests;
