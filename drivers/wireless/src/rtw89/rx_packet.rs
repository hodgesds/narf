// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked AX RXBD-info/RXD assembly for the initial RTL8852B profile.
//! Geometry follows pci.c::rtw89_pci_rxbd_deliver_skbs and
//! core.c::rtw89_core_query_rxdesc. Device bytes never become pointers.
use super::tx_transport::{self, Report};
use alloc::vec::Vec;

pub(super) const BUFFER_SIZE: usize = 11454 + 40 + 4;
const MAX_PACKET: usize = 11454;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Extent,
    Segment,
    Descriptor,
    Firmware,
    Report,
}
fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Extent)?
            .try_into()
            .map_err(|_| Error::Extent)?,
    ))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Descriptor {
    pub size: usize,
    pub offset: usize,
    pub kind: u8,
    pub rate: u16,
    pub bandwidth: u8,
    pub crc_error: bool,
    pub icv_error: bool,
    pub hardware_decrypted: bool,
    pub aggregate: bool,
}
impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let d0 = word(bytes, 4)?;
        let d1 = word(bytes, 8)?;
        let d3 = word(bytes, 16)?;
        // Linux's AX query uses desc_info.shift (zero), rather than reading
        // AX_RXD_SHIFT_MASK. This initial profile refuses nonzero shift bits
        // instead of silently applying a different layout from the reference.
        if d0 & 0xc000 != 0 || d0 & (1 << 22) != 0 {
            return Err(Error::Descriptor);
        }
        let length = if d0 & (1 << 31) == 0 { 16 } else { 32 };
        let offset = 4 + length + ((d0 >> 28) & 7) as usize * 8;
        if offset > bytes.len() {
            return Err(Error::Extent);
        }
        let size = (d0 & 0x3fff) as usize;
        if size > MAX_PACKET {
            return Err(Error::Extent);
        }
        Ok(Self {
            size,
            offset,
            kind: ((d0 >> 24) & 15) as u8,
            rate: ((d1 >> 16) & 0x1ff) as u16,
            bandwidth: (d1 >> 30) as u8,
            crc_error: d3 & (1 << 9) != 0,
            icv_error: d3 & (1 << 10) != 0,
            hardware_decrypted: d3 & 4 != 0,
            aggregate: d3 & ((1 << 3) | (1 << 5) | (1 << 6)) != 0,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ack {
    pub category: u8,
    pub class: u8,
    pub function: u8,
    pub sequence: u8,
    /// None is a receive acknowledgement, never execution completion.
    pub result: Option<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct C2h {
    pub category: u8,
    pub class: u8,
    pub function: u8,
    pub bytes: Vec<u8>,
}
impl C2h {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        let w0 = word(&bytes, 0)?;
        let w1 = word(&bytes, 4)?;
        // fw.h RTW89_C2H_HDR_W1_LEN counts the complete eight-byte envelope.
        if w1 & 0x3fff != bytes.len() as u32 || bytes.len() < 8 {
            return Err(Error::Firmware);
        }
        let result = Self {
            category: (w0 & 3) as u8,
            class: ((w0 >> 2) & 0x3f) as u8,
            function: ((w0 >> 8) & 0xff) as u8,
            bytes,
        };
        // Known MAC INFO acknowledgements have an actual third dword. Other
        // bounded messages remain available to their specific future handler.
        result.ack()?;
        Ok(result)
    }
    pub fn ack(&self) -> Result<Option<Ack>, Error> {
        if self.category != 1 || self.class != 0 || self.function > 1 {
            return Ok(None);
        }
        if self.bytes.len() != 12 {
            return Err(Error::Firmware);
        }
        let w2 = word(&self.bytes, 8)?;
        Ok(Some(Ack {
            category: (w2 & 3) as u8,
            class: ((w2 >> 2) & 0x3f) as u8,
            function: ((w2 >> 8) & 0xff) as u8,
            sequence: if self.function == 0 {
                (w2 >> 16) as u8
            } else {
                (w2 >> 24) as u8
            },
            result: (self.function == 1).then_some((w2 >> 16) as u8),
        }))
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// Exactly the native MPDU, after removing only its four-byte FCS.
    Wifi(Descriptor, Vec<u8>),
    Firmware(C2h),
    Releases(Vec<Report>),
    /// Bad FCS/ICV, unsupported aggregation/decryption/profile, PPDU or an
    /// unhandled bounded report does not become an ordinary station frame.
    Dropped,
}
struct Partial {
    descriptor: Descriptor,
    bytes: Vec<u8>,
}
#[derive(Default)]
pub(super) struct Assembler {
    partial: Option<Partial>,
}
impl Assembler {
    pub fn segment(&mut self, bytes: &[u8], reports: bool) -> Result<Option<Event>, Error> {
        let info = word(bytes, 0)?;
        let fs = info & (1 << 15) != 0;
        let ls = info & (1 << 14) != 0;
        let size = (info & 0x3fff) as usize;
        if !(4..=BUFFER_SIZE).contains(&size) || size > bytes.len() {
            return Err(Error::Extent);
        }
        let bytes = &bytes[..size];
        if reports {
            if !fs || !ls || self.partial.is_some() {
                return Err(Error::Segment);
            }
            let descriptor = Descriptor::parse(bytes)?;
            if descriptor.kind != 7 {
                return Err(Error::Report);
            }
            // Linux release_tx_skbs intentionally walks to RXBD write_size,
            // not RXD pkt_size: one RPQ DMA buffer can contain many records.
            let records = &bytes[descriptor.offset..];
            if records.is_empty() || records.len() % 4 != 0 {
                return Err(Error::Report);
            }
            let reports = records
                .chunks_exact(4)
                .map(tx_transport::parse_report)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::Report)?;
            return Ok(Some(Event::Releases(reports)));
        }
        if fs {
            if self.partial.is_some() {
                return Err(Error::Segment);
            }
            let descriptor = Descriptor::parse(bytes)?;
            if descriptor.size == 0 {
                return Err(Error::Extent);
            }
            self.partial = Some(Partial {
                descriptor,
                bytes: Vec::with_capacity(descriptor.size),
            });
        }
        let partial = self.partial.as_mut().ok_or(Error::Segment)?;
        let offset = if fs { partial.descriptor.offset } else { 4 };
        let payload = bytes.get(offset..).ok_or(Error::Extent)?;
        let remaining = partial.descriptor.size - partial.bytes.len();
        // Single-segment buffers may carry DMA alignment padding. Multi-
        // segment lengths must agree exactly; never borrow beyond write_size.
        let length = if fs && ls {
            if payload.len() < remaining {
                return Err(Error::Extent);
            }
            remaining
        } else {
            if payload.len() > remaining || (!ls && payload.len() == remaining) {
                return Err(Error::Extent);
            }
            payload.len()
        };
        partial.bytes.extend_from_slice(&payload[..length]);
        if !ls {
            return Ok(None);
        }
        let Partial {
            descriptor,
            mut bytes,
        } = self.partial.take().unwrap();
        if bytes.len() != descriptor.size {
            return Err(Error::Extent);
        }
        Ok(Some(match descriptor.kind {
            0 => {
                if descriptor.crc_error
                    || descriptor.icv_error
                    || descriptor.hardware_decrypted
                    || descriptor.aggregate
                    || descriptor.bandwidth != 0
                    || descriptor.rate > 11
                {
                    Event::Dropped
                } else {
                    if bytes.len() < 14 {
                        return Err(Error::Descriptor);
                    }
                    // core.c advertises RX_INCLUDES_FCS for this AX hardware.
                    bytes.truncate(bytes.len() - 4);
                    Event::Wifi(descriptor, bytes)
                }
            }
            10 => Event::Firmware(C2h::parse(bytes)?),
            _ => Event::Dropped,
        }))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rx_packet/tests.rs"]
mod tests;
