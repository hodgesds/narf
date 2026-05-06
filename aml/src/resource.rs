//! AML resource template (_CRS) and PCI routing table (_PRT) decoders.
//!
//! Pure byte/struct decoders — no global state, no hardware side effects.
//! ACPI 6.5 §6.4 (Resource Data Types) for the buffer format.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ── Public types ────────────────────────────────────────────────────────────

/// A decoded resource descriptor from a _CRS buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceItem {
    /// Small IRQ Descriptor (small tag type 4): IRQ mask (u16), optional flags (u8).
    Irq { mask: u16, flags: Option<u8> },
    /// Small DMA Descriptor (small tag type 5): channel mask (u8), flags (u8).
    Dma { mask: u8, flags: u8 },
    /// Small IO Port Descriptor (small tag type 8): info (u8), min, max, alignment, length.
    Io {
        info: u8,
        min: u16,
        max: u16,
        alignment: u8,
        length: u8,
    },
    /// Small Fixed IO Port Descriptor (small tag type 9): base (u16), length (u8).
    FixedIo { base: u16, length: u8 },
    /// Large 32-bit Memory Range Descriptor (large tag 0x05): info, min, max, alignment, length.
    Memory32 {
        info: u8,
        min: u32,
        max: u32,
        alignment: u32,
        length: u32,
    },
    /// Large 32-bit Fixed Memory Range Descriptor (large tag 0x06): info, base, length.
    Memory32Fixed { info: u8, base: u32, length: u32 },
    /// Large 32-bit Address Space Descriptor (large tag 0x07): kind, flags, type-specific flags,
    /// granularity, min, max, translation, length.
    AddressSpace32 {
        kind: u8,
        flags: u8,
        type_flags: u8,
        granularity: u32,
        min: u32,
        max: u32,
        translation: u32,
        length: u32,
    },
    /// Large 64-bit Address Space Descriptor (large tag 0x08): same fields but u64.
    AddressSpace64 {
        kind: u8,
        flags: u8,
        type_flags: u8,
        granularity: u64,
        min: u64,
        max: u64,
        translation: u64,
        length: u64,
    },
    /// Large Extended Interrupt Descriptor (large tag 0x09): flags, GSI list.
    ExtendedIrq { flags: u8, gsis: Vec<u32> },
    /// EndTag — small tag 0x79. Emitted so callers can verify termination.
    EndTag,
    /// Any descriptor type we don't decode. Carries the raw tag byte and payload.
    Unknown { tag: u8, payload: Vec<u8> },
}

/// Errors from resource template decoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// Buffer ran out before EndTag (or mid-descriptor).
    Truncated,
    /// Tag byte value is structurally impossible.
    BadTag,
    /// Buffer contained valid descriptors but no EndTag.
    NoEndTag,
}

/// A single entry from a _PRT (PCI Routing Table) result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrtEntry {
    /// PCI device address: `(slot << 16) | function`. Typically function = 0xFFFF.
    pub address: u64,
    /// Interrupt pin: 0=INTA, 1=INTB, 2=INTC, 3=INTD.
    pub pin: u8,
    /// Named interrupt source (e.g. "\\_SB.LNKB"). None when the source field was integer 0.
    pub source: Option<String>,
    /// When source is None, this is the GSI directly. When source is Some, it is the
    /// source index within the named link device.
    pub source_index: u32,
}

// ── Resource template decoder ────────────────────────────────────────────────

/// Decode an ACPI resource template buffer (as from _CRS) into a list of
/// `ResourceItem`s.
///
/// Walks the buffer descriptor-by-descriptor. Stops after `EndTag`. Returns
/// `Err(Truncated)` if the buffer is exhausted before `EndTag`. Unknown
/// descriptor types are pushed as `Unknown { tag, payload }` and decoding
/// continues.
pub fn decode_resource_template(buf: &[u8]) -> Result<Vec<ResourceItem>, ResourceError> {
    let mut items: Vec<ResourceItem> = Vec::new();
    let mut pos = 0usize;

    loop {
        if pos >= buf.len() {
            // No EndTag seen — truncated or missing.
            return Err(ResourceError::Truncated);
        }

        let tag = buf[pos];

        // EndTag: small tag 0x79 = 0b0_1111_001 (type=0xF, len=1).
        // The full byte 0x79 uniquely identifies it.
        if tag == 0x79 {
            // Consume the tag + 1-byte checksum.
            if pos + 1 >= buf.len() {
                return Err(ResourceError::Truncated);
            }
            // checksum byte at pos+1 — we ignore it per spec
            items.push(ResourceItem::EndTag);
            return Ok(items);
        }

        if tag & 0x80 == 0 {
            // ── Small tag ──────────────────────────────────────────────────
            // Bit layout: 0b0_TTTT_LLL
            let item_type = (tag >> 3) & 0x0F;
            let payload_len = (tag & 0x07) as usize;

            pos += 1; // consume tag byte
            if pos + payload_len > buf.len() {
                return Err(ResourceError::Truncated);
            }
            let payload = &buf[pos..pos + payload_len];
            pos += payload_len;

            match item_type {
                // IRQ Descriptor (type 4), payload 2 or 3 bytes
                4 => {
                    if payload_len < 2 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let mask = u16::from_le_bytes([payload[0], payload[1]]);
                        let flags = if payload_len >= 3 {
                            Some(payload[2])
                        } else {
                            None
                        };
                        items.push(ResourceItem::Irq { mask, flags });
                    }
                }
                // DMA Descriptor (type 5), payload 2 bytes
                5 => {
                    if payload_len < 2 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        items.push(ResourceItem::Dma {
                            mask: payload[0],
                            flags: payload[1],
                        });
                    }
                }
                // IO Port Descriptor (type 8), payload 7 bytes
                8 => {
                    if payload_len < 7 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let info = payload[0];
                        let min = u16::from_le_bytes([payload[1], payload[2]]);
                        let max = u16::from_le_bytes([payload[3], payload[4]]);
                        let alignment = payload[5];
                        let length = payload[6];
                        items.push(ResourceItem::Io {
                            info,
                            min,
                            max,
                            alignment,
                            length,
                        });
                    }
                }
                // Fixed IO Port Descriptor (type 9), payload 3 bytes
                9 => {
                    if payload_len < 3 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let base = u16::from_le_bytes([payload[0], payload[1]]);
                        let length = payload[2];
                        items.push(ResourceItem::FixedIo { base, length });
                    }
                }
                _ => {
                    items.push(ResourceItem::Unknown {
                        tag,
                        payload: payload.to_vec(),
                    });
                }
            }
        } else {
            // ── Large tag ──────────────────────────────────────────────────
            // Bit layout: 0b1_TTTTTTT
            let item_type = tag & 0x7F;

            pos += 1; // consume tag byte
            if pos + 2 > buf.len() {
                return Err(ResourceError::Truncated);
            }
            let payload_len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2; // consume 2-byte length

            if pos + payload_len > buf.len() {
                return Err(ResourceError::Truncated);
            }
            let payload = &buf[pos..pos + payload_len];
            pos += payload_len;

            match item_type {
                // Large tag 0x05 = 32-bit Memory Range Descriptor, 17 bytes payload
                0x05 => {
                    if payload_len < 17 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let info = payload[0];
                        let min =
                            u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let max =
                            u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]);
                        let alignment =
                            u32::from_le_bytes([payload[9], payload[10], payload[11], payload[12]]);
                        let length = u32::from_le_bytes([
                            payload[13],
                            payload[14],
                            payload[15],
                            payload[16],
                        ]);
                        items.push(ResourceItem::Memory32 {
                            info,
                            min,
                            max,
                            alignment,
                            length,
                        });
                    }
                }
                // Large tag 0x06 = 32-bit Fixed Memory Range Descriptor, 9 bytes payload
                0x06 => {
                    if payload_len < 9 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let info = payload[0];
                        let base =
                            u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let length =
                            u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]);
                        items.push(ResourceItem::Memory32Fixed { info, base, length });
                    }
                }
                // Large tag 0x07 = 32-bit Address Space Descriptor, ≥26 bytes payload
                0x07 => {
                    if payload_len < 26 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let kind = payload[0];
                        let flags = payload[1];
                        let type_flags = payload[2];
                        let granularity =
                            u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
                        let min =
                            u32::from_le_bytes([payload[7], payload[8], payload[9], payload[10]]);
                        let max = u32::from_le_bytes([
                            payload[11],
                            payload[12],
                            payload[13],
                            payload[14],
                        ]);
                        let translation = u32::from_le_bytes([
                            payload[15],
                            payload[16],
                            payload[17],
                            payload[18],
                        ]);
                        let length = u32::from_le_bytes([
                            payload[19],
                            payload[20],
                            payload[21],
                            payload[22],
                        ]);
                        items.push(ResourceItem::AddressSpace32 {
                            kind,
                            flags,
                            type_flags,
                            granularity,
                            min,
                            max,
                            translation,
                            length,
                        });
                    }
                }
                // Large tag 0x08 = 64-bit Address Space Descriptor, ≥43 bytes payload
                0x08 => {
                    if payload_len < 43 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let kind = payload[0];
                        let flags = payload[1];
                        let type_flags = payload[2];
                        let granularity = u64::from_le_bytes([
                            payload[3],
                            payload[4],
                            payload[5],
                            payload[6],
                            payload[7],
                            payload[8],
                            payload[9],
                            payload[10],
                        ]);
                        let min = u64::from_le_bytes([
                            payload[11],
                            payload[12],
                            payload[13],
                            payload[14],
                            payload[15],
                            payload[16],
                            payload[17],
                            payload[18],
                        ]);
                        let max = u64::from_le_bytes([
                            payload[19],
                            payload[20],
                            payload[21],
                            payload[22],
                            payload[23],
                            payload[24],
                            payload[25],
                            payload[26],
                        ]);
                        let translation = u64::from_le_bytes([
                            payload[27],
                            payload[28],
                            payload[29],
                            payload[30],
                            payload[31],
                            payload[32],
                            payload[33],
                            payload[34],
                        ]);
                        let length = u64::from_le_bytes([
                            payload[35],
                            payload[36],
                            payload[37],
                            payload[38],
                            payload[39],
                            payload[40],
                            payload[41],
                            payload[42],
                        ]);
                        items.push(ResourceItem::AddressSpace64 {
                            kind,
                            flags,
                            type_flags,
                            granularity,
                            min,
                            max,
                            translation,
                            length,
                        });
                    }
                }
                // Large tag 0x09 = Extended Interrupt Descriptor
                // Payload: flags(1), count(1), count*4 bytes of GSIs, [ResourceSourceIndex + Source]
                0x09 => {
                    if payload_len < 2 {
                        items.push(ResourceItem::Unknown {
                            tag,
                            payload: payload.to_vec(),
                        });
                    } else {
                        let flags = payload[0];
                        let count = payload[1] as usize;
                        if payload_len < 2 + count * 4 {
                            items.push(ResourceItem::Unknown {
                                tag,
                                payload: payload.to_vec(),
                            });
                        } else {
                            let mut gsis = Vec::with_capacity(count);
                            for i in 0..count {
                                let off = 2 + i * 4;
                                gsis.push(u32::from_le_bytes([
                                    payload[off],
                                    payload[off + 1],
                                    payload[off + 2],
                                    payload[off + 3],
                                ]));
                            }
                            items.push(ResourceItem::ExtendedIrq { flags, gsis });
                        }
                    }
                }
                _ => {
                    items.push(ResourceItem::Unknown {
                        tag,
                        payload: payload.to_vec(),
                    });
                }
            }
        }
    }
}

// ── _PRT decoder ─────────────────────────────────────────────────────────────

/// Decode a _PRT result.
///
/// The caller passes the outer Package's elements as a slice of `Value`s. Each
/// must itself be a `Value::Package` of exactly 4 elements:
///
/// 1. Address (integer) — PCI device address `(slot << 16) | function`.
/// 2. Pin (integer) — 0=INTA, 1=INTB, 2=INTC, 3=INTD.
/// 3. Source — `Value::Integer(0)` (no named source) or `Value::String(s)`.
/// 4. Source Index (integer).
pub fn decode_prt(items: &[crate::Value]) -> Result<Vec<PrtEntry>, ResourceError> {
    let mut entries = Vec::with_capacity(items.len());

    for item in items {
        let inner = match item {
            crate::Value::Package(v) => v,
            _ => return Err(ResourceError::BadTag),
        };

        if inner.len() < 4 {
            return Err(ResourceError::Truncated);
        }

        let address = inner[0].as_integer();
        let pin = inner[1].as_integer() as u8;
        let source_index = inner[3].as_integer() as u32;

        let source = match &inner[2] {
            crate::Value::Integer(0) => None,
            crate::Value::String(s) => Some(s.clone()),
            // Any other integer (besides 0) or buffer: treat as no named source.
            crate::Value::Integer(_) => None,
            _ => None,
        };

        entries.push(PrtEntry {
            address,
            pin,
            source,
            source_index,
        });
    }

    Ok(entries)
}
