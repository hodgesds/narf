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
    /// Large GPIO Connection Descriptor (large tag 0x0C), Connection Type 0
    /// = Interrupt. ACPI 6.5 §6.4.3.8.1. Used by HID-over-I2C children that
    /// route their attention line through a host GPIO controller.
    GpioInt {
        /// `true` = level-triggered, `false` = edge-triggered (bit 0 of
        /// the Interrupt and IO Flags word).
        level_triggered: bool,
        /// 0 = active high, 1 = active low, 2 = active both (bits 1-2).
        polarity: u8,
        /// `true` = shared (bit 3).
        shared: bool,
        /// `true` = wake-capable (bit 4).
        wake: bool,
        /// 0 = default, 1 = pull-up, 2 = pull-down, 3 = pull-none
        /// (Pin Configuration byte).
        pin_config: u8,
        /// Debounce timeout in 10-µs units (zero = none).
        debounce_timeout: u16,
        /// Pin numbers within the parent GPIO controller's pin space.
        pins: Vec<u16>,
        /// AML path of the GPIO controller (`ResourceSource`); empty
        /// string when absent.
        resource_source: String,
        /// Index inside the named ResourceSource (typically 0).
        resource_source_index: u8,
    },
    /// Large GPIO Connection Descriptor (large tag 0x0C), Connection Type 1
    /// = IO. ACPI 6.5 §6.4.3.8.1. Used for GPIO output / programmable
    /// device-state pins (touchpad RESET#, sensor enable, etc.).
    GpioIo {
        /// 0 = exclusive, 1 = shared (bit 3 of IO flags).
        shared: bool,
        /// 0 = default, 1 = pull-up, 2 = pull-down, 3 = pull-none.
        pin_config: u8,
        /// Output drive strength in 10-µA units (zero = controller default).
        drive_strength: u16,
        /// Debounce timeout in 10-µs units.
        debounce_timeout: u16,
        /// Pin numbers within the parent GPIO controller's pin space.
        pins: Vec<u16>,
        /// AML path of the GPIO controller.
        resource_source: String,
        /// Index inside the named ResourceSource.
        resource_source_index: u8,
    },
    /// Large Serial Bus Connection Descriptor (large tag 0x0E) with Bus
    /// Type 1 = I2C. ACPI 6.5 §6.4.3.8.2.1. Carries the slave address +
    /// bus reference for an I2C-attached child device (HID-over-I2C
    /// touchpad, sensor hub, etc.).
    I2cSerialBus {
        /// 7-bit (or 10-bit when `addr_10bit`) slave address.
        slave_address: u16,
        /// `true` = 10-bit addressing mode (Type-Specific Flags bit 0).
        addr_10bit: bool,
        /// Bus speed in Hz (Standard 100k / Fast 400k / Fast+ 1M / etc.).
        connection_speed: u32,
        /// `true` = device acts as bus slave (rare). General-flags bit 0.
        slave_mode: bool,
        /// AML path of the I2C controller node (`ResourceSource`).
        resource_source: String,
        /// Index inside the named ResourceSource.
        resource_source_index: u8,
    },
    /// Large Serial Bus Connection Descriptor with Bus Type 2 = SPI.
    /// ACPI 6.5 §6.4.3.8.2.2. Used by Renoir fingerprint readers,
    /// some BT controllers, and various embedded sensors.
    SpiSerialBus {
        device_selection: u16,
        /// Wire mode + polarity flags (Type-Specific Flags).
        wire_mode_3wire: bool,
        device_polarity_low: bool,
        data_bit_length: u8,
        clock_phase: u8,
        clock_polarity: u8,
        connection_speed: u32,
        slave_mode: bool,
        resource_source: String,
        resource_source_index: u8,
    },
    /// Large Serial Bus Connection Descriptor with Bus Type 3 = UART.
    /// ACPI 6.5 §6.4.3.8.2.3. Used by laptop BT controllers connected
    /// over the FCH UART.
    UartSerialBus {
        baud_rate: u32,
        rx_fifo_size: u16,
        tx_fifo_size: u16,
        parity: u8,
        lines_in_use: u8,
        flow_control: u8,
        stop_bits: u8,
        data_bits: u8,
        endianness_big: bool,
        slave_mode: bool,
        resource_source: String,
        resource_source_index: u8,
    },
    /// GPIO PinFunction Connection Descriptor (large tag 0x0D).
    /// ACPI 6.5 §6.4.3.8.5. Used by Renoir for non-default pin
    /// muxing of GPIO pins (e.g. pin acts as alt-function instead
    /// of as a generic GPIO).
    PinFunction {
        shared: bool,
        pull: u8,
        function_number: u16,
        pins: Vec<u16>,
        resource_source: String,
        resource_source_index: u8,
    },
    /// PinConfig Connection Descriptor (large tag 0x0F). ACPI 6.5
    /// §6.4.3.8.6. Used to override drive-strength / pull-up
    /// configuration on specific pins.
    PinConfig {
        shared: bool,
        config_type: u8,
        config_value: u32,
        pins: Vec<u16>,
        resource_source: String,
        resource_source_index: u8,
    },
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
                // Large tag 0x0C = GPIO Connection Descriptor
                0x0C => {
                    items.push(decode_gpio_connection(tag, payload));
                }
                // Large tag 0x0D = PinFunction (audit #14).
                0x0D => {
                    items.push(decode_pin_function(tag, payload));
                }
                // Large tag 0x0E = Serial Bus Connection Descriptor
                0x0E => {
                    items.push(decode_serial_bus(tag, payload));
                }
                // Large tag 0x0F = PinConfig (audit #14).
                0x0F => {
                    items.push(decode_pin_config(tag, payload));
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

// ── GPIO + Serial-Bus helpers ────────────────────────────────────────────────

/// Decode a GPIO Connection Descriptor (large tag 0x0C) — both
/// Interrupt (type 0) and IO (type 1) sub-types. ACPI 6.5 §6.4.3.8.1.
///
/// All offsets in the payload are derived by subtracting 3 from the
/// spec's "from start of descriptor" offsets (1 tag byte + 2 length
/// bytes consumed before we land in the payload slice).
fn decode_gpio_connection(tag: u8, payload: &[u8]) -> ResourceItem {
    // Header is 20 payload bytes (descriptor offset 3..22 inclusive,
    // i.e. payload indices 0..19) before the variable Pin Table /
    // Resource Source / Vendor blocks begin.
    if payload.len() < 20 {
        return ResourceItem::Unknown {
            tag,
            payload: payload.to_vec(),
        };
    }
    // payload[0] = Revision ID
    let conn_type = payload[1];
    // payload[2..4] = General Flags (only bit 0 = ConsumerProducer)
    let intr_io_flags = u16::from_le_bytes([payload[4], payload[5]]);
    let pin_config = payload[6];
    let drive_strength = u16::from_le_bytes([payload[7], payload[8]]);
    let debounce_timeout = u16::from_le_bytes([payload[9], payload[10]]);
    let pin_table_off_desc = u16::from_le_bytes([payload[11], payload[12]]) as usize;
    let resource_source_index = payload[13];
    let res_src_name_off_desc = u16::from_le_bytes([payload[14], payload[15]]) as usize;
    // payload[16..18] = Vendor Data Offset (unused here)
    // payload[18..20] = Vendor Data Length (unused; out of range for short payloads)

    // Offsets in spec are from the start of the descriptor (including
    // the 3-byte tag+length header), so subtract 3 to land in payload.
    let pin_off = pin_table_off_desc.saturating_sub(3);
    let res_off = res_src_name_off_desc.saturating_sub(3);

    // Pin Table runs from pin_off until either res_off (if present and
    // non-zero) or end of payload. Each pin is a u16 LE.
    let pin_end = if res_src_name_off_desc != 0 && res_off > pin_off && res_off <= payload.len() {
        res_off
    } else {
        payload.len()
    };
    let mut pins = Vec::new();
    if pin_off <= payload.len() && pin_end <= payload.len() && pin_end >= pin_off {
        let pin_bytes = &payload[pin_off..pin_end];
        for chunk in pin_bytes.chunks_exact(2) {
            pins.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
    }

    // ResourceSource is a NUL-terminated ASCII string.
    let resource_source = if res_src_name_off_desc != 0 && res_off < payload.len() {
        let tail = &payload[res_off..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).into_owned()
    } else {
        String::new()
    };

    match conn_type {
        0 => ResourceItem::GpioInt {
            level_triggered: intr_io_flags & 0x0001 != 0,
            polarity: ((intr_io_flags >> 1) & 0x0003) as u8,
            shared: intr_io_flags & 0x0008 != 0,
            wake: intr_io_flags & 0x0010 != 0,
            pin_config,
            debounce_timeout,
            pins,
            resource_source,
            resource_source_index,
        },
        1 => ResourceItem::GpioIo {
            shared: intr_io_flags & 0x0008 != 0,
            pin_config,
            drive_strength,
            debounce_timeout,
            pins,
            resource_source,
            resource_source_index,
        },
        _ => ResourceItem::Unknown {
            tag,
            payload: payload.to_vec(),
        },
    }
}

/// Decode a Serial Bus Connection Descriptor (large tag 0x0E). Only
/// `BusType == 1` (I2C) is decoded; SPI / UART / CSI-2 fall through
/// to `Unknown` until a driver needs them. ACPI 6.5 §6.4.3.8.2.1.
fn decode_serial_bus(tag: u8, payload: &[u8]) -> ResourceItem {
    // Common Serial Bus header occupies payload[0..9].
    if payload.len() < 9 {
        return ResourceItem::Unknown {
            tag,
            payload: payload.to_vec(),
        };
    }
    // payload[0] = Revision ID
    let resource_source_index = payload[1];
    let bus_type = payload[2];
    let general_flags = payload[3];
    let type_specific_flags = u16::from_le_bytes([payload[4], payload[5]]);
    // payload[6] = Type Specific Revision ID
    let type_data_len = u16::from_le_bytes([payload[7], payload[8]]) as usize;

    // Type-specific data follows immediately after the 9-byte common
    // header; ResourceSource string follows that. Vendor data after.
    let type_data_start = 9usize;
    let type_data_end = type_data_start + type_data_len;
    if type_data_end > payload.len() {
        return ResourceItem::Unknown {
            tag,
            payload: payload.to_vec(),
        };
    }

    // ResourceSource: NUL-terminated string between type-specific data
    // and (optional) vendor block. We don't have an explicit length,
    // so read until NUL or end of payload.
    let res_src_bytes = &payload[type_data_end..];
    let end = res_src_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(res_src_bytes.len());
    let resource_source = String::from_utf8_lossy(&res_src_bytes[..end]).into_owned();

    let td = &payload[type_data_start..type_data_end];
    match bus_type {
        0x01 => {
            // I2C type-specific data: ConnectionSpeed (4) +
            // SlaveAddress (2).
            if type_data_len < 6 {
                return ResourceItem::Unknown {
                    tag,
                    payload: payload.to_vec(),
                };
            }
            let connection_speed = u32::from_le_bytes([td[0], td[1], td[2], td[3]]);
            let slave_address = u16::from_le_bytes([td[4], td[5]]);
            ResourceItem::I2cSerialBus {
                slave_address,
                addr_10bit: type_specific_flags & 0x0001 != 0,
                connection_speed,
                slave_mode: general_flags & 0x0001 != 0,
                resource_source,
                resource_source_index,
            }
        }
        0x02 => {
            // SPI type-specific data: ConnectionSpeed (4) +
            // DataBitLength (1) + Phase (1) + Polarity (1) +
            // DeviceSelection (2). 9 bytes.
            if type_data_len < 9 {
                return ResourceItem::Unknown {
                    tag,
                    payload: payload.to_vec(),
                };
            }
            let connection_speed = u32::from_le_bytes([td[0], td[1], td[2], td[3]]);
            let data_bit_length = td[4];
            let clock_phase = td[5];
            let clock_polarity = td[6];
            let device_selection = u16::from_le_bytes([td[7], td[8]]);
            ResourceItem::SpiSerialBus {
                device_selection,
                wire_mode_3wire: type_specific_flags & 0x0001 != 0,
                device_polarity_low: type_specific_flags & 0x0002 != 0,
                data_bit_length,
                clock_phase,
                clock_polarity,
                connection_speed,
                slave_mode: general_flags & 0x0001 != 0,
                resource_source,
                resource_source_index,
            }
        }
        0x03 => {
            // UART type-specific data: BaudRate (4) +
            // RxFifoSize (2) + TxFifoSize (2) + Parity (1) +
            // LinesInUse (1) — 10 bytes total.
            if type_data_len < 10 {
                return ResourceItem::Unknown {
                    tag,
                    payload: payload.to_vec(),
                };
            }
            let baud_rate = u32::from_le_bytes([td[0], td[1], td[2], td[3]]);
            let rx_fifo_size = u16::from_le_bytes([td[4], td[5]]);
            let tx_fifo_size = u16::from_le_bytes([td[6], td[7]]);
            let parity = td[8];
            let lines_in_use = td[9];
            // Type-Specific Flags layout (ACPI §6.4.3.8.2.3):
            // bits 0-1 = flow control, 2-3 = stop bits, 4-7 =
            // data bits, 8 = big-endian.
            let flow_control = (type_specific_flags & 0x3) as u8;
            let stop_bits = ((type_specific_flags >> 2) & 0x3) as u8;
            let data_bits = ((type_specific_flags >> 4) & 0x7) as u8;
            ResourceItem::UartSerialBus {
                baud_rate,
                rx_fifo_size,
                tx_fifo_size,
                parity,
                lines_in_use,
                flow_control,
                stop_bits,
                data_bits,
                endianness_big: type_specific_flags & 0x0100 != 0,
                slave_mode: general_flags & 0x0001 != 0,
                resource_source,
                resource_source_index,
            }
        }
        _ => ResourceItem::Unknown {
            tag,
            payload: payload.to_vec(),
        },
    }
}

/// Decode a PinFunction (large tag 0x0D) connection descriptor.
fn decode_pin_function(_tag: u8, payload: &[u8]) -> ResourceItem {
    if payload.len() < 18 {
        return ResourceItem::Unknown {
            tag: 0x0D,
            payload: payload.to_vec(),
        };
    }
    // Layout per ACPI 6.5 §6.4.3.8.5:
    //   +0x00 RevisionId (1)
    //   +0x01 Flags (2)         bit 0 = shared
    //   +0x03 Pull (1)
    //   +0x04 FunctionNumber (2)
    //   +0x06 PinTableOffset (2)
    //   +0x08 ResourceSourceIndex (1)
    //   +0x09 ResourceSourceNameOffset (2)
    //   +0x0B VendorOffset (2)
    //   +0x0D VendorLength (2)
    //   +0x0F PinTable... (each pin: 2 bytes)
    let flags = u16::from_le_bytes([payload[1], payload[2]]);
    let pull = payload[3];
    let function_number = u16::from_le_bytes([payload[4], payload[5]]);
    let pin_off = u16::from_le_bytes([payload[6], payload[7]]) as usize;
    let resource_source_index = payload[8];
    let res_src_off = u16::from_le_bytes([payload[9], payload[10]]) as usize;
    // Pin offsets are descriptor-relative (include the 3-byte
    // descriptor header); subtract 3 to land in payload.
    let pin_off = pin_off.saturating_sub(3);
    let res_src_off = res_src_off.saturating_sub(3);
    let pin_end = if res_src_off > pin_off && res_src_off <= payload.len() {
        res_src_off
    } else {
        payload.len()
    };
    let mut pins = Vec::new();
    let mut p = pin_off;
    while p + 2 <= pin_end {
        pins.push(u16::from_le_bytes([payload[p], payload[p + 1]]));
        p += 2;
    }
    let resource_source = if res_src_off < payload.len() {
        let tail = &payload[res_src_off..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).into_owned()
    } else {
        String::new()
    };
    ResourceItem::PinFunction {
        shared: flags & 0x1 != 0,
        pull,
        function_number,
        pins,
        resource_source,
        resource_source_index,
    }
}

/// Decode a PinConfig (large tag 0x0F) descriptor.
fn decode_pin_config(_tag: u8, payload: &[u8]) -> ResourceItem {
    if payload.len() < 18 {
        return ResourceItem::Unknown {
            tag: 0x0F,
            payload: payload.to_vec(),
        };
    }
    // Layout per ACPI 6.5 §6.4.3.8.6:
    //   +0x00 RevisionId (1)
    //   +0x01 Flags (2)
    //   +0x03 PinConfigType (1)
    //   +0x04 PinConfigValue (4)
    //   +0x08 PinTableOffset (2)
    //   +0x0A ResourceSourceIndex (1)
    //   +0x0B ResourceSourceNameOffset (2)
    let flags = u16::from_le_bytes([payload[1], payload[2]]);
    let config_type = payload[3];
    let config_value = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let pin_off = u16::from_le_bytes([payload[8], payload[9]]) as usize;
    let resource_source_index = payload[10];
    let res_src_off = u16::from_le_bytes([payload[11], payload[12]]) as usize;
    let pin_off = pin_off.saturating_sub(3);
    let res_src_off = res_src_off.saturating_sub(3);
    let pin_end = if res_src_off > pin_off && res_src_off <= payload.len() {
        res_src_off
    } else {
        payload.len()
    };
    let mut pins = Vec::new();
    let mut p = pin_off;
    while p + 2 <= pin_end {
        pins.push(u16::from_le_bytes([payload[p], payload[p + 1]]));
        p += 2;
    }
    let resource_source = if res_src_off < payload.len() {
        let tail = &payload[res_src_off..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).into_owned()
    } else {
        String::new()
    };
    ResourceItem::PinConfig {
        shared: flags & 0x1 != 0,
        config_type,
        config_value,
        pins,
        resource_source,
        resource_source_index,
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
