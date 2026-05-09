//! HID 1.11 §6.2.2 Report Descriptor parser.
//!
//! ## Item format (HID 1.11 §5.3 — "Generic Item Format")
//!
//! A descriptor is a flat byte sequence of *items*. There are two
//! item shapes:
//!
//! - **Short item**: 1 prefix byte followed by 0/1/2/4 bytes of
//!   little-endian data. The prefix encodes:
//!
//!   ```text
//!     bits[1:0]  bSize: 0 → 0 data bytes
//!                       1 → 1
//!                       2 → 2
//!                       3 → 4
//!     bits[3:2]  bType: 0=Main, 1=Global, 2=Local, 3=reserved
//!     bits[7:4]  bTag : item-specific opcode
//!   ```
//!
//! - **Long item**: prefix `0xFE`, `bDataSize` byte, `bLongItemTag`,
//!   then `bDataSize` data bytes. Long items are reserved by the
//!   spec; we parse and skip them.
//!
//! ## State machine (HID 1.11 §6.2.2.4)
//!
//! Parsing maintains three state registers:
//!
//! - **Global state** — Usage Page, Logical Min/Max, Physical
//!   Min/Max, Unit, Unit Exponent, Report Size, Report ID, Report
//!   Count. Global items mutate this until overwritten or replaced
//!   by Push/Pop. Carries across Main items.
//! - **Local state** — Usage list, Usage Min/Max, Designator
//!   Min/Max/Index, String Min/Max/Index, Delimiter. Local items
//!   accumulate here, and the entire local block is *consumed and
//!   reset* on every Main item. (HID §6.2.2.8.)
//! - **Collection stack** — depth-tracked for diagnostics; each
//!   Main `Collection` item nests a level, `End Collection` pops
//!   one. Application-level collection identifiers are recorded so
//!   higher layers can pick reports by usage (e.g. "find the Touch
//!   Pad Application Collection").
//!
//! ## Output
//!
//! [`parse`] returns a [`ReportDescriptor`] holding an ordered
//! [`Field`] list. Each field captures one Main `Input` / `Output` /
//! `Feature` item with the global+local state at the point of that
//! item, plus the running bit offset within its report so a runtime
//! report decoder can pluck values out without re-walking the
//! descriptor.

extern crate alloc;
use alloc::vec::Vec;

/// Error returned by [`parse`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// Item prefix says the item extends beyond the buffer end.
    Truncated,
    /// More than [`MAX_NESTED_COLLECTIONS`] collections nested at
    /// once. Real-world descriptors max out around 4–5 deep; we
    /// allow 16 with margin.
    CollectionTooDeep,
    /// `End Collection` without a matching `Collection`.
    UnbalancedEndCollection,
    /// Push without a matching Pop, or Pop with empty stack.
    PushPopUnderflow,
    /// Push state stack exceeded [`MAX_PUSH_DEPTH`].
    PushTooDeep,
    /// Reserved short-item type (`bType == 3`).
    ReservedItemType,
    /// `Report Size` × `Report Count` overflowed when added to a
    /// running bit offset (corrupt descriptor).
    BitOffsetOverflow,
}

const MAX_NESTED_COLLECTIONS: usize = 16;
const MAX_PUSH_DEPTH: usize = 8;

/// HID 1.11 §6.2.2.6 — `Collection` item types.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CollectionKind {
    Physical,
    Application,
    Logical,
    Report,
    NamedArray,
    UsageSwitch,
    UsageModifier,
    Vendor(u8),
}

impl CollectionKind {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => CollectionKind::Physical,
            0x01 => CollectionKind::Application,
            0x02 => CollectionKind::Logical,
            0x03 => CollectionKind::Report,
            0x04 => CollectionKind::NamedArray,
            0x05 => CollectionKind::UsageSwitch,
            0x06 => CollectionKind::UsageModifier,
            other => CollectionKind::Vendor(other),
        }
    }
}

/// Which Main-item flavor a [`Field`] came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Device → host (Main `Input` item, prefix tag `0x80`).
    Input,
    /// Host → device (Main `Output` item, prefix tag `0x90`).
    Output,
    /// Device feature config (Main `Feature` item, prefix tag `0xB0`).
    Feature,
}

crate::bitflags_local! {
    /// HID 1.11 §6.2.2.5 — Main-item data bits (Input/Output/Feature).
    pub struct FieldFlags: u32 {
        /// Bit 0. 0 = Data, 1 = Constant (padding).
        const CONSTANT     = 1 << 0;
        /// Bit 1. 0 = Array, 1 = Variable.
        const VARIABLE     = 1 << 1;
        /// Bit 2. 0 = Absolute, 1 = Relative.
        const RELATIVE     = 1 << 2;
        /// Bit 3. 0 = NoWrap, 1 = Wrap.
        const WRAP         = 1 << 3;
        /// Bit 4. 0 = Linear, 1 = NonLinear.
        const NON_LINEAR   = 1 << 4;
        /// Bit 5. 0 = PreferredState, 1 = NoPreferred.
        const NO_PREFERRED = 1 << 5;
        /// Bit 6. 0 = NoNullPosition, 1 = NullState.
        const NULL_STATE   = 1 << 6;
        /// Bit 7. 0 = NonVolatile, 1 = Volatile (Output/Feature only).
        const VOLATILE     = 1 << 7;
        /// Bit 8. 0 = BitField, 1 = BufferedBytes.
        const BUFFERED     = 1 << 8;
    }
}

/// One Input / Output / Feature item with the resolved state at the
/// point that item appeared in the descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    pub flags: FieldFlags,
    /// 0 if the descriptor declares no `Report ID` Global item; else
    /// the latest declared ID at this point in the walk.
    pub report_id: u8,
    pub usage_page: u16,
    /// Explicitly-listed usage IDs at this point in the local-state
    /// block, in declaration order. Each entry is `(page, id)` — the
    /// page can differ per usage if the descriptor used the 4-byte
    /// extended-usage form (HID §6.2.2.8).
    pub usages: Vec<(u16, u16)>,
    /// Inclusive `Usage Minimum` … `Usage Maximum` range, if either
    /// was set in this Main item's local-state block.
    pub usage_min: Option<(u16, u16)>,
    pub usage_max: Option<(u16, u16)>,
    pub logical_min: i32,
    pub logical_max: i32,
    pub physical_min: i32,
    pub physical_max: i32,
    pub unit: u32,
    pub unit_exp: i32,
    /// Bits per element.
    pub report_size: u32,
    /// Number of elements.
    pub report_count: u32,
    /// Offset (bits) within this field's report, *not counting* the
    /// optional 1-byte report-id prefix. Decoders skip that byte
    /// before applying the offset.
    pub bit_offset: u32,
    /// Application-level collection path leading to this field, in
    /// outer-to-inner order. Each entry is the `(usage_page,
    /// usage_id)` declared by the enclosing Collection's most-recent
    /// `Usage` Local item. Empty if the field lives at descriptor
    /// top level.
    pub collection_path: Vec<(u16, u16)>,
}

/// Parsed report descriptor — the output of [`parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportDescriptor {
    pub fields: Vec<Field>,
    /// `true` iff the descriptor declared at least one `Report ID`
    /// Global item. When this is set, every report on the wire
    /// starts with a 1-byte report-id; field decoders must skip it.
    pub has_report_ids: bool,
    /// Top-level Application Collection identifiers, in declaration
    /// order. A modern PTP descriptor declares two: the Touch Pad
    /// (Digitizer / TouchPad) and the Mouse compatibility shim.
    pub top_level_apps: Vec<(u16, u16)>,
}

impl ReportDescriptor {
    /// Iterate fields whose `report_id` matches `id`.
    pub fn fields_with_report_id(&self, id: u8) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.report_id == id)
    }

    /// Total bit length of the body of the report with the given
    /// report id (excluding the 1-byte report-id prefix). Useful for
    /// validating that a runtime report has at least the right
    /// length before extraction.
    pub fn report_body_bits(&self, id: u8, kind: FieldKind) -> u32 {
        let mut max_end = 0u32;
        for f in self.fields.iter().filter(|f| f.report_id == id && f.kind == kind) {
            let end = f.bit_offset.saturating_add(f.report_size.saturating_mul(f.report_count));
            if end > max_end {
                max_end = end;
            }
        }
        max_end
    }
}

// ── Parser ───────────────────────────────────────────────────────

/// HID 1.11 §6.2.2.7 Global items — kept on the parser stack.
#[derive(Clone, Default, Debug)]
struct GlobalState {
    usage_page: u16,
    logical_min: i32,
    logical_max: i32,
    physical_min: i32,
    physical_max: i32,
    unit: u32,
    unit_exp: i32,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

#[derive(Default, Debug)]
struct LocalState {
    usages: Vec<(u16, u16)>,
    usage_min: Option<(u16, u16)>,
    usage_max: Option<(u16, u16)>,
}

/// Walk a HID Report Descriptor, returning the parsed structure.
pub fn parse(blob: &[u8]) -> Result<ReportDescriptor, DescriptorError> {
    let mut fields: Vec<Field> = Vec::new();
    let mut top_level_apps: Vec<(u16, u16)> = Vec::new();

    let mut global = GlobalState::default();
    let mut local = LocalState::default();
    let mut globals_stack: Vec<GlobalState> = Vec::new();
    let mut collection_stack: Vec<(u16, u16)> = Vec::new();
    // Bit offsets indexed by `report_id` — kept per (id, kind).
    // Kind is encoded as 0/1/2 for Input/Output/Feature.
    let mut bit_offsets: [Vec<(u8, u32)>; 3] = Default::default();
    let mut has_report_ids = false;

    let mut i = 0usize;
    while i < blob.len() {
        let prefix = blob[i];
        // Long item (HID §5.3): 0xFE, bDataSize, bLongItemTag, [data...]
        if prefix == 0xFE {
            if i + 3 > blob.len() {
                return Err(DescriptorError::Truncated);
            }
            let n = blob[i + 1] as usize;
            if i + 3 + n > blob.len() {
                return Err(DescriptorError::Truncated);
            }
            i += 3 + n;
            continue;
        }
        let size_code = prefix & 0x03;
        let size = match size_code {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };
        if i + 1 + size > blob.len() {
            return Err(DescriptorError::Truncated);
        }
        let item_type = (prefix >> 2) & 0x03;
        let tag = (prefix >> 4) & 0x0F;
        // Read item data: little-endian; sign-extension is decided
        // per-item based on which item it is (logical/physical
        // min/max are signed; usage values are unsigned).
        let raw_u: u32 = match size {
            0 => 0,
            1 => blob[i + 1] as u32,
            2 => u16::from_le_bytes([blob[i + 1], blob[i + 2]]) as u32,
            4 => u32::from_le_bytes([
                blob[i + 1],
                blob[i + 2],
                blob[i + 3],
                blob[i + 4],
            ]),
            _ => unreachable!(),
        };
        // Sign-extended view for items that take signed data.
        let raw_s: i32 = match size {
            0 => 0,
            1 => (raw_u as i8) as i32,
            2 => (raw_u as i16) as i32,
            4 => raw_u as i32,
            _ => unreachable!(),
        };

        match item_type {
            // ── Main items (HID §6.2.2.4) ─────────────────────
            0 => {
                match tag {
                    // Input
                    0x8 | 0x9 | 0xB => {
                        let kind = match tag {
                            0x8 => FieldKind::Input,
                            0x9 => FieldKind::Output,
                            _ => FieldKind::Feature,
                        };
                        emit_field(
                            &mut fields,
                            &global,
                            &local,
                            &collection_stack,
                            kind,
                            raw_u,
                            &mut bit_offsets,
                        )?;
                        local = LocalState::default();
                    }
                    // Collection
                    0xA => {
                        if collection_stack.len() >= MAX_NESTED_COLLECTIONS {
                            return Err(DescriptorError::CollectionTooDeep);
                        }
                        let usage = first_usage(&local).unwrap_or((global.usage_page, 0));
                        if matches!(
                            CollectionKind::from_byte(raw_u as u8),
                            CollectionKind::Application
                        ) && collection_stack.is_empty()
                        {
                            top_level_apps.push(usage);
                        }
                        collection_stack.push(usage);
                        local = LocalState::default();
                    }
                    // End Collection
                    0xC => {
                        if collection_stack.pop().is_none() {
                            return Err(DescriptorError::UnbalancedEndCollection);
                        }
                        local = LocalState::default();
                    }
                    _ => {
                        // Reserved / unknown main-item tag — discard local state per spec.
                        local = LocalState::default();
                    }
                }
            }
            // ── Global items (HID §6.2.2.7) ───────────────────
            1 => match tag {
                0x0 => global.usage_page = raw_u as u16,
                0x1 => global.logical_min = raw_s,
                0x2 => global.logical_max = raw_s,
                0x3 => global.physical_min = raw_s,
                0x4 => global.physical_max = raw_s,
                0x5 => global.unit_exp = raw_s,
                0x6 => global.unit = raw_u,
                0x7 => global.report_size = raw_u,
                0x8 => {
                    global.report_id = raw_u as u8;
                    has_report_ids = true;
                }
                0x9 => global.report_count = raw_u,
                0xA => {
                    if globals_stack.len() >= MAX_PUSH_DEPTH {
                        return Err(DescriptorError::PushTooDeep);
                    }
                    globals_stack.push(global.clone());
                }
                0xB => {
                    global = globals_stack.pop().ok_or(DescriptorError::PushPopUnderflow)?;
                }
                _ => {}
            },
            // ── Local items (HID §6.2.2.8) ────────────────────
            2 => match tag {
                0x0 => {
                    // Usage. 1- or 2-byte form: just usage id, page = current.
                    // 4-byte form: high 16 bits = page, low 16 = usage.
                    let (pg, id) = if size == 4 {
                        ((raw_u >> 16) as u16, raw_u as u16)
                    } else {
                        (global.usage_page, raw_u as u16)
                    };
                    local.usages.push((pg, id));
                }
                0x1 => {
                    let v = if size == 4 {
                        ((raw_u >> 16) as u16, raw_u as u16)
                    } else {
                        (global.usage_page, raw_u as u16)
                    };
                    local.usage_min = Some(v);
                }
                0x2 => {
                    let v = if size == 4 {
                        ((raw_u >> 16) as u16, raw_u as u16)
                    } else {
                        (global.usage_page, raw_u as u16)
                    };
                    local.usage_max = Some(v);
                }
                _ => { /* Designator/String/Delimiter — accepted but unused */ }
            },
            // ── Reserved (3) ──────────────────────────────────
            _ => return Err(DescriptorError::ReservedItemType),
        }

        i += 1 + size;
    }

    Ok(ReportDescriptor {
        fields,
        has_report_ids,
        top_level_apps,
    })
}

fn first_usage(local: &LocalState) -> Option<(u16, u16)> {
    local.usages.first().copied().or(local.usage_min)
}

#[allow(clippy::too_many_arguments)]
fn emit_field(
    fields: &mut Vec<Field>,
    global: &GlobalState,
    local: &LocalState,
    collection_stack: &[(u16, u16)],
    kind: FieldKind,
    flag_bits: u32,
    bit_offsets: &mut [Vec<(u8, u32)>; 3],
) -> Result<(), DescriptorError> {
    let kind_idx = match kind {
        FieldKind::Input => 0,
        FieldKind::Output => 1,
        FieldKind::Feature => 2,
    };
    let bucket = &mut bit_offsets[kind_idx];
    let id = global.report_id;
    let cur = match bucket.iter_mut().find(|(rid, _)| *rid == id) {
        Some(slot) => slot.1,
        None => {
            bucket.push((id, 0));
            0
        }
    };
    let bits = global.report_size.checked_mul(global.report_count)
        .ok_or(DescriptorError::BitOffsetOverflow)?;
    let new_cur = cur.checked_add(bits).ok_or(DescriptorError::BitOffsetOverflow)?;
    if let Some(slot) = bucket.iter_mut().find(|(rid, _)| *rid == id) {
        slot.1 = new_cur;
    }

    fields.push(Field {
        kind,
        flags: FieldFlags(flag_bits),
        report_id: id,
        usage_page: global.usage_page,
        usages: local.usages.clone(),
        usage_min: local.usage_min,
        usage_max: local.usage_max,
        logical_min: global.logical_min,
        logical_max: global.logical_max,
        physical_min: global.physical_min,
        physical_max: global.physical_max,
        unit: global.unit,
        unit_exp: global.unit_exp,
        report_size: global.report_size,
        report_count: global.report_count,
        bit_offset: cur,
        collection_path: collection_stack.to_vec(),
    });
    Ok(())
}

