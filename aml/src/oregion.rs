//! AML OpRegion + Field accessors.
//!
//! Provides storage and read-only access for `OpRegion` and `Field`
//! declarations parsed from DSDT/SSDT AML tables.

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{AmlError, NameValue, full_path};
use crate::{Parser, read_pkg_length, read_name_string, try_read_simple_value};

// ── Public types ─────────────────────────────────────────────────────────────

/// Address-space kind for an OpRegion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegionSpace {
    SystemMemory,
    SystemIO,
    PciConfig,
    EmbeddedCtl,
    SmBus,
    /// Anything we don't decode.
    Other(u8),
}

impl RegionSpace {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => RegionSpace::SystemMemory,
            1 => RegionSpace::SystemIO,
            2 => RegionSpace::PciConfig,
            3 => RegionSpace::EmbeddedCtl,
            4 => RegionSpace::SmBus,
            n => RegionSpace::Other(n),
        }
    }
}

/// One captured OpRegion.
///
/// `offset` and `length` are the already-evaluated TermArg results.
/// Only flat integer-literal TermArgs are captured at parse time;
/// computed expressions produce `offset=0, length=0` stubs.
#[derive(Clone, Debug)]
pub struct OpRegionInfo {
    pub path:   String,
    pub space:  RegionSpace,
    pub offset: u64,
    pub length: u64,
}

/// One Field item with its bit-extent inside the parent region.
#[derive(Clone, Debug)]
pub struct FieldInfo {
    /// Absolute path to the field name.
    pub path:        String,
    /// Absolute path to the parent OpRegion.
    pub region_path: String,
    pub bit_offset:  u64,
    pub bit_length:  u64,
    /// ACPI access-type: 0=AnyAcc 1=ByteAcc 2=WordAcc 3=DWordAcc 4=QWordAcc
    pub access_kind: u8,
}

/// Errors from `read_field`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FieldAccessError {
    NoField,
    NoRegion,
    Unsupported,
    /// Field bit-length > 64. `read_field` returns `u64` only.
    TooWide,
}

// ── Static storage ────────────────────────────────────────────────────────────

static REGIONS: IrqSafeSpinLock<Vec<OpRegionInfo>> =
    IrqSafeSpinLock::new(Vec::new());

static FIELDS: IrqSafeSpinLock<Vec<FieldInfo>> =
    IrqSafeSpinLock::new(Vec::new());

// ── Registration ──────────────────────────────────────────────────────────────

/// Register an `OpRegion` declaration.
pub fn register_region(info: OpRegionInfo) {
    REGIONS.lock().push(info);
}

/// Register a `Field` declaration.
pub fn register_field(info: FieldInfo) {
    FIELDS.lock().push(info);
}

// ── Lookup ────────────────────────────────────────────────────────────────────

/// Look up an `OpRegion` by absolute path.
pub fn region_for(path: &str) -> Option<OpRegionInfo> {
    REGIONS.lock().iter().find(|r| r.path == path).cloned()
}

/// Look up a `Field` by absolute path.
pub fn field_for(path: &str) -> Option<FieldInfo> {
    FIELDS.lock().iter().find(|f| f.path == path).cloned()
}

/// Call `f` on every registered `OpRegionInfo`.
pub fn for_each_region<F: FnMut(&OpRegionInfo)>(mut f: F) {
    let g = REGIONS.lock();
    for r in g.iter() { f(r); }
}

/// Call `f` on every registered `FieldInfo`.
pub fn for_each_field<F: FnMut(&FieldInfo)>(mut f: F) {
    let g = FIELDS.lock();
    for fi in g.iter() { f(fi); }
}

// ── Hardware read helpers ─────────────────────────────────────────────────────

/// MMIO read of `width_bytes` at physical address `phys`.
///
/// # Safety
/// `phys` must be a valid, identity-mapped physical address.
unsafe fn mmio_read(phys: u64, width_bytes: usize) -> u64 {
    // SAFETY: caller guarantees mapping.
    unsafe {
        match width_bytes {
            1 => core::ptr::read_volatile(phys as *const u8)  as u64,
            2 => core::ptr::read_volatile(phys as *const u16) as u64,
            4 => core::ptr::read_volatile(phys as *const u32) as u64,
            8 => core::ptr::read_volatile(phys as *const u64),
            _ => {
                // Byte-by-byte fallback for any other width.
                let mut val = 0u64;
                for i in 0..width_bytes.min(8) {
                    let b = core::ptr::read_volatile((phys + i as u64) as *const u8);
                    val |= (b as u64) << (i * 8);
                }
                val
            }
        }
    }
}

/// I/O port read for x86_64.
#[cfg(target_arch = "x86_64")]
unsafe fn io_in(port: u16, width_bytes: usize) -> u64 {
    // SAFETY: caller ensures port is a valid I/O port.
    unsafe {
        match width_bytes {
            1 => {
                let val: u8;
                core::arch::asm!(
                    "in al, dx",
                    in("dx") port,
                    out("al") val,
                    options(nomem, nostack)
                );
                val as u64
            }
            2 => {
                let val: u16;
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") port,
                    out("ax") val,
                    options(nomem, nostack)
                );
                val as u64
            }
            _ => {
                let val: u32;
                core::arch::asm!(
                    "in eax, dx",
                    in("dx") port,
                    out("eax") val,
                    options(nomem, nostack)
                );
                val as u64
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_in(_port: u16, _width_bytes: usize) -> u64 { 0 }

// ── PciConfig ECAM address resolution ────────────────────────────────────────

/// Resolve a PciConfig OpRegion's effective ECAM byte address.
///
/// Walks the parent chain from `region.path` to recover
/// (segment, bus, device, function), then computes:
///
///   `ecam_base + ((segment << 28) | (bus << 20) | (device << 15) | (function << 12)) + region.offset`
///
/// Returns `None` when no `_ADR` ancestor is found, when the ECAM base is
/// unavailable, or when the namespace lookup fails.
fn resolve_pci_config_addr(region: &OpRegionInfo) -> Option<u64> {
    // mcfg_ecam_base is segment-0's base; we default segment to 0.
    let ecam_base = narf_acpi::mcfg_ecam_base()?;

    // Strip the last segment of region.path to get the enclosing device scope.
    // e.g. "\\_SB.PCI0.GPP0.RGN0" → "\\_SB.PCI0.GPP0"
    let parent_path = {
        let p = &region.path;
        match p.rfind('.') {
            Some(dot) => &p[..dot],
            // Root-relative single-component path — no device ancestor possible.
            None => return None,
        }
    };

    // Walk the ancestor chain looking for Device nodes with _ADR / _BBN / _SEG.
    let mut adr_val: Option<u64> = None; // _ADR on the enclosing device
    let mut bbn_val: Option<u64> = None; // _BBN bus number
    let mut seg_val: u64         = 0;    // _SEG segment, default 0

    let mut current = String::from(parent_path);
    loop {
        // Check if this node is a Device.
        let node = crate::find_node(&current)?;
        if node.kind == crate::NodeKind::Device {
            // Try to read _ADR from this device (first one found wins).
            if adr_val.is_none() {
                let mut adr_path = current.clone();
                adr_path.push_str("._ADR");
                if let Some(n) = crate::find_node(&adr_path) {
                    if let Some(crate::NameValue::Integer(v)) = n.value {
                        adr_val = Some(v);
                    }
                }
            }

            // Try to read _BBN (bus number) from this device.
            if bbn_val.is_none() {
                let mut bbn_path = current.clone();
                bbn_path.push_str("._BBN");
                if let Some(n) = crate::find_node(&bbn_path) {
                    if let Some(crate::NameValue::Integer(v)) = n.value {
                        bbn_val = Some(v);
                    }
                }
            }

            // Try to read _SEG (segment) from this device.
            {
                let mut seg_path = current.clone();
                seg_path.push_str("._SEG");
                if let Some(n) = crate::find_node(&seg_path) {
                    if let Some(crate::NameValue::Integer(v)) = n.value {
                        seg_val = v & 0xFFFF;
                    }
                }
            }

            // Done once we have both _ADR and _BBN.
            if adr_val.is_some() && bbn_val.is_some() {
                break;
            }
        }

        // Walk up one level.
        match current.rfind('.') {
            Some(dot) => {
                current = String::from(&current[..dot]);
            }
            None => {
                // Reached root — stop.
                break;
            }
        }
    }

    let adr = adr_val?;
    // _BBN may be absent for bridges that inherit bus 0.
    let bus    = bbn_val.unwrap_or(0) & 0xFF;
    let device = (adr >> 16) & 0x1F;
    let func   = adr & 0x7;

    // ECAM offset per PCIe spec: bus[27:20] | device[19:15] | func[14:12]
    let ecam_offset = (seg_val << 28) | (bus << 20) | (device << 15) | (func << 12);
    Some(ecam_base + ecam_offset + region.offset)
}

// ── read_field ────────────────────────────────────────────────────────────────

/// Read a field by absolute path.
///
/// Looks up the field and its parent region, then issues the appropriate
/// hardware read and shifts/masks down to the field's bit-extent.
pub fn read_field(path: &str) -> Result<u64, FieldAccessError> {
    let fi = field_for(path).ok_or(FieldAccessError::NoField)?;
    if fi.bit_length > 64 {
        return Err(FieldAccessError::TooWide);
    }
    let region = region_for(&fi.region_path).ok_or(FieldAccessError::NoRegion)?;

    // Byte offset of the first bit within the region.
    let byte_offset_in_region = fi.bit_offset / 8;
    // Bit-within-byte offset.
    let bit_in_byte = fi.bit_offset % 8;

    // Width in bytes to read, rounded up to the access-kind alignment.
    let access_bytes: usize = match fi.access_kind {
        1 => 1, // ByteAcc
        2 => 2, // WordAcc
        3 => 4, // DWordAcc
        4 => 8, // QWordAcc
        _ => 1, // AnyAcc → byte
    };

    // Total bits spanned from the start of the access unit to the end of the field.
    let bits_needed = bit_in_byte + fi.bit_length;
    // How many access units we need.
    let access_units = (bits_needed + access_bytes as u64 * 8 - 1) / (access_bytes as u64 * 8);
    if access_units > 1 {
        // Multi-unit field — too wide for our simple reader.
        return Err(FieldAccessError::TooWide);
    }

    let phys_addr = region.offset + byte_offset_in_region;

    // Perform the hardware read.
    let raw = match region.space {
        RegionSpace::SystemMemory => {
            // SAFETY: we trust the AML table declared a valid address.
            unsafe { mmio_read(phys_addr, access_bytes) }
        }
        RegionSpace::SystemIO => {
            if phys_addr > 0xFFFF {
                return Err(FieldAccessError::Unsupported);
            }
            // SAFETY: AML table asserted the port is valid.
            unsafe { io_in(phys_addr as u16, access_bytes) }
        }
        RegionSpace::PciConfig => {
            match resolve_pci_config_addr(&region) {
                Some(addr) => unsafe { mmio_read(addr + byte_offset_in_region, access_bytes) },
                None       => return Err(FieldAccessError::Unsupported),
            }
        }
        _ => return Err(FieldAccessError::Unsupported),
    };

    // Shift right by the bit-in-byte offset, then mask to bit_length.
    let shifted = raw >> bit_in_byte;
    let mask = if fi.bit_length >= 64 {
        u64::MAX
    } else {
        (1u64 << fi.bit_length) - 1
    };
    Ok(shifted & mask)
}

// ── Test reset ────────────────────────────────────────────────────────────────

/// Clear all registered regions and fields. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGIONS.lock().clear();
    FIELDS.lock().clear();
}

// ── AML parse helpers (pub(crate)) ────────────────────────────────────────────

/// Parse RegionSpace + RegionOffset(TermArg) + RegionLen(TermArg) after the
/// NameString has already been consumed. Registers the region. Returns
/// `Ok(true)` if both TermArgs were flat literals (parser is positioned right
/// after the declaration); `Ok(false)` if a TermArg was complex (the region
/// is registered as a stub with offset=0/length=0, parser is positioned after
/// the space byte only — caller should bail from the TermList loop).
///
/// Called from `lib.rs`'s `EXT_OP_REGION_OP` arm after the NameString is
/// consumed and the path is known.
pub(crate) fn parse_op_region_after_name(
    p:    &mut Parser<'_>,
    path: String,
) -> Result<bool, AmlError> {
    let space_b = p.read_u8()?;
    let space   = RegionSpace::from_u8(space_b);

    // Try to decode RegionOffset as a flat literal.
    let start_off = p.pos;
    let offset_val = try_read_simple_value(p, p.pos + 1);
    let offset = match &offset_val {
        Ok(NameValue::Integer(v)) => *v,
        _ => {
            // Complex TermArg — register stub and signal caller to bail.
            register_region(OpRegionInfo { path, space, offset: 0, length: 0 });
            return Ok(false);
        }
    };

    // Try to decode RegionLen as a flat literal.
    let length_val = try_read_simple_value(p, p.pos + 1);
    let length = match &length_val {
        Ok(NameValue::Integer(v)) => *v,
        _ => {
            // Complex TermArg for length — register with known offset.
            let _ = start_off; // suppress warning
            register_region(OpRegionInfo { path, space, offset, length: 0 });
            return Ok(false);
        }
    };

    register_region(OpRegionInfo { path, space, offset, length });
    Ok(true)
}

/// Parse the body of an `OpRegion` declaration starting immediately after the
/// opcode bytes (`0x5B 0x80` already consumed). Registers the region.
///
/// Format (ACPI 6.5 §20.2.5.2):
///   NameString  RegionSpace(u8)  RegionOffset(TermArg)  RegionLen(TermArg)
///
/// This is the helper used for direct parsing (e.g., test scaffolding).
/// Returns `Ok(true)` if TermArgs were plain literals, `Ok(false)` if complex.
pub(crate) fn parse_op_region_body(p: &mut Parser<'_>, parent: &str) -> Result<bool, AmlError> {
    let name = read_name_string(p, parent)?;
    let path = full_path(name, parent);
    parse_op_region_after_name(p, path)
}

/// Parse the body of a `Field` declaration starting immediately after the
/// opcode bytes (`0x5B 0x81` already consumed).
///
/// Format (ACPI 6.5 §20.2.5.2):
///   PkgLength  NameString(region)  FieldFlags(u8)  FieldList…
pub(crate) fn parse_field_body(
    p:       &mut Parser<'_>,
    parent:  &str,
    pkg_end: usize,
) -> Result<(), AmlError> {
    // Region name that this Field references.
    let region_name = read_name_string(p, parent)?;
    let region_path = full_path(region_name, parent);

    // FieldFlags: bits 0..=3 = access type, bit 4 = lock rule,
    //             bits 5..=6 = update rule.
    let flags       = p.read_u8()?;
    let access_kind = flags & 0x0F;

    let mut bit_cursor: u64 = 0;

    while p.pos < pkg_end {
        let tag = p.read_u8()?;
        match tag {
            // NamedField: 4-byte NameSeg + PkgLength (bit length).
            b if b.is_ascii_uppercase() || b == b'_' => {
                // We already consumed the first byte of the 4-byte NameSeg.
                if p.pos + 3 > p.buf.len() {
                    return Err(AmlError::Truncated);
                }
                let mut seg = [b' '; 4];
                seg[0] = b;
                for slot in seg[1..].iter_mut() {
                    *slot = p.read_u8()?;
                }
                let bit_len = read_pkg_length(p)? as u64;

                // Build the field's absolute path as parent + '.' + NameSeg
                // (with trailing underscores stripped).
                let mut seg_end = 4;
                while seg_end > 0 && seg[seg_end - 1] == b'_' { seg_end -= 1; }
                if seg_end == 0 { seg_end = 1; }
                let seg_str: String = seg[..seg_end].iter().map(|&c| c as char).collect();

                let field_path = if parent == "\\" {
                    let mut s = String::from("\\");
                    s.push_str(&seg_str);
                    s
                } else {
                    let mut s = String::from(parent);
                    s.push('.');
                    s.push_str(&seg_str);
                    s
                };

                register_field(FieldInfo {
                    path:        field_path,
                    region_path: region_path.clone(),
                    bit_offset:  bit_cursor,
                    bit_length:  bit_len,
                    access_kind,
                });
                bit_cursor += bit_len;
            }
            // ReservedField: 0x00 + PkgLength (gap in bits).
            0x00 => {
                let gap = read_pkg_length(p)? as u64;
                bit_cursor += gap;
            }
            // AccessField: 0x01 + AccessType(1) + AccessAttrib(1).
            0x01 => {
                // Silently consume; access_kind update not implemented yet.
                p.skip(2)?;
            }
            // ConnectField: 0x02 + NameString — skip.
            0x02 => {
                // Skip the NameString operand: peek and skip past it.
                let _ = read_name_string(p, parent)?;
            }
            // ExtendedAccessField: 0x03 + AccessType + AccessAttrib + AccessLength.
            0x03 => {
                p.skip(3)?;
            }
            // Anything else: bail gracefully.
            _ => {
                p.pos = pkg_end;
                break;
            }
        }
    }

    // Snap parser to pkg_end regardless.
    if p.pos < pkg_end { p.pos = pkg_end; }
    Ok(())
}
