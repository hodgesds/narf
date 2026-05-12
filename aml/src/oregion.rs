//! AML OpRegion + Field accessors.
//!
//! Provides storage and read-only access for `OpRegion` and `Field`
//! declarations parsed from DSDT/SSDT AML tables.

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{full_path, AmlError, NameValue};
use crate::{read_name_string, read_pkg_length, try_read_simple_value, Parser};

// ── Public types ─────────────────────────────────────────────────────────────

/// Address-space kind for an OpRegion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegionSpace {
    SystemMemory,
    SystemIO,
    PciConfig,
    EmbeddedCtl,
    SmBus,
    SystemCmos,
    PciBarTarget,
    Ipmi,
    GeneralPurposeIO,
    GenericSerialBus,
    Pcc,
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
            5 => RegionSpace::SystemCmos,
            6 => RegionSpace::PciBarTarget,
            7 => RegionSpace::Ipmi,
            8 => RegionSpace::GeneralPurposeIO,
            9 => RegionSpace::GenericSerialBus,
            10 => RegionSpace::Pcc,
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
    pub path: String,
    pub space: RegionSpace,
    pub offset: u64,
    pub length: u64,
}

/// One Field item with its bit-extent inside the parent region.
#[derive(Clone, Debug)]
pub struct FieldInfo {
    /// Absolute path to the field name.
    pub path: String,
    /// Absolute path to the parent OpRegion (for plain Field) or
    /// the data register (for IndexField — the field's "region"
    /// is conceptually `_INDIRECT_`; reads/writes route through
    /// `index_field` below).
    pub region_path: String,
    pub bit_offset: u64,
    pub bit_length: u64,
    /// ACPI access-type: 0=AnyAcc 1=ByteAcc 2=WordAcc 3=DWordAcc 4=QWordAcc
    pub access_kind: u8,
    /// `Some` when this field belongs to an IndexField (audit
    /// #7 full impl). Reads write the field's byte offset to the
    /// index register, then read the data register; writes write
    /// the offset then the value.
    pub index_field: Option<IndexFieldRef>,
}

/// Index/data register pair for an IndexField member.
#[derive(Clone, Debug)]
pub struct IndexFieldRef {
    pub index_reg_path: String,
    pub data_reg_path: String,
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

static REGIONS: IrqSafeSpinLock<Vec<OpRegionInfo>> = IrqSafeSpinLock::new(Vec::new());

static FIELDS: IrqSafeSpinLock<Vec<FieldInfo>> = IrqSafeSpinLock::new(Vec::new());

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
    for r in g.iter() {
        f(r);
    }
}

/// Call `f` on every registered `FieldInfo`.
pub fn for_each_field<F: FnMut(&FieldInfo)>(mut f: F) {
    let g = FIELDS.lock();
    for fi in g.iter() {
        f(fi);
    }
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
            1 => core::ptr::read_volatile(phys as *const u8) as u64,
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
unsafe fn io_in(_port: u16, _width_bytes: usize) -> u64 {
    0
}

/// MMIO write of `width_bytes` at physical address `phys`.
///
/// # Safety
/// `phys` must be a valid, identity-mapped physical address.
unsafe fn mmio_write(phys: u64, width_bytes: usize, val: u64) {
    // SAFETY: caller guarantees mapping.
    unsafe {
        match width_bytes {
            1 => core::ptr::write_volatile(phys as *mut u8, val as u8),
            2 => core::ptr::write_volatile(phys as *mut u16, val as u16),
            4 => core::ptr::write_volatile(phys as *mut u32, val as u32),
            8 => core::ptr::write_volatile(phys as *mut u64, val),
            _ => {
                for i in 0..width_bytes.min(8) {
                    let b = ((val >> (i * 8)) & 0xff) as u8;
                    core::ptr::write_volatile((phys + i as u64) as *mut u8, b);
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn io_out(port: u16, width_bytes: usize, val: u64) {
    // SAFETY: caller ensures port is a valid I/O port.
    unsafe {
        match width_bytes {
            1 => core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val as u8,
                options(nomem, nostack)
            ),
            2 => core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") val as u16,
                options(nomem, nostack)
            ),
            _ => core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") val as u32,
                options(nomem, nostack)
            ),
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_out(_port: u16, _width_bytes: usize, _val: u64) {}

// ── Embedded Controller (audit #4 real impl) ───────────────────────
//
// Per ACPI 6.5 §12. The EC provides a 256-byte address space
// accessed through two I/O ports: a command/status port and a
// data port (typically 0x66 + 0x62 on PC laptops). Field reads
// land in `read_ec_byte`/`write_ec_byte` against the byte offset
// declared by the AML Field {} block.
//
// Protocol:
//   READ:  write 0x80 to cmd  → wait IBF=0
//          write offset to data
//          wait OBF=1
//          read data port → returned byte
//   WRITE: write 0x81 to cmd  → wait IBF=0
//          write offset to data → wait IBF=0
//          write value to data → wait IBF=0
//
// Status bits (read from command port): bit 0 = OBF (EC has
// data ready for host), bit 1 = IBF (host wrote, EC hasn't
// drained yet).

const EC_CMD_READ: u8 = 0x80;
const EC_CMD_WRITE: u8 = 0x81;
const EC_SC_OBF: u8 = 0x01;
const EC_SC_IBF: u8 = 0x02;
const EC_TIMEOUT_POLLS: u32 = 1_000_000;

static EC_PORTS: narf_lib::sync::IrqSafeSpinLock<Option<(u16, u16)>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Configure the EC's (data, status_cmd) port addresses. Called
/// once during parse_namespace from `discover_ec_ports`.
pub fn set_ec_ports(data: u16, cmd: u16) {
    *EC_PORTS.lock() = Some((data, cmd));
}

#[cfg(target_arch = "x86_64")]
fn ec_wait_ibf_clear() -> Result<(), FieldAccessError> {
    let (_data, cmd) = match *EC_PORTS.lock() {
        Some(p) => p,
        None => return Err(FieldAccessError::Unsupported),
    };
    for _ in 0..EC_TIMEOUT_POLLS {
        // SAFETY: cmd port owned by this driver, validated at
        // EC discovery time.
        let s = unsafe { io_in(cmd, 1) } as u8;
        if s & EC_SC_IBF == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(FieldAccessError::Unsupported)
}

#[cfg(target_arch = "x86_64")]
fn ec_wait_obf_set() -> Result<(), FieldAccessError> {
    let (_data, cmd) = match *EC_PORTS.lock() {
        Some(p) => p,
        None => return Err(FieldAccessError::Unsupported),
    };
    for _ in 0..EC_TIMEOUT_POLLS {
        // SAFETY: same.
        let s = unsafe { io_in(cmd, 1) } as u8;
        if s & EC_SC_OBF != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(FieldAccessError::Unsupported)
}

#[cfg(target_arch = "x86_64")]
fn ec_read_byte(offset: u8) -> Result<u8, FieldAccessError> {
    let (data, cmd) = match *EC_PORTS.lock() {
        Some(p) => p,
        None => return Err(FieldAccessError::Unsupported),
    };
    ec_wait_ibf_clear()?;
    // SAFETY: ports owned by EC driver path; established at boot.
    unsafe {
        io_out(cmd, 1, EC_CMD_READ as u64);
    }
    ec_wait_ibf_clear()?;
    // SAFETY: same.
    unsafe {
        io_out(data, 1, offset as u64);
    }
    ec_wait_obf_set()?;
    // SAFETY: same.
    Ok(unsafe { io_in(data, 1) } as u8)
}

#[cfg(target_arch = "x86_64")]
fn ec_write_byte(offset: u8, val: u8) -> Result<(), FieldAccessError> {
    let (data, cmd) = match *EC_PORTS.lock() {
        Some(p) => p,
        None => return Err(FieldAccessError::Unsupported),
    };
    ec_wait_ibf_clear()?;
    // SAFETY: ports owned by EC driver path; established at boot.
    unsafe {
        io_out(cmd, 1, EC_CMD_WRITE as u64);
    }
    ec_wait_ibf_clear()?;
    // SAFETY: same.
    unsafe {
        io_out(data, 1, offset as u64);
    }
    ec_wait_ibf_clear()?;
    // SAFETY: same.
    unsafe {
        io_out(data, 1, val as u64);
    }
    ec_wait_ibf_clear()?;
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn ec_read_byte(_offset: u8) -> Result<u8, FieldAccessError> {
    Err(FieldAccessError::Unsupported)
}

#[cfg(not(target_arch = "x86_64"))]
fn ec_write_byte(_offset: u8, _val: u8) -> Result<(), FieldAccessError> {
    Err(FieldAccessError::Unsupported)
}

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
    let mut seg_val: u64 = 0; // _SEG segment, default 0

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
    let bus = bbn_val.unwrap_or(0) & 0xFF;
    let device = (adr >> 16) & 0x1F;
    let func = adr & 0x7;

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
    // Audit #7 IndexField: write the field's byte offset to the
    // index register, then read the data register. Field
    // bit_offset is in bits; convert to bytes for the index
    // register write.
    if let Some(ref idx) = fi.index_field {
        let byte_off = fi.bit_offset / 8;
        write_field(&idx.index_reg_path, byte_off).ok();
        // Read full unit then mask to the field's bit width.
        let raw = read_field(&idx.data_reg_path).unwrap_or(0);
        let mask = if fi.bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << fi.bit_length) - 1
        };
        return Ok(raw & mask);
    }
    let region = region_for(&fi.region_path).ok_or(FieldAccessError::NoRegion)?;
    let access_bytes = access_unit_bytes(fi.access_kind);
    let access_bits = (access_bytes * 8) as u64;

    // Audit #6: multi-unit reads. Walk every access unit the
    // field spans, gluing the slices together. Per ACPI §19.6.31
    // the interpreter must issue access-aligned hardware
    // transactions, even when a single field crosses unit
    // boundaries — common for 32-bit fields at non-DWord-aligned
    // offsets in EC layouts. Pre-fix this returned TooWide and
    // every Field write to such a layout silently failed.
    let first_unit_bit = (fi.bit_offset / access_bits) * access_bits;
    let bit_in_unit = fi.bit_offset - first_unit_bit;
    let units = ((bit_in_unit + fi.bit_length) + access_bits - 1) / access_bits;
    let mut acc: u64 = 0;
    for u in 0..units {
        let unit_byte_offset = (first_unit_bit / 8) + u * access_bytes as u64;
        let raw = read_unit(&region, unit_byte_offset, access_bytes)?;
        acc |= raw << (u * access_bits);
    }
    let shifted = acc >> bit_in_unit;
    let mask = if fi.bit_length >= 64 {
        u64::MAX
    } else {
        (1u64 << fi.bit_length) - 1
    };
    Ok(shifted & mask)
}

/// Write a field by absolute path. Read-modify-write per
/// access unit when the field doesn't cover the unit.
///
/// Audit #2/#3 fix — pre-fix there was no write path and AML
/// `Store(value, FIELDNAME)` against an OpRegion field silently
/// did nothing. DSDTs use this to drive GPIO state, EC
/// commands, PCI-config registers (touchpad reset toggling,
/// thermal-zone setpoints, etc.).
pub fn write_field(path: &str, value: u64) -> Result<(), FieldAccessError> {
    let fi = field_for(path).ok_or(FieldAccessError::NoField)?;
    if fi.bit_length > 64 {
        return Err(FieldAccessError::TooWide);
    }
    // Audit #7 IndexField: index←offset, data←value.
    if let Some(ref idx) = fi.index_field {
        let byte_off = fi.bit_offset / 8;
        write_field(&idx.index_reg_path, byte_off)?;
        return write_field(&idx.data_reg_path, value);
    }
    let region = region_for(&fi.region_path).ok_or(FieldAccessError::NoRegion)?;
    let access_bytes = access_unit_bytes(fi.access_kind);
    let access_bits = (access_bytes * 8) as u64;
    let first_unit_bit = (fi.bit_offset / access_bits) * access_bits;
    let bit_in_unit = fi.bit_offset - first_unit_bit;
    let units = ((bit_in_unit + fi.bit_length) + access_bits - 1) / access_bits;
    let val_mask = if fi.bit_length >= 64 {
        u64::MAX
    } else {
        (1u64 << fi.bit_length) - 1
    };
    let masked_val = value & val_mask;
    // Compute aligned in-unit value bits per unit, RMW on each.
    for u in 0..units {
        let unit_byte_offset = (first_unit_bit / 8) + u * access_bytes as u64;
        // Slice of the field's masked value that lands in unit u.
        let slice_lo_bit = u * access_bits;
        let in_unit_bit = if u == 0 { bit_in_unit } else { 0 };
        let slice_hi_bit = ((u + 1) * access_bits).min(bit_in_unit + fi.bit_length);
        let slice_width = slice_hi_bit - slice_lo_bit - in_unit_bit;
        let unit_mask = if slice_width == 0 {
            continue;
        } else if slice_width >= access_bits {
            // All-bits write — no need to RMW.
            u64::MAX >> (64 - access_bits)
        } else {
            ((1u64 << slice_width) - 1) << in_unit_bit
        };
        let slice_val = (masked_val >> slice_lo_bit.saturating_sub(bit_in_unit)) & ((1u64 << slice_width) - 1);
        let new_bits = (slice_val << in_unit_bit) & unit_mask;
        // Update policy: AML field-flags update_rule (we don't
        // currently parse it; default is Preserve = RMW). Always
        // RMW unless writing the entire access unit.
        let final_unit = if slice_width >= access_bits {
            new_bits
        } else {
            let cur = read_unit(&region, unit_byte_offset, access_bytes)?;
            (cur & !unit_mask) | new_bits
        };
        write_unit(&region, unit_byte_offset, access_bytes, final_unit)?;
    }
    Ok(())
}

#[inline]
fn access_unit_bytes(access_kind: u8) -> usize {
    match access_kind {
        1 => 1, // ByteAcc
        2 => 2, // WordAcc
        3 => 4, // DWordAcc
        4 => 8, // QWordAcc
        _ => 1, // AnyAcc → byte
    }
}

fn read_unit(
    region: &OpRegionInfo,
    byte_offset_in_region: u64,
    width: usize,
) -> Result<u64, FieldAccessError> {
    match region.space {
        RegionSpace::SystemMemory => {
            // SAFETY: AML table declared a valid address.
            Ok(unsafe { mmio_read(region.offset + byte_offset_in_region, width) })
        }
        RegionSpace::SystemIO => {
            let port = region.offset + byte_offset_in_region;
            if port > 0xFFFF {
                return Err(FieldAccessError::Unsupported);
            }
            // SAFETY: AML asserted port is valid.
            Ok(unsafe { io_in(port as u16, width) })
        }
        RegionSpace::PciConfig => match resolve_pci_config_addr(region) {
            // SAFETY: ECAM identity-mapped at boot.
            Some(addr) => Ok(unsafe { mmio_read(addr + byte_offset_in_region, width) }),
            None => Err(FieldAccessError::Unsupported),
        },
        // EC: drive the firmware command/data-port protocol.
        // Returns 0 (instead of Unsupported) when EC ports
        // weren't discovered at boot, so non-EC platforms keep
        // working.
        RegionSpace::EmbeddedCtl => {
            // EC byte offsets fit in u8 by spec — the EC
            // address space is 256 bytes max.
            let mut acc = 0u64;
            for i in 0..width.min(8) {
                let off = (byte_offset_in_region + i as u64) as u8;
                let b = ec_read_byte(off).unwrap_or(0);
                acc |= (b as u64) << (i * 8);
            }
            Ok(acc)
        }
        // GenericSerialBus stub still — full impl needs the
        // I2C registry routing + bus-side block transactions
        // (deferred — touchpad bring-up doesn't depend on it).
        // Other rare spaces stubbed to 0 so AML flows through.
        RegionSpace::GenericSerialBus
        | RegionSpace::GeneralPurposeIO
        | RegionSpace::SmBus
        | RegionSpace::Ipmi
        | RegionSpace::Pcc => Ok(0),
        _ => Err(FieldAccessError::Unsupported),
    }
}

fn write_unit(
    region: &OpRegionInfo,
    byte_offset_in_region: u64,
    width: usize,
    val: u64,
) -> Result<(), FieldAccessError> {
    match region.space {
        RegionSpace::SystemMemory => {
            // SAFETY: AML table declared a valid address.
            unsafe {
                mmio_write(region.offset + byte_offset_in_region, width, val);
            }
            Ok(())
        }
        RegionSpace::SystemIO => {
            let port = region.offset + byte_offset_in_region;
            if port > 0xFFFF {
                return Err(FieldAccessError::Unsupported);
            }
            // SAFETY: AML asserted port is valid.
            unsafe {
                io_out(port as u16, width, val);
            }
            Ok(())
        }
        RegionSpace::PciConfig => match resolve_pci_config_addr(region) {
            // SAFETY: ECAM identity-mapped at boot.
            Some(addr) => {
                unsafe {
                    mmio_write(addr + byte_offset_in_region, width, val);
                }
                Ok(())
            }
            None => Err(FieldAccessError::Unsupported),
        },
        // EC writes — drive the WR_EC protocol.
        RegionSpace::EmbeddedCtl => {
            for i in 0..width.min(8) {
                let off = (byte_offset_in_region + i as u64) as u8;
                let v = ((val >> (i * 8)) & 0xff) as u8;
                let _ = ec_write_byte(off, v);
            }
            Ok(())
        }
        RegionSpace::GenericSerialBus
        | RegionSpace::GeneralPurposeIO
        | RegionSpace::SmBus
        | RegionSpace::Ipmi
        | RegionSpace::Pcc => Ok(()),
        _ => Err(FieldAccessError::Unsupported),
    }
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
    p: &mut Parser<'_>,
    path: String,
) -> Result<bool, AmlError> {
    let space_b = p.read_u8()?;
    let space = RegionSpace::from_u8(space_b);

    // Try to decode RegionOffset as a flat literal.
    let start_off = p.pos;
    let offset_val = try_read_simple_value(p, p.pos + 1);
    let offset = match &offset_val {
        Ok(NameValue::Integer(v)) => *v,
        _ => {
            // Complex TermArg — register stub and signal caller to bail.
            register_region(OpRegionInfo {
                path,
                space,
                offset: 0,
                length: 0,
            });
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
            register_region(OpRegionInfo {
                path,
                space,
                offset,
                length: 0,
            });
            return Ok(false);
        }
    };

    register_region(OpRegionInfo {
        path,
        space,
        offset,
        length,
    });
    Ok(true)
}

/// Parse the body of a `Field` declaration starting immediately after the
/// opcode bytes (`0x5B 0x81` already consumed).
///
/// Format (ACPI 6.5 §20.2.5.2):
///   PkgLength  NameString(region)  FieldFlags(u8)  FieldList…
pub(crate) fn parse_field_body(
    p: &mut Parser<'_>,
    parent: &str,
    pkg_end: usize,
) -> Result<(), AmlError> {
    // Region name that this Field references.
    let region_name = read_name_string(p, parent)?;
    let region_path = full_path(region_name, parent);
    parse_field_list(p, parent, &region_path, pkg_end, None)
}

/// Parse an IndexField body. Caller has already consumed the
/// IndexField extended opcode + PkgLength; this fn reads the
/// two register NameStrings + FieldFlags + FieldList and
/// registers each inner field with an IndexFieldRef so reads
/// drive index←offset, data→ value (audit #7 full impl).
pub(crate) fn parse_index_field_body(
    p: &mut Parser<'_>,
    parent: &str,
    pkg_end: usize,
) -> Result<(), AmlError> {
    let index_name = read_name_string(p, parent)?;
    let data_name = read_name_string(p, parent)?;
    let index_reg_path = full_path(index_name, parent);
    let data_reg_path = full_path(data_name, parent);
    parse_field_list(
        p,
        parent,
        "\\__INDIRECT__",
        pkg_end,
        Some(IndexFieldRef {
            index_reg_path,
            data_reg_path,
        }),
    )
}

/// Same as parse_index_field_body but for BankField — currently
/// no bank-switch driving (the bank value gets written to the
/// bank register at registration time only). Most platforms use
/// IndexField; BankField is rare. TODO: pre-write the bank
/// register before each access to actually switch banks.
pub(crate) fn parse_bank_field_body(
    p: &mut Parser<'_>,
    parent: &str,
    pkg_end: usize,
) -> Result<(), AmlError> {
    let region_name = read_name_string(p, parent)?;
    let _bank_reg = read_name_string(p, parent)?;
    // skip bank-value TermArg via the eval helper.
    let _ = crate::eval::skip_term_arg(p.buf, &mut p.pos);
    let region_path = full_path(region_name, parent);
    parse_field_list(p, parent, &region_path, pkg_end, None)
}

/// Backwards-compat shim — old callers used this name.
pub(crate) fn parse_indirect_field_body(
    p: &mut Parser<'_>,
    parent: &str,
    pkg_end: usize,
) -> Result<(), AmlError> {
    parse_field_list(p, parent, "\\__INDIRECT__", pkg_end, None)
}

fn parse_field_list(
    p: &mut Parser<'_>,
    parent: &str,
    region_path: &str,
    pkg_end: usize,
    index_field: Option<IndexFieldRef>,
) -> Result<(), AmlError> {
    // FieldFlags: bits 0..=3 = access type, bit 4 = lock rule,
    //             bits 5..=6 = update rule.
    let flags = p.read_u8()?;
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
                while seg_end > 0 && seg[seg_end - 1] == b'_' {
                    seg_end -= 1;
                }
                if seg_end == 0 {
                    seg_end = 1;
                }
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
                    path: field_path,
                    region_path: alloc::string::String::from(region_path),
                    bit_offset: bit_cursor,
                    bit_length: bit_len,
                    access_kind,
                    index_field: index_field.clone(),
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
    if p.pos < pkg_end {
        p.pos = pkg_end;
    }
    Ok(())
}
