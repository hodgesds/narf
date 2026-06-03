//! Minimum-viable AML namespace builder.
//!
//! AML (ACPI Machine Language) is the bytecode that DSDT + SSDT
//! tables carry. A real interpreter — ACPICA, uACPI — runs into
//! the tens of thousands of lines because it has to evaluate
//! arbitrary methods, walk OpRegions in SystemMemory / SystemIO /
//! PCI_Config, mediate Mutex / Event / Notify, and dispatch GPEs.
//!
//! Today's scope is intentionally narrow: parse the tables enough
//! to enumerate the *namespace* — the tree of declared objects
//! (Scope, Device, Processor, Method, Name, Mutex, PowerResource,
//! ThermalZone). Method bodies are skipped via PkgLength rather
//! than evaluated. Constant `Name(...)` values are resolved when
//! the body is a single-byte / DWord / QWord / String literal so
//! callers can read `_HID`, `_UID`, `_ADR`, `_BBN` and similar
//! flat-constant identifiers.
//!
//! What this enables today:
//!   - "How many devices does the platform declare?" — scheduler /
//!     observability shape questions.
//!   - "What's the _HID of `\\_SB.PCI0`?"
//!   - Foundation for the next layer, which adds method execution
//!     + OpRegion accessors + Resource templates.
//!
//! What it deliberately does NOT do:
//!   - Run methods. Method bodies are recorded as (offset, length)
//!     so a future pass can interpret them; today they're opaque.
//!   - Touch hardware. No `OpRegion(SystemIO, ...)` reads, no PCI
//!     config writes from AML.
//!   - Resolve forward references / cross-table fixups beyond the
//!     simple namespace lookup.
//!
//! Encoding: ACPI 6.5 §20 (AML grammar). PkgLength: §20.2.4.
//! NameString: §20.2.2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_acpi::{AcpiError, SdtHeader};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

pub mod buttons;
pub mod ec;
pub mod ec_events;
pub mod eval;
pub mod gpe;
pub mod irq_routing;
pub mod oregion;
pub mod prt_crs;
pub mod resource;
pub mod sync;
pub mod wmi;

mod tests;
mod e2e_tests;

/// Run-time AML value, used by the method evaluator + Field
/// accessors. `Name(...)` flat-constant decoding stays in
/// `NameValue` for backwards compat; `Value` is the live form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Integer(u64),
    String(String),
    Buffer(Vec<u8>),
    Package(Vec<Value>),
}

impl Value {
    /// Coerce to integer per ACPI implicit conversion rules: integers
    /// stay as-is; strings/buffers fall back to 0 when they can't
    /// trivially parse. Future evaluator passes can refine.
    pub fn as_integer(&self) -> u64 {
        match self {
            Value::Integer(v) => *v,
            Value::Buffer(b) => {
                let mut v = 0u64;
                for (i, byte) in b.iter().take(8).enumerate() {
                    v |= (*byte as u64) << (i * 8);
                }
                v
            }
            _ => 0,
        }
    }
}

/// Errors from AML parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmlError {
    /// AML byte stream truncated mid-decode.
    Truncated,
    /// PkgLength encoding was malformed.
    BadPkgLength,
    /// Tried to consume past a Pkg boundary.
    OutOfPkg,
    /// Underlying ACPI table walk failed.
    Acpi(AcpiError),
    /// AML stream contained a name segment that's not exactly 4
    /// 7-bit-ASCII chars (root char `\` and parent `^` are handled
    /// separately).
    BadNameSegment,
    /// DSDT was not present in the XSDT.
    NoDsdt,
    /// `evaluate_method` couldn't find the requested method path,
    /// or the path resolved to a non-Method node (Name / Device /
    /// Field / etc.). Distinct from `Truncated` so callers (e.g.
    /// the boot-time `_PIC` opt-in) can silently skip an absent
    /// method instead of treating it as a parse failure.
    MethodNotFound,
}

impl From<AcpiError> for AmlError {
    fn from(e: AcpiError) -> Self {
        AmlError::Acpi(e)
    }
}

/// Kind of an AML namespace node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Scope,
    Device,
    Processor,
    PowerResource,
    ThermalZone,
    Method,
    /// `Name(...)` — flat-constant Name values store the literal in
    /// `value`.
    Name,
    Mutex,
    Event,
    Field,
    /// `OpRegion(...)` declared. Body unparsed today.
    OpRegion,
    /// `CreateBitField` / `CreateByteField` / `CreateWordField` /
    /// `CreateDWordField` / `CreateQWordField` / `CreateField` —
    /// a named bit/byte slice into an existing Buffer. Source +
    /// extent live in `buffer_field`.
    BufferField,
}

/// A simple constant value attached to a `Name(...)` node when the
/// body is a single literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameValue {
    /// `0` (ZeroOp), `1` (OneOp), `0xFF...` (OnesOp), or a typed
    /// integer literal.
    Integer(u64),
    /// A null-terminated AsciiString literal.
    String(String),
    /// Live mutable Buffer — used when CreateXxxField writes
    /// splice into the underlying Buffer of a Name(...). The Vec
    /// owns its bytes via the global allocator (slab) so updates
    /// don't grow the AML store.
    Buffer(Vec<u8>),
    /// Live mutable Package — used by `Store(value, name)` when
    /// the destination was a `Name(BUF, Package(...))`.
    Package(Vec<NameValue>),
    /// Any other unrecognised non-trivial body we don't decode.
    /// `(offset, length)` lets a future evaluator pick it up.
    Unparsed { offset: usize, length: usize },
}

/// A flattened namespace node. The full path is the only identity
/// — children/parent links are derivable by string scan.
#[derive(Clone, Debug)]
pub struct AmlNode {
    pub path: String,
    pub kind: NodeKind,
    /// `Some` only when `kind == Name` and the body is a flat
    /// constant we managed to decode.
    pub value: Option<NameValue>,
    /// For `Method`: the offset within the source AML stream to
    /// the method body's first byte, plus the body length.
    /// `(0, 0)` for non-Method nodes.
    pub method_body: (usize, usize),
    /// For `Method`: raw `MethodFlags` byte (ACPI 6.5 §20.2.5.2).
    /// Bits[2:0] = ArgCount, bit 3 = SerializeFlag, bits[7:4] =
    /// SyncLevel. The evaluator reads bits[2:0] to know how many
    /// TermArgs to consume from the byte stream when this method
    /// is invoked. 0 for non-Method nodes.
    pub method_flags: u8,
    /// For `BufferField`: full path of the source Buffer + bit
    /// offset + bit length. Reads return the bit-slice as an
    /// Integer; writes (Store-to-this-name) read the source
    /// buffer, splice in the new bits, write back via
    /// `update_node_value`. `None` for non-BufferField nodes.
    pub buffer_field: Option<BufferFieldRef>,
}

/// Where a `BufferField` slice points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferFieldRef {
    /// Absolute path of the source Buffer (e.g. `\_SB.PCI0.CRS`).
    pub source_path: String,
    /// Bit offset into the source buffer.
    pub bit_offset: u64,
    /// Bit length of this field's slice.
    pub bit_length: u64,
}

/// Backing storage. We collect every parsed node into one Vec
/// behind an `IrqSafeSpinLock` — namespace builds are one-shot at
/// boot and reads are typically cold.
#[derive(Debug, Default)]
struct Namespace {
    nodes: Vec<AmlNode>,
    /// Concatenated AML byte streams of every table walked, so
    /// Method body offsets resolve cheaply. Each node's
    /// `method_body.0` is an offset into this Vec when the node
    /// was registered from `walk_aml_table`.
    aml: Vec<u8>,
}

pub(crate) static NAMESPACE: IrqSafeSpinLock<Namespace> = IrqSafeSpinLock::new(Namespace {
    nodes: Vec::new(),
    aml: Vec::new(),
});

/// Snapshot of a slice of the stored AML byte stream. Returns the
/// number of bytes copied. Out of range → 0.
pub fn copy_aml_bytes(offset: usize, out: &mut [u8]) -> usize {
    let g = NAMESPACE.lock();
    if offset >= g.aml.len() {
        return 0;
    }
    let n = (g.aml.len() - offset).min(out.len());
    out[..n].copy_from_slice(&g.aml[offset..offset + n]);
    n
}

/// Length of the stored AML byte stream.
pub fn aml_total_len() -> usize {
    NAMESPACE.lock().aml.len()
}

/// Snapshot of the current namespace. Returns the count.
pub fn copy_nodes(out: &mut Vec<AmlNode>) -> usize {
    let g = NAMESPACE.lock();
    out.clear();
    out.extend(g.nodes.iter().cloned());
    g.nodes.len()
}

/// Total number of nodes in the namespace.
pub fn node_count() -> usize {
    NAMESPACE.lock().nodes.len()
}

/// Snapshot of `node_count` and `device_count` taken once at boot,
/// after the first `parse_namespace`. Tests can consult this even
/// after later passes mutate the live namespace.
static BOOT_NODE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static BOOT_DEVICE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Boot-snapshot counts of devices matching the i2c-hid HIDs we
/// care about for diagnostics: AMDI0010 / AMDI0011 / AMDI0019 /
/// AMDI0510 (AMD FCH I2C controllers) and PNP0C50 (the standard
/// HID-over-I2C device HID). These are computed once in
/// `capture_boot_snapshot` so fb::status::paint can read them
/// LOCK-FREE — the previous `find_all_devices_by_hid` × 5 path
/// took NAMESPACE.lock 5 times AND cloned every device path,
/// which on real silicon with 100s of AML devices was both slow
/// and a lock-contention hazard (IrqSafeSpinLock disables IF on
/// the waiter; the executor would freeze).
static BOOT_AMDI001X_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static BOOT_PNP0C50_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// Number of direct AML children under any AMDI*/AMD0* I2C
/// controller. Populated by `dump_amd_i2c_subtree`. Exposed via
/// `boot_amdi_children_count` so the FB status panel can show "are
/// there any devices declared under the I2C controller" without
/// re-walking the namespace each paint.
static BOOT_AMDI_CHILDREN_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Capture the current namespace counts as the boot-time snapshot.
/// Idempotent — first non-zero value sticks. Boot calls this after
/// `parse_namespace` succeeds.
pub fn capture_boot_snapshot() {
    // Pull every device path under the lock in ONE pass (rather
    // than running find_all_devices_by_hid × 5 each of which
    // re-locks). Compute all four diagnostic counts off the snapshot.
    let device_paths: alloc::vec::Vec<alloc::string::String> = {
        let g = NAMESPACE.lock();
        g.nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Device)
            .map(|n| n.path.clone())
            .collect()
    };
    let n = {
        let g = NAMESPACE.lock();
        g.nodes.len() as u32
    };
    let d = device_paths.len() as u32;
    // Match what Linux matches:
    //
    //   - I2C-over-ACPI driver: AMDI* / AMD* prefix (covers
    //     AMDI0010, AMDI0019, AMDI0510, AMDI0020, AMD0010,
    //     AMD0020 — Linux's i2c-designware-platdrv.c match
    //     table, including the newer Phoenix-era 0020 IDs).
    //
    //   - i2c-hid driver: PNP0C50 OR ACPI0C50 in either _HID
    //     or _CID. Vendor touchpads typically have a vendor
    //     _HID (ELANxxxx, SYNAxxxx) plus a _CID that lists
    //     PNP0C50 — Linux's ACPI bus matcher checks both.
    //
    // Sources:
    //   drivers/hid/i2c-hid/i2c-hid-acpi.c     (HID-I2C IDs)
    //   drivers/i2c/busses/i2c-designware-platdrv.c (AMD I2C)
    //   drivers/acpi/bus.c::acpi_driver_match_device (_CID logic)
    let mut amdi_n = 0u32;
    let mut pnp_n = 0u32;
    for path in device_paths.iter() {
        let hid = device_hid(path);
        let cids = device_cids(path);
        let mut matched_amdi = false;
        let mut matched_pnp = false;
        let is_amd_i2c_id = |s: &str| s.starts_with("AMDI") || s.starts_with("AMD0");
        let is_hid_i2c_id = |s: &str| s == "PNP0C50" || s == "ACPI0C50";
        if let Some(ref h) = hid {
            if is_amd_i2c_id(h) {
                matched_amdi = true;
            }
            if is_hid_i2c_id(h) {
                matched_pnp = true;
            }
        }
        for cid in cids.iter() {
            if is_amd_i2c_id(cid) {
                matched_amdi = true;
            }
            if is_hid_i2c_id(cid) {
                matched_pnp = true;
            }
        }
        if matched_amdi {
            amdi_n += 1;
        }
        if matched_pnp {
            pnp_n += 1;
        }
    }
    BOOT_NODE_COUNT.store(n, core::sync::atomic::Ordering::Release);
    BOOT_DEVICE_COUNT.store(d, core::sync::atomic::Ordering::Release);
    BOOT_AMDI001X_COUNT.store(amdi_n, core::sync::atomic::Ordering::Release);
    BOOT_PNP0C50_COUNT.store(pnp_n, core::sync::atomic::Ordering::Release);
}

/// Real-HW bring-up diagnostic. Walks every AMDI* / AMD0* controller
/// device in the AML namespace and logs each one's path + _HID + its
/// direct children (path, _HID, _CID list). Intended to be called
/// LATE in boot — after most other init prints — so the dump lands
/// near the end of klog and stays visible in the FB status panel's
/// klog tail (which only shows the trailing 12 lines).
///
/// When PNP0C50 / ACPI0C50 enumeration returns zero on real hardware
/// but the controller _HID is present, this dump is the empirical
/// answer to "what's actually attached to the I2C controller". The
/// child's _HID/_CID tells us whether to extend i2c-hid match (a
/// vendor _HID with PNP0C50 in _CID we don't yet handle), write a
/// vendor driver (Elan / Synaptics RMI4), or pivot to a non-I2C
/// input path entirely (EC-attached keyboard via Notify, vendor
/// MMIO).
/// Walk the entire AML namespace and log every device that has an
/// `I2cSerialBus` in its `_CRS`. This is the touchpad-finder for
/// BIOSes that don't park I2C slaves under a recognisable I2C
/// controller HID — Renoir 4700U is the motivating case (AMDI0005
/// is actually PEP, and the touchpad's parent I2C controller has
/// either no `_HID` or one we don't match).
///
/// For each slave, log:
///   - device path
///   - `_HID` and `_CID` list
///   - I2C slave address + bus speed
///   - the `resource_source` (parent controller path) of its
///     I2cSerialBus — that's the thing we'd need to bind in
///     `amd_fch::probe_all` to make the slave reachable.
///
/// Use this to identify (a) which controller HID we're missing
/// from `AMD_FCH_HIDS` and (b) which touchpad vendor `_HID` to
/// add to the i2c-hid bind whitelist.
pub fn dump_i2c_slaves() {
    use core::fmt::Write as _;
    use crate::resource::ResourceItem;
    let device_paths = list_all_device_paths();
    let mut any = false;
    for path in device_paths.iter() {
        let items = match crate::prt_crs::evaluate_crs_for(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut i2c: Option<(u16, u32, alloc::string::String)> = None;
        for item in &items {
            if let ResourceItem::I2cSerialBus {
                slave_address,
                connection_speed,
                resource_source,
                ..
            } = item
            {
                i2c = Some((
                    *slave_address,
                    *connection_speed,
                    resource_source.clone(),
                ));
                break;
            }
        }
        let (addr, speed, src) = match i2c {
            Some(t) => t,
            None => continue,
        };
        if !any {
            let _ = writeln!(
                narf_console::Writer,
                "  aml-i2c-slaves: every device with an I2cSerialBus in _CRS:",
            );
            any = true;
        }
        let hid = device_hid(path);
        let cids = device_cids(path);
        let _ = writeln!(
            narf_console::Writer,
            "    slave: {} _HID={} _CID={:?} addr=0x{:02x} speed={} parent={}",
            path,
            hid.as_deref().unwrap_or("(none)"),
            cids,
            addr,
            speed,
            src,
        );
    }
    if !any {
        let _ = writeln!(
            narf_console::Writer,
            "  aml-i2c-slaves: no devices with I2cSerialBus resources \
             (touchpad not on I2C, OR _CRS decoder doesn't recognise the variant)",
        );
    }
}

/// Log every device in the AML namespace with its `_HID` and
/// `_CID` list. Used for full namespace audits when we don't know
/// the touchpad / sensor / accelerometer HID upfront — `grep`
/// the boot log for the line tagged with the vendor we suspect.
///
/// Format: `aml-dev: <path> _HID=<hid> _CID=<list>`. Devices with
/// no `_HID` are still emitted so the parent chain to a leaf
/// device is visible.
pub fn dump_all_devices() {
    use core::fmt::Write as _;
    let device_paths = list_all_device_paths();
    let _ = writeln!(
        narf_console::Writer,
        "  aml-dev-dump: {} device(s) in namespace:",
        device_paths.len()
    );
    for path in device_paths.iter() {
        let hid = device_hid(path);
        let cids = device_cids(path);
        let _ = writeln!(
            narf_console::Writer,
            "  aml-dev: {} _HID={} _CID={:?}",
            path,
            hid.as_deref().unwrap_or(""),
            cids
        );
    }
}

pub fn dump_amd_i2c_subtree() {
    use core::fmt::Write as _;
    let device_paths = list_all_device_paths();
    let mut any = false;
    let mut total_children: u32 = 0;
    for path in device_paths.iter() {
        let h = device_hid(path);
        let is_amdi = match &h {
            Some(s) => s.starts_with("AMDI") || s.starts_with("AMD0"),
            None => false,
        };
        if !is_amdi {
            continue;
        }
        if !any {
            let _ = writeln!(
                narf_console::Writer,
                "  aml-i2c-subtree: dumping AMD I2C controllers + children:",
            );
            any = true;
        }
        let _ = writeln!(
            narf_console::Writer,
            "  aml-i2c-ctrl: {} _HID={}",
            path,
            h.as_deref().unwrap_or("(none)")
        );
        let prefix = alloc::format!("{}.", path);
        let mut child_n = 0u32;
        for cpath in device_paths.iter() {
            if !cpath.starts_with(&prefix) {
                continue;
            }
            // Direct children only — skip deeper descendants.
            let rest = &cpath[prefix.len()..];
            if rest.contains('.') {
                continue;
            }
            child_n += 1;
            total_children += 1;
            let ch_hid = device_hid(cpath);
            let ch_cids = device_cids(cpath);
            let _ = writeln!(
                narf_console::Writer,
                "    child: {} _HID={} _CID={:?}",
                cpath,
                ch_hid.as_deref().unwrap_or("(none)"),
                ch_cids
            );
        }
        if child_n == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "    (no direct children — controller has no I2C slaves declared in AML)",
            );
        }
    }
    if !any {
        let _ = writeln!(
            narf_console::Writer,
            "  aml-i2c-subtree: no AMDI*/AMD0* controllers found in namespace",
        );
    }
    BOOT_AMDI_CHILDREN_COUNT.store(total_children, core::sync::atomic::Ordering::Release);
}

/// Returns `(boot_node_count, boot_device_count)` from the snapshot
/// taken after the first successful boot-time `parse_namespace`.
/// Both `(0, 0)` until `capture_boot_snapshot` runs.
pub fn boot_snapshot() -> (u32, u32) {
    (
        BOOT_NODE_COUNT.load(core::sync::atomic::Ordering::Acquire),
        BOOT_DEVICE_COUNT.load(core::sync::atomic::Ordering::Acquire),
    )
}

/// Lock-free boot-snapshot count of AMD FCH I2C controllers in
/// the AML namespace. For diagnostics; equivalent to what
/// `find_all_devices_by_hid` for each of {AMDI0010, AMDI0011,
/// AMDI0019, AMDI0510} returned at boot, but computed ONCE under
/// a single NAMESPACE.lock and exposed as an atomic.
pub fn boot_amdi001x_count() -> u32 {
    BOOT_AMDI001X_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

/// Lock-free boot-snapshot count of PNP0C50 (HID-over-I2C) devices.
pub fn boot_pnp0c50_count() -> u32 {
    BOOT_PNP0C50_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

/// Lock-free count of direct children under any AMDI*/AMD0* I2C
/// controller in AML. Populated by `dump_amd_i2c_subtree`. The FB
/// status panel reads this to surface "controller has N declared
/// I2C slaves" without re-walking the namespace each paint.
pub fn boot_amdi_children_count() -> u32 {
    BOOT_AMDI_CHILDREN_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

/// Find the first node with the given canonical path
/// (e.g. `"\\_SB.PCI0"`). Path comparison is exact.
pub fn find_node(path: &str) -> Option<AmlNode> {
    let g = NAMESPACE.lock();
    g.nodes.iter().find(|n| n.path == path).cloned()
}

/// Suffix-match fallback for the AML evaluator's relative-name
/// lookups. Strips a leading `"\\"` from `path`, then returns the
/// first node whose canonical path ends with `"." + tail` — so
/// `"PRTP"` matches `"\\_SB.PCI0.PRTP"`. Used when the eval can't
/// pin a name to the caller's exact scope (the eval doesn't yet
/// thread caller-scope through every `read_name_string`).
///
/// This is an approximation of ACPI 6.5 §5.3's
/// "scope-walk-up-then-root" rule; it works for sibling references
/// inside a Method body (e.g. `Return(PRTP)` from `\_SB.PCI0._PRT`)
/// but doesn't handle the rare case where two scopes export the
/// same leaf name and only one is in-scope. Tightens to a real
/// scope walk when the eval starts propagating
/// `current_method_scope`.
pub fn find_node_by_suffix(path: &str) -> Option<AmlNode> {
    let tail = path.strip_prefix("\\").unwrap_or(path);
    if tail.is_empty() {
        return None;
    }
    let needle = {
        let mut s = alloc::string::String::with_capacity(tail.len() + 1);
        s.push('.');
        s.push_str(tail);
        s
    };
    let g = NAMESPACE.lock();
    g.nodes
        .iter()
        .find(|n| n.path.ends_with(&needle))
        .cloned()
}

/// Iterate every Device node, calling `f` with its path.
///
/// `f` is called with the lock **released** — taking a snapshot
/// up-front lets the closure freely call other namespace APIs
/// (`find_node`, `evaluate_method`, etc.) that re-acquire
/// `NAMESPACE.lock()`. Without this, drivers like `acpi-fan` that
/// look up `<device>._HID` for every iterated device deadlock on
/// the non-recursive spinlock.
pub fn for_each_device<F: FnMut(&AmlNode)>(mut f: F) {
    let snapshot: alloc::vec::Vec<AmlNode> = {
        let g = NAMESPACE.lock();
        g.nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Device)
            .cloned()
            .collect()
    };
    for n in &snapshot {
        f(n);
    }
}

/// Iterate every namespace node, calling `f`. Same lock-released
/// callback contract as [`for_each_device`].
pub fn for_each_node<F: FnMut(&AmlNode)>(mut f: F) {
    let snapshot: alloc::vec::Vec<AmlNode> = {
        let g = NAMESPACE.lock();
        g.nodes.clone()
    };
    for n in &snapshot {
        f(n);
    }
}

/// Iterate every node of a specific kind, calling `f`.
///
/// Same lock-released-during-callback contract as
/// [`for_each_device`].
pub fn for_each_node_of_kind<F: FnMut(&AmlNode)>(kind: NodeKind, mut f: F) {
    let snapshot: alloc::vec::Vec<AmlNode> = {
        let g = NAMESPACE.lock();
        g.nodes
            .iter()
            .filter(|n| n.kind == kind)
            .cloned()
            .collect()
    };
    for n in &snapshot {
        f(n);
    }
}

/// Read a device's `_HID` property as a string. Returns the
/// EISA-style ID (e.g. `"PNP0A03"`) when the namespace declares
/// `_HID` as a literal `Name(_HID, "PNP0A03")` *or* as the more
/// common integer-encoded EISA ID. The integer form is decoded via
/// the standard EISA-ID-from-u32 algorithm (3 letters in
/// bits[15:0] + 4 hex digits in bits[31:16]). Returns `None` when
/// the device has no `_HID`, or when the value isn't a recognised
/// shape.
/// Return the path of every Device node in the namespace. Used by
/// driver bind paths that need to walk all devices to check _HID
/// + _CID combinations (rather than searching by a single _HID).
/// Single NAMESPACE.lock pass.
pub fn list_all_device_paths() -> alloc::vec::Vec<alloc::string::String> {
    let g = NAMESPACE.lock();
    g.nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Device)
        .map(|n| n.path.clone())
        .collect()
}

pub fn device_hid(device_path: &str) -> Option<alloc::string::String> {
    use alloc::string::String;
    let mut hid_path = String::from(device_path);
    hid_path.push_str("._HID");
    let g = NAMESPACE.lock();
    let node = g.nodes.iter().find(|n| n.path == hid_path)?;
    match &node.value {
        Some(NameValue::String(s)) => Some(s.clone()),
        Some(NameValue::Integer(v)) => Some(eisa_id_from_u32(*v as u32)),
        _ => None,
    }
}

/// Look up `_CID` (Compatible ID) for a device. ACPI allows
/// `_CID` to be either a single integer/string OR a package of
/// such — many vendor HID-over-I2C touchpads carry a vendor
/// `_HID` (e.g. `ELAN0001`) PLUS a `_CID` listing the standard
/// `PNP0C50` so the OS can bind it via the generic HID-I2C
/// driver. This helper returns ALL CID strings as a Vec — empty
/// if no `_CID` is present.
pub fn device_cids(device_path: &str) -> alloc::vec::Vec<alloc::string::String> {
    use alloc::string::String;
    let mut cid_path = String::from(device_path);
    cid_path.push_str("._CID");
    let g = NAMESPACE.lock();
    let node = match g.nodes.iter().find(|n| n.path == cid_path) {
        Some(n) => n,
        None => return alloc::vec::Vec::new(),
    };
    let mut out = alloc::vec::Vec::new();
    match &node.value {
        Some(NameValue::String(s)) => out.push(s.clone()),
        Some(NameValue::Integer(v)) => out.push(eisa_id_from_u32(*v as u32)),
        Some(NameValue::Package(items)) => {
            for item in items.iter() {
                match item {
                    NameValue::String(s) => out.push(s.clone()),
                    NameValue::Integer(v) => out.push(eisa_id_from_u32(*v as u32)),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

/// Evaluate `\_S5` and return the platform's `(SLP_TYPa, SLP_TYPb)`
/// values for ACPI S5 (soft-off). The namespace stores `\_S5_` as
/// a `Name` whose body is a `Package(...)` of at least two
/// integers — element 0 is SLP_TYPa, element 1 is SLP_TYPb;
/// elements 2-3 are reserved.
///
/// Spec: ACPI 6.5 §7.4 (System State Definitions),
/// §16.1.6 (`\_Sx` Object).
/// <https://uefi.org/specs/ACPI/6.5/>
///
/// Returns `None` when the namespace hasn't been built yet, when
/// `\_S5` is missing (rare — every spec-conformant DSDT carries
/// it), when the body isn't a Package, or when fewer than two
/// integer elements are present. Callers fall back to platform
/// defaults (QEMU + most x86_64 firmware uses `(5, 0)`).
pub fn evaluate_s5() -> Option<(u8, u8)> {
    let node = find_node("\\_S5_").or_else(|| find_node("\\_S5"))?;
    let (offset, length) = match node.value? {
        NameValue::Unparsed { offset, length } if length > 0 => (offset, length),
        _ => return None,
    };
    let mut body = alloc::vec![0u8; length];
    let n = copy_aml_bytes(offset, &mut body);
    if n < length {
        return None;
    }
    let value = crate::eval::decode_value(&body).ok()?;
    let pkg = match value {
        crate::Value::Package(p) => p,
        _ => return None,
    };
    if pkg.len() < 2 {
        return None;
    }
    let typa = pkg[0].as_integer() as u8 & 0x7;
    let typb = pkg[1].as_integer() as u8 & 0x7;
    Some((typa, typb))
}

/// Decode the 32-bit EISA ID encoding used by ACPI `_HID` /
/// `_CID` integer values into the canonical `"AAAxxxx"` string
/// form. Bits[15:0] hold three 5-bit packed letters
/// (`'A' + value - 1`); bits[31:16] hold a big-endian u16 of hex
/// digits. The encoding is in ACPI 6.5 §5.6.7.
pub fn eisa_id_from_u32(v: u32) -> alloc::string::String {
    let l1 = ((v >> 2) & 0x1F) as u8;
    let l2 = (((v & 0x3) << 3) | ((v >> 13) & 0x7)) as u8;
    let l3 = ((v >> 8) & 0x1F) as u8;
    let h0 = ((v >> 20) & 0xF) as u8;
    let h1 = ((v >> 16) & 0xF) as u8;
    let h2 = ((v >> 28) & 0xF) as u8;
    let h3 = ((v >> 24) & 0xF) as u8;
    fn nyb(n: u8) -> char {
        if n < 10 { (b'0' + n) as char } else { (b'A' + n - 10) as char }
    }
    let mut s = alloc::string::String::with_capacity(7);
    s.push(((l1 - 1) + b'A') as char);
    s.push(((l2 - 1) + b'A') as char);
    s.push(((l3 - 1) + b'A') as char);
    s.push(nyb(h0));
    s.push(nyb(h1));
    s.push(nyb(h2));
    s.push(nyb(h3));
    s
}

/// Find the first Device node whose `_HID` property matches `hid`.
pub fn find_device_by_hid(hid: &str) -> Option<AmlNode> {
    let g = NAMESPACE.lock();
    for device in g.nodes.iter().filter(|n| n.kind == NodeKind::Device) {
        // Look for _HID child of this device.
        let mut hid_path = String::from(&device.path);
        hid_path.push_str("._HID");
        if let Some(hid_node) = g.nodes.iter().find(|n| n.path == hid_path) {
            if let Some(NameValue::String(s)) = &hid_node.value {
                if s == hid {
                    return Some(device.clone());
                }
            }
        }
    }
    None
}

/// Find every device whose normalized `_HID` (string form, with
/// EISA-integer encodings decoded to `PNPxxxx` / `ACPIxxxx`) equals
/// `hid`. Used by enumerators that expect multiple instances of the
/// same controller class (e.g. AMD FCH I2C, where Zen2 typically
/// exposes 2-4 controllers).
pub fn find_all_devices_by_hid(hid: &str) -> Vec<AmlNode> {
    let mut out = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    {
        let g = NAMESPACE.lock();
        for device in g.nodes.iter().filter(|n| n.kind == NodeKind::Device) {
            paths.push(device.path.clone());
        }
    }
    for path in paths {
        if let Some(s) = device_hid(&path) {
            if s == hid {
                if let Some(node) = find_node(&path) {
                    out.push(node);
                }
            }
        }
    }
    out
}

/// Walk the DSDT + every SSDT and build the namespace. Idempotent —
/// repeated calls clear the table and rebuild.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the FADT chain
/// it leads to must also be identity-mapped (the BSP's 1 GiB low
/// identity map covers all sane QEMU layouts).
pub unsafe fn parse_namespace(rsdp_phys: PhysAddr) -> Result<u32, AmlError> {
    {
        let mut g = NAMESPACE.lock();
        g.nodes.clear();
    }

    // SAFETY: caller assertion.
    let dsdt = unsafe { narf_acpi::parse_fadt_for_dsdt(rsdp_phys) }?;
    // SAFETY: identity-mapped per caller assertion.
    let n = unsafe { walk_aml_table(dsdt, "\\")? };

    let mut total = n;
    // SAFETY: caller assertion.
    unsafe {
        let mut e: Result<(), AmlError> = Ok(());
        let _ = narf_acpi::walk_ssdts(rsdp_phys, |phys, _hdr| {
            if e.is_err() {
                return;
            }
            // SAFETY: identity-mapped (covered by enclosing block).
            match walk_aml_table(phys, "\\") {
                Ok(c) => total += c,
                Err(x) => e = Err(x),
            }
        })?;
        e?;
    }
    // Audit #4: discover the EC device's command/data ports
    // from its _CRS so EmbeddedCtl OpRegion field accesses
    // can drive the firmware protocol. Must run BEFORE
    // notify_reg_handlers because _REG(EmbeddedCtl, 1) on the
    // EC device may immediately trigger field accesses.
    crate::eval::discover_ec_ports();
    crate::ec::register_initcalls();
    // Audit #18: notify every device that owns an OpRegion that
    // its region-space is now "connected". Required by ACPI 6.5
    // §6.5.4 before any field read; EC + GenericSerialBus drivers
    // notably refuse to operate without it. Best-effort —
    // missing _REG methods just return MethodNotFound and we
    // move on.
    crate::eval::notify_reg_handlers();
    // Audit #19: power on every device whose _PR0 lists a
    // PowerResource that we control. Per ACPI 6.5 §7.3 the OS
    // must drive _PR0's PowerResources to ON before evaluating
    // a device's _CRS. Devices without _PR0 are presumed
    // always-on (no-op).
    crate::eval::power_on_all_devices();
    // Wire ACPI fixed-hardware events (lid + power + sleep button):
    // walk the namespace for PNP0C0D / PNP0C0C / PNP0C0E devices,
    // register Notify(0x80) handlers, and seed the initial lid
    // state from `_LID`. Best-effort — desktops without a lid
    // simply contribute no devices and `current_lid_state()`
    // stays `None`.
    let _ = crate::buttons::init();
    Ok(total)
}

/// Internal: parse one AML table (DSDT or SSDT) starting at the
/// given physical address, registering nodes under `root_path`.
/// Appends the table's AML bytes to the namespace-wide AML store
/// so `method_body` offsets are stable references into that store.
unsafe fn walk_aml_table(phys: u64, root_path: &str) -> Result<u32, AmlError> {
    // SAFETY: caller assertion.
    let total = unsafe { (phys as *const SdtHeader).read_unaligned().length as usize };
    if total <= 36 {
        return Ok(0);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(phys as *const u8, total) };
    let aml_slice = &body[36..];

    // Append into the global AML store, remember the base offset so
    // node body-offsets are absolute into that store.
    let base = {
        let mut g = NAMESPACE.lock();
        let b = g.aml.len();
        g.aml.extend_from_slice(aml_slice);
        b
    };

    let mut p = Parser::new(aml_slice);
    let mut count = 0u32;
    parse_term_list(&mut p, root_path, &mut count, aml_slice.len(), base)?;
    Ok(count)
}

// ── AML decoder ─────────────────────────────────────────────────────

const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const NAME_OP: u8 = 0x08;
const BYTE_PREFIX: u8 = 0x0A;
const WORD_PREFIX: u8 = 0x0B;
const DWORD_PREFIX: u8 = 0x0C;
const STRING_PREFIX: u8 = 0x0D;
const QWORD_PREFIX: u8 = 0x0E;
const SCOPE_OP: u8 = 0x10;
const BUFFER_OP: u8 = 0x11;
const PACKAGE_OP: u8 = 0x12;
const VAR_PACKAGE_OP: u8 = 0x13;
const METHOD_OP: u8 = 0x14;
const EXT_OP_PREFIX: u8 = 0x5B;
const ROOT_CHAR: u8 = b'\\';
const PARENT_PREFIX: u8 = b'^';
const DUAL_NAME_PREFIX: u8 = 0x2E;
const MULTI_NAME_PREFIX: u8 = 0x2F;
const ONES_OP: u8 = 0xFF;
const IF_OP: u8 = 0xA0;
const ELSE_OP: u8 = 0xA1;

// Extended opcodes (after 0x5B prefix).
const EXT_MUTEX_OP: u8 = 0x01;
const EXT_EVENT_OP: u8 = 0x02;
const EXT_OP_REGION_OP: u8 = 0x80;
const EXT_FIELD_OP: u8 = 0x81;
const EXT_DEVICE_OP: u8 = 0x82;
const EXT_PROCESSOR_OP: u8 = 0x83;
const EXT_POWER_RES_OP: u8 = 0x84;
const EXT_THERMAL_ZONE_OP: u8 = 0x85;
const EXT_INDEX_FIELD_OP: u8 = 0x86;
const EXT_BANK_FIELD_OP: u8 = 0x87;

pub(crate) struct Parser<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, AmlError> {
        let b = self.buf.get(self.pos).copied().ok_or(AmlError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Result<(), AmlError> {
        if self.pos + n > self.buf.len() {
            return Err(AmlError::Truncated);
        }
        self.pos += n;
        Ok(())
    }

    fn slice_n(&mut self, n: usize) -> Result<&'a [u8], AmlError> {
        if self.pos + n > self.buf.len() {
            return Err(AmlError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// PkgLength: 1-4 bytes encoding the *total length* of a Pkg
/// (including the PkgLength bytes themselves). Top 2 bits of byte 0
/// are the `byte_count` (number of *additional* bytes, 0..=3).
/// When count==0, byte 0's low 6 bits are the length. Otherwise,
/// byte 0's low 4 bits are the low nibble + each extra byte
/// contributes 8 bits.
pub(crate) fn read_pkg_length(p: &mut Parser<'_>) -> Result<usize, AmlError> {
    let first = p.read_u8()?;
    let extra = (first >> 6) & 0x3;
    let mut len: usize = if extra == 0 {
        (first & 0x3F) as usize
    } else {
        (first & 0x0F) as usize
    };
    for i in 0..extra {
        let next = p.read_u8()?;
        len |= (next as usize) << (4 + 8 * i as usize);
    }
    Ok(len)
}

/// NameString: optional root/parent prefix, then either a single
/// 4-byte NameSeg, DualNamePrefix + 2 segs, MultiNamePrefix +
/// count + count*4 bytes, or NullName (0x00 — handled by caller's
/// peek). Returns the canonical path string assembled relative to
/// `parent`. NameSegs are stripped of trailing underscores (ACPI
/// leading-zero / underscore convention).
pub(crate) fn read_name_string(p: &mut Parser<'_>, parent: &str) -> Result<String, AmlError> {
    let mut s = String::new();
    let first = p.peek().ok_or(AmlError::Truncated)?;

    if first == ROOT_CHAR {
        p.skip(1)?;
        s.push('\\');
    } else {
        // Parent prefixes (`^`) — count then resolve against parent.
        let mut up = 0usize;
        while p.peek() == Some(PARENT_PREFIX) {
            p.skip(1)?;
            up += 1;
        }
        // Build absolute prefix from parent, popping `up` segments.
        let mut base = if parent.is_empty() {
            String::from("\\")
        } else {
            String::from(parent)
        };
        for _ in 0..up {
            // Drop one segment after the last '.'. If we hit root,
            // leave it as '\\'.
            if let Some(dot) = base.rfind('.') {
                base.truncate(dot);
            } else if base.len() > 1 {
                base.truncate(1); // back to "\\"
            }
        }
        s.push_str(&base);
    }

    // Now decode the name-path portion.
    let pfx = p.peek().ok_or(AmlError::Truncated)?;
    let segs: usize;
    let consumed_pfx: usize;
    if pfx == DUAL_NAME_PREFIX {
        segs = 2;
        consumed_pfx = 1;
    } else if pfx == MULTI_NAME_PREFIX {
        consumed_pfx = 2;
        // Multi: 0x2F, count_u8.
        if p.buf.len() < p.pos + 2 {
            return Err(AmlError::Truncated);
        }
        segs = p.buf[p.pos + 1] as usize;
    } else if pfx == 0 {
        // NullName: empty path.
        p.skip(1)?;
        return Ok(s);
    } else {
        segs = 1;
        consumed_pfx = 0;
    }
    p.skip(consumed_pfx)?;

    // Each segment: 4 bytes, [A-Z_][A-Z0-9_]{3}.
    if !s.is_empty() && !s.ends_with('\\') { /* parent already there */ }
    for i in 0..segs {
        let bytes = p.slice_n(4)?;
        // Validate first char.
        let c0 = bytes[0];
        if !(c0.is_ascii_uppercase() || c0 == b'_') {
            return Err(AmlError::BadNameSegment);
        }
        if i == 0 && !s.ends_with('\\') && !s.is_empty() {
            s.push('.');
        } else if i > 0 {
            s.push('.');
        }
        // Strip trailing underscore padding.
        let mut end = 4;
        while end > 0 && bytes[end - 1] == b'_' {
            end -= 1;
        }
        if end == 0 {
            end = 1;
        } // keep at least one char
        for c in &bytes[..end] {
            s.push(*c as char);
        }
    }
    Ok(s)
}

/// Resolve a NameString relative to `parent`, producing a fully-
/// qualified absolute path. NullName → `parent`.
pub(crate) fn full_path(name: String, parent: &str) -> String {
    if name.is_empty() {
        if parent.is_empty() {
            String::from("\\")
        } else {
            String::from(parent)
        }
    } else if name.starts_with('\\') {
        name
    } else if parent.is_empty() || parent == "\\" {
        let mut s = String::from("\\");
        s.push_str(&name);
        s
    } else {
        let mut s = String::from(parent);
        s.push('.');
        s.push_str(&name);
        s
    }
}

/// Try to decode a flat-constant value at the cursor. Returns the
/// value + advances the parser past it. Anything we don't decode
/// returns `Unparsed` and skips to `after_offset`.
pub(crate) fn try_read_simple_value(
    p: &mut Parser<'_>,
    after_offset: usize,
) -> Result<NameValue, AmlError> {
    let start_pos = p.pos;
    let op = p.peek().ok_or(AmlError::Truncated)?;
    let val = match op {
        ZERO_OP => {
            p.skip(1)?;
            NameValue::Integer(0)
        }
        ONE_OP => {
            p.skip(1)?;
            NameValue::Integer(1)
        }
        ONES_OP => {
            p.skip(1)?;
            NameValue::Integer(u64::MAX)
        }
        BYTE_PREFIX => {
            p.skip(1)?;
            let v = p.read_u8()?;
            NameValue::Integer(v as u64)
        }
        WORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(2)?;
            NameValue::Integer(u16::from_le_bytes([bytes[0], bytes[1]]) as u64)
        }
        DWORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(4)?;
            NameValue::Integer(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
        }
        QWORD_PREFIX => {
            p.skip(1)?;
            let bytes = p.slice_n(8)?;
            NameValue::Integer(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }
        STRING_PREFIX => {
            p.skip(1)?;
            // Null-terminated AsciiString.
            let mut s = String::new();
            loop {
                let c = p.read_u8()?;
                if c == 0 {
                    break;
                }
                s.push(c as char);
            }
            NameValue::String(s)
        }
        _ => {
            // Skip past whatever this is, leave the body offset
            // for a future evaluator.
            let length = after_offset.saturating_sub(start_pos);
            p.pos = after_offset;
            return Ok(NameValue::Unparsed {
                offset: start_pos,
                length,
            });
        }
    };
    // Snap to after_offset in case the body has trailing bytes
    // (e.g. when nested inside a larger pkg).
    if p.pos < after_offset {
        p.pos = after_offset;
    }
    Ok(val)
}

/// TermList: a sequence of TermObj's bounded by `end_offset` (an
/// absolute position into the parser's buffer). Each TermObj is
/// either a NamedObj (Scope/Device/Method/...) or a SimpleObj
/// (we skip over those — they're not namespace-creating).
fn parse_term_list(
    p: &mut Parser<'_>,
    parent: &str,
    count: &mut u32,
    end_offset: usize,
    base: usize,
) -> Result<(), AmlError> {
    // Soft-fail wrapper: BadNameSegment / Truncated mid-parse return
    // Ok(()) instead of propagating, so the boot-time DSDT walk
    // registers everything it *can* parse rather than rejecting the
    // whole table on the first oddity. Real DSDTs occasionally
    // contain bytes our limited decoder can't follow (computed
    // TermArgs inside OpRegion offsets, etc.); the caller's pkg-end
    // clamp re-anchors at the next named object.
    match parse_term_list_inner(p, parent, count, end_offset, base) {
        Ok(()) => Ok(()),
        Err(AmlError::BadNameSegment) => Ok(()),
        Err(AmlError::Truncated) => Ok(()),
        Err(AmlError::BadPkgLength) => Ok(()),
        Err(AmlError::OutOfPkg) => Ok(()),
        Err(e) => Err(e),
    }
}

fn parse_term_list_inner(
    p: &mut Parser<'_>,
    parent: &str,
    count: &mut u32,
    end_offset: usize,
    base: usize,
) -> Result<(), AmlError> {
    while p.pos < end_offset {
        let op = match p.peek() {
            Some(b) => b,
            None => return Ok(()),
        };
        match op {
            SCOPE_OP => {
                p.skip(1)?;
                let pkg_start = p.pos;
                let pkg_len = read_pkg_length(p)?;
                let pkg_end = pkg_start + pkg_len;
                let name = read_name_string(p, parent)?;
                let path = full_path(name, parent);
                push_node(AmlNode {
                    path: path.clone(),
                    kind: NodeKind::Scope,
                    value: None,
                    method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                });
                *count += 1;
                parse_term_list(p, &path, count, pkg_end, base)?;
                if p.pos != pkg_end {
                    p.pos = pkg_end;
                }
            }
            NAME_OP => {
                p.skip(1)?;
                let name = read_name_string(p, parent)?;
                let path = full_path(name, parent);
                // Body is a DataRefObject. Three shapes worth
                // distinguishing:
                //
                //   1. Flat constant (Zero/One/Byte/Word/Dword/Qword
                //      /String). `try_read_simple_value` decodes +
                //      advances; record `NameValue::Integer/String`.
                //   2. Buffer (op 0x11) / Package (0x12) /
                //      VarPackage (0x13). The body is `op | PkgLength
                //      | payload`. We can't decode it inline (the
                //      term-list parser doesn't run TermArgs) but we
                //      MUST advance the cursor past the full body
                //      so subsequent siblings parse correctly. Read
                //      the PkgLength to get the right extent and
                //      record `Unparsed { offset, length }` pointing
                //      at the op byte so consumers (prt_crs,
                //      eval::decode_value) can decode later.
                //   3. Anything else — fall back to
                //      `try_read_simple_value`'s catch-all (skips
                //      one byte, records Unparsed{length: ...}).
                let body_start = p.pos;
                let op = p.peek().unwrap_or(0);
                let v = if op == BUFFER_OP || op == PACKAGE_OP || op == VAR_PACKAGE_OP {
                    // Skip the op byte, then read PkgLength to get
                    // the rest of the body's size. PkgLength encodes
                    // its own bytes + the payload; total body =
                    // 1 (op) + pkg_len.
                    p.skip(1)?;
                    let pkg_payload_start = p.pos;
                    let pkg_len = read_pkg_length(p)?;
                    let total_body = 1 + pkg_len; // op + (pkglen + payload)
                    let body_end = pkg_payload_start
                        .checked_add(pkg_len)
                        .ok_or(AmlError::Truncated)?
                        .min(p.buf.len());
                    p.pos = body_end;
                    Some(NameValue::Unparsed {
                        offset: base + body_start,
                        length: total_body,
                    })
                } else {
                    // Bound for the simple-value fallback. There's no
                    // PkgLength on a flat Name body, so we let the
                    // decoder consume what it recognises and only
                    // skip one byte if it bails — the parent
                    // TermList loop re-anchors on the next valid op.
                    let body_after = (p.pos + 1).min(p.buf.len());
                    match try_read_simple_value(p, body_after) {
                        Ok(NameValue::Unparsed { offset, length }) => {
                            // Translate cursor-relative offset into
                            // an absolute AML-store offset for the
                            // benefit of `eval::decode_value`.
                            Some(NameValue::Unparsed {
                                offset: base + offset,
                                length,
                            })
                        }
                        Ok(v) => Some(v),
                        Err(_) => {
                            // Defensive: if the helper threw
                            // Truncated mid-decode, leave the cursor
                            // alone and record a zero-length stub.
                            Some(NameValue::Unparsed {
                                offset: base + body_start,
                                length: 0,
                            })
                        }
                    }
                };
                push_node(AmlNode {
                    path,
                    kind: NodeKind::Name,
                    value: v,
                    method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                });
                *count += 1;
            }
            METHOD_OP => {
                p.skip(1)?;
                let pkg_start = p.pos;
                let pkg_len = read_pkg_length(p)?;
                let pkg_end = pkg_start + pkg_len;
                let name = read_name_string(p, parent)?;
                let path = full_path(name, parent);
                // 1 byte MethodFlags follows the name.
                let flags = p.read_u8()?;
                let body_off = base + p.pos;
                let body_len = pkg_end.saturating_sub(p.pos);
                push_node(AmlNode {
                    path,
                    kind: NodeKind::Method,
                    value: None,
                    method_body: (body_off, body_len),
                    method_flags: flags,
                    buffer_field: None,
                });
                *count += 1;
                p.pos = pkg_end;
            }
            EXT_OP_PREFIX => {
                let next = p.buf.get(p.pos + 1).copied().ok_or(AmlError::Truncated)?;
                p.skip(2)?;
                match next {
                    EXT_DEVICE_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::Device,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end {
                            p.pos = pkg_end;
                        }
                    }
                    EXT_PROCESSOR_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        // ProcID(1) + PblkAddr(4) + PblkLen(1) = 6 bytes.
                        p.skip(6)?;
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::Processor,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end {
                            p.pos = pkg_end;
                        }
                    }
                    EXT_POWER_RES_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        // SystemLevel(1) + ResourceOrder(2) = 3 bytes.
                        p.skip(3)?;
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::PowerResource,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end {
                            p.pos = pkg_end;
                        }
                    }
                    EXT_THERMAL_ZONE_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::ThermalZone,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                        parse_term_list(p, &path, count, pkg_end, base)?;
                        if p.pos != pkg_end {
                            p.pos = pkg_end;
                        }
                    }
                    EXT_MUTEX_OP => {
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        // SyncFlags (1 byte).
                        p.skip(1)?;
                        push_node(AmlNode {
                            path,
                            kind: NodeKind::Mutex,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                    }
                    EXT_EVENT_OP => {
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path,
                            kind: NodeKind::Event,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                    }
                    EXT_OP_REGION_OP => {
                        // Parse NameString then register the namespace node.
                        let name = read_name_string(p, parent)?;
                        let path = full_path(name, parent);
                        push_node(AmlNode {
                            path: path.clone(),
                            kind: NodeKind::OpRegion,
                            value: None,
                            method_body: (0, 0),
                    method_flags: 0,
                    buffer_field: None,
                        });
                        *count += 1;
                        // Try to decode RegionSpace + TermArg×2 and register
                        // the region. Returns true when both TermArgs were flat
                        // literals (parser is past the declaration, loop can
                        // continue). Returns false for complex TermArgs — bail
                        // so the outer pkg_end clamp re-anchors (same as the
                        // original behaviour for non-literal regions).
                        match oregion::parse_op_region_after_name(p, path) {
                            Ok(true) => {} // parsed cleanly; continue loop
                            Ok(false) | Err(_) => return Ok(()),
                        }
                    }
                    EXT_FIELD_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        // Parse individual field entries and register them.
                        // parse_field_body pushes a real Field node per
                        // NameSeg so find_node can resolve them.
                        let _ = oregion::parse_field_body(p, parent, pkg_end);
                        *count += 1;
                        p.pos = pkg_end;
                    }
                    EXT_INDEX_FIELD_OP => {
                        // IndexField (audit #7): registers each
                        // inner field with index/data register
                        // refs so reads/writes drive
                        // index←offset, data↔value via
                        // oregion::read_field/write_field.
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let _ = oregion::parse_index_field_body(p, parent, pkg_end);
                        p.pos = pkg_end;
                        push_node(AmlNode {
                            path: full_path(String::new(), parent),
                            kind: NodeKind::Field,
                            value: None,
                            method_body: (0, 0),
                            method_flags: 0,
                            buffer_field: None,
                        });
                        *count += 1;
                    }
                    EXT_BANK_FIELD_OP => {
                        let pkg_start = p.pos;
                        let pkg_len = read_pkg_length(p)?;
                        let pkg_end = pkg_start + pkg_len;
                        let _ = oregion::parse_bank_field_body(p, parent, pkg_end);
                        p.pos = pkg_end;
                        push_node(AmlNode {
                            path: full_path(String::new(), parent),
                            kind: NodeKind::Field,
                            value: None,
                            method_body: (0, 0),
                            method_flags: 0,
                            buffer_field: None,
                        });
                        *count += 1;
                    }
                    // CreateField (variable-width): 0x5B 0x13
                    // SourceBuf BitIndex NumBits NameString.
                    // Register at parse time so namespace lookups find
                    // the BufferField before eval starts.
                    0x13 => {
                        let src_path = match p.peek() {
                            Some(b) if is_parse_name_lead(b) => {
                                let s = read_name_string(p, parent)?;
                                Some(full_path(s, parent))
                            }
                            _ => {
                                let after = (p.pos + 1).min(p.buf.len());
                                let _ = try_read_simple_value(p, after)?;
                                None
                            }
                        };
                        let bit_idx = read_simple_uint(p)?;
                        let bit_len = read_simple_uint(p)?;
                        let fname = read_name_string(p, parent)?;
                        let fpath = full_path(fname, parent);
                        if let Some(src) = src_path {
                            register_buffer_field(&fpath, &src, bit_idx, bit_len);
                            *count += 1;
                        }
                    }
                    _ => {
                        // Unknown extended opcode. Best-effort:
                        // bail out of this term list — anything we
                        // miss the caller's outer pkg-clamp catches.
                        return Ok(());
                    }
                }
            }
            BUFFER_OP | PACKAGE_OP | VAR_PACKAGE_OP => {
                // These are TermArg-class objects that can appear at
                // the top level only as part of a `Name(...)` body
                // (which we already consumed above) or as method
                // call args. At namespace-build time we treat them
                // as opaque — bail out so the outer caller can
                // re-anchor.
                return Ok(());
            }
            IF_OP | ELSE_OP => {
                // Conditional block. Spec (ACPI 6.5 §20.2.5.3):
                //   IfOp PkgLength Predicate TermList
                //   ElseOp PkgLength TermList
                //
                // Recurse into the body's TermList so any
                // Device / Method / Name etc. declared inside
                // a top-level conditional registers in the
                // namespace. Both branches of an If/Else
                // declare the same names statically (the body
                // is part of the namespace regardless of
                // run-time predicate value), so walking
                // unconditionally is correct for namespace
                // building.
                let is_if = op == IF_OP;
                p.skip(1)?;
                let pkg_start = p.pos;
                let pkg_len = read_pkg_length(p)?;
                let pkg_end = pkg_start.saturating_add(pkg_len).min(p.buf.len());

                if is_if {
                    // Skip the predicate TermArg. If the
                    // skipper can't decode it, fall back to
                    // jumping past the whole package — same
                    // behaviour as before this change, just
                    // localised.
                    if skip_predicate_term_arg(p.buf, &mut p.pos, pkg_end).is_err() {
                        p.pos = pkg_end;
                        continue;
                    }
                }

                // Recurse into the body. Use the soft-fail
                // wrapper so a malformed inner body doesn't
                // abort the outer walk.
                if p.pos < pkg_end {
                    parse_term_list(p, parent, count, pkg_end, base)?;
                }
                // Re-anchor at pkg_end regardless of how far
                // the inner walk progressed — guards against
                // partial sub-walks leaving the cursor inside
                // an undecoded tail.
                p.pos = pkg_end;
            }
            // CreateBitField / CreateByteField / CreateWordField /
            // CreateDWordField / CreateQWordField at namespace-build
            // time. The eval-time handler in eval.rs covers in-method
            // declarations; this branch covers top-level / Scope-body
            // declarations so subsequent TermObjs (like sibling
            // Methods that reference the field) still parse and the
            // BufferField is reachable for read/write.
            0x8D | 0x8C | 0x8B | 0x8A | 0x8F => {
                let opc = op;
                p.skip(1)?;
                let src_path = match p.peek() {
                    Some(b) if is_parse_name_lead(b) => {
                        let s = read_name_string(p, parent)?;
                        Some(full_path(s, parent))
                    }
                    _ => {
                        let after = (p.pos + 1).min(p.buf.len());
                        let _ = try_read_simple_value(p, after)?;
                        None
                    }
                };
                let idx = read_simple_uint(p)?;
                let fname = read_name_string(p, parent)?;
                let fpath = full_path(fname, parent);
                if let Some(src) = src_path {
                    let (bit_offset, bit_length) = match opc {
                        0x8D => (idx, 1),       // CreateBitField
                        0x8C => (idx * 8, 8),   // CreateByteField
                        0x8B => (idx * 8, 16),  // CreateWordField
                        0x8A => (idx * 8, 32),  // CreateDWordField
                        0x8F => (idx * 8, 64),  // CreateQWordField
                        _ => unreachable!(),
                    };
                    register_buffer_field(&fpath, &src, bit_offset, bit_length);
                    *count += 1;
                }
            }
            _ => {
                // Anything else: best-effort skip of one byte.
                // Unknown opcodes may carry PkgLength; without
                // decoding them we'd misalign. Bail to the outer
                // pkg-clamp.
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Local helper: detect a NameString lead byte at parse time.
#[inline]
fn is_parse_name_lead(b: u8) -> bool {
    // RootChar '\', ParentPrefix '^', DualName '\x2E', MultiName '\x2F',
    // or NameSeg first char (uppercase / underscore).
    matches!(b, b'\\' | b'^' | 0x2E | 0x2F) || b.is_ascii_uppercase() || b == b'_'
}

/// Local helper: read a flat-integer TermArg (Zero/One/Byte/Word/
/// DWord/Qword prefix). Used by parse-time CreateXxxField handlers
/// for the BitIndex / NumBits arguments — these are almost always
/// literal integers in real AML; complex TermArgs at parse time
/// would require running the evaluator, which the namespace builder
/// doesn't do.
fn read_simple_uint(p: &mut Parser<'_>) -> Result<u64, AmlError> {
    let op = p.read_u8()?;
    Ok(match op {
        ZERO_OP => 0,
        ONE_OP => 1,
        ONES_OP => u64::MAX,
        BYTE_PREFIX => p.read_u8()? as u64,
        WORD_PREFIX => {
            let bytes = p.slice_n(2)?;
            u16::from_le_bytes([bytes[0], bytes[1]]) as u64
        }
        DWORD_PREFIX => {
            let bytes = p.slice_n(4)?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
        }
        QWORD_PREFIX => {
            let bytes = p.slice_n(8)?;
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        }
        _ => 0,
    })
}

/// Step `cur` past one TermArg in `buf`, bounded by `end`. Built
/// for namespace-build-time predicate skipping where the full
/// `eval::eval_term_arg` machinery isn't usable (it performs
/// namespace lookups under a lock the builder is already holding,
/// and method-arg-count lookups against an in-flight namespace
/// return wrong values).
///
/// Handles the closed set of TermArg shapes that DSDT predicates
/// actually use:
///   - constants (Zero/One/Ones), sized integer literals
///     (Byte/Word/Dword/Qword), null-terminated strings,
///   - PkgLength-bounded literals (Buffer / Package / VarPackage),
///   - Local0..7 / Arg0..6,
///   - logical operators (LAnd/LOr/LEqual/LGreater/LLess) — recursive,
///   - LNot (with the LNotEqual / LLessEqual / LGreaterEqual
///     two-byte forms),
///   - NameString as MethodInvocation, with arg-count for the
///     predefined names that show up in real predicates
///     (`_OSI` = 1, `_REV` = 0, `_OS_` = 0); unknowns default to
///     0 args (matches the predominant pattern of
///     `LEqual(_OSI(...), Ones)` and friends).
///
/// Returns `Err(AmlError::BadPkgLength)` for any shape this
/// skipper doesn't recognise — the caller treats that as "skip
/// the entire package and lose body extraction" (the previous
/// behaviour, still strictly an improvement over bailing the
/// outer term-list).
pub(crate) fn skip_predicate_term_arg(
    buf: &[u8],
    cur: &mut usize,
    end: usize,
) -> Result<(), AmlError> {
    if *cur >= end {
        return Err(AmlError::Truncated);
    }
    let op = buf[*cur];
    *cur += 1;
    match op {
        // Constants / Locals / Args.
        ZERO_OP | ONE_OP | ONES_OP => Ok(()),
        0x60..=0x67 | 0x68..=0x6E => Ok(()),

        // Sized integer literals.
        BYTE_PREFIX => {
            if *cur >= end {
                return Err(AmlError::Truncated);
            }
            *cur += 1;
            Ok(())
        }
        WORD_PREFIX => {
            if *cur + 2 > end {
                return Err(AmlError::Truncated);
            }
            *cur += 2;
            Ok(())
        }
        DWORD_PREFIX => {
            if *cur + 4 > end {
                return Err(AmlError::Truncated);
            }
            *cur += 4;
            Ok(())
        }
        QWORD_PREFIX => {
            if *cur + 8 > end {
                return Err(AmlError::Truncated);
            }
            *cur += 8;
            Ok(())
        }
        STRING_PREFIX => {
            // Null-terminated AsciiString.
            while *cur < end && buf[*cur] != 0 {
                *cur += 1;
            }
            if *cur >= end {
                return Err(AmlError::Truncated);
            }
            *cur += 1; // consume NUL
            Ok(())
        }

        // PkgLength-bounded literals.
        BUFFER_OP | PACKAGE_OP | VAR_PACKAGE_OP => {
            let pkg_start = *cur;
            let pkg_len = read_pkg_length_at(buf, cur)?;
            *cur = pkg_start.saturating_add(pkg_len).min(end);
            Ok(())
        }

        // Logical operators with two operands.
        0x90 /* LAnd */ | 0x91 /* LOr */ | 0x93 /* LEqual */
            | 0x94 /* LGreater */ | 0x95 /* LLess */ => {
            skip_predicate_term_arg(buf, cur, end)?;
            skip_predicate_term_arg(buf, cur, end)?;
            Ok(())
        }

        // LNot (one operand) — but ACPI encodes LNotEqual as
        // `LNot LEqual` (two-byte op), same for LLessEqual /
        // LGreaterEqual. Peek ahead to disambiguate.
        0x92 => {
            if *cur < end {
                let next = buf[*cur];
                if next == 0x93 || next == 0x94 || next == 0x95 {
                    *cur += 1;
                    skip_predicate_term_arg(buf, cur, end)?;
                    skip_predicate_term_arg(buf, cur, end)?;
                    return Ok(());
                }
            }
            skip_predicate_term_arg(buf, cur, end)
        }

        // NameString lead chars — RootChar, ParentPrefix,
        // DualName, MultiName. After consuming the name, the
        // TermArg shape requires knowing whether it's a
        // MethodInvocation (with N args) or a Name reference
        // (no args). Only MethodInvocation can validly have
        // args; we conservatively look up arg count for the
        // small set of predefined names that show up in real
        // predicates.
        ROOT_CHAR | PARENT_PREFIX | DUAL_NAME_PREFIX | MULTI_NAME_PREFIX => {
            *cur -= 1; // back up so the name reader sees the lead
            let name = read_name_string_inline(buf, cur, end)?;
            let argc = predefined_method_argcount(&name);
            for _ in 0..argc {
                skip_predicate_term_arg(buf, cur, end)?;
            }
            Ok(())
        }

        // NameSeg lead char — first byte of an inline NameSeg.
        // Must be `_` or A-Z (uppercase ASCII). Same handling
        // as the lead-char arm above.
        b if b == b'_' || (b >= b'A' && b <= b'Z') => {
            *cur -= 1; // back up to read the full NameSeg
            let name = read_name_string_inline(buf, cur, end)?;
            let argc = predefined_method_argcount(&name);
            for _ in 0..argc {
                skip_predicate_term_arg(buf, cur, end)?;
            }
            Ok(())
        }

        // Anything else: punt. Caller falls back to package skip.
        _ => Err(AmlError::BadPkgLength),
    }
}

/// PkgLength reader against a borrowed buffer + cursor (the
/// existing `read_pkg_length(p: &mut Parser)` works against the
/// crate's Parser type; this is the same algorithm against a
/// raw slice).
fn read_pkg_length_at(buf: &[u8], cur: &mut usize) -> Result<usize, AmlError> {
    if *cur >= buf.len() {
        return Err(AmlError::Truncated);
    }
    let first = buf[*cur];
    *cur += 1;
    let extra = ((first >> 6) & 0x3) as usize;
    let mut len: usize = if extra == 0 {
        (first & 0x3F) as usize
    } else {
        (first & 0x0F) as usize
    };
    for i in 0..extra {
        if *cur >= buf.len() {
            return Err(AmlError::Truncated);
        }
        let next = buf[*cur];
        *cur += 1;
        len |= (next as usize) << (4 + i * 8);
    }
    Ok(len)
}

/// Read a NameString from `buf` starting at `*cur`, advancing
/// the cursor past it. Returns the canonical 4-char NameSeg form
/// (or concatenated for DualName / MultiName). RootChar prefix
/// (`\`) and ParentPrefix (`^`) are stripped; predicates use
/// short relative names overwhelmingly.
fn read_name_string_inline(
    buf: &[u8],
    cur: &mut usize,
    end: usize,
) -> Result<String, AmlError> {
    let mut name = String::new();
    if *cur >= end {
        return Err(AmlError::Truncated);
    }
    // Strip optional RootChar / ParentPrefix prefixes — we don't
    // need them for the arg-count lookup.
    while *cur < end && (buf[*cur] == ROOT_CHAR || buf[*cur] == PARENT_PREFIX) {
        *cur += 1;
    }
    if *cur >= end {
        return Err(AmlError::Truncated);
    }
    let lead = buf[*cur];
    let segs = match lead {
        DUAL_NAME_PREFIX => {
            *cur += 1;
            2
        }
        MULTI_NAME_PREFIX => {
            *cur += 1;
            if *cur >= end {
                return Err(AmlError::Truncated);
            }
            let n = buf[*cur] as usize;
            *cur += 1;
            n
        }
        _ => 1,
    };
    for _ in 0..segs {
        if *cur + 4 > end {
            return Err(AmlError::Truncated);
        }
        for k in 0..4 {
            name.push(buf[*cur + k] as char);
        }
        *cur += 4;
    }
    Ok(name)
}

/// Arg-count for the small set of ACPI predefined methods that
/// show up in DSDT conditional predicates. Anything else returns
/// 0 — matches the predominant pattern of name references rather
/// than method invocations in predicates.
///
/// Reference: ACPI 6.5 §5.7 "Predefined Objects".
fn predefined_method_argcount(name: &str) -> usize {
    // Trim trailing underscores (NameSeg padding) before matching.
    let trimmed = name.trim_end_matches('_');
    match trimmed {
        "_OSI" => 1, // OS Interface compatibility check, takes a string
        "_REV" => 0,
        "_OS" => 0,
        "_DSM" => 4, // Device-Specific Method
        "_PIC" => 1, // ACPI 6.5 §5.8.1
        _ => 0,
    }
}

fn push_node(n: AmlNode) {
    let mut g = NAMESPACE.lock();
    g.nodes.push(n);
}

/// Register a `Field` namespace node so per-field NameSegs declared
/// inside `Field(...) {...}` (and IndexField / BankField) bodies are
/// reachable from `find_node`. Without this the evaluator falls
/// through to `Value::Integer(0)` instead of routing through
/// `oregion::read_field` for the backing region.
pub(crate) fn push_field_node(path: String) {
    push_node(AmlNode {
        path,
        kind: NodeKind::Field,
        value: None,
        method_body: (0, 0),
        method_flags: 0,
        buffer_field: None,
    });
}

/// Update the `value` field of the first `Name` node matching `path`.
/// Used by the method evaluator when `Store(v, named)` is executed.
pub(crate) fn update_name_value(path: &str, value: NameValue) {
    let mut g = NAMESPACE.lock();
    if let Some(node) = g.nodes.iter_mut().find(|n| n.path == path) {
        node.value = Some(value);
    }
}

/// Register a `BufferField` node (CreateXxxField). Audit #9: real
/// _CRS bodies use these to compose the returned Buffer by writing
/// into named bit/byte/word/dword/qword slots. Reads return the
/// bit-slice as Integer; writes splice into the source buffer.
pub fn register_buffer_field(path: &str, source_path: &str, bit_offset: u64, bit_length: u64) {
    push_node(AmlNode {
        path: alloc::string::String::from(path),
        kind: NodeKind::BufferField,
        value: None,
        method_body: (0, 0),
        method_flags: 0,
        buffer_field: Some(BufferFieldRef {
            source_path: alloc::string::String::from(source_path),
            bit_offset,
            bit_length,
        }),
    });
}

/// Read the current Buffer bytes of a Name node. Materialises
/// from the AML store on first call if the body is `Unparsed`,
/// then caches as `NameValue::Buffer` for subsequent O(1) reads
/// and in-place writes (audit #9 — splice instead of append-and-
/// repoint, so live updates don't bloat the AML store).
pub fn read_name_as_buffer(path: &str) -> Option<alloc::vec::Vec<u8>> {
    {
        let g = NAMESPACE.lock();
        if let Some(node) = g.nodes.iter().find(|n| n.path == path) {
            if let Some(NameValue::Buffer(ref b)) = node.value {
                return Some(b.clone());
            }
        }
    }
    // Not yet materialised — decode from the AML store.
    let node = find_node(path)?;
    let buf = match node.value? {
        NameValue::Buffer(b) => b,
        NameValue::Unparsed { offset, length } if length > 0 => {
            let mut body = alloc::vec![0u8; length];
            let n = copy_aml_bytes(offset, &mut body);
            if n < length {
                return None;
            }
            let v = crate::eval::decode_value(&body).ok()?;
            match v {
                crate::Value::Buffer(b) => b,
                _ => return None,
            }
        }
        _ => return None,
    };
    // Cache the decoded form on the node so future reads/writes
    // skip the AML decode + work in place.
    let mut g = NAMESPACE.lock();
    if let Some(node) = g.nodes.iter_mut().find(|n| n.path == path) {
        node.value = Some(NameValue::Buffer(buf.clone()));
    }
    Some(buf)
}

/// Splice `value` into the Name node's underlying Buffer at the
/// given bit slice. Updates the buffer in place via
/// `NameValue::Buffer` so the AML store doesn't grow on every
/// CreateXxxField write.
pub fn write_buffer_field(source_path: &str, bit_offset: u64, bit_length: u64, value: u64) {
    // Make sure the source is materialised as NameValue::Buffer.
    let _ = read_name_as_buffer(source_path);
    let mut g = NAMESPACE.lock();
    let node = match g.nodes.iter_mut().find(|n| n.path == source_path) {
        Some(n) => n,
        None => return,
    };
    let buf = match node.value {
        Some(NameValue::Buffer(ref mut b)) => b,
        _ => return,
    };
    let total_bits = (bit_offset + bit_length) as usize;
    let need_bytes = (total_bits + 7) / 8;
    if buf.len() < need_bytes {
        buf.resize(need_bytes, 0);
    }
    let mut bit = bit_offset as usize;
    let end = (bit_offset + bit_length) as usize;
    let mut v = value;
    while bit < end {
        let byte_idx = bit / 8;
        let in_byte = bit % 8;
        let take = (8 - in_byte).min(end - bit);
        let mask = ((1u64 << take) - 1) as u8;
        let val_bits = (v & mask as u64) as u8;
        buf[byte_idx] = (buf[byte_idx] & !(mask << in_byte)) | (val_bits << in_byte);
        v >>= take;
        bit += take;
    }
}

/// Read a BufferField bit-slice as a u64. Returns 0 on missing
/// node, missing source buffer, or out-of-range slice.
pub fn read_buffer_field(field_path: &str) -> u64 {
    let node = match find_node(field_path) {
        Some(n) => n,
        None => return 0,
    };
    let bf = match node.buffer_field {
        Some(b) => b,
        None => return 0,
    };
    let buf = match read_name_as_buffer(&bf.source_path) {
        Some(b) => b,
        None => return 0,
    };
    let mut acc = 0u64;
    let mut bit = bf.bit_offset as usize;
    let end = (bf.bit_offset + bf.bit_length) as usize;
    let mut out_shift = 0u32;
    while bit < end && (out_shift as usize) < 64 {
        let byte_idx = bit / 8;
        if byte_idx >= buf.len() {
            break;
        }
        let in_byte = bit % 8;
        let take = (8 - in_byte).min(end - bit);
        let mask = ((1u64 << take) - 1) as u8;
        let bits = (buf[byte_idx] >> in_byte) & mask;
        acc |= (bits as u64) << out_shift;
        out_shift += take as u32;
        bit += take;
    }
    acc
}

/// Reset the namespace. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = NAMESPACE.lock();
    g.nodes.clear();
    g.aml.clear();
}

/// Test entry: parse a synthetic AML body (no SDT header) under the
/// given root path. Public so unit tests can validate decoder
/// pieces without cooking a full ACPI table chain.
#[doc(hidden)]
pub fn __parse_body_for_test(body: &[u8], root: &str) -> Result<u32, AmlError> {
    // Push body into AML store so method offsets resolve.
    let base = {
        let mut g = NAMESPACE.lock();
        let b = g.aml.len();
        g.aml.extend_from_slice(body);
        b
    };
    let mut p = Parser::new(body);
    let mut count = 0u32;
    parse_term_list(&mut p, root, &mut count, body.len(), base)?;
    Ok(count)
}
