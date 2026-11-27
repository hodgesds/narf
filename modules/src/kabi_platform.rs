//! Platform-driver KABI family (tracker #2448).
//!
//! The kernel-side implementation behind the `narf_register_acpi_driver`,
//! `narf_aml_evaluate_method`, `narf_acpi_find_devices_by_hid`,
//! `narf_acpi_register_notify_handler`, `narf_led_register`,
//! `narf_led_register_trigger`, and `narf_led_audio_mic_muted` exports
//! (see `kabi.rs` — the exports themselves are thin validation +
//! delegation; the registries and the module-text shims live here).
//!
//! ## Shape
//!
//! The family follows the PCI/USB/DT precedent: a per-owner registry in
//! this crate, a trampoline/shim that carries module callbacks through
//! the module call gate, and an explicit `unregister_module_*` backstop
//! the loader runs on unload (see `syscalls.rs`). The one deliberate
//! deviation from the KABI design record is the argument shape: the
//! design's §4.9 `repr(C)` structs are NOT used. The in-tree rule is the
//! USB export's comment in `kabi.rs` — "Flat C arguments, one per
//! `usb_device_id` field, so no `repr(C)` struct has to be shared with
//! separately compiled modules" — and flat arguments are strictly
//! stronger here: the signature CRC covers every field of a flat
//! argument list, while a struct-pointer argument's CRC covers only
//! the struct's *name*, not its layout. A module redeclares the
//! signatures by hand (the mt76 `module_probe.rs` pattern), so a
//! kernel-side struct definition would not prevent layout drift
//! anyway. The AML value encoding is a flat pre-order quad stream
//! (see `aml_quad` below), which expresses the generic `Value` tree
//! — including the `_PSS` Package fetch — without sharing a struct.
//!
//! ## Owner attribution
//!
//! Registrations can arrive from `narf_module_init` (init context) or
//! from a probe / callback (call-gate context). [`calling_owner`]
//! resolves both: the gate's per-CPU execution id when one is in
//! flight, else the init id. The two are never different modules on
//! the same CPU — init does not enter the gate, and the gate restores
//! the previous owner on return.
//!
//! ## Re-entrancy guard
//!
//! The LED tick holds the trigger-engine lock while it drives
//! `set_brightness` / trigger `compute` through the shims below, so a
//! module callback must not re-enter the LED core. The shims bump
//! [`LED_CALLBACK_DEPTH`] around the gate call; the LED/trigger
//! registration exports refuse with `-EBUSY` while it is non-zero.
//! (The notify dispatch path holds no lock while calling handlers, so
//! notify handlers may register — the guard does not cover them.)

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_drivers_leds::LedDevice;
use narf_lib::sync::IrqSafeSpinLock;

// ── Owner attribution ────────────────────────────────────────────────

/// The module on whose behalf the current export call runs: the
/// call-gate execution id when inside a gate callback (probe,
/// notify handler, LED op, trigger compute, exit), else the init id
/// when inside `narf_module_init`, else `KERNEL_MODULE_ID` (0).
pub fn calling_owner() -> u64 {
    let exec = crate::symbols::current_execution_id().0;
    if exec != crate::symbols::KERNEL_MODULE_ID.0 {
        return exec;
    }
    crate::symbols::current_init_id().0
}

// ── Re-entrancy guard (§5.4) ─────────────────────────────────────────

/// Depth of in-flight LED/trigger module callbacks (shim → gate).
/// Non-zero while any `set_brightness` / `get_brightness` /
/// trigger `compute` shim is inside module text. A plain counter,
/// not per-CPU: a callback on another CPU blocks registration here
/// too, which is safe (registration is rare) and keeps the guard a
/// single atomic instead of a per-CPU table.
static LED_CALLBACK_DEPTH: AtomicU32 = AtomicU32::new(0);

/// True while any LED/trigger module callback is in flight.
pub fn in_led_callback() -> bool {
    LED_CALLBACK_DEPTH.load(Ordering::Acquire) != 0
}

/// RAII bump of [`LED_CALLBACK_DEPTH`]. The shims hold one across
/// the gate call; dropping it (normal return) restores the depth.
/// The kernel is `panic=abort`, so there is no unwind path that
/// could skip the decrement.
struct LedCallbackGuard;

impl LedCallbackGuard {
    fn enter() -> Self {
        LED_CALLBACK_DEPTH.fetch_add(1, Ordering::AcqRel);
        LedCallbackGuard
    }
}

impl Drop for LedCallbackGuard {
    fn drop(&mut self) {
        LED_CALLBACK_DEPTH.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Enter module text through the call gate from a LED/trigger shim.
/// Thin wrapper so the shims read identically.
fn call_module(owner: u64, call: impl FnOnce() -> i32) -> i32 {
    crate::call_in_module_context(owner, call)
}

// ── AML value quad codec ─────────────────────────────────────────────
//
// One 32-byte quad per `narf_aml::Value` node, pre-order (a Package's
// children follow it immediately, each subtree contiguous):
//
//   bytes 0..4   tag: u32 LE (0 Integer, 1 String, 2 Buffer, 3 Package)
//   bytes 4..8   reserved, must be zero (rejected otherwise)
//   bytes 8..16  int_val: u64 LE (Integer value; 0 otherwise)
//   bytes 16..24 payload: u64 LE — String/Buffer: byte offset of the
//                payload bytes into the payload region (see below);
//                Package: child count; Integer: 0
//   bytes 24..32 len: u64 LE — String/Buffer: byte length; else 0
//
// Arguments arrive as (quads, payload) where the payload region is a
// separate caller buffer and offsets are relative to its base.
// Results are written into a single caller buffer: quads first, then
// payload bytes, so an offset is relative to `out + 32 * node_count`.
// Bounds (design §4.3, plus a payload cap so a module cannot make the
// kernel copy unbounded bytes): at most 64 nodes, nesting depth at
// most 4, payload at most 4096 bytes.

/// Quad tag for `Value::Integer`.
pub const AML_TAG_INTEGER: u32 = 0;
/// Quad tag for `Value::String`.
pub const AML_TAG_STRING: u32 = 1;
/// Quad tag for `Value::Buffer`.
pub const AML_TAG_BUFFER: u32 = 2;
/// Quad tag for `Value::Package`.
pub const AML_TAG_PACKAGE: u32 = 3;

/// Bytes per quad node.
pub const AML_QUAD_LEN: usize = 32;
/// Maximum nodes in one args/result tree (design §4.3).
pub const AML_MAX_NODES: usize = 64;
/// Maximum nesting depth of a Package tree (design §4.3).
pub const AML_MAX_DEPTH: usize = 4;
/// Maximum String/Buffer payload bytes in one call.
pub const AML_MAX_PAYLOAD_BYTES: usize = 4096;

/// Decode a caller-supplied quad stream + payload region into owned
/// `Value`s. Returns `-EINVAL` on any malformed input (bad length,
/// unknown tag, non-zero reserved field, over-deep/over-wide tree,
/// payload offset out of range); `-ENOMEM` on allocation failure.
/// An empty quad stream decodes to an empty argument list (a method
/// with no arguments encodes as zero quads).
pub fn decode_aml_args(quads: &[u8], payload: &[u8]) -> Result<Vec<narf_aml::Value>, i32> {
    if quads.len() % AML_QUAD_LEN != 0 {
        return Err(-22); // -EINVAL
    }
    let nodes = quads.len() / AML_QUAD_LEN;
    if nodes > AML_MAX_NODES {
        return Err(-22);
    }
    if nodes == 0 {
        // An empty quad stream is a valid empty argument list — a
        // method with no arguments (a future `_PSS` fetch takes
        // none) encodes as zero quads, not as a malformed call.
        return Ok(Vec::new());
    }
    if payload.len() > AML_MAX_PAYLOAD_BYTES {
        return Err(-22);
    }
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < nodes {
        let (value, consumed) = decode_aml_node(quads, payload, pos, 0)?;
        out.push(value);
        pos += consumed;
    }
    Ok(out)
}

/// Decode one node (and, for a Package, its whole subtree) at `pos`.
/// Returns the value and the number of quads consumed.
fn decode_aml_node(
    quads: &[u8],
    payload: &[u8],
    pos: usize,
    depth: usize,
) -> Result<(narf_aml::Value, usize), i32> {
    if depth > AML_MAX_DEPTH {
        return Err(-22);
    }
    let q = &quads[pos * AML_QUAD_LEN..(pos + 1) * AML_QUAD_LEN];
    let tag = u32::from_le_bytes([q[0], q[1], q[2], q[3]]);
    let reserved = u32::from_le_bytes([q[4], q[5], q[6], q[7]]);
    if reserved != 0 {
        return Err(-22);
    }
    let int_val = u64::from_le_bytes([q[8], q[9], q[10], q[11], q[12], q[13], q[14], q[15]]);
    let payload_off = u64::from_le_bytes([q[16], q[17], q[18], q[19], q[20], q[21], q[22], q[23]]);
    let len = u64::from_le_bytes([q[24], q[25], q[26], q[27], q[28], q[29], q[30], q[31]]);
    match tag {
        AML_TAG_INTEGER => Ok((narf_aml::Value::Integer(int_val), 1)),
        AML_TAG_STRING | AML_TAG_BUFFER => {
            let off = usize::try_from(payload_off).map_err(|_| -22)?;
            let len = usize::try_from(len).map_err(|_| -22)?;
            let end = off.checked_add(len).ok_or(-22)?;
            if end > payload.len() {
                return Err(-22);
            }
            let bytes = &payload[off..end];
            if tag == AML_TAG_STRING {
                let s = core::str::from_utf8(bytes).map_err(|_| -22)?;
                Ok((narf_aml::Value::String(String::from(s)), 1))
            } else {
                Ok((narf_aml::Value::Buffer(bytes.to_vec()), 1))
            }
        }
        AML_TAG_PACKAGE => {
            let count = usize::try_from(payload_off).map_err(|_| -22)?;
            if len != 0 || count > AML_MAX_NODES {
                return Err(-22);
            }
            let mut children = Vec::new();
            let mut consumed = 1usize;
            for _ in 0..count {
                if pos + consumed >= quads.len() / AML_QUAD_LEN {
                    return Err(-22);
                }
                let (child, used) = decode_aml_node(quads, payload, pos + consumed, depth + 1)?;
                children.push(child);
                consumed += used;
            }
            Ok((narf_aml::Value::Package(children), consumed))
        }
        _ => Err(-22),
    }
}

/// Bytes the encoded form of `value` needs: quads first, then
/// payload bytes (see the layout above).
pub fn encoded_aml_len(value: &narf_aml::Value) -> usize {
    fn nodes(v: &narf_aml::Value) -> (usize, usize) {
        match v {
            narf_aml::Value::Integer(_) => (1, 0),
            narf_aml::Value::String(s) => (1, s.len()),
            narf_aml::Value::Buffer(b) => (1, b.len()),
            narf_aml::Value::Package(children) => children.iter().fold((1, 0), |(n, p), c| {
                let (cn, cp) = nodes(c);
                (n + cn, p + cp)
            }),
        }
    }
    let (n, p) = nodes(value);
    n * AML_QUAD_LEN + p
}

/// Encode `value` into `out` (quads first, payload bytes after).
/// Returns bytes written, or `-ENOSPC` when `out` is too small
/// (callers compute [`encoded_aml_len`] first).
pub fn encode_aml_result(value: &narf_aml::Value, out: &mut [u8]) -> Result<usize, i32> {
    let needed = encoded_aml_len(value);
    if out.len() < needed {
        return Err(-28); // -ENOSPC
    }
    // Payload region starts after all quads; count nodes first.
    fn count_nodes(v: &narf_aml::Value) -> usize {
        match v {
            narf_aml::Value::Package(children) => {
                1 + children.iter().map(count_nodes).sum::<usize>()
            }
            _ => 1,
        }
    }
    let payload_base = count_nodes(value) * AML_QUAD_LEN;
    let mut quad_pos = 0usize;
    let mut payload_pos = payload_base;
    encode_aml_node(value, out, &mut quad_pos, &mut payload_pos, payload_base);
    Ok(needed)
}

fn encode_aml_node(
    value: &narf_aml::Value,
    out: &mut [u8],
    quad_pos: &mut usize,
    payload_pos: &mut usize,
    payload_base: usize,
) {
    let q = *quad_pos * AML_QUAD_LEN;
    match value {
        narf_aml::Value::Integer(i) => {
            out[q..q + 4].copy_from_slice(&AML_TAG_INTEGER.to_le_bytes());
            out[q + 4..q + 8].copy_from_slice(&0u32.to_le_bytes());
            out[q + 8..q + 16].copy_from_slice(&i.to_le_bytes());
            out[q + 16..q + 24].copy_from_slice(&0u64.to_le_bytes());
            out[q + 24..q + 32].copy_from_slice(&0u64.to_le_bytes());
        }
        narf_aml::Value::String(s) => {
            // Stored offset is relative to the payload region base
            // (`payload_base`), not to the buffer start.
            let rel = (*payload_pos - payload_base) as u64;
            out[q..q + 4].copy_from_slice(&AML_TAG_STRING.to_le_bytes());
            out[q + 4..q + 8].copy_from_slice(&0u32.to_le_bytes());
            out[q + 8..q + 16].copy_from_slice(&0u64.to_le_bytes());
            out[q + 16..q + 24].copy_from_slice(&rel.to_le_bytes());
            out[q + 24..q + 32].copy_from_slice(&(s.len() as u64).to_le_bytes());
            out[*payload_pos..*payload_pos + s.len()].copy_from_slice(s.as_bytes());
            *payload_pos += s.len();
        }
        narf_aml::Value::Buffer(b) => {
            let rel = (*payload_pos - payload_base) as u64;
            out[q..q + 4].copy_from_slice(&AML_TAG_BUFFER.to_le_bytes());
            out[q + 4..q + 8].copy_from_slice(&0u32.to_le_bytes());
            out[q + 8..q + 16].copy_from_slice(&0u64.to_le_bytes());
            out[q + 16..q + 24].copy_from_slice(&rel.to_le_bytes());
            out[q + 24..q + 32].copy_from_slice(&(b.len() as u64).to_le_bytes());
            out[*payload_pos..*payload_pos + b.len()].copy_from_slice(b);
            *payload_pos += b.len();
        }
        narf_aml::Value::Package(children) => {
            out[q..q + 4].copy_from_slice(&AML_TAG_PACKAGE.to_le_bytes());
            out[q + 4..q + 8].copy_from_slice(&0u32.to_le_bytes());
            out[q + 8..q + 16].copy_from_slice(&0u64.to_le_bytes());
            out[q + 16..q + 24].copy_from_slice(&(children.len() as u64).to_le_bytes());
            out[q + 24..q + 32].copy_from_slice(&0u64.to_le_bytes());
        }
    }
    *quad_pos += 1;
    if let narf_aml::Value::Package(children) = value {
        for child in children {
            encode_aml_node(child, out, quad_pos, payload_pos, payload_base);
        }
    }
}

/// Decode a single encoded result buffer (quads first, payload
/// bytes after — the layout [`encode_aml_result`] produces) back
/// into its `Value`. The quad stream is self-delimiting for one
/// top-level value: a header traversal counts the nodes first
/// (Package child counts bound it), which fixes the payload base;
/// the payload bytes are never read as headers.
pub fn decode_aml_result(buf: &[u8]) -> Result<narf_aml::Value, i32> {
    let nodes = count_aml_nodes(buf)?;
    let payload_base = nodes * AML_QUAD_LEN;
    if buf.len() < payload_base {
        return Err(-22);
    }
    if buf.len() - payload_base > AML_MAX_PAYLOAD_BYTES {
        return Err(-22);
    }
    let quads = &buf[..payload_base];
    let payload = &buf[payload_base..];
    let (value, consumed) = decode_aml_node(quads, payload, 0, 0)?;
    if consumed != nodes {
        return Err(-22);
    }
    Ok(value)
}

/// Count the quads of one top-level value by header traversal only
/// (tags + Package child counts; payload bytes are never touched).
/// Validates the same structural bounds as the full decode.
fn count_aml_nodes(buf: &[u8]) -> Result<usize, i32> {
    fn count_at(buf: &[u8], pos: usize, depth: usize, budget: &mut usize) -> Result<usize, i32> {
        if depth > AML_MAX_DEPTH || *budget == 0 {
            return Err(-22);
        }
        let start = pos * AML_QUAD_LEN;
        if start + AML_QUAD_LEN > buf.len() {
            return Err(-22);
        }
        let q = &buf[start..start + AML_QUAD_LEN];
        let tag = u32::from_le_bytes([q[0], q[1], q[2], q[3]]);
        let reserved = u32::from_le_bytes([q[4], q[5], q[6], q[7]]);
        if reserved != 0 {
            return Err(-22);
        }
        *budget -= 1;
        match tag {
            AML_TAG_INTEGER | AML_TAG_STRING | AML_TAG_BUFFER => Ok(1),
            AML_TAG_PACKAGE => {
                let count =
                    u64::from_le_bytes([q[16], q[17], q[18], q[19], q[20], q[21], q[22], q[23]]);
                let count = usize::try_from(count).map_err(|_| -22)?;
                let mut consumed = 1usize;
                for _ in 0..count {
                    consumed += count_at(buf, pos + consumed, depth + 1, budget)?;
                }
                Ok(consumed)
            }
            _ => Err(-22),
        }
    }
    let mut budget = AML_MAX_NODES;
    let n = count_at(buf, 0, 0, &mut budget)?;
    if n == 0 || n > AML_MAX_NODES {
        return Err(-22);
    }
    Ok(n)
}
/// method is `-ENODEV` — the normal "this machine lacks the feature"
/// signal; every other evaluation failure is `-EIO`. Argument
/// validation failures are `-EINVAL` at the call site, not here.
pub fn aml_errno(e: narf_aml::AmlError) -> i32 {
    match e {
        narf_aml::AmlError::MethodNotFound => -19, // -ENODEV
        _ => -5,                                   // -EIO
    }
}

// ── ACPI driver registry ─────────────────────────────────────────────
//
// Mirrors `narf_bus::register_module_pci_driver` (`bus/src/driver_match.rs`):
// one driver per module, re-match against already-enumerated devices
// at registration, first `0` from a probe claims the device. The
// ACPI namespace is static after boot (no hotplug in v1), so
// registration-time re-match is the whole story — there is no bus
// probe path to hook.

/// A module's registered ACPI driver: its HID table, probe/remove
/// callbacks (raw module-text addresses), opaque cookie, and the
/// device paths its probe has claimed.
struct AcpiDriverEntry {
    owner: u64,
    name: String,
    hids: Vec<String>,
    probe: usize,
    remove: usize,
    cookie: u64,
    claimed: Vec<String>,
}

impl core::fmt::Debug for AcpiDriverEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcpiDriverEntry")
            .field("owner", &self.owner)
            .field("name", &self.name)
            .field("hids", &self.hids)
            .field("claimed", &self.claimed)
            .finish_non_exhaustive()
    }
}

static ACPI_DRIVERS: IrqSafeSpinLock<Vec<AcpiDriverEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Maximum HIDs in one driver's table (Linux `acpi_device_id` tables
/// are small; the ThinkPad driver passes three).
const ACPI_MAX_HIDS: usize = 16;

/// Parse a NUL-separated HID buffer into owned strings. Empty
/// segments are skipped; a non-UTF-8 segment or more than
/// [`ACPI_MAX_HIDS`] HIDs is `-EINVAL`.
pub fn parse_hid_buffer(buf: &[u8]) -> Result<Vec<String>, i32> {
    let mut hids = Vec::new();
    for seg in buf.split(|b| *b == 0) {
        if seg.is_empty() {
            continue;
        }
        let s = core::str::from_utf8(seg).map_err(|_| -22)?;
        hids.push(String::from(s));
        if hids.len() > ACPI_MAX_HIDS {
            return Err(-22);
        }
    }
    if hids.is_empty() {
        return Err(-22);
    }
    Ok(hids)
}

/// Register an ACPI driver for `owner`. One driver per module:
/// `-EBUSY` when this module already has one. On success the driver
/// is immediately re-matched against already-enumerated devices
/// (§5.5): each matching device's `probe` is called through the
/// module call gate, in task context, with the device path. A probe
/// returning `0` claims the device; a negative errno declines it and
/// the core moves on. The caller validates name/HIDs/probe first;
/// this function only enforces the per-owner rule and runs the
/// re-match.
pub fn register_acpi_driver(
    owner: u64,
    name: &str,
    hids: Vec<String>,
    probe: usize,
    remove: usize,
    cookie: u64,
) -> i32 {
    {
        let mut g = ACPI_DRIVERS.lock();
        if g.iter().any(|e| e.owner == owner) {
            return -16; // -EBUSY: one ACPI driver per module.
        }
        g.push(AcpiDriverEntry {
            owner,
            name: String::from(name),
            hids,
            probe,
            remove,
            cookie,
            claimed: Vec::new(),
        });
    }
    rematch_acpi_driver(owner);
    0
}

/// Re-match one owner's driver against already-enumerated devices.
/// Probes run through the gate with NO registry lock held (a probe
/// may itself register — e.g. LEDs — and the registry lock is a
/// spinlock, so holding it across module text would deadlock).
fn rematch_acpi_driver(owner: u64) {
    // Snapshot the entry so the lock is released before any probe.
    let (hids, probe, cookie) = {
        let g = ACPI_DRIVERS.lock();
        match g.iter().find(|e| e.owner == owner) {
            Some(e) => (e.hids.clone(), e.probe, e.cookie),
            None => return,
        }
    };
    // Collect matching paths across all HIDs, deduplicated: one
    // device matches one HID, but a table may list an HID twice.
    let mut paths: Vec<String> = Vec::new();
    for hid in &hids {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            if !paths.iter().any(|p| p == &node.path) {
                paths.push(node.path);
            }
        }
    }
    for path in paths {
        if is_path_claimed_by_other(owner, &path) {
            continue;
        }
        let probe_fn: extern "C" fn(u64, *const u8, usize) -> i32 =
            // SAFETY: the module promises `probe` is a valid probe
            // function for as long as the driver is registered; the
            // unload path removes it before unmapping the text.
            unsafe { core::mem::transmute(probe) };
        let path_bytes = path.as_bytes();
        let rc = call_module(owner, || {
            probe_fn(cookie, path_bytes.as_ptr(), path_bytes.len())
        });
        if rc == 0 {
            let mut g = ACPI_DRIVERS.lock();
            if let Some(e) = g.iter_mut().find(|e| e.owner == owner) {
                if !e.claimed.iter().any(|p| p == &path) {
                    e.claimed.push(path);
                }
            }
            // If the entry is gone (concurrent unregister), the claim
            // is dropped with it — the module is going away anyway.
        }
    }
}

fn is_path_claimed_by_other(owner: u64, path: &str) -> bool {
    ACPI_DRIVERS
        .lock()
        .iter()
        .any(|e| e.owner != owner && e.claimed.iter().any(|p| p == path))
}

/// Unregister `owner`'s ACPI driver. For each device the probe
/// claimed, the `remove` callback (when non-zero) is invoked through
/// the gate first — this runs from the module's exit path while it is
/// still Live, so the gate admits the call. Returns `0`, or
/// `-ENODEV` when this module has no ACPI driver registered.
/// Remove failures are ignored: remove is a notification, and the
/// core cannot act on a failure during unload.
pub fn unregister_acpi_driver(owner: u64) -> i32 {
    let entry = {
        let mut g = ACPI_DRIVERS.lock();
        match g.iter().position(|e| e.owner == owner) {
            Some(pos) => g.remove(pos),
            None => return -19, // -ENODEV
        }
    };
    if entry.remove != 0 {
        let remove_fn: extern "C" fn(u64, *const u8, usize) =
            // SAFETY: same promise as the probe; the module is still
            // Live while its exit path runs, so the text is mapped.
            unsafe { core::mem::transmute(entry.remove) };
        for path in &entry.claimed {
            let path_bytes = path.as_bytes();
            let _ = call_module(owner, || {
                remove_fn(entry.cookie, path_bytes.as_ptr(), path_bytes.len());
                0
            });
        }
    }
    0
}

/// Loader backstop: drop every ACPI driver owned by `owner` without
/// calling `remove` — the module is Going by now, so the gate would
/// refuse, and the exit path already had its chance to unbind.
/// Called from `syscalls.rs` (both the delete path and the
/// init-failure unwind) before the module's text is unmapped.
pub fn unregister_module_acpi_drivers(owner: u64) {
    ACPI_DRIVERS.lock().retain(|e| e.owner != owner);
}

// ── Notify shims ─────────────────────────────────────────────────────
//
// `aml::sync::NotifyHandler` is a plain `fn(target: &str, value: u64)`
// with no cookie, so one static shim fans out to the module handlers:
// the core calls the shim, the shim looks up every (path → handler,
// cookie, owner) entry and invokes each through the gate. The shim
// itself is registered with the core only while at least one module
// entry exists for the path.

/// One module notify subscription.
struct NotifyShimEntry {
    owner: u64,
    path: String,
    handler: usize,
    cookie: u64,
}

impl core::fmt::Debug for NotifyShimEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifyShimEntry")
            .field("owner", &self.owner)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

static NOTIFY_SHIMS: IrqSafeSpinLock<Vec<NotifyShimEntry>> = IrqSafeSpinLock::new(Vec::new());

/// The single core-side handler for every module notify path. Looks
/// up the path's module entries and delivers the notify to each
/// through the gate. Dispatch holds no core lock while calling
/// handlers (`aml/src/sync.rs:325`), so the gate's state lock is the
/// only lock in play — and `call_in_module_context` drops it before
/// entering module text.
fn kabi_notify_shim(target: &str, value: u64) {
    let entries: Vec<(u64, usize, u64)> = {
        let g = NOTIFY_SHIMS.lock();
        g.iter()
            .filter(|e| e.path == target)
            .map(|e| (e.owner, e.handler, e.cookie))
            .collect()
    };
    let target_bytes = target.as_bytes();
    for (owner, handler, cookie) in entries {
        let handler_fn: extern "C" fn(u64, *const u8, usize, u64) =
            // SAFETY: the module promises the handler stays mapped
            // while subscribed; the backstop removes the entry
            // before unmapping the text.
            unsafe { core::mem::transmute(handler) };
        let _ = call_module(owner, || {
            handler_fn(cookie, target_bytes.as_ptr(), target_bytes.len(), value);
            0
        });
    }
}

/// Register a notify subscription for `owner`. `-EEXIST` when the
/// exact (path, handler, cookie) triple is already subscribed.
pub fn register_notify_shim(owner: u64, path: &str, handler: usize, cookie: u64) -> i32 {
    let register_core_shim = {
        let mut g = NOTIFY_SHIMS.lock();
        if g.iter().any(|e| {
            e.owner == owner && e.path == path && e.handler == handler && e.cookie == cookie
        }) {
            return -17; // -EEXIST
        }
        let first_for_path = !g.iter().any(|e| e.path == path);
        g.push(NotifyShimEntry {
            owner,
            path: String::from(path),
            handler,
            cookie,
        });
        first_for_path
    };
    if register_core_shim {
        narf_aml::sync::register_notify_handler(path, kabi_notify_shim);
    }
    0
}

/// Unregister `owner`'s subscriptions for (`path`, `handler`)
/// (all cookies). When the last entry for the path goes away, the
/// core shim is unregistered too. Returns `0`, or `-ENODEV` when
/// nothing matched.
pub fn unregister_notify_shim(owner: u64, path: &str, handler: usize) -> i32 {
    let (removed, last_for_path) = {
        let mut g = NOTIFY_SHIMS.lock();
        let before = g.len();
        g.retain(|e| !(e.owner == owner && e.path == path && e.handler == handler));
        let removed = g.len() != before;
        let last_for_path = removed && !g.iter().any(|e| e.path == path);
        (removed, last_for_path)
    };
    if !removed {
        return -19; // -ENODEV
    }
    if last_for_path {
        narf_aml::sync::unregister_notify_handler(path, kabi_notify_shim);
    }
    0
}

/// Loader backstop: drop every notify subscription owned by `owner`,
/// unregistering the core shim for any path left empty. The module
/// is Going, so no handler is invoked.
pub fn unregister_module_notify_shims(owner: u64) {
    // Collect the paths this owner subscribed to BEFORE retaining:
    // after the retain the removed entries are gone and emptiness
    // cannot be decided from the survivors alone.
    let removed_paths: Vec<String> = {
        let mut g = NOTIFY_SHIMS.lock();
        let mut removed = Vec::new();
        g.retain(|e| {
            if e.owner == owner {
                if !removed.iter().any(|p: &String| p == &e.path) {
                    removed.push(e.path.clone());
                }
                false
            } else {
                true
            }
        });
        removed
    };
    for path in removed_paths {
        let still_used = NOTIFY_SHIMS.lock().iter().any(|e| e.path == path);
        if !still_used {
            narf_aml::sync::unregister_notify_handler(&path, kabi_notify_shim);
        }
    }
}

// ── Module LED shim ──────────────────────────────────────────────────
//
// `narf_led_register` cannot hand the core an `Arc<dyn LedDevice>`
// across the ABI, so the KABI builds a small shim that forwards the
// trait through the module call gate. The shim is created here (in
// the modules crate, where the gate lives) and registered with the
// LED class like any builtin device.

/// A module LED, as seen by the LED class. All hardware access goes
/// through the module's callbacks under the gate; the core never
/// touches module text directly.
pub struct ModuleLedShim {
    name: String,
    max_brightness: u32,
    owner: u64,
    set_brightness: usize,
    get_brightness: usize,
    set_trigger: usize,
    cookie: u64,
    trigger: IrqSafeSpinLock<narf_drivers_leds::Trigger>,
}

impl core::fmt::Debug for ModuleLedShim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleLedShim")
            .field("name", &self.name)
            .field("max_brightness", &self.max_brightness)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl narf_drivers_leds::LedDevice for ModuleLedShim {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max_brightness
    }

    /// Current brightness via the module's `get_brightness`. `0` on
    /// any failure (module gone, gate refused) — the trait's
    /// "returns 0 on any hardware-read failure" rule.
    fn brightness(&self) -> u32 {
        let get: extern "C" fn(u64) -> u32 =
            // SAFETY: validated non-null at registration; the module
            // promises it stays mapped while registered.
            unsafe { core::mem::transmute(self.get_brightness) };
        let cookie = self.cookie;
        let mut out = 0u32;
        let _guard = LedCallbackGuard::enter();
        let _ = call_module(self.owner, || {
            out = get(cookie);
            0
        });
        out
    }

    /// Drive the LED, clamped to `[0, max_brightness()]` per the
    /// trait contract. Infallible: a refused gate call simply does
    /// nothing (the LED keeps its last brightness).
    fn set_brightness(&self, level: u32) {
        let level = level.min(self.max_brightness);
        let set: extern "C" fn(u64, u32) =
            // SAFETY: validated non-null at registration; same
            // promise as `get_brightness`.
            unsafe { core::mem::transmute(self.set_brightness) };
        let cookie = self.cookie;
        let _guard = LedCallbackGuard::enter();
        let _ = call_module(self.owner, || {
            set(cookie, level);
            0
        });
    }

    fn current_trigger(&self) -> narf_drivers_leds::Trigger {
        self.trigger.lock().clone()
    }

    /// Install a trigger. The engine owns trigger behaviour; the
    /// module is only *informed* (when it supplied a `set_trigger`
    /// callback) of the trigger's sysfs name. A `0` callback means
    /// "engine-owned": the install is recorded and nothing is
    /// forwarded — the implementation must not invent a hardware
    /// trigger path to fill it (design §4.9).
    fn set_trigger(&self, trigger: narf_drivers_leds::Trigger) {
        *self.trigger.lock() = trigger.clone();
        if self.set_trigger == 0 {
            return;
        }
        let Some(name) = narf_drivers_leds::triggers::name_of_trigger(&trigger) else {
            return;
        };
        let forward: extern "C" fn(u64, *const u8, usize) =
            // SAFETY: validated non-null at registration; same
            // promise as the brightness callbacks.
            unsafe { core::mem::transmute(self.set_trigger) };
        let cookie = self.cookie;
        let name_bytes = name.as_bytes();
        let _guard = LedCallbackGuard::enter();
        let _ = call_module(self.owner, || {
            forward(cookie, name_bytes.as_ptr(), name_bytes.len());
            0
        });
    }
}

/// One (owner → LED name) record, holding the shim so the exit path
/// can drive the LED off through the gate while still Live.
struct LedOwnerEntry {
    owner: u64,
    name: String,
    shim: Arc<ModuleLedShim>,
}

static LED_OWNERS: IrqSafeSpinLock<Vec<LedOwnerEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a module LED: build the shim, publish it with the LED
/// class (same-name replacement follows the class rule), record
/// ownership, and apply the default trigger when one was given.
/// Another module's LED name is `-EBUSY` — a module may not steal
/// another module's LED (the class's same-name replacement would
/// otherwise let the backstop of the first module unregister the
/// second module's LED). A same-owner re-registration replaces the
/// shim. The caller validates name/max/callbacks first.
//
// Eight arguments is the flat KABI form of one registration — the
// export passes every field separately so no `repr(C)` struct is
// shared across the boundary (see the `kabi.rs` header). Grouping
// them would reintroduce exactly the drift the flat-args rule
// exists to prevent.
#[allow(clippy::too_many_arguments)]
pub fn register_module_led(
    owner: u64,
    name: &str,
    max_brightness: u32,
    set_brightness: usize,
    get_brightness: usize,
    set_trigger: usize,
    cookie: u64,
    default_trigger: Option<&str>,
) -> i32 {
    let shim = Arc::new(ModuleLedShim {
        name: String::from(name),
        max_brightness,
        owner,
        set_brightness,
        get_brightness,
        set_trigger,
        cookie,
        trigger: IrqSafeSpinLock::new(narf_drivers_leds::Trigger::None),
    });
    {
        let mut g = LED_OWNERS.lock();
        if g.iter().any(|e| e.name == name && e.owner != owner) {
            return -16; // -EBUSY: another module owns this LED name.
        }
        if let Some(pos) = g.iter().position(|e| e.owner == owner && e.name == name) {
            g[pos].shim = shim.clone();
        } else {
            g.push(LedOwnerEntry {
                owner,
                name: String::from(name),
                shim: shim.clone(),
            });
        }
    }
    narf_drivers_leds::register_led(shim);
    if let Some(trigger_name) = default_trigger {
        narf_drivers_leds::set_led_default_trigger(name, trigger_name);
    }
    0
}

/// Unregister `owner`'s LED `name`. When `drive_off` is set, the
/// LED is driven to brightness `0` through the gate first — this
/// runs from the module's exit path while it is still Live, so the
/// gate admits the call; if the gate refuses, the unregister
/// proceeds anyway (the LED keeps its last brightness). Returns `0`,
/// or `-ENODEV` when this module owns no LED of that name.
pub fn unregister_module_led(owner: u64, name: &str, drive_off: bool) -> i32 {
    let shim = {
        let mut g = LED_OWNERS.lock();
        match g.iter().position(|e| e.owner == owner && e.name == name) {
            Some(pos) => g.remove(pos).shim,
            None => return -19, // -ENODEV
        }
    };
    if drive_off {
        shim.set_brightness(0);
    }
    narf_drivers_leds::unregister_led(name);
    0
}

/// Loader backstop: unregister every LED owned by `owner`, without
/// driving them off — the module is Going, so the gate would refuse,
/// and the exit path already had its chance. The LEDs keep their
/// last brightness; what the backstop guarantees is that no
/// registration outlives the module's text.
pub fn unregister_module_leds(owner: u64) {
    let names: Vec<String> = {
        let mut g = LED_OWNERS.lock();
        let mut names = Vec::new();
        g.retain(|e| {
            if e.owner == owner {
                names.push(e.name.clone());
                false
            } else {
                true
            }
        });
        names
    };
    for name in names {
        narf_drivers_leds::unregister_led(&name);
    }
}

// ── Module trigger glue ──────────────────────────────────────────────
//
// The trigger's `compute` closure is built here (where the gate
// lives) and handed to the LED core as an opaque `Arc<dyn Fn>` — the
// core never sees a module address, and the closure re-enters module
// text only through the gate.

/// (owner → trigger name) records for the backstop. The LED core
/// owns the (name → closure) registry; this crate only tracks who
/// registered what.
static TRIGGER_OWNERS: IrqSafeSpinLock<Vec<(u64, String)>> = IrqSafeSpinLock::new(Vec::new());

/// Register a module trigger: wrap the module's `compute` callback
/// in a gate-crossing closure and hand it to the LED core. The
/// closure clamps nothing itself — the core clamps the result to
/// `[0, max_brightness]` (design §4.7). Returns the LED core's
/// errno (`-EINVAL` bad name/callback, `-EEXIST` builtin name).
pub fn register_module_trigger(owner: u64, name: &str, compute: usize, cookie: u64) -> i32 {
    let compute_fn: extern "C" fn(u64, u32, u32) -> u32 =
        // SAFETY: validated non-null by the caller; the module
        // promises it stays mapped while registered.
        unsafe { core::mem::transmute(compute) };
    let closure: Arc<dyn Fn(u32, u32) -> u32 + Send + Sync> = Arc::new(move |max, ticks| {
        let _guard = LedCallbackGuard::enter();
        let mut out = 0u32;
        let _ = call_module(owner, || {
            out = compute_fn(cookie, max, ticks);
            0
        });
        out
    });
    match narf_drivers_leds::triggers::register_module_trigger(name, closure) {
        Ok(_handle) => {
            let mut g = TRIGGER_OWNERS.lock();
            if !g.iter().any(|(o, n)| *o == owner && n == name) {
                g.push((owner, String::from(name)));
            }
            0
        }
        Err(errno) => errno,
    }
}

/// Unregister `owner`'s trigger `name`. Another module's trigger is
/// `-EBUSY`; unknown is `-ENODEV`; a trigger still driving LEDs is
/// `-EBUSY` (the caller must move those LEDs first — the loader
/// backstop force-reverts them instead).
pub fn unregister_module_trigger(owner: u64, name: &str) -> i32 {
    {
        let g = TRIGGER_OWNERS.lock();
        if !g.iter().any(|(o, n)| *o == owner && n == name) {
            return if g.iter().any(|(_, n)| n == name) {
                -16 // -EBUSY: another module owns this trigger.
            } else {
                -19 // -ENODEV
            };
        }
    }
    match narf_drivers_leds::triggers::unregister_module_trigger(name) {
        Ok(()) => {
            TRIGGER_OWNERS
                .lock()
                .retain(|(o, n)| !(*o == owner && n == name));
            0
        }
        Err(errno) => errno,
    }
}

/// Loader backstop: force-unregister every trigger owned by
/// `owner`. Affected LEDs are reverted to `Trigger::None` first
/// (brightness left at its last value), so an unload can never
/// strand a LED on a dead trigger.
pub fn unregister_module_triggers(owner: u64) {
    let names: Vec<String> = {
        let mut g = TRIGGER_OWNERS.lock();
        let mut names = Vec::new();
        g.retain(|(o, n)| {
            if *o == owner {
                names.push(n.clone());
                false
            } else {
                true
            }
        });
        names
    };
    for name in names {
        narf_drivers_leds::triggers::force_unregister_module_trigger(&name);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn quad(tag: u32, int_val: u64, payload_off: u64, len: u64) -> [u8; AML_QUAD_LEN] {
    let mut q = [0u8; AML_QUAD_LEN];
    q[0..4].copy_from_slice(&tag.to_le_bytes());
    q[8..16].copy_from_slice(&int_val.to_le_bytes());
    q[16..24].copy_from_slice(&payload_off.to_le_bytes());
    q[24..32].copy_from_slice(&len.to_le_bytes());
    q
}

fn smoke_kabi_platform_quad_round_trip() -> TestResult {
    // An empty quad stream is zero arguments, not malformed.
    match decode_aml_args(&[], &[]) {
        Ok(args) if args.is_empty() => {}
        _ => return TestResult::Fail("empty quad stream must decode to zero arguments"),
    }
    // Integer.
    let v = narf_aml::Value::Integer(0x60C0);
    let mut buf = [0u8; 64];
    let n = match encode_aml_result(&v, &mut buf) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("encode Integer must succeed"),
    };
    if n != AML_QUAD_LEN {
        return TestResult::Fail("encode Integer must need exactly one quad");
    }
    match decode_aml_result(&buf[..n]) {
        Ok(narf_aml::Value::Integer(0x60C0)) => {}
        _ => return TestResult::Fail("Integer result must round-trip"),
    }
    // String + Buffer + nested Package.
    let v = narf_aml::Value::Package(vec![
        narf_aml::Value::String(String::from("MLCS")),
        narf_aml::Value::Buffer(vec![1, 2, 3]),
        narf_aml::Value::Package(vec![narf_aml::Value::Integer(7)]),
    ]);
    let need = encoded_aml_len(&v);
    // 5 quads (package + 3 children + 1 grandchild) + 4 + 3 payload bytes.
    if need != 5 * AML_QUAD_LEN + 7 {
        return TestResult::Fail("encoded_len must count quads + payload");
    }
    let mut buf = alloc::vec![0u8; need];
    if encode_aml_result(&v, &mut buf).is_err() {
        return TestResult::Fail("encode Package must succeed");
    }
    match decode_aml_result(&buf) {
        Ok(decoded) if decoded == v => {}
        _ => return TestResult::Fail("Package result must round-trip"),
    }
    // -ENOSPC when the buffer is one byte short of the need.
    let mut short = alloc::vec![0u8; need - 1];
    if encode_aml_result(&v, &mut short).is_ok() {
        return TestResult::Fail("encode must fail on a short buffer");
    }
    // The args direction (two buffers) decodes the same quads.
    let quads = &buf[..5 * AML_QUAD_LEN];
    let payload = &buf[5 * AML_QUAD_LEN..];
    match decode_aml_args(quads, payload) {
        Ok(args) if args == [v] => {}
        _ => return TestResult::Fail("args decode must accept the same stream"),
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi-platform", smoke_kabi_platform_quad_round_trip);

fn smoke_kabi_platform_quad_rejects_malformed() -> TestResult {
    // Unknown tag.
    let q = quad(9, 0, 0, 0);
    if decode_aml_args(&q, &[]).is_ok() {
        return TestResult::Fail("unknown tag must be rejected");
    }
    // Non-zero reserved field.
    let mut q = quad(0, 1, 0, 0);
    q[4] = 1;
    if decode_aml_args(&q, &[]).is_ok() {
        return TestResult::Fail("non-zero reserved field must be rejected");
    }
    // Length not a multiple of the quad size.
    if decode_aml_args(&[0u8; 31], &[]).is_ok() {
        return TestResult::Fail("short quad stream must be rejected");
    }
    // Payload offset out of range.
    let q = quad(1, 0, 8, 4);
    if decode_aml_args(&q, b"ab").is_ok() {
        return TestResult::Fail("out-of-range payload offset must be rejected");
    }
    // Non-UTF-8 String payload.
    let q = quad(1, 0, 0, 2);
    if decode_aml_args(&q, &[0xFF, 0xFE]).is_ok() {
        return TestResult::Fail("non-UTF-8 String payload must be rejected");
    }
    // Package claiming more children than quads present.
    let mut stream = Vec::new();
    stream.extend_from_slice(&quad(3, 0, 2, 0));
    stream.extend_from_slice(&quad(0, 1, 0, 0));
    if decode_aml_args(&stream, &[]).is_ok() {
        return TestResult::Fail("truncated Package must be rejected");
    }
    // Over-deep nesting: 6 nested packages (max depth 4).
    let mut stream = Vec::new();
    for _ in 0..6 {
        stream.extend_from_slice(&quad(3, 0, 1, 0));
    }
    stream.extend_from_slice(&quad(0, 1, 0, 0));
    if decode_aml_args(&stream, &[]).is_ok() {
        return TestResult::Fail("over-deep Package nesting must be rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi-platform",
    smoke_kabi_platform_quad_rejects_malformed
);

fn smoke_kabi_platform_hid_buffer() -> TestResult {
    let hids = match parse_hid_buffer(b"LEN0268\0IBM0068\0LEN0018\0") {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("valid HID buffer must parse"),
    };
    if hids != ["LEN0268", "IBM0068", "LEN0018"] {
        return TestResult::Fail("HID buffer must split on NUL");
    }
    if parse_hid_buffer(b"").is_ok() || parse_hid_buffer(b"\0\0").is_ok() {
        return TestResult::Fail("empty HID buffer must be rejected");
    }
    if parse_hid_buffer(b"OK\0\xFF\xFE\0").is_ok() {
        return TestResult::Fail("non-UTF-8 HID must be rejected");
    }
    if aml_errno(narf_aml::AmlError::MethodNotFound) != -19 {
        return TestResult::Fail("MethodNotFound must map to -ENODEV");
    }
    if aml_errno(narf_aml::AmlError::Truncated) != -5 {
        return TestResult::Fail("other AmlErrors must map to -EIO");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi-platform", smoke_kabi_platform_hid_buffer);

extern "C" fn test_led_set(_cookie: u64, _level: u32) {}

extern "C" fn test_led_get(_cookie: u64) -> u32 {
    7
}

extern "C" fn test_trigger_compute(_cookie: u64, max: u32, _ticks: u32) -> u32 {
    max
}

/// ACPI registration enforces one driver per module, and the
/// unregister/backstop paths drop the entry. No AML namespace is
/// loaded in the host harness, so the re-match finds no devices and
/// the probe is never invoked (its address is never called).
fn smoke_kabi_platform_acpi_register_rules() -> TestResult {
    let owner = 0xA11CEu64;
    unregister_module_acpi_drivers(owner);
    let hids = match parse_hid_buffer(b"LEN0268\0IBM0068\0") {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("HID parse must succeed"),
    };
    if register_acpi_driver(owner, "thinkpad-led-test", hids, 0x1000, 0, 99) != 0 {
        return TestResult::Fail("first ACPI registration must succeed");
    }
    let hids2 = match parse_hid_buffer(b"LEN0268\0") {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("HID parse must succeed"),
    };
    if register_acpi_driver(owner, "second", hids2, 0x2000, 0, 99) != -16 {
        unregister_module_acpi_drivers(owner);
        return TestResult::Fail("second ACPI driver for the same module must be -EBUSY");
    }
    if unregister_acpi_driver(owner) != 0 {
        unregister_module_acpi_drivers(owner);
        return TestResult::Fail("unregister of a registered driver must succeed");
    }
    if unregister_acpi_driver(owner) != -19 {
        return TestResult::Fail("unregister with no driver must be -ENODEV");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi-platform",
    smoke_kabi_platform_acpi_register_rules
);

/// Notify shims dedup on the exact triple and drop the core shim
/// when the last entry for a path goes away.
fn smoke_kabi_platform_notify_shim_rules() -> TestResult {
    let owner = 0xB00u64;
    unregister_module_notify_shims(owner);
    if register_notify_shim(owner, "/SB.HKEY", 0x1000, 7) != 0 {
        return TestResult::Fail("first notify subscription must succeed");
    }
    if register_notify_shim(owner, "/SB.HKEY", 0x1000, 7) != -17 {
        unregister_module_notify_shims(owner);
        return TestResult::Fail("exact-duplicate subscription must be -EEXIST");
    }
    // Same handler, different cookie: a distinct subscription.
    if register_notify_shim(owner, "/SB.HKEY", 0x1000, 8) != 0 {
        unregister_module_notify_shims(owner);
        return TestResult::Fail("same handler with a different cookie must succeed");
    }
    if unregister_notify_shim(owner, "/SB.HKEY", 0x1000) != 0 {
        unregister_module_notify_shims(owner);
        return TestResult::Fail("unregister must remove the subscriptions");
    }
    if unregister_notify_shim(owner, "/SB.HKEY", 0x1000) != -19 {
        return TestResult::Fail("second unregister must be -ENODEV");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi-platform",
    smoke_kabi_platform_notify_shim_rules
);

/// LED registration enforces cross-owner name exclusivity, and a
/// shim whose owner is gone reads back 0 (the gate refuses a dead
/// owner, so no module text is ever entered).
fn smoke_kabi_platform_led_register_rules() -> TestResult {
    narf_drivers_leds::class::__reset_for_test();
    let owner_a = 0xA00u64;
    let owner_b = 0xB00u64;
    unregister_module_leds(owner_a);
    unregister_module_leds(owner_b);
    let set = test_led_set as usize;
    let get = test_led_get as usize;
    if register_module_led(owner_a, "test::kabi-led", 1, set, get, 0, 3, None) != 0 {
        return TestResult::Fail("first LED registration must succeed");
    }
    if register_module_led(owner_b, "test::kabi-led", 1, set, get, 0, 3, None) != -16 {
        unregister_module_leds(owner_a);
        unregister_module_leds(owner_b);
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("another module's LED name must be -EBUSY");
    }
    // Same-owner re-registration replaces the shim.
    if register_module_led(owner_a, "test::kabi-led", 1, set, get, 0, 3, None) != 0 {
        unregister_module_leds(owner_a);
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("same-owner re-registration must succeed");
    }
    // The shim's owner (a fake id) is not a Live module, so the gate
    // refuses and brightness reads back 0 — never a jump into the
    // test function above.
    let dev = match narf_drivers_leds::lookup_led_by_name("test::kabi-led") {
        Some(d) => d,
        None => {
            unregister_module_leds(owner_a);
            narf_drivers_leds::class::__reset_for_test();
            return TestResult::Fail("registered LED must be lookable-up");
        }
    };
    if dev.brightness() != 0 {
        unregister_module_leds(owner_a);
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("shim with a dead owner must read brightness 0");
    }
    if unregister_module_led(owner_b, "test::kabi-led", false) != -19 {
        unregister_module_leds(owner_a);
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("unregister by a non-owner must be -ENODEV");
    }
    if unregister_module_led(owner_a, "test::kabi-led", false) != 0 {
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("unregister by the owner must succeed");
    }
    if narf_drivers_leds::lookup_led_by_name("test::kabi-led").is_some() {
        narf_drivers_leds::class::__reset_for_test();
        return TestResult::Fail("unregistered LED must leave the registry");
    }
    narf_drivers_leds::class::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi-platform",
    smoke_kabi_platform_led_register_rules
);

/// Trigger registration round-trips through the LED core: the
/// module trigger becomes selectable, and unregister drops it.
fn smoke_kabi_platform_trigger_register_rules() -> TestResult {
    narf_drivers_leds::__reset_all_for_test();
    let owner = 0xC00u64;
    unregister_module_triggers(owner);
    let compute = test_trigger_compute as usize;
    if register_module_trigger(owner, "test-trigger", compute, 5) != 0 {
        return TestResult::Fail("trigger registration must succeed");
    }
    // A builtin name cannot be taken by a module trigger.
    if register_module_trigger(owner, "audio-mute", compute, 5) != -17 {
        unregister_module_triggers(owner);
        narf_drivers_leds::__reset_all_for_test();
        return TestResult::Fail("a builtin trigger name must be -EEXIST");
    }
    if unregister_module_trigger(owner, "test-trigger") != 0 {
        unregister_module_triggers(owner);
        narf_drivers_leds::__reset_all_for_test();
        return TestResult::Fail("unregister of a registered trigger must succeed");
    }
    if unregister_module_trigger(owner, "test-trigger") != -19 {
        narf_drivers_leds::__reset_all_for_test();
        return TestResult::Fail("second unregister must be -ENODEV");
    }
    narf_drivers_leds::__reset_all_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi-platform",
    smoke_kabi_platform_trigger_register_rules
);
