# Extending NARF: Input & HID Drivers

Prereq: [drivers.md](drivers.md). This doc covers emitting input events into the
evdev surface, and parsing HID report descriptors.

Sources: `input/src/evdev.rs` (per-device evdev surface — the modern path),
`input/src/lib.rs` (the legacy global ring), `hid/` (report-descriptor parser).
Reference drivers: `drivers/input/src/i8042.rs` (PS/2 keyboard),
`drivers/input/src/i2c_hid_bind.rs` (i2c-HID), and the USB-HID path under
`drivers/usb/`.

Cleanly out-of-tree: build `DeviceCaps`, `ROUTER.register_device(caps)`, then
`node.dispatch(event)` from your IRQ/pump.

---

## 1. The evdev per-device surface — use this for new drivers

This is the preferred seam (i8042, i2c-HID, virtio-input all use it). You get an
`Arc<DeviceNode>` and dispatch `EvdevEvent`s into it; the syscall layer serves
`/dev/input/eventN` from the node.

### 1.1 Register a device

```rust
pub static ROUTER: Router = Router::new();       // input/src/evdev.rs:687

impl Router {
    pub fn register_device(&self, caps: DeviceCaps)      // input/src/evdev.rs:602
        -> (DeviceId, Arc<DeviceNode>);
}
```

You describe the device's capabilities with `DeviceCaps`
(`input/src/evdev.rs:224`) and its builder methods:

```rust
let mut caps = DeviceCaps::new();
caps.add_key(code);     // input/src/evdev.rs:241  — a supported EV_KEY code
caps.add_rel(axis);     //                          — a supported EV_REL axis
caps.add_abs(axis);     //                          — a supported EV_ABS axis
let (dev_id, node) = ROUTER.register_device(caps);
```

Keep the returned `Arc<DeviceNode>` alive (store it in a `static`); dispatch
into it later.

### 1.2 The wire event and dispatch

`EvdevEvent` (`input/src/evdev.rs:125`) is the 16-byte, `#[repr(C)]`,
Linux-`struct input_event`-compatible record (nanosecond timestamp):

```rust
#[repr(C)]
pub struct EvdevEvent {          // input/src/evdev.rs:125
    pub time: u64,               // KernelInstant ns
    pub type_: EventType,        // Syn/Key/Rel/Abs/Msc/Led/Ff  (input/src/evdev.rs:39)
    pub code: u16,
    pub value: i32,
}
```

Push events with:

```rust
impl DeviceNode {
    pub fn dispatch(&self, ev: EvdevEvent) -> bool;   // input/src/evdev.rs:420
}
```

`dispatch` is **lock-free enough to call from an IRQ**: it pushes into the
node's ring (dropping the oldest + synthesising `SYN_DROPPED` on overflow),
wakes parked readers, and returns `false` if the node is dead. Always terminate
a logical event frame with a `SYN_REPORT` — use `EvdevEvent::syn_report(now)`
(`input/src/evdev.rs:143`).

### 1.3 Dispatch helpers (do the SYN for you)

You rarely build `EvdevEvent`s by hand; use the helpers
(`input/src/evdev.rs`):

```rust
pub fn dispatch_key_to_node(node: &DeviceNode, code: u16, pressed: bool);       // :704
pub fn dispatch_rel_to_node(node: &DeviceNode, dx: i32, dy: i32);               // :754
pub fn dispatch_pointer_to_node(node: &DeviceNode, dx: i32, dy: i32,           // :785
                                btn_changes: &[(u16, bool)]);
```

Each emits the data event(s) plus the trailing `SYN_REPORT` as one frame.

### 1.4 Legacy global ring (`input/src/lib.rs`)

The older, device-less path pushes `InputEvent` (`input/src/lib.rs:767`, an enum
of `Key`/`Pointer`/`Scroll`/`Absolute`/`Touch`/`Button`/`AsciiByte`) into a
single global ring:

```rust
pub fn push_key(code: KeyCode, pressed: bool) -> bool;   // input/src/lib.rs:970 (also updates modifiers)
pub fn push_global(ev: InputEvent) -> bool;              // input/src/lib.rs:995 (routes by variant)
```

New drivers should prefer the per-device evdev path; the global ring is kept for
the console/tty ASCII path (`AsciiByte` wakes the blocked console reader). A
driver can feed both, as i8042 does.

---

## 2. Worked reference: i8042 (PS/2 keyboard)

Registration inside `init()` (`drivers/input/src/i8042.rs`):

```rust
let mut caps = DeviceCaps::new();                    // drivers/input/src/i8042.rs:386
for c in 1u16..=127 { caps.add_key(c); }             // declare the key range
// … extended keys …
let (_dev_id, node_arc) = ROUTER.register_device(caps);   // :397
// stash the raw Arc ptr in an AtomicPtr for lock-free IRQ access, and the Arc
// itself in a static to keep it alive.
```

IRQ1 handler dispatches (`drivers/input/src/i8042.rs`, `on_irq1`): decode the
scancode → `KeyCode`, then both `push_key(code, pressed)` (legacy ring) and
`dispatch_key_to_node(node_ref, code as u16, pressed)` (evdev), where `node_ref`
comes from the `AtomicPtr` loaded in the ISR.

Wired at `Stage::Device` (`drivers/input/src/lib.rs:83`):

```rust
narf_init::register(Stage::Device, "i8042-kbd", || {
    let init_ok = unsafe { i8042::init() }.is_ok();
    let irq_ok  = install_isa_irq(1, on_irq1_safe);
    if init_ok && irq_ok { InitResult::Ok } else { InitResult::NotPresent }
});
```

Note the `NotPresent` return when the hardware isn't there — the correct,
non-fatal answer for an absent device (see [drivers.md](drivers.md) §1.3). The
PS/2 mouse follows the same shape (`drivers/input/src/lib.rs:105`).

---

## 3. HID report descriptors (`hid/`)

The `hid` crate is a **transport-agnostic parser** — it turns a raw report
descriptor blob (from USB `GET_DESCRIPTOR(Report)`, i2c-HID, or BT-HID) into a
structured `ReportDescriptor`. It has **no registration seam** and no device
model; you call `parse` and then decode reports using the returned field
metadata, dispatching the decoded values into evdev (§1).

```rust
pub fn parse(blob: &[u8]) -> Result<ReportDescriptor, DescriptorError>;  // hid/src/descriptor.rs:250
```

re-exported from the crate root (`hid/src/lib.rs:97`) alongside `Field`,
`FieldKind`, `FieldFlags`, `CollectionKind`, `DescriptorError`,
`ReportDescriptor`, and the report codecs `extract` / `pack`.

`ReportDescriptor` (`hid/src/descriptor.rs:185`) carries an ordered
`fields: Vec<Field>`, `has_report_ids`, and `top_level_apps`, with helpers like
`fields_with_report_id(id)` and `report_body_bits(id, kind)`. Each `Field`
(`hid/src/descriptor.rs:145`) has `kind` (`Input`/`Output`/`Feature`),
`usage_page`/`usages`, `logical_min`/`max`, `report_size`/`report_count`, and
`bit_offset` (its position within the report). Higher-level shape detectors live
alongside it: `narf_hid::ptp::detect`, `narf_hid::touchscreen::detect`,
`narf_hid::pen::detect`.

### 3.1 Worked reference: i2c-HID (`drivers/input/src/i2c_hid_bind.rs`)

The end-to-end HID pattern:

```rust
let parsed = narf_hid::parse(&report_desc_blob)?;    // drivers/input/src/i2c_hid_bind.rs:377
let ptp         = narf_hid::ptp::detect(&parsed);    // :389
let touchscreen = narf_hid::touchscreen::detect(&parsed);
let pen         = narf_hid::pen::detect(&parsed);
// … then per-report: extract field values and dispatch into an evdev DeviceNode.
```

This driver also shows the ACPI-namespace discovery + `I2cBus` transport pattern
from [drivers.md](drivers.md) §3.2/§3.4. The **USB-HID** equivalent registers as
a USB class driver (`drivers/usb/`, `class_registry::register_class_driver`, see
[drivers.md](drivers.md) §3.3) and then follows the same parse → extract →
`ROUTER.dispatch` flow.

---

## 4. Gotchas

- **IRQ-safe dispatch.** `DeviceNode::dispatch` is designed for IRQ context, but
  hold the `Arc<DeviceNode>` alive via a `static` and reach it in the ISR
  through an `AtomicPtr<DeviceNode>` (`Arc::as_ptr`) — do not lock an `Arc`
  behind a mutex you'd take in the ISR.
- **Always SYN.** Every logical frame ends with `SYN_REPORT`. The
  `dispatch_*_to_node` helpers do it for you; if you hand-roll `EvdevEvent`s you
  must append it yourself or userspace never sees the frame.
- **Report `NotPresent`, not panic,** from the initcall when the controller
  isn't present.
- **Codes are Linux evdev codes.** `KeyCode`/`add_key` use the `KEY_*` numbering;
  emit the same codes Linux would so userspace input libraries work unchanged.
- **HID has no register hook** — it's a pure library. The "driver" is whatever
  transport binding (i2c-HID / USB-HID) owns the device and calls `parse`.
