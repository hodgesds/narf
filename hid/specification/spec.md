# narf-hid

Transport-neutral HID 1.11 codec.

## Sources (public only)

- **HID 1.11** — *Device Class Definition for Human Interface
  Devices*, Version 1.11, 27 June 2001 (USB-IF / usb.org).
  - §5.3 — Generic Item Format (short / long item layout, prefix
    byte encoding).
  - §6.2.2 — Report Descriptor.
  - §6.2.2.4 — Main items (Input / Output / Feature / Collection /
    End Collection).
  - §6.2.2.5 — Input/Output/Feature data flags (Constant, Variable,
    Relative, Wrap, NonLinear, NoPreferred, NullState, Volatile,
    BufferedBytes).
  - §6.2.2.6 — Collection types.
  - §6.2.2.7 — Global items (Usage Page, Logical/Physical Min/Max,
    Unit/Unit Exp, Report Size/ID/Count, Push/Pop).
  - §6.2.2.8 — Local items (Usage, Usage Min/Max, Designator,
    String, Delimiter; rules around 4-byte extended-usage form and
    end-of-Main-item local-state reset).
  - §8 — Report Format (LSB-first bit packing, optional 1-byte
    Report ID prefix).
- **HID Usage Tables 1.4** — *USB HID Usage Tables*, 28 May 2020
  (USB-IF). Page + usage constants (§4 Generic Desktop, §10
  Keyboard/Keypad, §12 Button, §15 Consumer, §16 Digitizer).
- **HID 1.11 Appendix B.1** — Boot Keyboard reference descriptor,
  used as a fixture in tests/.

No GPL / Linux source consulted.

## Surface

- `descriptor::parse(blob) -> ReportDescriptor` — walks a report
  descriptor's Main / Global / Local item state machine, returns
  the ordered Field list, top-level Application Collection
  identifiers, and a flag indicating whether any `Report ID` global
  item appeared.
- `report::extract(field, body) -> Vec<i32>` — runtime report value
  decoder. Accepts the body *after* the optional report-id byte;
  applies sign-extension iff `logical_min < 0`.
- `report::pack(field, body, values)` — symmetric encoder for
  Output / Feature reports.
- `report::array_active_usages(field, body)` — convenience for
  array-style Input fields (boot keyboard, simple gamepad): maps
  each non-zero array slot back to its `(usage_page, usage_id)`.
- `usage::*` — selected page/usage constants from HID Usage Tables
  1.4 (Generic Desktop, Keyboard, Button, Digitizer, Consumer).

## Out of scope

- Transport (USB control / interrupt, i2c-HID, BT L2CAP, GATT) —
  callers feed bytes in and read decoded values out.
- Physical-units / unit-exponent post-processing — exposed verbatim
  on `Field`; consumers interpret.
- HID Class Descriptor (the device-level descriptor that says "I
  have a Report Descriptor of length N") — that's a USB / i2c
  transport detail.
