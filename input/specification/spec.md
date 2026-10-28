# narf-input — input event types + RMI4 codec

## Sources (public only)

All code is derived strictly from the references below.
**No GPL Linux source consulted.**

### Event ring + key/pointer/scroll types

- `evdev` user-space ABI — Linux's stable user-facing input event
  numbering and key-code conventions (the public ABI documented in
  `linux/input.h`'s comments / userspace-facing portion only — this
  is the *kernel-facing API*, not the kernel's GPL implementation).
  Used as a structural reference for the per-driver translation
  table shape.

### Goodix GT911 (touchscreen)

- **GT911 Programming Guide, Version 0.1** (March 2014) — Goodix
  Technology. Public document distributed by panel integrators
  (Hantick, Waveshare, Adafruit). I²C address pair (0x5D / 0x14)
  determined by INT pin state at reset, 16-bit register addressing.
- **GT911 Datasheet, Revision 0.9** — Goodix. Public.
  §3.5 (I²C protocol). §4.4 (Coordinate Reporting Layout — 5-touch
  data block at 0x814E with 1-byte status + N×8-byte point
  records). §6 (Configuration register block 0x8047..0x80FF with
  the 8-bit checksum at 0x80FF and the 1-byte "config-fresh"
  trigger at 0x8100).

### Synaptics RMI4 (touchpad)

- **Synaptics PS/2 ↔ SMBus + RMI4 Application Note** — Synaptics,
  public PDF (document number "511-000405-01"). Describes the RMI4
  transport layer that ClickPad / Force touchpads expose over
  SMBus. §4.4 Page Description Table walk. §4.5 F$01 Device Control
  control + status registers. §4.6 F$11 2D Touchpad finger
  position packing (12-bit X/Y across two bytes + a shared low-
  nibble byte). §4.10 F$34 Flash Reflash command codes.
- **Synaptics SMBus Touchpad Communication Application Note** —
  rev D, 2008. Public PDF. Covers the SMBus bring-up sequence
  modern Lenovo / Dell / HP laptop touchpads use to switch out of
  PS/2 mode into RMI4.

## Scope

### Landed
- `KeyEvent` / `PointerEvent` / `ScrollEvent` types + `EventRing`
  with the `narf-capabilities`-gated subscriber handle.
- `ButtonEvent` (generic `BTN_*` codes, `btn` module) and
  `SwitchEvent` (binary `SW_*` state changes — tablet mode, dock,
  lid, rfkill-all; `sw` module constants and the
  `InputEvent::Switch` variant, routed through their own
  per-class ring). `SW_*` numbering follows the same public
  evdev UAPI convention as the `btn` / `abs` code tables
  (Linux UAPI, per `LICENSES/exceptions/Linux-syscall-note`).
- `evdev` per-device publication surface: `Router::register_device`
  takes a `DeviceCaps` carrying the device's userspace-visible
  identity — `name`, `phys`, `uniq`, `InputId` (`bustype` / `vendor`
  / `product` / `version`, Linux `struct input_id`) — plus an
  `INPUT_PROP_*` property bitmap (`propbit`), alongside the existing
  key/rel/abs capability bitmaps and per-axis `AxisInfo` ranges.
  Producers fill the identity from their discovering transport;
  `DeviceCaps::default()` keeps the historical synthetic identity
  (`narf-input`, `BUS_VIRTUAL`, ids 0) for producers not yet plumbed.
- `evdev` LED output surface: `DeviceCaps::ledbit` (declared via
  `add_led`) advertises `EV_LED` codes. The input core owns the
  per-device LED state (`DeviceNode::led_state`, the bitmap
  `EVIOCGLED` returns, indexed by Linux `EV_LED` code):
  `DeviceNode::dispatch` sets/clears bits for `EV_LED` events and
  toggles the matching bit on a lock-key (Caps/Num/Scroll) press.
  On every change the core invokes the producer's registered LED
  sink (`DeviceNode::set_led_sink`, a plain `fn(u16)`) — or the
  producer polls `led_state` from its own pump (I2C-HID). evdev
  `write()` on a hardware device accepts *only* a pure `EV_LED`
  buffer of codes the device declares (validated whole before any
  dispatch) — the blanket denial of hardware writes otherwise
  stands, so arbitrary input injection stays impossible. Wire
  encodings are producer-local and differ from the core order:
  i8042's Set-LEDs data byte is Scroll/Num/Caps at bits 0/1/2;
  a HID LED Output report follows descriptor usage order.
  The filesystem layer answers `EVIOCGID` / `EVIOCGNAME` /
  `EVIOCGPHYS` / `EVIOCGUNIQ` / `EVIOCGPROP` from these fields and
  synthesises `/dev/input/by-id` / `/dev/input/by-path` aliases and
  the sysfs `name` / `phys` / `uniq` + `PRODUCT=` uevent fields from
  them.
- `evdev::MtEvdevState`: transport-neutral multi-touch emitter
  implementing Linux slot protocol B. The producer resolves wire
  contact ids to MT slots; the emitter owns the wire rules —
  per-slot `ABS_MT_SLOT` / `ABS_MT_TRACKING_ID` (`-1` on release) /
  `ABS_MT_POSITION_X/Y` / `ABS_MT_PRESSURE`, single-touch
  `ABS_X`/`ABS_Y` + `BTN_TOUCH` compatibility following the primary
  slot, integrated-button edges, and exactly one `SYN_REPORT` per
  non-empty frame.
- `goodix`: clean-room GT911 codec. I²C address constants,
  status-byte decoder (buffer-ready / large-detect / have-key /
  4-bit touch count), TouchPoint parser (track-id + LE 16-bit
  X/Y/size), CoordReport multi-finger decoder, command-register
  values (read coord / soft reset / baseline update /
  calibration / screen off), config-block 8-bit checksum builder
  + verifier.
- `rmi4`: Page Description Table entry decoder, Function-Number
  constants for F$01 / F$11 / F$12 / F$30 / F$34 / F$54, F$01
  Device Control byte builder + Device Status decoder, F$11 finger
  parser (12-bit X/Y packing, touch widths) and multi-finger
  Touchpad Report decoder. F$34 command-code constants.

### Out of scope (deferred)
- F$12 next-generation touchpad function (extends F$11 with
  "Sensor Report Format" descriptor — lands when a target Force
  Touch surface needs it).
- Force Touch / haptic-feedback path (Synaptics F$54 self-test +
  F$30 GPIO/LED wiring). Surface kept but not exercised end-to-end.
