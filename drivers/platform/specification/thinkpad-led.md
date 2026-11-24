# ThinkPad LED driver (`thinkpad_led`)

## 1. Purpose and scope

The LED half of `drivers/platform/thinkpad_acpi` (lane 2's corrected
surface), promoted into its own dual-build crate
(`drivers/platform/thinkpad_led`, package
`narf-drivers-platform-thinkpad-led`) so it builds two ways from one
source, exactly like `drivers/wireless/mt76/`:

- `builtin` (default): an rlib the `narf-drivers-platform` facade
  registers from its `Stage::Device` initcall.
- `module`: a relocatable `.ko` via `cargo xtask build-module`,
  registering through the `PlatformDriver` KABI exports
  (tracker #2448).

The driver exposes the three Linux mechanisms, re-derived against
`drivers/platform/linux/thinkpad_acpi.c` in the mechanism record
(`~/workspace/queue/thinkpad-led-mechanism-2026-11-23.md`):

- kbdlight: `MLCG`/`MLCS` on the HKEY device (`tpacpi::kbd_backlight`,
  max 2 levels).
- mute/micmute: `SSMS`/`MMTS` on HKEY (`platform::mute`,
  `platform::micmute`, max 1).
- generic LEDs: `LED` on the EC device, four safe indices only —
  power (0), standby (7), lid-logo-dot (10), thinkvantage (12).

`thinkpad_acpi.rs` keeps HKEY dispatch, fan, battery, and hotkeys; the
0x60C0 notify arm calls back into this crate to re-assert micmute.
The audio-micmute trigger lives in a separate trigger-only module
(`drivers/leds/audio_micmute`); there is no builtin duplicate.

## 2. Assumptions

- The machine is a ThinkPad with the HKEY device
  (`\_SB.PCI0.LPCB.EC.HKEY`, HID `LEN0268`) and the EC device
  (`\_SB.PCI0.LPCB.EC`, HID `PNP0C09`). Without them the driver
  registers nothing and probes report unavailable.
- **DSDT-UNVERIFIED:** every AML path literal in `defs.rs` is copied
  verbatim from lane 2's `thinkpad_acpi.rs` and has NOT been verified
  against the P14s DSDT yet (mechanism record §5, tracker #2448).
  The driver must not present them as grounded.
- The kbdlight probe is the full Linux test: `MLCG` returns
  non-negative AND bit 9 is set. A machine without kbdlight reports
  unsupported; `MLCS` is called from exactly one place in Linux
  (`kbdlight_set_level`), and this driver follows that.
- The namespace is static after boot: there is no bus probe path, so
  ACPI-driver registration re-matches against already-enumerated
  devices.

## 3. Public interface

- `defs::LED_DEFS`: the seven LEDs in cookie order — kbdlight
  (`tpacpi::kbd_backlight`, max 2), mute (`platform::mute`, max 1,
  default trigger `audio-mute`), micmute (`platform::micmute`, max 1,
  default trigger `audio-micmute`), power / standby / lid-logo-dot /
  thinkvantage (max 1). Safe mask `0x1481` (bits {0, 7, 10, 12}).
- `defs::GenericLed`: `Power`, `Standby`, `LidLogoDot`,
  `ThinkVantage`; `from_index` admits only the four safe indices.
- `builtin::set_generic_led(index, LedState) -> Result<(), LedError>`:
  index validation precedes any AML call; writes `LED(index, arg)`
  with arg `0x00` (Off) / `0x80` (On) / `0xC0` (Blink), and updates
  the packed-`AtomicU32` state cache on success.
- `builtin::set_kbdlight_level(u8) / get_kbdlight_level() /
  kbdlight_supported()`: level 0..=2; `MLCS(level)` folds the level
  into `MLVL` with bit 9 set; `MLCG` reads it back masked to 2 bits.
- `builtin::set_mute(bool) / set_micmute(bool) /
  mute_available() / micmute_available() / micmute_state()`:
  `SSMS(1/0)`, `MMTS(2/0)`; micmute state is cached for the 0x60C0
  re-assert.
- `builtin::register()`: seeds the kbdlight level first, then
  registers each available LED with its default trigger.
- `driver::set_led / get_led / seed_kbdlight / on_notify`: the shared
  probe/register/set logic behind the `Backend` trait; `on_notify`
  re-asserts micmute on 0x60C0 and ignores all other values.
- `module_probe::register() / exit()`: the `.ko` side — ACPI-driver
  registration, LED registration through `narf_led_register`, notify
  subscription through `narf_acpi_register_notify_handler`.
- `quad::encode_int_arg / decode_int_result`: the module-side
  Integer-only quad codec (the full String/Buffer/Package codec stays
  kernel-side in `modules/src/kabi_platform.rs`).
- LED class names are the Linux names (`tpacpi::kbd_backlight`,
  `platform::mute`, `platform::micmute`, `tpacpi::power`,
  `tpacpi::standby`, `tpacpi::lid_logo_dot`,
  `tpacpi::thinkvantage`).

## 4. Invariants

- Index validation precedes the AML call: restricted indices
  (1, 2, 3, 4, 5, 6, 8, 9, 11, 13, 14, 15 — including battery 1/2
  and dock_status1 at index 8) return `RestrictedIndex` and
  out-of-range indices return `InvalidIndex` without touching AML.
- The state cache is updated only on a successful AML call.
- Kbdlight level is clamped to the classdev max (2); level 3 is
  `InvalidLevel` and never reaches `MLCS`.
- Absent methods fail closed: setters return `MethodUnavailable` or
  `Aml(MethodNotFound)` and probes report unavailable; nothing is
  registered for a missing device.
- The micmute 0x60C0 arm re-asserts the *cached* state — it never
  invents a state.
- Module remove drives each LED OFF while the module is still Live;
  the unload backstop cannot drive off (the gate refuses a Going
  module), so an LED unregistered only by the backstop keeps its last
  brightness — a documented limitation, not silent state.

## 5. Architecture notes (x86_64, aarch64)

- x86_64 only: the builtin registration is gated on the platform
  facade's `Stage::Device` initcall; the crate has no aarch64 path.
- `Backend` trait (9 methods) separates the shared logic
  (`driver.rs`) from the two AML transports: `BuiltinBackend` calls
  `narf-aml` directly; `ModuleBackend` calls the KABI exports with
  the Integer-only quad codec. Both share `defs.rs` and `driver.rs`.
- Module AML evaluation starts with a 256-byte result scratch and
  retries once on `-ENOSPC` with a buffer sized to `out_needed`
  (up to 1024 bytes on the stack).
- Module availability is coarse by design: there is no method-exists
  export, so the module backend treats mute/micmute availability as
  "an HKEY device matched" and generic availability as "an EC device
  (`PNP0C09`) exists". A missing method surfaces as a failed set,
  which the driver tolerates. The kbdlight probe is exact (`MLCG(0)`
  is a read, so the bit-9 test runs unchanged).
- The `set_trigger` LED callback is `0` (engine-owned): these LEDs
  need no trigger notification from hardware.

## 6. Dependencies

- `narf-aml` (builtin only): method evaluation, namespace lookup.
- `narf-drivers-leds` (builtin only): `LedDevice` registration,
  `Trigger::Module` registry, default-trigger map.
- `narf-driver-macros`: `narf_driver!` (`required_caps:
  "PlatformDriver:Write"`, `target_domain: "platform"`).
- KABI exports (module only): `narf_register_acpi_driver`,
  `narf_aml_evaluate_method`, `narf_acpi_find_devices_by_hid`,
  `narf_acpi_register_notify_handler`, `narf_led_register`.
- `drivers/platform`: the facade registers the builtin build at
  `Stage::Device`; `thinkpad_acpi.rs` owns HKEY dispatch and calls
  into this crate for LED sets and the 0x60C0 arm.

## 7. Stage assignment

Stage 5 (Silicon): platform EC work on the P14s AMD (Ryzen 8840,
HawkPoint). Tracker #2448.

## 8. Open questions

- DSDT dump from the P14s (owed by Daniel): verifies the path
  literals and the kbdlight/mute/micmute method shapes on real
  firmware.
- A `narf_aml_method_exists` export is a follow-up, not a v1 item:
  it would sharpen the module backend's coarse availability
  (mute/micmute/generic) into exact per-method probes.
- The trigger-read attribute listing available triggers is a
  follow-up, not v1.
- Extending `quad.rs` past Integers (String/Buffer/Package) is the
  future `_PSS` lane's job.
- The HKEY dispatch → LED crate integration (0x60C0 decode to arm)
  is covered by platform decode tests plus hardware; the fixture
  smokes drive the shared handler directly.
