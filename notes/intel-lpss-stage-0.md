# Intel LPSS I2C — Stage-0 scaffold + audit

Date: 2026-05-25. Companion to `drivers/i2c/src/lpss.rs`.

## What landed in Stage-0

A new `lpss` module in `drivers/i2c/src/` that:

- Carries the ACPI HID list for modern Intel LPSS I2C controllers
  (Tiger Lake / Alder Lake / Raptor Lake: `INT34B7`, `INT34BA`,
  `INT34C5`), the Skylake / Kaby Lake (`INT3446`, `INT3447`),
  Haswell / Broadwell (`INT33C2..3`, `INT3432..3`), Lakefield /
  Jasper Lake (`INTC1009`, `INTC1010`), and older PCI-mode LPSS
  (`80860F41` Baytrail, `808622C1` Apollo Lake).
- Walks every device matching one of those HIDs, decodes `_CRS`
  (Memory32Fixed / Memory32 / AddressSpace32+64 / ExtendedIrq —
  same shape as the AMD FCH variant), reads `IC_COMP_TYPE`
  (0xfc) for the DesignWare magic (0x44570140), and registers an
  `I2cBus` whose `transfer()` is a stub returning `BadHardware`.
- Hooks the new probe into `register_initcalls` at `Stage::Device`
  as `lpss-i2c`, alongside `amd-fch-i2c`. Either successful probe
  installs the GenericSerialBus dispatcher.

Smokes: HID list guard, COMP_TYPE accept/reject, stub returns
BadHardware, shared-registry insertion.

## Why no real transactions

Stage-0 scope. The LPSS wrapper adds a private register page at
offset 0x200 holding chip-specific clock-gating and reset bits;
the DW core can read 0x0 from IC_COMP_TYPE if those are wrong.
Doing the gating sequence without real hardware to validate
invites a silently-broken driver. When Stage-1 lands the
`transfer()` stub is replaced wholesale — hard cutover, no
compat shim per project policy.

## AMD-only assumptions still in the tree (fix scope outside this skeleton)

1. `aml/src/lib.rs`: `BOOT_AMDI001X_COUNT` / `boot_amdi001x_count()`
   and `dump_amd_i2c_subtree` filter on `AMDI*` / `AMD0*` prefixes
   only. **Fix**: extend to also count `INT3xxx` / `80860Fxx` /
   `808622xx` LPSS HIDs, and rename the surface (`boot_i2c_count`,
   `dump_i2c_subtree`) so the panel telemetry isn't AMD-titled.
2. `fb/src/status.rs:147`: status line reads `AML: N nodes
   AMDI001x: M (children: K) PNP0C50: L`. **Fix**: pair AMDI001x
   with an LPSS count once aml exposes one; relabel to
   `I2C-ctrl:` rather than `AMDI001x:`.
3. `drivers/input/src/i2c_hid_bind.rs:110-123`: diagnostic dump
   prints `AMDI=`/`subtree dump` and calls `dump_amd_i2c_subtree`.
   **Fix**: replace with the renamed AML helper. The bind path
   itself (CRS decode → registry lookup) is already backend-
   agnostic via the shared registry, so Intel touchpads will be
   discovered correctly once `lpss-i2c` registers a bus.
4. `drivers/gpio/src/amd_fch.rs`: GPIO controller driver matches
   only `AMDI0030`. Intel PCH GPIO uses different HIDs
   (`INT34BB`, `INT3450`, `INT3451`, etc.). **Fix**: parallel
   Stage-0 for an `intel_pinctrl` driver. Out of scope here —
   the Intel touchpad i2c-hid path needs GPIO only for the
   attention-line IRQ, and Linux's i2c-hid-acpi runs fine
   without it (pump task polls when no GPIO IRQ is wired).

Items 1-3 are cosmetic / telemetry until Stage-1 lands real
transactions; item 4 is the only one that meaningfully affects
the i2c-hid pump's responsiveness on Intel laptops.
