# Intel PCH GPIO / pinctrl — Stage-0 scaffold

Date: 2026-05-25. Companion to `drivers/gpio/src/intel_pch.rs`.

## What landed

`intel_pch` module in `drivers/gpio/src/`:

- ACPI HID list spanning Sunrise Point → Meteor Lake: `INT344B`,
  `INT3437`, `INT3450`, `INT3452`, `INT3454`, `INT3455`, `INT345D`,
  `INT34BB`, `INT34C5`, `INT34C8`, `INT34C9`, `INT37FF`. Union of
  Linux's per-SoC `pinctrl-<soc>.c` driver tables.
- Per matching device, decodes `_CRS` and collects every
  `Memory32Fixed` (and Memory32/AddressSpace32/64) item — one per
  *community* (Intel splits each block into 2..4 communities, each
  with its own MMIO window).
- Per community: reads `REVID` @ 0x000 (sanity-check; `~0u` =
  absent), `PADBAR` @ 0x00C (pad-config base), computes pad count
  from `(mmio_len - padbar) / stride`. Stride = 16 B for REVID
  >= 0x94 (DEBOUNCE → PADCFG0/1/2 + reserved), else 8 B.
- Registers one `IntelPchGpio` per community in the shared GPIO
  registry under `<acpi_path>.C<N>`, so i2c-hid-bind can resolve a
  `GpioInt::resource_source` referring to a PCH GPIO block.
- Hooked into `register_initcalls` at `Stage::Device` as
  `intel-pch-gpio`, alongside `amd-fch-gpio`.

Smokes cover: HID list guard, REVID/PADBAR decode with/without
DEBOUNCE, rejection of REVID=~0u and PADBAR-OOB, Stage-0
`GpioController` ops return `BadHardware`, distinct multi-community
naming, shared-registry insertion.

## Not in this stage

- No pad-register programming. `read_pin`, `set_pin`,
  `register_irq` return `BadHardware`; `unregister_irq` is a no-op.
- No GSI routing. Vector is decoded from `_CRS` and logged.

## Stage-1 follow-ups

1. PADCFG0/1/2 programming per the trait surface (Linux's
   `pinctrl-intel.c` is the reference).
2. Route GSI → IDT vector + shared ISR scanning `GPI_IS`.
3. Consume `CAPLIST` "GPIO Hardware Info" (decoder present,
   `#[allow(dead_code)]`).
4. Replace `i2c-hid-bind`'s AMD-titled diagnostics.

## No `aml` decoder work needed

Brief mentioned adding `GpioInt`/`GpioIo` to `aml/src/resource.rs`,
but both variants are already present + exercised by
`smoke_aml_resource_gpio_{int,io}_decode` — landed during AMD FCH
bring-up. Remaining gap was the Intel consumer side, which this
scaffold closes.
