# IOAPIC routing

## 1. Purpose and scope

MADT-backed x86 interrupt redirection and inspection for device drivers.

## 2. Assumptions

MADT is validated and the IOAPIC MMIO windows are live before use.

## 3. Public interface

`unsafe gsi_route(gsi: u32) -> Option<(u8, u8, u32)>` reads an existing
redirection entry and returns its vector, physical destination APIC ID and raw
low dword. It returns `None` outside the enumerated IOAPIC ranges. Callers must
check delivery/destination mode, polarity, trigger and mask before sharing it.
It does not allocate a vector or grant ownership of an existing route.

`route_gsi_to_vector` programs a route. `program_entry` and `mask` operate on
an explicitly probed `IoApicHandle`.

`unsafe set_gsi_masked(gsi: u32, masked: bool) -> bool` sets or clears only
the mask bit of the MADT entry owning `gsi` (vector, destination, polarity and
trigger unchanged); `false` outside every range. It takes the IRQ-safe
`IOAPIC_LOCK` and allocates nothing, so a hard-IRQ handler may call it. A
masked level line stays asserted at the pin; after the local-APIC EOI retires
Remote IRR, unmasking a still-asserted line delivers it again (the
`interrupts::oneshot` contract).

## 4. Invariants

The global IOAPIC lock serializes selector/window access. Inspection never
modifies a redirection entry. Driver setup/teardown must preserve other handlers
on a shared line; inspection and later programming require external ownership
serialization if callers can race.

## 5. Architecture

x86_64 only; aarch64 uses GIC/ITS.

## 6. Dependencies

ACPI MADT, MMIO mappings, IRQ-safe locks and interrupt dispatch.

## 7. Stage assignment

Stage 5 native device interrupt routing.

## 8. Open questions

General reference-counted shared-GSI allocation remains a platform concern.
