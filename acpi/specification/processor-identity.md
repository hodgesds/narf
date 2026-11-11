# Processor identity

## 1. Purpose & scope

Retain the firmware identities needed to assign CPU power states correctly.

## 2. Assumptions

MADT and FADT data pass the existing bounds and checksum validation.

## 3. Public interface

`apic_id_for_processor_uid(uid: u32) -> Option<u32>` resolves an enabled
processor's ACPI identity to its hardware APIC ID. Type-0 MADT entries supply
an 8-bit Processor ID; type-9 entries supply a 32-bit UID. Enumeration index,
APIC ID and UID are distinct. Missing or duplicate UIDs return `None`.
`FadtPm::cst_control` retains the FADT CST_CNT byte at offset 95; nonzero
requests an OS-control handshake through the validated SMI_CMD port.

## 4. Invariants

Unknown identities never fall back to namespace order or logical CPU number.
Reset clears both APIC IDs and UIDs. Parsing is a boot-time operation.

## 5. Architecture

Used for x86 ACPI CPU idle discovery; no new ARM topology interpretation.

## 6. Dependencies

Existing ACPI table discovery and atomic boot-time topology storage.

## 7. Stage assignment

Stage 5 CPU power management.

## 8. Open questions

Runtime CPU hot-add requires coordinated topology republication.
