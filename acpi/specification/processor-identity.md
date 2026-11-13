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

Logical CPU ids are dense `0..cpu_count_from_madt()`: logical 0 is the boot
CPU (its CPUID APIC ID, `boot_cpu_apic_id_from_cpuid`), the other enabled
MADT processors follow in ascending APIC-ID order (Linux
`x86_cpu_to_apicid`). `apic_id_of_cpu(cpu) -> Option<u32>` is the APIC ID
every IPI, MSI, IOAPIC and NMI destination for logical CPU `cpu` uses;
`cpu_of_apic_id(apic) -> Option<usize>` is its inverse (the AP entry path
sets `IA32_TSC_AUX` from it). `apic_id_at(i)` is MADT firmware order and is
never a CPU-to-destination lookup. `cpu_node(cpu)` takes a logical id and
looks the SRAT up by that CPU's APIC ID. On a gap-free topology whose boot
CPU has the lowest APIC ID the map is the identity.

## 4. Invariants

Unknown identities never fall back to namespace order or logical CPU number.
Reset clears both APIC IDs and UIDs; it does not clear the logical CPU map,
which live interrupt delivery reads and only `parse_madt` rebuilds. Parsing
is a boot-time operation, on the boot CPU before any AP starts.

## 5. Architecture

Used for x86 ACPI CPU idle discovery; no new ARM topology interpretation.

## 6. Dependencies

Existing ACPI table discovery and atomic boot-time topology storage.

## 7. Stage assignment

Stage 5 CPU power management.

## 8. Open questions

Runtime CPU hot-add requires coordinated topology republication.
