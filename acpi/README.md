# acpi — ACPI Table Discovery and Platform Device Models

`narf-acpi` is the kernel's entry point into the Advanced Configuration
and Power Interface (ACPI). Firmware publishes a set of in-memory tables
describing the machine's topology, interrupt routing, and power
management; this crate finds those tables, validates them, and turns the
raw firmware bytes into structures the rest of the kernel can trust.

Discovery starts from the Root System Description Pointer (RSDP), which
the bootloader hands over on x86_64 / PVH through the boot-info block.
The crate validates the RSDP checksum, then walks the Extended System
Description Table (XSDT) — the array of physical pointers to every other
ACPI table. All reads are bounds-checked against each table's advertised
length and performed unaligned, because ACPI tables pack fields without
regard for natural alignment and malformed firmware must never be able
to push a read past a table's end.

The primary table consumed today is the System Resource Affinity Table
(SRAT), which describes NUMA topology: which CPUs and which physical
memory ranges belong to which proximity domain. The crate materializes
this into CPU-to-node and memory-range-to-node maps that the scheduler
and memory allocator consult for NUMA-aware placement and work-stealing
decisions. A generic XSDT walker is exposed so narrower consumers (MADT,
MCFG) can grow alongside the drivers that need them rather than bloating
this crate. The IOAPIC submodule provides the clean-room programming
primitives and MADT-derived discovery (interrupt source overrides, SCI
routing) for the x86 interrupt controller.

Beyond raw table parsing, the crate carries the state models for the
standard ACPI platform devices whose dynamic behavior is driven by AML
methods and firmware notifications: the AC adapter (`_PSR`), smart
batteries (`_BIF` / `_BST`), control-method and legacy fans, the laptop
lid switch (`_LID`), and the fixed-feature power and sleep buttons. These
models hold the decoded device state; the AML interpreter in the `aml`
crate routes firmware `Notify` events into them. An SMBIOS/DMI decoder is
also included for the structure types most useful at boot.

Deliberately out of scope here: the AML bytecode interpreter itself
(that is the `aml` crate), and heterogeneous-memory tables (HMAT / PMTT).

This crate is `no_std`. It builds on `narf-memory` for physical-address
handling, `narf-arch` for architecture glue, and `narf-lib` for the
per-CPU and locking primitives that guard the shared topology tables.
