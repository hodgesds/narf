# aml — ACPI Machine Language Namespace Builder and Evaluator

`narf-aml` reads the ACPI Machine Language (AML) bytecode carried in the
DSDT and SSDT tables and turns it into a usable picture of the platform.
AML is the language firmware uses to describe control-method devices,
power resources, thermal zones, embedded controllers, and the methods
that operate them. A production-grade interpreter (ACPICA, uACPI) runs to
tens of thousands of lines because it must evaluate arbitrary methods,
drive OpRegions over SystemMemory / SystemIO / PCI config space, mediate
mutexes and events, and dispatch general-purpose events (GPEs). This
crate implements a focused, growing subset of ACPI 6.5 §20 rather than
the whole thing.

The foundation is a namespace builder: a parser that walks the AML byte
stream and materializes the tree of declared objects — Scope, Device,
Processor, Method, Name, Mutex, PowerResource, ThermalZone. Method bodies
are skipped over by their PkgLength and recorded as offset/length spans
so a later pass can interpret them; flat-constant `Name(...)` values
(byte, dword, qword, string literals) are resolved eagerly so callers can
read identifiers like `_HID`, `_UID`, `_ADR`, and `_BBN` straight out of
the namespace. This alone answers the shape questions the scheduler and
observability layers ask — how many devices the platform declares, and
what each one is.

Layered on top is a method evaluator that executes the opcode subset
needed for the methods the boot path actually calls — `_STA`, `_PIC`,
`_OSC`, `_CRS`, `_PRT`, and common math and logic patterns. Supporting
this are OpRegion and Field accessors (storage and read access for
firmware-declared regions), a Mutex/Event/Notify runtime, and GPE block
discovery that scans for `\_GPE._Lxx` / `_Exx` handlers and dispatches
either the AML method or a registered native handler.

A substantial part of the crate is the set of real platform drivers that
AML enables. The Embedded Controller (EC) driver implements the ACPI 6.5
§12 interface — the laptop microcontroller that arbitrates battery, AC,
thermal, fan, lid, and hotkey access through a 256-byte address space
accessed via `EmbeddedControl` OpRegions — together with `_Qxx` query
event dispatch. The WMI mapper exposes the vendor extension surface
(`PNP0C14`, `_WDG`) that OEMs use for hotkeys and fan profiles. Resource
and PCI-routing decoders turn `_CRS` and `_PRT` results into structured
descriptors, and a boot-time INTx-to-GSI routing table is built from them
for the interrupt-controller and PCI bind paths. The lid and power/sleep
button modules model the fixed-hardware input events.

This crate is `no_std`. It builds directly on `narf-acpi` for table
discovery and headers, and ties into `narf-scheduler`, `narf-time`,
`narf-capabilities`, `narf-event-bus`, `narf-console`, and `narf-memory`
to run methods and deliver firmware events into the live kernel.
