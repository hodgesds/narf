# firmware/smbios — SMBIOS / DMI Table Parser

`narf-firmware-smbios` locates and decodes the System Management BIOS
(SMBIOS, also called DMI) tables that firmware publishes to describe the
machine's hardware inventory — BIOS version, system and baseboard
identity, chassis, processors, and memory devices. The kernel uses this
inventory for identification, logging, and platform-quirk decisions.
The parser is a clean-room implementation of the DMTF SMBIOS Reference
Specification v3.x (DSP0134); no GPL Linux source was consulted.

Finding the tables is a two-part job. The crate decodes both entry-point
anchor formats — the legacy 32-bit `_SM_` anchor and the modern 64-bit
`_SM3_` anchor — validating their checksums before trusting the pointers
they carry, because firmware is known to leave stale anchors lying around
in the BIOS region. It offers two discovery paths: an x86_64-only scan of
the legacy BIOS region (`0x000F_0000`–`0x000F_FFFF`) on 16-byte
boundaries, and a pure-data decode of an entry point handed in as bytes
(for example, the anchor QEMU exposes through `fw_cfg`). The caller
chooses whichever path matches the platform, obtains the structure
stream, and hands the parser a slice.

Given the structure stream, the parser walks the chain of fixed-size
records, each followed by its NUL-separated string pool, until it reaches
the Type-127 end-of-table marker. Every SMBIOS 3.x structure type is
accounted for: the most useful ones — BIOS, System, Baseboard, Chassis,
Processor, Cache, memory arrays and devices, and dozens more — are fully
decoded into typed structures, while types the kernel does not yet
consume (and the SMBIOS-3-deprecated types 5/6/10) are still length-
walked so the parser stays in sync with the stream. The decoded output is
held in static tables guarded by an IRQ-safe spinlock, so parsing can run
from any pre-userspace context.

This crate is `no_std`. It depends on `narf-memory` for physical-memory
access during the legacy anchor scan and `narf-lib` for the locking
primitives guarding the decoded tables.

- Spec: [`specification/spec.md`](./specification/spec.md)
