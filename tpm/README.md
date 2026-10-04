# tpm — TPM 2.0 Protocol Subsystem

`tpm` is the high-level Trusted Platform Module subsystem for NARF. It is
a *protocol and policy* crate, not a hardware driver: it owns the
device-agnostic TPM 2.0 command/response model, the capability type that
gates TPM access, and the PCR-selection and policy vocabulary that the
rest of the kernel uses. The concrete MMIO transports — the CRB and TIS
host interfaces — live in `drivers/tpm`, and the cryptographic primitives
(SHA-256, HMAC) are consumed from the `crypto` crate rather than
reimplemented here. The implementation is clean-room, following the
public TCG TPM 2.0 Library Specification without consulting non-free or
GPL-licensed stacks such as IBM's TSS or Linux's `tpm2-tss`.

The crate centers on a device abstraction that every backend implements:
submitting raw TPM 2.0 command buffers and the high-level operations
layered on top of them — hardware random generation, PCR extension, and
PCR reads. Because real TPM operations take milliseconds, the interface
is async-first, scheduled through `narf-scheduler`. A small registry
tracks the TPM devices present on the system so other subsystems can
discover them.

Internally the crate is organized around the TPM 2.0 wire format. One
module builds command frames and parses responses (every command and
response sharing the TCG 10-byte big-endian header of tag, size, and
command/response code); another encodes the specific TPM 2.0 opcodes —
Startup, GetRandom, GetCapability, PCR_Read, PCR_Extend and friends — and
decodes their payloads. A types module defines the PCR-set bitmask, the
policy-hash newtype, the error enum, and the categorization of TPM return
codes into the typed VER1 and FMT1 families from TCG Part 2. A CRB helper
module models the locality-acquisition and command-run register dance at
a level the hardware driver can reuse and test against a mock.

Access is governed by NARF's capability model rather than being globally
available. A dedicated TPM capability kind, with rights such as extending
a specific set of PCRs, unsealing data bound to a given policy, reading
PCRs, clearing the TPM, or full administrative control, lets the kernel
grant a domain exactly the TPM authority it needs — for example a disk
driver restricted to the secure-boot PCRs — in keeping with least
privilege.

The crate is `no_std` with `alloc`. It depends on `narf-capabilities`
for the TPM cap kind, `narf-crypto` for digests, and `narf-scheduler` for
async execution. The `kernel-test` feature compiles the in-kernel smoke
tests, which exercise the wire codecs and the CRB register sequencing
against mock backends.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: Stage 4 design draft (v0.1)
