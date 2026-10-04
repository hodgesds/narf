# drivers/tpm — TPM 2.0 Hardware Drivers

`drivers/tpm` is the hardware-facing side of NARF's TPM support: it
realizes the TPM 2.0 protocol over the two host interfaces real platforms
expose, and plumbs the resulting device into the kernel's filesystem so
userspace and other subsystems can reach it. Where the `tpm` protocol
crate owns the device-agnostic command model and capability policy, this
crate owns the register-level transports, the ACPI discovery, and the
TPM 2.0 wire codec itself.

Two transport flavors are implemented. **CRB** (Command/Response Buffer)
is the interface used by firmware TPMs on AMD and Intel platforms, with
ACPI device `MSFT0101`; it drives the control area's locality-acquisition
and command-run register sequence per the TCG PC Client Platform TPM
Profile. **TIS** (TPM Interface Specification) is the classic
MMIO/FIFO interface used by discrete LPC-attached chips from Infineon,
Nuvoton and others, per the TCG PC Client Platform TPM Interface Spec
1.3. Both are referenced against their Linux counterparts (`tpm_crb.c`
and `tpm_tis_core.c`) and both feed the shared TPM 2.0 command set. The
concrete bring-up targets are AMD fTPM 2.0 over CRB on Zen 2
(Renoir/Lucienne) and Zen 4 (Phoenix HawkPoint1).

Discovery is ACPI-driven. The probe path finds a CRB TPM either through
an ACPI device node declaring `_HID = MSFT0101` with its CRB MMIO
resource in `_CRS`, or through the fixed TPM2 ACPI table, whose
control-address and start-method fields point at the CRB control area and
name the interface. The TPM 2.0 command layer under `tpm2/` implements
the command/response wire format from the TCG TPM 2.0 Library
Specification (every frame sharing the 10-byte big-endian header), and is
further broken into command builders and response parsers, key and object
types (TPM2B_PUBLIC/PRIVATE, RSA and ECC P-256/P-384), the PCR allocation
and extension model, and NV-index management.

The driver also bridges the TPM into the VFS. A devfs bridge exposes
`/dev/tpm0` for raw access — serializing commands per open file
descriptor and allowing only one command in flight at a time, matching
Linux's `tpm-dev-common` semantics — and `/dev/tpmrm0` as a
resource-manager pass-through that additionally tracks transient object
handles and flushes them on close to prevent handle leaks across
concurrent users. A sysfs bridge surfaces device attributes. Operation is
polling-only today.

The crate is `no_std` with `alloc`, and depends on `narf-lib`,
`narf-filesystem`, and `narf-block` for the VFS bridges. The
`kernel-test` feature compiles the unit and end-to-end tests. Deferred
work includes TPM 1.2 compatibility, EK/AK provisioning, the TSS2
userspace daemon protocol, dynamic root-of-trust measurement, and
interrupt-driven operation.
