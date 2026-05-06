# narf-spdm — Specification

> Status: **v0.1** (Initial implementation). Clean-room SPDM 1.2
> attestation for device discovery and measurement extension.

## 1. Purpose & scope

**Owns:** SPDM (Security Protocol and Data Model) session management,
device attestation, and measurement collection.

**Does NOT own:** Hardware-specific transport (PCIe DOE, MCTP), which
is handled by the bus drivers.

## 2. Assumptions

- Transport layers (e.g., PCIe DOE) provide reliable delivery of
  SPDM messages.
- Measurement extension targets the system TPM for PCR extension.

## 3. Public interface

```rust
pub trait AttestationDevice {
    /// Discovers SPDM capabilities of the device.
    async fn discover(&self) -> Result<SpdmCaps, SpdmError>;

    /// Requests measurements from the device.
    async fn get_measurements(&self) -> Result<Vec<Measurement>, SpdmError>;

    /// Extends measurements to the system TPM.
    async fn extend_to_tpm(&self, tpm: &Cap<Tpm, Invoke>) -> Result<(), SpdmError>;
}
```

## 4. SPDM 1.2 Attestation Flow

1. **GET_VERSION**: Negotiate the SPDM version (1.2 required).
2. **GET_CAPABILITIES**: Discover supported features (measurements,
   certificates, etc.).
3. **NEGOTIATE_ALGORITHMS**: Agree on cryptographic algorithms.
4. **GET_MEASUREMENTS**: Retrieve device measurements and optionally
   the measurement signature.

## 5. Measurement Extension to TPM

Measurements collected via SPDM are extended to the system TPM to
ensure the boot chain includes all peripheral firmware states. Typically,
these are extended into PCR 17 or 18.

## 6. Dependencies

- `narf-capabilities`: For `Spdm` CapKind.
- `narf-tpm`: For measurement extension.
- `narf-scheduler`: For async execution.

## 7. Sources (public only)

All code in this crate is derived strictly from the references below.
**No GPL Linux source consulted.**

- **DMTF DSP0274 "Security Protocol and Data Model (SPDM)
  Specification, Version 1.3"** (Apr 2023). Public DMTF document.
  §10.3 (Message Header layout — SPDMVersion / RequestResponseCode
  / Param1 / Param2). §10.4 (GET_VERSION / VERSION). §10.5
  (GET_CAPABILITIES / CAPABILITIES — added DataTransferSize +
  MaxSPDMmsgSize fields in 1.2). §10.6 (NEGOTIATE_ALGORITHMS /
  ALGORITHMS — Base Asym + Hash bitmasks). §10.7 (GET_DIGESTS /
  DIGESTS). §10.8 (GET_CERTIFICATE / CERTIFICATE — slot id +
  offset + length operands). §10.9 (CHALLENGE / CHALLENGE_AUTH —
  32-byte nonce, measurement-summary-hash type byte).
- **DMTF DSP0274 v1.2** — referenced for the original Param1
  encoding before 1.3 added new fields.

## 8. Handshake submodule (`handshake`)

`handshake/` is a clean-room codec for the message framing of GET_*
requests and their responses. The crate's existing `messages/`
module already covered GET_VERSION + GET_CAPABILITIES +
GET_MEASUREMENTS (the minimum the v0.x driver used). `handshake/`
fills in the remaining mandatory commands and surfaces the version
+ capability + algorithm constants the responder negotiates against.
