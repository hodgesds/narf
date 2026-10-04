# spdm — SPDM Device Attestation Protocol

`spdm` implements SPDM — the DMTF Security Protocol and Data Model
(DSP0274) — at version 1.2, giving NARF a way to authenticate peripheral
devices and collect their firmware measurements. Like `tpm`, this is a
*protocol* crate rather than a hardware driver: it drives the SPDM
message exchange over a transport the bus drivers supply, and does not
own the transport itself. Physical delivery — PCIe DOE, MCTP, and the
like — is the responsibility of the bus layer; this crate assumes the
transport provides reliable delivery of SPDM messages. The implementation
is clean-room from public DMTF references, with no GPL Linux source
consulted.

The heart of the crate is a session driver that walks the SPDM
attestation handshake against an attestation device: GET_VERSION to
negotiate the protocol version (SPDM sends GET_VERSION pinned to 1.0 per
the spec, then settles on 1.2), GET_CAPABILITIES to discover which
features — measurements, certificates — the device supports,
NEGOTIATE_ALGORITHMS to agree on cryptographic algorithms such as
ECDSA-P384 and SHA-384, GET_CERTIFICATE to retrieve the device
certificate chain, CHALLENGE to prove freshness with a nonce, and
GET_MEASUREMENTS to collect the device's measurement blocks. A device
abstraction expresses the raw send/receive primitive each backend
provides, and a registry tracks the attestation-capable devices present
on the system.

Internally the crate splits into a message module (the 4-byte SPDM header
and the request/response/error code enums, encoded with little-endian
payload fields) and a handshake module (the per-message builders and
response parsers). The purpose of attestation is to fold peripheral
firmware state into the platform's trust chain: measurements gathered
over SPDM are meant to be extended into the system TPM — typically PCR 17
or 18 — so the boot chain accounts for device firmware as well as host
firmware. Access is gated through NARF's capability model via a dedicated
SPDM capability kind.

The crate is `no_std` with `alloc`. It depends on `narf-capabilities`
for the SPDM cap kind, `narf-tpm` for measurement extension and for its
shared error type, and `narf-scheduler` for async execution. The
`kernel-test` feature compiles the in-kernel smoke tests, which exercise
the full session flow against a mock device and round-trip every
handshake and message codec.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: Initial implementation (v0.1)
