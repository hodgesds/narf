# firmware — Kernel Firmware Blob Registry

`narf-firmware` owns the kernel's firmware-blob registry: a name-indexed
store of the vendor firmware images that drivers must hand to their
silicon at probe time (Qualcomm AMSS images, Intel iwlwifi microcode, AMD
ACP topology blobs, and so on). It solves a cross-cutting problem that
would otherwise be re-implemented badly in every driver — finding the
right blob, applying fallback policy, caching it, verifying its
signature, and keeping its bytes resident only while a driver needs them.

Drivers never reach into the filesystem for firmware. Instead they fetch
a blob through a capability-gated lookup that returns a read-only handle,
`Cap<FirmwareBlob, Read>`, whose bytes live in DMA-coherent memory and
carry the physical address the device-side loader expects. The registry
authority is itself a capability: a read handle permits lookups, while a
write handle additionally permits installing or replacing blobs at
runtime. This keeps firmware access auditable and revocable, and it means
a blob's backing pages are reclaimed — after an RCU grace period — once
the last cap referencing it is dropped.

Blobs are populated from three sources, consulted in priority order:
an in-tree fallback registered at boot, an initramfs unpack written in
during the late boot stage, and highest-priority hot-installs pushed by a
privileged userspace daemon through the write-capability surface. This
mirrors the Linux hybrid model — initramfs carries only the blobs needed
before the root filesystem mounts, and everything else comes from the
root partition. Name resolution rejects empty, absolute, or `..`-bearing
names so a driver can never escape the firmware namespace.

Every blob is verified before it is handed out. Signature checking uses
`narf-crypto` against a set of trusted Ed25519 signer keys embedded at
build time and registered before discovery runs; a blob trailer carries
the signature, signer fingerprint, and optional version metadata, and the
crate records a BLAKE3 digest of each blob in the bound-driver inventory
so kernel snapshots can correlate driver behavior with firmware version.

The registry does not own the device-side loader protocol (BHI, SBL,
iwlwifi's microcode phases, ACP `RI_LOAD`) — each driver owns the
hand-off its silicon understands, and this crate only supplies bytes plus
a physical address. It also leaves filesystem decisions to
`narf-filesystem` and DMA-coherent allocation to `narf-io`.

This crate is `no_std`. It depends on `narf-capabilities` for the cap
surface, `narf-crypto` for signature verification, `narf-io` for the
DMA-coherent backing memory, `narf-rcu` for safe reclaim, and
`narf-filesystem` / `narf-initramfs` / `narf-init` / `narf-scheduler` for
discovery and boot wiring. The `firmware-allow-unsigned` feature accepts
the all-zero developer sentinel signature for developer and CI builds —
every hand-out of an unsigned blob emits a warning — and is left off in
production so the registry rejects anything unsigned.

- Spec: [`specification/spec.md`](./specification/spec.md)
