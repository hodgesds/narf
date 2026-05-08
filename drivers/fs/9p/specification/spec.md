# Specification: 9P2000 Filesystem Driver

## 1. Purpose & scope

This driver provides a clean-room implementation of the 9P2000 protocol for NARF, primarily for host-to-guest file sharing (VirtIO-9P) and inter-domain communication.

- **Scope:** Full client-side implementation of 9P2000 (and 9P2000.u extensions), session management, fid/tag allocation, integration with NARF VFS.
- **Out of Scope:** Server-side implementation (in this driver), multi-user security (mapped to NARF domain-id instead).

## 2. Assumptions

- The transport layer (VirtIO-mmio, VirtIO-pci, or inter-domain ring) provides a reliable byte-stream or packet-oriented interface.
- One 9P session per mount point.

## 3. Public interface

The driver implements the `FileSystem` trait from `narf-filesystem`.

### Key Structs

- `P9FileSystem`: Root structure for a 9P mount.
- `P9Node`: VNode implementation mapping fids to VFS operations.
- `P9Session`: Stateful manager for message tagging and fid lifecycle.

## 4. Invariants

- **Tag Uniqueness:** Every pending T-message must have a unique 16-bit tag within the session.
- **Fid Lifecycle:** Every fid allocated via `attach` or `walk` must eventually be released via `clunk`.
- **Atomic Walk:** Multi-segment path traversal should ideally use a single `Twalk` message when supported.

## 5. Architecture notes

- **Async-First:** Each 9P transaction is an async future. The `P9Session` manages a completion registry for pending tags.
- **Serialization:** Messages are serialized directly into DMA-coherent buffers for zero-copy transport when possible.

## 6. Dependencies

- `narf-block` (if transport is block-like) or `narf-io` (general DMA/rings).
- `narf-filesystem`: For VFS integration.
- `narf-lib`: For base primitives.

## 7. Stage assignment

- **Stage 4:** Required for host-to-guest tool sharing and automated testing.

## 8. Open questions

- **Extension Level:** Should we target 9P2000.L immediately for best Linux tool compatibility? (Initial target: 9P2000.u).

## References

This implementation is derived solely from the following public documentation:

1. [Plan 9 Manual: Section 5 (9P Intro)](https://9p.io/magic/man2html/5/0intro)
2. [9P2000 Protocol Specification](https://ericvh.github.io/9p-rfc/9p2000.html)
3. [9P2000.u Extensions](https://ericvh.github.io/9p-rfc/9p2000.u.html)
