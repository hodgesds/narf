# narf-drivers-fs-9p

Clean room 9P2000 protocol driver for NARF.

## Features

- **9P2000.u Support**: Implements the core 9P2000 protocol with Unix extensions for special files.
- **Async-First**: Fully non-blocking transaction manager integrated with NARF's async VFS.
- **Transport Agnostic**: Operates over a generic `P9Transport` trait (VirtIO-9P, inter-domain, etc.).
- **Complete Object Lifecycle**: Supports `read`, `write`, `lookup`, `stat`, and session management.

## Status: Stage 4 (In Progress)

- [x] Message Serialization/Deserialization
- [x] Session & Fid Management
- [x] Async Transaction Manager
- [x] Path Traversal (Twalk)
- [x] File Access (Tread/Twrite)
- [x] Metadata Retrieval (Tstat)
- [ ] Object Creation (Tcreate)
- [ ] Object Removal (Tremove)

## References

- [Plan 9 Manual: Section 5 (9P Intro)](https://9p.io/magic/man2html/5/0intro)
- [9P2000 Protocol Specification](https://ericvh.github.io/9p-rfc/9p2000.html)
- [9P2000.u Extensions](https://ericvh.github.io/9p-rfc/9p2000.u.html)
