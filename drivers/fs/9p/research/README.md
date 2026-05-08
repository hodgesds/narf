# Research: 9P2000 Protocol

Clean-room implementation references for the 9P2000 network filesystem protocol.

## Primary Sources

1. **Plan 9 Manual: Section 5 (Introduction to 9P)**
   - URL: https://9p.io/magic/man2html/5/0intro
   - Role: Definitive conceptual introduction to 9P concepts: tags, fids, and messages.

2. **9P2000 Protocol Draft (RFC-style)**
   - URL: https://ericvh.github.io/9p-rfc/9p2000.html
   - Role: Detailed wire-format specification for all T-messages and R-messages.

3. **Plan 9 Manual: Section 5 (Full Message List)**
   - URL: https://9p.io/magic/man2html/5/
   - Role: Reference for specific message semantics (version, attach, walk, open, read, write, clunk, etc.).

## Protocol Variants & Extensions

- **9P2000.u (Unix Extensions)**
  - URL: https://ericvh.github.io/9p-rfc/9p2000.u.html
  - Role: Support for Unix-style special files (symlinks, devices) and numeric IDs.

- **9P2000.L (Linux Extensions)**
  - Role: Further enhancements for Linux VFS compatibility.

## Summaries

- [summaries/message-wire-format.md](summaries/message-wire-format.md) - Analysis of the 9P binary message envelope and common fields.
