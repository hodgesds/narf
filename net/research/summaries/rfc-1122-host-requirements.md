# RFC 1122: Host Requirements (Internet Host Communication Layers)

## Overview

RFC 1122 defines requirements for Internet hosts across three protocol layers: link, Internet (IP), and transport (TCP/UDP). For NARF as a Rust microkernel targeting networked systems, this document establishes foundational interoperability constraints that shape subsystem design.

## Core Mechanisms

**Layered Protocol Processing:** The RFC emphasizes strict layering with intentional violations—upper layers must access lower-layer information (IP options passed to transport). For NARF, this suggests shared data structures between IP and transport layers rather than strict procedure calls, enabling zero-copy IPC between domain boundaries.

**Robustness Principle:** "Be liberal in what you accept, and conservative in what you send." For NARF, capability domains handling network I/O must validate every received packet (checksum verification, address validation, option length bounds) while constraining outgoing traffic to standard formats. Malformed packets must be silently discarded with optional logging—critical for preventing broadcast storms.

**Fragmentation and Reassembly:** The Internet model "requires that every host support reassembly." NARF must allocate bounded buffers for fragment reassembly with protection against infinite loops from erroneous option lengths—a vulnerability if the network domain doesn't validate option headers before exposing them to application domains via IPC.

## Key Invariants

**Source Address Validation:** "When a host sends any datagram, the IP source address MUST be one of its own IP addresses." In NARF's capability model, only the network domain holding valid source addresses should construct or modify IP headers. Other domains receive immutable packet handles without address modification rights.

**Multihoming Complexity:** "Multihoming introduces considerable confusion and complexity." For NARF, this translates to careful capability separation: each logical network interface (distinct by IP address) maps to distinct capability tokens. A transport-layer domain cannot bypass routing decisions by claiming multiple source addresses.

**Gateway Function Control:** "An Internet host that includes embedded gateway code MUST have a configuration switch to disable the gateway function, and this switch MUST default to the non-gateway mode." NARF domains forward-declaring gateway capabilities require explicit caps; the default kernel must not auto-enable forwarding on multi-interface hosts.

## Performance Trade-offs

**ARP Caching:** The RFC recommends timeout-based ARP cache invalidation on the order of minutes. NARF could use event-driven invalidation through capability revocation: when a link-layer address changes, the network domain revokes cached capability tokens. This eliminates polling overhead but requires tighter capability lifecycle management.

**Packet Queuing at ARP Resolution:** The standard "SHOULD save (rather than discard) at least one (the latest) packet of each set of packets destined to the same unresolved IP address." NARF could implement this via a bounded async queue with backpressure: when ARP resolution completes, return exactly one retry capability, preventing duplicate transmission queues.

**TOS Field Propagation:** The RFC requires the transport layer set ToS on outgoing datagrams and receive ToS values on incoming packets. NARF should embed ToS in packet capability tokens as metadata, allowing QoS domains to inspect and apply scheduling policies without reparsing headers.

## Pitfalls and Adoption Guidance

**Silent Discard Semantics:** The RFC permits silent discard of malformed packets to prevent broadcast storms. However, NARF must ensure logging capability is available to diagnostic domains; missed logs hide systematic failures. Implement capability-gated logging without default performance penalty.

**Configuration Complexity:** The RFC acknowledges configurability is needed for administrative requirements and coexistence with legacy implementations. For NARF, avoid embedding configuration defaults in the kernel; instead, provide a capability-based configuration domain that injects parameters at boot via sealed capabilities.

**Option Processing Risk:** Unvalidated IP options have caused infinite loops in naive implementations. NARF's network domain must bound option parsing iterations and reject malformed option lists before passing to transport domains. Use a capability-safe options iterator that fails closed on invalid lengths.

**Ethernet Encapsulation:** RFC 1122 requires supporting RFC 894 (Ethernet) encapsulation with optional RFC 1042 (802.3) support and configurable preference. For NARF, model each encapsulation format as a distinct capability domain; allow capability-based selection rather than configuration files.

## NARF-Specific Recommendations

- **Capability-per-Interface:** Map each connected network to a distinct capability group; prevent cross-interface spoofing.
- **Async Executor Alignment:** Use async task boundaries at layer transitions (link→IP, IP→transport); RFC 1122's "procedure call" model maps naturally to async/await with zero-copy IPC.
- **MTU and Routing:** Cache MTU values per route using sealed capabilities; avoid global mutable routing tables prone to TOCTOU races.
- **Error Logging:** Implement a high-watermark circular buffer in the network domain; grant diagnostic domains selective read capabilities.

## Reference
- RFC 1122: "Requirements for Internet Hosts – Communication Layers"
- https://datatracker.ietf.org/doc/html/rfc1122
