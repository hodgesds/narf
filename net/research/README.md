# net — Research

## Primary sources

- **IEEE 802.3 (Ethernet) / 802.1Q (VLAN) / 802.11** — frame formats.
- **RFC 1122 — Host requirements** — what a stack must implement.
  <https://datatracker.ietf.org/doc/html/rfc1122>
- **RFC 9293 — TCP** (supersedes 793 and many updates).
- **Linux `af_xdp` + XDP docs** — zero-copy kernel-userspace frame path.
  <https://docs.kernel.org/networking/af_xdp.html>
- **io_uring networking ops** — precedent for async-first network I/O.

## Secondary sources

- **smoltcp** — `no_std` Rust TCP/IP stack; candidate userspace stack
  and library baseline. <https://github.com/smoltcp-rs/smoltcp>
- **DPDK + VPP** — userspace packet processing frameworks.
- **Fuchsia Netstack3 (Rust)** — modern capability-oriented stack,
  closest philosophical sibling to what a NARF userspace stack would
  look like. <https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0168_netstack3>
- **seL4 + LwIP userland driver** — precedent for "stack outside the kernel."
- **Snabb** — Lua-based userspace networking; interesting offload ideas.

## Distilled summaries

- `summaries/rfc-1122-host-requirements.md` — RFC 1122, layering, source validation, ARP
- `summaries/rfc-9293-tcp.md` — TCP sequence numbers, state machines, congestion control
- `summaries/af-xdp-zero-copy.md` — AF_XDP rings, UMEM, queue binding, zero-copy packet path
- `summaries/smoltcp-rs.md` — Smoltcp, zero-allocation design, event-driven processing
- `summaries/fuchsia-netstack3.md` — Netstack3, capability-based networking, async task integration

## Open research questions

- smoltcp vs. Netstack3 vs. custom as the reference userspace stack.
- How to wire XDP-equivalent declarative filters without introducing
  a probe-site VM (same concern as `tracing/`).
- Timestamp accuracy: hardware PTP timestamps vs. `time/` monotonic;
  plumbing the difference to consumers.
