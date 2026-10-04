# scmi — ARM System Control and Management Interface

`narf-scmi` is NARF's clean-room implementation of the control-plane side of
the ARM System Control and Management Interface (SCMI, ARM DEN 0056). SCMI is
the standardized message protocol by which an operating system asks platform
firmware — typically a dedicated system-control processor — to manage shared
platform resources it does not own directly. On ARM-style SoCs the OS does not
poke clock dividers or power-domain registers itself; it sends SCMI messages
and firmware carries them out. This crate is how the NARF kernel participates
in that conversation.

The crate owns the protocol abstractions, not the wire transport. It models
the three SCMI management domains the kernel cares about most: Clock
management (enumerate clocks, read and set rates, enable/disable), Power
Domain management (enumerate domains, read and set power state), and
Performance State management (enumerate performance domains, read and set
performance levels). Each is expressed as its own contract so a consumer can
hold authority over clocks without thereby controlling power domains. Attribute
records describe a clock, power domain, or performance domain to callers.

Transport is deliberately out of scope. The actual message carriage — SMC
calls, a mailbox, or a shared-memory region negotiated with firmware — lives
in separate transport drivers that implement these contracts. The crate
assumes firmware implements SCMI and that some transport is available; it
concerns itself only with the management semantics layered on top. Every
operation is asynchronous, because an SCMI round trip to firmware can take
arbitrary time and must not block the calling task; the contracts are built on
`async-trait` and driven by `narf-scheduler`.

Access is capability-gated. SCMI is its own capability kind (`CapKind::Scmi`),
so only a task holding the appropriate capability may change a clock rate,
power a domain up or down, or raise a performance level. This matters because
these are platform-wide, safety-relevant knobs: a bug that drops a shared power
domain can take out unrelated devices.

`narf-scmi` is `no_std` and `alloc`-backed, and depends on `narf-lib`,
`narf-scheduler`, and `narf-capabilities`. It provides its services to the
`power/` subsystem and to device drivers. The `kernel-test` feature compiles
in-kernel smokes that drive the clock, power-domain, and performance contracts
against a mock firmware and check the error and attribute shapes.

- Spec: [`specification/spec.md`](./specification/spec.md)

Stage: v0.1 (Stage 3 draft), per the crate specification.
