# Fuchsia FIDL — Typed IPC with Capability Passing

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

Fuchsia Interface Definition Language (FIDL) is a language and framework for defining type-safe interprocess communication (IPC) protocols. It abstracts the underlying transport mechanism while enforcing compile-time type checking and capability safety. This design is highly relevant to NARF's goal of passing capabilities, not pointers, across domain boundaries.

## Key Mechanisms

**FIDL Protocol Definition:**
- Protocols define a set of methods with typed parameters and return values
- Methods can be one-way (fire-and-forget) or two-way (request-response)
- Request/response pairs are matched by transaction IDs, allowing concurrent outstanding calls
- Protocols are versioned and support optional fields for future evolution

**Handle Passing:**
- Handles represent capabilities to kernel objects (channels, events, VMOs, etc.)
- Handles are opaque values from the userspace perspective; their semantics are enforced by the Zircon kernel
- Handles can be sent across IPC boundaries; the kernel performs transfer and validates recipient authority
- Rights can be restricted at the sender side (e.g., send a read-only handle instead of read-write)

**Type Safety:**
- FIDL compiler generates client/server stubs from interface definitions
- Code using these stubs is type-checked at compile time; only valid operations are permitted
- Serialization/deserialization is automatic and handles endianness, alignment, and validation
- Union types and variant discrimination are checked at runtime with clear error semantics

**Encoding and Validation:**
- FIDL uses a fixed, optimized wire format (not variable-length like protobuf)
- The kernel validates incoming messages before delivery (e.g., ensuring handles are valid, data is within bounds)
- Secondary validation occurs during deserialization; unrecognized values trigger clear errors
- Handles are transferred at the kernel level during message passing

## Critical Invariants

1. **Handle semantics are kernel-defined:** Userspace cannot manufacture, duplicate, or transfer handles outside kernel control
2. **Type matching at both ends:** If a receiver expects a handle of type X but gets type Y, the message is rejected
3. **One-way and two-way atomicity:** Transactions (request-response) are atomic; a reply arrives only if the request was fully processed
4. **Protocol state coherence:** If protocol methods have implicit dependencies (e.g., "must call Open before Read"), the application must enforce this; FIDL does not prevent protocol violations
5. **Message ordering:** Messages on a channel are delivered in order; causality is preserved

## Performance Trade-offs

**Typed RPC overhead:**
- Generating stubs adds binary size and minimal runtime overhead
- Type checking at compile time (not runtime) is nearly zero-cost
- Request-response with transaction IDs requires kernel bookkeeping for pairing replies

**Handle transfer cost:**
- Transferring a handle incurs kernel-side validation and capability accounting
- Rights restriction (e.g., copying a handle with fewer rights) is essentially free if the kernel supports it
- Bulk handle passing (many per message) adds overhead proportional to count

**Encoding efficiency:**
- Fixed wire format is more compact than variable-length encoding
- No serialization bloat for simple types, but padding may waste space in some cases
- Handles are small (typically 32-bit integers), so bulk passing is feasible

**Latency:**
- FIDL method calls are synchronous; the caller blocks until the response is received
- Zircon provides async channels and futures, enabling non-blocking patterns, but they require different API usage

## Pitfalls and Warnings

1. **Deserialization DoS:** If the kernel does minimal validation, a malformed message can trigger expensive validation on the receiving side (e.g., walking large arrays)
2. **Handle exhaustion:** Transfers that don't close old handles can exhaust the handle table
3. **Use-after-close races:** If a handle is closed before the last message using it is received, the message fails (synchronous RPC helps here, but async patterns require care)
4. **Type evolution risk:** Adding new optional fields or methods is forward-compatible, but removing them breaks old clients silently
5. **Covert channels via encoding:** Message size and timing can leak information; NARF must consider side-channel attacks in async designs
6. **Multi-threaded handle sharing:** If multiple threads share a channel, concurrent calls require explicit synchronization (FIDL does not provide mutual exclusion)

## Recommendations for NARF ABI Designers

**Adopt:**
- Language-based protocol definition with compile-time type checking
- Opaque handle passing instead of pointer passing
- Support for both synchronous (request-response) and asynchronous (one-way) calls
- Rights restriction capability for fine-grained authority delegation
- Automatic serialization/deserialization to reduce boilerplate and errors

**Avoid:**
- Untyped message passing; always use a schema language (FIDL or similar)
- Exposing capability objects as raw pointers in the ABI
- Mixing synchronous and asynchronous semantics without clear protocol versioning
- Implicit protocol state dependencies; make them explicit in the type system if possible

**Specific to NARF:**
- Integrate FIDL-style typed protocols with the async-first executor; consider whether request-response pairs block the executor or queue as futures
- Use PKS domain isolation to prevent unauthorized handle access; FIDL's kernel validation is a secondary check
- Combine Fuchsia's handle passing model with seL4-style rights restrictions for both safety and flexibility
- In zero-copy design, consider how handles to shared memory buffers are passed; ensure rights are checked consistently
- Add generation counters or epochs to handles to detect use-after-revocation without expensive kernel-side tracking
- Document covert channels explicitly; NARF's MTE-based memory tagging may leak information through handle transfer latency

<https://fuchsia.dev/fuchsia-src/reference/fidl>
