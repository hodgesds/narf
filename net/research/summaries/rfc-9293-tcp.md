# RFC 9293: Transmission Control Protocol (TCP)

## Overview

RFC 9293 supersedes RFCs 793 and multiple updates, defining the complete TCP protocol specification. For NARF's networking subsystem, TCP provides "reliable, in-order, byte-stream service"—but this creates tension with microkernel efficiency constraints and zero-copy IPC architecture.

## Core Mechanisms

**Sequence Number Management:** TCP uses modulo-2³² arithmetic for sequence space. Each connection (TCB) maintains send/receive windows as distinct resources. Rather than kernel-managed buffers, NARF should leverage capabilities to grant peers direct access to ring buffers for receive windows, with the TCP layer validating sequence numbers before granting access tokens. This preserves TCP's ordering invariant while enabling zero-copy reception.

**State Machine Integrity:** The protocol specifies eleven connection states. NARF's PKS/MTE domains should isolate state transitions—each domain transition validates state preconditions before permitting segment processing. For instance, transitions from SYN-RECEIVED require tracking whether the initial OPEN was passive or active; domain entry points can enforce this invariant through capability parameters.

**Checksum Validation:** The specification mandates that "the sender MUST generate it" and "the receiver MUST check it." Checksum computation involves accessing both TCP headers and pseudo-headers (derived from IP layer data). Async executors must serialize this access atomically—use dedicated checksum-verification domains that accept sealed capabilities over pseudo-header fields.

## Key Invariants

**Window Size Semantics:** Treat window sizes as unsigned values to prevent negative-window confusion. NARF should encode window state as sealed capabilities with numeric bounds—the async executor cannot reinterpret them as signed without domain-crossing verification.

**MSS Option Constraints:** TCP requires implementations to handle Maximum Segment Size (default 536 bytes for IPv4, 1220 for IPv6). NARF should pre-allocate receive buffers at connection establishment matching negotiated MSS, preventing dynamic allocation during data-path processing. Capabilities encode buffer bounds; segment acceptance domains verify SEG.LEN against capability size.

**Congestion Control Mandates:** The protocol requires congestion control algorithms but leaves implementation details flexible. NARF's async executor can employ lightweight per-connection congestion state without buffering entire send queues.

## Performance Trade-offs

**Congestion Control vs. Latency:** NARF trades buffering for latency by avoiding kernel-managed queues. Congestion control logic becomes per-domain, with explicit capability-based scheduling feedback.

**Nagle Algorithm Overhead:** The specification discusses the Nagle algorithm for batching small sends. NARF should make this optional per-connection via capability parameters, avoiding syscalls for time-sensitive protocols while enabling it for batch workloads.

**Retransmission Queue Management:** Rather than kernel-managed retransmit queues, grant the TCP domain a capability to a send-side ring buffer. Retransmission tracking uses sequence ranges (capabilities over intervals) rather than packet lists, reducing allocation pressure.

## Pitfalls and Mitigation

**Connection Reuse Attacks:** TCP's initial sequence number selection specifies cryptographic PRF mixing connection 4-tuples with secret keys. NARF must ensure this PRF runs in a dedicated, non-preemptible domain with constant-time secret comparisons. Async executors cannot safely implement this.

**Half-Open Connection Handling:** The spec describes scenarios where one peer crashes and reboots. NARF's capability revocation semantics must cleanly handle zombie TCBs—if a domain holding send-buffer capabilities crashes, those capabilities become inert. Use generation numbers in sealed capabilities to detect stale references.

**TIME-WAIT State Persistence:** TCP requires lingering in TIME-WAIT for "2×MSL" (4 minutes by default). NARF should implement this outside the async executor—perhaps via timer capabilities that, when fired, atomically transition TCBs to CLOSED. Avoid keeping full connection state in memory by storing only minimal identifiers.

**Option Processing Hazards:** TCP requires handling unknown options gracefully, ignoring them if they have length fields. NARF should pre-validate option lengths in a dedicated parsing domain before granting main TCP logic access, preventing malformed options from triggering length-based buffer overruns.

## Adoption Strategy for NARF

Implement TCP as a user-space library linked with network drivers, using NARF IPC for control-plane operations (OPEN, CLOSE, STATUS) and capabilities-based buffer sharing for data plane. Reserve kernel-side support only for sequence number validation and state machine gates—letting user domains implement congestion control and retransmission logic reduces TCB complexity and improves auditability.

## Reference
- RFC 9293: "Transmission Control Protocol (TCP)"
- https://datatracker.ietf.org/doc/html/rfc9293
