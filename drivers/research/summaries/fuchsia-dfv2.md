# Fuchsia Driver Framework v2 (DFv2)

## Key Mechanisms

Fuchsia's Driver Framework v2 (DFv2) separates driver execution from device topology management through three core entities:

The **driver manager** (a system component) maintains the device hierarchy and orchestrates driver binding—a critical responsibility that decouples policy from mechanism. When new device nodes appear, the manager queries the driver index for matching drivers via FIDL protocols, then instantiates drivers in isolated **driver hosts** (per-process containers).

The **driver index** tracks three driver tiers: boot drivers (ZBI-resident, for bootstrapping), base drivers (loaded post-storage), and universe drivers (runtime-registered for development). This tiered approach mirrors package management, enabling predictable initialization ordering. Crucially, the index evaluates node properties against bind rules, returning metadata rather than executing binding directly.

The **driver runtime** provides an elegant solution to cross-process overhead: co-located drivers communicate through in-process primitives mirroring Zircon channels and ports, avoiding kernel transitions. This reflects the trade-off between isolation and throughput.

## Invariants for NARF Adoption

**Process isolation via address spaces**: Each driver host owns its address space. For NARF's PKS/MTE domain isolation, this maps cleanly—each driver domain could be a PKS region, with the manager coordinating capabilities between domains.

**Capability-based binding**: Drivers access capabilities (node control, FIDL protocols) through explicit grants from the manager. DFv2's reliance on FIDL's `Node` and `NodeController` protocols for framework communication is purely capability-driven, avoiding ambient authority—ideal for NARF's capability security model.

**Typed metadata discovery**: The driver index's bind rules operate on node properties (structured metadata), not ad-hoc matching. This determinism is essential: NARF designers should enforce strongly-typed device properties and reject string-based or runtime-computed matching.

## Performance Trade-Offs

**IPC cost vs. isolation**: Co-location of drivers in one host sacrifices isolation for throughput. DFv2 handles this explicitly—drivers can request placement with parents. NARF should quantify this: measure latency of kernel IPC (your zero-copy channel) against in-process calls. If zero-copy IPC is sufficiently fast, isolation becomes less costly, justifying strict per-driver address spaces.

**Async executor scheduling**: Fuchsia's driver framework doesn't specify executor details here, but NARF's async model should expose driver dispatcher threads carefully. The document notes "driver dispatcher and threads" as a concept; NARF must define whether the async executor is per-host, global, or driver-managed to avoid priority inversion or starvation.

**Boot-time topology discovery**: Deferring base and universe driver loading until storage is available simplifies boot but delays service availability. For NARF, measure the cost of lazy initialization against eager pre-loading—especially for devices needed early (timers, interrupts).

## Pitfalls to Avoid

**Ambient device discovery**: DFv2's strength is explicit manager-mediated binding. Avoid letting drivers enumerate devices directly or use global device registries. NARF should enforce that drivers discover capabilities only through their assigned node's protocol exports.

**Untyped bind rules**: The framework's bind rules are metadata-driven. Resist the temptation to use string patterns or dynamic evaluation. Strongly type bind rules and validate them at index registration time, not match time.

**Blocking in driver initialization**: The document doesn't detail startup sequencing, but DFv2's synchronous `Start()` hook suggests drivers must not block on unavailable dependencies. NARF should define clear initialization contracts: which capabilities are guaranteed present at start, which are discovered later, and enforce timeouts.

**Driver host co-location without governance**: While co-location improves throughput, uncontrolled packing creates blast-radius risks. DFv2 leaves this to driver choice; NARF should add policy—perhaps a resource budget per host or a manifest-declared affinity requirement.

## NARF-Specific Recommendations

**Leverage zero-copy IPC**: DFv2's driver runtime justifies in-process optimization because cross-process FIDL calls are expensive (kernel transitions). NARF's zero-copy channels may invert this—measure whether kernel IPC is competitive with in-process communication, then design accordingly.

**Enforce separation of concerns**: The driver manager's single responsibility (topology + binding) versus the driver index's responsibility (metadata matching) is crisp. NARF should similarly isolate device model management from capability routing.

**Adopt tiered driver loading**: The boot/base/universe distinction is valuable for predictable initialization. NARF should implement similar stages, with clear dependencies and startup guarantees.

**Type your driver interfaces**: Use strong FIDL (or equivalent) for driver-to-driver and driver-to-framework communication. Avoid any bus-specific ad-hoc protocols.

DFv2's design reflects hard lessons from monolithic driver stacks: isolation matters, but typed metadata-driven matching and explicit capability grants scale better than dynamic discovery.
