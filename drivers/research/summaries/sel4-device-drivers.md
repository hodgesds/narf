# seL4 Device Drivers Model

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Key Mechanisms

The seL4 microkernel uses a user-mode driver model where hardware drivers run as isolated user-space processes, communicating with the kernel through seL4's capability-based IPC. Device drivers do not run in the kernel; instead, they interact with hardware through a hardware abstraction layer that mediates memory-mapped I/O and interrupt handling.

**Interrupt endpoints**: Drivers receive interrupts through seL4 notification objects (capability-based event channels). The kernel forwards hardware interrupts to designated interrupt handler objects, allowing drivers to block and wait for interrupts without polling or busy-waiting.

**MMIO access control**: Rather than a single privileged driver ring, seL4 grants drivers capabilities to specific memory regions. Each driver only accesses the MMIO regions it needs, with page-table-backed isolation enforced by the kernel. Drivers cannot access memory outside their granted regions without explicit capability grants.

**Separate address spaces**: Each driver runs in its own address space with no shared memory unless explicitly configured. Communication occurs through seL4 IPC (capability-invocation), which provides message-passing semantics with optional shared-buffer support via capability delegation.

## Invariants for NARF Adoption

**Capability-based hardware access**: seL4's fundamental principle—all hardware access is mediated through capabilities—maps directly to NARF's design. NARF's PKS/MTE domain isolation should encode this: a driver capability to a device includes the right to access its MMIO region (via the capability's associated physical address mappings).

**Interrupt routing through endpoints**: seL4 drivers block on notification objects waiting for interrupts. NARF's async executor should model similar primitives: each driver registers an interrupt handler capability, and the frame subsystem (interrupt controller) delivers interrupts through async notifications or callback registration, allowing drivers to yield CPU while waiting.

**No ambient device discovery**: seL4 drivers cannot enumerate available devices; they are granted capabilities at initialization. This matches NARF's capability model perfectly. A driver is initialized with exactly the capabilities it needs; if a capability is absent, the driver cannot access that resource.

## Performance Trade-Offs

**User-mode vs. kernel drivers**: Running drivers in user-space trades throughput for safety—MMIO access requires entering the kernel for capability validation. However, seL4's validation is minimal (capability objects are fast), and the isolation benefit (no driver can corrupt kernel memory) justifies this cost. NARF should similarly evaluate whether in-kernel drivers for performance-critical paths are worth the safety tradeoff.

**IPC latency vs. isolation**: seL4 IPC is relatively fast (500–2000 cycles for a capability invocation on modern hardware), but still slower than in-kernel calls. For drivers sharing resources (e.g., PCI configuration space), this latency accumulates. NARF's zero-copy IPC should aim for similar or better latency, enabling fine-grained capability routing without prohibitive overhead.

**Interrupt batching**: Drivers waiting for interrupts block; they do not poll. This saves CPU but delays batching—if multiple devices interrupt in quick succession, the driver may service one at a time. Evaluate interrupt aggregation at the frame layer to balance latency and throughput.

## Pitfalls to Avoid

**Capability leakage through MMIO**: A driver with access to a device's MMIO region can sometimes infer information about other devices. For example, PCI configuration space access can enumerate all devices. NARF should carefully bound MMIO capabilities: grant access only to the minimum offset range needed, not entire device regions.

**Interrupt storms without backpressure**: A misbehaving device may fire interrupts faster than the driver can service them. seL4 documentation acknowledges this. NARF should implement driver-level backpressure: drivers can disable interrupts locally (through their own interrupt control), or request that the frame subsystem throttle interrupt delivery if handlers are blocked.

**Shared devices without arbitration**: If two drivers need the same device (e.g., PCI configuration space access), seL4 requires explicit arbitration. NARF should enforce: a device capability grants exclusive access, or explicitly defines multiplexing semantics. Avoid implicit sharing or race conditions.

**Blocking IPC during interrupt handling**: seL4 drivers typically service interrupts in the interrupt handler thread. If a handler calls IPC (to notify a userspace service or request capability grant), it blocks. NARF's async model should clarify whether interrupt delivery occurs in the async executor context or a dedicated interrupt thread.

## Design Recommendations for NARF

**Adopt seL4's interrupt endpoint model**: Drivers should block on interrupt objects, not poll. Your async executor should efficiently park driver tasks on interrupt capabilities, yielding CPU to other work.

**Enforce strict MMIO capability bounds**: Never grant drivers access to entire device address ranges. Use physical address grant lists to restrict access to specific offsets, preventing device-enumeration attacks.

**Model device capabilities explicitly**: Each PCI device, virtio device, or platform device is a capability. Drivers gain them at initialization; they cannot enumerate or request new capabilities at runtime (unless a policy daemon grants them, which requires explicit audit).

**Implement interrupt masking at the driver level**: Drivers should be able to locally disable interrupts for their devices without kernel intervention (e.g., a PCI IRQ mask bit). This allows drivers to apply backpressure without blocking in the kernel.

**Separate device discovery (boot-time) from driver binding**: seL4 uses a boot manifest (like Capsl) to declare which drivers get which capabilities. NARF should adopt a similar manifest-based initialization, avoiding runtime device enumeration.

seL4's approach is philosophically aligned with NARF's capability model. The main adjustment is efficiency: NARF's zero-copy IPC and PKS/MTE domains allow even tighter driver isolation without the performance penalty seL4 accepted.

Source: https://docs.sel4.systems/Tutorials/devicedrivers.html
