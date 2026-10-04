# drivers/runtime — Driver Runtime Abstraction

`narf-driver-runtime` is the thin seam that lets a single hardware-
driver source compile against two different execution environments.
Hardware drivers — networking, USB, NVMe, and their siblings — need
only a small, well-defined set of primitives from the kernel: memory-
mapped I/O against a device's BAR region, allocation of DMA-coherent
host memory the device can read and write, subscription to an
interrupt vector that the driver can `await`, PCIe configuration-space
writes (enabling memory space, bus-mastering, MSI-X), and a lock the
driver holds across shared-state mutation. This crate re-exports
exactly that surface, and nothing wider, so that driver crates depend
on it instead of reaching directly into the bus, I/O, interrupt, and
core-library crates.

The value of routing those primitives through one crate is that each
of them has both a kernel implementation today and a plausible
userspace implementation tomorrow. In the kernel, MMIO walks the PCI
BAR and identity-maps physical memory, DMA uses the buddy allocator
with IOMMU pinning, interrupt waits ride a per-vector waker queue,
and the lock toggles the interrupt-enable flag because it runs in
ring 0. In a userspace driver the same operations become capability-
mediated syscalls: the kernel grants a mapped MMIO window through the
IOMMU and EPT, mints a shared coherent page, delivers interrupts over
an IPC endpoint capability, gates config writes behind a capability,
and the lock degrades to a plain mutex because user code cannot touch
the interrupt flag. Because the driver names the same identifiers
either way, only the runtime implementation changes — never the
driver.

Which implementation a driver gets is selected by feature. The
kernel feature (the default) is simply a re-export of the existing
kernel crates and is the live path today; drivers built against it
run in ring 0 with full hardware access. The userspace feature
currently surfaces the same type and function names as a stub whose
constructors fail loudly — pending futures, capability-denied
errors — so that a driver accidentally linked for userspace without
the forthcoming companion runtime crate breaks obviously at the call
site rather than silently misbehaving. The two features are mutually
exclusive and exactly one must be enabled; both conditions are
enforced at compile time.

This crate is distinct from the driver *model* that probes and binds
drivers to devices; it is purely the per-driver primitive runtime. It
is `no_std`.
