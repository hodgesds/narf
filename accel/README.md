# accel — Compute Accelerator Subsystem

The kernel's home for hardware compute accelerators — NPUs, TPUs, FPGAs, and
DSPs — as a class distinct from GPUs (which belong to `drivers/gpu`). Where
the GPU subsystem is about graphics and display, `accel` is about offloading
raw computation: submitting a job (a model, graph, or bitstream plus its input
and output buffers) to a device, waiting on it, and reclaiming the results.
The subsystem's guiding idea is that accelerators are first-class memory
consumers, so it is designed around zero-copy data flow — ultimately wiring a
NIC or storage device directly into an accelerator's local memory via `io/`
P2P DMA so data never has to detour through the CPU.

Conceptually the crate defines three things. First, a device abstraction: a
common trait every accelerator driver implements, describing the device
(kind, memory size, compute-unit count, supported numeric formats) and the job
lifecycle of submit, wait, and abort. Second, a capability model: operations
are gated by accelerator capabilities with distinct rights for reading status,
submitting compute jobs, memory-mapping device BARs, and administrative
actions such as reset or firmware update — consistent with NARF's
capability-based, no-ambient-authority design. Third, a registry where probed
accelerators register themselves so the rest of the kernel can enumerate
available compute resources.

The one concrete driver today is `intel_npu`, covering the Intel NPU (VPU)
for device identification and buttress telemetry. Because it attaches over
PCIe, it is compiled only on x86_64; the device trait, capability types, and
registry are architecture-independent. Security intent follows the subsystem
spec: accelerator drivers are meant to run in isolated PKS/MTE domains with
IOMMU/SMMU confining each device to only the DMA buffers it has been granted,
and virtualization-capable hardware is exposed as multiple device instances.
The crate is `#![no_std]` and uses async job submission; high-level ML
runtimes and FPGA compiler toolchains deliberately live in userspace, not
here.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: 4 (crate skeleton and design draft).
