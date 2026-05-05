# accel — Specification

> Status: **v0.1** (Stage 4 design draft).
>
> Subsystem for hardware accelerators (NPU, TPU, FPGA) in the NARF ecosystem.
> Optimized for zero-copy data flow between IO devices and compute engines.

## 1. Purpose & scope

**Owns:**
- The **Accelerator Trait** (`AccelDevice`) for heterogeneous compute.
- **Compute Capabilities** (`AccelCap<T, R>`) for memory-mapping and kernel submission.
- **Accelerator Registry** — discovery of NPU/FPGA resources.
- **P2P DMA Coordination** — directly wiring `narf-net` or `narf-storage` to `narf-accel`.

**Does NOT own:**
- High-level ML frameworks (TensorFlow/PyTorch) — these live in userspace.
- Compiler toolchains for FPGA bitstreams.
- GPU graphics (owned by `drivers/gpu`).

## 2. Design Principles

1. **Memory-First**: Accelerators are treated as first-class memory consumers.
2. **Cap-Gated Submission**: Submitting a compute graph requires a `ComputeCap`.
3. **Zero-Copy Chain**: Data flows from NIC → Accelerator → Storage without CPU interaction via **P2PDMA**.

## 3. Public Interface

### 3.1 Device Information

```rust
pub struct AccelInfo {
    pub id:          AccelId,
    pub kind:        AccelKind,           // Npu, Tpu, Fpga, Dsp
    pub memory_size: u64,
    pub compute_units: u32,
    pub features:    AccelFeatures,       // Bfloat16, Int8, AsyncQueue, etc.
}
```

### 3.2 Submission API

```rust
pub struct ComputeJob {
    pub graph_blob: Cap<DmaBuffer, Read>, // The model or bitstream
    pub inputs:     Vec<Cap<DmaBuffer, Read>>,
    pub outputs:    Vec<Cap<DmaBuffer, Write>>,
}

pub async fn submit(cap: &Cap<AccelDevice, Compute>, job: ComputeJob) -> Result<JobId, AccelError>;
pub async fn wait(cap: &Cap<AccelDevice, Read>, id: JobId) -> Result<(), AccelError>;
```

## 4. P2PDMA Integration

One of NARF's primary innovations is the ability to wire devices together.
`narf-accel` leverages `io/spec` §4 to establish P2P DMA:

```rust
pub fn wire_p2p(
    src: &Cap<NetIface, Rx>,
    dst: &Cap<AccelDevice, Write>,
) -> Result<P2PLink, IoError>;
```

This creates a dedicated Narf-Ring where the `NetIface` driver writes directly into the `AccelDevice`'s local memory or BAR.

## 5. Security & Isolation

- **Domain Isolation**: Accelerator drivers run in their own PKS/MTE domains.
- **Address Space Guard**: IOMMU/SMMU ensures accelerators only see memory they are granted via `DmaBuffer` caps.
- **Multi-Tenant**: Hardware with virtualization (SR-IOV) is exposed as multiple `AccelDevice` instances.

## 6. Stage Assignment

- **Stage 4**: Initial design and `narf-accel` crate skeleton.
- **Stage 5**: First driver (candidate: Intel NPU or generic FPGA wrapper).
- **Stage 6**: Full P2PDMA chain integration.

## 7. Dependencies

- **Consumes**: `drivers/`, `capabilities/`, `io/`, `ipc/`.
- **Provides to**: Userspace ML runtimes.
