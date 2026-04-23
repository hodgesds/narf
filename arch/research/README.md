# arch — Research

## Primary sources

- **Intel® 64 and IA-32 Architectures Software Developer's Manual (SDM)**
  — all volumes, especially Vol. 3 (System Programming) for privilege,
  paging, PKS/PKU, APIC, UIPI.
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- **Arm Architecture Reference Manual for A-profile architecture (DDI 0487)**
  — EL1/EL2 state, MMU, MTE, PAC, GIC integration.
  <https://developer.arm.com/documentation/ddi0487/latest/>
- **Arm Generic Interrupt Controller v3 and v4 Architecture Specification
  (IHI 0069)** — GICv3/GICv4 and ITS.
  <https://developer.arm.com/documentation/ihi0069/latest/>

## Secondary sources

- OSDev wiki — quick pragmatic reference for x86_64 boot, CPUID, APIC.
  <https://wiki.osdev.org/>
- The `rust-osdev` organisation: `bootloader`, `x86_64`, `uart_16550`,
  `aarch64-cpu`. <https://github.com/rust-osdev>
- Hubris HAL crates (Oxide) — minimalist Rust HAL precedent.
  <https://github.com/oxidecomputer/hubris>
- Redox `kernel/src/arch` — another multi-arch Rust kernel HAL shape.
  <https://gitlab.redox-os.org/redox-os/kernel>

## Distilled summaries

- [`summaries/pks-vs-mte.md`](./summaries/pks-vs-mte.md) — side-by-side of
  the two primary hardware-isolation primitives we depend on.

## Fetched this round

- summaries/intel-sdm-pks.md — Protection Keys Supervisor; 16-domain isolation model and WRMSR cost
- summaries/arm-ddi0487-mte.md — Memory Tagging Extensions, exception levels, and Pointer Authentication
- summaries/arm-gicv3-v4.md — Generic Interrupt Controller architecture and MSI/ITS for interrupt delivery

## Open research questions

- Does PKS apply uniformly to all supervisor memory accesses including
  instruction fetches on current CPUs? (SDM citation needed.)
- MTE tag granule size implications for our 16-domain model.
- UIPI availability: which CPU generations, what's the EL2 equivalent
  story on aarch64.
