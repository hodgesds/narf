# interrupts — Research

## Primary sources

- **Intel Instruction Set Extensions and Future Features, "User
  Interrupts" (UIPI) chapter** — canonical UIPI spec.
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- **Intel SDM Vol. 3A — Chapter 10 (APIC) and §11 (User Interrupts)**.
- **Arm GICv3 and GICv4 Architecture Specification (IHI 0069)**.
  <https://developer.arm.com/documentation/ihi0069/latest/>

## Secondary sources

- **Linux `arch/x86/kernel/uintr.c`** — production UIPI code path.
- **`pcie` MSI-X capabilities reference in PCIe base spec**.
- **GICv3 ITS Linux driver** (`drivers/irqchip/irq-gic-v3-its.c`) — ITS
  programming reference implementation.
- **FreeBSD `arm64/arm64/gicv3.c`** — BSD-licensed GICv3 driver.

## Distilled summaries

- [`summaries/intel-uipi.md`](./summaries/intel-uipi.md) — UIPI enable
  sequence, UITT layout, SENDUIPI/STUI/CLUI, receiver task model.

## Fetched this round

### 2026-04-22

- `summaries/intel-uipi-spec.md` — Intel UIPI mechanisms, invariants, domain-switch semantics
- `summaries/arm-gicv3-gicv4.md` — Arm interrupt controller, ITS, device steering

## Open research questions

- Steering IRQs across NUMA nodes cheaply.
- GICv4 direct-injection vs. v3 baseline — do we care pre-virtualisation story?
- Interaction between UIPI delivery and PKS domain switch — does the
  receiver run in its domain already, or does it enter on first poll?
