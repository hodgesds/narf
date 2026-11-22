# AMD PMC (S0i3 hints)

## 1. Purpose and scope

`amd_pmc` sends the AMD SoC's power-management controller the S0i3 OS hint
around suspend-to-idle, after Linux's `drivers/platform/x86/amd/pmc/pmc.c`.
Without that hint the SoC never enters S0i3. It covers every root complex
that Linux's `pmc_pci_ids` lists. Raphael (0x14D8) and Phoenix (0x14E8) are
the Stage 5 targets, and Renoir/Cezanne (0x1630) shares their mailbox.

## 2. Assumptions

- The firmware exposes an ACPI PMC device (`AMDI0005`…`AMDI000C`,
  `AMD0004`, `AMD0005`) and an LPS0 device (`PNP0D80`), which
  `narf_power::lps0` attaches.
- The root complex 00:00.0 is enumerated, and its config window carries
  the SMN index/data pair (0x60/0x64).

## 3. Public interface

```rust
pub const ACPI_IDS: [&str; 10];
pub struct CpuInfo { pub message: u32, pub argument: u32, pub response: u32, pub os_hint: u32 }
pub enum PmcError { UnknownCpu(u16), NoS0i3, Absent, Timeout, Busy, Unknown, Failed(u32) }
pub fn cpu_info(root_device: u16) -> Result<CpuInfo, PmcError>;  // amd_pmc_set_cpu_info
pub fn window(lo: u32, hi: u32) -> u64;                          // the SMN-reported base + 0x10000
pub trait Mailbox { fn read32(&mut self, offset: u32) -> u32; fn write32(&mut self, offset: u32, value: u32); fn now_ns(&mut self) -> u64; }
pub fn send(mb: &mut impl Mailbox, info: &CpuInfo, arg: u32, msg: u32) -> Result<(), PmcError>;
pub fn prepare(mb: &mut impl Mailbox, info: &CpuInfo) -> Result<(), PmcError>;  // OS hint, 1
pub fn restore(mb: &mut impl Mailbox, info: &CpuInfo) -> Result<(), PmcError>;  // OS hint, 0; log dump
pub fn init() -> Result<(), PmcError>;  // amd_pmc_probe (x86_64 Device initcall)
pub fn bound() -> bool;
```

`init` reads `AMD_PMC_BASE_ADDR_LO`/`_HI` over SMN, maps the 4 KiB
mailbox window with Device attributes, and registers an `amd_pmc` handler
with `narf_power::lps0`. That handler's `prepare` and `restore` run the
two messages.

## 4. Invariants

- One mailbox transaction at a time, under the driver's lock (`pmc.lock`).
- A message is written only after the previous response is non-zero.
  Every wait is bounded at 1 s (`PMC_MSG_DELAY_MIN_US` ×
  `RESPONSE_REGISTER_LOOP_MAX`).
- A failed hint is logged and never stops the suspend, as in Linux.

## 5. Architecture

x86_64 only: the initcall is compiled out elsewhere. The mailbox offsets
come from `cpu_info`: 0x538/0x9BC/0x980, except 1Ah M20h/M60h (message
0x938) and M80h (0xA10/0xA18/0xA14).

## 6. Dependencies

`narf-power` (`lps0`), `narf-aml` (the HID scan), `narf-bus` (ECAM, root
complex), `narf-memory` (`ioremap`), `narf-time`.

## 7. Stage assignment

Stage 5 (Silicon): real S0ix on the AMD laptops and Raphael.

## 8. Open questions

Not done, all Linux diagnostics or narrow quirks:
- SMU logging and the s0i3 statistics;
- the STB trace buffer;
- the idle-mask read in `check`;
- the 2.5 s EC delay quirk;
- the DMI quirk table;
- Cezanne's RTC wake programming (`amd_pmc_verify_czn_rtc`).

Without the RTC programming, an RTC alarm may not wake a Cezanne or
Renoir from S0i3.
