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
pub struct CpuInfo { pub message: u32, pub argument: u32, pub response: u32, pub os_hint: u32, pub scratch: Option<u32> }
pub enum PmcError { UnknownCpu(u16), NoS0i3, Absent, Timeout, Busy, Unknown, Failed(u32), Unsupported }
pub fn cpu_info(root_device: u16) -> Result<CpuInfo, PmcError>;   // amd_pmc_set_cpu_info
pub fn window(lo: u32, hi: u32) -> u64;                           // the SMN-reported base + 0x10000
pub trait Mailbox {                                               // mailbox, metrics table, FCH scratch byte
    fn read32(&mut self, offset: u32) -> u32; fn write32(&mut self, offset: u32, value: u32);
    fn now_ns(&mut self) -> u64; fn delay_us(&mut self, us: u64);
    fn map_table(&mut self, phys: u64) -> bool; fn table_read32(&mut self, offset: u64) -> u32; fn table_zero(&mut self);
    fn clear_fch_scratch_bit0(&mut self);
}
pub fn send(mb, info, arg, msg) -> Result<(), PmcError>;          // amd_pmc_send_cmd
pub fn send_read(mb, info, arg, msg) -> Result<u32, PmcError>;    // ... with a data reply
pub struct Options { pub delay_suspend: i8, pub disable_workarounds: bool }  // amd_pmc.delay_suspend, amd_pmc.disable_workarounds
pub struct State { pub info, pub cpu, pub version, pub active_ips, pub table, pub first_check, pub quirk, pub options }
pub fn smu_version(mb, st) -> Result<[u8; 4], PmcError>;         // program, major, minor, revision
pub fn setup_logging(mb, st) -> Result<(), PmcError>;            // amd_pmc_setup_smu_logging
pub struct Metrics { pub s0i3_last_entry_status: u32, pub timein_s0i3_lastcapture: u64 }
pub fn metrics(mb, st) -> Result<Metrics, PmcError>;             // get_metrics_table
pub fn czn_rtc_hint(mb, st, arg: u32) -> Result<u32, PmcError>;  // amd_pmc_verify_czn_rtc's gate
pub fn idle_mask(mb, st) -> Result<u32, PmcError>;               // amd_pmc_idlemask_read
pub fn prepare(mb, st) -> Result<(), PmcError>;                  // amd_pmc_s2idle_prepare
pub struct Check { pub delayed: bool, pub idle_mask: Option<u32> }
pub fn check(mb, st) -> Check;                                    // amd_pmc_s2idle_check
pub fn restore(mb, st) -> (Result<(), PmcError>, Option<Metrics>); // amd_pmc_s2idle_restore
pub fn init() -> Result<(), PmcError>;                           // amd_pmc_probe + amd_pmc_quirks_init
pub fn bound() -> bool;
// amd_pmc_quirks (pmc-quirks.c)
pub struct Quirk { pub s2idle_bug_mmio: bool, pub spurious_8042: bool, pub need_suspend_delay: bool }
pub struct Dmi { pub sys_vendor, pub product_name, pub board_vendor, pub board_name, pub bios_version: String }
pub fn lookup(dmi: &Dmi) -> Option<(&'static str, Quirk)>;     // dmi_first_match(fwbug_list), 39 entries
pub fn read_dmi() -> Dmi;
```

`init` does the following:
- reads `AMD_PMC_BASE_ADDR_LO`/`_HI` over SMN and maps the mailbox window
  with Device attributes;
- looks the machine up in `fwbug_list` (skipped with
  `amd_pmc.disable_workarounds`);
- registers an `amd_pmc` handler with `narf_power::lps0`.

The handler's steps:
- **`prepare`:** resets and starts SMU logging, then sends the OS hint with 1.
- **`check`:** delays 2.5 s if the last wakeup came out of S0i3, or if the
  `need_suspend_delay` quirk or `delay_suspend=1` asks for it; then reads
  the idle mask.
- **`restore`:** sends the hint with 0 and the log dump, reads the
  deepest-state metrics (it warns "Last suspend didn't reach deepest
  state"), then runs the `s2idle_bug_mmio` quirk.

## 4. Invariants

- One mailbox transaction at a time, under the driver's lock (`pmc.lock`).
- Every wait (the 1 s response timeout, the data-reply delay and the 2.5 s
  delay) runs on `narf_time::raw_cycles`. The park has frozen
  `CLOCK_MONOTONIC`, and a wait on it there would never end.
- A message is written only after the previous response is non-zero.
  Every response wait is bounded at 1 s (`PMC_MSG_DELAY_MIN_US` ×
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

- STB is off by default in Linux (`enable_stb`) and is not ported, nor is
  the debugfs statistics.
- `spurious_8042` (`amd_pmc_wa_irq1`) needs nothing here: NARF's s2idle
  park masks every discrete IRQ, IRQ1 included, and only SCI-funneled
  sources wake it.
- Cezanne's RTC wake programming stops at its version gate. NARF has no
  RTC alarm API, so no alarm is ever pending: Linux's "no alarm" path.
