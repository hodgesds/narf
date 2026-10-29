# sdio — Specification

> Status: owned standard SDHCI PIO/card lifecycle, PCI function dispatch,
> and CYW43439 consumer integration. No physical controller has been tested.

## 1. Purpose & scope

Own standard SDHCI register access, bounded command/PIO execution, SDIO
card enumeration, function enable/block sizing and exclusive handoff to a
chip driver. SD storage, eMMC, ADMA/SDMA and vendor register quirks are out
of the current implementation profile.

## 2. Assumptions

A standard register aperture is exclusively owned, device ordered, and at
least 256 bytes long. The profile uses 3.3 V and negotiates, as Linux
`mmc_sdio_init_card` does on sdhci-pci, a 4-bit bus and SDIO high-speed
timing (≤ 50 MHz) when card, host and board configuration allow; otherwise
one data line, legacy timing and at most 25 MHz. PCI interfaces 0 (PIO) and 1 (standard registers
with DMA capability) are supported using PIO. Vendor interface 2 and
multi-slot PCI functions are rejected. A platform supplies its own owned
`pio::Registers` implementation and explicit soldered-card configuration;
this does not configure platform clocks, pin muxes or power GPIOs.

## 3. Public interface

- `pio::HostIdentity { address: BusAddr, id: DeviceId }` exposes immutable host
  facts captured by its exclusive owner. `Registers::host_identity`,
  `Controller::host_identity` and `Card::host_identity` return them without I/O
  or authority. The default is None; non-PCI platforms must report actual
  identity explicitly. This configures no pins, clocks, regulator or reset.
- `pio::Registers` owns exact-width 8/16/32-bit accesses. No independent
  register handle may race a command or a window selection.
  `Controller::execute` validates command/data shape before I/O, waits for
  inhibit/response/FIFO/completion using scheduler deadline primitives,
  validates R5 before FIFO access and copies complete PIO buffers before
  return. Transfers are bounded by 32 KiB, blocks 1–512 bytes and 511
  blocks. Hardware/card/timeout errors terminally poison the owner.
  The controller does not enable DMA or auto-CMD12/23.
- `card::Card::initialize(registers, Config)` consumes the controller,
  resets it, disables interrupt signalling, enables status latches, sets
  power and a representable clock at most 400 kHz, then executes CMD0,
  CMD5 query/ready negotiation, CMD3 and CMD7. Memory-combo cards and
  unsupported voltage/version profiles fail. CMD5 ready is bounded to
  one second, command waits to 100 ms, clock stabilization to 150 ms and
  data/busy completion to one second. Waiting uses `responsive_spin_until`.
  After selection, inherited CCCR interrupt/function enables are cleared:
  resetting the host alone need not reset a soldered card's always-on rail.
- `Card::host` returns immutable negotiated state; `function(n)` returns
  validated CIS identity/block limit metadata. CIS scanning is bounded to
  1024 bytes per function, checks 17-bit extents, and requires a valid
  FUNCE. Function MANFID may inherit common identity. After the CIS,
  initialization reads CCCR card capability; with `Config::high_speed`, a
  `CAN_DO_HISPD` host and an SDIO ≥ 1.20 card advertising SHS, it sets EHS
  and host `CTRL_HISPD` (`mmc_sdio_switch_hs`) and allows 50 MHz; otherwise
  the clock is bounded by the common CIS maximum and 25 MHz. The caller's
  `Config::max_clock_hz` always bounds it. With `Config::four_bit` and not a
  low-speed card lacking 4BLS (`sdio_enable_wide`), it writes CCCR_IF
  4-bit (reserved bits kept) and host `CTRL_4BITBUS`. `SdhciHost::bus_width`
  and `high_speed` record the result. `Config` defaults: 25 MHz,
  `four_bit` and `high_speed` enabled (sdhci-pci `MMC_CAP_4_BIT_DATA`).
- `SdioFunction` is implemented by `Card`. CMD52 checks function/address;
  CMD53 checks function enable, address extent, byte count, CIS per-function
  block limit in both byte/block modes, programmed block size and exact
  buffer length. `cmd53_read_fixed` uses a fixed FIFO
  address. `set_block_size` writes both FBR bytes; `enable_func` preserves
  other enabled functions and waits for IO_READY using CIS timeout.
  Adapters without fixed-read/block-size operations return `Unsupported`.
- Card interrupts. `Card::attach_interrupt(Box<dyn InterruptLine>,
  Arc<Subscriber>) -> bool` first asks `Registers::enable_intx` (default
  `false`) to let the function assert INTx; on refusal the line is dropped
  (masked) and the card keeps polling. `SdioFunction::enable_card_interrupt(
  functions, notify) -> Result<bool, _>` is Linux `sdio_claim_irq`: it
  validates the function bitmask (bit N = function N, no master bit, at most
  `func_count`), installs `notify` (wake only, hard-IRQ context), sets CCCR
  IENM plus the function bits, enables SDHCI card-interrupt status and signal
  (`sdhci_enable_sdio_irq`; no other source is signalled) and unmasks the
  line. `Ok(false)` without a line. `rearm_card_interrupt` unmasks after the
  owner serviced every function source. Dropping the card clears SDHCI
  status/signal enables before the line is masked.
- `native::register_pci_driver` registers class 08:05:00 and 08:05:01.
  `probe` reserves each BDF once, clears inherited BME and memory decode,
  sets INTx disable and verifies all three before sizing/mapping the control
  BAR with memory decode still off. SLOT_INFO 0x40 selects first BAR/slot count.
  Only after a valid full mapping does it enable/verify memory decode with BME off.
  Repeated BDF probes leave the owner untouched; extra functions beyond the
  32-host bound remain parked with decode/BME off. New owners map control
  registers and initialize the card. `native::Mmio`
  retains PCI authority and invokes its current validity for every exact-width
  register access and PCI configuration transition. Inside that invocation,
  command readback must be live (notffff), MEM set, BME clear, and
  INTx-disable set unless this owner bound its oneshot line (then clear)
  before MMIO. `probe` binds the host function's INTx pin through the root
  `_PRT` (`\_SB.PCI0`, as e1000/xHCI; bridged functions and named link
  entries keep polling) to an exclusive GSI as a masked `oneshot::Line`
  (x86_64 only), and clears INTx-disable only after the card initialized
  (`Mmio::enable_intx` with readback), so a failed probe leaves it parked. Range/alignment failure, revoked authority or invalid
  decode permanently closes the adapter. The private handle cannot be cloned.
- `native::register_function_driver(FunctionDriver)` registers up to 16
  exact `(function,vendor,device)` consumers. The matching callback receives
  the whole `NativeCard`, preserving shared F0/F1/F2 ownership. Registry
  locks are released before initialization and callbacks. Unclaimed cards
  are dropped and powered down; the host publishes no network interface.
- Dropping a `Card`, including initialization failure, disables status and
  signalling, stops the clock and removes card power. PIO has no retained
  caller pointer, descriptor mapping or DMA lifetime.

## 4. Invariants

Every buffer transfer finishes synchronously or fails before its borrow
ends. An R5 rejection cannot access BUFFER, even if readiness is asserted.
No retries follow a partially accepted transfer under the same controller
owner. PCI BME remains off throughout the PIO lifecycle. SDIO command
execution does not clear card IRQ state as command completion. Bounds and
function checks precede COMMAND writes. No IRQ spin lock spans hardware
initialization, driver callback or async work.

## 5. Architecture notes

PCI MMIO uses `map_bar_control` and bus exact-width accessors, including
architecture device barriers. Divided clocks use powers of two on v1/v2
and every even divisor on v3; a saturated divisor that would exceed the
requested clock fails. No descriptor DMA ordering or IOMMU contract is
claimed by this PIO profile.

## 6. Dependencies

`narf-bus` PCI authority/control mappings, scheduler responsive deadline
waits, monotonic time and chip consumers. The CYW43439 wireless module
registers exact SDIO identities and consumes this host through its loader
and packet runtime. Linux `mmc/host/sdhci.c`, `sdhci-pci-core.c` and
`mmc/core/{sdio,sdio_ops,sdio_cis}.c` are implementation references.

## 7. Stage assignment

Stage 5. Production-shared register models cover complete initialization,
CIS, fixed FIFO read, block write, R5 rejection before FIFO, terminal
controller failure, address rejection, clock divisors and bounded CIS.
A revoked real PCI cap with deliberately invalid ECAM/MMIO proves current
authority rejection occurs before those accesses. An Arc/IRQ-safe standard
register/CIS fixture exposes the same initialized Card to composed wireless
provisioning tests, including controller-command failure after preflight.
They validate software contracts, not electrical/controller compatibility.

## 8. Open questions

Platform ACPI/devicetree enumeration, regulators/pin mux/clock/reset GPIOs,
vendor SDHCI quirks, multiple slots/card removal/reprobe, UHS-I,
interrupt-driven command/data completion, aarch64 PCI INTx (no
INTx-to-SPI map) and DMA remain software work.
Physical PCI/SDIO acceptance, real card timing and cancellation/power-down
behavior require a target test after these software profiles are reviewed.
