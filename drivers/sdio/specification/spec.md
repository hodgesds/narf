# sdio — Specification

> Status: owned standard SDHCI PIO and ADMA2/SDMA data path, card
> lifecycle, PCI function dispatch, and CYW43439 consumer integration. No
> physical controller has been tested.

## 1. Purpose & scope

Own standard SDHCI register access, bounded command/PIO execution, SDIO
card enumeration, function enable/block sizing, host DMA (ADMA2 with
SDMA fallback) and exclusive handoff to a chip driver. SD storage, eMMC,
ADMA3, v4 mode, external DMA and vendor register quirks are out of the
current implementation profile.

## 2. Assumptions

A standard register aperture is exclusively owned, device ordered, and at
least 256 bytes long. The profile uses 3.3 V and negotiates, as Linux
`mmc_sdio_init_card` does on sdhci-pci, a 4-bit bus and SDIO high-speed
timing (≤ 50 MHz) when card, host and board configuration allow; otherwise
one data line, legacy timing and at most 25 MHz. PCI interfaces 0 (PIO) and 1 (standard registers
with DMA capability) are supported; like Linux `sdhci_pci_enable_dma`, the
DMA decision follows the capability register, not the interface byte. Vendor interface 2 and
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
  The controller never enables auto-CMD12/23.
- Host DMA (`sdhci/adma.rs`, `dma.rs`). `Registers::enable_dma() ->
  Option<narf_io::DmaDevice>` (default None) is the platform bus-master
  grant (Linux `sdhci_pci_enable_dma` -> `pci_set_master`);
  `Registers::disable_dma() -> bool` (default true) revokes it with
  readback. `Controller::setup_dma(spec_version, caps) -> Option<Mode>`
  is the `sdhci_setup_host` DMA admission without v4 mode/external DMA:
  `adma::select` picks ADMA2 for spec >= 2.00 with `SDHCI_CAN_DO_ADMA2`
  (`Adma64`, 12-byte descriptors, when `SDHCI_CAN_64BIT`, else `Adma32`),
  else SDMA for `SDHCI_CAN_DO_SDMA` without 64-bit; then it takes the grant
  and allocates, with `narf_io::alloc_coherent_for` below the mode's mask
  (32-bit, or 64-bit for `Adma64`), one coherent region holding the
  512-byte align buffer then a 257-entry descriptor table (base 8-byte
  aligned, else refused) and a 32 KiB bounce buffer. Failure falls back
  ADMA -> SDMA (`Mode::without_adma`) -> PIO and revokes the grant.
  `Card::initialize` calls it after the host reset and records the mode
  in `SdhciHost::dma`; `Controller::dma_mode` reports it. Once admitted,
  every data command (`sdhci_prepare_dma`) copies write payloads into the
  bounce buffer (caller slices are not DMA memory), calls
  `DmaBuffer::sync_for_device` with the request direction (`ToDevice` /
  `FromDevice`), builds the table (`adma::table_pre`: TRAN descriptors,
  segments over 64 KiB split into 32 KiB pieces, 65536 encoded as 0,
  closing NOP/END/VALID; unaligned heads would use align-buffer slots,
  never taken for the page-aligned bounce) or programs the SDMA address,
  writes `ADMA_ADDRESS`(`_HI`), selects the mode in HOST_CONTROL
  (`sdhci_config_dma`; PIO commands clear the select), programs
  `make_blksz(7, size)` and sets `TRNS_DMA`. All of this precedes COMMAND
  and any publication scope. Completion waits for DATA_END, restarting
  SDMA at the next 512 KiB boundary on DMA_END; `SDHCI_INT_ADMA_ERROR`
  returns `Error::Dma(ADMA_ERROR)`. Success calls `sync_for_cpu` with the
  same direction and copies reads out (`sdhci_request_done`). A refused
  publication scope or pending CARD_INT disarms without reset. Any failure
  after a potential COMMAND (ADMA/data error, timeout, R5 rejection) is
  `sdhci_do_reset(CMD|DATA)`, a revoked grant and a terminal owner as for
  PIO (no retry after a partially accepted transfer; Linux returns -EIO);
  a preparation failure before COMMAND moves that command to PIO. Both
  latch the owner PIO-only. DMA buffers are freed only after
  `disable_dma` confirms bus mastering off; otherwise they are leaked
  (quarantined).
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
  initialization reads CCCR card capability (SMB recorded as
  `SdhciHost::multi_block`, reported by `SdioFunction::multi_block`, Linux
  `cccr.multi_block`); with `Config::high_speed`, a
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
  buffer length. `cmd53_read_fixed` and `cmd53_block_read_fixed` (block
  mode, Linux `sdio_readsb`; default `Unsupported`) use a fixed FIFO
  address. `set_block_size` writes both FBR bytes; `enable_func` preserves
  other enabled functions and waits for IO_READY using CIS timeout.
  Adapters without fixed-read/block-size operations return `Unsupported`.
- `SdioFunction::disable_func(n)` defaults to `Unsupported`. The actual
  `Card` first denies further host CMD53 for that function, clears its CCCR
  IO_ENABLE bit while retaining the other functions, requires exact enable
  readback and bounded IO_READY clear, then checks command/data engines are
  inactive. Partial failure grants no stop receipt; a later explicit enable
  is a separate operation. No power-off or DMA proof is inferred from a bit.
- `SdioFunction::disable_card_interrupt()` defaults to `Unsupported` and
  retires the exclusive whole-card subscription. `Card` clears the original
  Subscriber, disables and reads back SDHCI card-interrupt signal/status,
  drops the original oneshot CPU line even on failure, and requires actual
  CCCR master/function interrupt clear. Failed readback remains an error;
  callback/CPU quarantine alone supplies no device-quiet receipt. No later
  rearm revives the retired line. Card drop also clears its Subscriber.
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
- System PM (`card_pm.rs`). `PmFlags` is Linux `mmc_pm_flag_t`
  (`KEEP_POWER`, `WAKE_SDIO_IRQ`). `Registers::pm_caps()` (default none) is
  the platform grant; the native PCI owner reports `KEEP_POWER` as
  sdhci-pci-core `sdhci_pci_probe_slot` does, plus `WAKE_SDIO_IRQ` when the
  host function's PCI PM capability has a non-zero `PME_Support`
  (`pci_pm_init` -> `device_can_wakeup`). `SdioFunction::host_pm_caps()`
  (`sdio_get_host_pm_caps`) masks `WAKE_SDIO_IRQ` without a bound card line.
  `SdioFunction::suspend_host(flags)` refuses a flag the host lacks
  (`sdio_set_host_pm_flags` -EINVAL), wake without keep-power, or an active
  command/data engine. With `KEEP_POWER` the card keeps power, selection and
  function enables; a waking suspend requires CCCR IENM, arms the line with
  `InterruptLine::set_wake` (oneshot: `narf_interrupts` `enable_irq_wake`),
  drops a 4-bit bus to 1-bit with `SDIO_BUS_ASYNC_INT` (`mmc_sdio_suspend` ->
  `sdio_disable_wide`), sets SDHCI `WAKE_UP_CONTROL` `WAKE_ON_INT`, enables
  only card-interrupt status/signal and unmasks the line
  (`sdhci_enable_irq_wakeups`); a non-waking one clears both enables
  (`sdhci_suspend_host`). Without `KEEP_POWER` it is `mmc_power_off`: clock
  and power off, function enables and the card receipt retired. Every
  command is refused (`Busy`) while suspended. `resume_host()` with power
  kept is `sdhci_resume_host` (CMD/DATA-line reset, replay of timing, bus
  width, 3.3-V power and clock, wake disarm, saved enables restored) then
  `mmc_sdio_resume` (4-bit restored); the CCCR I/O-enable byte must still
  equal the enabled functions (the card kept power), else the card turns
  terminal (`HostError`). A power-off resume is `mmc_sdio_reinit_card`: full
  enumeration whose per-function identities must match; functions return
  disabled. Arming PCI PME / the ACPI wake route of the host for an S-state
  is the system-PM owner's (`narf-power` `pci_wake`), not this crate's.
- Hardware reset (`card_pm.rs`, Linux `core.c::mmc_hw_reset` ->
  `sdio.c::mmc_sdio_hw_reset` for a single-driver card).
  `SdioFunction::power_off_host()` is the host-side stop
  `brcmf_sdio_bus_reset` takes before the reset: card-interrupt subscriber
  cleared, SDHCI signal/status enables, SD clock and bus power
  (`sdhci_set_power`: `POWER_CONTROL` 0) off and read back with an idle
  command/data engine; every function enable and receipt is retired.
  `SdioFunction::hw_reset()` is `mmc_power_cycle` (`mmc_power_off`, 1 ms,
  1 ms more per the SD spec, `mmc_power_up`: host `RESET_ALL`, 3.3-V bus
  power, 10 ms `ios.power_delay_ms`, 400 kHz clock, 10 ms) then
  `mmc_sdio_reinit_card`: `mmc_sdio_pre_init`'s `sdio_reset` (CCCR I/O
  Abort RES, errors ignored with a CMD/DATA host reset as
  `sdhci_request_done` does), CMD0, CMD5, CMD3, CMD7 and CCCR/CIS, the
  function count and every function's vendor/device equal to the old card
  (`mmc_sdio_init_card(oldcard)`, `-ENOENT` otherwise). It revives a
  controller left terminal by an errored command (new Controller/Card
  lifetimes; old receipts stay retired); functions return disabled. The
  bound card-interrupt line survives unless `disable_card_interrupt` already
  dropped it. Failure leaves the card powered off and terminal. The
  power-off resume shares the same reinit, including `sdio_reset`. Whether
  the card's own supply (vmmc / WL_REG_ON) follows SDHCI bus power is board
  wiring this crate does not own: with a fixed supply Linux relies on the
  CCCR I/O reset alone, and a card that then does not re-enumerate fails
  the reset. `vqmmc`/`pwrseq` regulator and GPIO hooks are not modelled.
- `source::Source` is an opaque original native host plus Controller/Card
  lifetime receipt. `Registers::source` and `SdioFunction::source` default
  to None; observed identity, a caller validator or a scalar cannot create
  it. The native PCI owner retains its original capability, device and
  actual decode/BME-off/INTx policy. Controller/Card privately attach their
  own nonreviving lifetimes. Only that complete receipt can pass `current`
  or `invoke`; bare host metadata cannot. Actual PIO poison, destructive
  function retirement and owner Drop close the corresponding lifetime.
  Re-enabling a function cannot revive it; a fresh Card initialization owns
  a distinct generation. Fixed lifetime gates serialize terminal retirement
  against the final copy; no hardware wait, provider callback or endpoint
  lookup runs under them. `invoke` is for fixed guard checks/copy after all
  dynamic preparation, and supplies no RF, peer, key or DATA authority.
- `pio::Publication` is a kernel producer's fixed original scope around
  the supplied actual COMMAND action. `Controller::execute_published` and
  `SdioFunction::cmd53_write_published` validate bounds and finish inhibit/
  readiness waits first. The producer must enclose exactly one action under
  its original current authority; no socket/provider callbacks, hardware
  waits or authority lookup run in that scope. Native Card/controller and
  per-MMIO capability/device checks remain independently mandatory. A
  refused scope before action entry returns `Denied` without poisoning the
  controller or issuing COMMAND/FIFO. Entry followed by failure/duplicate
  action is potentially issued and terminal; error handling/retirement runs
  after scope guards release. A split frame requires a new scope for every
  actual transfer, and an earlier accepted part cannot become retry credit.
  Unknown adapters default to `Unsupported`. Source lifetimes use a fixed
  retirement gate plus a nonreviving atomic terminal latch: normal retire
  serializes against publication, while actual MMIO failure inside its own
  short action latches denial without recursively acquiring that gate.
- Published writes additionally require `observe_publication(function_mask)`
  to establish actual CCCR master/function interrupt-enable and SDHCI
  CARD_INT status-enable readbacks. It installs no CPU route or callback.
  The Card retains the exact observed function mask; every scoped transfer
  rechecks that function's actual CCCR bits. After all hardware waits, the
  final fixed publication action reads actual host status-enable and
  INT_STATUS immediately before COMMAND. A pending CARD_INT returns `Busy`
  without COMMAND/FIFO or controller poison. An absent enable or retired
  source refuses the unissued operation. Command/data W1C handling preserves
  the independent CARD_INT latch. `clear_publication_pending` acknowledges
  only that latch before a fresh family mailbox read; it never proves an
  empty native prefix by itself.
- `cmd53_block_write_published` admits one exact size/count extent under
  the same original scope, with actual current FBR block-size readbacks in
  addition to retained CIS/function bounds. It does not split or restart
  a frame. Unknown adapters default to `Unsupported`. A new native Card
  case observes late CARD_INT denial, one actual three-block COMMAND and
  FIFO copy including its zero tail, polling-only status observation and
  refusal after physical FBR geometry changes. Existing scoped byte cases
  retain native source/issued-terminal assertions, accounting read-only
  CCCR proof commands separately from forbidden CMD53 publication.
- The `kernel-test` feature also enables bus ECAM fixture support. Four
  written publication cases exercise actual NativeMmio under its original
  scope, late original loss after readiness, attempted-command failure and
  independently scoped complete PIO copies. They grant no AP/RF capability
  and have not yet been executed.
- A `kernel-test`-only Card endpoint can provide inert F1/F2 register/FIFO
  bytes behind the existing real SDHCI/CCCR/CIS/PIO model. It supplies no
  source validator, host constructor, completion, AP or RF authority. F0,
  R5, function/block bounds, original Controller/Card lifetimes, native
  commands and PIO copy receipts remain the parent model's responsibility.
  Its setup-boundary transition hook can inject real modeled firmware
  loss/source changes before COMMAND; pending status is still observed
  through actual INT_STATUS. Production Card behavior is unchanged.
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
  on x86_64; on aarch64 it resolves the root-bus function's pin through the
  boot DTB host bridge `interrupt-map` (`narf_firmware_fdt::pci::intx_route`,
  level-high GIC SPI only) and binds `Line::bind_spi`. It clears INTx-disable
  only after the card initialized
  (`Mmio::enable_intx` with readback), so a failed probe leaves it parked.
  `Mmio::enable_dma` sets and reads back BME after `narf_bus::dma::configure`
  supplies the function's `DmaDevice`; from then the per-access and source
  policy require BME set, and `disable_dma` clears it with readback. Hosts
  of vendors with Linux `sdhci-pci-core.c` `pci_ids` fixes (Ricoh, ENE,
  Marvell, JMicron, SysKonnect, VIA, Intel, O2, Arasan, Synopsys, GLI,
  Realtek; `native::dma_quirk_vendor`) are refused the grant and stay PIO,
  since their DMA quirks (`BROKEN_DMA`/`BROKEN_ADMA`, `32BIT_ADMA_SIZE`,
  `NO_ENDATTR_IN_NOPDESC`, `BROKEN_64_BIT_DMA`, vendor DMA ops) are not
  carried; AMD's class fixes leave DMA generic. Range/alignment failure, revoked authority or invalid
  decode permanently closes the adapter. The private handle cannot be cloned.
- `native::register_function_driver(FunctionDriver)` registers up to 16
  exact `(function,vendor,device)` consumers. The matching callback receives
  the whole `NativeCard`, preserving shared F0/F1/F2 ownership. Registry
  locks are released before initialization and callbacks. Unclaimed cards
  are dropped and powered down; the host publishes no network interface.
- Dropping a `Card`, including initialization failure, disables status and
  signalling, stops the clock and removes card power; the controller then
  revokes any DMA grant before its buffers are freed. No caller pointer is
  retained; the descriptor table and bounce buffer are host-owned.

## 4. Invariants

Every buffer transfer finishes synchronously or fails before its borrow
ends. An R5 rejection cannot access BUFFER, even if readiness is asserted.
No retries follow a partially accepted transfer under the same controller
owner. PCI BME remains off throughout the PIO lifecycle and is set only by
an admitted DMA grant; a host DMA buffer is freed only after BME clear is
read back. The device sees only `DmaAddr`s of host-owned `narf_io`
buffers, each handed over with `sync_for_device` and returned with
`sync_for_cpu` in the request direction. SDIO command
execution does not clear card IRQ state as command completion. Bounds and
function checks precede COMMAND writes. No IRQ spin lock spans hardware
initialization, driver callback or async work.

## 5. Architecture notes

PCI MMIO uses `map_bar_control` and bus exact-width accessors, including
architecture device barriers. Divided clocks use powers of two on v1/v2
and every even divisor on v3; a saturated divisor that would exceed the
requested clock fails. Descriptor/bounce stores are fenced before the
ADMA address and COMMAND MMIO writes; streaming maintenance is `narf_io`'s
(x86_64 CLFLUSH; aarch64 DC CVAC/CIVAC on non-coherent paths, fenced per
invariant #4). On aarch64 a non-coherent host without a reserved coherent
pool fails `alloc_coherent_for` and stays PIO. With a per-domain IOMMU the
buffers' IOVAs are programmed. DMA is a data-path mode only: it changes no
bus clock, width, timing or signalling, so it adds no electrical/timing
qualification requirement of its own.

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
A DMA register model (`dma_tests.rs`) runs the selected engine against
real `narf_io` buffers: ADMA2 bounce write/read, sync direction, ADMA error
reset/PIO latch, R5 rejection under DMA, admission without caps/grant and
SDMA boundary restart/ADMA64; `sdhci/adma_tests.rs` covers mode selection,
32/64-bit descriptor layout, the 64 KiB split and align-buffer slots
(written, not yet executed).
They validate software contracts, not electrical/controller compatibility.

## 8. Open questions

Platform ACPI/devicetree enumeration, regulators/pin mux/clock/reset GPIOs,
vendor SDHCI quirks (including DMA quirks for the refused vendors),
zero-copy scatter-gather from caller DMA buffers, ADMA3/v4 mode, multiple
slots/card removal/reprobe, UHS-I, interrupt-driven command/data
completion and INTx for bridged hosts remain software work.
Physical PCI/SDIO acceptance, real card timing and cancellation/power-down
behavior require a target test after these software profiles are reviewed.
