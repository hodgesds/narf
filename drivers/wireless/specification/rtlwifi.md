# rtlwifi — Specification

> Status: retained RTL8188EE firmware, factory-qualified MAC/BB/RF/IQ/LC,
> signed channel/power, parked operational MAC and native polled packet/stop
> core are software covered. Station service and physical validation remain.

## 1. Purpose & scope

Owns diagnostic detection of RTL8188EE, RTL8192CE/DE/EE, RTL8723AE/BE,
and RTL8821AE. RTL8822BE belongs to rtw88 and is no longer matched here.

## 2. Assumptions

The caller owns the PCI function exclusively. Linux's per-chip `bar_id=2`
selects the register aperture. Diagnostic probe does not initialize packet
DMA, unmask device IRQs or report association success.

## 3. Public interface

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
through probe and the native worker's `MacConfigured` boundary; identity and
allocation alone do not authorize DMA. A repeat probe of the retained bus address
returns without configuration access; a distinct additional singleton match
parks only its own PCI function. Only the retained qualified packet owner below
has a one-shot transition that can enable BME.

`RtlwifiDevice::registers` is the mandatory BAR2 `map_bar_control` mapping;
it must cover through EFUSE access gate `0xcf`. Probe enables MEM decoding,
runs the profile power flow and reads factory identity with IRQs masked.
The mapping and actual power/IRQ/EFUSE operations execute inside the current
PCI `Cap::invoke` operation. The same invocation helper protects every native
firmware access; holding a retained token alone grants no register access.
MAC/LLT code is not dispatched as if a packet DMA owner already existed.

`efuse::read_mac(registers, pci_device_id, pci_function)` reads sparse physical
programming records and returns a nonzero unicast identity. The helper sets
read clocks, uses the appropriate access/power gate, triggers reads by clearing
bit 31, waits for it to set, allows data to settle and closes access on failure.
Programming LDOE25 is not enabled for a read.

| Profile | Unprotected physical bytes | Logical bytes | MAC offset |
|---|---:|---:|---:|
| 8188EE / 8192EE / 8723BE / 8821AE | 238 | 512 | `0xd0` |
| 8192CE and alternate ID | 497 | 128 | `0x16` |
| 8192DE function 0 / 1 | 497 | 256 | `0x55` / `0x5b` |
| 8723AE | 497 | 256 | `0x67` |

Unknown geometry/functions fail before I/O. Sparse-map bounds/overrides
share the checked Realtek record decoder. Scan, association and configuration
continue to return `NotSupported`; packet TX remains unavailable.

`power::run_with(io, cut, fab, interface, table)` is the production-shared
byte-register parser: selected rows preserve unrelated fields, PCI rows use
MAC base, register failures stop at the exact transaction, and unknown commands,
invalid delay units or missing END fail. `power_on_with` selects the flow.
RTL8188EE uses the complete Linux PCI NIC-enable flow, including
CardDisabled→CardEmu, BB reset, Schmitt trigger and LDO-normal. It first performs
the Linux XCK-output/HWPDN/reserved-register-unlock prefix. Other parts still
require their complete reset/power qualification.

RTL8188EE probe retains `firmware_transport::Owner<firmware_native::PciIo>`
before spawning `initialize_registered()`. `RtlwifiDevice::firmware_status()`
returns the shared attempt state; other profiles return None. Registry selection
uses exactly `rtlwifi/rtl8188efw.bin`, authenticated through firmware authority.
The complete 32-byte header, exact nonempty declared RAM-code length, 88E1
signature and at most eight 4096-byte pages are checked before allocation/I/O.
The EE filename remains mandatory because the signature alone cannot distinguish
USB EU firmware. Supplied-byte `initialize` is for authenticated owners/tests.

The one-shot owner closes CR HCI/TX/RX DMA and MAC packet gates and verifies
readback, enables the CPU clock, performs 8051 reset when replacing a running
image, writes selected 4KiB pages at MMIO0x1000 in bounded byte chunks, pads the
final dword and awaits fresh checksum plus firmware WINTINI readiness. It checks
reserved page-selector/CPU bits and stops on absent device, stale authority,
active BME or a short BAR. Every real MMIO operation occurs inside Cap::invoke
and validates MEM decoding with BME disabled. No raw authority/handle escapes.

States are Detected, Validated, Preparing, Downloading, Ready and terminal
Failed(error). The bounded attempt is self-driven/async, holds no IRQ-disabling
guard across await, and never invokes block_on in a spawned task. Cancellation,
timeout or write/checksum/start failure prevents retry and performs no cleanup
I/O. Ready means a running firmware CPU, with packet DMA/IRQ/station admission
still closed. The one-shot native continuation below does not dispatch
H2C/C2H or advertise HT/VHT support. The diagnostic interface remains down.

`prepare::Prepared<I, M>` is the RTL8188EE-only inactive descriptor/LLT owner.
It validates DMA32 full extents, alignment and overlap before MMIO, constructs
seven distinct linked 64-byte TX rings (DW10 next pointers, all OWN clear),
one 32-byte RX ring and separately retained 4096-byte RX buffers (DW6 address,
OWN/EOR). Exact Linux `_rtl88ee_llt_table_init` uses boundary0xab/max-page0xaf;
all seven queue bases and RX base use the 8188EE register map: BCN308, HIGH310,
MGMT318, VO320, VI328, BE330, BK338 and RX340. The retained owner uses explicit
EE-only constants, independent of the inactive generic8192EE scaffolds.
An oracle compiles actual EE `reg.h` definitions in `hw.c::init_mac` publication
order; the native device model also resolves those independently generated
addresses. The former8192EE base publication is a rejected packet-admission
regression. No 8192EE TXBD
count registers or aliased queue bases are used. BME stays off, PCIe DMA byte
0x301 stays0xff, CR packet gates and both interrupt masks remain closed.

The private `prepare_native` adapter claims one non-cloneable `PacketIo` from
the exact successful firmware owner. Failed allocation, cancellation and Drop
never reopen that claim. Every actual allocation/register access uses current
PCI authority and verifies parked bus mastering; unsupported per-domain IOMMU
mode is rejected. The controller and diagnostic interface share an async
mutex that retains the complete native owner before its first base write.
`RtlwifiDevice::native_preparation_status()` reports the retained Allocated,
Prepared, RadioConfigured, ChannelConfigured, MacConfigured or terminal Failed
state; the packet core additionally has Running/Stopping/Stopped phases.
None covers unallocated state (including allocation
failure) or initialization holding the async guard. Cancellation installs Failed before awaiting LLT. Published mappings
are retained on every error/Drop until a future reset/quiescence proof; no
firmware/reset helper may reconstruct a second packet owner.

`initialize_registered` now composes authenticated firmware boot with that
retained inactive preparation in the real probe worker, then continues through
`Prepared::configure_radio(profile)` under the same retained async owner.
`efuse::Factory` retains the complete decoded logical map alongside its validated
MAC. The radio profile checks EEPROM8129/VID10ec/DID8179 and applies Linux's
HP197d RF52 override only for default-customer103c:197d factory identity.
Other silicon is not dispatched through this continuation.

The radio continuation loads all90 MAC,191 BB,128 AGC and95 RF table rows,
including exact50ms RF settling intervals, and retains all88 PG triples for
the later channel-power owner. It uses 8-bit-address/20-bit LSSI and the actual
HSSI edge/readback protocol, with 10/120us waits and PI/SI register selection.
The previous unused family scaffolds do not supply any of these operations.
The factory antenna type and HP identity select Linux's static MAIN/AUX path
before IQK; dynamic antenna selection is outside this fixed measured profile.
Single-path IQK backs up and restores MAC/ADDA/BB state, performs bounded TX
and RX retries over up to three samples, compares Linux's tolerance and fallback
candidates, applies the signed TX/RX matrix and retains recovery registers.
Missing/unstable TX or RX measurements fail rather than reporting calibrated
hardware through Linux's TX-only/default fallback. LCK follows Linux's paused
or continuous-TX sequence and its100ms calibration interval; elapsed time alone
does not establish physical oscillator convergence.

The one-shot transition installs terminal Failed before its first await and
commits `RadioConfigured` plus `radio_report()` only after all operations and
final parked-gate checks succeed. Every native register still executes under
current PCI authority with BME off. PCIe DMA0x301 staysff, CR packet gates and
both interrupt masks stay closed; error, cancellation and Drop retain all
published mappings. Repeated configuration does no I/O. An independent C oracle
executes original Linux calibration functions; the register/RF model checks its
complete write/delay trace, signed matrix, HP variant, factory negatives,
transaction failures and cancellation at RF/IQK/LCK waits.

`RadioConfigured` remains below full MAC operational configuration, active
packet ownership and station admission. It cannot scan, transmit ordinary
packets, associate or raise carrier. Physical table/calibration acceptance
remains unvalidated.

`Prepared::configure_channel(permission)` continues the retained owner through
the initial legacy1T20 profile on channels1–11. PathA factory gains come from
all six CCK bases, five BW40 bases and signed OFDM nibbles; per-rate PG groups
follow the EEPROM regulatory mode. Erased gains or signed arithmetic outside
the hardware range fail before I/O instead of selecting defaults or wrapping.
The original Linux EFUSE/PG functions independently generate192 numeric cases.
The driver does not use Linux's scan turbo, HT rates or thermal gain boosts.

Raw gain indices and Linux's index-to-dBm reporting estimate do not establish
an EIRP bound. `channel_power::Calibration::load_registered` reads exactly
`rtlwifi/rtl8188ee-cal-v1-<factory-mac-as-12-hex-digits>.bin` through current
firmware capability invocation and requires an authenticated signer. The
artifact qualifies the complete board operating envelope for fixed legacy20,
1T1R, continuously awake software-crypto operation without gain tracking.
It binds VID10ec/DID8179, the MAC and SHA256(MAC || full512-byte decoded EFUSE
map), including channel-plan, power, antenna and thermal identity. EU/other-bus
artifacts cannot supply this permission.

The NEPC v1 blob has a96-byte little-endian header: magic[4], version:u16,
header-size:u16, total-size:u32, VID:u16, DID:u16, factory-digest[32], MAC[6],
reserved[2], nonnegative antenna upper bound:i16 in quarter-dBi, qualified
EIRP upper bound:i16 in quarter-dBm, row-count:u16, profile:u16=1 and reserved[32].
Each260-byte row contains channel:u8, reserved[3], and64 signed quarter-dBm
conducted upper bounds for each CCK and OFDM gain index. Unknown bounds are
INT16_MAX; channels must be strictly increasing and within1–11. These are
measured conservative upper envelopes across the qualified operating range,
not curves inferred from factory indices or another chip.

Each final rate gain is bounded by the exact factory/PG result, the matching
measured envelope plus antenna gain, the artifact EIRP ceiling and every
overlapping signed host rule, with an independent20dBm ceiling from Linux's
`RTL819x_2GHZ_CH01_11` shared by every retained channel-plan/world mapping.
Neither a board signer nor a more permissive host rule raises that bound.
Partial-span, unsupported flags, absent curves
or an uncovered channel deny TX permission. The opaque permission binds the
same retained radio report's full factory identity. A mismatched grant does
no device access; accepted programming installs terminal Failed before await.
Actual CCK/OFDM gains, MAC/BB20MHz and RF18 channel are read back before
`ChannelConfigured` is committed. MCS slots are zero and no HT packet profile
is admitted. TX remains paused, BME/PCIe DMA/CR packet gates and IRQ masks
stay closed. Missing staged calibration/policy leaves the native worker's
radio owner retained and without channel/transmit admission. Initial worker
qualification selects channel1; later station control must obtain its own
matching channel permission. Cancellation/failure never commits a permission
or reuses the uncertain owner.

`Prepared::configure_mac(factory)` checks the same opaque factory identity and
continues `ChannelConfigured` to `MacConfigured` without opening packet gates.
It supplies the remaining operational clock/watchdog/queue/MAC prefix, exact
legacy receive/transmit configuration, legacy response rates and factory MAC.
Host sequence numbers, software crypto and no early-mode prefix are explicit;
CAM encryption/decryption and both interrupt masks stay disabled. Readbacks
qualify all stable configuration fields. Linux's `efuse_read_1byte(0x1fa)`
PA-bias call is guarded by this chip's256-byte physical geometry and returns
ff without I/O, so no out-of-range/protected-tail read or bias write is invented.
The real probe worker reaches this boundary after signed board/channel policy.

`prepare::packet` extends that same retained owner, rings and unique `PacketIo`.
Its crate-private `start_packets` validates actual retained descriptor links,
DMA32 addresses, base registers, RX postings and operational MAC readbacks before
the one-shot current-capability BME transition and CR/PCIe DMA opening. Device
IRQs stay masked. This is a bounded polling transport core; the registered
diagnostic netdev still has no station service and remains down.

Management and non-QoS legacy data use distinct retained rings. Linux queue
IDs MGNT6/BE1 supply doorbell bits64/2; allocation-vector indices1/4 never
substitute those IDs. One pending native payload is retained before OWN
publication, along with its exact queue, slot, serial, length and address.
The host copies through the actual retained DMA mapping and preserves DW10's
linked-next pointer. Terminal OWN clear is checked against stable descriptor
identity, and the delivery carries bytes read from that retained payload.
This is terminal host/DMA delivery, not an AP acknowledgement. Independent C
receipts execute original Linux descriptor setters and `rtl88ee_tx_polling`;
the device model reacts to actual published descriptors/body, including ring
wrap. It does not complete from a saved encoder/source byte vector.

RX reads OWN-cleared32-byte descriptors, checks retained DW6 address/high-word,
EOR, complete length/driver-info/shift extents and current fixed channel. It
rejects CRC/ICV, fragments, aggregates, HT/40MHz and non-normal report types.
Protected MPDUs require the native SWDEC bit; open frames may legitimately
have it clear. It retains original MPDU bytes for shared station security,
removes the four appended FCS bytes and reposts the same owned buffer only
after processing/copy and device barriers. Malformed ownership/address/extent
data is terminal. Invalid ordinary packet profiles are consumed without
admitting bytes to management or security.

`wait_delivery` installs terminal Failed before its first actual wait; timeout,
cancellation, stale PCI authority or descriptor rebinding cannot reopen TX or
release pending DMA. `stop_packets` closes host admission first, attempts all
independent IRQ/TX-pause/CR/PCIe-DMA/BME gates and verifies the accessible
readbacks. Success commits terminal `Stopped`, with no reuse/restart. Every
published ring/RX buffer and pending payload remains retained on stop, failure,
cancellation and Drop: parked BME is not claimed as a prefetch-quiescence or
reclamation proof. The next station facade must invoke this terminal stop on
all association/disconnect/error paths; transport readiness alone raises no
carrier or controlled port.

## 4. Invariants

Read requests never set the programming trigger. Preserve unrelated EFUSE
address/control and SYS-clock bits. Exclude protected physical tails, reject
truncated/outside records, and never register an invalid factory identity.

## 5. Architecture notes

BAR mapping and byte-order conversion are architecture independent. Shared
register-model smokes cover every matched geometry and both dual-MAC functions.

## 6. Dependencies

Bus/PCI ownership, MMIO and firmware registry follow their subsystem contracts.
The scheduler's responsive wait supplies bounded EFUSE completion/settling.

## 7. Stage assignment

Factory identity, RTL8188EE CPU firmware, inactive LLT/linked-ring preparation
and retained factory-qualified table/IQK/LCK continuation are software covered.
Complete station software and physical
board qualification remain required.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| Correct BAR2/read-only EFUSE lifecycle and per-chip identity | Implemented; shared-path regressions |
| Complete source-matched per-chip power/reset qualification | RTL8188EE PCI enable prefix/flow implemented; other families remain incomplete |
| Authenticated image/header selection and runtime firmware loading | RTL8188EE retained probe owner implemented; other profiles missing |
| DMA allocation/publication/quiesce, IRQ ownership, H2C/C2H | RTL8188EE retained DMA32 linked rings/LLT, one-shot active polled core, exact terminal host delivery and terminal gate-close/retention implemented; station/native service integration remains. Reclamation/reset/recovery and optional IRQ/H2C/C2H work remain |
| RF/BB tables, calibration, channel/power and rate control | RTL8188EE complete tables/retained1T IQK/LCK, static factory antenna, signed board/factory/regulatory legacy20 channel power and parked operational MAC implemented; negotiated peer/rate/filter integration remains. Optional gain tracking is excluded by measured profile |
| Scan, management RX/TX, authentication/association and WPA2 | Missing |
| Ethernet packet path and terminal TX completion ownership | Native raw-MPDU terminal ownership implemented; shared station-security and Ethernet/DHCP/IP service composition remains |
| Multi-radio, removal, suspend/reset/recovery | Missing |

References: Linux `rtlwifi/efuse.c`, per-chip `sw.c`/`reg.h`,
`rtl8192d/hw_common.c` dual-MAC selection, and per-chip firmware/HW code.
