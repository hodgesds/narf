# rtw88 — Specification

> Status: **v1.6** (RTL8821CE retained firmware/MAC/PHY, separately signed IQK/parked-power/awake-station, legacy12/WMM, exact-chip HT20/SGI, separately qualified RX/TX Block Ack and native RTS-threshold continuations; RTL8822CE retained firmware, MAC/PHY, bounded radio calibration,
> signed operating-power qualification, native packets and channel1 station
> integration; composed software gates and physical acceptance remain distinct).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** PCI matching, baseline power-on, and factory identity for
RTL8821CE / RTL8822BE / RTL8822CE, plus the retained RTL8821CE firmware/inactive
MAC/PHY-table owner with separately qualified IQK, parked-power and native
awake station continuations, and RTL8822CE native firmware
loader, MAC/FIFO/PHY, H2C, calibrated radio/board-power continuations and a
single awake channel1/20MHz station for RTL8821CE/RTL8822CE. Each retained station
supports Open and WPA2-PSK with host RSNA/CCMP; its ordinary host TX rate is
fixed at1Mbps by default and requires an AP advertising that basic rate.
RTL8821CE/RTL8822CE can separately qualify response-bound legacy12 DATA rates
and WMM BE/TID0, then distinct HT20/one-stream MCS0..7/SGI20 with mandatory
default A-MSDU receive and native ADDBA refusal, plus distinct optional recipient
and BE/TID0 originator Block Ack grants; management and EAPOL remain
at1Mbps. N21S alone does
not admit the C21 extension, and neither chip can reuse the other's assets.
The probe decodes physical EFUSE programming
records to obtain the correct PCIe MAC.

**Does NOT own:** Trusted deployment policy, measured board calibration
artifacts or their signing authority. Factory country hints supply no policy.

## 2. Assumptions

The caller owns the PCI function and its BAR2 register aperture exclusively.
`pci::bring_up` maps BAR2 with `map_bar_control` (Device memory attributes)
and rejects windows smaller than `0x170c` for RTL8821CE/RTL8822BE/RTL8822CE
(firmware LTE indirect data) before MMIO. Chip/cut-filtered
PCI power enable/disable tables and pre/system setup now follow Linux's
actual flows. BAR2 is mandatory and is a control-register window. The
device has no active firmware/packet DMA or IRQ handler during this reset.
The initial native DMA profile requires physical/identity DMA addressing;
per-domain IOMMU translation is rejected before allocation or MMIO.

## 3. Public interface

`FirmwareInfo` retains the original header `subindex: u8` and
`features: u32` alongside version/subversion/H2C/section geometry. As in
Linux7.3-rc4, feature bits are zero unless `FW_FEATURE_SIG` bit0 is present.
These are authenticated image observations; they confer no sleep/wake or RF
readiness. The power-mode codec keeps the existing ACTIVE initialization
bytes unchanged. Its reserved-page and CPWM/RFON/TCR helpers are prerequisites;
they do not activate native runtime sleep.

`reset_function(BusAddr) -> Result<(), OperatingResetError>` recovers the
original retained RTL8821CE/RTL8822CE station generation. It serializes with
that function's provisioner, checks the original exact PCI identity/capability,
then reserves the same BDF against ordinary probes and other resets. The old
station may already have closed its port, but must still be its retained
StationReady lifecycle; a previously removed/unproven lifecycle is rejected.
It synchronously withdraws original admission, waits for unlocked native
RX/stack callbacks, and uses the actual original lifecycle's TX-index/RXDMA
idle proof before releasing its buffers. Only successful retirement produces
the noncopyable one-use `Retired` precondition for native card recovery.

Recovery follows Linux7.3-rc4 `main.c::rtw_core_stop`/`rtw_core_start` and
`mac.c::rtw_mac_power_switch`: actual chip/cut-filtered card-disable and
card-enable commands, including real source polls. It requires an active CR
and refuses an unexpected already-off card before writes, checks CR0xea after
disable and a non0xea/non0xff CR after enable, and keeps original PCI bus
mastering and IRQ publication closed. It then rereads physical EFUSE and
requires the same factory MAC/chip/BDF before constructing a fresh cold
firmware shell. It grants no power/association right from BME closure alone.
Every actual recovery power/factory MMIO access invokes the original PCI
capability and reset reservation with actual parked PCI-command readback.
Denial sticks for the whole one-shot sequence; waits break on source loss,
and later retry/system/factory writes cannot proceed after cap revocation
or hot removal. Existing failure cases revoke the actual cap or request
function removal during a power poll and require no subsequent enable/setup.

The original function reservation remains held throughout. Cancellation,
failed native idle/power/identity receipts or hot removal quarantine it and
prevent a fresh producer; removal racing reset is recorded before publication.
Success publishes a fresh nonreused endpoint cookie and queues ordinary
provisioning. That new generation must earn its own current firmware/hardware
report, calibration, board-policy and optional continuation receipts. No old
admission, key, PN, BA state, descriptor, interface handle or unlocked callback
can become authority for it. Late old cleanup cannot remove the replacement.
The cold shell has a newly reserved netdev name, and success does not await
provisioning or associate automatically; callers can await `provision_function`
and explicitly supply fresh association credentials. Stable-name reassociation
uses `rejoin_function` below; system PM and credential replay remain separate
work. Six source-written cases
cover source power/false-state receipts, actual native firmware/CCMP/DHCP owner
replacement and failed RXDMA, plus exact registry cancellation/hot removal.
Their release/native execution and physical acceptance remain pending.

`rejoin_function(BusAddr, AssociateRequest) -> Result<(), RejoinError>` adds
explicit safe rejoin on the admitted C21/C22 channel1 Open/WPA2 profiles. It
validates the caller's request before reset and keeps its PMK in zeroizing
storage across pending reset/provisioning. It retires the original netdev for
rebind only after all old unlocked ingress callbacks finish; the existing
`net::iface` mechanism retains the exact name, ifindex, operator state,
addresses and counters. The original endpoint cookie, registration and native
source retire permanently. Ordinary reset still allocates a new name.

Rejoin uses the confirmed native reset boundary above, then fresh ordinary
firmware/calibration/policy provisioning and an actual fresh passive scan of
the caller's BSS. The exact replacement function is checked across awaited
steps, and its per-function provisioner excludes another reset through the
new association. A new host key exchange and actual M4 terminal receipts
open the port. No old credentials, supplicant, key, PN, BA agreement, grant
object or descriptor is replayed. The caller explicitly supplies its Open or
WPA2 request; automatic credential replay remains absent.

Before scanning, the exact new registration's original UP observation binds
a fixed weak, nonreviving native lifetime to its retained power Gate. This
observation supplies no RF/device grant: original PCI/calibration/policy
invocations remain mandatory. Actual native packet/batch publication and
unlocked delivery also check this lifetime, including after descriptor writes.
An operator DOWN, retirement or replaced registration permanently denies that
owner even if the name later returns UP. Cancellation or any failed awaited
step closes only the captured fresh admission and retains ambiguous native
DMA; late old replies cannot resurrect it. Late old cleanup cannot address
the new name's carrier. Four native source cases cover Open/WPA2 stable-name
DHCP, terminal-disconnect recovery/fresh keys, held-M4 cancellation, original
DOWN between descriptor/doorbell, old ingress and preserved operator DOWN.
They await release/native batch execution and physical acceptance.

`idle_function(BusAddr) -> Result<RuntimeIdle, DevicePmError>` supplies explicit
unassociated IPS for actual C21/C22 identity-DMA passive stations. The retained
owner mutex serializes the real passive/no-peer eligibility check, original
function reservation and admission closure against scan/join. Associated or
busy stations are refused before withdrawal. The durable worker then withdraws
original callbacks/endpoints, proves native DMA retirement, and runs actual
card-disable to CR0xea. It saves the original parked PCI configuration without
requiring a PCI PM capability or changing to D3. It does not enable ASPM or
claim a system wake source.

The `RuntimeIdle` handle observes completion and requests resume; its boolean
status grants no hardware authority. `resume(self).await` and handle Drop
request the same retained background worker. Both async public operations
require normal executor polling: neither `block_on` nor `block_on_spin` drives another
scheduler task. Cancelling a foreground waiter
cannot drop an in-progress native retirement. Fresh startup consumes the actual
card-off/retirement receipts and restores the original name/ifindex/operator
state through ordinary provisioning. No old keys, admission or endpoint revive;
association remains explicit. Failed native receipts quarantine the original
function and retain ambiguous DMA. Three native model cases are written for
passive off/fresh-start/DHCP, associated refusal with preserved DATA, and
foreground cancellation during original ingress; release/native acceptance
remains pending. `idle_function` has no in-tree production trigger yet
(Linux `rtw_ips` on interface down / unassociated idle).

`lps_request_function(BusAddr)` returns the separately signed continuation
request for `lps_function(BusAddr, milliseconds) -> Result<(), RuntimeSleepError>`.
The latter supplies explicit nondeep associated LPS for the original completed
CCK1 channel1 C21/C22 station. Requested residence is1..100ms; scheduler delays
and bounded source polling remain part of the async operation. Linux
`LPS_DEEP_MODE_NONE` keeps MMIO alive; no LCLK, PG, WoW, ASPM or HT/BA/tracking
combination is inferred. The separate N21Z/N22Z128v1 record uses the generic
continuation format, stem `lps`, tag Z and payload byte0=1/rest0. It attests the
complete PS-Poll/Null/download/RFoff-on/automatic response/retry/transient
program against the exact retained base envelope over its full thermal/supply/
antenna/coexistence conditions. Earlier awake records do not authorize it.

The original retained owner mutex excludes other packet/control transitions.
The actual association supplies own/AP/AID, and an original nonreviving UP
identity plus the original receive/key epoch enclose every native operation.
The existing completed/disarmed beacon mapping uploads dummy/PS-Poll/QoS-Null/
Null pages through the original native DMA owner. Fresh BCN_VALID, device
fences, exact base/boundary/queue checks and final current source after OWN
before the physical doorbell precede mapping disarm and register restoration.
Cancellation or ambiguous completion leaves the mapping retained.

Mailbox consumption is transport only. The actual TCR power-management bit
must become set after the source LPS H2C. Before ACTIVE/wake H2C, all old
native RX prefix and stale RFON are consumed. Fresh C2H_WLAN_RFON is required
when the original signature-gated firmware feature advertises it; TCR must
actually clear and RX must reach idle before DATA resumes. Original RF/TXAGC/
automatic-response readbacks must match before entry and after awake. No host write
fabricates a wake receipt. Captured DATA/EAPOL/CCMP remains private until
confirmed awake, with original keys/PN untouched. Peer loss, source/UP/key
loss, cancellation or failed wake closes the old station; confirmed reset/
rejoin supplies any replacement.

Each PS H2C (locations, LPS entry, ACTIVE wake) uses the PS-only native
`Io::ps_mailbox_submit` through the retained `Backend` and `Registers`, never
the ordinary `mailbox_submit`. Mirroring Linux fw.c
`rtw_fw_send_h2c_command`, it checks the HMETFR box and base permission,
stages HMEBOX_EXT, then reruns the original PS source (PCI publication, UP,
receive/key epoch, N2xZ grant) around one final native check immediately
before the HMEBOX low-word write that publishes the command: HMETFR box
still free, no command-ring work, the actual Core RX-prefix receipt
(`maintenance_quiet`: RX idle and hardware RX index equal to the consumed
host index, plus TX host/device and native TX indices) and base permission.
If RX/TX advanced, the result is `PsSubmit::Unissued`: extended-only staging
is not a command, the mailbox stays free and the caller retires that prefix
through the private LPS collector (peer loss/key/control still deny) before
staging again. Before entry a changed or nonidle peer returns `Busy` with
nothing issued and the original station stays open; the wake command retries
within its bound. Source loss before the low word is an unissued error that
closes the station. After the low word is written only consumption is
polled; an error there marks the native owner terminal and is never retried.

Eight actual C21 retained-reserved-DMA/native Device cases are written for
Open/WPA2 DHCP, stale RFON/TCR and restored-power failures, final source/UP
loss after OWN, native-page cancellation, private CCMP RX, peer/source loss
in the HMEBOX_EXT/low-word gap of LPS entry, and RX in the wake-command gap
(restaged and published exactly once, DATA retained). They are unexecuted
pending batch validation.

Production trigger (`interface.rs`): the shell advertises `SUPPORTS_PS`
(`power_save_default`/`set_power_save`, main.c `SUPPORTS_PS` |
`SUPPORTS_DYNAMIC_PS`, PS off by default) only when activate found a nondeep
LPS firmware profile and a loadable N2xZ record (`Owner::lps_capable`).
`set_power_save` is `rtw_recalc_lps` (`ps_enabled`). `Device::watchdog` runs
`lps_watchdog` after the dm period: every 2s (`RTW_WATCH_DOG_DELAY_TIME`)
with power save on, the link up and at most `RTW_LPS_THRESHOLD` (50) data
frames each way since the last period (main.c `rtw_watch_dog_work`
`!ps_active`), it runs one 100ms `Owner::lps_window` under the original UP
identity, the same operation as `lps_function`. Linux stays in LPS until
traffic; NARF sleeps one bounded window per period. Refusal (`Busy`/
`Unsupported`: peer/queues busy, `wl_force_lps_ctrl`, a continuation-bound
station, no N2xZ record on this channel) leaves the station open; a failed
window has closed it and the shell drops the link. Case
`smoke_rtw88_power_save_interface_follows_lps_capability` (written,
unexecuted) covers the interface and the `ps_active` threshold.

The `rtw88` asynchronous system-PM hook covers the retained C21/C22 identity-DMA
profiles with an actual PCI PM capability in D0. A family barrier retains the
exact original function snapshot and excludes new probe/reset producers until
all suspend workers finish resume or reach terminal state. Busy provisioning
and unsupported PM state are refused before withdrawing the original shell.
Diagnostic C22B chip rows do not gain a runtime from this hook.

Each durable worker, independent of the foreground suspend waiter, owns the
original function reservation through actual callback/native DMA retirement,
source card-disable with CR0xea receipt, saved parked PCI configuration and
real PMCSR D3hot entry/readback. It waits the bus API's10ms settle interval
without config or MMIO access. Source cap/removal loss stops later operations;
an unproven old DMA owner stays pinned and cannot produce a parked receipt.
Cancelling or failing foreground preparation requests rollback; it does not
drop the in-flight native retire future. The family barrier stays retained
until the workers complete that rollback. Suspend status never constructs a
hardware, reset, DMA, power or RF grant.

Resume checks actual D0 after its settle interval, restores original BAR/ROM
and command state with bus mastering off and INTx disabled, and verifies the
restored values. For actual C22 RFE6, Linux `rtw_pci_clkreq_pad_low` is ported
as an original-source DBI byte transaction at0x719: exact0x718 read address,
byte1 WREN0x2718, actual busy-flag completion and final readback. Suspend clears
CLKREQ_N_PAD, resume sets it, preserving all other bits. No DBI transaction is
inferred from an iteration count or silently treated as successful.

The real retained card-off receipt is consumed by fresh cold bring-up on the
same factory MAC/chip/cut/BDF and original netdev name/ifindex. A still-off
card runs enable; firmware that powered it during S3 must complete a new
observed disable/enable cycle. A previously operating station must finish
fresh firmware/hardware/calibration/policy provisioning before resume reports
success. A previously unqualified cold shell may retain only an actual stable
parked checkpoint while deployment assets remain absent; it gains no RF or
packet admission. Failed fresh startup
is withdrawn and quiesced, with uncertain DMA pinned. Old admission, cookies,
keys, PN/BA state and queued frames never reopen. Resume leaves a fresh passive
station; the SME explicitly supplies a new association. WoW, D3cold board
power-resource discovery and automatic credential replay remain separate.
The framework supplies the platform sleep/wake transition.

Six native source cases cover actual old-DMA/card-off/fresh-firmware and
explicit WPA2/DHCP on the preserved ifindex, foreground cancellation during
old ingress, failed RXDMA/token reuse, literal DBI/readback/source loss, and
the real family probe/reset barrier. They are written pending release/native
batch execution; actual S3, PCI/clock behavior and deployment RF acceptance
still require physical validation.

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every identity error; identity and ring allocation do not authorize
DMA. `pci_park::invoke` places the actual parking, BAR mapping, power and
EFUSE operations inside the current PCI capability invocation. The shared
helper is also used by rtlwifi firmware MMIO; a real revoked-cap regression
proves the register callback is not entered after revocation.
A non-spinning RAII reservation for each exact BDF covers the complete
synchronous probe transaction from admission through power, retained
controller/interface publication and spawn. Overlapping same-function probes
return `BadDevice` without PCI/MMIO access; a repeat fully retained function
is observational. Additional functions acquire independent reservations before
hardware access, bounded to four retained BDFs including DMA quarantine. The RTL8822CE firmware owner may later enable BME only after retaining
and checking every host ring, with firmware-only beacon DMA runnable.

`Rtw88Device::registers` holds the single mandatory BAR2 control mapping;
there is no separate firmware data BAR. Mapping/short-window failures are
reported as `ProbeError::{RegisterBarMapFailed, RegisterBarTooSmall}`.

`power::power_on(registers, pci_device_id)` detects the silicon cut,
rejects unknown cuts/absent hardware, runs cold-card enable or the warm
disable/enable cycle, and preserves unrelated register fields. PCI polling
uses a bounded responsive wait and the Linux PFM_WOWL retry. Cut-C-only
8822B rows remain cut filtered. This stage does not enable station traffic.

`efuse::read_mac(registers, pci_device_id)` returns a validated, nonzero
unicast factory MAC or `EfuseError`. Unknown PCI IDs fail before MMIO;
the ID selects both logical-map geometry and read-power controls:

| PCIe chip | Physical bytes | Protected tail | Logical bytes | MAC offset |
|---|---:|---:|---:|---:|
| RTL8821CE | 512 | 96 | 512 | `0xd0` |
| RTL8822BE | 1024 | 96 | 768 | `0xd0` |
| RTL8822CE | 512 | 124 | 768 | `0x120` |

For RTL8822CE, `efuse::read_factory` retains the complete768-byte logical
map from that same physical read in the exact `Firmware` owner. `Factory`
exposes the actual PCI MAC, RFE, raw crystal, board/BT options, channel-plan
hint, country hint and both thermal values; the original four packed42-byte
power-path records remain available to the radio continuation. Raw erased
fields stay `0xff`; identity discovery supplies no calibration defaults or
transmit authority. Factory country/channel hints cannot replace the trusted
deployment regulatory policy or measured per-board power qualification.
Nineteen separate source-defined protected OTP cells retain the actual thermal,
2G/5G gain and PA-bias trims. Those explicit bounded raw reads are distinct from
sparse-map decoding; protected cells can never be interpreted as map records.
The same current PCI invocation covers the original map and trim capture.

For RTL8821CE/RTL8822CE, `bring_up` creates one named, unpublished station shell sharing
the exact `Arc<Lifecycle>` retained by the firmware owner. Probe acquires frame
registry authority and registers the shell in the frame, kernel IP and wireless
registries before spawning the firmware worker or activating packet DMA. The
controller view delegates control, carrier and frame rings to this same shell.
Carrier stays down until actual peer association and security admission.
The driver name follows the actual retained chip. RTL8822BE keeps its diagnostic
static interface (wireless controls and packet TX unsupported) while its
retained native B22 owner runs (see "RTL8822BE retained native B22 owner"). A C21 shell stays inactive
until its complete separately qualified chain succeeds.
`Rtw88Device::firmware_status()` returns its
`FirmwareStatus { stage, info, error }`; `FirmwareStage` is `Detected`,
`Allocating`, `Loading`, `Ready`, `PreparingMac`, `MacPrepared`,
`PreparingPhy`, `PhyTablesPrepared`, `PreparingCalibration8821c`,
`Calibration8821cPrepared`, `PreparingOperating8821c`, `Operating8821cPrepared`,
`PreparingRadio8821c`, `Radio8821cPrepared`, `Calibrating`, `Calibrated`,
`StationPreparation`, `StationReady`, or `Failed`. `Ready` identifies firmware
completion and parked host DMA, independently of station/radio readiness.
`StationReady` identifies completed packet preparation, not an associated peer
or authorized controlled port. RTL8822BE firmware runs in its own B22 owner. The safe
`fw::download_firmware(registers, pci_device_id)` helper returns
`FwError::Unsupported` before registry or MMIO access for every device:
raw MMIO alone cannot prove exclusive DMA/ring/reset ownership.

### RTL8822BE retained native B22 owner

`10ec:b822` is the third native chip ("B22"), structured like C21/C22 and
sharing none of their assets. Probe runs the 8822B card-disable→enable power
tables, then one 1024-byte physical EFUSE read (96 protected bytes excluded)
decoded into the distinct 768-byte `efuse8822b::Factory8822b`
(`rtw8822b.c::rtw8822b_read_efuse` over `struct rtw8822b_efuse` /
`rtw8822be_efuse`): PCIe MAC `0xd0`, whole-byte `rfe_option` `0xca`,
`regd = rf_board_option(0xc1) & 7`, crystal `0xb9`, thermal `0xba`, PA `0xbc`,
LNA `0xbd`/`0xbf`, channel plan `0xb8`, country `0xcb`, USB mode bit7 of
`0x06`, and four raw 42-byte `txpwr_idx_table` records from `0x10`. Erased
fields stay raw; country/power fields grant nothing.
`Rtw88Device::rtl8822b_factory()` exposes it.

`native8822b::Owner8822b` retains the exact cold function/cap/BAR, that
factory map and a `Lifecycle` keyed by `0xb822`. Its scheduled continuation
retries only while `Detected` (firmware registry not yet populated), then
loads `rtw8822b_hw_spec.fw_name` = `rtw88/rtw8822b_fw.bin` through the
authenticated registry and the shared beacon-DMA/IDDMA owner
(`mac.c::__rtw_download_firmware`, WCPU 3081, LTE-coex 0x38 backup). RTL8822B
and RTL8822C share the `0x8822` header signature; the PCI identity selects
the layout. The installed B22 image places IMEM at OCP `0x0` (header
`imem_addr` `0x80000000`, bit31 masked as in `start_download_firmware`), so
B22 admits exactly DMEM `0x200000`/IMEM `0x0`/optional EMEM `0x100000`; the
C22 IMEM `0x30000` profile rejects it and vice versa.

The same retained owner then runs the inactive MAC continuation
(`mac::prepare_on(0xb822)`): shared `rtw_mac_init` FIFO/LLT/H2C-queue setup
with the `rtw_set_trx_fifo_info` B22 layout (2048 pages, `csi_buf_pg_num` 0,
`rsvd_drv_pg_num` 8 → reserved boundary 1996, H2CQ 2036, firmware TXBUF 2044;
PCIe `page_table_8822b[1]` 64/64/64/64 and `rqpn_table_8822b[1]` equal to
C22's), then `rtw8822b_mac_init` (`mac/rtl8822b.rs`: `BIT_PRE_TX_CMD` clear,
no 8821C PRECNT/INIRTS/ACKTO_CCK/TRXPTCL writes, no C22 `0x3fc` quirk). As on
C21/C22, TXPAUSE stays `0xff` and host DMA/MAC TX/RX stay closed. The owner
then runs the PHY table continuation (`phy8822b`, `Lifecycle::prepare_phy8822b`)
from `rtw8822b_phy_set_param`: BB/RF domain power-on (`SYS_FUNC_EN` BB bits,
`RF_CTRL` 7, `WLRF1` BBRF), `RXPSEL` reset hold, `rtw_phy_load_tables` in
MAC (byte) → BB (delay codes `0xfe..0xf9`) → AGC → RF-A → RF-B order (8822B
has no `rfk_init_tbl`), RF rows through `rtw_phy_write_rf_reg_sipi` at
`0xc90`/`0xe90` (13 µs), crystal cap `& 0x3f` into `0x24[30:25]`/`0x28[6:1]`,
and `RXPSEL` release. Rows are `rtw8822b_table.c` verbatim, preselected by
`phy/gen_rtl8822b_tables.py` with `rtw_parse_tbl_phy_cond`/`check_positive`
for PCIe (pkg 15 since 8822B sets no `pkg_type`, cut 0 → 15) over all 16 cuts
and the only `rtw8822b_rfe_defs` RFEs 2/3/5 (17 distinct tables, 48
profiles). Other RFEs, an erased crystal/board option or a non-2T2R firmware
report are refused. The same stage then runs the `rtw8822b_phy_set_param`
tail (`radio8822b::finish_set_param`): `rtw8822b_config_trx_mode(BB_PATH_AB,
BB_PATH_AB, false)` (AGC/CDD/TX-RX path select, MRC, the RF-mode LUT write
after the bounded 100-try `RF_LUTWA` readback poll — refused with
`Error::Timeout` where Linux only WARNs — `rtw8822b_toggle_igi`, ch1/20 CCA and
the `rtw8822b_rfe_info` RFE program for `hal.current_channel` 0, i.e. the 5 GHz
branch), `rtw_phy_init` (IGI history from `rtw8822b_dig[0]`,
`rtw8822b_adaptivity_init` EDCCA 0x7f/0x7f), `rtw8822b_phy_rfe_init`,
`rtw8822b_pwrtrack_init` (`default_ofdm_index` from 0xc1c against
`rtw8822b_txscale_tbl`, else 24) and `rtw8822b_phy_bf_init`
(`bf::phy_init` + 0x1c94 `0xafffafff`); `phy8822b::Info` retains IGI and
`default_ofdm_index`. RF access uses the 8822B direct window 0x2800/0x2c00
and SIPI 0xc90/0xe90 only. `radio8822b::set_channel` ports
`rtw8822b_set_channel` (`_bb`, `rtw_set_channel_mac` on the 3081 WCPU, `_rf`
with RF18 on both paths and the RF 0xbe band table, `_rxdfir`, IGI toggle,
`_cca` per RFE 2 I2GE5G / RFE 3,5 IFEM_EXT and cut B, `_rfe_efem`/`_rfe_ifem`)
for 2.4 GHz 20/40 MHz and 5 GHz 20/40/80 MHz centres; centres outside
`IS_CH_*_BAND`, the `0xff` RFBE table holes, malformed sub-channel indices and
2.4 GHz 80 MHz are refused before any register access.
`radio8822b::write_txagc` ports `rtw8822b_set_tx_power_index_by_rate` (0x1d00 /
0x1d80 + `rate & 0xfc`, the twelve CCK/OFDM/HT1S/HT2S/VHT1S/VHT2S words; HT3S/
HT4S words are never written) for caller-supplied coded indices ≤ 0x3f.

#### RTL8822BE signed calibration-only IQK (`N2BQ`)

From `PhyTablesPrepared` the owner runs `rtw8822b_phy_calibration` =
`rtw8822b_do_iqk` only inside a signed, measured `N2BQ` envelope
(`calibration8822b`), the B22 counterpart of C21's `N21Q`: the same 128-byte
layout (`N2BQ`, version 1, length 128, PCI header `10ec:b822`, 32-byte board
identity, factory MAC, channel 1 / 20 MHz, quarter-dBm antenna gain,
qualified and measured peak power, RF42 thermal window, `US`, zero padding),
loaded through the authenticated registry as
`rtw88/rtw8822be-iqk-v1-<mac>.bin`. The identity hashes the 768-byte
`Factory8822b` map, the authenticated firmware digest, the firmware hardware
report, (cut, RFE, crystal), every selected `rtw8822b_table.c` row and the
recipe; an erased thermal meter or a non-B22 FIFO geometry (1996/2036/2044) is
refused. The signing metadata comes from
`Lifecycle::calibration_request8822b`; no record values are inferred, and an
unprovisioned, unsigned, foreign, mismatched or policy-refused record keeps
the pure retryable `PhyTablesPrepared` checkpoint (no register access). Current
US policy must plainly cover 2402–2422 MHz at 20 MHz and bound peak + antenna
gain, re-checked around every native operation (`radio8821c::Checked` is now
generic over `calibration8821c::Enclosure`, implemented by both envelopes;
`Error::Calibration8822b` reports B22 refusals).

`radio8822b::calibrate` (`Stage::Calibrating`, 12 s deadline) opens the PCI
calibration state (`begin_calibration8821c`, now also admitting `0xb822`;
closed CR/TXPAUSE checks), verifies the cut from 0xf0, triggers RF42[17:16]
and samples the meter after the 2 s `rtw8822b_pwr_track` interval, programs
`set_channel(1, 20 MHz)` and all-zero coded TXAGC on both paths, refuses a
stale RF08 `0xabcde`, sends `rtw_fw_send_general_info`,
`rtw_fw_send_phydm_info` (`command::phydm8822b`: RFE, `FW_RF_2T2R`, cut,
AB/AB) and `rtw_fw_do_iqk` (clear 0, segment 0), polls RF08 300×20 ms with a
thermal check per sample, clears RF08, refuses any 0x1bf0 fail/reload bit
(Linux only logs them), re-samples the meter, parks host DMA and finishes
at `Stage::Calibrated` with a `radio8822b::Calibration` receipt
(`calibration_info8822b`). The owner's internal phase reuses
`Calibration8821cPrepared`; every C21 operating/station continuation checks
`0xc821` and refuses it. The chain continues with the `N2BP` record below.

#### RTL8822BE parked operating power (`N2BP`) and awake-station grant (`N2BS`)

`operating8822b` holds the B22 operating/station record family, keyed by the
PCI identity `10ec:b822` and bound to the retained `N2BQ` board. From
`Stage::Calibrated`, `Lifecycle::operating_request8822b` returns the identity
(the `N2BQ` request identity, the calibration receipt channel/width and the
literal program recipe) and `rtw88/rtw8822be-power-v1-<mac>.bin`. The signed
192-byte `N2BP` v1 record is: magic 0, version 1 at 4, header and total length
192 at 6/8, VID/DID at 12/14, identity at 16, MAC at 48, channel 1 / 20 MHz at
54/55, antenna gain (quarter-dBi i16) 56, board EIRP ceiling 58,
complete-program and aggregate automatic-response conducted peaks 60/62
(quarter-dBm), thermal min/max 64/65, `US` 66, path-A and path-B coded TXAGC
indices for DESC_RATE 0..11 (CCK1..11, OFDM6..54) at 68 and 80, twelve per-rate
combined-chain conducted peaks at 92, zero 116..192. Every index must be ≤ 0x3f
and ≤ that path's factory channel-group-0 base (`txpwr_idx_table[path]`
`cck_base[0]` and `bw40_base[0] + ofdm_diff`, `txgi_factor` 1, as in
`phy.c::rtw_phy_get_2g_tx_power_index`; 8822B has no BTG path substitution);
erased/wrapped factory cells refuse. All peaks plus antenna gain must fit the
signed ceiling, 20 dBm and every intersecting current US rule; the program peak
encloses the others. Missing/unsigned/foreign/over-limit records keep the pure
`Calibrated` checkpoint. The program (inside `N2BQ` + `N2BP` + policy, 3 s
deadline) re-triggers RF42[17:16] and waits the 2 s `rtw8822b_pwr_track`
interval, checks the meter against both thermal windows plus RF08 clear and
0x1bf0 zero, writes both paths through `rtw8822b_set_tx_power_index_by_rate`
(0x1d00/0x1d80; the three legacy words carry the measured indices, every other
written 2SS word zero) with readback, and programs `RRSR_INIT_2G` 0x15f.
Success earns `Operating8821cPrepared` (stage name shared with C21; owner keyed
by `0xb822`) and `operating_info8822b`; packet gates stay closed.

`station_request8822b` (from `Operating8821cPrepared`) returns the `N2BS`
identity, binding the `N2BP` identity, both paths' indices, the parked and
station response masks, and `rtw88/rtw8822be-station-v1-<mac>.bin`. `N2BS` v1
is the 128-byte `N21S` layout with B22 magic/header (antenna 56, ceiling 58,
ordinary/automatic-response/complete-program peaks 60/62/64, thermal 66/67 that
must be exactly 0/63, `US` 68, zero 70..128); `Grant::invoke` nests the `N2BQ`,
`N2BP` and `N2BS` source invocations and current policy (it implements
`calibration8821c::Enclosure`, so `radio8821c::Checked` encloses every native
operation in it).

`radio8822b::prepare_station` is the B22 awake-station radio program (the
counterpart of `radio8821c::prepare_station`; `Lifecycle::prepare_station8822b`,
`Operating8821cPrepared → PreparingRadio8821c → Radio8821cPrepared`, 4 s
deadline, the stage names shared with C21 and the owner keyed by `0xb822`). The
PCI transport's `begin_station8821c`/`finish_station8821c` arms now admit
`0xb822` with a gate whose `did()` equals the function. The program keeps the
`N2BQ` channel program (`rtw8822b_set_channel` is not replayed), verifies RF18
on both paths and 0x8ac at ch1/20, closed CR/TXPAUSE, the cut, RF08 clear,
0x1bf0 clean, the factory MAC against the grant and both paths' measured
`N2BP` TXAGC words; takes a fresh RF42 conversion (2 s) inside both `N2BP`
thermal windows; writes the conservative CCK response mask `0x440 = 0x1f`;
invalidates the 32 CAM entries with host-only crypto and native RCR
(`radio::software_crypto`, shared with C21/C22); wakes the firmware through
RPWM/CPWM (`radio::awake`); re-verifies geometry, TXAGC, RRSR, PCIe 0x303 stop
bits and zero HIMR 0xb0/0xb8/0x10b8; and hands the transport
`power_policy::Gate::b22`. No beacon/BCN_CTRL write is part of it (Linux arms
beacon functions only for AP/IBSS ports). The `N2BS` request identity hashes
this literal recipe. `Gate::b22` (`Scope::B22`) is keyed by `10ec:b822`
(`phy8821c::Host::PCI_B22`, family `rtw8822be`), binds the grant's MAC and
re-invokes `N2BS` + current policy on every `current`/`invoke`. It also
retains the `rtw8822b_phy_set_param` facts (`phy8822b::Info`) a retune needs.
Its continuation families are `N2BO`, `N2BD`/`N2BW` and the station-core
families bound over `N2BL` (below).
The reserved-page backend's `finish_station8821c` (firmware beacon-page
disarm: 0x383 bit4, `BCN_CTRL` 0x550 bit3, as for C21) also admits the B22
gate.

The B22 station shell is the shared `interface::Device` over the B22 owner's
lifecycle (`pci::bring_up` builds it like C21/C22; probe publishes it as
`rtw8822be`, Linux `rtw8822be.c` `rtw_8822be_driver.name`, instead of the
former diagnostic `wlan%d` registration). `pci::schedule_owner` drives
`provision_owner` with the C21 retry set plus B22 `Calibrated` (awaiting
`N2BP`); once `Owner8822b::provision` reaches `Radio8821cPrepared` (all three
signed records current) `provision_owner` calls `interface.activate()`, i.e.
`Lifecycle::start_station` → the shared `station::State::start`
(`station_control::prepare_initial`, `packet_prepare`/`packet_start`/
`packet_open`) over the shared rtw88 PCI packet backend
(`pci_packet`: TXDESC48/TXBD16/RXDESC24/RXBD8). RX PHY status parses with the
C21 page layout (`rtw8822b.h` `GET_PHY_STAT_P0/P1_*` page/RXSC/RF_MODE fields
equal `rtw8821c.h`; no channel field). The admitted B22 station is the base
profile only: channel 1 / 20 MHz legacy, host-only crypto, plus the
per-channel `N2BO` primaries below, and the station-core continuations
bound over `N2BL` (below). `Gate::b22` admits no coex record and
`reserved_page::station_boundary(0xb822)` is None (no LPS/firmware swap; see
"RTL8822BE documented gaps" below). `N2BS` qualifies only the static awake profile; thermal
tracking and re-IQK run only under their own `N2BD` + `N2BW` records (below). No board's
`N2BP`/`N2BS` asset is provisioned, so on real hardware the shell is
published but stays unadmitted at `PhyTablesPrepared` until signed records
exist.

#### RTL8822BE per-channel operating records (`N2BO`) and retune

B22 joins the shared N2xO family (`channel_policy.rs`, "C21/C22 noninitial
2.4GHz/20MHz operating channels and retune" below) with its own layout and
binding. A noninitial primary N (2.4GHz 2..=13 or a 5GHz `band5::primary`) is
admitted only by `rtw88/rtw8822be-channelNN-v1-<mac>.bin`: the generic
`qualification.rs` layout with magic `N2BO`, PCI header `10ec:b822`, the
shared per-primary `Kind`, and a request that additionally hashes
`channel_policy::SOURCE8822B` (the B22 program below). It binds
`Gate::base_request`, which for B22 is the exact `N2BS` request (identity,
MAC, `rtw8822be-station-v1` filename); continuation requests over a bound
record are channel-scoped (`rtw8822be-chNN-station-...`) as for C21/C22.
Payload: the N2xO header fields (primary, width 20, antenna gain, ceiling,
three peaks), path-A TXAGC indices DESC_RATE 0..11 at 14..26 and path-B at
36..48 (both ≤ 0x3f; CCK zero on 5GHz), gains/OFDM-reference/difference
fields zero, zero 48..64. `channel_policy::within_factory` bounds every
index by that primary's own factory group per path: 2.4GHz `cck_base[g]` /
`bw40_base[g] + ht_1s_diff.ofdm` (`operating8822b::group_limits`, groups of
`rtw_get_channel_group`), 5GHz `rtw_phy_get_5g_tx_power_index` OFDM
(`band5::Power5g::ofdm`, txgi 1, ≤ 0x3f); the raw `txpwr_idx_table[0..1]`
records are retained in the `N2BP` envelope for this. Erased/wrapped cells
refuse. Regulatory admission is the shared N2xO span/peak check; the bound
record re-enters inside the nested `N2BQ`+`N2BP`+`N2BS` invocation
(`Gate::invoke_inner`).

Retune (`channel_policy::program8822b`, under the shared native retune
owner: TX refusal, TXPAUSE, drain, epoch): `rtw8822b_set_channel(N, 20MHz)`
over the retained `phy8822b::Info` (`_bb`, `rtw_set_channel_mac`, `_rf` RF18
A+B, `_rxdfir`, `toggle_igi`, `_cca`, `_rfe`), both paths'
`rtw8822b_set_tx_power_index_by_rate` words (measured legacy words, every
other written word zero), RRSR 0x440 = 0x1f (2.4GHz) or `RRSR_OFDM6_5G`
(5GHz), then before association `rtw8822b_do_iqk` (`iqk8822b`: clear 0 /
segment 0 H2C, RF-A RF08 0xabcde polled 300×20 ms, host clear, 0x1bf0
fail/reload refused — Linux only logs it), then readback
(`radio8822b::verify_channel20`: RF18 A+B, RF-A 0xbe[17:15], 0x8ac 20MHz,
0x454 bit7 by band; `verify_txagc`; RRSR). Retuning back to channel 1
replays the same program with the `N2BP` indices. Scan, association
retune, CSA and safe rejoin are the shared station paths. HT40/VHT80
widening needs B22 HT records (not yet). No `N2BO` record is provisioned
for any board. Case written, unexecuted:
`smoke_rtw8822be_n2bo_channel_record_binds_base_and_retunes`.

#### RTL8822BE dm watchdog (`N2BD`)

B22 joins the shared dm watchdog (`dm.rs`, tag `D`, "Separately signed
continuation contracts and the dm watchdog" below) as
`rtw88/rtw8822be-dm-v1-<mac>.bin` (magic `N2BD`, bound to the channel-scoped
`N2BS` base, request also hashing `dm::SOURCE8822B`). Admitted mechanisms
are exactly those `rtw8822b.c` implements and this tree ports: DIG
(`rtw8822b_dig` 0xc50/0xe50[6:0] both paths, `dig_min` 0x1c) over
`rtw8822b_false_alarm_statistics` (register-identical to the 8821C one) and
RA (H2C 0x42/0x58/0x40, RRSR), `rtw8822b_pwr_track` (bit 5, below) and
`rtw8822b_adaptivity` EDCCA (bit 6): `rtw_phy_adaptivity_set_mode` with the
8822B `l2h_th_ini_ad` −14 + 50 = 36 (ETSI) and `l2h_th_ini_cs` 10 + 50 = 60
(JP) (`dm::edcca_mode8822b`), normal `l2h = max(igi + 8, 48)`, `h2l = l2h −
8`, adaptivity `l2h = min(igi, l2h_th_ini)`, `h2l = l2h − 7`, written by
`rtw_phy_set_edcca_th` over `rtw8822b_edcca_th` (0x8a4 byte0/byte1, offset
0); dm init captures 0x8a4[15:0] (the `rtw8822b_adaptivity_init` 0x7f/0x7f)
and restore writes it back. The MAC EDCCA state of
`rtw8822b_adaptivity_init` is already part of the PHY tail. 8822B has no
`cck_pd_set`, tx-path-diversity, CFO or DPK hooks, so those bits refuse.
Case written, unexecuted: `smoke_rtw8822be_edcca_adaptivity_follows_rtw8822b`. RSSI follows `rtw8822b.c::
query_phy_status_page0` (PWDB word0[15:8] − 110, path A) and `_page1`
(PWDB A/B word0[15:8]/[23:16] − 110, two-path `rtw_phy_rf_power_2_rssi`).
`Lifecycle::prepare_station8822b` records the dm facts (RFE, crystal,
path-A thermal). As for C21/C22 the dm grant binds at association on 2.4GHz
only. Case written, unexecuted:
`smoke_rtw8822be_n2bd_dm_admission_and_phy_status`.

`tracking8822b::Tracker::pass` ports `rtw8822b_pwr_track` (type 0) and is
driven by the dm watchdog when the `N2BD` payload enables `dm::PWR_TRACK`:
alternating RF42[17:16] trigger and RF-A meter sample, `DECLARE_EWMA(thermal,
10, 4)` average, `rtw_phy_pwrtrack_thermal_changed`/`_get_delta`/`_get_pwridx`
over the `rtw8822b_pwr_track_type0_tbl` rows of the committed band (2.4 GHz
CCK tables for DESC_RATE ≤ 11M; 5 GHz `pwrtrk_5g{a,b}`), one meter (path A) for both paths, `rtw8822b_pwrtrack_set` with the
committed program's coded per-path per-rate index (`Gate::b22_rate_indices`:
the `N2BP` indices on channel 1, the bound `N2BO` record's elsewhere, plus
the bound HT/VHT words) in place of
`rtw_phy_get_tx_power_index` (`offset = 0x3f − index`),
`rtw8822b_txagc_swing_offset` (max offset 0xf, `default_ofdm_index + 10`
upper bound) and the 0xc94/0xe94[29:25] and 0xc1c/0xe1c[31:21]
`rtw8822b_txscale_tbl` writes, all inside the `N2BD` authority (which nests
`N2BS`/`N2BP`/`N2BQ` and current policy). dm init takes
`default_ofdm_index` from 0xc1c (`rtw8822b_get_swing_index`, else 24) and
captures both paths' TXAGC-index/TX-scale fields; restore (authority loss,
an out-of-envelope pass) writes them back under the base gate. An erased
meter is refused before any write; a current rate the committed program
never wrote skips the pass (`Pass::Skipped`, no register access); refused
likewise is a sample outside the `N2BD` thermal window or the `N2BP`
windows and a table delta beyond the `N2BD` `power_up`/`power_down` bounds
(C22 clamps; B22 refuses and restores).

`rtw_phy_pwrtrack_need_iqk` (threshold 8 against `thermal_meter_k`, the
EFUSE thermal from `rtw8822b_read_efuse`) runs `rtw8822b_do_iqk` as an
associated-station maintenance (`station.rs::iqk8822b`) after the period's
H2C commands, under the separately signed `N2BW` continuation
(`tracking8822b::KIND`, generic `qualification.rs` layout, magic `N2BW`,
`rtw88/rtw8822be-power-track-v1-<mac>.bin`, request also hashing
`tracking8822b::SOURCE`). Payload: bytes 0..32 the exact `N2BD` request
identity, 32/33 the thermal window [lo, hi] the associated IQK was measured
over, zero tail. A B22 `N2BD` enabling `PWR_TRACK` binds at association only
together with an `N2BW` naming it (`tracking8822b::binds`); without one the
dm program stays unbound. The maintenance (PCI `Native::station_b22_iqk`,
`tracking8822b::Step`): Begin refuses unless Packets with no retune/width/
mailbox/H2C in flight, a current B22 gate, TXPAUSE 0 and RXDMA not parked;
sets TXPAUSE 0x522 = 0xff and `REG_RXPKT_NUM` `BIT_RW_RELEASE`; Quiet is the
retune receipt (packet core quiet, every TX ring RP == WP, TXDMA_PQ_MAP
0xc5a0, FIFOPAGE_INFO_1..4 configured == free) plus `BIT_RXDMA_IDLE`, polled
1000 × 10 µs; a fresh RF-A meter must lie inside the `N2BW` and `N2BP`
windows; Submit sends the `rtw8822b_do_iqk` H2C (clear 0, segment 0) on the
retained ring (`submit_h2c` admits exactly that packet for B22), then
`channel_policy::iqk8822b_associated` polls the ring, RF08 0xabcde
300 × 20 ms, clears RF08 and refuses any 0x1bf0 fail/reload bit; Finish
requires a consumed ring and still-quiet hardware, releases RXDMA and
TXPAUSE with readback. Copied receive admission is retired around it as for
N21W. Any failure closes the station (no invented coefficient restore).
The quiet FIFO receipt now uses the per-chip `__priority_queue_cfg` counts
`mac::prepare_on` programmed (`Native::fifo_pages`: C21 16/16/16/14,
C22/B22 64/64/64/64); the former 16/16/16/14 constant refused every
C22/B22 retune, HT program and IQK quiet on real FIFO geometry. No `N2BD`
or `N2BW` asset is provisioned for any board. Case written, unexecuted:
`smoke_rtw8822be_n2bw_power_tracking_and_iqk_admission`.

#### RTL8822BE legacy12 DATA and WMM BE/TID0 (`N2BL`)

B22 joins the shared N2xL family (`station_profile.rs`, "RTL8822CE
separately qualified legacy12 DATA and WMM BE/TID0" below) through
`power_policy::ExtensionChip::B22` over the exact `N2BS` grant
(`Gate::extension_base`, channel-scoped by a bound `N2BO` record as for
C21/C22). The request (`station_profile::request_b22`,
`rtw88/rtw8822be-legacy-wmm-v1-<mac>.bin`) hashes the `N2BS` request identity,
the `N2BS` record digest (`operating8822b::Grant::extension_request`), both
paths' `N2BP` DESC_RATE 0..11 indices and the literal program. The record is
the 128-byte N2xL layout with magic `N2BL` and PCI header `10ec:b822`. No new
gain program exists: the B22 base already writes both paths' measured legacy
words through `rtw8822b_set_tx_power_index_by_rate` (0x1d00/0x1d80) under
`rtw8822b_config_trx_mode(AB, AB)`, so the record measures DATA at those
indices. Its limit is the live `N2BS` policy limit inside all three source
invocations (`operating8822b::Grant::extension_limit`), intersected with the
record ceiling and the bound channel record's span. The DATA/RA/EDCA program
is the shared chip-independent one. No `N2BL` asset is provisioned. Case
written, unexecuted: `smoke_rtw8822be_n2bl_legacy_wmm_binds_n2bs`.

#### RTL8822BE HT20 1SS/2SS (`N2BH`)

B22 joins the shared HT20 family (`ht.rs`, "C21/C22 separately qualified
HT20 and SGI20 station" below) over a bound `N2BL`. Facts
(`operating8822b::Grant::ht_facts`, `Envelope::ht_limits`): the firmware
hardware report the `N2BQ` board bound, path A's legacy indices and, per
group, `phy.c::rtw_phy_get_2g_tx_power_index` HT20 with `txgi_factor` 1
(`operating8822b::ht20_limit`: `bw40_base[g]` + `ht_1s_diff.bw20`, plus
`ht_2s_diff.bw20` for 2SS, ≤ `max_power_index` 0x3f) or the 5GHz
`band5::Power5g::bw20`, intersected over both paths; a bound `N2BO` primary
supplies its own group and legacy indices. As on C21/C22 local HT needs a
VHT-protocol (`ptcl` 3) report; 2T2R (two streams and antennas) and complete
HT2S cells add the two-stream child. RX LDPC is advertised
(`rtw8822b_hw_spec.rx_ldpc`, `coding::rx_ldpc`).

Requests: `rtw88/rtw8822be-ht20-v1-<mac>.bin` (1SS, the generic 192-byte
layout with magic `N2BH`) and the child
`rtw88/rtw8822be-ht20-2ss-v2-<mac>.bin` (preferred when present). The v2
record is the 256-byte N22H v2 layout with magic `N2BH`, path-A MCS0..15
indices at 70..86 and path-B MCS8..15 at 174..182 (zero 182..256); every
index is ≤ the intersected 1S/2S ceiling. There is no path change:
`rtw8822b_config_trx_mode(AB, AB, false)` already leaves 1SS on path A
(`REG_CDDTXP` 0x93c[31:20] = 0x001) and 2SS on A+B (`REG_TXPSEL1`
0x940[15:4] = 0x43), so the C22 TX-pause/RX-park path switch is not used.
The program (`ht::Grant::program`) takes the C21-style fresh RF42 conversion
(SIPI 0xc90, 2 s, read 0x2908) inside the `N2BP` windows, then writes the
`rtw8822b_set_tx_power_index_by_rate` HT words 0x0c..0x1b of both paths
(0x1d00/0x1d80 + 0xc..0x18): path A MCS0..7, both paths MCS8..15 for v2,
path-B HT1S zero; legacy words keep the base/`N2BO` values. Readback
(`readback_b22`) checks 0x93c/0x940, both paths' words 0..6 and host-only
crypto. Under a bound `N2BH` the `N2BD` power tracker covers DESC_RATE
0..19/0..27 (`Gate::b22_rate_indices`; path-B HT1S headroom uses path A's
index). No `N2BH` asset is provisioned. Case written, unexecuted:
`smoke_rtw8822be_n2bh_ht20_2ss_binds_n2bl`.

The B22 retune (`channel_policy::program8822b`) writes legacy12-only TXAGC
tables, so it refuses a gate with any extension bound
(`Gate::base_only`); the PCI retune owner (`station_retune_begin`) already
required that, as on C21/C22, so a retune or CSA never zeroes bound HT/VHT
words.

#### RTL8822BE HT40 (`N2BB`) and VHT80 (`N2BV`) widening

B22 joins the shared N2xB/N2xV families (`ht40.rs`, `vht.rs`; "Separately
qualified HT40" / "VHT80" below) with the generic continuation layout and
magics `N2BB`/`N2BV` (`qualification`, chip byte `B`); every B22 request
additionally hashes `ht40::SOURCE8822B` / `vht::SOURCE8822B`. Payload
differences: indices are absolute `rtw8822b_set_tx_power_index_by_rate`
values ≤ `max_power_index` 0x3f (no C22 MCS7 reference); `N2BB` bytes
16..32 are path-A MCS0..15 and 32..40 path-B MCS8..15 (zero outside the MCS
mask, 40..64 zero); `N2BV` bytes 16..36 are path-A VHT1SS/2SS MCS0..9 and
36..46 path-B VHT2SS MCS0..9 (zero for one stream, 46..64 zero).

Ceilings (`operating8822b::Envelope::ht40_limits`/`vht80_limits`, reached
through `Gate::ht40_limits`/`vht80_limits`): `phy.c::
rtw_phy_get_2g_tx_power_index` at BW40 is `bw40_base[group(center)]` ("bw40
is the base power") plus `ht_2s_diff.bw40` (signed high nibble of byte 12)
for 2SS (`operating8822b::ht40_limit`); 5GHz uses `band5::Power5g::bw40`
and, at BW80, `Power5g::bw80` (the average of `bw40_base[g]` and `[g+1]`
plus `vht_1s_diff.bw80` (+ `vht_2s_diff.bw80`)); `txgi_factor` 1, both
paths intersected. Path-B indices must also be within the 2S ceiling.

Programs (inside `station_width_begin`'s TX pause/drain, as for C21/C22):
`ht40::program8822b` runs `radio8822b::set_channel(center, BW40, sc)`
(`rtw8822b_set_channel`), writes words 0..6 of both paths
(`ht40::b22_words`: legacy12 at the committed `N2BO`/`N2BP` indices,
path-A MCS0..7, MCS8..15 per path for two streams, path-B HT1S zero),
runs `rtw8822b_do_iqk` (`channel_policy::iqk8822b`), then reads back
`radio8822b::verify_channel` (RF18 A+B, RF 0xbe, 0x8ac `sc << 2 | bw`,
0xa00[4] at 40MHz, 0x483 DATA_SC, 0x668 BIT_RFMOD, CCK_CHECK), the words
and RRSR (0x1f 2.4GHz, 0x10 5GHz). `vht::program8822b` does the same at
`(center80, BW80, sc)` with the whole per-path DESC_RATE tables
(`vht::b22_tables`: legacy12 with CCK zero, HT zero as on C22, path-A
VHT1SS MCS0..9 at 0x2c..0x35, VHT2SS per path at 0x36..0x3f) and RRSR
0x10. `rtw_set_channel_mac` BIT_RFMOD was written unshifted by the B22
`channel_mac` (harmless at 20MHz only); it is now `BIT_RFMOD_40M` BIT(7) /
`_80M` BIT(8). The operating readback (`ht::Grant::readback_at` →
`readback_b22_at`) checks the 1SS-A/2SS-AB path selection, the committed
width's words and host-only crypto. Under a bound `N2BB` the `N2BD` power
tracker offsets against the HT40 words (`Gate::b22_rate_indices`); under
`N2BV` against the whole DESC_RATE 0x00..0x3f VHT80 tables
(`tracking8822b::RATES` 64; path-B VHT1SS headroom uses path A's index).
`rtw_phy_config_swing_table` now selects the band rows from the committed
channel (`dm::Authority::b22_channel`, read inside `Tracker::pass`): 2.4GHz CCK/OFDM per path, 5GHz the
`rtw8822b_pwrtrk_5g{a,b}_{p,n}` rows (equal for `RTW_PWR_TRK_5G_1..3`).
A current rate the committed program never wrote (beyond the covered range
or zero on both paths) returns `Pass::Skipped` with no register access
instead of failing the dm program. RX bandwidth follows the 8821C
page-1 RXSC/RF_MODE layout (`pci_packet::receive_chip` C21 for B22,
`rtw8822b.c::query_phy_status_page1`). No `N2BB`/`N2BV` asset is
provisioned. Case written, unexecuted:
`smoke_rtw8822be_n2bb_n2bv_wide_records_limits_and_bw40_readback`.

#### RTL8822BE TX coding (`N2BC`), all-AC QoS (`N2BQ`) and fallback (`N2BF`)

The chip-independent N2xC/N2xQ/N2xF continuations (`coding.rs`, `qos.rs`,
`fallback.rs`; generic layout, chip byte `B`) now admit `0xb822` over the
bound B22 programs with the shared contracts and requirements (N2xC over the
HT program, N2xQ over a WMM `N2BL`, N2xF over `N2BL`). Coding: per
`rtw8822b_hw_spec` (`rx_ldpc` true, no `tx_stbc`), `coding::bounds` allows
LDPC only, so `rtw_init_ht_cap` advertises no HT TX STBC and the one-stream
LDPC DATA rides the 1SS path-A program (`tx.c` W5_DATA_LDPC, `fw.c`
RA_INFO_LDPC). QoS uses the shared PCI BK/BE/VI/VO rings and `mac.c` EDCA
registers; fallback the shared `tx.c` W3 bits and `fw.c` RA mask. The B22
`N2BQ` QoS magic equals the `N2BQ` calibration magic (as `N21Q` does on
C21); the kind tag at byte 54, the request identity and the filename keep
them apart. No asset is provisioned. Cases updated, unexecuted:
`smoke_rtw88_coding_payload_bounds_and_apply`,
`smoke_rtw88_fallback_payload_bounds_and_descriptor_bits`.

#### RTL8822BE recipient/originator BA (`N2BR`/`N2BT`) and RTS (`N2BX`)

The exact-chip RX BA, TX BA and RTS-threshold records (`rx_ba_power.rs`,
`tx_ba_power.rs`, `protection.rs`) replace the former B22 refusal with
the B22 magics (`tx_ba_power::magic`: `N21x`/`N22x`/`N2Bx` by chip, every
other chip refused) and unchanged layouts, header `10ec:b822`, over the
bound B22 `N2BH` (and, for T/X, the bound R/T as on C21/C22). Each B22
request also hashes `tx_ba_power::SOURCE8822B`. B22 program facts:
`rtw8822b_mac_init` writes neither BIT_BA_PARSER_EN (0x426) nor the 0x66e
ACK type, so `rx_ba::readback` now takes the chip id and checks those two
only on C22 (C21 and B22 skip them); REG_BAR_MODE_CTRL+2 0x4ce is 0x0801
(`WLAN_BAR_RETRY_LIMIT` 1, `WLAN_RA_TRY_RATE_AGG_LIMIT` 8); RXFLTMAP1
0x6a2/0x6a3 = 0xff from the `rtw8822b_mac` table after `WLAN_RX_FILTER1`
0x0fff (as on C21); the TX FIFO quiet check uses the B22 64/64/64/64
pages (`tx_ba::fifo_empty_tids`, non-C21 arm); `ampdu_density` is
`IEEE80211_HT_MPDU_DENSITY_2` as on C21/C22. The TX BA static program
(0x42a 0x0808, 0x455 0x20) and the RTS descriptor fields are the shared
`tx.c`/`rtw_coex_limited_tx` ones. No `N2BR`/`N2BT`/`N2BX` asset is
provisioned. Case extended, unexecuted:
`smoke_rtw8822be_n2bh_ht20_2ss_binds_n2bl` (N2BR binds; N21R/N22R refuse).

#### RTL8822BE documented gaps: LPS and Bluetooth coexistence

The `rtw88 | rtl8822be` row is scoped to the RTL8822CE chip-row station core.
LPS and coexistence are separate feature rows on C22 and stay open for B22:

- LPS / runtime PS. `reserved_page::station_boundary(0xb822)` is None, so
  no B22 reserved-page station layout, `runtime_ps_page` (PS-Poll/null/QoS
  null pages from the 1996 boundary below H2CQ 2036 and firmware TXBUF 2044,
  `rsvd_drv_pg_num` 8) or firmware page swap exists. A B22 LPS needs its own
  channel-scoped `N2BZ` program over the station core (the N2xZ scope of
  `lps_peer`), with `rtw8822b_hw_spec.lps_deep_mode_supported =
  BIT(LPS_DEEP_MODE_LCLK)`; none is implemented, so LPS stays refused.
- Coexistence. No `N2BK` record or B22 coex owner exists: the
  `rtw8822b_coex_*` chip ops (`coex_set_init`, `_ant_switch`, `_gnt_fix`,
  `_gnt_debug`, `_rfe_type`, `_wl_tx_power`, `_wl_rx_gain`), the
  `table_sant_8822b`/`table_nsant_8822b` and `tdma_sant_8822b`/
  `tdma_nsant_8822b` tables, `rf_para_tx/rx_8822b`, `coex_para_ver`
  0x20070206 and `bt_desired_ver` 6 are not ported. `coex::record` has no
  B22 mode table, so a B22 gate never binds coexistence-driven SMPS.

### RTL8821CE retained firmware, PHY and qualified calibration continuation

Probe captures `efuse::Factory8821c` from the same single512-byte logical-map
read that establishes its factory MAC. The distinct type retains raw4×42-byte
power records, thermal/crystal/board/BT/channel/country fields and the original
RFE byte. Its decoded RFE mask/package bit follows `rtw8821c_read_efuse`; erased
values are never replaced. The later parked-power owner applies the exact
source RFE-specific power-path selection. `Rtw88Device::rtl8821c_factory()` borrows this exact
retained identity. No protected C22 trim cells or C22 factory offsets are used.

The station shell retains a separate native lifecycle before any
firmware work. `firmware_status()` reports its stages just as for C22.
`pci::provision()` serializes explicit calls with probe's bounded background
worker and advances `Detected → Ready → MacPrepared → PhyTablesPrepared → Calibration8821cPrepared → Operating8821cPrepared → Radio8821cPrepared → StationReady`; missing/revoked/malformed
firmware remains at the pure retryable `Detected` checkpoint without allocating
DMA. Missing or invalid calibration assets/current policy remain retryable at
`PhyTablesPrepared`, without register access or DMA allocation. A repeated
`Operating8821cPrepared` or `Radio8821cPrepared` checkpoint continues only with
the next required genuine asset/current policy; a `StationReady` request is a
no-op. Once native allocation or a
hardware attempt starts, failure/cancellation is terminal and retains the exact
inner owner and every published mapping; no cold-power/firmware reconstruction
occurs. Existing IRQ-safe static locks never cross an await.

This profile opens only `rtw88/rtw8821c_fw.bin`, validates its0x8821 signature and
actual64-byte section header before native allocation, and uses the common Linux
3081 reserved-page/IDDMA flow. The authenticated loaded bytes retain their
digest. Original source matches the shared48-byte TX descriptors, seven
non-beacon rings, RX geometry, LTE registers and firmware-ready predicate;
those mechanisms are reused without treating the C22 firmware as a C21 image.
DMA is parked and the host rings rechecked before the inactive-MAC continuation.

The C21 MAC path uses its own Linux chip function and64KiB TX/16KiB RX FIFO
profile: reserved boundary460, H2C page500, firmware TX page508 and16/16/16/14
priority-page allocation. LLT completion and empty configured H2C pointers are
required. Its EDCA/SIFS/receive configuration uses evaluated8821C constants;
the C22 cut-D PCI quirk is excluded. DMA/MAC TX/RX, packet producers and IRQs
remain closed throughout. Native Rust tests compare complete inactive register
traces with frozen reference cases for two seeded images/cuts. They also cover
MAC access failures, stale hardware reports, LLT cancellation and exact
firmware/owner retention. Packed-factory offsets and pinned raw-firmware-header
metadata remain fixed inputs with source provenance.

The C21 continuation then executes the original `rtw8821c_phy_set_param`
prefix through its three retained channel-filter snapshots. Admission requires
cut0..6, original valid RFE0/2/4/6, non-erased crystal and a one-path antenna/
stream report (Linux IGNORE0 is accepted). Both decoded package0/1 profiles
are selected with Linux's original condition rules, including cut-A/package0
mapping to condition15. A current SYS_CFG1 read must still match the retained
cut and identify one physical RF path; firmware antenna narrowing cannot
qualify two-path silicon. The native aperture must cover `0x2000` before any
PHY write; C22 retains its separate `0x5000` requirement. Every register access
invokes current PCI authority and checks parked BME, with a two-second outer
budget for the C21 table sequence.

The source BB-reset/RF-domain preamble, MAC/BB/AGC tables, RFE2/4 BTG AGC,
one RF-A table, exact6-bit factory crystal and source postamble run in order.
C21 writes all RF registers through SIPI `0xc90`, with source13us+1us delays.
Every selected RF0 write is the source `0x10000`; the MAC TX/RX/DMA gates,
TX pause, empty host producers and IRQ masks remain parked. C21 has no
`rfk_init_tbl`, so no C22 RFK program, direct RF aperture, trims or calibration
routine is substituted. The C21 BB table's own instruction RAM is preserved.
The stage stops before dynamic PHY initialization, power tracking and
beamforming setup, and retains its source TXSF2/TXSF6/TXFILTER snapshots for
those later continuations. Successful parked readbacks alone earn
`PhyTablesPrepared`; they do not prove hardware calibration.

Native Rust tests check stored table/callback digests and channel-filter
snapshots for all56 C21 cut/package/RFE profiles and49 C22 cut/RFE profiles.
The frozen reference data cites Linux `phy.c`, chip callbacks and per-chip table
sources. No compiler/extraction pipeline participates in this validation.
Composed regressions preserve the actual reserved-page backend and its
published firmware DMA buffers through firmware/MAC/PHY success, access
revocation and cancellation before or during RF table loading. Failed or
cancelled attempts retain the exact owner and refuse replay/reallocation.

`Rtw88Device::rtl8821c_calibration_request()` returns the exact retained
calibration identity, factory MAC and requested filename
`rtw88/rtw8821ce-iqk-v1-<12 lowercase MAC hex digits>.bin`. It grants no RF
authority. The identity binds the complete512-byte factory map, authenticated
firmware digest, raw hardware report, cut/package/RFE/crystal, retained filter
snapshots, selected actual C21 tables and versioned calibration recipe. Factory
thermal must be0..63 and raw2G swing0..9; erased values fail before writes.

The signed `N21Q` v1 envelope is exactly128 bytes, little endian: magic at0,
version:u16=1 at4, header:u16=128 at6, total:u32=128 at8, vendor:u16=0x10ec
at12, device:u16=0xc821 at14, identity[32] at16, MAC[6] at48, channel:u8=1
at54, bandwidth:u8=20 at55, antenna gain:i16 quarter-dBm at56, qualified
EIRP ceiling:i16 quarter-dBm at58, measured aggregate complete-calibration
conducted peak:i16 quarter-dBm at60 (including channel/RF setup transients and
firmware IQK), measured thermal minimum/maximum:u8 at62/63,
country bytes `US` at64/65 and zero reserved bytes66..127. Antenna gain is
0..128; each signed power field is-512..256; thermal bounds must be ordered,
within0..63 and enclose the factory thermal value. It must describe the actual
board, firmware, programmed recipe and environment; this implementation supplies
no measured asset or inferred dBm conversion for a TXAGC index.

The initial profile explicitly chooses trusted US, non-SRRC channel1/20MHz.
Current authenticated policy must cover2402..2422MHz at20MHz and every
overlapping rule is enforced, including NO_IR/DFS/indoor/unknown restrictions.
Only NO_P2P is irrelevant to this calibration. Measured conducted peak plus
antenna gain must fit the minimum of the signed EIRP ceiling, every overlapping
policy ceiling and80 quarter-dBm. Missing policy is never substituted with a
factory country hint or permissive default. Retained signed firmware authority
and fresh policy enclose every native register operation and H2C publication;
resuming after a wait rechecks both. Observed revocation stops the continuation;
it cannot retract an already-issued command or autonomous firmware RF.

After qualification the same owner checks its larger `0x2c00` register aperture
and current physical cut/one-path state. Linux `rtw8821c_set_channel*` ch1/20
BB/filter/ADC/clock, factory swing, RFE0/6 WLG or RFE2/4 BTG, RF-A channel,
XTAL toggle and RX DFIR operations run through C21 SIPI with bounded async
delays and stable readbacks. All supported CCK/OFDM/HT1S/VHT1S TXAGC words
are programmed to minimum coded index0 solely for the calibration setup;
this is neither a measured power curve nor permission for ordinary packets.
Fresh RF thermal conversions now bracket IQK. The source C21 power-tracking
trigger writes RF42[17:16]=3; the next watchdog pass reads RF42[15:10]. The
native continuation preserves that two-second conversion interval before both
initial and final meter reads, without inventing a conversion-done bit or
substituting the factory thermal byte. During IQK polling the actual meter
register remains checked against the same signed interval. Recipe revision2
binds these trigger/wait operations into the N21Q identity; an earlier signed
identity cannot authorize the changed calibration program. The asset format
and filename remain v1 because their wire schema is unchanged. General H2C boundary48 and PHYDM firmware RF_1T1R=4 with
TX-A/RX-A fields precede C21 IQK clear=0/segment=0. Transport retirement alone
does not complete IQK: a pre-existing RF08=0xabcde is rejected; a fresh actual
RF08 marker is required within300 polls20ms apart, then cleared and read back.
IQK fail bits0..7 or reload bit16 at0x1bf0 reject this fresh-result profile.
The complete attempt has a twelve-second outer bound. Published command DMA
stays retained on error/cancellation. Success drains commands, parks BME and
MAC/ordinary producers/IRQs again and earns only `Calibration8821cPrepared`.
`rtl8821c_calibration_info()` reports this historical receipt, not continuing
RF authority. C21's Linux calibration callback is firmware IQK; no C22 DACK,
protected trim cells or C22 RF access method is substituted.

Six native Rust regressions compose real retained reserved-page firmware DMA,
MAC and PHY through this continuation. They check literal command bytes, all
four supported RFE branches/swing bins, actual modeled RF receipts and failure/
reload/thermal/transport errors, missing/malformed/unsigned/foreign assets,
NO_IR/overlap policy, suspended cancellation/revocation and exact retained DMA.
These are register/transport model checks; no physical IQK acceptance is recorded.

C21 beamforming/coexistence and additional source-required profiles remain
broader work. The separately qualified N21W continuation below implements
thermal power tracking and periodic associated IQK. The calibration-only
asset cannot authorize operating RF or station admission; the separate full
awake grant and retained native chain below are mandatory.
C21 PHY state has a distinct type and never populates the C22 PHY/power/radio
fields; C22 calibration callbacks remain inaccessible to C21. The completed
C21 native profile exposes passive channel1 scan and legacy Open/WPA2 station;
That calibration-only stage advertises no HT/VHT, QoS or additional bands. Physical firmware/board
acceptance remains unrecorded.

### Multiple live retained functions

Up to four RTW88 PCI functions retain independent controllers, exact firmware/
factory/calibration/source identities, power-policy providers, native ring
owners, station keys/PNs, interface names and provisioning mutexes. The native
station applicability remains RTL8821CE/RTL8822CE; additional chip IDs keep
their existing diagnostic behavior. Linux
[`pci.c::rtw_pci_probe`/`rtw_pci_remove`](https://codebrowser.dev/linux/linux/drivers/net/wireless/realtek/rtw88/pci.c.html)
uses per-`pci_dev` hardware ownership; NARF retains a bounded BDF registry.
A pending claim and a removed function with unproven DMA reclamation retain
only their own BDF. Removal holds the original Arc through native teardown;
only proven reclamation releases that entry, and stale cleanup cannot release
a fresh owner or a different function.

Every native shell uses `net::iface::register_with_context` with a nonwrapping,
never-reused boot dispatch cookie. RX drain snapshots all endpoints and
services each after releasing its registry lock. A held native TX terminal,
revoked original qualification, firmware wait or disconnect cannot select or
stall another retained function. Background provisioning captures its original
owner, and explicit continuation requires the BDF when more than one is live.

Withdrawal closes only the old admission, permanently fences carrier metadata,
and retains its name/dispatch reservation until an old stack ingress callback
returns. The async remove path waits for delivery quiescence before the original
DMA-stop teardown and BDF release. No driver lock spans a stack callback.
Repeated old removal or drain work cannot modify a fresh shell. Existing
current-source receive/copy proofs and the exact native stop/reclamation rules
remain in force. This implements independent device lifetimes; operating reset,
safe reassociation, runtime sleep and system suspend remain separate rows.

Three new cases under `drivers/wireless/rtw88/multiple` cover real retained
firmware/radio/native-packet models with distinct factory MACs and CCMP keys,
original qualification loss, independent TX terminal waits, production context
routing, ingress-delayed removal, stale callbacks, explicit BDF selection,
per-function provisioning serialization and quarantine. They await batch
validation; no physical multi-board acceptance is claimed.

### RTL8822CE retained station provisioning

`pci::provision()` (also re-exported as `rtw88::provision`) is the public
staged-asset continuation when exactly one live retained function exists.
With multiple functions it returns `State`, without choosing a radio. Explicit
`pci::provision_function(BusAddr)` (also re-exported from `rtw88`) selects the
original live function; `pci::with_controller_at(BusAddr, callback)` borrows
that exact controller. The legacy `with_controller` also requires one live
function. Probe's worker captures its original controller Arc and uses the
same owner-specific continuation; its async admission mutex serializes boot
and operator calls for that function alone; no IRQ-disabling lock crosses an await. Admission snapshots the
exact firmware/interface Arcs, verifies their shared lifecycle and factory MAC,
and rejects absent controllers, diagnostic siblings, closed interfaces and
in-progress/failed stages. Only `Detected`, completed firmware/MAC/PHY-table/
calibration checkpoints can advance. `StationReady` is idempotent. No call
reconstructs the device, repeats an earlier stage or resets a failed owner.

Registered firmware lookup, current Registry/Blob capability invocations,
owned snapshot and header/extent parsing complete before the lifecycle's
single-use atomic begin and before allocating native rings. Missing, revoked
or malformed registered assets leave `Detected` with a diagnostic error and
no native allocation/I/O. A later provisioning call can load newly staged bytes
on that same owner. Probe drives background provisioning via `drive_scheduled`
across 120 attempts with 500 ms intervals, retrying while in `Stage::Detected` or `Stage::PhyTablesPrepared`.
Direct retained `Owner::initialize_registered` likewise
preserves `Phase::New` on preflight failure. The supplied-byte diagnostic path
keeps its existing one-shot semantics. Once allocation/claim begins, failure or
cancellation remains terminal and cannot reopen preflight or reuse DMA.

Missing signed board/policy assets preserve `PhyTablesPrepared`. Fresh current
policy, board binding and power permission are checked in an opaque pure radio
preflight before publishing `Calibrating`; after that accepted attempt, current
checks during real radio operations still fail terminally. Regressions cover
late firmware staging without allocations, real publication/cancellation,
resumption from a completed PHY checkpoint through actual radio calibration,
exact retained-owner identity, and cancelled public admission waits.

The private RTL8822CE continuation opens exactly
`rtw88/rtw8822c_fw.bin` through current firmware authority, snapshots the
authenticated image, and rejects malformed layouts before DMA claim. It
copies image bytes inside current firmware-capability invocation and retains
SHA256 of those exact loaded bytes for board-qualification binding. It
parses the actual 64-byte `0x8822` header, exact DMEM/IMEM/optional EMEM
extents and each eight-byte checksum trailer. Only fixed Linux OCP bases
DMEM `0x200000`, IMEM `0x30000`, and EMEM `0x100000` are admitted;
relocated or trailing data fails. RTL8821C uses its separate exact image and
inactive continuation above; RTL8822B uses its own B22 image/IMEM base
(see "RTL8822BE retained native B22 owner"); WoW filename selection is C22-only. IDDMA consumes serial reserved pages of at
most 4096 bytes, including section checksum tails, then validates section
checksums and the exact final `0xc078` firmware-ready status.

Before BME, the native owner allocates all seven non-beacon TX BD rings,
512 RX buffers plus their BD array, and the beacon BD/frame (522 coherent
mappings). Every mapping is below 4 GiB; bases, counts and reset indices
are checked while MAC TX/RX and interrupts are parked and ordinary host
producer indices remain empty.
Only the retained beacon queue runs during download. Completion closes
HCI/MAC DMA, verifies BME clear, and restores exact ring
bases/counts/reset indices. Native packet TX/RX and IRQ delivery are not started by firmware readiness.
PCI control `0x303 | 0xf7` is the source DMA configuration, not a queue-stop
bitmap. Parking relies on CR DMA/MAC gates and verified BME clear; only owned
producer indices may advance while BME is enabled. No pause bitmap is inferred
from another chip family, and RX-tag configuration at `0x301[7]` is preserved.

The same retained firmware `Owner` then executes one `prepare_mac` continuation;
it cannot reconstruct the PCI function or reuse firmware pages. `PreparingMac`
is published before native preparation. The native backend rechecks current PCI
authority, the real firmware-ready register and parked BME/queue/MAC/IRQ state.
The continuation ports Linux's RTL8822CE PCIe queue mapping, complete on-chip
FIFO boundaries, LLT initialization, internal H2C head/read/tail setup, chip
MAC configuration and cut-D-or-newer PCIe MAC-clock quirk. `MacInfo` records
the actual cut and reserved/H2C/firmware FIFO pages. LLT waits are bounded and
cooperative; equal H2C pointers must also name the configured queue start.
`MacPrepared` requires the final parked-state readbacks. Any access error,
queue mismatch, failed LLT or cancellation makes the owner terminal and
retains all previously published mappings.

This is an inactive preparation: the Linux CR writes are masked to preserve
closed MAC/HCI DMA, TXPAUSE remains set, BME and every packet queue/IRQ stay
closed. It does not apply RF/BB tables, perform calibration, send H2C packets,
admit scan/station traffic or open carrier. The probe invokes this continuation
only after its actual retained firmware attempt succeeds.

Native DMA claim also writes Linux's boot-time `C2HEVT=0xfd` feature request
before loading/starting the MCU, replacing any previous report. The later
MAC continuation requires the actual `0x19` report, retains all13 bytes,
extracts the original HCI/BW/NSS/antenna/protocol bitfields and acknowledges
the mailbox only after reading the complete report. Missing, unconsumed or
failed report accesses cannot reach MAC readiness. These descriptive fields
do not grant RF, calibration or station authority; radio selection must
intersect them with the exact chip/factory profile and trusted policy.

`prepare_phy_tables` continues that same owner after `MacPrepared`. Its initial
geometry requires both physical RF paths (reported2 or Linux IGNORE), RFE0..6,
the checked silicon cut and non-erased crystal/board/thermal factory fields.
The native backend requires the complete `0x5000` RF aperture before any PHY
write and keeps BME, MAC TX/RX and IRQs closed with empty ordinary
producer indices. It powers the
BB/RF configuration domain, runs source-selected BB/AGC/RFK-init/RF tables,
applies the actual crystal value, and restores the source header-file mode.
RF0 uses SIPI and other RF registers use direct20-bit read/modify/write, with
the actual source delays. Final parked readbacks precede `PhyTablesPrepared`.
Missing factory data, unsupported geometry, access error and cancellation are
terminal. This state means table loading only; DAC/IQ/LO calibration, trims,
channel/power qualification and station activation remain separate steps. No packet/carrier interface is enabled by this continuation.

The native continuation next loads the exact per-device
`rtw88/rtw8822ce-cal-v2-<12 lowercase MAC hex digits>.bin` qualification through
current firmware authority. Loading and metadata parsing execute inside the
blob's `Cap::invoke`; a signer is mandatory even in builds that admit unsigned
device firmware. The retained calibration cap is invoked again before every
permission/gain check. Qualification itself changes no native registers or DMA
state and does not claim hardware calibration complete.

`PowerPermission` has private fields. Its board identity binds the original
logical map, nineteen protected trims, cut/RFE/crystal/two-path geometry,
decoded firmware hardware capabilities, exact loaded-image SHA256, selected
PHY tables and source-derived factory ceilings. Source PG decoding and
normalization constrain each channel 1 CCK gain by the minimum of all four
CCK response rates and all source
regional rows, including the stricter RFE5 table. A country hint cannot raise
an index. Erased or underflowing factory values are refused; indices are never
interpreted as dBm. Signed measured upper bounds must additionally fit current
host policy, antenna gain, qualified EIRP and the conservative20dBm initial
profile ceiling. Every overlapping rule must cover the complete20MHz channel;
DFS, environmental/unknown restrictions and missing coverage keep TX closed.
`NO_P2P` does not prevent the retained STA profile. Unknown measurements never
mean zero power. The qualification also supplies separate measured upper bounds for aggregate
calibration transients and hardware automatic control responses. Both must fit
the current EIRP limit before a grant; rejecting a host RX frame cannot prevent
an automatic hardware ACK or CTS.
Policy changes and actual cap revocation invalidate prior gain tokens.

The family-specific `N22C` version 2 record is exactly 640 bytes: magic[4],
version:u16 (2), header128:u16, length:u32, vendor/device:u16 each, board
identity[32], MAC[6], channel:u8 (1), operating-envelope flags:u8 (3), antenna
gain:i16 in quarterdBi, qualified EIRP:i16 in quarterdBm, profile:u16 (2),
aggregate calibration conducted peak:i16, native-response conducted peak:i16,
and 62 zero reserved bytes. Two 128-entry signed-i16 conducted upper-envelope
arrays follow, for paths A and B. `i16::MAX` denotes unmeasured curve entries;
all measured bounds, including both peaks, lie in [-512,256] quarterdBm.
Antenna gain lies in [0,128] quarterdBi. Version 1, missing response attestation,
unknown peaks and altered profiles are refused. No real measured artifact is
provided or inferred by the implementation.

The exact version 2 identity binds awake channel 1, legacy 20 MHz, software
1 Mbps TX-A/RX-AB, fresh DACK/IQK, no GAPK/DPD/power tracking, software CCMP/raw
RX, fixed source IGI `0x1c` and conservative adaptive EDCCA thresholds 40/33.
It also binds source `RRSR=0x1f`, selected CCK references, OFDM reference zero
and zero relative differences for all twelve legacy rates. Source RRSR
selection at 1 Mbps retains CCK rates and mandatory OFDM responses; this is
not a claim that hardware transmits only at the host TXD rate. The response
peak must bound every native control-response mode over the entire admitted
CCK index range and OFDM reference zero, including uncertainty and retained
environmental limits. The separate calibration peak bounds all calibration
emissions, including any path combination. Neither is derived from an index.

`prepare_radio` continues the same `PhyTablesPrepared` owner after a current
version 2 board grant. It poisons the owner before its first radio write or
await, configures TX-A/RX-AB and the actual channel 1 MAC/BB/RF registers,
programs qualified references, performs fresh ADC/DAC DC calibration and X2
checks, and applies the nineteen retained OTP trims with source erased-cell
semantics. Fresh DACK requires complete bounded sampling, stable samples,
actual hardware IQ-vector receipts and residual convergence. It preserves
separate per-path RF originals; Linux's `path*i+i` backup alias cannot overwrite
path A with path B. No vector-cache restore, reset or recalibration is claimed.
The fixed CCK profile keeps source low-rate DPD disabled and selects the source
no-GAPK/no-DPK branch; it does not claim broad PHY calibration coverage.

H2C packet DMA uses the original retained 128-entry ring and one additional
80-byte coherent command mapping allocated while BME is off. All command
payload/BD mutations and MMIO publications invoke current PCI authority.
Occupancy commits before any reusable copy; one command remains pending until
its exact bounded hardware head advances. Foreign, stale or out-of-range heads,
timeout and cancellation cannot unlock a buffer. Original GeneralInfo and
PHYDM packets precede IQK. DMA retirement proves command transport only:
IQK additionally requires a non-stale pre-submit report and the firmware's
actual `RPT_CIP=0xaa` completion within 300 ms. A host write never fabricates
that receipt.

Before `Calibrated`, the continuation requires a fresh RPWM/CPWM awake toggle,
invalidates all 32 source CAM entries with bounded command completion, disables
CR/SECCFG hardware crypto and default-key search, and selects native RX with
PHY metadata and trailing FCS. MAC TX/RX and IRQs remain disabled. On completion
it parks BME and seals the completed firmware beacon BD and packet descriptor
inside current PCI authority, clears its work trigger and disables the beacon
function. Only then can it transfer the sealed, retained calibration `Gate`
to the same native packet owner. `Calibrated` describes that exact parked radio;
it does not assert association, carrier, DHCP or hardware acceptance.

A checked radio adapter re-invokes retained calibration authority and samples
the current authenticated policy before each host radio write across awaits.
The native packet gate likewise rechecks that same calibration and current
policy; no enum state or copied gain alone grants TX. The explicit model policy
closure is isolated from the native authenticated database.

`station_control::Admission` shares a closed flag and publication lock with
the station/device owner. Every asynchronous control helper checks admission
after waits and serializes the final synchronous MMIO/mailbox publication with
close; no publication lock spans an await. Port 0 binds the sealed factory MAC,
actual BSSID, checked AID and managed link type. Source awake/keep-alive-disable,
fixed CCK1 RA, media-status and default-port commands use the original four-box
HMEBOX protocol. The cursor and pending identity remain in the native owner;
actual HMETFR consumption is required before reuse and never presented as an
applied-command acknowledgement. Close prevents later peer publications;
terminal disconnect may drain a previously published mailbox and send media-down
without reopening the data port. Initial MLME uses the source long-slot20
setting; short-slot9 is selected only after the successful association response.

`StationPreparation` borrows the exact retained owner's backend; it never moves
or reconstructs that owner. It prepares one additional bounded packet buffer
with BME off, reuses the original management/BE TX rings and 512 RX mappings,
verifies the sealed firmware beacon request and source PCI configuration, then
enables MAC/HCI DMA and BME last. Interrupts remain masked. Every synchronous
poll advances a bounded amount of native DMA/RX/CCX work, so kernel DHCP and
ARP/ND callbacks can make progress without a second executor task. Frame
callbacks use nonblocking owner/ring locks; stack receive callbacks run only
after those locks and publication guards have dropped.

The default native TX descriptors select fixed CCK1 and software security;
the distinct C22 N22L profile below can extend ordinary DATA only. A consumed TX
buffer proves transport retirement only. Authentication, association and EAPOL
security replies additionally require the matching fresh CCX identity and ACK,
the exact immutable MPDU bytes, and the receive-idle reuse fence; DMA retirement
alone cannot commit M4. RX descriptors must prove original legacy20 native MPDU
bytes without hardware decryption or decapsulation. Wi-Fi FCS is stripped
exactly once; C2H bytes are never treated as Wi-Fi payload. Current PCI authority,
the retained signed calibration cap and fresh authenticated policy are checked
before every native packet publication and progress step.

Scan admits channel1/2412 MHz plus any signed N2xO primary (see the
noninitial-channel section below), bounded dwell and SSID filters.
Active scanning and driver-admitted extra probe IEs are implemented on that
channel (`src/rtw88/scan.rs`, `station.rs::scan_for`) as Linux's software
scan: this profile has no `FW_FEATURE_SCAN_OFFLOAD`, so `rtw_ops_hw_scan`
returns 1 and mac80211 sends one broadcast-DA/wildcard-BSSID Probe Request
per SSID (empty list = one wildcard; at most `RTW_SCAN_MAX_SSIDS`=4) with
SSID, all twelve legacy rates (Supported/Extended, no basic flags), DS
Parameter Set channel1, then the caller's IEs. `max_scan_ie_len` is
`IEEE80211_MAX_DATA_LEN` less those driver elements (2227 bytes), so every
probe fits the retained2304-byte TX MPDU. Caller IEs must be well formed and
may not repeat SSID/rates/DS; extra IEs on a passive scan are refused. Each
probe uses the ordinary management queue (QSEL18, W0 BMC, rate ID8/CCK1,
no CCX report) under the same current PCI/calibration/regulatory checks as
authentication, so a NO_IR or otherwise disallowed policy prevents the first
probe DMA. Probes are published one at a time and retired on DMA consumption
before the dwell; unicast Probe Responses feed the same shared observer as
beacons. Random-MAC scanning follows Linux v6.12: `main.c::rtw_register_hw`
sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR` (`supports_scan_random_mac`),
and `rtw_core_scan_start` points port0 `REG_MACID` (0x610) at the
mac80211 `get_random_mask_addr` address (random bits outside the mask, base
bits inside; cfg80211 `nl80211_parse_random_mac` requires the mask to keep
the group bit of a unicast base). Every probe uses that SA, packet core
admits a broadcast Probe Request from exactly the current scan address,
and Probe Responses to it feed the observer. `rtw_core_scan_complete`
restores the own address and clears the packet scan address on every
exit. Passive requests transmit nothing and bind no address; association
always uses the own address. Evidence: `drivers/wireless/rtw88/narrow/scan`
(mask/variation/probe SA) and `drivers/wireless/rtw88/random_scan`
(actual DMA probe SA, 0x610 follows and is restored, joining afterwards
uses the own address); a mask clearing the group bit is refused.
6 GHz scanning stays refused. HT capability elements
are not added to probes. Native smokes: `scan_tests.rs` (exact preq bytes,
SSID/IE budget, malformed/unsupported requests, BMC/MGMT/no-report
descriptor) and `station_composition_tests.rs` (actual DMA probes, probe-
response-only BSS joined, NO_IR refusal without TX publication). The shared
association parser validates actual beacons, authentication and association
responses, including mandatory supported rates. Open and WPA2-PSK use that same
retained peer transition. WPA2 uses shared host RSNA and packet-key owners for
nonce, replay, CCMP and controlled-port admission; no hardware key-cache fallback
is available. Kernel Ethernet enqueue admits the sealed local source MAC,
bounded Ethernet-II frames and no checksum/TSO/VLAN offloads. It rechecks current
authority before CPU queue publication and native DMA checks independently.
Explicit channel/power changes outside the retained profile are refused.

The shell and station share one `Admission`. Activation, scan and association
future cancellation closes it terminally before releasing the retained owner.
Public disconnect reserves teardown under the publication lock and publishes
link-down before awaiting the lifecycle mutex. Closed workers retain native
cleanup access while that reservation exists: source NoLink/media-down precedes
packet stop. Dropping a cancelled reservation leaves admission closed and allows
the next worker to stop the retained packet owner. No disconnect or error
reopens the one-shot radio. Deauthentication, peer liveness/security deadline,
native failure and policy/cap revocation close the data port and carrier.
Temporary WPA2 rekey closure preserves established carrier while blocking
ordinary data. New frames and returned RX are suppressed after terminal close.
Hardware carrier publication changes only the carrier metadata, preserving
operator-controlled IFF_UP. It cannot invoke an administrative open/stop hook
while the retained owner or metadata lock is held.

One atomic lifecycle claim prevents concurrent/repeated reconstruction.
The exact inner owner is retained before its first DMA publication.
Timeout, access failure, failed readback, checksum error or cancellation
leaves a terminal owner; a new attempt returns `State` without allocation
or device access. Published mappings remain retained on every error and
Drop, including a failed parking sequence or revoked authority. A later
reset/removal implementation must establish device quiescence before
reclaiming them; this stage deliberately has no reclaim/retry path.

### RTL8821CE parked operating-power continuation

After the same owner's successful IQK, `rtl8821c_operating_power_request()`
exposes the immutable calibration/board/firmware/program digest and exact
MAC-bound `rtw88/rtw8821ce-power-v1-<mac>.bin` filename. The identity binds
channel1/20MHz, actual source RF-A TXAGC addresses, fresh RF42 conversion,
zero unused MCS lanes, source RRSR_INIT_2G=0x15f and closed packet gates.
Actual thermal samples gate admission independently; changing a valid sample
within a measured interval does not manufacture a different board identity.

The signed N21P v1 record is exactly160 bytes: magic0, version:u16 at4,
header-size:u16 at6=160, total-size:u32 at8=160, VID/DID at12/14,
identity[32] at16, MAC[6] at48, channel/bandwidth at54/55=1/20,
antenna upper bound:i16 quarter-dBi at56, board EIRP:i16 quarter-dBm at58,
complete operating-program conducted peak:i16 at60 and aggregate autonomous
response conducted peak:i16 at62, thermal min/max:u8 at64/65, `US` at66/67,
twelve explicit CCK/OFDM gain indices at68, twelve per-rate measured conducted
peaks:i16 at80, and zero reserved104..159. Indices must be0..63 and no higher
than the retained factory channel1 CCK/OFDM base. Original C21 RFE2/4 selects
pathB's2G factory record for physical RF-A; other admitted RFE uses pathA.
The OFDM signed nibble uses C21 txgi_factor1; erased/wrapped factory values
fail. These indices and peaks are actual external measurements over the whole
qualified board/antenna/supply/temperature range, never inferred factory dBm
or substituted C22 data. All peaks plus antenna gain must satisfy the board
ceiling, every overlapping installed host restriction and conservative20dBm ceiling.
The aggregate complete-program peak must also enclose every per-rate/response peak.

Missing, unsigned, foreign or unqualified assets leave the completed IQK owner
retryable before writes. Both actual signed source invocations enclose native
operations; installed policy is required without implicit reload. The active
attempt becomes terminal before access, triggers a source two-second RF42
conversion, checks actual thermal/IQK/RF08 state, writes and reads back three
packed legacy TXAGC words, zeroes the five unselected MCS words and programs
the exact response mask. Cooperative yields preserve ownership between words;
the outer attempt is bounded to three seconds. Cancellation, current-source or
policy loss, ignored writes and transport failure retain firmware/command DMA.

Success earns `Operating8821cPrepared` and historical
`rtl8821c_operating_power_info()`, with BME, MAC TX/RX, producers and IRQs still
closed. Sibling provisioning continues to this stage when the exact asset is
available. This is parked power preparation; the independent full awake grant
below is required before native packet/peer activation. Three composed native Rust
smokes cover exact words, BTG factory substitution, retry, per-rate/response/
thermal limits, partial I/O, cancellation and both source/device revocation.

### RTL8822CE separately qualified legacy12 DATA and WMM BE/TID0

`rtl8822c_legacy_wmm_request()` exposes metadata only after the retained C22
radio has completed. Its `C22LegacyWmmRequest` contains the exact recipe
SHA256, factory MAC and
`rtw88/rtw8822ce-legacy-wmm-v1-<12 lowercase MAC hex digits>.bin` filename.
The identity binds the original board identity, exact signed N22Cv2 digest,
both selected CCK references, original OFDM reference0/legacy differences0,
source response-mask function, native descriptor/rate policy, bounded EDCA
recipe, and software CCMP/raw QoS semantics. A different calibration, board,
gain selection or emitted program needs a different signed identity.

The optional signed128-byte little-endian **N22L** record is:

| Offset | Meaning |
|---|---|
|0..4|`N22L`|
|4..8|version1 and header length128 (u16 each)|
|8..12|total length128 (u32)|
|12..16|VID0x10ec, DID0xc822 (u16 each)|
|16..48|exact extended station recipe SHA256|
|48..54|exact factory MAC|
|54..56|channel1, width20MHz|
|56..60|signed antenna gain and qualified EIRP ceiling (i16 quarter-dB units)|
|60..64|signed measured full-program transient and automatic-response conducted peaks (i16 quarter-dBm each)|
|64..88|twelve signed worst-case DATA conducted peaks in IEEE order1,2,5.5,11,6,9,12,18,24,36,48,54Mbps|
|88..90|measured allowed-rate bitmap, bits0..11 only, including1Mbps|
|90|bit0 permits WMM BE/TID0; all other bits zero|
|91..128|zero reserved bytes|

Each enabled rate and both global peaks require actual measured values in
range−128..64dBm, antenna gain0..32dBi and a ceiling in the same signed power
range. Disabled-rate slots supply no authority. These are worst-case bounds
for the complete static awake operating envelope, including temperature;
there is no narrow-temperature or adaptive-compensation shortcut. The original
N22Cv2 source and its acknowledged gain/power ceiling remain current and
mandatory. All new peaks plus antenna gain must fit the minimum of its
current applied ceiling and N22L's ceiling. No real measurement is supplied.

Association looks up this optional record through trusted firmware authority
before changing hardware. Missing, malformed, unsigned, foreign, revoked or
currently denied N22L retains the original qualified CCK1 legacy path. A valid
extension requires the AP's basic rates to be measured. Only this C22 sealed
grant can attach to the retained native packet gate; C21 cannot obtain it.
After attachment, both signed source invocations and the current installed
host policy enclose actual register/CPU-DMA/doorbell/BME publications. Source
or observed policy loss then closes that owner permanently; reinstalling
policy cannot restore it. No live operation implicitly bootstraps policy.
The extension retains a statically base-only `ExtensionBase`: C22's
`CalibratedBase` contains the original calibration source/permission; the C21
arm retains its actual N21S source. Neither arm routes through an
extension-aware packet gate, and an already extended gate refuses extraction.
C21 still refuses extraction as a C22 `CalibratedBase`. Current source
enclosures therefore remain chip-specific and generic dispatch stays acyclic.

Shared `wireless::wmm` parses the original complete AP offer and the bound
successful association response. Only a valid offered Parameter IE and a
WMM-enabled N22L cause the driver to append its no-UAPSD Information IE to
the actual association frame. Caller WMM cannot replace this driver-owned IE.
The bound response must contain one valid Parameter IE; malformed, duplicate,
missing or BE-ACM parameters fail before a data port opens. Its actual set
count/UAPSD/AC rows are retained; response parameters may update the offer.
Only the response's common supported rates intersected with measured rates
become the new DATA bitmap, and every negotiated basic rate must remain in it.

Linux `mac80211.c::__rtw_conf_tx` maps canonical BE/BK/VI/VO to registers
`0x508/0x50c/0x504/0x500`. The driver encodes TXOP in32us units, ECW exponents
and AIFS=`10 + AIFSN * slot`, with slot20 initially and slot9 only after actual
AP capability intersection. BE is conservatively clamped to AIFSN≥3,
CWmin≥31, CWmax≥1023 and TXOP0. Other AC rows preserve the bounded response
facts but have no host producer. Unsupported AIFS/TXOP extents are rejected.
Every source register value is read back, with a cooperative cancellation
boundary between ACs; partial writes never admit QoS/data or release DMA.

The source RA mailbox uses actual negotiated legacy bits and rate-ID B8,
BG6 or G7, initRA1, power-training disabled,20MHz and no SGI/HT/VHT/LDPC.
Consumption is transport evidence, never an invented applied firmware ACK.
The highest permitted IEEE bit rate is selected for ordinary DATA; IEEE
descriptor numbering is not monotone because11Mbps exceeds6/9Mbps. Source
`rtw_phy_get_rrsr_mask(selected_rate) & RRSR_INIT_2G` programs and reads back
`0x1f/0x5f/0x15f`; N22L's distinct automatic-response peak must cover it.
Both selected CCK references, both OFDM references0, all three zero legacy
difference words and disabled hardware crypto are checked through the exact
native owner before/after the extended programming. New RF tables or gain
measurements are never inferred from descriptor rate IDs.

Only then does the same packet core install its qualified DATA profile.
TXDESC48 uses source fixed-rate/no-fallback fields, the actual legacy rate-ID,
BE QSEL0 and manual sequence. It admits raw QoS26/TID0 only when negotiated;
other TIDs, A-MSDU, AMPDU, hardware sequence, SGI and wider PHY modes stay
closed. QoS is formed before shared host CCMP, so its nonce/AAD/MIC match the
actual26-byte header. EAPOL/security and management stay legacy24/CCK1 and
retain exact consumed-DMA+CCX+MPDU/M4 receipt requirements. RX ordinary data
is bound to the permitted response-rate bitmap and original legacy20 native
descriptor; raw QoS requires TID0/control0 and negotiated WMM before delivery.

A qualified non-WMM AP keeps legacy24 headers/DCF and can use measured richer
DATA rates. An unqualified WMM AP retains the original legacy CCK1 connection.
The same registered shell, firmware owner, original PCI rings, packet buffer,
RSNA/CCMP and controlled-port lifecycle remain retained. Safe shutdown uses
current PCI authority even after RF-source revocation. Host QoS/rate admission
retires before any uncertain native cleanup; no reset/reconstruction occurs.

Thirteen new native Rust smokes cover distinct qualification/fallback, all twelve
literal descriptor rates and source EDCA units, response-updated WMM and
response-narrowed rates, Open/WPA2 real kernel DHCP and exact bidirectional IP,
non-WMM legacy headers, each partial EDCA wait's cancellation/source/policy,
malformed/missing response or gain/register loss, held/modified M4 and late
receipts, and descriptor/RX revocation before publication. These are native
software models; actual firmware/RF acceptance and signed full-envelope assets
remain external. N22L alone does not grant HT; the distinct HT profile below
extends it. Full AC/TID scheduling, broader HT/VHT, BA/reordering, other channels,
dynamic RF tracking, recovery and PM remain work.

Final host publication uses a retained private `Publication` scope, shared by
the unchanged C21/C22 legacy and extended C22 paths. It retains the exact chip's
signed-source gate and native PCI authority/device; each invocation validates
the live sources/current policy and actual BME/MEM/INTX state before enclosing
the carrier or frame publication. The station uses it after the last native
RX-idle read, before M4 key admission, established state and releasing received
Ethernet. The interface independently uses it for activation, post-await
carrier, TX/RX ring publication after allocation and each final network-stack
callback. The stack callback retains no device/ring/admission locks, so an
ARP/ND reply can reenter enqueue safely. Native read success and earlier
qualification snapshots cannot authorize these later publications. Two exact
native-idle hooks revoke either signed source or current policy only after
the final descriptor/register observation; regressions check suppressed RX
frames/carrier, terminal reinstall denial and stable retained DMA.
An enqueue regression additionally revokes source/current policy after the
publication scope is captured but before invocation. Outer authority/PCI
failure maps to terminal Access; inner host ring-full remains retryable and
can resume after real native progress.

### RTL8821CE full awake radio and retained native station

`rtl8821c_station_request()` is available after the same owner's N21P success.
It returns the exact recipe identity, MAC and
`rtw88/rtw8821ce-station-v1-<12 lowercase MAC hex digits>.bin` filename.
The SHA256 identity binds the immutable N21P program, all12 selected gain
indices, C21 channel/RFE/swing retention, fresh thermal conversion, literal
CAM/wake/response programming, native PCI formats/rings and bounded port0
station recipe. It changes the response mask from parked `0x15f` to the
initial station's `0x1f`; old IQK/parked records never authorize that sequence.

The separate signed128-byte little-endian **N21S** record is:

| Offset | Meaning |
|---|---|
|0..4|`N21S`|
|4..8|version1, header length128 (u16 each)|
|8..12|total length128 (u32)|
|12..16|VID0x10ec, DID0xc821 (u16 each)|
|16..48|exact awake-station recipe SHA256|
|48..54|exact unicast factory MAC|
|54..56|channel1, width20MHz|
|56..60|signed antenna gain, qualified EIRP ceiling (i16 quarter-dB units)|
|60..66|signed measured ordinary-packet, automatic-response and complete awake-program transient conducted peaks (i16 quarter-dBm each)|
|66..68|raw thermal minimum0/maximum63; full static awake envelope is mandatory|
|68..70|trusted profile country `US`|
|70..128|zero reserved bytes|

The source must have a verified signer and current blob authority. The actual
N21Q, N21P and N21S capability invocations nest around every native radio
operation, packet-memory access, MMIO publication and PCI BME enabling. The
current installed host domain must cover the entire2402..2422MHz span with
at least20MHz, no restrictions except NO_P2P and countryUS. All intersecting
rules contribute their minimum power ceiling; all three measured peaks plus
antenna gain must fit that ceiling, signed ceiling and the initial20dBm board
profile. Live checks read current policy without implicitly reinstalling it.
N21Q/N21P limits and current source authority remain mandatory too. Missing,
foreign, unsigned, revoked or policy-denied N21S leaves the parked checkpoint
retryable without register writes. No real measurement asset is supplied.
This initial awake profile has no continuous conversion watchdog, so N21S
must qualify every possible six-bit meter value0..63. A narrow N21S thermal
interval is rejected even when the initial reading lies within it. Thus a
one-time sample cannot authorize an indefinitely awake narrow-temperature
program. The earlier N21Q/N21P intervals still constrain the actual preparation
samples; N21S must independently bound all subsequent static-gain awake RF.

The C21-specific continuation checks its retained RF18 channel, RFE/swing,
original12 TXAGC values and zeroed unused HT/VHT words, RF08 cleared after
genuine IQK and zero failed/reload status. It triggers a fresh RF42 conversion
and preserves the source two-second wait, checks the actual meter against all
three signed intervals, invalidates all32 source CAM slots with bounded busy
receipts, disables hardware encryption/decryption and retains native raw RX.
The source RPWM3d9/CPWM3da handshake requires a fresh device toggle. There is
no C22 DACK/trim/RF callback substitution or inferred RF-mode receipt. This
entire attempt has a four-second deadline. Failure/cancellation after its
first access is terminal and retains the exact owner and published mappings.

The original completed beacon descriptor is disarmed through the retained
reserved-page owner only under actual parked PCI authority; C21 is already
parked after IQK/N21P, so it does not reuse C22's active-command parking
transition. Success earns `Radio8821cPrepared` and historical
`rtl8821c_station_radio_info()`. This copyable receipt itself grants no TX.
Only its sealed exact-chip grant can admit the common PCI packet backend.

Original `rtw8821c.c`/`rtw8822c.c` chip-info and `pci.c` share48-byte TXDESC,
16-byte TXBD,24-byte RXDESC and8-byte RXBD formats; C21's checksum callback
belongs to USB, not this PCI path. The same retained seven TX rings and512 RX
buffers continue into the MGMT128/BE256 packet owner, using consumed indices
plus actual CCX for security/management delivery. Common `fw.c` port0
ACTIVE/media/RA/default-port commands and `main.c`/`mac80211.c` MAC/BSSID/AID/
conservative DCF semantics are reused. C21 RF, EFUSE and qualification remain
distinct. The qualified shell then uses shared MLME/RSNA/host CCMP and exposes
Open/WPA2, passive ch1/20, CCK1 ordinary TX and receive-only legacy rates;
no QoS, aggregation or HT/VHT admission is inferred by N21S alone.

Seven new native Rust smokes compose the actual reserved-DMA firmware/MAC/PHY/
IQK/N21P owner through radio and packet/station. They cover literal CAM/wake/
gain/mailbox/DCF receipts, retry without writes, receipt failures, pending
thermal cancellation and all three source/policy losses, real descriptor
Open/WPA2 kernel DHCP and exact bidirectional IP, and held M4 cancellation/
late receipt/terminal reinstall and actual descriptor-to-doorbell source/policy
revocation. These are inert software models. Physical
RF acceptance, real signed measured assets and qualification over the full
permitted awake operating/temperature envelope remain external gates; dynamic
power tracking and thermal compensation are not claimed by N21S; the distinct
N21W continuation below is required.

### RTL8821CE separately qualified legacy12 DATA and WMM BE/TID0

`rtl8821c_legacy_wmm_request()` returns `C21LegacyWmmRequest` after genuine
same-owner N21S radio preparation. Its MAC-bound
`rtw88/rtw8821ce-legacy-wmm-v1-<mac>.bin` name and SHA256 identify a distinct
C21 program: the exact retained N21S recipe and signed-record digest, all12
actual N21P TXAGC indices, RF-A channel/IQK state, source EDCA/RA/RRSR, native
legacy12 fixed DATA selection and raw QoS26/host CCMP. This metadata grants no
RF authority and cannot request a C22 qualification.

The signed128-byte **N21L** record uses the N22L field layout documented above,
with magic `N21L`, DID0xc821 and this exact C21 identity. Its enabled-rate
bitmap (including1Mbps), independently measured12 DATA peaks, complete-program
transient and automatic-response peaks, antenna gain, ceiling and optional
WMM flag apply to the complete static awake raw thermal range0..63. A narrow
initial sample cannot replace that full measured envelope. No actual measured
asset is supplied. The original N21Q/N21P/N21S sources stay mandatory/current;
every actual radio/control/packet/host publication nests their invocations with
the new N21L capability. All peaks plus antenna gain fit the new signed ceiling,
current N21S ceiling,20dBm profile and every overlapping host-policy minimum.
Missing, foreign-chip, malformed, unsigned, revoked or denied N21L preserves
the original N21S CCK1 legacy profile before any changed hardware operation.
Once attached, observed source/policy loss is terminal, including after native
RX/CCX read and before final carrier/frame publication; reinstall cannot reopen.

C21's own `rtw8821c_set_tx_power_index_by_rate` packs the measured indices in
RF-A `0x1d00/0x1d04/0x1d08`; the five unused HT/VHT words remain zero. This
continuation reads all eight actual words, RF18 ch1/20, RF08 cleared after IQK,
zero failed/reload status and disabled hardware crypto before/after extended
control programming. It never reads or substitutes C22's `0x18a0/0x41a0`
reference gains or `0x3a00` relative-difference power format. Source C21 chip
info independently declares matching48/16/24/8 PCI descriptors and
`old_datarate_fb_limit=false`; its RA and EDCA port0 ABI matches the reviewed
common path. No new RF/calibration completion or thermal sample is inferred.

Only a strict offered WMM Parameter IE, N21L WMM permission and the actual
bound association response admit BE/TID0. The same response's common measured
legacy rates drive RA/rate-ID and the highest IEEE bit rate for ordinary DATA.
Source EDCA readbacks, conservative BE limits and the source response mask
precede native profile admission. Management/EAPOL remain legacy24/CCK1; QoS26
is formed before host CCMP, unsupported TIDs/A-MSDUs/AMPDUs and HT/VHT remain
closed. A qualified non-WMM peer retains legacy headers; an unqualified WMM
peer keeps the prior CCK1 connection. Original firmware/beacon/command and
packet DMA owners remain retained without reset, replay or ring replacement.

Eight new native Rust smokes compose the actual C21 reserved-DMA firmware,
inactive MAC/PHY, IQK, parked-power, awake and station owner through this path.
They check exact-chip asset refusal/retry and legacy fallback, Open/WPA2 real
kernel DHCP and bidirectional IP, actual source TXAGC/EDCA/RA/RRSR/descriptors,
response narrowing and non-WMM headers, bad QoS/MIC/replay, partial EDCA
cancellation and all four signed-source/policy losses, missing/duplicate/ACM
responses or native register/RF/IQK loss, held/modified/late M4 and actual
descriptor/final-RX publication revocation. Firmware bounce bytes and native
packet allocation identity stay unchanged; ambiguous exits retain DMA.
These are inert software models, not physical RF acceptance. Real full-envelope
signed assets, HT/VHT widths/aggregation, other bands/channels, full AC/TID (now N2xQ),
dynamic tracking/coexistence, recovery and PM remain explicit gates/work.


### C21/C22 separately qualified HT20 and SGI20 station

The same retained RTL8821CE and RTL8822CE station owners can now select
channel1/20MHz HT MCS0..7 with long GI and optionally SGI20. Native source
hardware facts, the exact AP offer/request/response, a distinct signed HT
emission record and all preceding current grants are independent gates.
Existing N21S/N22C records retain their1Mbps profile; N21L/N22L alone retain
legacy12/WMM. An absent, malformed or currently denied optional HT input
preserves that existing legacy connection before writes. Once attached,
observed source/policy loss or partial programming is terminal.

`Rtw88Device::ht20_request().await -> Ht20Request` supplies exact identity,
MAC and filename metadata for external measurement. It requires the matching
current L qualification. The names are
`rtw88/rtw8821ce-ht20-v1-<mac>.bin` and
`rtw88/rtw8822ce-ht20-v1-<mac>.bin`. The hash binds the actual chip-specific
L recipe and complete signed-record digest, already bound factory/cut/RFE/
firmware/calibration identity, genuine boot C2H hardware-feature report,
source factory ceiling and retained gain program, native gain/control/
descriptor/receive/ADDBA program below. It grants no measured limit or RF
permission. No real HT measurement asset is supplied.

The signed little-endian record is exactly192 bytes:

| Offset | Field |
|---|---|
|0..4|`N21H` or `N22H`, matching actual C21/C22 |
|4..8|version1:u16, header192:u16|
|8..12|total192:u32|
|12..16|VID0x10ec and exact DID0xc821/0xc822|
|16..48|request identity|
|48..54|exact factory MAC|
|54..56|channel1, width20|
|56..60|antenna upper bound and board EIRP ceiling:i16 quarter-dB units|
|60..64|whole-program transient peak and automatic-response peak:i16 quarter-dBm|
|64..66|raw thermal minimum0/maximum63: full static envelope|
|66..68|nonempty MCS0..7 bitmap and flags bit0 SGI20 permission; other bits0|
|68..76|eight explicit MCS gain indices|
|76..92|eight long-GI conducted peaks:i16 quarter-dBm|
|92..108|eight SGI20 conducted peaks:i16 quarter-dBm|
|108..132|twelve retained legacy-rate conducted peaks:i16 quarter-dBm|
|132..192|reserved zero|

RTL8822CE additionally exposes an optional `HtRequest.two_streams` proposal
when the original hardware report has at least two streams and antennas,
and both retained factory paths have complete HT1S/HT2S power fields. The
original v1 identity and record remain unchanged. The child is named
`rtw88/rtw8822ce-ht20-2ss-v2-<mac>.bin`; its identity binds the complete v1
recipe plus both stream ceilings and the exact native two-path program.
It contains no nested proposal and grants no authority. The registered
loader prefers this separately authenticated asset; only absence permits
fallback to the original v1 asset. An invalid present v2 cannot authorize
v1 or2SS. C21 has one physical transmit path and exposes no2SS proposal.

The additional N22H v2 record is exactly256 little-endian bytes. Bytes0..66
retain the corresponding v1 field meanings, except header length and total
length are256 and version is2. Its remaining layout is:

| Offset | Field |
|---|---|
|66..68|nonempty u16 TX MCS0..15 mask, including at least one2SS rate|
|68..70|SGI20 bit0 (other bits zero), literal RX stream count2|
|70..86|sixteen explicit MCS gain indices|
|86..118|sixteen long-GI conducted peaks:i16 quarter-dBm|
|118..150|sixteen SGI20 conducted peaks:i16 quarter-dBm|
|150..174|twelve retained legacy conducted peaks:i16 quarter-dBm|
|174..256|reserved zero|

For MCS8..15 the factory ceiling follows Linux7.3-rc4
`phy.c::rtw_phy_get_2g_tx_power_index`: BW40 group0 base plus both the signed
HT1S BW20 high nibble of power byte11 and the additional signed HT2S BW20
low nibble of byte12, multiplied by txgi_factor2, intersected across A/B.
Erased, negative and unrepresentable values fail closed. The signed v2
record measures simultaneous-chain combined conducted power, every selected
LGI/SGI rate, retained legacy/automatic responses and the complete transition
under all original thermal/supply/antenna/BT bounds. Individual chain gains
or factory indices never stand in for that measurement.

Before changing paths the original native packet owner proves all joint
TXBD/CCX completions, every original TX host/device index pair, no pending
mailbox/H2C ring command, MAC TX-empty and matching reserved/free quotas.
It pauses all TX and parks RX with actual RW_RELEASE/RXDMA_IDLE receipts.
Only then does it write/read back the16-rate signed difference table and
equal MCS7 references, ANT820 low byte0x31 and TXLGMAP1e2c low16bits0x0400,
with the source OFDM/outer SYS_FUNC_EN BB_RSTB reset sequence. CCK and1SS
stay on A;2SS uses A/B; existing RX-AB remains intact. Current original
source and policy, exact gain/path/crypto readbacks and the parked receipt
must all pass before RX and TX resume. Partial failure or cancellation
cannot restore publication or free an unproven native owner.

Association under v2 advertises local RX MCS0..15 independently of the
qualified TX selection. The original AP offer and response may narrow TX
to one stream without narrowing local RX. RA_INFO uses BGN20_2SS RAID2 or
GN2SS RAID4 and bits12..27; native fixed-rate TXWD/RXD admit codes12..27,
BW20 and only the locally authorized receive mask. ACK basic-rate selection
uses the actual two-stream data rate; MCS8 does not imply a24Mbps ACK.
The A-MPDU duration bound accounts for the second HT-LTF. Original1SS
coding continuations cannot widen to coded2SS; two-stream TX stays uncoded.
Original software CCMP, PN/SN, key/reply epochs, default3839-byte A-MSDU,
source-bound BA continuations and native DMA ownership remain in force.
The native cases cover Open/WPA2 MCS8..15, SGI, DHCP/IP, peer1SS TX with
local RX2SS, original v1, invalid measurements and source/path failure.
These are source-written cases awaiting the release validation batch;
physical acceptance still requires the board's actual signed v2 asset.

The complete transition peak must enclose all other peak fields. All peaks
plus antenna gain must satisfy this record's ceiling, every preceding signed
source ceiling and all overlapping current host rules. Unknown, indoor,
NO_IR/DFS and too-narrow restrictions fail closed. Measurements cover the
entire static raw0..63 thermal range and board/antenna/supply/BT states;
one meter sample or a factory index is never a power measurement. Current
C21 Q/P/S/L/H and C22 calibration/L/H capability invocations enclose the actual
native operation, carrier, IPC and unlocked stack callback. The typed base
grant graph remains acyclic.

C21 retains its original12 absolute legacy indices and uses exact source
RF-A `1d0c/1d10` for MCS0..7, keeping unused HT/VHT words zero. Its factory
HT20 upper bound uses the original high signed nibble of the selected power
record, BW40 group0 base and txgi_factor1, with RFE2/4's pathB-to-RF-A
substitution. Erased/wrapped factory data never manufactures a ceiling.
Fresh source RF42 conversion, existing Q/P/S thermal bounds and actual
RF18/RF08/IQK/crypto readbacks remain necessary.

C22 preserves TX-A/RX-AB, original CCK references and legacy effective gains.
It programs both OFDM reference fields `18e8/41e8` from the selected MCS7
index, then source signed7-bit differences at `3a00..3a3c`; MCS0..7 occupy
`3a0c/3a10`. Both physical paths use the same explicit bounded indices;
their factory HT20 ceilings use txgi_factor2 and are intersected. Equal
references preserve existing effective legacy OFDM index0; unselected
rates have effective index0. Unrepresentable signed differences are refused.
This is the source reference/difference format, never C21's absolute format.
Every word/reference is read back before native packet-profile admission.
No new DPK/GAPK completion, tracking or measured peak is inferred.

The shared opt-in PHY observer and JoinPlan retain original mandatory HT
membership selectors and emit an owned HT request. Caller PHY/WMM elements
remain rejected. Local RX supports MCS0..7, SGI20, default3839-byte A-MSDU,
8KiB A-MPDU capability factor and source2us density; local TX uses the
measured MCS/GI subset. Width remains20MHz, SMPS is disabled and no
LDPC/STBC/greenfield/HT-control/VHT or extra stream is advertised.
The actual bound response may narrow TX MCS/GI, while local RX bounds remain
independent of the AP's receive bitmap. Unsupported HT protection modes,
missing/duplicate elements, wrong primary and unsupported mandatory basic
MCS cannot partially commit a new peer.
The published per-band capability body is cached only after retained native
station activation and reports this factual one-stream HT20/default3839-byte
implementation on2400MHz; it grants no measured power or association right.
The mandatory hardware TX/RX MCS0..7 body remains intact while the typed
TX selection separately restricts the actual measured/native transmit set.

Native EDCA retains response WMM and conservative BE/TID0 policy. Source
H2C40 uses BGN20_1SS RAID3 (or GN1SS5 for the corresponding rate set),
full HT mask bits12..19, BW20, SGI bit23 only when negotiated/qualified,
PT disabled and no LDPC/VHT. DATA uses actual fixed descriptor codes12..19
and W5 SGI bit4 with fallback disabled; management/EAPOL stay1Mbps/raw24.
AGG_EN and aggregate count remain zero. The native RX parser admits only
MCS0..7/BW20 under the attached H profile, preserves original ciphertext/
IV/MIC/FCS semantics and refuses hardware plaintext. Ordinary RX TIDs use
separate shared replay state; host TX remains BE/TID0.

The complete original RAW QoS A-MSDU is admitted only at native HT rates,
under the actual AP/receiver/header/profile and an already-open port.
Protected input passes through `Security::receive_amsdu` once, with bounded
whole-aggregate authentication, syntax and per-TID/key PN commit before any
subframe publication. Open input uses the same bounded whole-body decoder.
The mandatory default3839-byte body fits the original retained RX mapping.
Malformed later subframes or MIC/replay failure publish no prefix and do not
consume a valid aggregate's PN. Captured closed-port data is discarded
before crypto; ReplyReady clears queued/decoded originals so a late M4 or
rekey receipt cannot retrospectively authorize it.

The retained packet Core selects its PHY decoder from the actual PCI chip,
never from AP bytes. After validated RXD bounds it reads exactly one32-byte
PHY-status record at `RX_DESC+shift`, before the driver-info/payload boundary.
The four driver-info units are eight-byte blocks, not four status pages.
C21 page1 uses HT_RXSC at word1[15:12], with zero falling back to RF_MODE
at word3[29:28]; source codes1..8 mean20MHz,9..12 mean40 and13..15 mean80.
C21 has no channel field and never interprets C22's channel byte. C22 page1
uses the same RXSC map, zero falls back to this retained programmed20MHz
owner, and word1[23:16] must report channel1. Both chips bind CCK to page0
and OFDM/HT to page1; C22 page0 also checks its actual channel field. Unknown
pages, reserved C21 fallback mode, wide/foreign reported facts, duplicate
status extents and truncated native storage cannot reach CCMP/PN. No PHY
record is synthesized when PHYST is absent: source-valid RXD rate/BW0 and
the retained channel owner remain the factual inputs, and PHY evidence is
`None`. No first-only PPDU context or cross-MPDU PHY carry is introduced.

Native ReplyReady, exact terminal security reply and local close advance a
monotone receive epoch. Publication tokens retain that exact generation;
changed generations retire queued RX IPC too. Before each unlocked stack
callback the driver refreshes the actual retained owner/current controlled
port, then drops owner/ring/admission locks and rechecks the token inside
current source/PCI invocation. An old batch is discarded after a callback
drives rekey, including a fully reopened new epoch, without closing that
legitimate current station. Receive authorization is independent of ordinary
TX credit, so a reentrant held ordinary packet does not masquerade as key
closure or invalidate the rest of the received aggregate.

This slice owns a genuine native ADDBA-decline path rather than claiming a
BA agreement from an HT offer. A bound, complete immediate single-TID AP
request produces Category3 response status37 through the retained management
DMA slot and actual CCX receipt/current authority. Foreign/malformed requests
produce no transmission; held, cancelled or uncertain native management
ownership remains pinned. This remains the behavior under H alone. The
separately qualified recipient extension below adds RX BA; the distinct
originator extension then adds bounded native TX A-MPDU. Shared Reorder alone never
supplies Realtek BA negotiation, native receipt or descriptor authority.

Twenty-three new native smokes (eleven per chip plus a literal source PHY
decoder/offset case) compose exact retained owners:
Open/WPA2 long/short-GI DHCP/IP; every MCS and independent RX bounds; real
3839-byte authenticated A-MSDU/replay; distinct asset retry/legacy fallback;
original mandatory selectors and response narrowing/refusal; lost native
gain writes; actual ADDBA decline/held receipt; held/altered/cancelled M4
across all signed sources; and descriptor/native-RX/current-policy publication
fences with retained DMA. Synthetic records remain private fixture inputs.
The added native PHY cases cover original DATA/A-MSDU bad-PHY-to-same-PN
retry, missing/duplicate/truncated/shifted records and distinct chip fallback
semantics. Actual two-subframe callback regressions cover held/reopened group
rekey and held ordinary TX, independently checking the actual group reply MIC.
Physical signed assets, EVM/RF/silicon acceptance and external interoperability
are deployment/acceptance gates, not outcomes of these software tests.

### C21/C22 separately qualified recipient RX Block Ack

`Rtw88Device::rx_ba_request().await -> RxBaRequest` returns exact-H measurement
metadata, not a radio grant. The names are
`rtw88/rtw8821ce-rx-ba-v1-<mac>.bin` and
`rtw88/rtw8822ce-rx-ba-v1-<mac>.bin`. Each identity binds the retained chip's
H recipe, complete signed H-record SHA256, factory MAC, original RAW receive
contract, explicit-SSN BA protocol/control/receipt program and source readbacks.
Production opens authenticated signed firmware-registry inputs; no real measured
R asset is supplied. Private synthetic records are fixture inputs only.

The signed little-endian record is exactly128 bytes:

|Offset|Field|
|---|---|
|0..4|`N21R`/`N22R`, exact C21/C22|
|4..8|version1:u16, header128:u16|
|8..12|total128:u32|
|12..16|VID0x10ec, exact DID0xc821/0xc822|
|16..48|RX BA request identity|
|48..54|exact factory MAC|
|54..56|channel1, width20|
|56..60|antenna upper bound and R EIRP ceiling:i16 quarter-dB units|
|60..66|whole transition, autonomous compressed-BA response and management peaks:i16 quarter-dBm|
|66..68|full raw thermal envelope0..63|
|68..70|maximum window1..64; nonzero allowed TID0..7 bitmap|
|70..128|reserved zero|

Every peak plus antenna must meet the R ceiling, preceding H/source ceiling
and current overlapping host rules. The transition peak encloses both response
peaks. Measurements must cover success/DELBA, automatic BA and corresponding
traffic/duty/supply/antenna/BT states over the full static thermal range. H's
decline/no-TX-BA program is never reinterpreted as this changed emission program.
The R grant retains that exact H owner; its actual capability invocation wraps
native operations and final host publication through the existing acyclic
grant graph. Missing/malformed/unqualified optional R inputs remain retryable
before writes and preserve H's native status37 decline/non-BA connection.
Observed loss of an attached R or preceding source/policy is terminal.

The source `rtw_ops_ampdu_action` RX_START/RX_STOP operations perform no
per-session register/H2C program. This implementation does not invent a BA
CAM or applied firmware acknowledgement. Before success it checks retained
HT gain/crypto state, source RAW/FCS/PHY/RCR flags without BASSN/header conversion,
each chip's original control filter, BAR retry setting and C22-only BA-parser/
ACK-type readbacks. C21's no-channel PHY page and C22's reported channel/width
rules remain unchanged. The retained filter is `RXFLTMAP1=0xffff` on both:
C21's initial `mac_init` value0x0fff is overwritten by its later source MAC
table's `0x6a2=0xff,0x6a3=0xff`. R performs no new filter write. These exact
post-table facts are included in R's request identity. Automatic SIFS BA generation and over-air behavior
remain physical/firmware acceptance work.

Only the current bound, established HT/WMM peer can request a recipient
agreement. An exact33-byte immediate-policy request carries the actual SSN,
dialog, TID0..7, timeout and window; zero window means64, and the signed maximum
may narrow it. This profile requires request A-MSDU bit1 and emits bound
response bit1: native RX does not expose reliable aggregate-membership facts,
so admitting a no-A-MSDU agreement would make a mandatory standalone original
indistinguishable from an excluded in-A-MPDU original. Requests without that
bit retain status37 and standalone3839 reception. No delayed/multi-TID BA,
TID8..15 session, fragmentation or firmware-deaggregated piece is admitted.

Each TID has one bounded window and at most one pending proposal. Same-dialog
identical retries preserve existing ordering; changed parameters cannot reset
the active window using the same dialog. A different proposal retires old
buffered ownership before success. The actual success response uses retained
management DMA and an immutable-body/native-index/matching-positive-CCX receipt.
Only an additional genuine RX-idle observation can activate its host window.
After real native publication, a bounded opaque prefix (at most that window)
may be staged against the exact pending request, peer/TID/SSN and still-open
controlled-port/key/receive epoch. The AP can legitimately receive success
before the host observes CCX. This prefix is neither authenticated nor
delivered until the exact success ACK plus idle; capture ages are retained
when originals enter reordering. Pre-proposal, unsent-proposal and closed-port
captures cannot acquire that grant retrospectively. Failure, cancel, DELBA or
an epoch change discards the entire pending prefix. A peer originator DELBA
can cancel a held proposal before its receipt. Unsent success controls and
same-batch captured requests are removed before publication; a submitted
control instead retains native ownership/receipt drainage without activation.
Selection alone never marks a control submitted. Uncertainty/cancel/negative or
altered receipt closes admission and retains possibly published DMA.

The host window is explicitly seeded with the on-air SSN using shared
`Reorder::advance`; unknown-SSN offload auto-sequence is not used. Complete
pre-SSN originals before the BA stream starts follow source semantics through
the actual key/PN owner without replacing that negotiated head. Complete
original unicast QoS MPDUs are routed by the current peer/TID, staged opaquely
and sequence-ordered before shared CCMP/per-TID replay or whole A-MSDU decode.
Native metadata, original header and negotiated profile must agree before
staging. The entire3839-byte body, IV and MIC stay intact; no prefix, partial
firmware piece or cross-TID/key carry is accepted. Normal-ACK QoS can belong
to BA; explicit BlockAck-policy QoS needs that current ordered session.
Explicit BlockAck A-MSDU uses the additive shared security opt-in only for a
reordered original with a current live recipient session; normal-ACK standalone
input keeps the stricter existing API. The original header is never normalized.
An ordinary output batch also leaves room for one complete maximum-subframe
original before any authenticated subframes are handed to publication.

Genuine compressed single-TID20-byte BARs are admitted through a separate
native control envelope and bound RA/TA/reserved/fragment/SSN checks. They
advance only the matching active window. Hole expiry runs at100ms even when
RX is idle; negotiated nonzero inactivity is separately measured in1024us
TUs. Timeout zero creates no inactivity timer. Inactivity retires host
admission before a native30-byte recipient DELBA/CCX; a peer's recipient
DELBA cannot tear down an RX session. ReplyReady, actual terminal key receipt,
peer loss, local close and current-source loss discard all buffered originals,
proposals and queued output under the existing receive/publication epochs.
An exact original plaintext unicast EAPOL from the bound authenticator remains
private protocol input if M3 was copied before the terminal M2 receipt retires
the data epoch. It still requires the actual shared Supplicant phase/MIC/replay
checks; captured data admission remains false and no DATA/BA/publication right
is inferred. Ordinary and aggregated old/closed captures remain denied.
CPU staging can be dropped; no such transition reclaims native DMA without
terminal ownership. Under R without the separate T extension, TX AGG_EN/count
stay zero and host TX stays BE/TID0.

Twenty-two added native smokes are validated: ten per chip plus literal protocol
and native separate-grant/CCX cases. They cover Open/WPA2 real DHCP through
out-of-order native replies and exact IP; explicit SSN/wrap/windows/BAR/100ms/
TU inactivity; original3839 A-MSDU, bad PHY/MIC-to-same-PN retry, independent
TID replay and many-subframe admission; held success/peer DELBA/old-capture;
signed asset refusal/retry/H fallback; every preceding source, R/policy loss,
cancel/uncertain payload and retained DMA; and a genuine held group-key reply
retiring an old window. They passed the coordinated native software suites.
Two additional native reply-epoch regressions, one per chip, inject a real
M3 and protected DATA before M2 CCX, require the actual held M4 continuation,
and then retry that identical DATA/PN only after the genuine M4 receipt.

### C21/C22 separately qualified originator TX Block Ack

`Rtw88Device::tx_ba_request().await -> Result<TxBaRequest, FirmwareError>`
returns the exact current request identity, station MAC and expected registry
filename. It grants no radio authority. `tx_ba_power` loads a separately
signed192-byte N21T/N22T record through the actual firmware registry/capability
owner. T retains an acyclic concrete H base, or R over that exact H; its identity
binds the complete H record and, when attached, the complete R record/digest.
An H-only T asset cannot authorize a later R automatic-response program.
The base gains, previous R peaks and all T peaks must each fit the minimum of
the current host/channel ceiling, all preceding grants and T's own ceiling.
Every real publication invokes the current T/base/firmware/PCI authority;
retained bytes or an earlier valid capability cannot substitute for it.

|Bytes|T record field|
|---|---|
|0..4|`N21T`/`N22T`, exact native chip|
|4..12|version1, header192, total192 (little endian)|
|12..16|VID10ec and exact DIDc821/c822|
|16..48|exact H or R-over-H request identity|
|48..56|station MAC, channel1, width20|
|56..60|antenna gain and maximum EIRP:i16 quarter-dBm|
|60..68|complete transition, automatic response, control and entire retry/burst conducted peaks:i16|
|68..72|full static thermal range0..63, maximum batch2..4, maximum peer window1..64|
|72..76|maximum native aggregate bytes1560..8191 and conservative airtime2500..4000us:u16|
|76..108|eight LGI and eight SGI conducted MCS peaks:i16|
|108..192|reserved zero|

This record's measurement contract includes the actual retry/burst duty,
transients, supply/antenna/coexistence envelope and native automatic responses.
It is an external exact-board qualification, not an inference from single-MPDU
H measurements. No measured real-board T asset is provided. Missing, unsigned,
malformed or restricted optional T input before binding leaves the existing
H/R nonaggregate connection unchanged. Once T is attached, observed loss is
terminal even if its source or policy is subsequently reinstalled.

Source `mac80211.c::rtw_ops_ampdu_action` TX_START is immediate and TX_OPERATIONAL
sets host per-queue eligibility; it has no per-session firmware ACK command.
This implementation instead owns the genuine on-air33-byte immediate TID0
ADDBA request, actual retained management DMA and requested matching CCX,
bound peer/dialog/status/TID/window/timeout response, actual RX idle and MAC
quiet before enabling native AGG_EN. The SSN is sampled from the actual next
per-TID producer before crypto: shared `Security::next_qos_sequence(0)` for
WPA2 or a separate retained Open QoS counter. Non-QoS EAPOL/management use a
different counter; no protected header is rewritten and no SSN is invented.
Fresh key continuations use a fresh dialog, preserving the per-TID sequence.
Wrong, refused or timed-out peer responses retain nonaggregate H data only
after submitted control ownership drains and native DELBA closes uncertainty.

Before that dialog, T programs and reads back the exact source
`coex.c::rtw_coex_limited_tx` retry value `RETRY_LIMIT(0x042a)=0x0808` and
`AMPDU_MAX_TIME_V1(0x0455)=0x20`. Fixed native MCS/GI and disabled fallback
remain from H. The full state machine is the separate N2xK owner, which leaves
these two registers to T while T is bound.
The separate R BAR/RA aggregate limit `0x04ce=0x0801` is unchanged and still
checked by R. These distinct addresses and complete T-over-R emission recipe
allow the recipient and originator owners to coexist without relaxing either
grant's readbacks. T alone retains H's recipient refusal.

The native packet Core preallocates four independent coherent32-bit-addressed
TXD/body buffers while the device is parked, in addition to its original
control/single-packet allocation. It publishes at most four immutable original
QoS26 TID0 DATA MPDUs through separate actual BE descriptors and one final WP
doorbell. Source `tx.c` permits AMPDU and REQ_TX_STATUS independently: W2 has
AGG_EN bit12, SPERPT bit19 and peer density[22:20]; W3 MAX_AGG_NUM=3 uses the
mandatory8191-byte/factor0 ceiling. No USB DMA aggregation field, TX A-MSDU,
protected-header rewrite or invented firmware BA bitmap is used. Byte/airtime
admission includes hardware FCS, delimiter, padding, HT service/tail symbols,
mixed preamble and a conservative density allowance before consuming PN/SN.
The actual current T count/byte/airtime limits and peer window bound each batch.

Each original requires both the actual consumed PCI prefix and its own
matching positive native CCX; out-of-order CCX cannot reorder software receipts.
Receipts read the exact retained DMA bodies, not saved host copies. A new
burst, key publication or control transfer additionally waits for source
`mac.c::__rtw_mac_flush_prio_queue`'s16-bit reserved/available equality on
the actual BE and management priority FIFOs selected by `TXDMA_PQ_MAP`.
The exact C21/C22 queue geometry is independently checked. PCI consumption,
CCX or ring emptiness alone is insufficient. Invalid counters, changed
mapping, negative/duplicate reports or a bounded1s drain timeout close and
retain the native allocations. After an acknowledged burst and genuine MAC
quiet, an actual20-byte compressed BAR at the producer's current next SSN
uses retained native control DMA and CCX. No returned bitmap is treated as
a fabricated radio receipt; native MAC retry/status remain authoritative.

Peer recipient DELBA and negotiated nonzero TU inactivity retire host TX
eligibility before more DATA. Local key/close/current-source transitions
retire active TX BA, drain submitted ownership, and serialize a native
originator DELBA as appropriate. Security's actual controlled-port and current
key/receive epochs remain authoritative independently of ordinary TX credits.
All earlier RX publication/callback epoch fences remain in force. Partial BD
publication, cancellation, corrupt payload or uncertain receipt pins every
possibly visible buffer; no reset/reclamation proof is inferred.

Twenty added native smokes are validated: eight per chip, three native packet
Core cases and one literal protocol/receipt case. They exercise Open/WPA2 real
DHCP/IP, actual four-buffer descriptors and ordered receipts, H/R/T identity
and power intersections, invalid assets/H fallback, real SSN/response/refusal/
TU timeout, held request CCX/cancel, FIFO/source/policy loss, partial-BD
revocation, peer DELBA and genuine group-key reply/drain/reopen. Combined T/R
cases preserve `0x04ce=0x0801` while checking T's separate program and receiving
opaque reordered originals through real CCMP/PN. Together with the two
cross-reply epoch regressions above, all44 added cases passed the coordinated
native software suites. The full scoped Wi-Fi suites reported x86_64:
2317 pass/0 fail/9 skip, and aarch64:1847 pass/0 fail/3 skip. These are full
scoped Wi-Fi totals, not RTW88-only counts. Production boots and both btrfs
postflight checks also completed cleanly on each architecture. Debug/release
builds and strict Clippy, including the exact CI feature contexts, passed. None of
these software results establishes silicon or RF acceptance.
TX A-MSDU, larger/native IRQ pipelines, wider PHY/channels, reset/rejoin and
power management remain software work. All-AC routing uses N2xQ below;
originator agreements beyond TID0 use the separate v2 program next.

### C21/C22 qualified originator BA on every non-VO TID

The separate N21T/N22T v2 program implements actual originator BA on admitted
TIDs0..5 across BE/BK/VI, preserving the complete v1 record/identity and its
BE/TID0-only permission. `TxBaRequest` adds `all_tids_identity` and
`all_tids_filename` alongside its unchanged v1 fields. Each agreement has its
own actual producer SSN, globally unique nonwrapping dialog, peer window/TU,
current control/CCX state and key retirement. Other TIDs begin on real DATA
demand; VO and EAPOL retain their source exclusions.

Public IPC selects a same-TID FIFO prefix and complete length/airtime bounds
before SN/PN. The four actual original mappings publish on that TID's physical
BE/BK/VI ring with its own depth, consumed prefix and each positive CCX.
Source RQPN FIFO quiet and actual RX-idle precede the matching TID BAR and any
next burst/key/control. All agreements share the original serialized physical
owner. Current N2xQ admission encloses native batch publication, with checks
before each BD/final WP; stale or partially published work stays closed/pinned.

[RTW88 originator BA on non-VO TIDs](rtw88-originator-all-tids.md) specifies
its distinct v2 full-program qualification and exact Linux call chain. No real
measured asset is supplied. Sixteen new native registrations are written,
including real Open/WPA2/kernel DHCP for each chip, all-TID physical rings,
mixed IPC prefix/SN/PN, v1 negatives, per-TID DELBA/TU/key, held native controls
and callback source loss, plus actual ring-wrap/consumed-prefix Core cases.
New release/native and physical acceptance remain pending.

### C21/C22 separately qualified native RTS threshold

`Rtw88Device::rts_request().await -> Result<RtsRequest, FirmwareError>`
returns exact current H/R/T source-program identity, factory MAC and the
expected `rtw88/rtw882{1,2}ce-rts-v1-<mac>.bin` registry name. It grants no
power or transmission permission. The optional X extension retains a concrete
acyclic H, R-over-H or T-over-exact-H/R owner; the request binds every
preceding recipe and full signed record digest, including the actual T
retry/burst limits. H/R/T assets cannot themselves grant RTS.

The real registry loader requires a signed128-byte N21X/N22X record. Missing,
unsigned, malformed or restricted optional input before binding preserves
the preceding non-RTS station. Actual attached-source or policy loss closes
the owner and cannot be repaired by a later asset/policy reinstall. The
minimum of current policy, X and every earlier grant bounds every emission;
previous H data, R automatic-response and T retry/burst peaks must fit that
same limit, with each record's own antenna bound. No measured real-board X
asset is supplied.

|Bytes|X record field|
|---|---|
|0..4|exact native chip `N21X` or `N22X`|
|4..12|version1, header128, total128 (little endian)|
|12..16|VID10ec, exact DIDc821/c822|
|16..48|current H/R/T program request identity|
|48..56|factory MAC, channel1, width20|
|56..60|antenna upper bound and maximum EIRP:i16 quarter-dB units|
|60..68|whole transition, native RTS, automatic-response and complete retry/control/burst conducted peaks:i16 quarter-dBm|
|68..70|full static thermal range0..63|
|70..72|smallest measured/admitted finite RTS threshold0..2347:u16|
|72..128|reserved zero|

The measurement contract covers actual RTS/CTS/retry/control/data transitions,
burst duty, supply, antenna, coexistence and all static raw thermal values.
It does not infer those quantities from HT gains or a single-MPDU measurement.
T's existing DATA-PPDU byte/symbol/density limits remain in force when T is
attached; the extra RTS/control emission envelope requires X independently.

The existing `WirelessNetIface::{rts_threshold,set_rts_threshold}` API is
implemented for this single live retained HT20 station only after actual
X admission and negotiated support for source24Mbps RTS. The initial setting
is disabled (`u32::MAX`), which does not change the original H/R/T emitting
program. Finite settings must lie between the signed minimum and2347;
`u32::MAX` disables. Invalid values return EINVAL, unqualified/unsupported
requests return EOPNOTSUPP, and an occupied native/key/control owner or
nonempty MAC FIFO returns EBUSY without changing the setting. Configuration
never waits for another executor while holding an IRQ-safe lock. No additional
vdev or reset/recovery continuation is implemented by this API.

Before publishing a setting, the exact retained owner must have an open real
controlled port, no pending DATA/security/BA operation, current H gains/crypto
readbacks and source native BE/management FIFO emptiness. Its actual X/base
capabilities enclose the atomic setting change. The value survives a genuine
same-owner key replacement; it creates no key, peer or controlled-port right.
The public cached value reports configuration, not transmission authority.

Source `mac80211.c::rtw_ops_set_rts_threshold` and `tx.c` select RTS for eligible
ordinary DATA only when the original MPDU length is strictly greater than the
threshold. The native packet Core adds exact source W3 USE_RTS bit12,
W4 RTSRATE[28:24]=8 (`DESC_RATE24M`) and W5 DATA_RTS_SHORT bit12 to that
original's descriptor. It requires the bound response's actual24Mbps rate;
mandatory HT capability alone is not substituted for that negotiated fact.
The QoS header, sequence, plaintext/ciphertext and CCMP nonce/MIC are never
rewritten. Management, BA controls and raw24 private M2/M4/group-key replies
stay on their existing non-RTS source descriptors and legacy rate.

Single RTS DATA requests genuine native CCX and requires its exact retained
DMA bytes plus consumed PCI ownership and positive radio status. It then
requires the actual source MAC FIFO drain before another DATA/control/key
publication or threshold change. T's four-buffer path keeps each MPDU's
same independent CCX/consumed-prefix/FIFO proofs and R's exact source BAR
mode. A negative/duplicate/corrupt/missing receipt, invalid FIFO, bounded1s
drain timeout, cancellation or current-source loss closes admission while
retaining every possibly published native allocation. There is no fabricated
RTS firmware acknowledgement or inferred returned BA bitmap.

Twelve new native smokes are authored, six per chip: Open/WPA2 kernel DHCP/IP
over X-on-H/R/T, literal descriptor flags and strict threshold boundaries,
disable/old assets/unsigned and malformed input/retry, exact source identity
and prior-peak intersections, absent24Mbps response support, held CCX and
genuine group-key reply with RTS absent, native FIFO/corrupt/negative/cancel
failures, every preceding/X source and current policy loss, and revocation
between actual batch BDs with retained DMA. All twelve additive RTS cases passed
on both architectures in the coordinated scoped Wi-Fi suites: x86_64
2360 pass,0 fail,9 skip; aarch64 1890 pass,0 fail,3 skip. Production boots and
all btrfs postflights were clean. Earlier RX/TX BA totals describe the preceding
validated checkpoint. Native RTS/CTS execution and physical
RF/interoperability acceptance still require real firmware/silicon and the
external measured X asset.

No CTS-to-self or new AP HT-protection mode is inferred from the source RTS
path. Current width/stream/channel restrictions remain unchanged. Source
`rtw_ops_can_aggregate_in_amsdu` explicitly declines TX A-MSDU on2.4GHz;
the channel-1 owner therefore adds no TX A-MSDU producer. The 5GHz producer
is described in "5GHz TX A-MSDU and A-MSDU in A-MPDU".


### Separately signed continuation contracts and the dm watchdog

`qualification.rs` is the single reusable loader for every new RTW88 program
that needs its own measured authority. A static `Kind { tag, stem, source,
admit }` describes the program; the generic code supplies the 128-byte
layout (`N21<tag>`/`N22<tag>`, `[1,0,128,0]`, length, `ec 10` + PCI id,
identity, exact factory MAC, `[tag, 1]`, 64-byte kind payload, zero tail),
signer and capability checks, and `Grant::invoke(gate, op)`, which re-enters
the continuation capability and then the current base `Gate` (regulatory
policy and every bound base capability). The identity binds the chip, the
MAC, the exact retained board/calibration base (`Gate::extension_request`,
i.e. N22Cv2 or N21S) and the hashed upstream source contract. Requests are
filed as `rtw88/rtw882{1,2}ce-<stem>-v1-<mac>.bin`;
`Rtw88Device::tracking_request()` returns the `ContinuationRequest` for the
dm kind. New programs add a `Kind` instead of another bespoke loader.

`dm.rs` (tag `D`, stem `dm`) ports Linux `main.c::rtw_watch_dog_work`
(2 s period, run with the retained owner mutex held) and
`phy.c::rtw_phy_dynamic_mechanism`:

| Mechanism (payload bit) | Source | Chips |
|---|---|---|
| statistics | `rtw_phy_statistics`: RSSI EWMA(10,16) from peer PHY status, `rtw_phy_get_rssi_level`, H2C 0x42; `false_alarm_statistics` counters and reset pulses | both |
| DIG (0) | `rtw_phy_dig` thresholds/steps/damping/boundaries; signed `dig_max` caps `DIG_PERF_MAX` | C21 `0xc50`, C22 `0x1d70` both paths |
| CCK PD (1) | `rtw_phy_cck_pd` + `cck_pd_set` (8822c PD/CS deltas, 8821c `0xa08`/`0xaa8`), level capped by payload | both |
| RA (2) | `rtw_phy_ra_track`: H2C 0x58 WL-PHY info, every fourth period RA_INFO 0x40 with RSSI-level mask and NO_UPDATE, C2H 0x0c RA report, RRSR = retained qualified RRSR & report mask | both |
| TX path diversity (3) | `rtw_phy_tx_path_diversity` + `rtw8822c_config_{cck,ofdm}_tx_path` | C22 |
| CFO (4) | `rtw8822c_cfo_track`, crystal `0x1040[23:10]`, BT scoreboard reset, window bounded by payload | C22 |
| thermal power tracking (5) | `rtw8822c_pwr_track` type 0: RF42 trigger, EWMA(10,4), 2G/CCK swing tables, LCK at 8 steps, `0x18a0`/`0x41a0[6:0]` delta clamped to the signed up/down bound; samples outside the signed thermal window refuse | C22 |
| EDCCA adaptivity (6) | `rtw8822c_adaptivity` normal/ETSI(45)/JP(60) from the regulatory country (wireless-regdb DFS region), `0x84c` bytes 2/3 | C22 |
| DPK calibration + tracking (7) | `rtw8822c_phy_calibration` RFK power-save bracket around `rtw8822c_do_dpk`, then `rtw8822c_dpk_track` (`dpk.rs`); payload byte 9 bounds the PWSF offset | C22 |

The continuation binds at association and the watchdog runs only on an
established station. Each register group runs inside admission + continuation
+ base gate; H2C goes through the retained mailbox after a fresh grant check.
Revocation, policy loss or an out-of-envelope sample restores the base program
(initial IGI/EDCCA, factory crystal, path A, zero power delta, qualified RRSR,
level-0 CCK PD) under the base gate only and stops tracking for that
association. Deviations from Linux, each a qualification bound: the RRSR base
is the qualified mask rather than `RRSR_INIT_2G`; DIG/CCK-PD/crystal/power
deltas are capped by the signed payload; there is no unlinked DIG because the
continuation binds at association.

DPK (`dpk.rs`, bit 7, RTL8822C only, payload byte 9 = `dpk_window`
<= 0x3f and zero unless bit 7 is set) ports Linux v7.3 `rtw8822c.c`:
`rtw8822c_do_dpk` (BB `0x520..0x41a4`/RF `0,1a,55,63,87,8f,de` backups,
`dpk_tx_pause`, `rtw8822c_table.c` `dpk_mac_bb`/`dpk_afe_is_dpk`/
`dpk_afe_no_dpk`, `dpk_pre_setting`, `dpk_result_reset`, per-path
`dpk_gainloss` with the `pas_agc` gain/loss state machine and
`psd_log2base`, `dpk_by_path` one-shot + 20 coefficients, saturation check
and bypass coefficients, `fill_result` TXAGC-6, `dpk_on`/`dpk_cal_gs`,
`dpk_cal_coef1`, `dpk_enable_disable`, RF/BB restore + RXBB DC), every
one-shot bracketed by `dpk_set_gnt_wl` (`0x70` bit26 plus LTE-coex indirect
`0x38` byte1 = 0x77 through `util.c::ltecoex_{read_reg,reg_write}`), and the
`rtw8822c_rfk_power_save(false/true)` bracket of `rtw8822c_phy_calibration`.
`is_dpk_pwr_on` holds because the C22 base loads `rfk_init_tbl`
(`phy.c::rtw_load_rfk_table`). Calibration runs in the first watchdog
period after the D grant binds and again whenever RF18's channel differs
from the calibrated one (Linux reruns `phy_calibration` from
`rtw_chip_prepare_tx` after each channel set); otherwise each period runs
`rtw8822c_dpk_track` (EWMA(10,4) thermal, `0x1b58[6:0]` PWSF offset).
Deviations, each fail-closed or a qualification bound: thermal reads outside
the signed thermal window refuse (restore); the PWSF offset is clamped to
`dpk_window`; an LTE-coex indirect access that never becomes ready
(`check_hw_ready`) is a `Timeout` instead of Linux's logged zero; a zero GS
refuses instead of dividing by zero in `dpk_cal_coef1`; there is no
`dpk_reload` because each association starts a fresh tracker and recalibrates;
GAPK (`rtw8822c_do_gapk`) is not run, matching the retained base IQK, so
DPK runs on the post-IQK state without TX gain-gap calibration. The BB/RF
backup is held until the source restore completes, so a mid-calibration
authority loss or hardware failure still restores it (including the `0x522`
TX pause) under the base gate; base restore also clears both PWSF offsets,
re-enters RFK power save and turns DPD off on both paths.

Linux rtw88 reads no `ht_operation_mode` and takes no protection action
(`mac80211.c`, `tx.c`), so the retained station now admits APs that advertise
HT protection modes 1..3 unchanged. The check was local to rtw88; no shared
`JoinPlan` change was needed.

Evidence: nine `drivers/wireless/rtw88/dm_engine` register-model cases
(`dm_tests.rs`), five `drivers/wireless/rtw88/dpk` cases (`dpk_tests.rs`:
payload admission/`psd_log2base`, calibration enabling DPD with GS and
backup restore, window/envelope/restore tracking, channel-change
recalibration, LTE timeout and revocation; written, unexecuted), and composed C21/C22 Open/WPA2 watchdog, revocation-restore
and refusal cases (`dm_station_tests.rs`, `drivers/wireless/rtw88/dm/rtl882{1,2}c`)
plus HT protection modes 1..3 (`drivers/wireless/rtw88/ht_protection/*`).
These are software/model results. A real signed N2xD measurement and physical
acceptance remain external deployment gates.

### C21/C22 Bluetooth coexistence state machine (`N2xK`)

`coex.rs` ports Linux `coex.c` with the `rtw8821c.c`/`rtw8822c.c` chip hooks
and tables (`table_{sant,nsant}`, `tdma_{sant,nsant}`, `rf_para_{tx,rx}`,
`wl_rssi_step`/`bt_rssi_step`, AFH spans 0x24/0x36, `new_scbd10_def`,
`ble_hid_profile_support`, `bt_rssi_type`). It runs only under a separately
signed `N21K`/`N22K` continuation (stem `coex`, `qualification::Kind` tag
`K`) whose payload is `[modes, share_ant, rfe_option, btcoex, 0..]`:

| bit | family | Linux source |
|---|---|---|
| 0 `PTA` (required) | power-on/init, scoreboard, PTA/GNT/antenna path, coex tables, TDMA off, WL-only/BT-off/not-connected/all-off/IPS | `rtw_coex_power_on_setting`, `__rtw_coex_init_hw_config`, `rtw_coex_set_ant_path`, `rtw_coex_table`, `coex_cfg_{init,ant_switch,gnt_fix,gnt_debug,rfe_type}` |
| 1 `TDMA` | PS-TDMA on (H2C 0x60) and every BT-profile action using it | `rtw_coex_tdma`, `rtw_coex_action_bt_*`, `_wl_linkscan` |
| 2 `FREERUN` | non-shared freerun and every RF parameter set except the normal one (BT TX power H2C 0x62, BT LNA constraint H2C 0x67/op 0x32 + scoreboard RXGAIN, C22 WL RX low gain RF 0xde/0x1d) | `rtw_coex_action_freerun`, `rtw_coex_set_rf_para` |
| 3 `BAND5` | pure-5GHz action/antenna path | `rtw_coex_action_wl_under5g`, `COEX_SET_ANT_5G` |
| 4 `MIMO_PS` | C22 only: coexistence-driven 1SS on 2GFREE (see below) | `rtw_coex_mimo_ps`, `rtw_set_txrx_1ss`, `rtw8822c_config_trx_mode` |

Board facts are never supplied by the record alone: `Facts` carries the
retained efuse `rfe_option`, raw `rf_board_option` and `bt_setting`;
`share_ant = bt_setting & BIT(0)` and `btcoex = (rf_board_option & 0xe0) ==
0x20` (0xff normalised to 0) exactly as `main.c::rtw_chip_efuse_info_setup`.
A record qualified on different facts never binds; a WL-only board
(`!btcoex`) admits only `PTA` and stops after init (`stop_dm`). An action
needing a family the record does not carry returns `Unsupported`; the
station then restores the base and unbinds coexistence for the station's
lifetime (fail-closed, like the dm envelope).

Trigger points (`station.rs`, `CoexEvent`): bind + `rtw_power_on` program at
station `start`; `rtw_core_scan_start`/`_complete` (`COEX_SCAN_START`/
`FINISH`) around `scan_for`; `rtw_set_channel` band change in `retune`
(`switchband`, 5G or 2.4G for/not-for scan); `mgd_prepare_tx` connect start
before authentication; `BSS_CHANGED_ASSOC` connect finish + media connect
after `commit_peer` (beacon interval recorded after the run, as
`BSS_CHANGED_BEACON_INT` follows); media disconnect in `disconnect` before
the owner closes; C2H 0x09/0x0b/0x27/0x45 queued by `progress` and handled
after it returns (`rtw_c2h_work`); every 2s watchdog the busy-traffic
change (`tx_cnt`/`rx_cnt` > 100, `wl_status_change_notify`),
`rtw_coex_wl_status_check` (BT counters 0x770/0x774, 0x76e) and
`rtw_coex_query_bt_hid_list`; the eight delayed works (relink 1/6s,
reenable 15s, defreeze 5s, wl_remain 12s, bt_remain 4s, connecting 2s,
multi-link remain 3s, cck-lock 3s) run as deadlines from the watchdog and
after each `poll`. `stop` restores synchronously (best effort, base gate
only) like `rtw_coex_power_off_setting`.

Every touched MAC byte/word/dword, RF register and LTE-coex indirect word
(0x38/0xa0/0xa4 via 0x1700/0x1704/0x1708 with `check_hw_ready`) is backed
up on first write and restored in reverse order; restore also sends TDMA
off and a zero WL channel info when they had been sent nonzero.
`rtw_coex_limited_tx` programs 0x45e/0x426/0x430/0x434 and, unless the T
originator owner is bound (it already holds the same coex-limited values
and checks their readbacks), 0x42a/0x455.

Deviations, each explicit: the BT MP info request (scan type / LNA
constraint) is not awaited for 10ms; its 0x0b reply updates
`bt_ble_scan_type` when it arrives. WL RSSI comes from the bound N2xD
tracker (`min_rssi`); without it RSSI is 0 (every RSSI state LOW: no
RSSI-driven freerun). The noisy-environment CCK count is 0 (no CCK FA
counter is shared with coex), so `wl_noisy_level` stays 0.
`COEX_PS_LPS_OFF` records `wl_force_lps_ctrl` (`Coex::forces_lps_off`),
which refuses LPS entry like ps.c `rtw_enter_lps`
(`State::coex_forces_lps_off` in `Owner::lps_window`). The LPS window sends
`CoexEvent::Lps(true)` (`rtw_coex_lps_notify(COEX_LPS_ENABLE)`) before the
LPS power-mode H2C and `CoexEvent::Lps(false)` after the confirmed ACTIVE
wake (or when entry stays unissued); unassociated IPS sends
`CoexEvent::Ips(true)` (`rtw_coex_ips_notify(COEX_IPS_ENTER)`) from
`Device::idle_claim` before the station stops, which then unbinds and
restores coexistence. `COEX_IPS_LEAVE` has no separate caller: the fresh
generation's coexistence `start` (`rtw_coex_power_on_setting` + `init_hw`,
scoreboard ACTIVE|ONOFF, `wl_under_ips` clear) is that state. HID game detection (and with it `COEX_WLINK_2GFREE`)
requires `MIMO_PS` (`hid_supported`, Linux `wl_mimo_ps_support`); a 2GFREE
mode reached without it is refused (`Unsupported`, restore and unbind).

#### Coexistence-driven static SMPS (`smps_txrx_1ss`, C22 `MIMO_PS`)

Linux sources: `coex.c::rtw_coex_run_coex` exit (`wl_mimo_ps_support`:
2GFREE -> `rtw_coex_mimo_ps(force = reason 2GMEDIA, true)`, otherwise
`(false, false)`), `rtw_coex_mimo_ps`, `main.c::rtw_set_txrx_1ss`,
`rtw_vif_smps_iter`, `rtw_update_sta_info` (`hal.txrx_1ss` -> 1SS RA mask),
`tx.c::rtw_tx_pkt_info_update` (`stbc = hal.txrx_1ss ? false : ..`),
`rtw8822c.c::rtw8822c_config_trx_mode` and mac80211
`ht.c::ieee80211_request_smps`/`ieee80211_send_smps_action`,
`cfg.c::__ieee80211_request_smps_mgd`, `status.c::ieee80211_handle_smps_status`.

- Hardware (`coex.rs` `Coex::config_trx`, run after every coex event in
  `station.rs::coex_event`): on entry the exact `rtw8822c_config_trx_mode(A,
  A, false)` field program (`TRX_1SS`): ORITXCODE 0x1800 = 0x33312,
  ORITXCODE2 0x4100 = 0x11111, CCK RX A (0x1a2c 18:17/22:21 = 0, 0x1a04
  27:24 = 0), OFDM RX A (0x1d30 9:8/22:21, 0xc44[17], 0xc54[20], 0xc38[24] =
  0, 0x824 27:24/19:16 = 1), CCK TX A (0x1a04 31:28 = 8, `bb_reset`), OFDM TX
  A (0x820 7:0 = 0x11, 0x1e2c 7:0 = 0, `bb_reset`), `bb_reset`,
  `toggle_igi`. The pre-entry field values are retained first; exit (and
  `Coex::restore` at unbind/failure) writes them back in the same order with
  the same resets and IGI toggle, so the base paths return exactly. Linux
  exit reprograms `hal.antenna_tx/rx`, which is the retained base program.
- Path-diversity ownership: before entry the station calls
  `dm::Tracker::hold_tx_path` (base gate) which returns 1SS TX diversity to
  path A (`rtw_phy_set_tx_path_by_reg(A)`); `dm::Period::txrx_1ss` then skips
  `rtw_phy_tx_path_div_select` and drops its samples until exit. Linux keeps
  running path diversity (it checks only `hal.antenna_rx`) and could select
  path B while ORITXCODE2/RX run A only; here 0x820/0x1a04/0x1e2c never have
  two writers at once.
- Readback: `ht::Grant::set_txrx_1ss` makes the two-stream (N22H256v2) TX
  readback expect 0x820 = 0x11 instead of 0x31 (TXLGMAP 15:8 and CCK path
  are unchanged).
- Station (`follow_txrx_1ss`, `hal_profile`, `txrx_1ss_live`): once the
  native packet owner is idle the DATA profile drops 2SS HT/VHT rates and
  STBC (descriptor W5 STBC = 0, highest rate 1SS); DATA waits (`Busy`) until
  it has. The next watchdog sends RA_INFO with the 1SS mask and dm's periodic
  RA_INFO uses the same profile. Exit restores the negotiated profile.
- AP notification: on an associated HT link a changed request queues
  `ieee80211_send_smps_action` (DA = BSSID = AP, category 7, action 1, SM
  power control static = 1 on entry, disabled = 0 on exit). It goes out in
  the native control slot after BA control frames; an unacknowledged status
  is ignored like `ieee80211_handle_smps_status`. `packet_format::smps_action`
  admits only that shape on an HT profile.

Deviations, explicit: the hardware half runs after the run's `gnt_fix` /
`limited_wl` writes but before the H2C commands (ch_info) are sent; the RA
rate id follows the masked set (Linux keeps `tx_num = hw_cap.nss`), because
the fixed-rate descriptor here must not name an MCS8..15 rate on one path;
`associate` returns `Busy` while 1SS is in effect (the HT program owns the
same TX path fields; 2GFREE needs `wl_connected`, so the media-disconnect
run clears it first); mac80211's `req_smps` is per station lifetime here,
so the next association request never carries a stale static SM PS.

Evidence: `drivers/wireless/rtw88/coex`
`smoke_rtw88_coex_c22_mimo_ps_config_trx_mode_and_exact_restore` (1SS
fields, resets, IGI toggle, idempotence, exact exit and unbind restore) and
`smoke_rtw88_coex_mimo_ps_unqualified_refused_and_smps_frame_shape`, and
`drivers/wireless/rtw88/dm_engine`
`smoke_rtw88_dm_path_div_held_under_coex_txrx_1ss` (`coex_tests.rs`,
`dm_tests.rs`). Written, **unexecuted**; the station-side profile/RA/action
path has no composed case yet. No signed N22K `MIMO_PS` record, BT-active
measurement or over-the-air SMPS capture exists.

Evidence: five `drivers/wireless/rtw88/coex` register-model cases
(`coex_tests.rs`): record/efuse admission, C22 power-on/init program, C22
non-shared A2DP table 112/TDMA 113 4-slot/limited TX, unqualified TDMA
refusal with exact restore, revoked authority writes nothing. Written,
**unexecuted**. No signed N2xK record, BT-active measurement or physical
coexistence pass exists.

### C21/C22 HT TX coding: LDPC and STBC (`N2xC`)

`coding.rs` (tag `C`, stem `coding`) is the first TX/PHY feature qualified
through the generic continuation contract. Linux v6.12 sources:

- `main.c::rtw_init_ht_cap` (~L1540): every chip advertises one-stream RX
  STBC (`1 << IEEE80211_HT_CAP_RX_STBC_SHIFT`); HT `LDPC_CODING` only with
  `chip->rx_ldpc` (`rtw8822c.c` `.rx_ldpc = true`, `rtw8821c.c` false);
  HT `TX_STBC` only with `chip->tx_stbc` (`rtw8822c.c`).
- `main.c::rtw_update_sta_info` (~L1200): `si->ldpc_en` from the peer's HT
  `LDPC_CODING`, `si->stbc_en` from the peer's nonzero HT `RX_STBC`.
- `tx.c::rtw_tx_pkt_info_update` (~L375): `stbc = hal.txrx_1ss ? false :
  si->stbc_en`, `ldpc = si->ldpc_en`; `tx.c::rtw_tx_fill_tx_desc` encodes
  `tx.h` `RTW_TX_DESC_W5_DATA_LDPC` (BIT 7) and `W5_DATA_STBC` (bits 9:8).
- `fw.c::rtw_fw_send_ra_info` / `fw.h` `SET_RA_INFO_LDPC` (H2C word0 bit 26).

RX advertisement is a local decode promise and belongs to the base HT
station: with a bound N2xH every HT association request now carries RX
STBC1, and C22 also carries LDPC. Emitting coded PPDUs changes the waveform,
so it needs a separate `N2xC` continuation over the exact retained base.
Payload byte 0 requests TX LDPC (bit 0) and TX STBC (bit 1); every other
byte is zero. C21 is one-path and may request LDPC only, matching Linux,
which gates no TX LDPC on the chip. The grant loads, identity-matched, before
`JoinPlan` preparation, so the offer advertises `TX_STBC` only when a
matching N2xC exists. Its live check runs when it binds into the retained
`Gate` (`with_continuation`), right after the HT program. A grant that is
not current at that point leaves TX uncoded.
At the association response the data profile takes LDPC/STBC only where the
qualified flags and the shared `HtNegotiation::tx_ldpc`/`tx_stbc` (peer
capability) agree. `wmm::ra_info` sets RA_INFO bit 26 and the native
descriptor sets W5 bit 7 and W5 bits 9:8 = 1. `Gate::allows_profile` admits a
coded profile only with a current bound grant whose flags permit it.

While coexistence holds `hal.txrx_1ss` (C22 `MIMO_PS`, see "Coexistence-driven
static SMPS") `Station::hal_profile` forces STBC off in the native
descriptor and limits RA_INFO to one stream; the negotiated coded profile
returns on exit. The
coding grant is not part of `Gate::current`. Every DATA send and every
watchdog pass call `coding_live`. If the grant is revoked or no longer
matches, the station drops to the uncoded HT profile under the base gate.
The next watchdog then resends RA_INFO without LDPC, and the link stays up.
Teardown clears the bound coding.

Evidence: two `drivers/wireless/rtw88/narrow/coding` cases (descriptor W5
bits, payload bounds, peer/flag intersection) and composed C21/C22 cases in
`drivers/wireless/rtw88/coding/rtl882{1,2}c` (`coding_tests.rs`):
advertisement, coded descriptor and RA_INFO, revocation downgrade, an
unqualified station, a peer without coding, refused records and teardown.
A real signed N2xC measurement and over-the-air acceptance remain external.

### C21/C22 all-AC WMM and all-TID QoS routing (`N2xQ`)

`qos.rs` (tag `Q`, stem `qos`) lifts the base N2xL single BE/TID0 producer
to every TID and all four EDCA rings. Sources:

- `net/wireless/util.c::cfg80211_classify8021d` (RFC 8325 DSCP to 802.1d,
  IPv4/IPv6/MPLS/802.21, no QoS map) picks the TID of each Ethernet frame.
- `net/mac80211/wme.c::{ieee802_1d_to_ac,wme_downgrade_ac,
  ieee80211_downgrade_queue}`: with no admitted TSPEC, ACs whose AP WMM
  parameter has ACM set are stepped down (BK when every lower AC needs
  admission).
- `rtw88/tx.c::rtw_tx_ac_to_hwq` maps VO/VI/BE/BK to the hardware rings
  and `rtw_tx_pkt_info_update` sets `qsel = skb->priority` (the TID).
- `rtw88/pci.h` `RTK_PCI_TXBD_IDX_{VO,VI,BE,BK}Q` (0x3a0/0x3a4/0x3a8/0x3ac)
  and `pci.c::max_num_of_tx_queue` (BE 256, others 128). The original
  retained owner already maps all seven rings; packet core now drives
  BE/BK/VI/VO.

Payload byte 0 is the qualified set of extra ACs (bit 0 BK, bit 1 VI,
bit 2 VO); every other byte is zero. The continuation binds into the
retained `Gate` right after the WMM extension, and only when the AP
advertised WMM. `DataProfile::acs` carries the set and
`Gate::allows_profile` admits it only with a current bound grant.
Classification is followed by the ACM downgrade. A TID whose AC is not
qualified then steps further down; an unqualified BK falls back to
BE/TID0. QoS Control carries the TID with normal ack and no
EOSP/A-MSDU bit, and the descriptor QSEL is the TID. EDCA for all four
ACs is already programmed from the bound AP parameters (`wmm.rs`). RX
accepts QoS DATA on any TID while `acs` is set. The original T v1 still
aggregates only its TID0 agreement; the separate T v2 program above admits
independent non-VO agreements. Without T v2, other TIDs use single-MPDU
publication. Revocation is checked on every send and every watchdog pass,
like N2xC; it returns every frame to BE/TID0 without dropping the link.

Evidence: two `drivers/wireless/rtw88/narrow/qos` cases (DSCP mapping,
ACM downgrade, qualified-AC fallback, ring/index/QSEL and payload bounds)
and composed C21/C22 Open/WPA2 cases in `drivers/wireless/rtw88/qos/*`
(`qos_tests.rs`): per-TID routing to the AP, revocation and teardown, an
unqualified station, a VI-only subset and refused records. A real signed
N2xQ measurement and over-the-air acceptance remain external.

### C21/C22 DATA rate fallback (`N2xF`)

`fallback.rs` (tag `F`, stem `fallback`) lets firmware rate adaptation
step DATA down instead of transmitting every frame at one fixed rate.
Sources (Linux v7.2 rtw88):

- `tx.c::rtw_tx_data_pkt_info_update` leaves `use_rate` and
  `dis_rate_fallback` false for a station DATA frame. Only
  `dm_info->fix_rate` forces both on. The descriptor rate is the highest
  negotiated rate, which the base profile already carries.
  `rtw_tx_mgmt_pkt_info_update` keeps management frames fixed with both
  bits set.
- `tx.c::rtw_tx_fill_tx_desc`: `RTW_TX_DESC_W3_USE_RATE` (bit 8) and
  `RTW_TX_DESC_W3_DISDATAFB` (bit 10).
- `fw.c::rtw_fw_send_ra_info`: rate ID, `SET_RA_INFO_RA_MASK0..3` and a
  clear `DIS_RA`. `wmm.rs::ra_info` already sends this with the bound rate
  and MCS mask at peer commit, so firmware RA is running and falls back
  within the mask.

Payload byte 0 is 1; every other byte is zero. The continuation binds into
the retained `Gate` right after the base N2xL extension. It needs no WMM
or HT program. `DataProfile::fallback` carries it, and
`Gate::allows_profile` admits it only with a current bound grant. With the
grant, ordinary DATA (including QoS DATA and the HT profile) clears both
W3 bits. Management, EAPOL/radio-report frames and BAR keep
USE_RATE|DISDATAFB, and so do originator BA bursts: the N2xT burst
envelope is qualified as fixed-rate/no-fallback, unlike Linux, which
lets firmware RA run on A-MPDUs too. Revocation is checked on every send and every watchdog
pass (`Station::fallback_live`). It returns DATA to the fixed rate without
dropping the link.

Evidence: `drivers/wireless/rtw88/narrow/fallback` (payload and chip
bounds; W3 bits for QoS/non-QoS DATA with and without the profile; a
Probe Request staying fixed) and composed C21/C22 cases in
`drivers/wireless/rtw88/fallback/*` (`fallback_tests.rs`): Open and WPA2
joins with fallback DATA, then revocation back to fixed rate and teardown;
an unqualified station staying fixed; unsigned, altered, foreign and
revoked records refused. A real signed N2xF measurement and over-the-air
rate behaviour remain external.

### RTL8821CE thermal TXAGC/txscale and associated IQK (`N21W`)

`Rtw88Device::rtl8821c_power_tracking_request()` exposes measurement metadata
for the exact already-bound C21 HT session, at 20MHz or 40MHz. The distinct
authenticated `rtw88/rtw8821ce-power-track-v1-<mac>.bin` asset enables
actual type0 RF-A tracking on a fresh association; a 40MHz association
uses the HT40 variant `rtw88/rtw8821ce-power-track-v1-ht40-<mac>.bin`,
whose identity additionally binds the bound N2xB record and whose AGC
split narrows across that record's one-stream MCS0..7 at BW40 instead of
the HT20 tracking indices. Its N21W identity binds original factory
facts and initial scale, H plus optional R/T1/T2/RTS and exact C/Q/F/D signed
sources, all-rate factory headroom and the complete measured thermal/swing/
AGC/calibration/transient envelope. N21X remains RTS and N21D's accepted
C21 mechanism mask stays DIG/CCK-PD/RA.

The retained watchdog triggers the real RF42 conversion and consumes a meter
at least2s later, applies the source EWMA and CCK/OFDM tables, and writes and
reads back actual global signed TXAGC and TX-scale fields. Factory headroom
intersects every legacy/automatic-response/HT rate. Fallback table selection
uses a real native C2H RA report. Threshold8 periodic IQK uses the original
retained H2C ring/buffer with associated segment1, nonwrapping command
sequence, actual DMA terminal and a fresh applied RF08/IQKFAIL receipt.

Mutation retains all keys, PN/replay floors, BA state, native DMA and peer
ownership, but retires old copied receive admission. DATA/copy publication
stays closed through actual all-QCU/FIFO quiet, RXDMA park, program/IQK,
readback and RX/TX restore. Missing, revoked, cancelled or ambiguous native
receipts keep the station closed and allocations pinned. A power-only change
can restore the exact static program under current original authority.
After periodic IQK has changed firmware coefficients, source loss requires a
fresh lifecycle: there is no invented receipt for restoring startup IQK.

The complete192-byte format, source chain, native barriers and physical
qualification requirements are in [rtw8821ce-power-tracking.md](rtw8821ce-power-tracking.md).
Eight composed native cases are written; release/native validation and real
radio/board acceptance remain pending. No measured deployment asset is shipped.

### PCI DMA-stop proof and reclamation (`dma_stop.rs`)

A stopped owner used to keep every published mapping forever: the seven TX
rings, the 512-entry RX ring and its buffers, the H2C bounce buffer, the
packet-core frame and batch buffers and the reserved-page ring/frame.
Clearing BME alone is not a retirement proof. `Io::quiesce_dma` now follows
Linux v7.2 `pci.c::rtw_pci_stop` (`rtw_pci_disable_interrupt` writes
`RTK_PCI_HIMR0/1/3` = 0 at 0xb0/0xb8/0x10b8, then `rtw_pci_dma_release`)
and adds the idle proof that Linux gets for free by powering the MAC off
first. Native runs the packet stop (`Core::stop` or a bare `Port::stop`):
HIMRs zero, `REG_TXPAUSE` 0x522 = 0xff, CR 0x100 low DMA gates
(`MAC_TRX_ENABLE` bits 0..3/6/7) cleared and BME off. `dma_stop::prove`
then requires, through a teardown view that needs only the current PCI cap
and memory decode:

1. a fresh PCI command read showing BME clear, INTx disabled and memory
   decode on;
2. all three HIMRs zero, TXPAUSE 0xff and the CR DMA gates clear;
3. for each `rtw_pci_tx_queue_idx_addr` register (H2C 0x132c, BK 0x3ac,
   BE 0x3a8, VO 0x3a0, VI 0x3a4, MGMT 0x3b0, HI0 0x3b8), hardware RP
   (bits 16..27, `__pci_get_hw_tx_ring_rp`) equal to host WP (bits 0..11),
   the drained test of `rtw_pci_dma_check`. Each ring gets 1000 polls
   10 us apart (`util.c::check_hw_ready`);
4. RX stopped the way `wow.c::rtw_wow_rx_dma_stop` does it:
   `REG_RXPKT_NUM` 0x284 `BIT_RW_RELEASE` (18) set, then `BIT_RXDMA_IDLE`
   (17) polled with the same budget;
5. a second command read showing BME still clear.

An all-ones read is surprise removal (`Gone`). Any timeout, readback
mismatch or authority failure leaves every mapping retained. Success clears
`Native::published` and calls `Core::release`, which needs a stopped core.
The reserved-page backend releases its ring and frame only if its beacon
page completed (`Idle`/`Continued`) or was disarmed after radio
completion. A poisoned or timed-out page is never proven. The backend is
then terminal and no page, packet or proof can reopen it.

`Owner::station_disconnect` runs the proof after the station stop. Its
result never turns a completed disconnect into a failure.
`Owner::quiesce_dma` is the phase-independent entry for removal and
failure paths: it stops the station first. Linux frees ring skbs in
`rtw_pci_free_trx_ring` at `rtw_pci_destroy`. Here the release happens
when the proven owner is dropped.

Evidence: `drivers/wireless/rtw88/dma_stop` (proof success, BME open,
armed HIMR, TX unpaused, TXDMA on, H2C not drained, RXDMA busy, surprise
removal, BME reopened mid-drain), the reserved-page reclamation case in
`drivers/wireless/rtw88` (unclaimed, success and drop count, busy RXDMA
retained, a timed-out beacon page never proven) and the composed station
cases (an Open DHCP disconnect proves and reclaims; a busy RXDMA disconnect
still completes and keeps every mapping).

### PCI device removal (`pci.rs::remove`)

`register_pci_driver` registers a `narf_bus::register_pci_remove` hook
for every match name. It follows Linux v7.2 `pci.c::rtw_pci_remove`:

1. `rtw_unregister_hw`: `interface::Device::withdraw` closes admission,
   drops the link, clears the stack rings and unregisters the wireless
   registry, the net registry and the `wlan%d` interface. The 1 ms
   drain/watchdog task exits once the shell is withdrawn. A diagnostic
   RTL8822BE shell unregisters its static interface.
2. `rtw_pci_disable_interrupt` + `rtw_pci_destroy`:
   `Lifecycle::remove` marks the lifecycle removed, so no initialization
   or stage can install an owner later. Under the owner mutex it records
   `Failed`/`Gone`, takes the retained owner and runs
   `Owner::quiesce_dma`, which stops the station, then runs `rtw_pci_stop`
   and the DMA idle proof above. Then it drops the owner.
3. Drop frees the rings and buffers only after a successful proof.
   Otherwise they stay pinned and the bus address is quarantined: a later
   probe of that address returns `BadDevice` without touching config space
   or BARs. A proven removal clears the quarantine.

The hook takes the controller slot only for the exact bound address, and
the teardown runs on the executor because removal cannot fail or block
the bus dispatcher.

Evidence (`drivers/wireless/rtw88/station`): removal of a joined
RTL8822CE station withdraws the shell, reclaims after the proof, leaves
`Failed`/`Gone` with no retained owner, refuses association and finds
no owner on a second removal. A removal whose RXDMA never idles reports the mappings
pinned. A lifecycle removed before any owner existed refuses a later
`initialize_bytes`.

### C21/C22 noninitial 2.4GHz/20MHz operating channels and retune (`N2xO`)

`channel_policy.rs` admits primaries 2..=13 at 20MHz on the retained C21/C22
station; channel 1 keeps its base N22Cv2/N21S program unchanged. Channel 14
(CCK-only) and 5GHz stay unadmitted. Each noninitial primary N is admitted
only by an optional separately signed continuation
`rtw88/rtw882{1,2}ce-channelNN-v1-<mac>.bin` (generic `qualification.rs`
layout, tag `O`, one static `Kind` per primary whose source contract hashes
the Linux functions below and the primary). Payload: primary, width 20,
antenna gain, qualified ceiling, three measured peaks (calibration, response,
data; quarter dBm), C22 per-path CCK references or C21 twelve CCK/OFDM TXAGC
indices, zero tail. The record must bind the exact base identity
(`Gate::extension_request`), and its TX power must not exceed the factory
base of the primary's own `phy.c::rtw_get_channel_group` (C22
`cck_base[group]` plus the RFE response adjustment per path, C21
`cck_base[group]` and `bw40_base[group] + ofdm_diff`). Nothing is derived from
another channel's measurement and no record is fabricated: without provisioned
records the interface advertises and accepts channel 1 only, as before.

`Gate::with_channel` binds a record only over a base-only gate (no WMM/HT/BA/
protection/coding/QoS/fallback/tracking continuation) and its live check is part
of `Gate::current`/`current_in`: the current record capability plus the
installed regulatory domain, whose overlapping rules must be plain, cover the
primary's 20MHz occupied span and admit every peak plus antenna gain.

Per-channel operating records. Every continuation program on a noninitial
primary is that channel's own record. With a record bound,
`Gate::extension_request` (and `ExtensionBase::request`) return the
channel-scoped base `channel_policy::scope_request`: SHA-256 over the base
N22Cv2/N21S request identity, the N2xO request identity and file digest and
the primary, with the per-channel filename `rtw882Xce-chNN-<stem>`
(`scoped_filename`). N2xL (`extension_base` now carries the channel record),
and transitively N2xH/R/T/X (their identities hash the parent identity; their
filenames carry the same `chNN`), the generic N2xC/Q/F/D/Z kinds
(`qualification::request`) and N21W therefore can only be signed for that
channel; a channel-1 record never matches. N2xO itself binds the unscoped
`Gate::base_request`. The channel-scoped base supplies that primary's factory
facts: HT20 1S/2S ceilings from `bw40_base[rtw_get_channel_group]`
(`ht::factory_limit_group`, `phy.c::rtw_phy_get_2g_tx_power_index`), the
record's C22 CCK references or C21 TXAGC indices as `Facts::cck`/`legacy`,
and N21W's CCK/OFDM ceilings from the channel group. `ExtensionBase::current`
returns min(base EIRP, record EIRP ceiling under the installed domain) and
`ExtensionBase::invoke` re-enters the record capability and span check
immediately before each operation. `with_extension`, `with_continuation` and
`with_power_tracking` accept a channel-bound gate; the station loads each
program exactly as on channel 1 (an extension whose base channel is not the
committed one is ignored). LPS (`lps_peer`) needs a channel-scoped N2xZ.
Without any per-channel record the primary carries the base legacy CCK1
Open/WPA2 profile only.

Native retune owner (`station.rs::retune`, `pci_firmware.rs`
`station_retune_{begin,iqk,finish}`), unassociated Passive station only:
`begin` installs the target gate (base for channel 1), refuses all new TX
publication (ordinary/batch packets, HMEBOX and PS mailboxes), sets
REG_TXPAUSE 0x522=0xff, points packet-core PHY admission at the target and
reports quiet only after the packet core, every TX ring index pair and the
reserved-page queues drain (same receipts as N21W maintenance). The station
then programs, in Linux 7.3-rc4 order, `main.c::rtw_set_channel` ->
chip `set_channel` and `phy.c::rtw_phy_set_tx_power_level`:

- C22 `rtw8822c_set_channel`: `_bb` 2.4GHz/20MHz with SCOTRK 0xc30
  0x9aa/0x96a(11,12)/0x969(13) and TXDFIR0 0x808[6:4] 3 on 13 else 1,
  `rtw_set_channel_mac`, `_rf` RF18 channel byte on both paths inside the
  3-wire reset, `rtw8822c_toggle_igi`; CCK references from the record.
- C21 `rtw8821c_set_channel` non-SRRC: `_bb`/MAC/`_rxdfir`/`_bb_swing` are
  identical across 1..=13, so only `_rf` (LUTDBG, 0x64, RF18 channel byte,
  XTALX2 bit19 toggle) runs, then the record's TXAGC words 0x1d00..0x1d08
  (HT/VHT words zero).

Scan retunes skip RF calibration like `RTW_FLAG_SCANNING`. Association first
retunes to the BSS primary with calibration as `mac80211.c::
rtw_ops_mgd_prepare_tx` -> `phy_calibration` does: C22 `rtw8822c_do_iqk`
(clear=1, DPD kept off, gains reapplied) and C21 `rtw8821c_do_iqk`
(clear=0/segment=0, stale RF_DTXLOK refused, host clear, IQK fail mask
0x1bf0 must be clear). The IQK H2C is the only command admitted during a
retune. The C22 completion matches `rtw8822c_do_iqk`: after the H2C is
consumed, REG_RPT_CIP 0x2d9c is polled for the IQK_DONE level 0xaa every 20ms
for at most 300ms, then REG_IQKSTAT 0x1b10 is cleared. Linux only warns on a
timeout; this owner fails the retune. The earlier stricter rule (a non-0xaa
value must be observed first) was dropped: RPT_CIP has no host reset and no
source shows the firmware leaving IQK_DONE when an IQK starts, so that rule
could time out on silicon. A stale level is bounded by the readbacks below. Readbacks then check RF18 channel/band/BW,
SCOTRK/TXDFIR (C22), the programmed CCK references or TXAGC words, RRSR 0x1f
and (C21) the IQK fail mask. `finish` requires an idle H2C ring, the paused and
quiet hardware, the target gate current again, clears TXPAUSE, commits the
primary and advances the retune epoch (`station_channel`, initial 1). Any
failure or cancellation after `begin` leaves TX refused and the station
reporting Failed; nothing reopens it except teardown.

Scan (`scan.rs::plan`) maps authoritative frequencies or channel numbers to
2.4GHz primaries 1..=13; the interface refuses any unadmitted one and expands
an empty list to every admitted primary. `scan_for` visits each requested
primary (Probe Request DS Parameter Set rewritten per channel), then retunes
back to the pre-scan channel even after an error. Scan results report each
BSS's own primary/frequency; association and safe rejoin accept any admitted
primary. C22 PHY status must report the current primary (`on_channel`); C21
reports none. The BSS cache observes Beacons and Probe Responses against the
currently tuned primary (DS Parameter Set must match it), so scan results and
peer liveness work off channel 1.

Channel switch while associated (`station.rs::channel_switch_ie`/
`channel_switch`) follows mac80211's software CSA for emulated channel
contexts (`main.c` sets `CHANCTX_STA_CSA`; `mlme.c::
ieee80211_sta_process_chanswitch`). The associated BSS's own Beacon/Probe
Response CSA (37) or ECSA (60, preferred; only class 81 2.4GHz/20MHz) is
parsed (`channel_policy::switch_ie`). Same-channel announcements are ignored.
Another band/class, an unadmitted primary, a target without a loadable N2xO
record, or any bound continuation program (L/H/R/T/X/C/Q/F/D/W, whose records
are per-channel and cannot be carried in place) drops the connection
(`Error::PeerLost`, mac80211 `drop_connection`); the SME re-associates and
loads the new primary's own records. Otherwise the switch is due after
(max(count,1)-1) beacon intervals; mode 1 blocks host TX (`ready()` false)
from receipt until a peer Beacon on the new primary
(`ieee80211_chswitch_post_beacon`). The periodic watchdog runs it like
`ieee80211_chswitch_work` -> `rtw_ops_config(IEEE80211_CONF_CHANGE_CHANNEL)`
-> `rtw_set_channel`: the same native retune owner (TX refusal, TXPAUSE,
drain, chip `set_channel`, TX power level, readbacks, epoch) without RF
calibration (Linux defers it to `need_rfk`), restoring the associated phase.
Keys, peer/AID and port state are unchanged and peer-loss monitoring
restarts. A retune failure is terminal like any other retune failure.

Remaining before physical acceptance (no row closure is claimed here): no
signed N2xO record exists for any board, so on real hardware only channel 1
is admitted until per-channel measurements are provisioned. Extension
programs are per-channel records over the channel-scoped base (above); none
is provisioned for any channel. An in-place channel switch carries only the base
legacy CCK1 profile; with continuation programs bound it disconnects. Three new cases are written and
unexecuted at the time of writing:
`smoke_rtw88_channel_policy_linux_groups_bb_rf_and_probe_ds`,
`smoke_rtw88_channel_record_admission_and_regulatory_span`,
`smoke_rtw8821ce_retune_txagc_and_rf18_readback`,
`smoke_rtw8821ce_operating_readback_rf18_tracks_primary`.

C21 RF18 expectations come from one helper, `radio8821c::rf18_for(channel,
bw)` (`rtw8821c_set_channel_rf`: band, RFSI, BW and channel byte under mask
0x70fff). The post-program operating readbacks
(`station_profile_readback` -> `radio8821c::operating_readback{,_ht}`, used
after the legacy/HT20 programs and by `ht::Grant::readback`) take the
committed primary (`Gate::channel` / `ht::Grant::channel`), so an HT20 or
legacy program on a noninitial primary checks that primary's RF18, not
channel 1's 0xc01. Only the initial channel-1 IQK bring-up and its
`verify_geometry` stay pinned to channel 1.

### RTL8822CE Wake-on-WLAN source layer (`wow.rs`)

**Scope.** Only `rtw8822c.c` declares `wow_fw_name`
(`rtw88/rtw8822c_wow_fw.bin`) and `wowlan_stub`; `wow::support(did)` is
`Some` for `0xc822` only. It mirrors `rtw_wowlan_stub_8822c` minus what is
not ported: disconnect, magic packet, GTK-rekey wake (`gtk_rekey_failure`,
`RTW_WOW_RSN_RX_GTK_REKEY`), 12 patterns of 1..=128 bytes at offset 0.
`WIPHY_WOWLAN_SUPPORTS_GTK_REKEY` is not set because rtw88 has no
`set_rekey_data`; `WIPHY_WOWLAN_NET_DETECT` is not set because the PNO
reserved pages, `rtw_fw_set_nlo_info` and `rtw_fw_channel_switch` are not
ported. `wow::validate` re-checks every retained configuration.

**Firmware.** `firmware_transport::registered_wow_image` opens the WoW
image through the same firmware registry/signature authority and section
parser as the NIC image (`registered_image`); the restore uses a freshly
registered normal image, never a cached copy. `Owner::swap_firmware`
(`wow.c::rtw_wow_swap_fw`) reuses the exact bring-up section download
(`Owner::run`) on a `Phase::Station` owner after `Io::claim_swap`, and
poisons the owner on any failure.

**Sequence (`wow::suspend`/`wow::resume`, managed-linked station).**
Suspend = `rtw_wow_stop_trx` (100 ms, TXPAUSE 0xff, clear BB_RSTB; set
RW_RELEASE and require RXDMA_IDLE — Linux only logs a non-idle RX DMA, NARF
refuses to swap firmware under it) → WoW image download + MEDIA_STATUS_RPT
→ STA reserved pages (`runtime_ps_wire::Pages::station`, PS-Poll/NULL/
QoS-NULL) → `rtw_wow_fw_start`: RSVD_PAGE H2C, pattern CAM (`REG_WKFMCAM_*`,
four mask words + CRC/type/valid word per entry at `id << 3`, polled),
AOAC_GLOBAL_INFO, DISCONNECT_DECISION (adopt, 30, 5), KEEP_ALIVE (adopt,
NULL, 5), WOWLAN, REMOTE_WAKE_CTRL, `rtw_wow_check_fw_status(true)` (wake
reason cleared within 100 ms) → `rtw_hci_stop` → `rtw_wow_bb_start` →
`rtw_wow_avoid_reset_mac` (`REG_RSV_CTRL` 0x20, 0x60). Patterns follow
`rtw_wow_pattern_generate` (6-bit mask shift for the LLC offset, Realtek
CRC16 over masked bytes from offset 12). Resume reads
`REG_WOWLAN_WAKE_REASON` first (`rtw_wow_show_wakeup_reason` →
`wow::WakeReport`, a driver accessor as in iwlwifi §3.80 because the shared
contract has no `ieee80211_report_wowlan_wakeup` event), then
`rtw_hci_setup`/`start`, `rtw_wow_fw_stop` (disable H2Cs, CAM clear,
`check_fw_status(false)`), `bb_stop`, normal image + MEDIA_STATUS_RPT,
normal reserved pages, `rtw_wow_resume_trx`. Any error returns `Err` (resume
still returns the captured report) and the caller must run the cold
`system_suspend` resume (full restart, fresh association); `keeps_link`
additionally drops the link after a disconnect/unknown reason.

**Deliberate differences.** No LPS entry in WoW (`rtw_wow_enter_ps`): the
WoW firmware stays awake under the station's existing power program, so
no unqualified sleep program is introduced. `rtw_send_rsvd_page_h2c` is not
re-sent on resume (Linux sends it only in `rtw_wow_fw_start`). PCI PME /
wake-enable of the function belongs to the system-PM owner, as for iwlwifi
WoW (iwlwifi.md §3.80), and is not claimed here.

**Security CAM for AOAC (`security_cam.rs`).** The awake station keeps
software CCMP (`radio::software_crypto`: all 32 CAM entries invalid,
`REG_CR` bit 9 clear, `RTW_SEC_CONFIG` & 0xcf zero, re-checked by the HT
and C21 guards). For the WoW window only, `wow::Plan::new` takes
`station_security::Security::suspend_keys` (current PTK + every live GTK
by key id; only a settled open port, never IGTK — BIP stays in software as
rtw88 `set_key` returns `-EOPNOTSUPP` for BIP; `station::State::suspend_keys`
returns `Ok(None)` for an open BSS) and builds `rtw_ops_set_key` entries
under default key search: GTK at its key id, PTK at entry 4 addressed to the
AP, both `RTW_CAM_AES`. `wow::suspend` writes them with
`rtw_sec_write_cam`'s word order (7..0, valid bit last) after the WoW image
runs and before the reserved pages/`rtw_wow_fw_start`, then
`rtw_sec_enable_sec_engine` (CR bit 9, `RTW_SEC_CONFIG |= 0xcf`); AOAC
reports `RTW_CAM_AES` for both (or none on an open BSS). Install refuses a
non-software-crypto starting state. `wow::resume` first runs
`rtw_sec_clear_cam` for each installed entry, turns the engine off and
re-proves the software-crypto state *before* `rtw_hci_setup/start`, so the
host CCMP path never sees a device-decrypted frame. Deliberate differences:
Linux keeps the keys in the CAM permanently (hardware crypto awake); NARF
bounds each CAM command on the polling bit (10 us x 1000) where Linux does
not poll. PN/replay: the host's PN counters and replay windows never leave
`station_security` and are not lowered; the WoW firmware transmits only
unprotected NULL keep-alives (no ARP/NS/GTK-rekey offload is ported), so
host transmit PNs stay unique. Linux rtw88 reads back no AOAC RX counters
either (no `rtw_wow_get_aoac_rpt` in rtw88), so frames the firmware consumed
while asleep do not raise the host replay floor — identical to Linux.
Unexecuted case: `smoke_rtw88_wow_security_cam_install_and_clear`.

**Reversible host-DMA stop (`pci_swap.rs`).** `Registers::hci_stop` /
`hci_restart` (forwarded by `reserved_page::Backend` and
`firmware_transport::Io`) mirror `pci.c::rtw_pci_stop` and
`rtw_pci_setup` + `rtw_pci_start`. Stop requires `State::Packets`, no
pending H2C/mailbox command, no retune or tracking maintenance and a
transmit-quiet packet core (`packet_core::Core::halt`: every TX ring
retired to the host index; unreaped RX is dropped as Linux drops it), then
rewrites the zero HIMRs and runs `rtw_pci_reset_buf_desc` (0x303 |= 0xf7,
beacon/H2C/BK/BE/VO/VI/MGMT/HI0/RX bases and counts reprogrammed and read
back, `RWPTR_CLR` 0x39c, `H2CQ_CSR` 0x1330 bits 16|8, every index proved
zero, host H2C producer back to zero) into the new `State::Halted`. Unlike
`Port::stop`/`quiesce` it keeps PCI BME, `REG_CR` and every published
mapping; the halted owner refuses packet work (`transmit_allowed`).
Restart re-arms all 512 RX descriptors under the packet gate, repeats the
ring reset, sets `BIT_RST_TRXDMA_INTF | BIT_RX_TAG_EN` (`rtw_pci_dma_reset`),
zeroes the core's host/device/tag indices (`Core::reset_indices`) and
proves zero device indices before returning to the halted-from state. NARF
has no IRQ line, so `rtw_pci_enable_interrupt` is not mirrored (HIMRs stay
zero). Any failure is `State::Terminal`. Unexecuted case:
`smoke_rtw88_wow_packet_core_halt_restart_from_zero`.

**Firmware swap window (`reserved_page.rs` swap mode, `pci_swap.rs`,
`wow_owner.rs`).** Chosen design: the retained `reserved_page::Backend`
beacon channel reopens in a swap mode rather than a second native page
owner. `firmware_transport::Io::claim_swap(boundary)` (boundary from
`reserved_page::station_boundary`: C21 460, C22 1938, the same values
`runtime_ps_page` uses) requires the station-era closed channel
(`Terminal`, published, completed, disarmed), `0x308` = the retained ring,
`0x204` = boundary and `BCNQ_DL`/`EN_BCN_FUNC` clear, then the native
`Registers::claim_swap`: from `State::Packets` only with no pending
H2C/mailbox, no retune/tracking maintenance, a ready packet core,
`retune_quiet` (TX rings retired, MAC queue pages free) and
`REG_RXPKT_NUM` RW_RELEASE|RXDMA_IDLE set, into the new `State::Swap`
(BME/CR/mappings live, packet producers refused, H2C ring and mailbox
open). Every page in the window (`Owner::run` sections at page 0,
`Io::swap_page` at the boundary = Linux `rtw_fw_download_rsvd_page`)
restores `0x204` to the station boundary (Linux restores
`fifo.rsvd_boundary`), restores `BCNQ_DL` and zeroes the consumed
descriptor (`runtime_ps_page` tail), so the window never holds an armed
descriptor. In swap mode `finish_dma` calls `Registers::finish_swap`
(window stays open) instead of bring-up's park. A re-claim inside the
open window (resume restores the normal image) is accepted.
`Io::end_swap` closes it: Backend back to `Terminal` + disarmed (the
`runtime_ps_page` precondition), native `Swap` -> `Packets`. `hci_stop`
may run from `Swap`; `hci_restart` returns to `Swap`. `wow_owner.rs`
implements `wow::Io` on `Owner<I>` (C22, `Phase::Station` only):
`download` = `swap_firmware` + `rtw_fw_send_general_info`/`phydm_info`
(sequences 0/1, as the fresh bring-up image), `reserved_page` =
`swap_page`, `h2c` = `station_control::send` mailbox, `hci_*`/`end_swap`
forwarded; `wow::resume` ends with `end_swap`. A failed swap poisons the
owner (`Phase::Failed`) and every later `wow::Io` call refuses. Unexecuted
case: `smoke_rtw88_wow_reserved_page_swap_window`.

**System-PM wiring (`interface.rs`, `wow_owner.rs`, `system_pm_native.rs`).**
`WirelessNetIface::wowlan_support` returns `wow::support(did)` (RTL8822CE
only); `set_wowlan` refuses `EOPNOTSUPP` elsewhere and `EINVAL` for any
configuration `wow::validate` rejects, then retains it in
`IrqSafeSpinLock<Option<WowlanConfig>>` (`wowlan_config` reads it back);
the configuration and the last wake report are carried into the fresh
shell by a cold system resume, as cfg80211 keeps `wiphy->wowlan_config`.
`Owner::wow_plan` reads own address, AP, AID (`station::State::aid`), WMM
(`State::wmm`) and `suspend_keys` from a settled `Phase::Open` station
(`ready`: no switch, handshake or reply in flight). `Device::wow_suspend`
(`rtw_ops_suspend`) holds the `lifecycle.retained` mutex for the whole
sequence, re-checks a published, admitted, unwithdrawn `StationReady`
shell with a linked peer and an acceptable plan (otherwise `Ok(None)`,
nothing touched), then drops `admitted` (closing `control_ready`,
`enqueue`, `progress`, `watchdog`; `set_rts_threshold` refuses `EBUSY`),
clears the host TX rings and runs `Owner::wow_suspend` (WoW image from the
registry, `wow::suspend`). The interface stays published and the link
metadata is untouched (no `withdraw_for_rebind`). `Device::wow_resume`
(`rtw_ops_resume`) runs `Owner::wow_resume` (freshly registered normal
image, `wow::resume`), records the report, and reopens `admitted` and the
link publication only if the restore succeeded, the reason `keeps_link`,
the shell is still open and `station_check` passes; the station's 5 s
link-loss window restarts (`State::wow_resumed`), as mac80211's
jiffies-based monitors do not advance across suspend.

`system_pm_native::Parked` is `Cold(..)` (the previous MAC-off park) or
`Wow { claim, armed, config }`. On the system path, after the D0 check and
`ResetClaim::acquire_system`, `prepare_wow` runs when the function is C22,
a WoW configuration is retained and the board is not RFE6: save PCI config
(`pci_save_state`, BME/MEM left as the running driver has them),
`Device::wow_suspend`, then the same D3hot + settle + readback step the cold
path uses, *without* card-off (rtw88 `pci.c::rtw_pci_suspend` powers
nothing off; the PCI core moves the function to D3hot). Resume: D0 +
settle + readback, `restore_config` with exact BAR/ROM/command readback,
origin identity, `Device::wow_resume`, and the reset claim is republished
to the same original owner. Any WoW failure (not applicable, arming, D3,
PCI restore, firmware restore, disconnect/unknown wake reason) takes the
existing cold path: `withdraw_for_rebind` -> `retire` -> `off_with`
(rtw88 `rtw_ops_suspend`/`resume` returning 1, mac80211 full restart); a
suspend-side failure after arming first runs `wow_resume` and returns to
D0; a resume-side failure parks cold without a second D3 cycle and then
runs the cold resume (fresh shell, fresh association). IPS
(`Native::idle`) never takes the WoW branch.

The swap window also follows `mac.c::__rtw_download_firmware`: the swapped
image's download resets the native H2C sequence and mailbox box cursor to
zero (`h2c.seq`, `h2c.last_box_num`), and in `State::Swap` the native H2C
ring accepts only general-info (13) / phydm-info (17) packets carrying the
running sequence (`rtw_fw_send_h2c_packet`), so 0/1 after each swap is the
Linux value and a later associated IQK continues at 2.

**Deliberate differences / unclaimed.** RTL8822CE RFE6 boards keep the
cold path: `rtw_pci_suspend`'s CLKREQ-pad DBI step is only ported over the
retired-function `RecoveryIo`, not the live WoW owner. PME/wake-enable of
the function and the platform wake source belong to the system-PM owner
(iwlwifi.md §3.80) and are not claimed; whether a D3hot->D0 transition
preserves the WoW firmware (PCIe No_Soft_Reset) is a board fact not
qualified here; a lost state fails `wow::resume` and takes the cold path.
Wake reports are a driver accessor (`Device::wakeup`), not an nl80211
event. No physical board run is claimed. Written, unexecuted:
`smoke_rtw88_wow_support_and_validation`,
`smoke_rtw88_wow_pattern_cam_layout`,
`smoke_rtw88_wow_suspend_config_sequence`,
`smoke_rtw88_wow_resume_reason_and_firmware_restore`,
`smoke_rtw88_wow_failure_requires_full_restart`,
`smoke_rtw88_wow_interface_config_and_unlinked_suspend`.

### C21/C22 2.4GHz HT40 (`N2xB`, `ht40.rs`)

A 2.4GHz 40MHz association is admitted only by an optional separately signed
continuation `rtw88/rtw882{1,2}ce[-chNN]-ht40-v1-<mac>.bin` (generic
`qualification.rs` layout, tag `B`, stem `ht40`), qualified over the
channel-scoped extension base of its primary (`channel_policy::scope_request`)
and bound only over a bound HT program with the same TX MCS set
(`Gate::with_continuation`). Payload: primary, secondary (primary +/- 4, both
in 1..=13), width 40, flags (bit0 SGI40), antenna gain, qualified ceiling,
three measured 40MHz peaks (calibration, response, data; quarter dBm), TX MCS
mask, HT40 TXAGC index per MCS0..15 (zero outside the mask; C21 one stream;
C22 within the signed 7-bit difference of the MCS7 reference), zero tail.
Nothing is derived from the 20MHz programs or another channel.

Admission, all of which must hold:

- `main.c::rtw_init_ht_cap`: firmware `hw_cap.bw` includes 40MHz
  (`hw_bw_cap_to_bitamp`: 0, 6 or 7).
- The AP's Beacon/Probe Response HT Operation names the pair: secondary
  channel offset 1/3 with the STA channel width bit, primary equal to the
  committed primary.
- Both 20MHz halves are admitted channels: channel 1 or a loadable N2xO
  record for the secondary (checked over the still base-only gate right
  after the association retune).
- Factory bound: every qualified index is at most the BW40 base of the
  center channel's `rtw_get_channel_group` (`phy.c::
  rtw_phy_get_2g_tx_power_index`: one stream `bw40_base[group]`; C22 two
  streams `+ ht_2s_diff.bw40 * 2`; C22 min over both paths, C21 RF-A with
  txgi factor 1; `ht::factory_limit_bw40{,_2ss}`, `Gate::ht40_limits`).
- Regulatory (`ht40::policy`, cfg80211 `NO_HT40*` semantics): every rule
  overlapping the 40MHz span (center +/- 20MHz) is plain and allows 40MHz,
  one rule covers the span, and every peak plus antenna gain fits the
  minimum ceiling. This is part of `Gate::current`, `current_in` and every
  `invoke` once bound, because a 40MHz program has no in-place downgrade.

Association (`station.rs::associate`): with the record present the request
advertises `SUP_WIDTH_20_40 | DSSSCCK40 | SGI_40` (RX SGI40 always, TX SGI40
only with the record's SGI40 flag; `ht::Grant::local_wide`,
`LocalHt::with_dsss_cck40`). An offered 40MHz selection must be exactly the
record's pair, otherwise the association is refused; a 20MHz offer leaves the
record unbound. After the HT program, the station binds N2xB and widens
(`State::widen`) under the native retune owner (`station_width_begin` ->
`station_retune_finish`): TX refusal, REG_TXPAUSE, drain, then in Linux order
`rtw_set_channel(center, BW40, sc)` with `sc` `RTW_SC_20_UPPER` (1) when the
primary is above the center else `RTW_SC_20_LOWER` (2):

- C22 `rtw8822c_set_channel_bb` 2.4GHz BW40: RXAGC CCK 4/OFDM 0, SCOTRK/
  TXDFIR of the center, CCKSB 0x1a00[4] (sc 1), TXBWCTL 0x9b0 0xf=5, 0xc0=0,
  0xff00=sc|sc<<4, NBI 0x1abc[30]=1, SBD 1, PT_OPT 0xcbc[21]=1;
  `rtw_set_channel_mac` DATA_SC 0x483=sc, RFMOD_40M 0x668[7], 80MHz MAC clock;
  `rtw8822c_set_channel_rf` RF18 BW40 (bit13) on the center, RXBB 0x10 inside
  the 3-wire reset; `rtw8822c_toggle_igi`; CCK references; `rtw8822c_do_iqk`.
- C21 `rtw8821c_set_channel_bb` BW40 `set_bw` (RXSB 0xa00[4] for sc 1,
  ADCCLK 0x8ac `&0xff3ff300 | 0x20020000 | sc<<2 | 1`, ADC160[30]); the 2.4GHz
  head and `_bb_swing` are channel-independent and stay as programmed; MAC as
  above; `_rf` RF18 BW40 (bit11) on the center plus the XTALX2 toggle;
  `_rxdfir` BW40; `rtw8821c_do_iqk`.
- HT40 TX power: C22 per-path MCS7 reference and per-rate difference words
  0x3a00.. (layout as the HT20 program), C21 HT words 0x1d0c/0x1d10. Legacy
  CCK/OFDM indices are unchanged (Linux uses `bw40_base` for OFDM at both
  widths). Readbacks then check every field; failure is terminal.

The 20MHz `radio::channel_to` writes every field the BW40 branch changes
(Linux BW20 branch), so a later 20MHz program restores the full 20MHz state.
After widening, `station_profile_readback` checks the HT40 selection
(`ht::Grant::readback_at`; C21 RF18 at the center). C21 N21W power tracking
tracks the committed selection at either width: the HT20 indices on a
20MHz association, the bound N2xB record's one-stream MCS0..7 at BW40
(the indices `ht40::write_power` commits to 0x1d0c) on a 40MHz
association. The N21W request identity binds the bound N2xB record when
one is bound (marker `B` plus its source identity), and the HT40 variant
is provisioned under its own `-ht40` filename, so an HT20 record cannot
authorize HT40 tracking or vice versa; HT20 identities and filenames are
unchanged. One case written, unexecuted:
`smoke_rtw8821ce_power_tracking_ht40_selects_bw40_indices`.

Data path at 40MHz (`rtw_update_sta_info` with `IEEE80211_STA_RX_BW_40`):
the association response must negotiate the same pair (`Error::Profile`
otherwise); `DataProfile::bw40` selects `get_rate_id` BGN_40M_1SS (1) /
BGN_40M_2SS (0), TX descriptor `W5_DATA_BW` 1 (bits 6:5), SGI = SGI40 from
the peer's `SGI_40` and the record, RA_INFO `BW_MODE` 1 (bits 25:24) in the
association and dm RA refreshes; `Gate::allows_profile` admits `bw40` only
under the live N2xB grant and its MCS/SGI40 set. RX PHY status follows
`rtw8822c.c::query_phy_status_page1`: C22 RXSC 0 is the current width,
9..=12 a 40MHz PPDU; packet-core admission accepts 20MHz and 40MHz PPDUs on
the committed primary (`packet_phy::parse_at`, `Evidence::on_operating`).

2.4GHz 20/40 coexistence: like mac80211 the station trusts the AP's HT
Operation and does not run OBSS scans or send 20/40 BSS Coexistence frames
(mac80211 implements neither for a client). If the associated AP's
Beacon/Probe Response HT Operation stops naming the programmed pair (for
example the AP fell back to 20MHz), the station drops the connection
(`Error::PeerLost`) and the SME re-associates at the width the AP now
operates; mac80211 instead narrows in place (`ieee80211_config_bw`), which
this owner does not implement. A CSA cannot carry a bound N2xB record and
drops the connection like the other per-channel programs.

Remaining before physical acceptance: no N2xB record is provisioned for any
board, so real hardware stays at 20MHz. The PHY-status channel byte at 40MHz
is assumed to be the primary (Linux passes it to mac80211 as the RX
frequency, which mac80211 compares with the primary). Four cases are written
and unexecuted: `smoke_rtw88_ht40_record_pair_factory_and_regulatory_span`,
`smoke_rtw88_ht40_operation_element_and_phy_status_width`,
`smoke_rtw88_ht40_descriptor_rate_id_and_profile`,
`smoke_rtw88_ht40_linux_bw40_bb_mac_rf_programs`.

### C21/C22 5GHz channel programs (`band5.rs`)

Step 1 of `five_ghz_operation`: the Linux 7.3-rc4 5GHz primitives below.
5GHz primaries are admitted, scanned, joined and advertised only through
signed per-channel N2xO records (station band handling below).

- `band5::{band, group, primary, frequency}`: `IS_CH_5G_BAND_{1..4}`,
  `rtw_get_channel_group` 5GHz rows (unlisted numbers return None where
  Linux WARNs and falls back to group 0), 20MHz primaries 36..=64,
  100..=144, 149..=177.
- `band5::Power5g`: `rtw_5g_txpwr_idx` at bytes 18..42 of each path's
  factory record and `rtw_phy_get_5g_tx_power_index` (OFDM `bw40_base +
  ht_1s.ofdm`, HT/VHT20 `+ ht_1s.bw20 (+ ht_2s.bw20)`, 40MHz base
  `(+ ht_2s.bw40)`, 80MHz group average `+ vht_1s.bw80 (+ vht_2s.bw80)`,
  times `txgi_factor`). Erased (0xff) or out-of-range bases and negative
  results return None instead of Linux's u8 wrap.
- C22 `radio::channel5_to` / `verify_channel5`: `rtw8822c_set_channel_bb`
  5GHz head (CCKTXONLY/CCK_CHECK set, RX IQ weight, TXF4 bit20 clear,
  CCAMSK 0x22, TXDFIR0 3, OFDM RXAGC 1/2/3 by band, SCOTRK per channel),
  BW20 tail, `rtw_set_channel_mac` (CCK_CHECK set only on 5GHz), `_rf` RF18
  (`radio::rf18_8822c`: band bits16|8, RFSI bit17 band 3 / bit18 band 4),
  `toggle_igi`. `channel_to` stays 2.4GHz-only and rewrites every 5GHz field.
- C21 `radio8821c::set_channel20` / `verify_channel20` over
  `BandFacts` (`ch_param` filters, RFE BTG, factory swing bytes 0xc6/0xc7):
  full `rtw8821c_set_channel` at 20MHz on either band, including
  `rtw8821c_switch_rf_set` WLA (RFECTL WL|WLA) and LUTDBG 0 on 5GHz, and the
  full 2.4GHz `_bb`/swing/BTG-WLG switch when returning. A swing byte above 9
  is refused (Linux uses setting 0).

5GHz N2xO records (`channel_policy::Record`, payload bytes 26..36): a 5GHz
primary record carries C22 per-path OFDM references (bytes 26..28) and the
two OFDM difference words for 0x3a04/0x3a08 (bytes 28..36, four 7-bit
signed `rtw8822c_set_tx_power_diff` bytes each, bit 7 clear), with the CCK
references zero; C21 carries OFDM6..54 TXAGC indices with CCK1..11 zero.
2.4GHz records must leave bytes 26..36 zero. One static Kind per 5GHz
primary (`KINDS5`, stems `channel36`..`channel177`, file
`rtw88/rtw882Xce-channelNN-v1-<mac>.bin`). `within_factory` bounds the
selection by the channel's 5GHz group `Power5g::ofdm` (C22 txgi factor 2,
max 0x7f, both paths: every `reference + difference` in `0..=limit`; C21
factor 1, max 0x3f, path A, since `rtw8821c_read_efuse` substitutes only
the 2.4GHz record). Regulatory admission uses the 5GHz center frequency.
Written, unexecuted: `smoke_rtw88_channel5_record_ofdm_selection_and_kinds`.

Band-aware base rate (`packet_format::DataProfile::band5`): a 5GHz profile
admits no CCK rate; `DataProfile::LEGACY5` is OFDM6 only, so DATA and the
firmware RA_INFO use `get_rate_id` WIRELESS_OFDM = `RTW_RATEID_G` (7);
management/EAPOL descriptors use `rtw_tx_pkt_info_update_rate`'s 5GHz
`RTW_RATEID_G` at DESC_RATE6M (2.4GHz stays `RTW_RATEID_B_20M` at
DESC_RATE1M); `response_mask` masks with `RRSR_INIT_5G` (0x150) instead of
0x15f, so the OFDM6 base answers with 0x10. C22 `radio::ofdm5` /
`verify_ofdm5` program the record's per-path OFDM references and the
0x3a04/0x3a08 differences with CCK references/differences zero and
REG_RRSR 0x10. Written, unexecuted:
`smoke_rtw88_band5_base_rate_rrsr_and_ofdm_reference`.

Gate/retune wiring: `channel_policy::program` dispatches a 5GHz primary to
`program5`: C22 `radio::channel5_to` + `radio::ofdm5` (IQK via the shared
firmware path, references reprogrammed after it) with `verify_channel5` /
`verify_ofdm5`; C21 `radio8821c::set_channel20` over `Gate::band_facts`
(the N21 calibration board now carries `BandFacts`: hashed `ch_param`
filters, `rfe_btg`, raw factory swing bytes 0xc6/0xc7), OFDM-only TXAGC
and REG_RRSR 0x10, checked by `verify_channel20` + `verify_txagc`. A C21
2.4GHz retune that finds CCK_CHECK bit7 set (a 5GHz program preceded it)
runs the full cross-band `set_channel20` and restores RRSR 0x1f.
`PacketCore::set_operating_channel` resets DATA to the band's base profile
(`LEGACY5`/`LEGACY`) when the band changes. Written, unexecuted:
`smoke_rtw8821ce_channel5_ofdm_txagc_and_rrsr`.

Station band handling: admitted primaries are published as a 64-bit mask
(bit N = 2.4GHz channel N, bit 16+i = `PRIMARIES5[i]`) and reported as a
2400 and (when nonempty) a 5000 `WirelessBand`. `scan::plan` accepts 5GHz
primary frequencies/numbers; `channel_policy::probe_for` rebuilds a preq
for a 5GHz channel like `ieee80211_put_preq_ies_band` (OFDM Supported
Rates, no Extended Supported Rates, no DS Parameter Set), also for a
home-channel 5GHz scan. BSS cache and association require the band's base
rate as basic (`base_rate_ok`: CCK1 on 2.4GHz; OFDM6 and no CCK on 5GHz).
BssInfo, associate and rejoin map frequencies with `any_frequency`. ECSA
follows the 20MHz global classes 81, 115, 118, 121, 124 and 125 only
(IEEE 802.11 Annex E Table E-4). On 5GHz a continuation program
(extension/WMM/HT/HT40/VHT80/...) binds only as that primary's own band-5
record over its OFDM6 base (`channel_policy::scope_request`); without one the
station runs the OFDM6 base profile;
`Gate::allows_profile` refuses a profile whose band differs from the
committed primary. PHY-status channel bytes are compared by number on both
bands. Written, unexecuted: `smoke_rtw88_band5_station_scan_csa_and_probe`.

5GHz wiphy capabilities (`Device::phy_capabilities(5000)`, `hw_caps`;
main.c `rtw_set_supported_band` with `rtw_init_ht_cap`/`rtw_init_vht_cap`
on the 5GHz sband) are retained at activate from
`Owner::station_band5_capability` -> `Io::station_band5_capability` ->
`vht::band5_capability` per admitted 5GHz primary, mirroring
`Station::associate`: the gate `retune` installs there (`Gate::with_channel`
over the base-only gate), the band-5 N2xL extension of exactly that primary
with WMM and its N2xH HT program. The first primary whose join can offer
VHT80 (`vht::hardware_allows`, every other constituent of its Annex E block
admitted, a loadable N2xV record naming that primary and center) supplies
the `ht::Grant::vht80_capability` HT (20/40, RX SGI40) and VHT bodies and
sets `vht_supported`; otherwise the first HT20 offer
(`ht::Grant::ht20_capability`) is reported with no VHT; a band whose joins
all stay legacy reports no capabilities. 2.4GHz keeps the HT20
`Facts::capability` body. Written, unexecuted:
`smoke_rtw88_band5_wiphy_caps_follow_admitted_station_offer`.

**DFS / NO_IR passive primaries.** Following rtw89 (rtw89.md "DFS / NO_IR
passive scanning and client admission") through the shared
`narf_wireless::reg::witness::BeaconWitness` (wireless spec §3.5):
`channel_policy::passive_rule` is the 5GHz variant of `plain_rule` that also
accepts `DFS` / `NO_IR` (cfg80211 reg.c `handle_channel_single_rule` ->
`IEEE80211_CHAN_RADAR` / `NO_IR`); `channel_policy::admission` admits a 5GHz
N2xO record under such a rule as passive-only (2.4GHz, indoor and unknown
bits still refuse). A passive-only primary is admitted for RX, retune and
passive scan. Frame TX on it (`Native::submit_packet[_batch]` ->
`Native::passive_tx_allowed`, on top of the live gate check, with
`Gate::passive_in` re-deciding passivity against the installed snapshot at
every submission) needs the station's passive TX grant
(`Io::station_passive_tx`) for exactly the committed primary and the same
policy `Arc`; a retune to another primary drops it. The station
(`Io::station_regulatory` = `reg::db::snapshot()`): `scan_channels` sends no
probe request on a passive-only primary (mac80211
`ieee80211_scan_state_decision`); every dwell (`scan_inner`) opens a witness
generation for the tuned 20MHz center and `cache` records `beacon_found`
only for an actual Beacon (subtype 8, nonzero interval, observed on the
tuned primary) during it; `associate` refuses an unwitnessed passive-only
candidate before the retune (`may_associate`) and grants passive TX after it,
before the first Authentication frame; CSA receipt drops the link
(`PeerLost`) unless the target is witnessed, and `channel_switch` re-checks
the witness and grants the target after the switch; `stop` clears the
witnesses and withdraws the grant. Requiring a witness for a CSA target is
NARF's stricter client rule (the station performs no radar detection).
Written, unexecuted: `smoke_rtw88_dfs_passive_rule_and_record_admission`
(plus the class 118/121 rows in
`smoke_rtw88_band5_station_scan_csa_and_probe`).

Non-QoS DCF on 5GHz (`station_control::commit_peer(.., band5, ..)`):
rtw88 mac80211.c `rtw_aifsn_to_aifs` AIFS = AIFSN * slot + SIFS with SIFS
16 on `RTW_BAND_5G` (10 on 2.4GHz), and mac80211 mlme.c
`ieee80211_handle_bss_capability` forces the short slot (REG_SLOT 9) on
5GHz whatever the AP's Short Slot Time bit; the base keeps CWmin31.
Written, unexecuted: the 5GHz rows of
`smoke_rtw8822ce_station_dcf_matches_original_non_qos_defaults_and_fails_closed`.

Not part of this row: 5GHz HT20/HT40 continuations (WMM/HT/BA/... records
qualified over the OFDM6 base, 5GHz HT facts and C22 HT/MCS difference
words) are follow-on work like every per-channel continuation; without
them a 5GHz primary runs the legacy OFDM base profile.

**5GHz legacy extension (N2xL band-5 variant).** Groundwork for 5GHz
HT/VHT. A base scoped to a 5GHz N2xO primary (`channel_policy::scope_request`)
hashes an extra band-5 contract line (OFDM-only legacy8 with OFDM6
mandatory, rate id G7, mgmt/EAPOL 6M `RTW_RATEID_G`, `RRSR_INIT_5G`, the
record's OFDM references/differences or OFDM TXAGC, SIFS16 with the forced
short slot), so its N2xL identity and filename stem differ from every
2.4GHz program. `station_profile::Grant::decode` then requires `rates &
0x1f == 0x10` (no CCK, OFDM6) instead of CCK1; `Grant::band5`. The station
binds such an extension on its own primary (`associate`), checks the
association response's legacy intersection the same way and commits a
`band5` DATA profile; `wmm::words(p, short, band5)` encodes AIFS with
`rtw_aifsn_to_aifs` SIFS16 and the forced short slot on 5GHz.
`wmm::readback5` checks a C22 5GHz retained program (CCK references zero,
N2xO OFDM references, 0x3a04/0x3a08 differences) where 2.4GHz checks the
CCK references; C21 keeps `operating_readback` at the 5GHz RF18.
`Gate::allows_profile` without an extension admits the band's own base
(`LEGACY5` on 5GHz). Written, unexecuted: the 5GHz rows of
`smoke_rtw8822ce_legacy12_descriptor_rate_order_and_wmm_register_units`.

**5GHz HT20 (N2xH over a band-5 N2xL).** Groundwork for 5GHz HT40/VHT.
`power_policy::overlay` takes a primary's HT ceilings from its 5GHz
`rtw_get_channel_group` group when the bound N2xO record is 5GHz:
`Board::ht5_groups` (C22, `Power5g::bw20` 1S/2S, txgi factor 2, min over
both paths) and `Envelope::ht5_groups` (C21, path A, factor 1, max 0x3f);
the record's CCK references (C22) / CCK TXAGC indices (C21) are zero. The
HT request over a band-5 base hashes a 5GHz HT20 line plus the C22 OFDM
selection. C22 keeps OFDM on 5GHz (management/EAPOL at OFDM6): the HT
program's 0x3a04/0x3a08 bytes are the N2xO OFDM indices
`min(ofdm[A] + diff(r), ofdm[B] + diff(r))`
(`channel_policy::Record::ofdm5_indices`, the per-rate path minimum of
`rtw8822c_set_tx_power_index`) relative to the MCS7 reference, with CCK
bytes zero (2.4GHz writes OFDM at index 0); decode refuses a selection
whose OFDM difference leaves -64..=63. C21 writes the 0x1d0c HT TXAGC
over the N2xO OFDM TXAGC and reads back at the 5GHz RF18. The HT DATA
profile carries `band5` (rate id GN 5/4). On 5GHz the station binds the
extension, N2xF/N2xQ, HT, N2xC and the BA programs; the N2xR RTS program,
the N2xD dynamic mechanism and N21W tracking stay off (qualified with a
CCK RTS rate, CCK PD and 2.4GHz swing tables); 5GHz N2xB HT40 follows
below. Written, unexecuted: the OFDM-selection
rows of `smoke_rtw88_band5_linux_groups_and_factory_power`; no 5GHz HT
station case is written.

**5GHz HT40 (N2xB over a 5GHz N2xH).** Groundwork for VHT80. The N2xB
payload, binding and association flow of the 2.4GHz HT40 section apply
unchanged with these 5GHz differences:

- Pairs (`band5::center40`, `ht40::center`): IEEE 802.11 Annex E 40MHz
  blocks 36/40, 44/48, 52/56, 60/64, 100/104, ..., 140/144, 149/153,
  157/161 (either half primary); 165/169 and 173/177 are not admitted.
  `sc` is `rtw_update_channel`'s `RTW_SC_20_UPPER` (1) / `_LOWER` (2).
- Kind: `ht40::KIND5` (same tag `B`, stem `ht40`, payload layout) hashes a
  5GHz BW40 source contract; `ht40::kind(primary)` selects it for a 5GHz
  primary, `KIND.admit` refuses 5GHz pairs and `KIND5.admit` 2.4GHz
  pairs, so a record never verifies across bands. It is qualified over
  the primary's band-5 N2xL scope.
- Factory bound (`Gate::ht40_limits(center)`): `rtw_phy_get_5g_tx_power_index`
  BW40 `bw40_base[5g group(center)] (+ ht_2s_diff.bw40)` via
  `band5::Power5g::bw40` (C22 min over both paths, factor 2,
  `Board::ht40_5_groups`; C21 path A, factor 1, max 0x3f,
  `Envelope::ht40_5_groups`). C22 additionally requires every N2xO OFDM
  index (`Gate::ofdm5_indices`) within -64..=63 of the record's MCS7
  reference (`ht40::within_factory`).
- Regulatory (`ht40::admission`): 5GHz rules over the 40MHz span may be
  passive (`channel_policy::passive_rule` at 40MHz, DFS / NO_IR); a
  passive span is admitted only when both 20MHz halves are passive-only
  (`reg::witness::passive_only`), a mixed span is refused. This runs in
  `Gate::current`/`invoke` like the 2.4GHz check. The station
  (`Station::wide_witnessed`) offers 40MHz only when no half is
  passive-only, or both are and both halves were heard in their latest
  covering scan (`BeaconWitness::may_associate` over both centers); frame
  TX stays under the primary's passive TX grant. Otherwise it joins at
  20MHz.
- Program (`ht40::program5`, Linux order): C22 `radio::wide5_to(center,
  Forty(sc))` = `rtw8822c_set_channel_bb` 5GHz head of the *center*
  (OFDM RXAGC by band, SCOTRK of the center) + BW40 tail (CCKSB, TXBWCTL
  5/sc, NBI, SBD 1, PT_OPT 1), `rtw_set_channel_mac` (DATA_SC sc, RFMOD
  40, CCK_CHECK set), `_rf` RF18 5GHz band/RFSI + BW40 bit13 at the
  center with RXBB 0x10, `toggle_igi`; then the N2xO OFDM references /
  differences (`radio::ofdm5`, CCK zero, RRSR 0x10) around
  `iqk8822c_run`, then the HT40 words with the OFDM bytes at the N2xO
  selection relative to MCS7 (`ht40::write_power(.., Some(ofdm))`);
  readback `radio::verify_wide5` + `ht40::verify_power`. C21
  `radio8821c::wide5(center, Forty(sc))` = `rtw8821c_set_channel` 5GHz
  head of the center (TXSCALE/CLKTRK of the center), BW40 `set_bw` (RXSB,
  ADCCLK `&0xff3ff300 | 0x20020000 | sc<<2 | 1`, ADC160), 5GHz swing,
  MAC, `_rf` WLA + LUTDBG 0 + RF18 BW40 bit11 at the center + XTALX2
  toggle, `_rxdfir` BW40; then `rtw8821c_do_iqk` and the HT words
  0x1d0c/0x1d10 (the N2xO OFDM TXAGC and RRSR 0x10 stay as programmed);
  readback `radio8821c::verify_wide5`. RRSR must still read 0x10.
- Data path: `DataProfile::bw40` with no CCK rate gives `get_rate_id`
  `RTW_RATEID_GN_N1SS` (5) / `GN_N2SS` (4) (WIRELESS_OFDM|HT has no 40MHz
  variant), `W5_DATA_BW` 1 and RA_INFO `BW_MODE` 1 as on 2.4GHz.

`radio::wide5_to`/`radio8821c::wide5` also carry the BW80 branch for
`vht`.

**5GHz VHT80 (`N2xV`, `vht.rs`).** VHT is advertised only for an
association bound to an N2xV record (below). Separately signed
continuation `rtw88/rtw882{1,2}ce-chNN-vht80-v1-<mac>.bin` (tag `V`, stem
`vht80`) over the primary's band-5 N2xL scope. Payload: primary, center
(`band5::center80`: Annex E class 128 blocks 42/58/106/122/138/155;
165..177 not admitted), width 80, flags (bit0 SGI80), antenna gain,
ceiling, three 80MHz peaks, streams (C22 1..=2, C21 1), highest VHT MCS
7..=9, VHT80 TXAGC indices 1SS MCS0..9 and 2SS MCS0..9 (zero when unused;
C22 within the 7-bit signed difference of the VHT1SS MCS7 reference),
zero tail. Sub-channel `band5::sc80` = `rtw_update_channel` UPPER 1 /
LOWER 2 / UPMOST 3 / LOWEST 4. `vht::hardware_allows`: `hw_cap.bw` 0 or 7.
Factory (`Gate::vht80_limits(center)`): `rtw_phy_get_5g_tx_power_index`
BW80 = `band5::Power5g::bw80` (average of `bw40_base[g]` and `[g+1]` of
the center's group plus `vht_1s_diff.bw80` (+ `vht_2s_diff.bw80`); C22
`Board::vht80_groups` min over both paths, factor 2; C21 path A, factor 1,
max 0x3f). Regulatory (`vht::admission`): one rule covers center +/- 40MHz,
every overlapping rule plain or passive at 80MHz, a passive span needs all
four constituents passive-only. Program (`vht::program`): C22
`radio::wide5_to(center, Eighty(sc))` (BW80 tail TXBWCTL 0xa/sc, SBD 6,
PT_OPT 1; CCKSB/NBI/DFIRBW/TXCLK untouched as in Linux; DATA_SC
`sc | txsc40 << 4` with `RTW_SC_40_UPPER` 9 for sc 1/3 else 10; RFMOD 80;
RF18 bit12, RXBB 0x8), N2xO OFDM power around `iqk8822c_run`, difference
words 0x3a00..0x3a3c with OFDM at the N2xO selection and VHT bytes
0x2c..0x3f from the record (HT bytes at index 0: `rtw_update_sta_info`
builds a VHT-only HT/VHT ra_mask); C21 `radio8821c::wide5(center,
Eighty(sc))` (ADCCLK `&0xfcffcf00 | 0x40040000 | sc<<2 | 2`, RF18 bit10,
`_rxdfir` BW80 ACBBRXFIR 1 / TXDFIR 0 / CHFIR 1), IQK, VHT words
0x1d2c..0x1d34; readbacks `verify_wide5` + `vht::check_power`; RRSR 0x10.
Station binding (`station.rs::associate`, `Gate::with_continuation`):
the AP's VHT Operation (192, `vht::vht_operation`) has channel width 1 and
CCFS0 the Annex E center of the primary (`band5::center80`), `hw_cap.bw` is
0 or 7, the three other constituents are admitted channels (loadable N2xO
records) and `Station::wide_witnessed` holds over all four constituents
(passive-only spans need all four passive and beacon-witnessed); then the
N2xV record for this primary/center (identity only) over the HT program is
preferred over N2xB (never both: `with_continuation` refuses N2xV next to
N2xB). The association PHY is `LocalPhy::vht80` = `rtw_init_ht_cap` 20/40
(RX SGI40, no HT TX SGI40, no N2xC TX coding advertised) + `rtw_init_vht_cap`
narrowed (`vht::local`): maximum MPDU 3895, SHORT_GI_80 (TX per record
flag), RXSTBC_1, RXLDPC per chip, A-MPDU exponent 0, RX MCS0..9 on the HT
program's streams, TX map = record streams x highest MCS; no TX STBC/LDPC,
HTC-VHT; SU/MU beamformee per "VHT SU and MU beamformee". The offer must be 80MHz with VHT on the record's
center (else `Profile`); `widen(Wide::Eighty)` binds and runs
`vht::program` under the retune owner, `station_width_begin` sets PHY
admission width 2 (`query_phy_status_page1` RXSC 13+ / RXSC0 = current).
Association response: negotiated width 80 on the record's center with VHT
negotiation, data profile `vht = VhtRates { tx: get_vht_ra_mask(negotiated
TX map) & record mask, rx: rtw_init_vht_cap RX }`, SGI = peer SHORT_GI_80 and
record SGI80, uncoded (`DataProfile::vht`; `Gate::allows_profile` bounds it
by the live N2xV record). Data path: `get_rate_id` WIRELESS_OFDM|VHT
`ARFR1_AC_1SS` 10 / `ARFR0_AC_2SS` 9, RA_INFO mask `RA_MASK_VHT_RATES |
RA_MASK_OFDM_IN_VHT` (HT dropped), VHT_EN 1 and BW_MODE 2
(`DataProfile::{ra_mask,bw_mode}`), TX descriptor W5_DATA_BW 2, SHORT =
SGI80, DATARATE `get_highest_vht_tx_rate` (0x2c + highest stream/MCS); RX
admits VHT rates 0x2c.. within the advertised RX set and MPDUs up to 3895
bytes (`receive_rates`). Readback at 80MHz (`ht::Wide::Eighty`): C22
`vht::check_power` over the CCK/2SS checks, C21
`operating_readback_vht` (legacy + HT20 words unchanged, VHT words
0x1d2c..0x1d34 from the record, RF18 BW80 bit10 on the center). A beacon/
probe VHT Operation leaving the block (width 0, other CCFS0) or an HT
Operation on another primary drops the connection; CSA cannot carry N2xV.
Not covered: VHT at 20/40MHz, 160/80+80, VHT TX coding/beamforming, the
dm/N21W/RTS programs on 5GHz. No N2xV record is provisioned for any board.
Written, unexecuted:
`smoke_rtw88_vht80_station_profile_descriptor_rx_and_readback`,
`smoke_rtw88_vht80_record_span_and_bw80_program`. Written, unexecuted:
`smoke_rtw88_ht40_5ghz_pairs_programs_and_passive_span`. No 5GHz N2xB
record is provisioned for any board.

Plain regulatory rules (`channel_policy::plain_rule`, used by every rtw88
per-channel, HT40, C22 operating and C21 calibration/operating/station
power check): a rule may carry only `NO_P2P`, `AUTO_BW` and `NO_160MHZ`;
its usable bandwidth is `RegulatoryDomain::max_bandwidth`
(cfg80211 `reg.c::reg_get_max_bandwidth`: an AUTO_BW rule spans its
adjacent run, NO_160MHZ caps at 80MHz), which must cover the program's
width. DFS, NO_IR, indoor and unknown bits still refuse (a 5GHz N2xO
record alone may sit under DFS / NO_IR as passive-only, `passive_rule`). Written,
unexecuted: `smoke_rtw88_plain_rule_auto_bw_and_no_160mhz`. Three cases are written and
unexecuted: `smoke_rtw88_band5_linux_groups_and_factory_power`,
`smoke_rtw8822ce_channel5_bb_mac_rf_program`,
`smoke_rtw8821ce_channel20_cross_band_readback`.

### 5GHz TX A-MSDU and A-MSDU in A-MPDU (`station_tx_amsdu.rs`)

Linux `main.c::rtw_register_hw` sets `TX_AMSDU` and, for C21/C22
(`amsdu_in_ampdu = true`), `SUPPORTS_AMSDU_IN_AMPDU`; mac80211
`tx.c::ieee80211_amsdu_aggregate` builds the aggregate and
`mac80211.c::rtw_ops_can_aggregate_in_amsdu` declines it while
`hal.current_band_type` is 2.4GHz. The station mirrors that path:

- **Gate** (`State::amsdu_limit`): an associated 5GHz (`DataProfile::band5`)
  HT/VHT QoS profile with a negotiated peer. On 2.4GHz nothing changes, and
  `packet_format::classify_profile` refuses the A-MSDU-present QoS bit
  (0x80) on any 2.4GHz or non-HT profile.
- **Size** (`agg.max_amsdu_len`, `ht.c`/`vht.c`): the peer VHT maximum MPDU
  length (`Limit::from_vht_capability`) on an N2xV association, else HT
  capability bit11 (`Limit::from_ht_capability`); narrowed to the native
  allocation `MAX_TX_MPDU` = 3891 bytes (VHT 3895 less FCS; covers HT 3839
  plus QoS header and CCMP) and to `max_rc_amsdu_len` from the latest
  firmware RA report (`fw.c::rtw_fw_ra_report_iter` bit rate via
  `cfg80211_calculate_bitrate_{ht,vht}`, `get_max_amsdu_len`: below 55Mbps 1,
  then 1200/2600/3500, unlimited from 700Mbps; unlimited before any report).
  At most `PREFIX` = 8 same-TID admitted frames per aggregate; EAPOL and
  other control-port protocols are never aggregated
  (`narf_wireless::amsdu::encode`).
- **Frame**: QoS DATA, A-MSDU-present, Address3 = BSSID
  (`ieee80211_amsdu_prepare_head`), one SN; a protected association uses the
  shared `Security::transmit_amsdu_qos` (one PN, CCMP over the whole
  aggregate). Descriptor QSEL is the TID (A-MSDU bit masked); the PCI TX
  buffers (`packet_core::Core::prepare`, four batch buffers) and the BD
  length bound grow to `MAX_TX_MPDU`. MPDUs other than A-MSDUs keep the
  2304-byte bound.
- **Outside BA**: `send_batch` with no active agreement on the TID emits
  one A-MSDU MPDU of the longest fitting prefix (at least two frames) on
  the ordinary single-packet path; the interface hands `send_batch` a FIFO
  prefix while `amsdu_ready` (`batch_capacity` 16).
- **In A-MPDU**: ADDBA requests carry the A-MSDU-supported bit
  (`agg-tx.c::ieee80211_send_addba_request`) only when the association is on
  5GHz, so the qualified 2.4GHz N2xT request bytes are unchanged; native
  `originator_control_tid` admits either value. A response without A-MSDU
  permission for the TID sets the sticky per-TID `no_amsdu`
  (`IEEE80211_TXQ_NO_AMSDU`, `ieee80211_process_addba_resp`). Each burst
  subframe is one MSDU or one A-MSDU, chosen before any SN/PN is consumed
  under the N2xT count/byte/airtime bound; `Aggregation::admits_lengths`
  bounds a VHT descriptor rate by the HT20 MCS of the same stream count
  (MCS8/9 by MCS7) instead of indexing past the HT table.

Not covered: no RX direction change (RX A-MSDU/recipient permission is the
existing R contract); no peer-specific `max_amsdu_subframes` (extended
capabilities) is parsed, the 8-frame prefix bounds the subframe count; the
RA report is read for mac_id 0 only. No physical 5GHz board run exists.
Written, unexecuted:
`smoke_rtw88_tx_amsdu_descriptor_admission_is_5ghz_only`,
`smoke_rtw88_tx_amsdu_ra_report_bounds_max_rc_amsdu_len`,
`smoke_rtw88_tx_ba_addba_amsdu_request_and_no_amsdu`,
`smoke_rtw88_tx_amsdu_vht_aggregate_airtime_bound`.


### VHT SU and MU beamformee (`bf.rs`)

Bound only on an N2xV VHT80 association (Linux reads `vht_cap`):

- **Advertisement** (`vht::local`, `main.c::rtw_init_vht_cap`): SU
  beamformee (bit12) and MU beamformee (bit20) with Beamformee STS 3
  (`hal.bfee_sts_cap`, four NDP STS); the shared request narrows them to the
  AP's roles like `mlme.c::ieee80211_add_vht_ie` (both dropped without the
  AP's SU beamformer bit11, MU dropped without its MU beamformer bit19), so
  this single station is the `mu_mimo_owner` exactly when MU stays in the
  request.
- **Association** (`State::bf_assoc`, after the native peer commit like
  `rtw_ops_bss_info_changed` `BSS_CHANGED_ASSOC` -> `bf.c::rtw_bf_assoc`):
  MU is preferred. When the negotiated VHT `mu_beamformee()` holds,
  `Bfee::mu` binds `bf::Role::Mu` with `p_aid = (bssid[5] << 1) |
  (bssid[4] >> 7)` and `aid` the association ID (`& 0xfff`); otherwise, when
  `su_beamformee()` holds, `Bfee::su` binds `Role::Su` with `sound_dim` from
  the AP's sounding dimensions field, register index 0. `nc_index` follows
  the chip's RX paths (C22 2R 1, C21 1R 0). `bf::phy_init`
  (`rtw_bf_phy_init`, which Linux runs at chip init and the retained init
  does not) precedes the enable. Every word is read back under the station
  admission.
  - SU (`bf::enable_su`, `rtw_bf_enable_bfee_su`): SND_PTCL_CTRL 0x9b under
    mask 0x9f, BFMER0 address, CSI report parameter coef 3 / codebook 1 /
    grouping 0 / nr / nc, NDP standby 0x70; C22
    `rtw8822c_bf_enable_bfee_su` also sets `BIT_WMAC_USE_NDPARATE`, clears
    the AP-mode bit12 and writes `CSI_RRSR` 0x550.
  - MU (`bf::enable_mu`, `rtw_bf_enable_bfee_mu` on both chips):
    `rtw_bf_init_bfer_entry_mu` (BFMER0 address, `p_aid` at 0x6ea, CSI
    parameter coef 0 / codebook 1 / nr 1 / nc at 0x6f4, `MU_BF_CTL` 0x1680
    keeping bits 15:14 with `my_aid` and `HAL_CSI_SEG_4K`);
    `rtw_bf_cfg_sounding(DESC_RATE6M)` (SND_PTCL_CTRL 0x9b, NDP standby
    0x26, RXFLTMAP1 bit4 and RXFLTMAP4 0x68a bit4 cleared,
    `BIT_WMAC_USE_NDPARATE | csi_rsc << 13` with bit12 cleared;
    `CSI_RSC_PRIMARY_20M_BW` on C22, `CSI_RSC_FOLLOW_RX_PACKET_BW` on C21);
    RXFLTMAP0 `ACTIONNOACK` bit14 set; RXFLTMAP1 `BF` bits 4|5 set. Linux
    rewrites RXFLTMAP1 from `hal.rxfltmap1`, the chip `mac_init` value
    (C22 0xffff, C21 0x0fff); the retained C21 init is followed by the
    source MAC table (0x6a2/0x6a3 0xff), so the register is 0xffff (which
    `rx_ba::readback` requires) and the Linux C21 shadow is stale. The shadow
    here is the retained register, so both chips end at
    `shadow | BIT_RXFLTMAP1_BF` without narrowing the init's control
    subtypes.
- **Group ID** (`State::gid_management` in the RX loop, mac80211
  `rx.c::ieee80211_rx_h_action` -> `vht.c::ieee80211_process_mu_groups` ->
  `BSS_CHANGED_MU_GROUPS` -> `bf.c::rtw_bf_set_gid_table`): only while the
  bound role is MU, a VHT Group ID Management action (category 21, action 1,
  at least 50 bytes: 8-byte membership + 16-byte user position), unprotected
  (VHT is non-robust), individually addressed to the station from the
  associated AP (A2 = A3 = BSSID) is consumed; when membership or position
  differ from the last programmed `MuGroup` (zero from association, like the
  `mlme.c` reset), `bf::set_gid` runs `rtw_bf_cfg_mu_bfee`: `MU_TX_CTL`
  0x14c0 table-valid bits cleared then bits 0|1 set and `BIT_EN_MU_MIMO`
  clear; table select 0x14c1 (low 3 bits) 0 then 1, each with `GID_VLD`
  0x14c4 and `USER_POS` 0x14c8/0x14cc from the little-endian membership /
  position words. The control byte and the last-selected table 1 are read
  back (Linux never reselects table 0). Outside the MU role the frame is not
  consumed, as `rtw_bf_set_gid_table` returns for non-MU vifs.
- **Cleanup** (`State::stop`, `rtw_bf_disassoc` -> `bf::remove`): SU
  `rtw_bf_remove_bfee_su` (SND_PTCL_CTRL 0x98, BFMER0/CSI words cleared);
  MU `rtw_bf_remove_bfee_mu` (SND_PTCL_CTRL 0x98, `rtw_bf_del_bfer_entry_mu`
  clears BFMER0 0x6e4..0x6eb, `MU_BF_CTL` and `MU_TX_CTL` byte 0, then
  `rtw_bf_del_sounding` mask 0x9f to 0 since no SU/MU count remains; the CSI
  word, `BBPSF_CTRL` and RX filter maps keep their values as in Linux). Best
  effort since the owner is already closed; the `MuGroup` resets and a fresh
  association reprograms.

Not covered: SU/MU beamformer (station never sounds),
`rtw_dynamic_csi_rate` (watchdog `rtw_bf_cfg_csi_rate` needs the dm
`min_rssi`, and the dm watchdog is not bound on 5GHz; the CSI rate stays at
`rtw_bf_phy_init`'s OFDM6), HT/VHT20/40 associations, Group ID Management
received while the runtime-PS LPS collector owns RX (`lps_collect` does not
parse it; the next awake poll processes later notifications). Linux
`rtw_bf_assoc` reads the unnarrowed band capability, so for an AP with bit19
but not bit11 (invalid per 802.11) it would bind MU without having
advertised it; here MU binds only when advertised. No physical sounding or
MU-MIMO exchange has been run. Written, unexecuted:
`smoke_rtw88_bf_phy_init_and_su_bfee_program`,
`smoke_rtw88_bf_mu_bfee_enable_and_remove`,
`smoke_rtw88_bf_vht_group_id_management_table`; the VHT capability check in
`smoke_rtw88_vht80_station_profile_descriptor_rx_and_readback` now expects
SU and MU beamformee with STS field 3.

### RTL8821CU USB transport (`usb.rs`, `usb_driver.rs`)

Linux drives RTL8821CU with rtw88 (`rtw8821cu.c` over `usb.c`), not
rtl8xxxu. `usb.rs` ports that host interface for the C21 die; the PCI files
(`pci*.rs`, `reserved_page.rs`, `power.rs`, `mac.rs`) are unchanged, so the
PCI path stays byte-identical. Register access reuses the existing async EP0
owner (`rtl8xxxu::firmware_transport::ControlIo` bound to
`narf_drivers_usb::device::USBDevice`); bulk data uses
`narf_drivers_usb::bulk`.

- IDs: `RTL8821CU_IDS` = `rtw_8821cu_id_table` (15 entries, vendor interface
  0xff/0xff/0xff).
- `Registers`: `rtw_usb_read`/`rtw_usb_write` (request 0x05, 0xc0/0x40,
  wValue = address, wIndex 0, exact length) with `rtw_usb_reg_sec`: after an
  access in 0x00..=0xff or 0x1000..=0x10ff, a one-byte write of the data
  buffer's first byte to 0x4e0. `write_firmware_page` is the legacy 8051
  196/8/1-byte block download at 0x1000 (C21's 3081 MCU uses the reserved
  page instead).
- Power: `rtw8821c.c` power sequences filtered to `RTW_PWR_INTF_USB_MSK`
  (`*_8821C_USB`; all rows MAC/USB base). `pre_system` is
  `rtw_mac_pre_system_cfg` without the PCIe `BIT_USB_SUS_DIS` write;
  `power_switch` uses RPWM 0xfe58, treats `REG_SYS_STATUS1+1` bit0 as off
  (as well as CR 0xea), has no PFM_WOWL poll retry, and clears that bit after
  power-on; `power_on` adds the -EALREADY off/on cycle and
  `__rtw_mac_init_system_cfg` (sys_func_en 0xd8).
- Endpoints: `Endpoints::parse` = `rtw_usb_parse` (one bulk-IN, optional
  interrupt-IN, up to four bulk-OUT in descriptor order) plus `qsel_to_ep`
  from `rqpn_table_8821c[bulkout]` via `dma_mapping_to_ep`. A mapping that
  would index past the discovered OUT pipes (one pipe: MGMT -> EXTRA) is
  refused rather than submitting on an unset `out_ep` slot.
- Queues: `usb_tables`/`txdma_pq_map`/`public_pages` = `txdma_queue_mapping`
  and `priority_queue_cfg` USB rows (2/3/4 pipes; 0xfea0/0xf5a0/0xc5a0);
  `queue_mapping_tail` sets `BIT_RXDMA_ARBBW_EN`; `priority_queue_tail` sets
  the AUTO_LLT_V1 block-descriptor count 3, byte+3 = 3 and
  TXDMA_OFFSET_CHK+1 bit1. `interface_cfg` = `rtw_usb_init_burst_pkt_len`;
  `dynamic_rx_agg` = `rtw_usb_dynamic_rx_agg_v1`.
- TX: `descriptor` = `rtw_tx_fill_tx_desc` for the firmware/H2C subset;
  `fill_checksum` = `fill_txdesc_checksum_common(txdesc, 16)` (W7[15:0]);
  `reserved_page_packet` = `rtw_usb_write_data_rsvd_page` with
  `send_firmware_pkt`'s +1 byte when descriptor+payload is a multiple of 512;
  `h2c_packet` = `rtw_usb_write_data_h2c`; `tx_qsel` =
  `rtw_usb_tx_queue_mapping_to_qsel`; `aggregate` = `rtw_usb_tx_agg_skb`
  (8-byte aligned, at most 3 packets / 20 KiB, DMA_TXAGG_NUM + checksum).
- RX: `split_rx` = the `rtw_usb_rx_handler` framing loop (24-byte RXDESC +
  drv_info*8 + shift + pkt_len, next record at round_up(..., 8), URBs below
  24 bytes or at 32 KiB dropped). Each record must still pass
  `packet_format::receive*` admission.
- EFUSE: `efuse_mac` reads the USB map MAC at 0x107
  (`rtw8821cu_efuse_parsing`); `Factory8821c::mac` is the PCI 0xd0 layout.

Registration (`usb_driver.rs`, `rtw8821cu.c::rtw_8821cu_driver` over
`usb.c::rtw_usb_probe`): `RTW8821CU_USB_IDS` registers every
`RTL8821CU_IDS` entry with the vendor interface triple 0xff/0xff/0xff
(`USB_DEVICE_AND_INTERFACE_INFO`) through
`class_registry::register_class_driver_with_unbind` ("rtw8821cu"); 0bda:c811
is removed from `rtl8xxxu::RTL8XXXU_USB_IDS`, so rtl8xxxu no longer claims
it. `probe` records the slot and spawns the asynchronous attach:
`rtw_usb_intf_init` (full configuration descriptor -> `Endpoints::parse`),
SET_CONFIGURATION and xHCI contexts for the bulk-IN and every bulk-OUT pipe
(`endpoint_configs`; the interrupt-IN pipe is never used), `Speed::from_port`,
`usb_firmware::Backend` over `rtl8xxxu::firmware_transport::UsbControl` and
`rtl8xxxu::packet_transport::UsbIo`, `usb::Registers::power_on` and
REG_C2HEVT (0x1a0) = 0xfd (`rtw_chip_efuse_enable`), the asynchronous USB
EFUSE read, `Lifecycle::new(0xc821).on(Interface::Usb { vendor, product })`,
`interface::Device::new` and `interface::publish` (`rtw8821cu`), the
`narf_drivers::record_bound` entry `rtw88-8821cu` (`BoundKind::Net`, no PCI
IDs; `pci.rs::probe` records `rtw88-8821ce`), then the
`sibling.rs::Sibling::provision` stage sequence (firmware download, MAC,
PHY, C21 calibration/operating/station with `Source::Registered`) and
`Device::activate`, retried as `pci.rs::schedule_owner` (120 x 500 ms) while
the firmware image or signed records are not registered. The backend stays
unclaimed in the attach task until an attempt's image is available.
`rtw_usb_phy_cfg` is a no-op for 8821C (empty `usb2/usb3_param_8821c`) and
`rtw_usb_switch_mode` does not apply to it. The unbind hook withdraws the
shell and spawns `Lifecycle::remove`. `rtl8xxxu::regs::REALTEK_USB_IDS`
still lists 0bda:c811 as an identification table (chip-family naming and the
rtl8xxxu tests); the bind table `RTL8XXXU_USB_IDS` excludes it. An
unprovisioned RTL8821CU (no signed
`rtw8821cu-*` N21Q record) stops at `PhyTablesPrepared` and is never
admitted: no station, band or TX grant is published. Written, unexecuted:
`smoke_rtw88_usb_driver_id_table_and_endpoint_contexts`.

Recovery, idle and system sleep (`usb_recovery.rs`). Linux rtw88 recovers
USB and PCI through the same HCI-agnostic core: `main.c::rtw_fw_recovery_work`
(`__fw_recovery_work` resets keys/stations/vifs, then `ps.c::rtw_enter_ips`
-> `rtw_core_stop` + `rtw_power_off`) and `ieee80211_restart_hw` ->
`rtw_ops_start` -> `rtw_core_start` (`rtw_power_on`, firmware, MAC/PHY);
IPS (`rtw_enter_ips`/`rtw_leave_ips` -> `rtw_ips_pwr_up`) is the same
stop/power-off/start pair. `usb.c::rtw_usb_disconnect`'s
`usb_reset_device` is removal-only and is not used on these paths.
`usb_driver.rs` keeps per slot the `Origin` learned at the first attach
(endpoints, speed, factory MAC) and a provisioning mutex
(`Rtw88Device::provisioning`); a `Generation` is one lifecycle + published
shell, published before it is installed as the slot's current generation
(a slot unbound meanwhile gets it withdrawn). `usb_recovery::park` (under
that mutex) withdraws the current shell for rebind (name/ifindex kept),
retires its owner with the actual bulk-receipt stop
(`operating_reset::retire`), checks the slot is still current and powers
the card off over EP0 (`usb::Registers::power_off` = `rtw_power_off`:
empty `rtw_usb_stop`, `rtw_coex_power_off_setting` REG_WIFI_BT_INFO =
BIT_BT_INT_EN, `rtw_mac_power_off`, plus a CR 0xea / SYS_STATUS1+1 bit0
readback). `unpark` builds a fresh backend over the original pipes (xHCI
contexts stay configured; Linux keeps the interface bound), runs
`rtw_mac_power_on` + REG_C2HEVT + a fresh EFUSE map whose MAC must equal
the original (`Identity` otherwise, as `pci.rs::bring_up_mode` re-reads
it), and publishes a fresh `Generation` under the kept name; every stage is
then earned again through the host-keyed `rtw8821cu-*` records. Entry
points (`pub` in `rtw88::usb_recovery`, keyed by USB slot):
`reset_usb` = `operating_reset::reset_function` (operating station only;
fresh generation provisioned in the background, `pci.rs::schedule_owner`
retries); `rejoin_usb` = `rejoin::rejoin_function` (reset, one provisioning
attempt, then `rejoin::associate_fresh` with the caller's fresh Open/WPA2
credentials, `Pending` zeroizes on cancellation); `idle_usb` =
`runtime_idle::idle_function` (`Interface::idle_claim`: the actual
unassociated passive station only; a durable `system_pm_worker` owns the
parked receipts and the returned `RuntimeIdle`'s `resume`/drop powers a fresh
generation on and provisions it). No old key, peer, station or calibration
receipt is replayed. System sleep: `rtw_8821cu_driver` has no
`.suspend`/`.resume`, so the Linux USB core
(`usb/core/driver.c::usb_suspend` -> `unbind_no_pm_drivers_interfaces` ->
`usb_forced_unbind_intf`) unbinds it before the device suspends and
`usb_resume_complete` -> `rebind_marked_interfaces` probes it fresh. Here
`system_pm::SystemPm::prepare` adds one `usb_recovery` worker per bound
slot to the same session: prepare parks any stage (a slot with no live
generation parks nothing), resume unparks and provisions once; a station
that was not operating keeps the scheduled retries rather than inventing
records, an operating one that fails is withdrawn
(`system_pm_native::resume_cold`). WoWLAN: Linux sets `wiphy->wowlan` from
`chip->wowlan_stub` for every HCI (`main.c::rtw_register_hw`), so
`rtw_ops_suspend` may arm the 8821C WoW firmware, but the USB core's forced
unbind then runs `rtw_usb_disconnect` -> `usb_reset_device`, so no armed WoW
state survives a USB system suspend. This tree advertises no C21 WoW on
either HCI (`wow::support` is C22-only; PCI 8821CE system sleep is the cold
path), so the USB station never arms one and matches PCI 8821CE scope. The
USB core's port/host-controller suspend is not claimed here. A failed park
or unpark leaves the slot bound with its shell withdrawn (fail closed);
unbind or replug starts over. Written, unexecuted:
`smoke_rtw88_usb_power_off_sequence`,
`smoke_rtw88_usb_recovery_unbound_slot_refuses`.
Former blockers, verified against the tree:

1. Register contract (resolved: asynchronous `Io`). `firmware_transport::Io`
   `read8/16/32` and `write8/16/32` return `impl Future + Send` (RPITIT, not
   boxed), and every retained stage that touches them is async: `mac.rs`,
   `phy.rs`/`phy/rtl8821c.rs`, `calibration8821c.rs`/`radio8821c.rs`,
   `operating8821c.rs`, `radio.rs`, `dack.rs`, `dpk.rs`, `dm.rs`, `ht*.rs`,
   `vht.rs`, `bf.rs`, `security_cam.rs`, `station*.rs`, `wmm.rs`,
   `tx_ba.rs`/`rx_ba.rs`, `tracking8821c/program.rs`, `runtime_lps.rs` and
   `wow.rs`/`wow_owner.rs` (`wow::Io` follows the same shape). C22 uses the
   same converted stages. The PCI backend (`reserved_page::Backend` over the
   synchronous `reserved_page::Registers`) returns futures that complete in
   their first poll, so its MMIO byte stream and order are unchanged; a USB
   backend implements the same trait with real EP0 transfers. No synchronous
   polled EP0 primitive is added. Supporting rules:
   - `firmware_transport::enclosed(wrap, operation)` replaces each
     synchronous enclosure around register work (`Grant::invoke`,
     `Envelope::invoke`, `Admission::run`, `dm::Authority::run`,
     `tracking8821c::Grant::authority`, ...). The operation's first poll runs
     inside `wrap`, so a PCI operation executes wholly inside the enclosure as
     before; an operation still in flight (USB) continues outside and its
     completion re-enters `wrap`, so revocation or `Admission::close` during a
     transfer voids the result instead of returning it.
   - Readbacks (`ht::Grant::readback*`, `radio8821c::operating_readback*`,
     `ht40::check_power`, `vht::check_power`, `wmm::readback*`,
     `tracking8821c::Grant::read_program`) take a `firmware_transport::Read32`
     (`IoRead32`, `RadioRead32`, or `Sampled` for a synchronous PCI sampler)
     rather than a borrowing closure.
   - Synchronous PCI entry points that drive the converted station
     (`pci_firmware.rs` `station_profile_readback` and peers,
     `interface.rs` `progress`/`set_rts_threshold`, `station.rs::stop`'s
     best-effort beamformee removal) use `firmware_transport::ready_now`,
     which refuses (`Error::State`) a future that does not complete in one
     poll instead of spinning. A USB owner must drive those paths from an
     async worker; that is part of blocker 2.
   - The HT path-switch RX-DMA idle wait (`ht.rs::program`) samples through
     the gate every executor turn for the same 10 ms bound, instead of a
     synchronous `responsive_spin_until`.
2. Packet path (packet owner landed; station worker open).
   `packet_core::Port` stays shaped around PCI TXBD/RXBD rings.
   `usb_packet.rs::Owner` is the queue/URB-shaped USB counterpart over the
   persistent begin/poll bulk receipts (`rtl8xxxu::packet_transport::Io`,
   `USBDevice::begin_bulk_*`), so `poll` never blocks or spins:
   - TX (`rtw_usb_tx_write`): `transmit_packet` builds the PCI owner's
     descriptor (`transmit_profile` + RTS protection), replaces W1 QSEL by
     `rtw_usb_tx_queue_mapping_to_qsel` (MGMT/HIGH/TID) with MORE_DATA for
     HIGH, and applies the USB checksum. Frames queue on
     `tx_queue[qsel_to_ep]` (at most `MAX_QUEUED` = 32 in total, `Busy`
     beyond); `rtw_usb_tx_handler` walks the pipes from the highest index
     down, one URB in flight per pipe, each URB one `aggregate` of up to
     three queued packets.
   - Completion (`rtw_usb_write_port_tx_complete`): a frame that requested a
     report (SPE_RPT, six-bit `sn << 2` not held by any queued, in-flight or
     awaiting frame) waits for its CCX C2H (1 s deadline, NACK terminal, as
     on PCI; acknowledged frames are released in completion order); every other frame completes on the exact-length USB completion
     with `radio_acknowledged = false`. Linux's `IEEE80211_TX_STAT_ACK` for
     those is mac80211 bookkeeping, not radio evidence.
   - RX: one persistent 32 KiB bulk-IN receipt; a completed URB is copied,
     the receipt re-posted, and every `split_rx` record admitted by `admit`
     under the PCI owner's rules (`receive_rates` at the current profile,
     PHY status on the operating channel/width, FCS removed, short non-BAR
     MPDUs dropped). C2H records also feed CCX matching.
   - Any USB error fails the owner (the 8188EU halt-recovery sequence is not
     ported); `stop` retires every retained receipt through `Io::stop`.
   Station worker (landed): `firmware_transport::Io::SYNCHRONOUS`
   (default `true`; the USB backend is `false`) selects how
   `interface::Device` drives the owner. `Device::step` is the single
   progress turn (poll, publish, one TX slot or batch); each owner future
   goes through `settle`, which is `ready_now` for a synchronous backend
   (PCI semantics and byte stream unchanged) and an `.await` otherwise. The
   synchronous `progress`/`drain` (stack RX drain, endpoint `drain`) are
   no-ops for USB; `interface::publish`'s spawned loop awaits
   `Device::drain_async` (`step` + delivery) instead. `set_rts_threshold`
   on USB records the value (EOPNOTSUPP when RTS is not capable) and the
   worker applies it through `station_set_rts_threshold` (Busy retries,
   a newer request supersedes; Linux `rtw_ops_set_rts_threshold` also only
   records it). `publish` names an RTL8821CU (`Interface::Usb`, C21,
   asynchronous) `rtw8821cu`. `Io::dynamic_rx_agg` (default no-op =
   `rtw_pci_ops.dynamic_rx_agg == NULL`) is `rtw_usb_dynamic_rx_agg_v1` on
   USB; the station watchdog (`station_rx_agg.rs`) counts delivered/sent
   unicast DATA bytes over each 2 s period and programs
   `tx_mbps >= 1 || rx_mbps >= 1` (`main.c::rtw_watch_dog_work`,
   `RTW_TP_SHIFT`) inside the admission, only for `Hci::Usb` and only when
   the selection changes. Written, unexecuted:
   `smoke_rtw88_usb_station_worker_dynamic_rx_agg` (also a static `Send`
   check of the USB worker turn).
   The synchronous register-touching `Io` surface is converted (option
   (b), as blocker 1): `mailbox_ready`/`mailbox_submit`/`mailbox_consumed`,
   `ps_mailbox_submit` (`PsScope` is now `Send`), `submit_h2c`/`poll_h2c`,
   `park_radio`, `station_ht_program_quiet`, `station_power_tracking_quiet`
   and `station_profile_readback` return `impl Future + Send`. The PCI
   `reserved_page::Backend` runs its synchronous `Registers` call inside
   `async move`, so the call happens in the first poll, inside any
   `firmware_transport::enclosed` wrapper, and the MMIO byte stream and
   order are unchanged. The synchronous enclosures around them
   (`runtime_lps` mailbox/readback, `tracking8821c::program` park/IQK/
   restore, `radio8821c::Checked`) use `enclosed`. The `packet_*` methods
   stay synchronous because `usb_packet::Owner` is already non-blocking.
   USB `Io` backend (landed, `usb_firmware.rs::Backend`, Linux
   `rtw_usb_ops`): registers are `usb::Registers` (EP0 vendor requests with
   the `rtw_usb_reg_sec` mirror); `reserved_page` is
   `fw.c::rtw_fw_write_data_rsvd_page` without the PCIe-only
   REG_FWHW_TXQ_CTRL+2 BCNQ_DL toggle (BCN_VALID W1C, ENSWBCN, BCN_CTRL,
   one BEACON-qsel `reserved_page_packet` on the `qsel_to_ep` pipe,
   `check_hw_ready` BCN_VALID_V1, boundary/BCN_CTRL/CR+1 restore), so the
   unchanged `firmware_transport::Owner::download` section/IDDMA sequence
   runs over USB; `submit_h2c`/`poll_h2c` are `rtw_usb_write_data_h2c` on
   the H2C-qsel pipe with exact-length completion; the mailbox is
   `rtw_fw_send_h2c_command` (HMETFR 0x1cc, HMEBOX_EXT 0x1f0, HMEBOX 0x1d0);
   `lte_*` is the REG_WL_LTECOEX_CTRL indirect access; `packet_*` delegate
   to `usb_packet::Owner` (one multi-record USB step is replayed one
   frame/C2H/receipt per `packet_poll`). Every bulk-OUT receipt is retained
   until its exact completion or `quiesce_dma`'s endpoint stop; any failure
   leaves the backend terminal. The PCI phase gates that are MAC registers
   (CR & 0xcf, HIMR 0xb0/0xb8/0x10b8) are kept; PCIe DMA config (0x303) and
   bus mastering have no USB counterpart. `Io::hci` (default PCIe) feeds
   `mac::prepare_on`: for `Hci::Usb { bulkout, speed }` the FIFO uses the
   bulk-out-count `rqpn_table_8821c`/`page_table_8821c` rows, sets
   BIT_RXDMA_ARBBW_EN after the CR write, writes the AUTO_LLT_V1
   block-descriptor count and TXDMA_OFFSET_CHK+1 BIT(1) before LLT init
   (`rtw_set_trx_fifo_info`) and ends with `rtw_usb_init_burst_pkt_len`
   (`rtw_mac_init` -> `rtw_hci_interface_cfg`); USB is refused for C22 and
   the PCIe byte stream is unchanged. Packet open/close (landed):
   `Io::packet_open`/`Io::packet_close` are asynchronous hooks (default
   `Ok`, so PCI, which opens and closes inside its synchronous
   `packet_start`/`packet_stop`, is unchanged). `station::State::start`
   awaits `packet_open` right after `packet_start` inside the admission
   (`enclosed`); `disconnect` and `Owner::quiesce_dma` await
   `State::close_packets` before the synchronous `stop`. The USB backend's
   `packet_open` is the PCI `Port::start` MAC open over EP0 (CR = 0xff,
   TXPAUSE = 0, both read back; the station gate must be current), and
   `packet_submit`/`packet_ready` require it. `packet_close` writes
   TXPAUSE = 0xff, clears CR & 0xcf, verifies both, and retires every packet
   bulk receipt (`rtw_usb_cancel_rx_bufs`/TX purge) even when the register
   close failed; on success the backend is `Closed` and `packet_stop` only
   records it (it fails the backend closed only when no asynchronous close
   ran, leaving retirement to `quiesce_dma`). Station grant hooks
   (landed): the USB backend binds the PCI backend's signed-gate operations
   without register access (`station_extension`/`_bind_extension`,
   `_ht_extension`/`_bind_ht`/`_ht_request`, `_rx_ba_*`, `_tx_ba_*`,
   `_protection_extension`/`_bind_protection`/`_rts_request`,
   `_continuation*`, `_channel_grant`, `_regulatory`, `_bind_host`,
   `_gate`, `_ht_facts`); every record is host-keyed (`rtw8821cu-*`), so a
   PCI record never admits it. `station_publication` returns
   `Publication::usb(gate, open)`: it encloses each publication in the
   signed gate plus the backend's open flag (set by `packet_open`, cleared by
   `packet_close`/`packet_stop`/`quiesce_dma` and any non-`Busy` packet
   failure, the USB counterpart of the PCI bus-master check).
   `packet_submit` requires the current gate (`Port::transmit_allowed`),
   `packet_profile` the gate's `allows_profile`, and
   `station_profile_readback` replays the PCI readback over EP0 at the
   committed width (`committed_wide`). Retune and widening (landed):
   `Io::station_retune_begin`/`_width_begin`/`_retune_iqk`/`_retune_finish`
   return `impl Future + Send` (the PCI `reserved_page::Backend` runs the
   unchanged synchronous `Registers` call in the first poll;
   `station.rs::retune_to`/`widen` enclose them with
   `firmware_transport::enclosed`). The USB backend mirrors
   `pci_firmware.rs`: begin installs the target gate (base for channel 1,
   else the N2xO record over the base) or, for widening, requires exactly
   one bound N2xB/N2xV record on the committed primary, refuses new TX
   (`packet_submit` -> `State`) and mailbox H2C, sets the
   `usb_packet::Owner` RX admission channel/width (a band crossing resets
   DATA to the band's base profile), writes TXPAUSE = 0xff and reports
   quiet. USB quiet (`transmit_quiet`) has no TXBD indices: no frame queued,
   in a URB or awaiting CCX, no outstanding H2C receipt, REG_TXDMA_PQ_MAP
   & 0xfff0 = this pipe count's `rqpn_table_8821c` map, and each
   REG_FIFOPAGE_INFO_1..4 reporting all of its `page_table_8821c` pages
   free. The only in-retune H2C is `command::iqk8821c` at the running
   sequence on the H2C pipe (`poll_h2c` admits it). Finish re-proves quiet
   and the target gate, clears TXPAUSE with readback and advances the
   epoch (`wide` after widening). The C21 RF/BB stages
   (`channel_policy::program`/`program5`, `ht40::program`,
   `vht::program`) then run over EP0 unchanged, so a USB station follows
   the same signed host-keyed (`rtw8821cu-*`) 2.4/5 GHz N2xO and
   N2xB/N2xV records as PCI. `station_passive_tx` and the passive-primary
   TX rule (`passive_tx_allowed`) and `station_ht_program_quiet` follow
   PCI too. TX A-MPDU (landed; Linux rtw88 runs mac80211
   `IEEE80211_AMPDU_TX_START` on USB with the same `rtw_tx_fill_tx_desc`
   AGG_EN/density/MAX_AGG_NUM descriptor, packed by `rtw_usb_tx_agg_skb`):
   `station_tx_ba_extension` loads the host-keyed N21T record over the
   gate's TX base as PCI does; `packet_aggregation` installs an envelope
   only within the bound grant (`usb_packet::Owner::aggregation`, idle
   owner); `packet_submit_batch` requires the open, non-retuning, current
   gate, the passive TX rule, a grant TID (< 6) and an admitted profile
   (`Port::originator_ba_allowed`/`batch_allowed`), then runs
   `usb_packet::Owner::submit_batch` inside `Gate::invoke_batch`
   (`batch_publication`). The owner mirrors `packet_core::Core::submit_batch`:
   idle owner only (`Busy` otherwise), envelope `admits`, one QoS TID,
   fixed rate without fallback, each MPDU with W2 AGG_EN | density << 20,
   W3 MAX_AGG_NUM 3 << 17 before RTS protection, its own CCX sequence,
   then the USB qsel and checksum, all queued on the TID's pipe and kicked
   (URB packing as for any queue). CCX reports may arrive out of order;
   report-awaiting frames are released strictly in completion order
   (`Core::complete_batch` FIFO), which the station's FIFO DATA retirement
   needs. A refusal before queueing leaves the owner running; a failed URB
   begin fails it and the backend. Written, unexecuted:
   `smoke_rtw88_usb_packet_ampdu_batch`. Power tracking (landed;
   `phy.c::rtw_phy_pwr_track` -> `rtw8821c.c::rtw8821c_pwr_track`):
   `Io::station_power_tracking_request`/`_extension`/
   `station_bind_power_tracking`/`_begin`/`_quiet`/`_iqk`/`_finish` return
   `impl Future + Send` (the PCI `reserved_page::Backend` runs the unchanged
   synchronous `Registers` call in the first poll; `tracking8821c::program`
   and `station.rs` enclose begin/bind/finish with
   `firmware_transport::enclosed` instead of `Admission::run`). The USB
   backend mirrors `pci_firmware.rs` over EP0: request/extension read
   0xc94/0xc1c and load the host-keyed N21W record
   (`rtw88/rtw8821cu-power-track-v1-*`, header = USB VID/PID) over an HT
   gate; bind reads back the W program; begin requires the open,
   non-retuning backend with no H2C/mailbox outstanding and the bound W,
   flips it to Changing (so `Gate::current`, and with it `packet_submit` and
   every publication, refuses TX) and reports `transmit_quiet`; the
   continuation's only H2C is `command::iqk8821c_associated` at the running
   sequence (`poll_h2c` admits it); finish re-proves quiet, TXPAUSE 0xff and
   RXPKT_NUM RXDMA_IDLE|RW_RELEASE, reads back the program, the HT grant and
   the thermal window, releases RW_RELEASE/TXPAUSE with readback and commits
   or retires W. USB has no RX descriptor ring: the RX side is the
   continuation's RXDMA_IDLE park plus the station's receive retirement.
   Unlike PCI, USB `packet_submit` cannot replay the W readback per frame
   (that would be EP0 I/O in a synchronous call); the W phase in
   `Gate::current` and the readbacks at bind/begin/finish and in
   `station_profile_readback` stand in for it. Written, unexecuted:
   `smoke_rtw88_usb_power_tracking_preconditions`. Nondeep LPS (landed;
   `ps.c::rtw_enter_lps_core`/`rtw_leave_lps_core` as on PCI):
   `runtime_lps::lps_usb(slot_id, ms)` / `lps_request_usb` are
   `lps_function`/`lps_request_function` keyed by the claimed USB slot
   (`usb_driver::station`), running the unchanged generic
   `Owner::lps_window`. The USB backend supplies `station_reserved_page`
   as a bulk BEACON-queue uploader (`fw.c::rtw_fw_write_data_rsvd_page`
   over `usb.c::rtw_usb_write_data_rsvd_page`, `usb::reserved_page_packet`;
   no BCNQ_DL toggle, no beacon descriptor ring), instead of
   `runtime_ps_page.rs`'s PCI-DMA shape: the same 464-byte source page at
   the station boundary (460), an RX-quiet proof (open idle owner, no
   retune/W continuation/H2C/mailbox, no RX backlog, `transmit_quiet`),
   BCN_FUNCTION off and the boundary unchanged, then poison, BCN_VALID
   clear, ENSWBCN, the bulk page, a fresh BCN_VALID (1000 x 10 us) and the
   REG_FIFOPAGE_CTRL_2/BCN_CTRL/CR+1 restore with readback; every EP0 step
   and the bulk submission run inside the original PS source and station
   admission (`firmware_transport::enclosed`). `ps_mailbox_submit` stages
   HMEBOX_EXT and re-reads HMETFR over EP0, then inside the PS scope runs
   the host-side quiet and gate checks and begins the publishing HMEBOX EP0
   write in its first poll (PCI re-reads HMETFR inside the scope; on USB
   that read is the EP0 step just before it). `Unissued` leaves the mailbox
   free; a begun low word that fails is terminal. Written, unexecuted:
   `smoke_rtw88_usb_lps_mailbox_preconditions`. No RTL8821CU LPS (N2xZ)
   record exists; an unprovisioned station returns `Unsupported` from
   `station_continuation` and never sleeps.
   Written, unexecuted: `smoke_rtw88_usb_station_retune_preconditions`. Written, unexecuted:
   `smoke_rtw88_usb_firmware_reserved_page_sequence`,
   `smoke_rtw88_usb_mac_fifo_rows`, `smoke_rtw88_usb_firmware_h2c_bulk`,
   `smoke_rtw88_usb_packet_open_close_async`.
   USB EFUSE (landed): `efuse::read_factory8821c_usb` runs the
   `rtw_dump_physical_efuse_map` sequence of the synchronous PCI reader
   (bank 0, programming LDO off, per-byte REG_EFUSE_CTRL address write and
   VALID poll bounded by `EFUSE_POLL_MS`) over the asynchronous register
   `Io`, decodes it with the shared `decode_map` and returns
   `Factory8821c::on_usb` (MAC at 0x107). Each poll is an EP0 transfer, so
   nothing spins; the PCI `EfuseIo` path is unchanged. Written, unexecuted:
   `smoke_rtw88_usb_efuse_factory_async`.
   Remaining: none in the transport (above).
3. Identity and records (resolved: host-keyed records).
   `phy8821c::Interface::Usb { vendor, product }` carries the claimed
   VID/PID; `Interface::host()` yields `phy8821c::Host` (PCI 0x10ec:0xc821,
   `Host::PCI_C22` for C22). `Lifecycle::on(interface)` /
   `firmware_transport::Owner::on` hand it to the owner, whose
   `prepare_phy8821c` applies `Info::on(interface)` and refuses a factory
   map of the other layout (`Factory8821c::on_usb`: MAC at 0x107,
   `rtw8821cu_efuse_parsing`). The calibration `Board` retains the host and,
   for USB only, binds `host-usb` + VID/PID into its identity (after the
   `intf-usb` table binding), so every downstream identity differs. Each C21
   record decoder compares header bytes 12..16 with `Host::header()` (vendor
   LE, device LE) and names its file `rtw88/<Host::family()>-...`
   (`rtw8821ce`/`rtw8822ce` on PCI, `rtw8821cu` on USB): N21Q
   (`calibration8821c`), N21P (`operating8821c`), N21S
   (`station_power8821c`), N21L (`station_profile`), N21W
   (`tracking8821c`), N21H (`ht`), N21R (`rx_ba_power`), N21T
   (`tx_ba_power`), N21X (`protection`) and every N2x* continuation
   (`qualification`, which also carries channel/HT40/VHT80/coding/QoS/
   fallback/dm/LPS kinds). The host flows Board -> `calibration8821c::Request`
   -> `operating8821c::{Request, Info}` -> `station_power8821c::Request` ->
   `Gate::host`/`ExtensionBase::host` -> `station_profile::Grant::host` ->
   `ht::Grant::host`. `channel_policy::scoped_filename` splits at the first
   `-` so per-channel USB names stay distinct. PCI identities, headers and
   filenames are byte-identical to the PCI-only encoding. No RTL8821CU
   board/power measurement or record exists and none is invented: an
   unprovisioned 8821CU fails `Source::Registered` at N21Q and stays
   unadmitted before any radio TX. Written, unexecuted:
   `smoke_rtw8821cu_calibration_records_keyed_by_usb_host`.
4. Tables (resolved). Linux selects rows with `cond.intf = INTF_USB`
   (`phy.c::rtw_phy_setup_phy_cond`, `check_positive`).
   `phy/rtl8821c.rs::Info::interface` (`Interface::{Pcie, Usb}`, set with
   `Info::on`) feeds `rows`, which every table application and
   `bind_tables` use. Re-derived from `rtw8821c_table.c`: the only
   interface-qualified branch headers in `rtw8821c_mac`/`_bb`/`_agc`/
   `_agc_btg_type2`/`_rf_a` are `INTF_SDIO` (`_bb`, `_rf_a`), so for every
   admitted cut 0..=6, package 0/1 and RFE 0/2/4/6 the USB parse emits the
   PCIe rows (138/1669/386/128/586) and USB selects the same frozen tables.
   `bind_tables` prefixes `intf-usb` for USB only, so PCIe hashes are
   unchanged and USB bindings never alias PCIe ones. Written, unexecuted:
   `smoke_rtw8821cu_phy_usb_interface_rows_match_linux_references` (USB
   replays the frozen Linux callback hashes).

RTL8822BU is the retained RTL8822BE B22 runtime over this USB transport
(see "RTL8822BU: the B22 die over the USB transport" below: the
`usb_driver.rs` `rtw8822bu` class driver over `usb::RTL8822BU_IDS` and
`efuse::read_factory8822b_usb`). The C21 5 GHz/VHT80 programs
(`channel_policy::program5`, `vht::program`, N2xV) run over this transport
through the USB station retune (`usb_firmware.rs` `station_retune_*`), under
the same signed host-keyed records as PCI (see the retune paragraph above).

Written, unexecuted: `smoke_rtw88_usb_endpoints_and_qsel_map`,
`smoke_rtw88_usb_queue_tables_and_tx_qsel`,
`smoke_rtw88_usb_reserved_page_descriptor_and_checksum`,
`smoke_rtw88_usb_tx_aggregation_framing`,
`smoke_rtw88_usb_rx_aggregate_split`,
`smoke_rtw88_usb_register_section_mirror`,
`smoke_rtw88_usb_power_on_sequence`,
`smoke_rtw88_usb_interface_cfg_and_rx_agg`,
`smoke_rtw88_usb_packet_tx_queues_and_aggregation`,
`smoke_rtw88_usb_packet_rx_aggregate_and_ccx_receipt`,
`smoke_rtw88_usb_packet_timeout_stop_and_descriptor`.

## 4. Invariants

- Physical reads select Wi-Fi EFUSE bank zero and disable the programming
  LDO25: `0x37[7]` for 8821C/8822B, `0x29[0]` for 8822C.
- A read clears `REG_EFUSE_CTRL[31]` and waits for hardware to set it.
  Address bits are `[17:8]`; unrelated control bits are preserved. The
  per-byte wait is bounded and uses the scheduler's responsive wait.
- Only the unprotected physical area is decoded. One- and two-byte
  headers select eight-byte logical blocks, with zero bits enabling
  two-byte words. Later records override earlier words; absent words
  remain `0xff`. Truncated/out-of-map records fail explicitly.
- Beacon completion clears stale valid status before publication and
  waits for a fresh valid observation. An outer-shareable acquire fence
  orders that exact completion before CPU reuse; ambiguous completion or
  cancelled restoration cannot reopen the buffer.
- No successful association or usable packet ring is implied by identity
  detection or firmware-ready status.

## 5. Architecture notes

The register protocol and byte-stream decoder are architecture independent;
BAR mapping and responsive waits use the existing bus/scheduler services.
Traced fake-register smokes exercise the live identity and firmware
helpers without a Realtek device on both architecture builds. Native
publication and completion use full outer-shareable device barriers on
aarch64.

## 6. Dependencies

`narf-bus` owns BAR/configuration access, `narf-io` supplies coherent
DMA storage, `narf-firmware` supplies authenticated image snapshots,
`narf-scheduler` owns the asynchronous continuation, and `narf-time`
provides bounded completion waits. Shared `narf-wireless` association,
station-security and packet-key owners supply bounded MLME, RSNA and CCMP;
`narf-net` supplies frame registration and the kernel IP/DHCP stack.

## 7. Stage assignment

- **Stage 1**: PCI match table + sparse EFUSE MAC read (software covered;
  physical hardware acceptance pending).
- **Retained RTL8822CE software profile**: section firmware/reserved-page/
  IDDMA, MAC/PHY/radio, signed operating power, H2C/mailbox, ordinary packet
  rings and the channel1 Open/WPA2 station shell are implemented. Composed
  software gates and physical acceptance are tracked separately. Distinct
  optional N22L enables response-bound legacy12 DATA and WMM BE/TID0.
- **Retained RTL8821CE software profile**: exact firmware, inactive MAC,
  chip-specific one-path PHY tables, separate N21Q IQK/N21P parked-power/N21S
  awake-radio grants and native ch1/20 Open/WPA2 station are implemented.
  Real measured signed assets and physical acceptance remain gates.
- **Additional profiles**: RTL8822BE native station support, broader
  PHY/rates/channels, power management and recovery remain outside this gate.

## 8. Open questions and references

RTL8821CE, RTL8822CE and RTL8822BE (B22) firmware have retained native owners;
RTL8822BE stops at the inactive PHY-table stage. BAR2 contains registers, so firmware travels through beacon
host DMA and IDDMA rather than whole-blob BAR writes. The initial hardware
target is exclusively RTL8822CE, awake channel1/20 MHz, host CCK1 data and
qualified native legacy responses, Open or WPA2-PSK, software CCMP and bounded
polling. A signed measured version2 envelope for the actual board/environment,
authenticated firmware and deployment policy are mandatory before any RF
qualification or packet transmission. No default country, curve or calibration
authority is supplied. Physical scan/association/DHCP/bidirectional IP and safe
disconnect/failure on that exact board remain hardware acceptance obligations.

Remaining software ledger:

| Prerequisite | State |
|---|---|
| PCI BAR2, power/cut sequencing, factory identity | Implemented; register-model and QEMU regressions |
| Beacon reserved-page DMA owner, descriptors, successful park | Implemented for RTL8821CE/RTL8822CE; terminal failures retain mappings |
| Authenticated section loading, IDDMA validation | Implemented with separate exact RTL8821CE/RTL8822CE/RTL8822BE images; raw-MMIO helper rejects |
| Inactive PCIe MAC/FIFO/LLT/internal H2C queue setup | Implemented in the same retained firmware owners with chip-specific FIFO/EDCA/SIFS and C22-only PCI quirk; packet DMA stays closed |
| H2C packet ring and port0 command mailbox | Same retained native owner; bounded exact transport receipts and separate IQK completion |
| Retained complete RTL8822CE factory map | Implemented from same probe EFUSE read; original Linux packed geometry checked |
| Factory-selected inactive BB/AGC/RF tables | Same-owner C21 package/RFE/one-path SIPI and C22 two-path RFK-init/mixed-access ports; separate frozen reference fixtures and composed failure/cancellation/DMA retention regressions |
| C21 measured calibration-only ch1/20 IQK | Exact N21Q identity/current signed authority/policy, source channel/RFE/swing and one-path H2C, fresh RF08/status/thermal receipt, retained command DMA and parked success; the real measured envelope is external and cannot authorize operating RF |
| C21 parked operating-power program | Same-owner post-IQK N21P exact-board/source-recipe qualification, source RFE-selected factory ceilings, explicit measured12-rate indices/peaks and response envelope, fresh thermal/TXAGC/RRSR readbacks implemented; distinct N21S required for awake packets |
| C21 awake radio/packet/port0/station | Exact N21S identity/current triple signed-source authority and live policy, C21 gain/channel/thermal and real wake/CAM receipts, parked same-owner beacon disarm and native Open/WPA2 DHCP/IP composition implemented; measured assets/physical acceptance remain external |
| Current signed per-board gain/operating-envelope qualification | Implemented loader, exact identity/source ceilings, cap revocation and current-policy checks; real measured signed artifact is an external deployment gate |
| Fixed awake ch1 radio/DACK/IQK/OTP/qualified power | Implemented for the explicit version2 CCK/control-response profile; real signed measured envelope remains a deployment gate |
| C21/C22 legacy12 DATA/WMM BE-TID0 | Separate N21L/N22L exact-chip identities/current signed measurements and host-policy gates; bound response rates/parameters, source EDCA/RA/RRSR, each chip's actual gain readbacks, native fixed legacy DATA, raw QoS/CCMP and Open/WPA2 DHCP/IP composition implemented. Base N21S/N22Cv2 alone retain CCK1; full AC/TID scheduling is the separate N2xQ program |
| C21/C22 HT20/one stream/SGI20 | Distinct N21H/N22H static measured contracts/current source gates; source-native absolute/reference-difference MCS gains, typed original offer/request/response, actual RA/TXD/RXD, authenticated whole3839-byte A-MSDU, native ADDBA-decline/CCX and Open/WPA2 DHCP/IP. Real assets/physical acceptance remain external; richer PHY remains work |
| C21/C22 recipient RX BA | Distinct exact-H N21R/N22R contract; actual bound ADDBA success/CCX/idle, explicit SSN, TIDs0..7/window<=64 with A-MSDU permission, source RAW/PHY admission, opaque originals before CCMP/PN, BAR20/DELBA/hole/TU timers and key/publication epochs implemented; native tests passed the coordinated x86_64/aarch64 software suites. Real measured assets/automatic BA/over-air acceptance remain external |
| C21/C22 originator TX BA | Distinct exact-H or R-over-H N21T/N22T contract; bound on-air request/response/current SSN, genuine CCX/RX-idle/MAC-FIFO proof, four independent native DMA originals, source AGGEN/density/MAXAGG and per-MPDU status, current-SSN BAR20/DELBA/key drains implemented; native tests passed the coordinated x86_64/aarch64 software suites. Measured assets/real MAC aggregation and over-air behavior remain external |
| C21/C22 RTS threshold | Separate N21X/N22X over exact current H/R/T; native24Mbps RTS descriptor/control program, actual response-rate admission, drained current-authority setting, CCX/immutable-DMA/FIFO completion and EAPOL exclusion implemented. Twelve native cases pass on both architectures; real measured X assets/RTS-CTS/physical acceptance remain external |
| C21/C22 HT TX coding (LDPC/STBC) | N2xC continuation: base RX STBC1 (+C22 RX LDPC) advertisement, qualified TX LDPC (both) / TX STBC (C22) intersected with the peer, W5 bit7/bits9:8, RA_INFO bit26, revocation downgrade. Real N2xC measurement external |
| C21/C22 all-AC WMM / all-TID QoS | N2xQ continuation: cfg80211_classify8021d + ACM downgrade, BK/VI/VO/BE rings with QSEL=TID, any-TID RX, revocation to BE/TID0. Real N2xQ measurement external |
| Generic continuation contract + dm watchdog | Reusable signed N2x<tag> loader; N2xD rtw_watch_dog_work/rtw_phy_dynamic_mechanism port: DIG/CCK-PD/RA on both chips, path diversity/CFO/thermal power tracking/EDCCA/DPK calibration+tracking on C22; base restore on revocation. Real N2xD measurement external |
| Port0 peer/AID/media/RA/default-port control | Implemented bounded source mailbox, long-slot initial MLME, same-owner station integration and close/cancel behavior |
| Passive/active channel1 scan with probe IEs, authentication/association, WPA2 controlled port | Retained channel1 shared MLME/RSNA/CCMP through actual native DMA and CCX, including held/altered/cancelled M4 and queued peer-loss closure |
| Native management/data TX, RX, completion and ring ownership | Implemented original rings, source descriptors, exact DMA plus CCX security receipt and current-authority publication |
| Device/frame/kernel IP integration | One shell before activation, same Arc lifecycle, bounded synchronous progress; Open/WPA2 real kernel DHCP and exact bidirectional IP pass composed model tests |
| Reset/suspend/removal, retained-map reclamation and multi-device lifetime | Outside the one-shot awake profile; published mappings remain retained |

Per-chip hardware backlog follows original `rtw8821c.c`, `rtw8822b.c` and
`rtw8822c.c` chip-info/ops. C21 is1SS and C22B/C22C are2SS; all declare2.4/5GHz,
HT and VHT. A separately qualified HT20/1SS/SGI20/A-MSDU station subset now has
a complete software path on C21/C22C. Broader HT streams and widths, VHT,
Broader TX aggregation and recipient negotiation, noninitial channels (channel1 active scan is implemented),
RF tracking, coexistence, sleep/WoW and controller-proven reset/rejoin. C22B needs
retained firmware, MAC/PHY/RF/power and packet composition. C21/C22C supply
separate qualified legacy station chains. None of these initial-profile exclusions are hardware
inapplicability claims; no6GHz/HE/EHT capability is declared by these chip-info
records.

The actual reserved-page backend transfers successful firmware ownership into
an explicit continuation state when inactive MAC admission succeeds. Firmware
page reuse is already closed there. C22 radio completion accepts only that
state plus a completed beacon receipt, poisons it before native parking, and
disarms the old beacon descriptors only under parked current device authority.
An unrelated terminal/ambiguous page state cannot enter this path. A native
Rust regression composes the full C22 firmware/MAC/PHY/radio chain through this
actual backend, including park/disarm failures, pending-command cancellation,
one-shot refusal and retained mappings after destruction.

Power-table rows are fixed Rust programming data ported from each Linux
chip's `trans_*` arrays. Native Rust regressions cover all chips, warm/cold boot,
cut-C filtering, bounded polling/retry/failure, unknown cuts and absent hardware.
Frozen firmware reference traces cover81 loader operations. Tests also exercise
header/section bounds, complete reserved-page composition, scripted I/O failures,
stale completion, reuse ordering and terminal cancellation. Native capability
regressions reject revoked authority before CPU/config/MMIO/allocation access.
These are software checks, not silicon acceptance.

MAC regressions compare Rust FIFO/LLT/H2C and chip-specific register behavior
with frozen traces for cut-A/cut-D seeded images, preserving unrelated fields.
They compose firmware-download and MAC ownership, sweep access failures, cancel
LLT waits and reject invalid H2C pointers. PHY regressions retain56 C21 and49
C22 profile digests and source filter snapshots, with same-owner stage faults,
cancellation, replay refusal and invalid factory/path rejection. Table loading
remains distinct from successful calibration or station readiness.

Frozen radio references cover fresh DACK, TRX/channel/trim and IQK-command
writes/delays for zero/nonzero seeded register images and distinct RF paths.
Rust models continue the actual retained firmware/MAC/PHY owners through current
signed qualification into bounded calibration. They cover missing receipts,
pending-command cancellation, restrictive live policy, actual cap revocation,
distinct-path restoration and H2C wrap/foreign-head ownership. Fixed station
mailbox vectors and control regressions cover readiness/consumption, close during
a wait, retained cancelled commands and teardown after close.

The stored reference values are historical Linux-source inputs, not expected
values calculated from the Rust implementation or an executable equivalence
proof. RTW88 requires no Python, C compiler, temporary Rust compilation harness
or external source checkout. The former pipelines were removed; source citations,
recorded hashes, firmware metadata and the native Rust tests remain in
`src/rtw88/REFERENCE_FIXTURES.md` and per-fixture provenance. Updates require
source-contract review and must preserve independent expected values.

Source contracts remain Linux `rtw88/efuse.c`, `mac.c`, `fw.c`, `pci.c`,
`rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}` and the per-chip tables.
`pci.c::rtw_pci_io_mapping` identifies the mandatory BAR2 register aperture.
The public Realtek RTL8822C datasheet remains supporting hardware documentation.

Shell-future regressions additionally cover unpublished activation, cancelled
activation before owner-mutex acquisition, public disconnect reservation before
the mutex, nonblocking drain, cancellation release and terminal cleanup without
owner reconstruction. Their empty lifecycle cannot fabricate a firmware,
calibration or station-ready receipt.

The complete station fixture earns firmware, MAC, PHY, board qualification and
radio receipts on that same lifecycle before Device activation. Its simulated
AP consumes the current real DMA bytes at each doorbell and generates native
RXBD/RXD and identity-matched CCX events. Open and WPA2 run the actual kernel
DHCP client and exchange exact IP payloads through host frame rings and the
registered stack. Negative cases retain M4 DMA across cancellation, alter its
actual receipt bytes, queue peer loss before RX idle, revoke the actual
calibration epoch between descriptor write and doorbell, remove current power
policy and serialize disconnect against synchronous workers. Administrative
IFF_UP remains independent of physical carrier. These are software/model
results; no fixture creates deployable board measurements or physical evidence.

### RTL8822BU: the B22 die over the USB transport (`usb_driver.rs`)

Linux binds RTL8822BU with rtw88 (`rtw8822bu.c::rtw_8822bu_driver`, the
`rtw8822b_hw_spec` B22 die over `usb.c`), not rtl8xxxu. As RTL8821CU is
C21 over USB, RTL8822BU is the retained RTL8822BE B22 runtime above over the
RTL8821CU USB transport; no PCI byte, record or filename changes.

- Registration: `usb::RTL8822BU_IDS` = `rtw_8822bu_id_table` (35 entries,
  table order) registered as `usb_driver::RTW8822BU_USB_IDS` with the vendor
  interface triple 0xff/0xff/0xff ("rtw8822bu",
  `register_class_driver_with_unbind`). The table is disjoint from
  `rtw_8821cu_id_table`; `usb_driver::chip` maps the claimed VID/PID to
  0xc821 or 0xb822 (`id->driver_info`). 0bda:b82c is removed from
  `rtl8xxxu::RTL8XXXU_USB_IDS` (rtl8xxxu's detection-only probe no longer
  claims an RTL8822BU); `rtl8xxxu::regs::REALTEK_USB_IDS` keeps it as an
  identification row only.
- Host identity: `phy8821c::Host` gains `chip`; `Interface::host_of(did)`
  keys B22 records by the claimed VID/PID (header bytes 12..16, the
  `host-usb` identity binding) with the filename family `rtw8822bu`
  (`Host::family`). `calibration8822b::Board`/`Request`,
  `operating8822b::Request`/`Info`/`StationRequest` and
  `station_profile::request_b22` carry that host, and `power_policy` returns
  the `N2BS` grant's host for B22, so every later B22 record (`N2BO`,
  `N2BD`, `N2BW`, `N2BL`, `N2BH`, `N2BB`/`N2BV`, `N2BC`, `N2BF`, `N2BR`/
  `N2BT`, `N2BX`) is `rtw88/rtw8822bu-*` with the USB header. PCI keeps
  `Host::PCI_B22` (10ec:b822, `rtw8822be-*`, no host binding), byte-identical.
- Power: `usb::Registers::for_chip(io, 0xb822)` runs `card_enable_flow_8822b`
  / `card_disable_flow_8822b` filtered to `RTW_PWR_INTF_USB_MSK`
  (`*_8822B_USB`, with the cut-C-only 0x10a8..0x10aa rows and the USB-base
  0xff1a row) and `__rtw_mac_init_system_cfg` with `sys_func_en` 0xdc; the
  rest of `rtw_mac_power_on`/`rtw_power_off` is the C21 USB path.
- EFUSE: `efuse::read_factory8822b_usb` is the asynchronous physical dump +
  logical decode of the PCI B22 map, parsed as `rtw8822bu_efuse_parsing`
  (`Factory8822b::usb_map`, MAC at 0x107 = `rtw8822bu_efuse::mac_addr`);
  `prepare_phy8822b` refuses a factory whose layout does not match the
  lifecycle's host interface.
- Probe tail (`rtw_usb_probe` after `rtw_chip_info_setup`):
  `Registers::phy_cfg(cut)` = `rtw_usb_phy_cfg` HIGH (empty
  `usb2_param_8822b`) then SUPER (`usb3_param_8822b`: PHY offset 0x01 =
  0xa841 for `RTW_INTF_PHY_CUT_D` only, through `rtw_usb_phy_write` 0xff0d/
  0xff0e/0xff0c); `Registers::switch_mode(usb_mode_switch)` =
  `rtw_usb_switch_mode_new` (8822B is `rtw_usb3_chip_new`; the factory
  `usb_mode` bit 7, module parameter default on). When it asks the chip to
  re-enumerate as USB 3 no shell is published (Linux skips
  `rtw_register_hw`) and the new function probes fresh.
- MAC: `mac::prepare_on(0xb822, Hci::Usb { .. })` uses the bulk-out-count
  `rqpn_table_8822b` (row-for-row equal to `rqpn_table_8821c`) and
  `page_table_8822b` (64/64/64/64, 64/64/0/0 for two pipes, 64/64/64/0 for
  three) with the B22 boundary 1996, plus the USB tails already described
  for C21; USB stays refused for C22.
- PHY: the `rtw8822b_table.c` rows are interface-independent:
  `phy/gen_rtl8822b_tables.py` with `cond.intf = INTF_USB` (BIT(1)) emits
  the same 17 frozen tables as `INTF_PCIE`, so `phy8822b::rows` serves both.
- Backend (`usb_firmware::Backend::new_for(0xb822, ..)`): the page row
  check, firmware-page boundary restore (1996), `transmit_quiet` FIFO pages
  and `finish_station8821c`'s gate chip follow the claimed die. The B22
  retune/widening H2C is `command::iqk8821c` at the running sequence, as on
  PCI (`retune_iqk_packet`). `station_b22_iqk` mirrors
  `pci_firmware.rs::station_b22_iqk` over EP0: Begin requires an open,
  non-retuning station with no H2C/mailbox outstanding and a current B22
  gate, writes TXPAUSE 0xff and RXPKT_NUM `BIT_RW_RELEASE`; Quiet is
  `b22_iqk_quiet` (TXPAUSE held, no queued/in-flight/awaiting frame or H2C
  receipt, the `rqpn_table_8822b` map and every `page_table_8822b` page free,
  `BIT_RXDMA_IDLE`); Submit sends the `rtw8822b_do_iqk` H2C on the H2C pipe;
  Finish needs the completed receipt and still-quiet hardware and releases
  RXDMA and TXPAUSE with readback. `dynamic_rx_agg` is
  `rtw_usb_dynamic_rx_agg_v1` (`RTW_CHIP_TYPE_8822B` too). The receive PHY
  status parser is C21's (`packet_phy::Chip::C21`), as on PCI 8822BE.
- Provisioning (`usb_driver::provision8822b`): firmware
  (`rtw88/rtw8822b_fw.bin`), MAC, `prepare_phy8822b`,
  `prepare_calibration8822b` (`N2BQ`), `prepare_operating8822b` (`N2BP`),
  `prepare_station8822b` (`N2BS`), then `Device::activate`; retried as
  `pci.rs::schedule_owner` while the image or a record is missing (B22
  `Calibrated` counts as pending). The shell is published as `rtw8822bu`
  (`interface::publish`), the bound record is `rtw88-8822bu`.
- Recovery/idle/sleep: `Origin` records the die; `usb_recovery` powers the
  card off with the B22 rows and `power_up` re-reads the B22 USB map
  (`Identity` on a MAC change), so reset, rejoin, runtime idle and system
  sleep follow the RTL8821CU USB path unchanged and re-earn every stage
  through the `rtw8822bu-*` records.

Scope equals the RTL8822BE row: LPS and Bluetooth coexistence stay open as
documented for B22 (`ps_page` refuses a non-C21 source). No `rtw8822bu-*`
record is provisioned: an unprovisioned RTL8822BU stops at
`PhyTablesPrepared` and is never admitted (no station, band or TX grant).
Written, unexecuted: `smoke_rtw88_usb_8822bu_id_table_host_and_fifo`,
`smoke_rtw88_usb_8822bu_power_phy_cfg_and_switch`,
`smoke_rtw88_usb_8822bu_backend_mac_efuse_and_iqk`.

### Upstream applicability triage (2026-10-27)

This subsection resolves the former `unknown` inventory rows against Linux
v6.12 `rtw88/{main.c,mac80211.c,tx.c,phy.c,rtw8821c.c,rtw8822b.c,rtw8822c.c}`.
It records applicability only; nothing below is implemented by this change.

Inapplicable on upstream rtw88 (rows removed):

| Former row | Evidence |
|---|---|
| `checksum_offload_applicability` | `main.c::rtw_register_hw` assigns no `hw->netdev_features`; `tx.c::rtw_tx_fill_tx_desc` has no checksum descriptor field. Host checksums remain authoritative. |
| `tso_offload_applicability` | Same: no `NETIF_F_TSO*` and no segmentation descriptor; mac80211 delivers single MSDUs/A-MSDUs. |
| `vlan_offload_applicability` | Same: no VLAN insertion/stripping field or netdev feature. |
| `greenfield_applicability` | `main.c::rtw_init_ht_cap` never sets `IEEE80211_HT_CAP_GRN_FLD` on any chip. |
| `ht_control_scope` (HT +HTC) | `rtw_init_ht_cap` advertises no HT-control capability. VHT +HTC (`IEEE80211_VHT_CAP_HTC_VHT` in `rtw_init_vht_cap`) belongs to the `vht` row. |
| `cts_to_self` | `tx.c` maps only `info->control.use_rts` or `len > rts_threshold` to `W3_USE_RTS`/RTS24M; neither `tx.c` nor `mac80211.c` reads `use_cts_prot` or programs a CTS-to-self descriptor bit. The implemented RTS threshold is the complete upstream protection mechanism. |

Resolved into named feature rows (applicability proven, work remains):

| Former row | Named rows and evidence |
|---|---|
| `additional_ht_widths` | `ht40`: `rtw_init_ht_cap` adds `SUP_WIDTH_20_40`, `DSSSCCK40` and `SGI_40` when EFUSE `hw_cap.bw` has 40MHz (all three chips). VHT80 stays in `vht`. |
| `broader_ba_variants` | `tx_ba_all_tids`: `tx.c::rtw_txq_check_agg` requests originator BA for every non-VO TID (never EAPOL). `tx_amsdu_5ghz`: `TX_AMSDU`/`SUPPORTS_AMSDU_IN_AMPDU` with `rtw_ops_can_aggregate_in_amsdu` declining only on 2.4GHz. Recipient negotiation is mac80211-owned (`RX_START`/`RX_STOP` are driver no-ops) and already covered by the R contract. |
| `dynamic_phy_thermal_scope` | `phy.c::rtw_phy_dynamic_mechanism` runs statistics, `dig_tracking` (all chips), `cck_pd_tracking` (C21/C22C `cck_pd_set`, 2.4GHz only), `ra_tracking` (firmware RA info and RRSR update), `tx_path_diversity` (C22C `path_div_supported`), `cfo_tracking` and `dpk_tracking` (C22C only), `rf_power_tracking` (all chips, existing row) and `edcca_adaptivity` (C22B/C22C `adaptivity`, or firmware `FW_FEATURE_ADAPTIVITY`). |
| `ldpc_applicability` | `ldpc`: `rx_ldpc = true` on 8822B/8822C (false on 8821C) gates HT `LDPC_CODING` and VHT `RXLDPC`; TX sets `W5_DATA_LDPC` from the peer's `si->ldpc_en`. |
| `stbc_applicability` | `stbc`: one-stream RX STBC is advertised on every chip (HT `RX_STBC`=1, VHT `RXSTBC_1`); HT TX STBC only with `tx_stbc` (8822C) and VHT `TXSTBC` when `rf_path_num > 1`; `W5_DATA_STBC` is forced off while `hal.txrx_1ss` (implemented: `Station::hal_profile`, "Coexistence-driven static SMPS"). |
| `smps_scope` | `smps_txrx_1ss`: only 8822C has `config_txrx_mode`; `main.c::rtw_vif_smps_iter` requests static SMPS while coexistence forces 1SS and SMPS off otherwise. No `NL80211_FEATURE_{STATIC,DYNAMIC}_SMPS` is set, so user-driven local SMPS is inapplicable. |

Refined feature rows: `wow` applies to RTL8822CE only (`wow_fw_name`/
`wowlan_stub` exist only in `rtw8822c.c`; 8821C/8822B declare neither).
`ht_protection_modes`: upstream reads no `ht_operation_mode` and takes no
protection action, so the remaining work is admitting APs that advertise
nonzero HT protection in the shared HT JoinPlan instead of refusing them.

### Open rtw88 ledger rows (2026-10-28)

Each row below was checked against the tree after the N2xC/N2xQ/random-MAC
changes. None is a physical blocker unless stated.

| Row | Blocker |
|---|---|
| `additional_operating_channels` | Source candidate (see "C21/C22 noninitial 2.4GHz/20MHz operating channels and retune"): Linux per-channel `rtw8822c_set_channel`/`rtw8821c_set_channel` programs, signed per-channel N2xO records bounded by factory channel-group power, native drain/TXPAUSE retune owner with epoch, multi-channel scan and association/rejoin on admitted primaries 1..=13, per-channel continuation records over the channel-scoped base (`scope_request`), Linux-level C22 IQK completion, and associated CSA/ECSA following mac80211 software CSA (base profile in place; bound continuations disconnect). No N2xO record is provisioned for any board, so hardware stays channel-1 only until measured; release/native and physical acceptance pending. |
| `beamforming` | SU and MU beamformee source-complete on N2xV VHT80 associations (see "VHT SU and MU beamformee"): SU+MU advertisement, MU-preferred `rtw_bf_assoc`, `rtw_bf_phy_init`/`rtw_bf_enable_bfee_su`/`rtw_bf_enable_bfee_mu` with readback, VHT Group ID Management -> `rtw_bf_set_gid_table` while the role is MU, role-matched disassoc cleanup. Dynamic CSI rate (needs dm `min_rssi`, absent on 5GHz) and beamformer roles not ported. Three cases written, unexecuted; physical acceptance pending. |
| `dpk_tracking` | Source-complete for C22 under N22D bit 7 (`dpk.rs`, §3 dm section): `rtw8822c_do_dpk` + `rtw8822c_dpk_track`. Five register-model cases are written, unexecuted; GAPK, a real signed N22D DPK measurement and physical acceptance remain external. |
| `five_ghz_operation` | Source candidate (see "C21/C22 5GHz channel programs"): 5GHz `set_channel` BB/RF/MAC branches, 5GHz power groups, per-channel N2xO admission, scan/retune/join/CSA and DFS passive handling, band advertisement plus 5GHz HT/VHT wiphy capabilities of the admitted station offer. No 5GHz N2xO record is provisioned for any board; release/native and physical acceptance pending. |
| `ht40` | Source candidate (see "C21/C22 2.4GHz HT40" and its 5GHz `KIND5` variant): N2xB-bound 2.4/5GHz BW40 `set_channel` programs, retune before authentication, HT40 offer and RA/descriptor width. No N2xB record is provisioned; release/native and physical acceptance pending. |
| `multi_stream_ht` | Source-complete for actual2T2R RTL8822CE under separate N22H256v2: cumulative per-path factory ceilings, measured combined-chain envelope, native quiet/parked two-path gains/readbacks, original local RX16/peer TX negotiation and actual RA/TXWD/RXD MCS8..15. C21 is1TX-path hardware. Five native cases are written; release/native and physical acceptance remain pending. |
| `operating_reset` | Source-complete for retained C21/C22 under original BDF/cap: old endpoint/callback/native DMA retirement produces a one-use power-reset precondition; forced source card-disable/enable and CR readbacks precede physical factory identity and fresh firmware shell/provisioning. Cancellation/hot removal quarantine the reservation; old cookies/keys/cleanup cannot alias the replacement. Six source cases are written; release/native and physical acceptance remain pending. |
| `radio_coexistence` | Source-complete under separate N2xK (see "C21/C22 Bluetooth coexistence state machine"): `coex.c` init/notify/BT-info/run_coex/actions/works with per-chip tables and hooks, efuse-qualified modes, full backup/restore. Five register-model cases written, unexecuted; no signed N2xK record or BT-active physical pass. |
| `rf_power_tracking` | Source-complete for admitted C21 type0 RF-A HT20 under distinct N21W: real meter/AGC/txscale/associated IQK, exact H/R/T2/RTS plus C/Q/F/D current source composition, all-rate factory limits and actual native quiet/terminal/restore. Power-only restore retains keys/BA; after periodic IQK source loss requires a fresh owner. Eight native cases are written; release/native and physical acceptance remain pending. C22 retains N22D. HT40 variant: the same N21W program over the bound N2xB record's one-stream MCS0..7 at BW40, with the N2xB-bound request identity and its own `-ht40` filename; one index-selection case written, unexecuted. |
| `rtl8822be` | Station core source-complete, pending validation (unexecuted tests, no hardware run, no board asset provisioned): the retained native B22 owner (identity, factory map, authenticated `rtw8822b_fw.bin`, `rtw8822b_mac_init`, the complete `rtw8822b_phy_set_param`, `rtw8822b_set_channel`), the signed `N2BQ` calibration IQK, `N2BP` operating power and `N2BS` awake-station grant ("RTL8822BE retained native B22 owner" ... "parked operating power"), per-channel `N2BO` 2.4/5GHz records and retune (refused over any bound extension), the `N2BD` dm watchdog (DIG/RA/PWR_TRACK/EDCCA) with `N2BW` associated re-IQK, `N2BL` legacy12/WMM, `N2BH` HT20 1SS/2SS, `N2BB` HT40 and `N2BV` VHT80 widening via `rtw8822b_set_channel` at 40/80, `N2BC` LDPC-only TX coding, `N2BQ` all-AC QoS, `N2BF` fallback, `N2BR`/`N2BT` recipient/originator BA and `N2BX` RTS (see the "RTL8822BE ..." sections of §3 from "RTL8822BE per-channel operating records" to "recipient/originator BA"). LPS and Bluetooth coexistence are separate C22 feature rows and stay open for B22 ("RTL8822BE documented gaps: LPS and Bluetooth coexistence"). Unprovisioned boards stay unadmitted. |
| `runtime_sleep` | Source candidate: explicit unassociated IPS through `idle_function`, retained original callback/DMA/card-off/fresh-start workers; associated nondeep legacy CCK1 LPS through `lps_function` with distinct N2xZ program, real retained reserved-page DMA, original UP/peer/key epoch, fresh RFON plus actual TCR wake, PS-only HMEBOX_EXT/low-word publication fence and private CCMP RX. Production trigger: `set_power_save` (`SUPPORTS_PS` only with a composed LPS owner) arms a 2s watchdog LPS window below `RTW_LPS_THRESHOLD`, with coex LPS/IPS notifications; IPS (`idle_function`) still has no production trigger. Three IPS, eight LPS and one interface case are written/unexecuted. Full review/release/native and physical acceptance are pending; do not remove this row until integration review accepts the whole candidate. |
| `safe_rejoin` | Source-complete explicit C21/C22 channel1 Open/WPA2 rejoin: confirmed original reset/DMA retirement, exact name/ifindex/admin rebind, fresh provisioning/BSS scan/key exchange and original new-UP native publication lifetime. Original cookies/keys/replies never revive, failed/cancelled M4 stays closed, caller credentials zeroize. Four native cases are written; release/native and physical acceptance remain pending. |
| `smps_txrx_1ss` | Source-complete for C22 under N22K `MIMO_PS` (see "Coexistence-driven static SMPS"): `rtw_coex_mimo_ps` -> `config_trx_mode(A, A)` with exact field restore, dm path diversity held on A, 1SS RA mask / STBC off, SM Power Save static/disabled action. Three register-model cases written, unexecuted; no signed N22K MIMO_PS record or BT-active measurement. |
| `system_suspend` | Source-complete for actual C21/C22 identity-DMA PCI-PM D0 profiles: retained uncancelled native retirement/card-off/D3hot receipts, original-source C22 RFE6 DBI pad, D0/config restoration and fresh cold provisioning on the original netdev. Foreground cancellation rolls workers back; old keys/cookies never revive and fresh association stays explicit. Six native cases are written; release/native and physical S3 acceptance remain pending. |
| `tx_amsdu_5ghz` | Source-complete on 5GHz HT/VHT associations (see "5GHz TX A-MSDU and A-MSDU in A-MPDU"): gated producer, peer/allocation/RA-report size bound, CCMP over the aggregate, ADDBA A-MSDU request bit and NO_AMSDU. Four cases written, unexecuted; physical acceptance pending. |
| `tx_ba_all_tids` | Source-complete for admitted C21/C22 TIDs0..5 with distinct full-program N2xT v2, actual independent peer/SSN/dialog/key ownership and physical BE/BK/VI burst/CCX/prefix publication. v1 remains BE/TID0; Linux excludes VO/EAPOL. Sixteen native cases are written; release/native and physical acceptance remain pending. |
| `vht` | Source candidate (see "5GHz VHT80 (`N2xV`, `vht.rs`)"): N2xV-bound BW80 program and `LocalPhy::vht80` join offer; the wiphy reports the same VHT body (`vht_supported`) once an admitted 5GHz join can offer it. No N2xV record is provisioned; release/native and physical acceptance pending. |
| `wow` | Source layer only (see "RTL8822CE Wake-on-WLAN source layer"): authenticated `wow_fw_name` load, `rtw_wow_swap_fw` download hook, full `wow.c` suspend/resume sequence, pattern CAM, WoW H2Cs and wake-reason decode with five unexecuted fixture cases. WPA2 AOAC security-CAM PTK/GTK install + software-CCMP restore (`security_cam.rs`). Native `wow::Io` over the reserved-page swap window and reversible host-DMA halt; `set_wowlan`/`wowlan_config`/`wowlan_support` advertised for C22; `system_pm_native` WoW branch (D3hot without card-off, cold fallback on any failure; RFE6 stays cold). Unexecuted fixtures; no physical board run. |
