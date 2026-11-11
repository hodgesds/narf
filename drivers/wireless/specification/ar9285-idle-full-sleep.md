# AR9285 D0 idle FULL_SLEEP

The admitted source implementation is unvalidated. This document specifies the
family §3.11 controller interface; it supplies no physical acceptance evidence
or measurement asset.

The family controller exposes `set_idle_full_sleep(bool)`,
`idle_full_sleep_status()` and `acquire_idle_wake()`. Desired idle is distinct
from `WirelessNetIface::set_power_save`, operator IFF_UP/DOWN, and system S3.
The present baseline accepts idle only on a current published Passive station
with no peer, join/security continuation, software/native original or control,
or undrained host input. A live association, pending control, unavailable lock,
partial calibration, old physical generation or quarantined DMA returns an
error before an idle transition. Other callers must explicitly complete their
normal work before requesting idle; a passive BSS cache is not a quiet receipt.

Each native station generation retains a counted controller guard for its full
native lifetime. Initialize, reset and accepted queued channel work retain
additional guards. An independently acquired guard also pins the original
controller against idle FULL_SLEEP. The counter is nonwrapping; a zero count
alone grants no IO, key, policy, source or DMA authority. Qualified S1 station
NETWORK_SLEEP is separate and remains available under an idle wake guard.

A driver-owned continuation captures the original controller Arc and physical
generation. It holds whole-controller serialization, withdraws the exact
interface/name, closes copied RX and software IPC, and retires the same Radio
and Packet. Only actual all-ten-QCU/RX/IRQ/BME-off terminal proof releases the
station guard and DMA storage. The completed retained RX tail is not pending
work and stays mapped until that terminal proof. Missing proof pins the original
owner, mappings and guard and forbids clock-off or successor publication.

After terminal retirement the continuation owns Linux's100ms idle delay.
Dropping a public waiter cannot drop the native continuation. Leaving-idle
requests cancel the delay and wake that original worker, including after the old
station was already retired. Different-generation waiters cannot retarget it.
An idle reversal cannot reconstruct old packet/key/capture state.

D0 FULL_SLEEP uses the original exclusive device capability at every PCI/MMIO
access. Before clock-off it rechecks BMEoff, RXE0, allQCU pending0, IER0,
async/syncIRQ delivery0, RXfilter0, RXabort/disable and actual RXstate0 with
RTC_ON2. It applies STA_ID1.PWR_SAV, clears FORCE_WAKE.EN, holds AHB|HOSTIF
reset, asserts active-low RTC_RESET and observes actual RTC_SHUTDOWN1. A request
bit, RTC0, NETWORK_SLEEP4, ignored write or missing source is no sleep receipt.
The PCI function stays in D0. System suspend's reset/paired PCIeD3 workaround
helper is deliberately separate, as in Linux idle and pci_suspend callers.

Leaving idle takes a fresh actual20 cold-generation path at the retained
primary. Full power-on reset, exact identity/raw factory-image comparison,
INI/PLL/RF/current host and factory plan, analog calibration, complete MAC/key
cache preparation and Native report/readback all precede publication. The
physical generation increments without wrapping. Association, keys, replay/PN,
BA, copied frames, software IPC and netdev name from the old generation do not
cross this boundary. A failed or revoked wake leaves the owner closed; it never
relabels an old H/H3/P/S receipt as a new calibration.

Original H1/H2/H3/B/T/Q/S/P recipes are unchanged. The idle transition emits no
RF and occurs only after every native P/S/packet owner is terminal. Wake
emission still requires the same current native calibration, factory plan and
external measured program qualification as an ordinary fresh generation. No new
board measurements, fake calibration result or broad wake/quiet receipt is
introduced. P1's live always-awake invariant and S1's actual-bound/current IER
exception remain mandatory until their complete owner is retired.

`Operational` means the controller is not intentionally parked. It includes
initial provisioning before a station is published and can include qualified S1
doze; it does not claim completed calibration, association or current IO authority. `Asleep` is returned only after completed physical idle
FULL_SLEEP. `Quiescing`, `Armed`, `Waking`, `Blocked`, `Failed`, `Removed` and
count distinguish in-flight/lost ownership. The status getter does no sleeping
MMIO and grants no current access. A public wake-use return additionally requires
a Running packet and the existing actual source/PCI/awake packet fence; a cached count is insufficient.
System suspend atomically refuses outstanding extra users, fences new users,
then applies its existing terminal/S3 path. Resume uses the same fresh actual20
cold wake. Remove permanently closes the old idle owner before waiting for the
same whole-controller lock. The terminal rejoin supervisor never resurrects an
intentionally parked or failed idle owner.

Pinned Linux7.2 call chain: `main.c::ath9k_config(CONF_CHANGE_IDLE)` →
`ath9k_ps_wakeup/restore` count and100ms timer → `ath_ps_full_sleep` →
`ath9k_hw_setrxabort` + `ath9k_hw_stopdmarecv` →
`hw.c::ath9k_set_power_sleep`; leaving idle invokes
`ath_chanctx_set_channel` reset because FULL_SLEEP loses register state.
`reg.h` defines RTC_SHUTDOWN1, RTC_ON2, RTC_SLEEP4 and IER0x24 (RXCFG0x34).


Seven native cases are written in `idle/tests.rs`. They compose the same
counted admission, terminal `retire_station`, cancellable armed timer and actual
FULL_SLEEP helper with real Device/Radio/Packet, mapped native descriptors,
reactive Open/WPA2 peers and kernel DHCP. They cover counted control refusal,
retained RX-tail ownership, actual SHUTDOWN/order/readbacks, busy association,
cancelled delay, cold generation on the same netdev, all-ten-QCU/RX quarantine,
revocation/removal/system-PM fences and actual full40 above/below to fresh
primary20. They run the same complete identity/EEPROM/PHY/calibration/MAC
primitives for model cold wakes. The singleton native PCI controller itself is
not instantiated by these model fixtures; its original-controller/generation/
CONTROL orchestration also requires source review and later physical testing.
No new cases, release builds or hardware tests have run for this feature.

The admitted baseline deliberately refuses idle while associated or while
calibration/control work is partial. It does not advertise deep sleep while a
live AP/key/BA context survives, does not preserve an old netdev on wake, and
does not infer a firmware or board-specific retention scheme. PCI runtime D3,
platform wake routing, S3 and unadvertised chips retain their separate owners.
