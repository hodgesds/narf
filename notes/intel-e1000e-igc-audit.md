# Intel e1000e + igc — laptop / dock audit (Stage 1)

Date: 2026-05-25. Companion to `drivers/net/src/{e1000,igc}.rs`.
Stage-1: match-table extension; quirks + EEE deferred.

## A. Match-table coverage

`e1000.rs` `SUPPORTED_DEVICE_IDS` (74 IDs) mirrors Linux's
`e1000e_pci_tbl[]` (`e1000e/netdev.c`): LPT (Haswell I217/I218),
SPT (Skylake I219_LM..V5), CNP/CMP (Coffee/Cannon/Comet Lake
LM6..V12), ICP (Ice Lake LM8/V9), TGP (Tiger Lake LM13..V15),
ADP/RPL (Alder/Raptor LM16..V23), MTP/LNP/ARL/PTP/NVL (Meteor/
Lunar/Arrow/Panther/Nova LM18..V29). Phoenix HawkPoint1 PCH = MTP
→ `E1000E_DEV_I219LM18` (0x550A) is the bring-up-laptop binding.

`igc.rs` `SUPPORTED_DEVICE_IDS` (16 IDs) mirrors `igc_pci_tbl[]`:
I225 LM/V/IT/I/K/K2/LMVP + I220-V + BLANK_NVM; I226 LM/V/IT/K/
LMVP + BLANK_NVM + I221-V.

Both `register_pci_driver()` loops + their smokes walk the same
list — table and test can't drift.

I210/I211/82576/I350 (Linux `igb`) are in e1000.rs so the bus
probe still binds; full bring-up wants advanced descriptors.
Stage-2: split into `igb.rs`.

## B. PHY/MAC quirks — deferred

I219 needs MEI-driven PHY release before PHY ops where the Intel
ME owns it. Linux reads `FWSM` (0x5B54) bit 15
(`E1000_ICH_FWSM_FW_VALID`); if set, ask ME via the H2ME mailbox
to drop PHY. Stage-2: gate PHY register access on FWSM; MAC reset
is OK without the dance.

## C. PCI BAR + MSI-X

BAR0 (MMIO) mapped in both. BAR4 (flash) not mapped — we trust
EFI/option-ROM-programmed RAL/RAH. Modern I219/I225/I226 only need
BAR0 — fine.

MSI-X: e1000.rs uses `enable_msix` (one vector, INTx fallback);
igc.rs is polled-only. Stage-2: lift e1000.rs's MSI-X path.

## D. RX ring

e1000.rs: real ring (8 desc × 2 KiB, RDH/RDT, DD-driven `rx_recv`,
`rx_pump_step` hook). Layout matches 8254x SDM §3.2 legacy
descriptor byte-for-byte (16 B).

igc.rs: real ring (8 × 2 KiB) using **legacy** descriptors. Linux's
`union igc_adv_rx_desc` differs on write-back. Basic bring-up
works; RSS/VLAN need advanced format. Stage-2: switch.

## E. EEE — deferred

Neither driver disables EEE during link bring-up. Linux's
`e1000_set_eee_pchlan` clears `EEE_LP_ABILITY` before `CTRL.SLU`
on PCH parts to avoid an I218/I219 hang when a dock partner pushes
aggressive EEE mid-reset. Stage-2: write 0 to `EEE_LP_ABILITY`
(PHY page 0xA) + clear bit 14 of `IPCNFG` (0x00E38) before SLU.

## Stage-2 follow-ups

1. MEI/`FWSM` gating for PHY ownership (I218+).
2. EEE disable-during-bring-up for I218+.
3. Advanced-descriptor RX path for igc.rs.
4. MSI-X for igc.rs.
5. Real `igb.rs` for I210/I211/82576/I350.
6. ULP wake sequencing on I219+ for S0ix.

## Verification

QEMU TCG `-device e1000` → 0x8086:0x100E. Still in
`SUPPORTED_DEVICE_IDS`; existing smokes continue to bind it.
Match tables grew 5 → 74 (e1000) and 6 → 16 (igc) without
disturbing the QEMU path.
