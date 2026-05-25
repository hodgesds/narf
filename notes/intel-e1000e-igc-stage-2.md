# Intel e1000e + igc — Stage 2 follow-ups

Date: 2026-05-25. Companion to `drivers/net/src/{e1000,igc}.rs`.
Stage-1 audit in `notes/intel-e1000e-igc-audit.md`.

## What landed

### 1. MEI/FWSM PHY-ownership handshake (e1000e)

I217 / I218 / I219 share the integrated PHY with the Intel ME. PHY
register reads return garbage if the ME is mid-reconfiguration.
Mirrors `e1000_get_swflag_ich8lan` (`e1000e/ich8lan.c`).

- FWSM (0x05B54) bit 15 = `FW_VALID` — is the ME alive?
- EXTCNF_CTRL (0x00F00) bit 5 = `SW_FLAG` — claim/release.
- `is_pch_part(did)` discriminator gates the whole dance.
- On QEMU (no ME, FWSM = 0) the handshake is a fast no-op.

Held across the whole bring-up since we don't touch MDIC yet —
Linux scopes per access. Re-scope when MDIC lands.

### 2. EEE disable during bring-up (e1000e)

PCH parts wedge if a dock partner pushes aggressive EEE during the
post-reset → pre-link-up window. Mirror `e1000_set_eee_pchlan`:
clear IPCNFG (0x0E38) bits 14 / 12 (EEE_1G_AN / EEE_100M_AN) and
EEER (0x0E30) bits 16..18 (LPI_*) before CTRL.SLU.

### 3. Single-vector MSI-X (igc)

igc was polled-only. Lift the e1000.rs MSI-X scaffold: one IDT
vector for all causes, mirrors `igc_request_irq`'s fallback. GPIE
(0x01514) + IVAR_MISC (0x01740) wired for the single-vector cause
encoding; IMS programmed with the standard RX/TX/LSC mask. No
INTx fallback (modern Linux doesn't either).

### 4. Advanced RX descriptors (igc)

Switch from legacy 16-byte RX to `union igc_adv_rx_desc`. Same
slot size; chip selects interpretation via SRRCTL.DESCTYPE
(0x0C00C, ADV_ONEBUF = 1 << 25). Read form: `pkt_addr` + `hdr_addr`.
WB form: `lower` u64 + `status_error` u32 + `length` u16 + `vlan`
u16. DD bit at `status_error & 1`.

## Still deferred

1. ULP wake on S0ix (out of scope).
2. Per-queue MSI-X (Stage-3 — separate RX/TX vectors).
3. MDIC-driven PHY-page LP-ability writes — needs MDIC bring-up.
4. Real `igb.rs` for I210/I211/82576/I350 (Stage-1 carry).
5. RSS / VLAN / extended-status decode now that wb-form is in.

## Validation

- `cargo build --workspace --bins` — clean.
- `cargo xtask run --arch=x86_64 --display none` (30 s) — QEMU
  82540EM still binds polled-only (no ME, no MSI-X).
- `cargo xtask test --arch=x86_64` (180 s) — 2388 pass / 2 fail /
  49 skip. Both fails are the pre-existing virtio-blk-pci_irq_async
  baseline; no new regressions. 5 new smokes:

  - `smoke_e1000_is_pch_part_discriminator`
  - `smoke_e1000_qemu_fwsm_dance_is_noop`
  - `smoke_e1000_eee_disable_constants_match_linux`
  - `smoke_igc_msix_constants_match_linux`
  - `smoke_igc_advanced_rx_descriptor_layout`
