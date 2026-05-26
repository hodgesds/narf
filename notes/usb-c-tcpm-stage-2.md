# USB-C TCPM Stage 2 — Swaps + PPS + BIST

Builds on the Stage-1 source state machine
(`drivers/usbpd/src/tcpm.rs::SourcePort`). All Stage-2 work lives on
the source side; sink-side swap initiation lands in Stage 3.

## What landed

- **Message types** (`usbpd/src/message.rs`):
  - `CtrlMsg::DrSwap` (0x09), `PrSwap` (0x0A), `VconnSwap` (0x0B)
    per PD 3.1 §6.3 table 6-5.
  - `DataMsg::Bist` is in `from_u8` now.
  - `ProgrammableRdo` (§6.4.2.5): 20 mV / 50 mA step PPS RDO.
  - `BistMode` + `BistDataObject` (§6.4.3.1).

- **Policy** (`drivers/usbpd/src/policy.rs`):
  - `SinkPolicy::prefer_pps` + `pps_voltage_mv`. When set,
    `evaluate()` picks an APDO bracketing the requested voltage and
    quantises to 20 mV; falls back to Fixed if no APDO fits.
  - `SinkSelection::is_pps` + `to_programmable_rdo()`.
  - `SourcePolicy::evaluate_programmable_request()` — Accept if
    voltage in `[min..=max]` and current ≤ max.
  - `accept_{pr,dr,vconn}_swap` flags on both policies, defaulting
    `false`.

- **TCPM** (`drivers/usbpd/src/tcpm.rs`):
  - `SourceState` extended with twelve new states: the
    initiator/responder/VConn-supplier/VConn-consumer arms of the
    three swap protocols, plus `BistCarrierMode`.
  - `SourcePort::is_dfp` / `is_vconn_supplier` atomics — flipped on
    every successful DR_Swap / VConn_Swap.
  - `initiate_pr_swap` / `initiate_dr_swap` / `initiate_vconn_swap`
    — only legal from `SRC_READY`.
  - `step_ready_or_handle_inbound()` drains one inbound message per
    step from Ready: PR/DR/VConn_Swap → swap handlers, BIST →
    `BistCarrierMode`, Soft_Reset → re-Startup.
  - Negotiate-capability inspects the targeted PDO; Augmented uses
    `ProgrammableRdo` + PPS policy. `TransitionSupply` builds the
    contract from the PPS-requested voltage when applicable.
  - `PortStepOutcome` extended with `RoleSwapped(PortState)`,
    `DataRoleSwapped { now_dfp }`, `VconnSwapped { now_supplying }`.
    The async TCPM task logs each transition and clears the
    "contract announced" latch when power role flips.

## Smokes

- **policy** — 11 new (PPS pick / quantise / fall-through;
  Programmable RDO encode round-trip; Accept/Reject programmable;
  swap-knob defaults off).
- **tcpm** — 11 new (PR_Swap initiate accept/reject + inbound
  accept/reject + block outside Ready; DR_Swap initiate / inbound
  accept / inbound reject default; VConn_Swap supplier release +
  inbound reject default; PPS Accept and Reject paths; BIST entry
  parks and TcpmPort relay).

Baseline: 2451 → 2569 pass / 0 fail / 49 skip.

## Deferred (Stage 3+)

- Sink-side swap initiation.
- Vbus rail control through `Tcpc`.
- USB PD Firmware Update Extended Header.
- BIST emission generation (chip-level today).
