# DP Alt Mode Stage 1 — wire DisplayPort Alt Mode → iGPU

Stage 0 handled the VESA DP-Alt VDM handshake and logged
`GPU-side display-pipe wiring deferred` on success. Stage 1 closes
the loop: when DP-Alt reaches Active, the iGPU is told a DP link is
live on connector N with K lanes, and the modeset orchestrator runs
against that DDI.

## Surface

`drivers/usbpd/src/dp_gpu_bridge.rs` — cross-driver seam:
- `ConnectorId(u32)` — per-port USB-C id, assigned at TCPC probe.
- `DpLinkConfig::from_vdo` derives `lanes` from `DpPinAssignment`
  per VESA DP Alt 2.0 §6 (A/C/E → 4 lanes, B/D/F → 2+2).
- `trait DpAltModeGpuBridge { name; enter_dp_mode(cfg); }`.
- `register_bridge` + `notify_dp_entered` — registry + dispatch.
  First bridge to claim wins; others see `NoSuchConnector`.

`drivers/usbpd/src/altmode_dp.rs` — `DpAltModePort::new` takes a
`ConnectorId`. On Active, `dispatch_to_gpu_bridge` replaces the
old log; logs which bridge claimed (or none).

`drivers/gpu/src/intel_gpu_dp_bridge.rs` — Intel impl:
- `connector_to_ddi` maps TC1..5 → `Ddi::D..H` per TGL/ADL PRM Vol 12.
- `enter_dp_mode` resolves DDI, pulls live `IntelGpu` via
  `with_controller`, runs `IntelAux::new`, hands off to
  `Modeset::modeset`. Stage-2 modeset TODOs surface as
  `ModesetError` → `DpBridgeError::ModesetFailed`; DDI captured,
  engine not lit.
- Registered via `Stage::Late` initcall `intel-gpu-dp-bridge`.

## Out of scope

- **amdgpu bridge** — no DDI exposed yet; registry is multi-tenant,
  drops in later.
- **EDID parse** — AUX runs, 128-byte block not yet decoded to
  `Mode`; the modeset orchestrator's own Stage-2 path covers it.
- **HPD-IRQ re-dispatch** — only first entry fires; cable yank
  skips re-dispatch until flag resets (Stage-2 work).

## Smokes

- `drivers/usbpd/dp-gpu-bridge` — 6 smokes: lane derivation, MF pin
  classification, garbage-bitmap fallback, dispatch routing,
  same-name re-registration.
- `drivers/gpu/intel_gpu_dp_bridge` — 4 smokes: connector → DDI map
  and unprobed/out-of-range fall-through.

## QEMU

QEMU TCG has neither FUSB302/TPS65987 nor an Intel iGPU; new code
is dormant. Real-HW (Zen2 / Phoenix) exercises the path.
