# iwlwifi Stage-2 — CSR map, PRPH wrapper, APM init, ucode header

**Files:**
- `drivers/net/src/iwlwifi.rs` — module entry + probe + log.
- `drivers/net/src/iwlwifi/csr.rs` — CSR offsets + bit defines.
- `drivers/net/src/iwlwifi/prph.rs` — PRPH indirect-access wrapper.
- `drivers/net/src/iwlwifi/apm.rs` — sw_reset + apm_init + activate_nic.
- `drivers/net/src/iwlwifi/ucode.rs` — TLV ucode header decode.
- `drivers/net/src/iwlwifi/tests.rs` — smokes.

**Upstream provenance** (all GPL-2.0 OR BSD-3-Clause):
- `iwl-csr.h` — every CSR + HBUS offset, RESET / GP_CNTRL / INT bits.
- `iwl-prph.h` — APMG sub-block layout.
- `pcie/gen1_2/trans.c` — `iwl_pcie_apm_init`, `iwl_trans_pcie_sw_reset`, `iwl_trans_pcie_{read,write}_prph`, `iwl_pcie_gen1_2_activate_nic`.
- `fw/file.h` — `iwl_tlv_ucode_header`, `enum iwl_ucode_tlv_type`.

**What probe does now:**
1. Enable Memory + Bus Master + INTx-disable in PCI config space.
2. `map_bar(0)` to get a `MmioRegion` over BAR0.
3. Read `CSR_HW_REV` (0x028).
4. If reads as `0xFFFFFFFF` → "not-present" log + `record_bound`.
5. Otherwise log `"iwlwifi: detected $name rev=$hw_rev (type=$type step+dash=$step) family=Family{1,2} BAR0=$phys+$len"` and `record_bound`.

**What probe does NOT do** (Stage 3):
- Doesn't call `apm::sw_reset` or `apm::apm_init` yet — the BAR mapping path proves the data plane works, but actually waking the NIC is gated on having a firmware load to follow it.
- Doesn't DMA-upload ucode sections.
- Doesn't wait on the alive notification.

**DeviceFamily classification:**
- Family1: AX200 / AX201 (`0x02F0`, `0x4DF0`) — 20-bit PRPH window, APMG present.
- Family2: AX210 (`0x2725`, `0x7AF0`) / AX211 (`0x51F0`, `0x51F1`, `0x7E40`) / AX411 (`0x54F0`) / Killer 1690 (`0x5417`) — 24-bit PRPH, no APMG.

**Smokes added (8 new):** PCI table (expanded), CSR offsets vs Linux byte values, CSR bit positions (SW_RESET, INIT_DONE, MAC_CLOCK_READY, INI_SET_MASK), HW_REV decode round-trip, PRPH pack-addr for both masks, APMG offsets, APM timeout constants, APM family default, device-family classification, ucode magic constant + truncation + bad-magic + header-decode round-trip + metadata vs section.

**Stage 3 plan:** Run apm sequence from probe → call `narf_firmware::request_firmware("iwlwifi-${name}.ucode")` → walk sections via `ucode::parse_header` → DMA-upload to device SRAM via the FH service channel → poll for alive interrupt at `CSR_INT` bit 0.
