//! Intel iwlwifi PCIe — Wi-Fi 6 / 6E / 7 chips.
//!
//! Targets:
//!   - AX200  (8086:2723)  — Cyclone Peak, Qu/QuZ MAC + HR RF
//!   - AX201  (8086:02f0/06f0/34f0/3df0/4df0/43f0/a0f0/7df0) — same as AX200, different SKU
//!   - AX210  (8086:2725)  — Typhoon Peak, Ty MAC + GF RF (gen3)
//!   - AX211  (8086:51f0/54f0/7e40) — So/Ma MAC + GF/GF4 RF (gen3)
//!   - BE200  (8086:272b)  — Bz MAC + GF/GF4/FM RF (gen3, Wi-Fi 7)
//!
//! AX210+ RFH receive rings, TFH commands/data, owned boot context,
//! firmware API negotiation, and an MLD station control/data path are
//! implemented in `runtime`, `device`, and `connection`. The current MLD
//! command profile targets Sc/BE211 firmware. Unsupported command
//! versions fail startup explicitly. Gen2 has a retained API77 context-v1
//! boot owner with RFH/TFH commands and NVM initialization. The separate
//! `mvm_device` publishes its retained legacy20 Open/WPA2 station worker only
//! after exact discovered firmware selection and native initialization; actual
//! signed platform power is required before station transmit. It supports
//! passive scans, native MLME/keys/data and receipt-fenced local retirement.
//!
//! The station path supports 2.4/5 GHz legacy-rate Open or WPA2-PSK/CCMP
//! networks. Firmware supplies channel/antenna data and enforces its
//! regulatory profile alongside the host's configured regulatory domain.
//! Hardware validation and the userspace wireless control daemon remain
//! separate from the in-kernel transport and WirelessNetIface contract.
//!

//! ## References
//!
//! Post-2026-05-20 GPL relicense permits direct citation:
//! - `drivers/net/wireless/intel/iwlwifi/fw/file.h` — TLV layout,
//!   magic constant, tag enumeration.
//! - `drivers/net/wireless/intel/iwlwifi/fw/img.h` — fw_desc,
//!   paging constants, SEC_RT/SEC_INIT semantics.
//! - `drivers/net/wireless/intel/iwlwifi/iwl-drv.c` —
//!   `iwl_request_firmware` filename ladder, TLV walker.
//! - `drivers/net/wireless/intel/iwlwifi/cfg/22000.c`, `ax210.c`,
//!   `bz.c`, `rf-{hr,gf,fm}.c` — per-chip config tables.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c` —
//!   gen2 PCIe transport (load_given_ucode_8000).
//! - `drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-v2.c` —
//!   gen3 IML / context-info loader.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub mod aggregation;
#[cfg(feature = "builtin")]
mod ap_gen2_wire;
#[cfg(feature = "builtin")]
mod ap_host;
#[cfg(feature = "builtin")]
mod ap_owner;
mod ap_power_limit;
#[cfg(feature = "builtin")]
mod ap_session;
#[cfg(feature = "builtin")]
mod ap_wire;
pub mod bcast;
pub mod boot_context;
#[cfg(feature = "builtin")]
mod bootstrap;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_ap_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_ba_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_client_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_go_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_ht20_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_nested_ba_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_p2p_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_scan_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_shared_memory_configuration;
#[cfg(feature = "builtin")]
pub use bootstrap::gen2_transmit_power_request;
#[cfg(feature = "builtin")]
pub use bootstrap::{provision, provision_state, ProvisionState};
pub use mvm_boot::PowerRequest as Gen2TransmitPowerRequest;
mod gen2_smem;
pub use gen2_smem::SharedMemory as Gen2SharedMemory;
#[cfg(any(test, feature = "kernel-test"))]
mod bz_fixture;
mod bz_profile;
pub mod connection;
mod context_v1;
pub mod csum;
pub mod data_queue;
#[cfg(feature = "builtin")]
pub mod device;
pub mod firmware_api;
mod firmware_identity;
#[cfg(any(test, feature = "kernel-test"))]
mod firmware_parser_tests;
pub mod frame_api;
pub mod fw_loader;
mod gen2_prepare;
mod gen2_profile;
#[cfg(any(test, feature = "kernel-test"))]
mod gen3_fixture;
mod gen3_profile;
mod gen3_wire;
pub mod handshake;
pub mod ht_vht;
pub mod iwl_msix;
pub mod mac_ctx;
#[cfg(feature = "builtin")]
mod mld_platform;
mod mld_policy;
#[cfg(feature = "builtin")]
mod mld_power;
mod mld_regulatory;
mod mld_start;
pub mod mlme;
mod mvm_boot;
mod mvm_d3;
#[cfg(feature = "builtin")]
mod mvm_device;
mod mvm_publication;
mod native_band;
#[cfg(feature = "builtin")]
mod p2p_client;
#[cfg(feature = "kernel-test")]
mod p2p_client_fixture;
#[cfg(feature = "builtin")]
mod p2p_client_request;
#[cfg(feature = "builtin")]
mod p2p_client_rx;
mod p2p_gen2_wire;
#[cfg(feature = "builtin")]
mod p2p_go;
#[cfg(feature = "kernel-test")]
mod p2p_go_fixture;
mod p2p_go_key;
#[cfg(feature = "builtin")]
mod p2p_host;
#[cfg(feature = "builtin")]
mod p2p_owner;
mod p2p_wire;
pub mod pnvm;
mod progress;
pub mod qos;
pub mod rates;
mod reg_source;
pub mod regs;
pub mod rekey;
pub mod runtime;
pub mod rx;
mod rx_multi;
pub mod rx_rfh;
mod sc_eht;
mod sc_emlsr;
mod sc_he;
mod sc_mlo;
mod sc_mlo_assoc;
pub use sc_mlo_assoc::MldLinkCandidate;
mod sc_security;
mod sc_ttlm_neg;
mod sc_tx_amsdu;
pub mod scan_api;
mod scheduled_epoch;
#[cfg(feature = "builtin")]
mod scheduled_wire;
pub mod security;
mod six_ghz_power;
mod six_ghz_scan;
mod six_ghz_span;
mod six_ghz_station;
pub mod sta;
pub mod station_api;
pub mod transport;
pub mod tx;
pub mod tx_gen2;

#[cfg(any(test, feature = "kernel-test"))]
mod protocol_tests;
pub mod wpa;

/// The loadable build's KABI platform, PCI binding and netdev (`iwlwifi.ko`).
#[cfg(feature = "module")]
pub mod module;
/// Roles the module build does not carry, under the names the shared station
/// code uses (`module/absent.rs`).
#[cfg(feature = "module")]
use module::absent::{p2p_client, p2p_go};

#[cfg(feature = "builtin")]
use narf_bus::{BusDevice, BusDeviceCap};
#[cfg(feature = "builtin")]
use narf_capabilities::{Cap, Write};
#[cfg(feature = "builtin")]
use narf_lib::sync::IrqSafeSpinLock;

pub const INTEL_VENDOR: u16 = 0x8086;

// ── Interface name ─────────────────────────────────────────────────

/// This adapter's interface name, `wlan%d` as Linux `dev_alloc_name` picks
/// it. Reserved the first time a station device needs it — the Gen3
/// `device::Device` or the Gen2 `mvm_device::Device` — and shared, so the
/// card has one name.
#[cfg(feature = "builtin")]
static IFNAME: IrqSafeSpinLock<&'static str> = IrqSafeSpinLock::new("");

#[cfg(feature = "builtin")]
pub(crate) fn iwl_ifname() -> &'static str {
    let mut name = IFNAME.lock();
    if name.is_empty() {
        *name = narf_net::iface::reserve_name("wlan%d");
    }
    *name
}

// ── MMIO implementation ────────────────────────────────────────────

#[cfg(feature = "builtin")]
mod mmio;
#[cfg(feature = "module")]
#[path = "module/mmio.rs"]
mod mmio;
use mmio::IwlMmioImpl;

// ── Per-chip configuration table ───────────────────────────────────

/// Hardware generation. Determines the PCIe transport path.
///
/// gen2 (AX200/AX201) uses the original FH (Flow Handler) DMA
/// path — driver pushes each section to device memory by writing
/// to FH_SRVC_CHNL registers per `pcie/gen1_2/trans.c`.
///
/// gen3 (AX210+) uses context-info-v2 / IML: driver builds the
/// context info in host RAM, points CSR_CTXT_INFO_ADDR + CSR_IML_*
/// at it, and the device's ROM pulls sections through itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    Gen2,
    Gen3,
}

/// MAC die family. Set by the device's PCI ID via the per-cfg
/// table in `iwlwifi/cfg/*.c`. Linux composes firmware filenames
/// from MAC + RF family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacFamily {
    /// AX200/AX201 — Cyclone Peak baseband.
    QuB0,
    /// AX200/AX201 alternative stepping.
    QuC0,
    /// AX200 alt variant.
    QuZA0,
    /// AX210 — Typhoon Peak.
    TyA0,
    /// AX211 (so-a0).
    SoA0,
    /// AX211 (ma-a0).
    MaA0,
    /// AX211 (ma-b0).
    MaB0,
    /// BE200 — Bz baseband.
    BzA0,
    /// BE20x / BE21x — Sc ("Scorpius Peak") baseband. Ships as the
    /// CNVi companion on Lunar Lake and Panther Lake. Verified on
    /// the Minisforum MS-03: `00:14.3` reports PCI `8086:e340`
    /// subsys `8086:0114` and Linux loads `sc-a0-wh-b0` firmware.
    ScA0,
}

impl MacFamily {
    /// Lowercase string Linux uses in the filename ladder.
    pub fn prefix(self) -> &'static str {
        match self {
            MacFamily::QuB0 => "Qu-b0",
            MacFamily::QuC0 => "Qu-c0",
            MacFamily::QuZA0 => "QuZ-a0",
            MacFamily::TyA0 => "ty-a0",
            MacFamily::SoA0 => "so-a0",
            MacFamily::MaA0 => "ma-a0",
            MacFamily::MaB0 => "ma-b0",
            MacFamily::BzA0 => "bz-a0",
            MacFamily::ScA0 => "sc-a0",
        }
    }
}

/// RF (Wi-Fi PHY) chip family. Independently variable from MAC —
/// the device's PRPH `WFPM_OTP_CFG1_ADDR` register decides which
/// RF chip is fused. We can't read PRPH without BAR0 access, so
/// the candidate list expands to every plausible RF per MAC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RfFamily {
    /// "hr-b0" — used with Qu/QuZ MACs (AX200/AX201).
    HrB0,
    /// "gf-a0" — Wi-Fi 6E GFf radio (AX210+).
    GfA0,
    /// "gf4-a0" — Wi-Fi 6E 4x4 RF.
    Gf4A0,
    /// "fm-a0" — Wi-Fi 7 FM radio.
    FmA0,
    /// "fm-b0" — Wi-Fi 7 FM radio, B0 stepping (Sc MAC pairings).
    FmB0,
    /// "fm-c0" — Wi-Fi 7 FM radio, C0 stepping (Sc MAC pairings).
    FmC0,
    /// "wh-b0" — Wi-Fi 7 "Wildcat Peak" radio, B0 stepping. The RF
    /// fused on the MS-03's BE211 (`Detected RF WH, rfid=0x20113100`).
    WhB0,
}

impl RfFamily {
    pub fn prefix(self) -> &'static str {
        match self {
            RfFamily::HrB0 => "hr-b0",
            RfFamily::GfA0 => "gf-a0",
            RfFamily::Gf4A0 => "gf4-a0",
            RfFamily::FmA0 => "fm-a0",
            RfFamily::FmB0 => "fm-b0",
            RfFamily::FmC0 => "fm-c0",
            RfFamily::WhB0 => "wh-b0",
        }
    }
}

/// Per-PCI-ID descriptor. Sourced from the Linux cfg/*.c
/// `iwl_*_trans_cfg` + `iwl_cfg` tables (each chip ID gets one
/// MAC family + the candidate RF set its OTP can fuse).
#[derive(Clone, Debug)]
pub struct ChipConfig {
    pub vid: u16,
    pub did: u16,
    pub display_name: &'static str,
    pub generation: Generation,
    pub mac: MacFamily,
    /// Candidate RF families. The OTP fuse selects one; without
    /// MMIO access we pessimistically try each via the filename
    /// ladder (kernel-side: the actually-fused RF is matched
    /// against this set after probe).
    pub rf_candidates: &'static [RfFamily],
    /// UCODE API version walk: try filenames with API stamps from
    /// `api_max` down to `api_min`, interpreted together with
    /// `api_prefix`.
    pub api_max: u32,
    pub api_min: u32,
    /// Literal prefix stamped in front of the API number in the
    /// firmware filename. Empty for the historical numbering
    /// (`…-gf-a0-89.ucode`); `"c"` for the core-release numbering.
    ///
    /// Linux encodes both in one integer: an API value at or above
    /// `API_IS_CORE_START` (1000) is a core release, and `FW_API_ARG`
    /// renders it as `"c"` plus `value - 1000`
    /// (`iwl-config.h`). Here the two halves are kept apart —
    /// `api_max` / `api_min` hold the bare number and this field
    /// holds the prefix — so the ladder builder stays a plain
    /// decrementing loop.
    pub api_prefix: &'static str,
}

/// AX200 — single fused chip. Linux ships HR-b0 RF only.
const RF_HR_ONLY: &[RfFamily] = &[RfFamily::HrB0];
/// AX210 — GF / GF4 RFs depending on OTP fuse.
const RF_GF_OR_GF4: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0];
/// BE200 — GF / GF4 / FM RFs.
const RF_GF_FAMILY: &[RfFamily] = &[RfFamily::GfA0, RfFamily::Gf4A0, RfFamily::FmA0];
/// BE20x / BE21x on the Sc MAC.
///
/// Modern iwlwifi does not carry a static RF list per PCI ID: it
/// reads the fused RF type + step out of `CSR_HW_RF_ID` and composes
/// `iwlwifi-<mac>-<step>-<rf>-<step>` at runtime
/// (`iwl_drv_get_fwname_pre`). Without MMIO at match time we
/// enumerate the pairings linux-firmware actually ships for `sc-a0`.
/// WH-b0 goes first because it is the pairing the MS-03 reports
/// (`Detected RF WH, rfid=0x20113100`, firmware `sc-a0-wh-b0-c103`).
const RF_SC_A0_CANDIDATES: &[RfFamily] = &[
    RfFamily::WhB0,
    RfFamily::FmC0,
    RfFamily::FmB0,
    RfFamily::GfA0,
];

/// Match a PCI device against the iwlwifi chip table.
pub fn chip_config_for_pci_id(vid: u16, did: u16) -> Option<ChipConfig> {
    if vid != INTEL_VENDOR {
        return None;
    }
    let cfg = match did {
        // AX200 — single canonical PCI ID.
        0x2723 => ChipConfig {
            vid,
            did,
            display_name: "AX200",
            generation: Generation::Gen2,
            mac: MacFamily::QuZA0,
            rf_candidates: RF_HR_ONLY,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        // AX201 family — same MAC/RF as AX200, multiple SKUs. Linux
        // pcie/drv.c "Qu devices" plus the identification-only 0x7df0.
        0x02f0 | 0x06f0 | 0x34f0 | 0x3df0 | 0x4df0 | 0x43f0 | 0xa0f0 | 0x7df0 => ChipConfig {
            vid,
            did,
            display_name: "AX201",
            generation: Generation::Gen2,
            mac: MacFamily::QuB0,
            rf_candidates: RF_HR_ONLY,
            api_max: 100,
            api_min: 100,
            api_prefix: "",
        },
        // AX210.
        0x2725 => ChipConfig {
            vid,
            did,
            display_name: "AX210",
            generation: Generation::Gen3,
            mac: MacFamily::TyA0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 89,
            api_min: 89,
            api_prefix: "",
        },
        // AX211 family. Linux 7.3 `pcie/drv.c` "So devices" binds 0x51F0
        // and 0x7AF0/0x7F70 (`iwl_so_mac_cfg`), 0x51F1/0x7A70
        // (`iwl_so_long_latency_imr_mac_cfg`) to the same So MAC.
        0x51f0 | 0x51f1 | 0x54f0 | 0x7a70 | 0x7af0 | 0x7f70 => ChipConfig {
            vid,
            did,
            display_name: "AX211 (so-a0)",
            generation: Generation::Gen3,
            mac: MacFamily::SoA0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 89,
            api_min: 89,
            api_prefix: "",
        },
        // "Ma devices": 0x2729 and 0x7E40 bind `iwl_ma_mac_cfg`.
        0x2729 | 0x7e40 => ChipConfig {
            vid,
            did,
            display_name: "AX211 (ma-b0)",
            generation: Generation::Gen3,
            mac: MacFamily::MaB0,
            rf_candidates: RF_GF_OR_GF4,
            api_max: 89,
            api_min: 89,
            api_prefix: "",
        },
        // BE200 — Wi-Fi 7 Bz MAC + GF / GF4 / FM RF. "Bz devices" also
        // binds integrated 0x7740/0x4D40 (any subsystem) and 0xA840 only
        // for the subsystem IDs in [`BZ_A840_SUBSYSTEMS`].
        0x272b | 0x7740 | 0x4d40 | 0xa840 => ChipConfig {
            vid,
            did,
            display_name: if did == 0x272b { "BE200" } else { "BE20x (bz)" },
            generation: Generation::Gen3,
            mac: MacFamily::BzA0,
            rf_candidates: RF_GF_FAMILY,
            api_max: 102,
            api_min: 100,
            api_prefix: "",
        },
        // Sc ("Scorpius Peak") — Wi-Fi 7 BE20x / BE21x CNVi. Every
        // one of these IDs binds `iwl_sc_mac_cfg` in Linux's
        // `iwl_hw_card_ids` (pcie/drv.c, "Sc devices" block).
        //
        // 0xe340 is hardware-verified on the Minisforum MS-03
        // (Panther Lake-H, `00:14.3`, subsys 8086:0114): the device
        // announces as "Wi-Fi 7 BE211 320MHz" and Linux walks
        // `sc-a0-wh-b0-c107 … c103`, landing on c103.
        //
        // The API ladder is the core-release numbering: `iwl_sc_base`
        // sets `ucode_api_max = ENCODE_CORE_AS_API(107)` and
        // `ucode_api_min = ENCODE_CORE_AS_API(102)`, and
        // `FW_API_ARG` stamps those as `c107 … c102`.
        0x6e70 | 0x9327 | 0xd240 | 0xd340 | 0xe340 | 0xe440 => ChipConfig {
            vid,
            did,
            display_name: match did {
                0xe340 => "BE211 (sc-a0)",
                _ => "BE2xx (sc-a0)",
            },
            generation: Generation::Gen3,
            mac: MacFamily::ScA0,
            rf_candidates: RF_SC_A0_CANDIDATES,
            api_max: 107,
            api_min: 102,
            api_prefix: "c",
        },
        _ => return None,
    };
    Some(cfg)
}

// ── Firmware filename ladder ────────────────────────────────────────

/// Generate the firmware filename candidate ladder for `chip`.
/// Mirrors `iwl_request_firmware` in iwl-drv.c: outer loop over
/// `rf_candidates`, inner loop over API versions from `api_max`
/// down to `api_min`. First file the firmware registry resolves
/// is the one we use. Native Sc startup instead binds this API ladder to its
/// actual CSR MAC/RF/step through `firmware_identity`, never cross-RF fallback.
///
/// Linux's special-case at API 100 → 102 (the "core" numbering
/// jump on Bz+) is preserved: when the requested chip's
/// `api_max ≥ 100`, we start the walk at `api_max` if it's ≥ 102
/// and decrement past 100 down to `api_min`. Conversely a chip
/// pinned at `api_max = 100` gets exactly one API value tried per
/// RF.
pub fn firmware_filename_ladder(chip: &ChipConfig) -> Vec<String> {
    let mut out = Vec::new();
    for rf in chip.rf_candidates {
        // Decreasing walk, but with the API-100 → API-102 jump
        // baked in. Linux's iwl_request_firmware does this by
        // restarting the API counter at 102 when the prefix
        // matches the core-numbering family.
        let mut api = chip.api_max;
        loop {
            // NARF uses vendor-qualified registry keys. `xtask
            // import-firmware` maps linux-firmware's flat Intel files
            // into this iwlwifi/ namespace, including sibling PNVM.
            out.push(format!(
                "iwlwifi/iwlwifi-{}-{}-{}{}.ucode",
                chip.mac.prefix(),
                rf.prefix(),
                chip.api_prefix,
                api,
            ));
            if api == chip.api_min {
                break;
            }
            // Step from 102 → 101 → 100 → done (vs decrementing
            // forever). When we cross 100 we stop; api_min for
            // older chips is 100, for Bz it's also 100.
            api = api.saturating_sub(1);
            if api < chip.api_min {
                break;
            }
        }
    }
    out
}

// ── TLV firmware container parser ───────────────────────────────────

/// Magic value at offset 4 of a valid Intel .ucode file
/// (`iwl_tlv_ucode_header.magic`).
pub const IWL_TLV_UCODE_MAGIC: u32 = 0x0a4c_5749;

/// Header preceding the TLV stream — fields per
/// `iwl_tlv_ucode_header` in `fw/file.h`. Its packed fields occupy
/// 88 bytes (4 zero + 4 magic + 64 human_readable + 4 ver + 4 build +
/// 8 ignore); the TLV stream starts immediately afterward.
pub const TLV_HEADER_BYTES: usize = 4 + 4 + 64 + 4 + 4 + 8;

/// Parsed firmware header.
#[derive(Clone, Debug)]
pub struct UcodeHeader {
    pub version: u32,
    pub build: u32,
    /// Human-readable version string from the 64-byte field.
    pub human_readable: String,
}

/// Tag IDs from `enum iwl_ucode_tlv_type` (`fw/file.h`). Only the
/// tags we need to round-trip a modern AX2xx/BE2xx blob are
/// enumerated; unknown tags are surfaced as `Other(u32)` so the
/// walker is forward-compatible with future Linux additions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlvType {
    /// Legacy CPU1 instruction blob (pre-22000 era).
    Inst = 1,
    /// Legacy CPU1 data.
    Data = 2,
    /// Legacy INIT instructions.
    Init = 3,
    /// Legacy INIT data.
    InitData = 4,
    /// Legacy boot (unused on AX2xx+).
    Boot = 5,
    /// Modern runtime section: `{ dest_offset: u32; payload }`.
    /// One TLV per section, ordered.
    SecRt = 19,
    /// Modern INIT section.
    SecInit = 20,
    /// WoWLAN image section.
    SecWowlan = 21,
    /// `u32`: 1 or 2. Sections beyond NUM_OF_CPU split go to CPU2.
    NumOfCpu = 27,
    /// Cipher schemes (encryption capability bitmaps).
    Cscheme = 28,
    /// API capability bitmap.
    ApiChangesSet = 29,
    /// Feature capability bitmap.
    EnabledCapabilities = 30,
    /// `maj.min.api` version triple.
    FwVersion = 36,
    /// Required PNVM blob version (gen3 only).
    PnvmVersion = 62,
    /// PNVM SKU selector.
    PnvmSku = 64,
    /// Section table address.
    SecTableAddr = 66,
}

impl TlvType {
    pub fn from_raw(v: u32) -> Option<Self> {
        Some(match v {
            1 => TlvType::Inst,
            2 => TlvType::Data,
            3 => TlvType::Init,
            4 => TlvType::InitData,
            5 => TlvType::Boot,
            19 => TlvType::SecRt,
            20 => TlvType::SecInit,
            21 => TlvType::SecWowlan,
            27 => TlvType::NumOfCpu,
            28 => TlvType::Cscheme,
            29 => TlvType::ApiChangesSet,
            30 => TlvType::EnabledCapabilities,
            36 => TlvType::FwVersion,
            62 => TlvType::PnvmVersion,
            64 => TlvType::PnvmSku,
            66 => TlvType::SecTableAddr,
            _ => return None,
        })
    }
}

/// Magic offset value separating CPU1 sections from CPU2 in the
/// SEC_RT / SEC_INIT TLV stream (`CPU1_CPU2_SEPARATOR_SECTION`).
pub const CPU1_CPU2_SEPARATOR: u32 = 0xFFFF_CCCC;
/// Magic offset value introducing paged-section blocks
/// (`PAGING_SEPARATOR_SECTION`).
pub const PAGING_SEPARATOR: u32 = 0xAAAA_BBBB;
/// PAGING block size — 8 × 4 KiB pages per the iwlwifi paging IF.
pub const PAGING_BLOCK_SIZE: usize = 32 * 1024;
/// Maximum total paging image size.
pub const MAX_PAGING_IMAGE_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub enum ParseError {
    /// A recognized metadata TLV has an invalid shape.
    InvalidMetadata(&'static str),
    /// Header too short for the magic + fields.
    TooShort,
    /// Magic doesn't match `IWL_TLV_UCODE_MAGIC`.
    BadMagic(u32),
    /// A TLV's declared length runs past the end of the blob.
    TruncatedTlv {
        offset: usize,
        declared_len: u32,
        remaining: usize,
    },
    /// A SEC_RT/SEC_INIT TLV is smaller than 4 bytes (the leading
    /// dest_offset).
    SecTooShort { offset: usize, len: u32 },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidMetadata(reason) => f.write_str(reason),
            ParseError::TooShort => write!(f, "blob too short for header"),
            ParseError::BadMagic(m) => write!(f, "bad TLV magic: {:#x}", m),
            ParseError::TruncatedTlv {
                offset,
                declared_len,
                remaining,
            } => write!(
                f,
                "truncated TLV at {}: declared {} bytes, only {} remain",
                offset, declared_len, remaining
            ),
            ParseError::SecTooShort { offset, len } => {
                write!(f, "SEC_RT/SEC_INIT at {} too short ({} bytes)", offset, len)
            }
        }
    }
}

/// Parse + classify one section TLV (SEC_RT or SEC_INIT). First 4
/// bytes are the device-memory destination offset; remainder is the
/// payload. A few sentinel `dest_offset` values are NOT real
/// addresses but markers: `CPU1_CPU2_SEPARATOR` and
/// `PAGING_SEPARATOR`.
#[derive(Clone, Debug)]
pub struct FwSection<'a> {
    pub dest_offset: u32,
    pub payload: &'a [u8],
}

impl<'a> FwSection<'a> {
    pub fn is_separator(&self) -> bool {
        matches!(self.dest_offset, CPU1_CPU2_SEPARATOR | PAGING_SEPARATOR)
    }
    pub fn is_cpu1_cpu2_separator(&self) -> bool {
        self.dest_offset == CPU1_CPU2_SEPARATOR
    }
    pub fn is_paging_separator(&self) -> bool {
        self.dest_offset == PAGING_SEPARATOR
    }
}

/// Walked .ucode blob. Each method below borrows the underlying
/// bytes so the parser is zero-copy — sections point into the
/// original CPIO payload.
#[derive(Clone, Debug)]
pub struct ParsedUcode<'a> {
    pub api: firmware_api::FirmwareApi<'a>,
    pub header: UcodeHeader,
    /// Number of CPUs declared by `NUM_OF_CPU` TLV (default 1).
    pub num_of_cpu: u32,
    /// Sections from the `SEC_INIT` TLV stream (image type INIT).
    pub init_sections: Vec<FwSection<'a>>,
    /// Sections from the `SEC_RT` TLV stream (image type REGULAR).
    pub rt_sections: Vec<FwSection<'a>>,
    /// Raw display `FW_VERSION` triple: (major, minor, local component).
    /// Header/API_NEW_VERSION selects the protocol API independently.
    pub fw_version: Option<(u32, u32, u32)>,
    /// PNVM version metadata when present; runtime ALIVE SKU selects
    /// the required calibration image (embedded or an external sibling).
    pub pnvm_version: Option<u32>,
    /// Unknown / unparsed TLVs surface count for diagnostics. The
    /// walker doesn't fail on these — Intel adds new tags in
    /// every kernel release.
    pub unknown_tlv_count: usize,
}

impl<'a> ParsedUcode<'a> {
    pub fn is_dual_cpu(&self) -> bool {
        self.num_of_cpu >= 2
    }

    /// Firmware includes PNVM metadata. The ALIVE SKU determines
    /// whether calibration must actually be loaded at runtime.
    pub fn requires_pnvm(&self) -> bool {
        self.pnvm_version.is_some() || self.api.pnvm.is_some()
    }

    /// PNVM uses the MAC/RF prefix without the firmware API or PNVM
    /// version suffix: `iwlwifi-<mac>-<rf>.pnvm`. Gen2 has no sibling.
    pub fn pnvm_filename(&self, chip: &ChipConfig, rf: RfFamily) -> Option<String> {
        if chip.generation != Generation::Gen3 {
            return None;
        }
        Some(format!(
            "iwlwifi-{}-{}.pnvm",
            chip.mac.prefix(),
            rf.prefix(),
        ))
    }
}

/// Parse an Intel iwlwifi .ucode blob.
pub fn parse_ucode(bytes: &[u8]) -> Result<ParsedUcode<'_>, ParseError> {
    if bytes.len() < TLV_HEADER_BYTES {
        return Err(ParseError::TooShort);
    }
    // Header (struct iwl_tlv_ucode_header): zero(4) + magic(4) +
    // human_readable[64] + ver(4) + build(4) + ignore(8).
    let magic = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if magic != IWL_TLV_UCODE_MAGIC {
        return Err(ParseError::BadMagic(magic));
    }
    let mut hr = String::new();
    for &b in &bytes[8..8 + 64] {
        if b == 0 {
            break;
        }
        if b.is_ascii() && !b.is_ascii_control() {
            hr.push(b as char);
        }
    }
    let version = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
    let build = u32::from_le_bytes(bytes[76..80].try_into().unwrap());

    let header = UcodeHeader {
        version,
        build,
        human_readable: hr,
    };

    let mut api = firmware_api::FirmwareApi::default();
    let mut num_of_cpu: u32 = 1;
    let mut init_sections: Vec<FwSection<'_>> = Vec::new();
    let mut rt_sections: Vec<FwSection<'_>> = Vec::new();
    let mut fw_version: Option<(u32, u32, u32)> = None;
    let mut pnvm_version: Option<u32> = None;
    let mut unknown_tlv_count: usize = 0;

    // TLV stream starts at TLV_HEADER_BYTES.
    let mut pos = TLV_HEADER_BYTES;
    while pos < bytes.len() {
        if bytes.len() - pos < 8 {
            return Err(ParseError::InvalidMetadata("truncated TLV header"));
        }
        let raw_type = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        let raw_len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
        pos += 8;
        let len = raw_len as usize;
        if len > bytes.len() - pos {
            return Err(ParseError::TruncatedTlv {
                offset: pos - 8,
                declared_len: raw_len,
                remaining: bytes.len() - pos,
            });
        }
        let data = &bytes[pos..pos + len];
        let metadata = api
            .consume(raw_type, data)
            .map_err(ParseError::InvalidMetadata)?;
        // Secure sections use the same wire layout as ordinary sections.
        let section_type = match raw_type {
            24 => 19,
            25 => 20,
            other => other,
        };
        match TlvType::from_raw(section_type) {
            Some(TlvType::NumOfCpu) if len >= 4 => {
                num_of_cpu = u32::from_le_bytes(data[..4].try_into().unwrap());
            }
            Some(TlvType::SecInit) | Some(TlvType::SecRt) => {
                if len < 4 {
                    return Err(ParseError::SecTooShort {
                        offset: pos - 8,
                        len: raw_len,
                    });
                }
                let dest_offset = u32::from_le_bytes(data[..4].try_into().unwrap());
                let sec = FwSection {
                    dest_offset,
                    payload: &data[4..],
                };
                if matches!(TlvType::from_raw(section_type), Some(TlvType::SecInit)) {
                    init_sections.push(sec);
                } else {
                    rt_sections.push(sec);
                }
            }
            Some(TlvType::FwVersion) if len >= 12 => {
                let major = u32::from_le_bytes(data[0..4].try_into().unwrap());
                let minor = u32::from_le_bytes(data[4..8].try_into().unwrap());
                let api = u32::from_le_bytes(data[8..12].try_into().unwrap());
                fw_version = Some((major, minor, api));
            }
            Some(TlvType::PnvmVersion) if len >= 4 => {
                pnvm_version = Some(u32::from_le_bytes(data[..4].try_into().unwrap()));
            }
            Some(_) => {} // recognised but not consumed
            None => {
                if !metadata {
                    unknown_tlv_count += 1;
                }
            }
        }
        // TLVs are 4-byte aligned in the stream — round `len` up.
        let advance = (len + 3) & !3;
        if advance > bytes.len() - pos {
            return Err(ParseError::InvalidMetadata(
                "truncated TLV alignment padding",
            ));
        }
        pos += advance;
    }

    Ok(ParsedUcode {
        api,
        header,
        num_of_cpu,
        init_sections,
        rt_sections,
        fw_version,
        pnvm_version,
        unknown_tlv_count,
    })
}

// ── PCI probe (skeleton) ────────────────────────────────────────────

/// PCI probe retains and parks the exact native binding, then defers all
/// firmware resolution/startup to its retained executor-time continuation.
/// Exact Gen2/API77 and supported Gen3 profiles use distinct retained owners.
#[cfg(feature = "builtin")]
static OWNED: IrqSafeSpinLock<Option<narf_bus::BusAddr>> = IrqSafeSpinLock::new(None);

/// Linux 7.3 `pcie/drv.c` claims PCI 0xA840 only with these subsystem
/// device IDs (`IWL_PCI_DEVICE(0xA840, <subdev>, iwl_bz_mac_cfg)`).
pub const BZ_A840_SUBSYSTEMS: &[u16] = &[
    0x0000, 0x0090, 0x0094, 0x0098, 0x009c, 0x00c0, 0x00c4, 0x00e0, 0x00e4, 0x00e8, 0x00ec, 0x0100,
    0x0110, 0x0114, 0x0118, 0x011c, 0x0310, 0x0314, 0x0510, 0x0a10, 0x1671, 0x1672, 0x1771, 0x1772,
    0x1791, 0x1792, 0x4090, 0x40c4, 0x40e0, 0x4110, 0x4314,
];

/// Subsystem qualification on top of the vendor/device match. Every claimed
/// ID except 0xA840 matches `PCI_ANY_ID`.
pub fn pci_subsystem_claimed(device: u16, subsystem_id: u16) -> bool {
    device != 0xa840 || BZ_A840_SUBSYSTEMS.contains(&subsystem_id)
}

#[cfg(feature = "builtin")]
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    let chip = match chip_config_for_pci_id(device.id.vendor, device.id.device) {
        Some(c) if pci_subsystem_claimed(device.id.device, device.id.subsystem_id) => c,
        _ => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    let extra = {
        let mut owner = OWNED.lock();
        match *owner {
            Some(address) if address == device.addr => return Ok(()),
            Some(_) => true,
            None => {
                *owner = Some(device.addr);
                false
            }
        }
    };
    // Retain the exact current native binding before even initial parking.
    // Gen2 startup uses its own context-v1 and retained MVM station owner.
    let startup = if !extra
        && (chip.generation == Generation::Gen2
            || rx_rfh::CompletionFormat::for_mac(chip.mac).is_some())
    {
        Some(bootstrap::retain(device, cap, chip.clone()))
    } else {
        None
    };
    if let Err(error) = mmio::park(&device, &cap) {
        if let Some(owner) = &startup {
            owner.fail();
        }
        return Err(narf_bus::ProbeError::Other(error));
    }
    if extra {
        return Ok(());
    }
    if let Some(owner) = &startup {
        owner.parked();
    }
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("iwlwifi"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  iwlwifi: probed {} ({:04x}:{:04x}, {:?}, MAC={}, RF={:?})",
        chip.display_name,
        chip.vid,
        chip.did,
        chip.generation,
        chip.mac.prefix(),
        chip.rf_candidates,
    );

    if let Some(owner) = startup {
        bootstrap::schedule(owner);
    }
    Ok(())
}

/// Register the PCI match table. Picked up at boot via the bus
/// walker; once any of these PCI IDs is enumerated the `probe`
/// function fires.
///
/// The bus match registry is keyed by `name` and idempotent on
/// re-registration (later entry replaces the earlier), so we
/// need a unique `name` per PCI ID — using the bare "iwlwifi"
/// for all of them would collapse to just the last entry. The
/// per-match names are `iwlwifi-<did>` (the canonical display
/// name is still recorded via `record_bound("iwlwifi", ...)`).
#[cfg(feature = "builtin")]
pub fn register() {
    for &(did, name) in PCI_DIDS.iter() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Whether `iwlwifi.ko` carries `chip`: the one predicate behind the module's
/// PCI claim and `register_builtin_only`, so the two never disagree.
pub fn module_carries(chip: &ChipConfig) -> bool {
    matches!(chip.generation, Generation::Gen2 | Generation::Gen3)
}

/// `narf-drivers-wireless/iwlwifi-module-only`: register every id except the
/// ones `iwlwifi.ko` claims ([`module_carries`]), so an early-loaded module
/// owns those devices while any other generation stays built in.
#[cfg(feature = "builtin")]
pub fn register_builtin_only() {
    for &(did, name) in PCI_DIDS.iter() {
        if chip_config_for_pci_id(INTEL_VENDOR, did).is_some_and(|chip| module_carries(&chip)) {
            continue;
        }
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// PCI device IDs the driver claims, with the unique per-ID match
/// name used at registration. Names match `iwlwifi-<did>` pattern
/// so registry lookups can find them by string. Sync with
/// `chip_config_for_pci_id`.
pub(crate) const PCI_DIDS: &[(u16, &str)] = &[
    (0x2723, "iwlwifi-2723"),
    (0x02f0, "iwlwifi-02f0"),
    (0x06f0, "iwlwifi-06f0"),
    (0x34f0, "iwlwifi-34f0"),
    (0x3df0, "iwlwifi-3df0"),
    (0x4df0, "iwlwifi-4df0"),
    (0x43f0, "iwlwifi-43f0"),
    (0xa0f0, "iwlwifi-a0f0"),
    (0x7df0, "iwlwifi-7df0"),
    (0x2725, "iwlwifi-2725"),
    (0x51f0, "iwlwifi-51f0"),
    (0x51f1, "iwlwifi-51f1"),
    (0x7a70, "iwlwifi-7a70"),
    (0x7af0, "iwlwifi-7af0"),
    (0x7f70, "iwlwifi-7f70"),
    (0x54f0, "iwlwifi-54f0"),
    (0x2729, "iwlwifi-2729"),
    (0x7e40, "iwlwifi-7e40"),
    (0x272b, "iwlwifi-272b"),
    (0x7740, "iwlwifi-7740"),
    (0x4d40, "iwlwifi-4d40"),
    (0xa840, "iwlwifi-a840"),
    (0x6e70, "iwlwifi-6e70"),
    (0x9327, "iwlwifi-9327"),
    (0xd240, "iwlwifi-d240"),
    (0xd340, "iwlwifi-d340"),
    (0xe340, "iwlwifi-e340"),
    (0xe440, "iwlwifi-e440"),
];

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Sanity: every PCI ID in the device-ID table resolves
    /// through `chip_config_for_pci_id`.
    fn smoke_iwlwifi_chip_table_is_complete() -> TestResult {
        for (did, _) in PCI_DIDS {
            if chip_config_for_pci_id(INTEL_VENDOR, *did).is_none() {
                return TestResult::Fail("PCI ID without chip config entry");
            }
        }
        TestResult::Pass
    }

    /// AX200 ladder = exactly one filename
    /// (`iwlwifi-QuZ-a0-hr-b0-100.ucode`).
    fn smoke_iwlwifi_ax200_ladder_pinned_api_100() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x2723).expect("ax200");
        let ladder = firmware_filename_ladder(&chip);
        if ladder.len() != 1 {
            return TestResult::Fail("expected exactly one AX200 candidate");
        }
        if ladder[0] != "iwlwifi/iwlwifi-QuZ-a0-hr-b0-100.ucode" {
            return TestResult::Fail("AX200 candidate didn't match expected name");
        }
        TestResult::Pass
    }

    /// BE200 ladder spans 3 RFs × API 102..=100 = 9 names.
    fn smoke_iwlwifi_be200_ladder_spans_rfs_and_apis() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x272b).expect("be200");
        let ladder = firmware_filename_ladder(&chip);
        if ladder.len() != 9 {
            return TestResult::Fail("expected 3 RFs × 3 APIs = 9 BE200 candidates");
        }
        // First candidate should be gf-a0 @ 102 (max API, first RF).
        if ladder[0] != "iwlwifi/iwlwifi-bz-a0-gf-a0-102.ucode" {
            return TestResult::Fail("BE200 first candidate wrong");
        }
        TestResult::Pass
    }

    /// Parse a minimal hand-crafted TLV blob and confirm the
    /// walker reaches the SEC_RT entry without choking on
    /// alignment padding.
    fn smoke_iwlwifi_tlv_parser_round_trip() -> TestResult {
        let mut blob = Vec::<u8>::new();
        // Header: 4 zero, 4 magic, 64 hr, 4 ver, 4 build, 8 ignore.
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&IWL_TLV_UCODE_MAGIC.to_le_bytes());
        let mut hr = [0u8; 64];
        hr[..b"smoketest"[..].len()].copy_from_slice(b"smoketest");
        blob.extend_from_slice(&hr);
        blob.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // ver
        blob.extend_from_slice(&42u32.to_le_bytes()); // build
        blob.extend_from_slice(&[0u8; 8]); // ignore
                                           // TLV: SEC_RT (19), length = 4 (dest) + 3 (payload), so
                                           // 7 bytes — needs 1 byte of padding to 8.
        blob.extend_from_slice(&19u32.to_le_bytes()); // type
        blob.extend_from_slice(&7u32.to_le_bytes()); // len
        blob.extend_from_slice(&0x0040_1000u32.to_le_bytes()); // dest
        blob.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // payload
        blob.push(0); // alignment pad
                      // TLV: NUM_OF_CPU = 2.
        blob.extend_from_slice(&27u32.to_le_bytes());
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());

        let parsed = match parse_ucode(&blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse_ucode unexpectedly failed"),
        };
        if parsed.header.version != 0x0102_0304 || parsed.header.build != 42 {
            return TestResult::Fail("header decode wrong");
        }
        if parsed.header.human_readable != "smoketest" {
            return TestResult::Fail("human_readable decode wrong");
        }
        if parsed.rt_sections.len() != 1 {
            return TestResult::Fail("expected exactly one SEC_RT");
        }
        if parsed.rt_sections[0].dest_offset != 0x0040_1000 {
            return TestResult::Fail("SEC_RT dest_offset wrong");
        }
        if parsed.rt_sections[0].payload != [0xAB, 0xCD, 0xEF] {
            return TestResult::Fail("SEC_RT payload wrong");
        }
        if parsed.num_of_cpu != 2 {
            return TestResult::Fail("NUM_OF_CPU not honoured");
        }
        TestResult::Pass
    }

    /// A blob with a bad magic should produce `BadMagic`.
    fn smoke_iwlwifi_tlv_parser_rejects_bad_magic() -> TestResult {
        let mut blob = Vec::<u8>::new();
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // wrong magic
        blob.resize(TLV_HEADER_BYTES, 0);
        match parse_ucode(&blob) {
            Err(ParseError::BadMagic(0xDEADBEEF)) => TestResult::Pass,
            _ => TestResult::Fail("expected BadMagic on wrong magic"),
        }
    }

    /// CPU1/CPU2 separator is recognised structurally.
    fn smoke_iwlwifi_cpu1_cpu2_separator_classified() -> TestResult {
        let sec = FwSection {
            dest_offset: CPU1_CPU2_SEPARATOR,
            payload: &[],
        };
        if !sec.is_separator() || !sec.is_cpu1_cpu2_separator() {
            return TestResult::Fail("CPU1/CPU2 separator not detected");
        }
        TestResult::Pass
    }

    /// PCI match table registered correctly.
    fn smoke_iwlwifi_pci_match_table_registers() -> TestResult {
        register();
        let regs = narf_bus::driver_match::registered();
        for (did, _) in PCI_DIDS {
            let found = regs.iter().any(|e| {
                matches!(
                    e.kind,
                    narf_bus::MatchKind::VendorDevice { vendor, device }
                        if vendor == INTEL_VENDOR && device == *did
                )
            });
            if !found {
                return TestResult::Fail("PCI ID missing from registered match table");
            }
        }
        TestResult::Pass
    }

    /// Linux 7.3 `pcie/drv.c` So/Ma/Bz IDs are claimed with their
    /// sibling MAC configuration; 0xA840 only for the listed subsystems.
    fn smoke_iwlwifi_gen3_linux_pci_ids_are_claimed() -> TestResult {
        for (did, mac) in [
            (0x7a70, MacFamily::SoA0),
            (0x7af0, MacFamily::SoA0),
            (0x51f1, MacFamily::SoA0),
            (0x7f70, MacFamily::SoA0),
            (0x2729, MacFamily::MaB0),
            (0xa840, MacFamily::BzA0),
            (0x7740, MacFamily::BzA0),
            (0x4d40, MacFamily::BzA0),
        ] {
            let Some(chip) = chip_config_for_pci_id(INTEL_VENDOR, did) else {
                return TestResult::Fail("Linux-claimed Gen3 PCI ID has no chip config");
            };
            if chip.mac != mac
                || chip.generation != Generation::Gen3
                || rx_rfh::CompletionFormat::for_mac(chip.mac).is_none()
                || !PCI_DIDS.iter().any(|(d, _)| *d == did)
            {
                return TestResult::Fail("Linux-claimed Gen3 PCI ID has wrong MAC/registration");
            }
        }
        if !pci_subsystem_claimed(0xa840, 0x0114)
            || !pci_subsystem_claimed(0xa840, 0x0000)
            || !pci_subsystem_claimed(0xa840, 0x4314)
            || pci_subsystem_claimed(0xa840, 0x0124)
            || !pci_subsystem_claimed(0x7740, 0x1234)
        {
            return TestResult::Fail("0xA840 subsystem qualification differs from Linux");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_chip_table_is_complete
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen3_linux_pci_ids_are_claimed
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_ax200_ladder_pinned_api_100
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_be200_ladder_spans_rfs_and_apis
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_tlv_parser_round_trip
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_tlv_parser_rejects_bad_magic
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_cpu1_cpu2_separator_classified
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pci_match_table_registers
    );

    /// PNVM sibling filename derived from PnvmVersion TLV + chip
    /// MAC/RF prefixes.
    fn smoke_iwlwifi_pnvm_filename_derived_correctly() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x272b).expect("be200");
        let parsed = ParsedUcode {
            api: Default::default(),
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 2,
            init_sections: Vec::new(),
            rt_sections: Vec::new(),
            fw_version: None,
            pnvm_version: Some(0x42),
            unknown_tlv_count: 0,
        };
        let name = parsed
            .pnvm_filename(&chip, RfFamily::GfA0)
            .expect("Some filename");
        if name != "iwlwifi-bz-a0-gf-a0.pnvm" {
            return TestResult::Fail("PNVM filename wrong");
        }
        TestResult::Pass
    }

    /// No PNVM required → no filename.
    fn smoke_iwlwifi_pnvm_filename_none_when_no_version() -> TestResult {
        let chip = chip_config_for_pci_id(INTEL_VENDOR, 0x2723).expect("ax200");
        let parsed = ParsedUcode {
            api: Default::default(),
            header: UcodeHeader {
                version: 0,
                build: 0,
                human_readable: String::new(),
            },
            num_of_cpu: 1,
            init_sections: Vec::new(),
            rt_sections: Vec::new(),
            fw_version: None,
            pnvm_version: None,
            unknown_tlv_count: 0,
        };
        if parsed.pnvm_filename(&chip, RfFamily::HrB0).is_some() {
            return TestResult::Fail("expected None for non-PNVM blob");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pnvm_filename_derived_correctly
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_pnvm_filename_none_when_no_version
    );

    // ── Stage 3: MAC_CONTEXT_CMD + TIME_EVENT_CMD encode ──────────

    fn smoke_iwlwifi_mac_context_cmd_encode() -> TestResult {
        use mac_ctx::{
            build_mac_context_cmd, ctxt_action, filter_flags, mac_type, MAC_CONTEXT_CMD,
        };
        let node_addr: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bssid: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let filter = filter_flags::IN_NON_MCAST | filter_flags::IN_MCAST;
        let cmd = build_mac_context_cmd(0, mac_type::BSS_STA, node_addr, bssid, filter);
        // cmd_hdr(4) + id_and_color(4) + action(4) + mac_type(4) + tsf_id(4)
        // + node_addr(6)+pad(2) + bssid(6)+pad(2) + cck_rates(4) + ofdm_rates(4)
        // + protection_flags(4) + cck_short_preamble(4) + short_slot(4)
        // + filter_flags(4) + qos_flags(4) + ac[5]*8(40) + type_stub(4) = 108 bytes.
        if cmd.len() != 108 {
            return TestResult::Fail("mac_context_cmd size wrong (expected 108)");
        }
        // cmd[0] = MAC_CONTEXT_CMD = 0x28.
        if cmd[0] != MAC_CONTEXT_CMD {
            return TestResult::Fail("cmd[0] != MAC_CONTEXT_CMD (0x28)");
        }
        // id_and_color at bytes 4..8 = 0.
        let id_and_color = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        if id_and_color != 0 {
            return TestResult::Fail("id_and_color != 0");
        }
        // action at bytes 8..12 = ADD = 1.
        let action = u32::from_le_bytes(cmd[8..12].try_into().unwrap());
        if action != ctxt_action::ADD {
            return TestResult::Fail("action != ADD(1)");
        }
        // mac_type at bytes 12..16 = BSS_STA = 5.
        let mtype = u32::from_le_bytes(cmd[12..16].try_into().unwrap());
        if mtype != mac_type::BSS_STA {
            return TestResult::Fail("mac_type != BSS_STA(5)");
        }
        // node_addr at bytes 20..26 (after cmd_hdr+id_and_color+action+mac_type+tsf_id=20).
        if cmd[20..26] != node_addr {
            return TestResult::Fail("node_addr bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_mac_context_cmd_encode
    );

    fn smoke_iwlwifi_time_event_cmd_encode() -> TestResult {
        use mac_ctx::{build_time_event_cmd, ctxt_action, te_type, TIME_EVENT_CMD};
        let cmd = build_time_event_cmd(0, te_type::BSS_STA_ASSOC, 100);
        // Expected: 4-byte cmd hdr + 36-byte body = 40 bytes.
        if cmd.len() != 40 {
            return TestResult::Fail("time_event_cmd size wrong (expected 40)");
        }
        // cmd[0] = TIME_EVENT_CMD = 0x29.
        if cmd[0] != TIME_EVENT_CMD {
            return TestResult::Fail("cmd[0] != TIME_EVENT_CMD (0x29)");
        }
        // id_and_color at bytes 4..8 = 0.
        let id_and_color = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        if id_and_color != 0 {
            return TestResult::Fail("id_and_color != 0");
        }
        // action at bytes 8..12 = ADD = 1.
        let action = u32::from_le_bytes(cmd[8..12].try_into().unwrap());
        if action != ctxt_action::ADD {
            return TestResult::Fail("action != ADD(1)");
        }
        // te_id at bytes 12..16 = BSS_STA_ASSOC = 1.
        let te_id = u32::from_le_bytes(cmd[12..16].try_into().unwrap());
        if te_id != te_type::BSS_STA_ASSOC {
            return TestResult::Fail("te_id != BSS_STA_ASSOC(1)");
        }
        // duration at bytes 32..36 (after cmd_hdr+id+action+te_id+apply+max_delay+depends+interval = 32).
        let duration = u32::from_le_bytes(cmd[32..36].try_into().unwrap());
        if duration != 100 {
            return TestResult::Fail("duration != 100");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_time_event_cmd_encode
    );

    fn smoke_iwlwifi_cmd_header_layout() -> TestResult {
        let hdr = tx::IwlCmdHeader {
            cmd: 0x07,
            group_id: 0x0C,
            sequence: 0x1234,
        };
        if core::mem::size_of::<tx::IwlCmdHeader>() != 4 {
            return TestResult::Fail("IwlCmdHeader should be 4 bytes");
        }
        // Manual decode to verify packing + LE.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let bytes: [u8; 4] = unsafe { core::mem::transmute(hdr) };
        if bytes[0] != 0x07 {
            return TestResult::Fail("cmd wrong");
        }
        if bytes[1] != 0x0C {
            return TestResult::Fail("group_id wrong");
        }
        // sequence is u16 LE.
        if bytes[2] != 0x34 || bytes[3] != 0x12 {
            return TestResult::Fail("sequence (LE) wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_cmd_header_layout);

    /// BAR0 on this family is 16 KiB (`lspci` reports `size=16K` for
    /// the MS-03's 8086:e340). Anything handed to
    /// `MmioRegion::{read32,write32}` is a *CSR offset* and has to
    /// land inside that window.
    ///
    /// PRPH addresses are a different namespace: they are values
    /// written *through* the HBUS window, not offsets into it, and
    /// they legitimately run into the 0xA0_0000 range. Conflating the
    /// two is how `HBUS_TARG_PRPH_WADDR` came to be 0x44C000 — the
    /// PRPH data register's 0x44c with four zeroes stuck on — which
    /// put every indirect register access roughly 4.5 MiB past the
    /// end of the mapping.
    fn smoke_iwlwifi_csr_offsets_fit_in_bar0() -> TestResult {
        use super::regs;

        /// Smallest BAR0 this driver claims to support.
        const BAR0_BYTES: u32 = 16 * 1024;

        let csr_offsets: &[(&str, u32)] = &[
            ("CSR_HW_IF_CONFIG_REG", regs::CSR_HW_IF_CONFIG_REG),
            ("CSR_INT_COALESCING", regs::CSR_INT_COALESCING),
            ("CSR_INT", regs::CSR_INT),
            ("CSR_INT_MASK", regs::CSR_INT_MASK),
            ("CSR_FH_INT_STATUS", regs::CSR_FH_INT_STATUS),
            ("CSR_GPIO_IN", regs::CSR_GPIO_IN),
            ("CSR_RESET", regs::CSR_RESET),
            ("CSR_GP_CNTRL", regs::CSR_GP_CNTRL),
            ("CSR_HW_REV", regs::CSR_HW_REV),
            ("CSR_FUNC_SCRATCH", regs::CSR_FUNC_SCRATCH),
            ("CSR_EEPROM_REG", regs::CSR_EEPROM_REG),
            ("CSR_UCODE_DRV_GP1", regs::CSR_UCODE_DRV_GP1),
            ("CSR_UCODE_DRV_GP2", regs::CSR_UCODE_DRV_GP2),
            ("CSR_GIO_REG", regs::CSR_GIO_REG),
            ("CSR_CTXT_INFO_ADDR", regs::CSR_CTXT_INFO_ADDR),
            ("CSR_IML_DATA_ADDR", regs::CSR_IML_DATA_ADDR),
            ("CSR_IML_SIZE_ADDR", regs::CSR_IML_SIZE_ADDR),
            ("CSR_CTXT_INFO_BOOT_CTRL", regs::CSR_CTXT_INFO_BOOT_CTRL),
            ("HBUS_TARG_PRPH_WADDR", regs::HBUS_TARG_PRPH_WADDR),
            ("HBUS_TARG_PRPH_RADDR", regs::HBUS_TARG_PRPH_RADDR),
            ("HBUS_TARG_PRPH_WDAT", regs::HBUS_TARG_PRPH_WDAT),
            ("HBUS_TARG_PRPH_RDAT", regs::HBUS_TARG_PRPH_RDAT),
            ("FH_TFDIB_CTRL0_REG_SRVC", regs::FH_TFDIB_CTRL0_REG_SRVC),
            ("FH_TFDIB_CTRL1_REG_SRVC", regs::FH_TFDIB_CTRL1_REG_SRVC),
        ];

        for (name, off) in csr_offsets {
            let _ = name;
            if *off >= BAR0_BYTES {
                return TestResult::Fail("a CSR offset lies outside the 16 KiB BAR0 window");
            }
            // Every register in this device is 32 bits wide and the
            // MMIO accessors are naturally-aligned reads and writes.
            if off % 4 != 0 {
                return TestResult::Fail("a CSR offset is not 4-byte aligned");
            }
        }

        // The HBUS window's four registers are distinct and ordered
        // WADDR, RADDR, WDAT, RDAT at +0x44..+0x50 from HBUS_BASE.
        const HBUS_BASE: u32 = 0x400;
        if regs::HBUS_TARG_PRPH_WADDR != HBUS_BASE + 0x44
            || regs::HBUS_TARG_PRPH_RADDR != HBUS_BASE + 0x48
            || regs::HBUS_TARG_PRPH_WDAT != HBUS_BASE + 0x4C
            || regs::HBUS_TARG_PRPH_RDAT != HBUS_BASE + 0x50
        {
            return TestResult::Fail("HBUS PRPH window registers are not at their offsets");
        }

        // PRPH addresses go *through* that window, so they are not
        // bounded by BAR0 — but they do all live in the peripheral
        // range, and one small enough to look like a CSR offset is
        // the symptom of the same confusion.
        let prph_addrs: &[u32] = &[
            regs::UREG_DOORBELL_TO_ISR6,
            regs::PRPH_UREG_UCODE_LOAD_STATUS,
            regs::PRPH_WFPM_OTP_CFG1_ADDR,
            regs::PRPH_LMPM_CHICK,
        ];
        for a in prph_addrs {
            if *a < BAR0_BYTES {
                return TestResult::Fail("a PRPH address is small enough to be a CSR offset");
            }
            if a % 4 != 0 {
                return TestResult::Fail("a PRPH address is not 4-byte aligned");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_csr_offsets_fit_in_bar0
    );

    /// Pin the register values that were wrong, each against the
    /// Linux symbol it mirrors. These are not derivable from anything
    /// in the tree, so a typo in one is invisible without a reference
    /// to compare against.
    fn smoke_iwlwifi_register_values_match_linux() -> TestResult {
        use super::regs;

        // (ours, linux value, linux symbol)
        let pinned: &[(u32, u32, &str)] = &[
            (regs::HBUS_TARG_PRPH_WADDR, 0x444, "HBUS_TARG_PRPH_WADDR"),
            (regs::HBUS_TARG_PRPH_RADDR, 0x448, "HBUS_TARG_PRPH_RADDR"),
            (regs::HBUS_TARG_PRPH_WDAT, 0x44C, "HBUS_TARG_PRPH_WDAT"),
            (regs::HBUS_TARG_PRPH_RDAT, 0x450, "HBUS_TARG_PRPH_RDAT"),
            (regs::CSR_CTXT_INFO_ADDR, 0x118, "CSR_CTXT_INFO_ADDR"),
            (regs::CSR_IML_DATA_ADDR, 0x120, "CSR_IML_DATA_ADDR"),
            (regs::CSR_IML_SIZE_ADDR, 0x128, "CSR_IML_SIZE_ADDR"),
            (
                regs::CSR_CTXT_INFO_BOOT_CTRL,
                0x0,
                "CSR_CTXT_INFO_BOOT_CTRL",
            ),
            (
                regs::UREG_DOORBELL_TO_ISR6,
                0x00A0_5C04,
                "UREG_DOORBELL_TO_ISR6",
            ),
            (
                regs::PRPH_UREG_UCODE_LOAD_STATUS,
                0x00A0_5C40,
                "UREG_UCODE_LOAD_STATUS",
            ),
            (
                regs::PRPH_WFPM_OTP_CFG1_ADDR,
                0x00A0_3098,
                "WFPM_OTP_CFG1_ADDR",
            ),
            (regs::PRPH_LMPM_CHICK, 0x00A0_1FF8, "LMPM_CHICK"),
            (regs::PRPH_RELEASE_CPU_RESET, 0x300C, "RELEASE_CPU_RESET"),
            (regs::IWL_ALIVE_STATUS_OK, 0xCAFE, "IWL_ALIVE_STATUS_OK"),
        ];
        for (ours, linux, sym) in pinned {
            let _ = sym;
            if ours != linux {
                return TestResult::Fail("a register constant no longer matches its Linux value");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_register_values_match_linux
    );

    /// The gen2/gen3 descriptor sizes are load-bearing: the device
    /// strides through the TFD ring by descriptor size and through a
    /// TFD's buffers by entry size, so a struct that is the wrong
    /// width desynchronises everything after the first entry. These
    /// are exactly the numbers the hardware documentation states —
    /// 10-byte transmit buffers and 256-byte descriptors.
    fn smoke_iwlwifi_gen2_descriptor_layout() -> TestResult {
        use super::tx_gen2::*;
        use core::mem::size_of;

        if size_of::<TfhTb>() != 10 {
            return TestResult::Fail("iwl_tfh_tb must be 10 bytes (len then 64-bit addr, packed)");
        }
        if size_of::<TfhTfd>() != 256 {
            return TestResult::Fail("iwl_tfh_tfd must be 256 bytes");
        }
        // 2 + 25*10 + 4 = 256; if any of the three changes the total
        // has to be rechecked against the hardware, not just patched.
        if TBS_OFFSET + IWL_TFH_NUM_TBS * size_of::<TfhTb>() + 4 != size_of::<TfhTfd>() {
            return TestResult::Fail("TFD size is not num_tbs + 25 buffers + pad");
        }

        // AX210+: len, flags(16), offload_assist(32), dram(8),
        // rate_n_flags(32), reserved[8] = 28.
        if size_of::<DramSecInfo>() != 8 {
            return TestResult::Fail("iwl_dram_sec_info must be 8 bytes");
        }
        if size_of::<TxCmdAx210>() != 28 {
            return TestResult::Fail("AX210+ iwl_tx_cmd must be 28 bytes");
        }
        // 22000-series: len, offload_assist(16), flags(32), dram(8),
        // rate_n_flags(32) = 20. Different size as well as different
        // field order, which is the cheapest way to catch a mix-up.
        if size_of::<TxCmdV9>() != 20 {
            return TestResult::Fail("iwl_tx_cmd_v9 must be 20 bytes");
        }
        if size_of::<TxCmdAx210>() == size_of::<TxCmdV9>() {
            return TestResult::Fail("the two TX command layouts must not be interchangeable");
        }
        if size_of::<BcTblEntry>() != 2 {
            return TestResult::Fail("iwl_bc_tbl_entry must be a single 16-bit word");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_descriptor_layout
    );

    /// Appending transmit buffers has to keep `num_tbs` and the entry
    /// array in step, mask the count to five bits, and refuse a
    /// buffer the DMA engine would read from the wrong address.
    fn smoke_iwlwifi_gen2_tfd_push_tb() -> TestResult {
        use super::tx_gen2::*;

        let mut tfd = TfhTfd::default();
        if tfd.num_tbs() != 0 {
            return TestResult::Fail("a fresh TFD has no buffers");
        }

        match tfd.push_tb(0x1234_5000, 64) {
            Ok(0) => {}
            _ => return TestResult::Fail("the first buffer should land at index 0"),
        }
        match tfd.push_tb(0x1234_6000, 128) {
            Ok(1) => {}
            _ => return TestResult::Fail("the second buffer should land at index 1"),
        }
        if tfd.num_tbs() != 2 {
            return TestResult::Fail("num_tbs should track the appended buffers");
        }
        // Read back through copies: the fields are packed, so they
        // cannot be referenced directly.
        let (len0, addr0) = (tfd.tbs[0].tb_len, tfd.tbs[0].addr);
        let (len1, addr1) = (tfd.tbs[1].tb_len, tfd.tbs[1].addr);
        if (len0, addr0) != (64, 0x1234_5000) || (len1, addr1) != (128, 0x1234_6000) {
            return TestResult::Fail("buffer length and address stored wrong");
        }

        // Filling to capacity then one more.
        let mut full = TfhTfd::default();
        for i in 0..IWL_TFH_NUM_TBS {
            if full.push_tb(0x1000 + (i as u64) * 0x1000, 16).is_err() {
                return TestResult::Fail("should accept exactly IWL_TFH_NUM_TBS buffers");
            }
        }
        if full.num_tbs() as usize != IWL_TFH_NUM_TBS {
            return TestResult::Fail("a full TFD should report 25 buffers");
        }
        if full.push_tb(0x9_0000, 16) != Err(TfdError::Full) {
            return TestResult::Fail("a 26th buffer must be refused");
        }

        // Reserved bits above the count must survive an append —
        // the device owns them.
        let mut reserved = TfhTfd {
            num_tbs: 0xFFE0,
            ..TfhTfd::default()
        };
        if reserved.push_tb(0x2000, 8) != Ok(0) {
            return TestResult::Fail("reserved bits must not be read as a buffer count");
        }
        if reserved.num_tbs & !NUM_TBS_MASK != 0xFFE0 {
            return TestResult::Fail("appending must not clobber the reserved bits");
        }
        if reserved.num_tbs() != 1 {
            return TestResult::Fail("the count should be 1 after one append");
        }

        // A buffer straddling 4 GiB is read from the wrong address by
        // the DMA engine, which computes the end without carrying.
        if !crosses_4gib(0xFFFF_FFF0, 32) {
            return TestResult::Fail("a buffer spanning the 4 GiB line should be detected");
        }
        if crosses_4gib(0xFFFF_FF00, 16) {
            return TestResult::Fail("a buffer ending exactly at 4 GiB does not cross it");
        }
        if crosses_4gib(0x1_0000_0000, 64) {
            return TestResult::Fail("a buffer wholly above 4 GiB does not cross a boundary");
        }
        let mut bad = TfhTfd::default();
        match bad.push_tb(0xFFFF_FFF0, 32) {
            Err(TfdError::CrossesFourGiB { .. }) => {}
            _ => return TestResult::Fail("a 4 GiB-crossing buffer must be refused"),
        }
        if bad.num_tbs() != 0 {
            return TestResult::Fail("a refused buffer must not be counted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_gen2_tfd_push_tb);

    /// The byte-count table tells the device both how long the frame
    /// is and how many 64-byte chunks of the descriptor to fetch.
    /// AX210+ carries the length in bytes; everything before it
    /// carries dwords and shifts the chunk count four bits higher.
    fn smoke_iwlwifi_gen2_byte_count_entry() -> TestResult {
        use super::tx_gen2::*;

        // A TFD with three buffers is 2 + 30 = 32 bytes filled, which
        // is one 64-byte chunk — encoded as zero.
        let mut tfd = TfhTfd::default();
        for i in 0..3 {
            let _ = tfd.push_tb(0x1000 + (i as u64) * 0x1000, 100);
        }
        if tfd.filled_bytes() != 32 {
            return TestResult::Fail("three buffers should fill 32 bytes of the TFD");
        }
        if fetch_chunks(32) != 0 {
            return TestResult::Fail("32 bytes is one chunk, encoded as 0");
        }
        // 64 bytes is still one chunk; 65 needs two.
        if fetch_chunks(64) != 0 || fetch_chunks(65) != 1 || fetch_chunks(128) != 1 {
            return TestResult::Fail("chunk count should be DIV_ROUND_UP(filled,64) - 1");
        }
        // A full TFD: 2 + 250 = 252 bytes -> four chunks -> 3.
        let mut full = TfhTfd::default();
        for i in 0..IWL_TFH_NUM_TBS {
            let _ = full.push_tb(0x1000 + (i as u64) * 0x1000, 16);
        }
        if full.filled_bytes() != 252 || fetch_chunks(full.filled_bytes()) != 3 {
            return TestResult::Fail("a full TFD is 252 filled bytes and four fetch chunks");
        }

        // AX210+ packs raw bytes with the chunk count at bit 14.
        match bc_entry_ax210(1500, 32) {
            Ok(e) if e.tfd_offset == 1500 => {}
            _ => return TestResult::Fail("AX210 entry should carry the byte length unscaled"),
        }
        match bc_entry_ax210(1500, 252) {
            Ok(e) if e.tfd_offset == 1500 | (3 << 14) => {}
            _ => return TestResult::Fail("AX210 entry should put the chunk count at bit 14"),
        }
        if bc_entry_ax210(0x4000, 32) != Err(BcError::LengthTooLarge(0x4000)) {
            return TestResult::Fail("a length needing more than 14 bits must be refused");
        }
        match bc_entry_ax210(BC_MAX_LEN_AX210, 32) {
            Ok(e) if e.tfd_offset == BC_MAX_LEN_AX210 => {}
            _ => return TestResult::Fail("0x3fff is the largest length that fits"),
        }

        // Pre-AX210 rounds up to dwords and shifts the count to 12.
        match bc_entry_pre_ax210(1500, 32) {
            Ok(e) if e.tfd_offset == 375 => {}
            _ => return TestResult::Fail("pre-AX210 should carry length in dwords"),
        }
        match bc_entry_pre_ax210(1501, 32) {
            Ok(e) if e.tfd_offset == 376 => {}
            _ => return TestResult::Fail("pre-AX210 dword length should round up"),
        }
        match bc_entry_pre_ax210(1500, 252) {
            Ok(e) if e.tfd_offset == 375 | (3 << 12) => {}
            _ => return TestResult::Fail("pre-AX210 should put the chunk count at bit 12"),
        }
        // The two encodings must not agree, or one silently stands in
        // for the other.
        let a = bc_entry_ax210(1500, 252);
        let b = bc_entry_pre_ax210(1500, 252);
        if a == b {
            return TestResult::Fail("the two byte-count encodings must differ");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_byte_count_entry
    );

    /// Gen2 rings every queue through one CSR, with the queue id in
    /// the written value. RX queues are offset by 512 so RX queue 0
    /// cannot ring TX queue 0 — the whole point of the encoding.
    fn smoke_iwlwifi_gen2_doorbell_encoding() -> TestResult {
        use super::tx_gen2::*;

        if HBUS_TARG_WRPTR != 0x460 {
            return TestResult::Fail("HBUS_TARG_WRPTR should be HBUS_BASE + 0x60");
        }
        // The doorbell is a CSR offset, so it must be inside BAR0.
        if HBUS_TARG_WRPTR >= 16 * 1024 {
            return TestResult::Fail("the doorbell must lie inside BAR0");
        }

        if tx_doorbell(0, 7) != 7 {
            return TestResult::Fail("TX queue 0 should encode to the bare write pointer");
        }
        if tx_doorbell(3, 0x2A) != 0x2A | (3 << 16) {
            return TestResult::Fail("the TX queue id belongs at bit 16");
        }
        if rx_doorbell(0, 0x10) != 0x10 | (512 << 16) {
            return TestResult::Fail("RX queue 0 should encode as queue 512");
        }
        if rx_doorbell(1, 0x10) != 0x10 | (513 << 16) {
            return TestResult::Fail("RX queue ids should be offset by 512");
        }
        if tx_doorbell(0, 0x10) == rx_doorbell(0, 0x10) {
            return TestResult::Fail("TX and RX queue 0 must not share a doorbell value");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_gen2_doorbell_encoding
    );

    /// Gen2 queues are created by a host command that hands the
    /// firmware the rings the driver allocated. The ring depth is
    /// carried as a biased exponent, which only encodes powers of two
    /// between 8 and 256.
    fn smoke_iwlwifi_gen2_queue_cfg() -> TestResult {
        use super::tx_gen2::*;
        use core::mem::size_of;

        if size_of::<TxQueueCfgCmd>() != 24 {
            return TestResult::Fail("iwl_tx_queue_cfg_cmd must be 24 bytes");
        }
        if size_of::<TxQueueCfgRsp>() != 8 {
            return TestResult::Fail("iwl_tx_queue_cfg_rsp must be 8 bytes");
        }

        // log2(depth) - 3: 8 TFDs is 0, 256 is 5.
        if cb_size_for(8) != Ok(0) {
            return TestResult::Fail("8 TFDs should encode as 0");
        }
        if cb_size_for(256) != Ok(5) {
            return TestResult::Fail("256 TFDs should encode as 5");
        }
        if cb_size_for(IWL_MGMT_QUEUE_SIZE) != Ok(1) {
            return TestResult::Fail("the 16-slot management queue should encode as 1");
        }
        if cb_size_for(IWL_CMD_QUEUE_SIZE) != Ok(2) {
            return TestResult::Fail("the 32-slot command queue should encode as 2");
        }

        // A depth with no encoding is refused rather than rounded:
        // serving a 200-slot ring as 128 would leave host and
        // firmware disagreeing about where the ring wraps.
        if cb_size_for(200) != Err(QueueCfgError::NotPowerOfTwo(200)) {
            return TestResult::Fail("a non-power-of-two depth must be refused");
        }
        if cb_size_for(4) != Err(QueueCfgError::DepthOutOfRange(4)) {
            return TestResult::Fail("a depth below 8 must be refused");
        }
        if cb_size_for(512) != Err(QueueCfgError::DepthOutOfRange(512)) {
            return TestResult::Fail("a depth above 256 must be refused");
        }

        let cmd = match TxQueueCfgCmd::enable(0, 7, 256, 0x1234_0000, 0x5678_0000) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("a 256-deep queue should be describable"),
        };
        let (sta, tid, flags, cb) = (cmd.sta_id, cmd.tid, cmd.flags, cmd.cb_size);
        let (bc, tfdq) = (cmd.byte_cnt_addr, cmd.tfdq_addr);
        if (sta, tid, cb) != (0, 7, 5) {
            return TestResult::Fail("queue config fields stored wrong");
        }
        if flags & TX_QUEUE_CFG_ENABLE_QUEUE == 0 {
            return TestResult::Fail("an enable command must set the enable bit");
        }
        if (bc, tfdq) != (0x1234_0000, 0x5678_0000) {
            return TestResult::Fail("the ring addresses must not be transposed");
        }

        // The AX210+ byte-count table is a fixed 1024 entries, not
        // one per ring slot: a 16-slot management queue still needs
        // the full 2 KiB, and sizing it from the ring would hand the
        // firmware a table it writes past the end of.
        if BC_TABLE_BYTES_AX210 != 2048 {
            return TestResult::Fail("an AX210+ byte-count table is 1024 entries of 2 bytes");
        }
        if bc_table_bytes_pre_ax210(256) != (256 + 64) * 2 {
            return TestResult::Fail("pre-AX210 tables are ring depth plus the 64-entry dup");
        }
        if bc_table_bytes_pre_ax210(IWL_MGMT_QUEUE_SIZE) >= BC_TABLE_BYTES_AX210 {
            return TestResult::Fail("the two table sizings should not coincide");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_gen2_queue_cfg);

    /// The RFH splits receive into a free list the host posts onto
    /// and a used list the device returns on, each with its own
    /// stride. A wrong descriptor size desynchronises the ring after
    /// the first entry, and the Bz and AX210 completion layouts put
    /// `rbid` at different offsets, so reading one as the other
    /// yields a tag for the wrong buffer.
    fn smoke_iwlwifi_rfh_descriptor_layout() -> TestResult {
        use super::rx_rfh::*;
        use core::mem::size_of;

        if size_of::<RxTransferDesc>() != 16 {
            return TestResult::Fail("iwl_rx_transfer_desc must be 16 bytes");
        }
        if size_of::<RxCompletionDesc>() != 32 {
            return TestResult::Fail("the AX210 completion descriptor must be 32 bytes");
        }
        if size_of::<RxCompletionDescBz>() != 4 {
            return TestResult::Fail("the Bz completion descriptor must be 4 bytes");
        }
        if CompletionFormat::Ax210.size() != 32 || CompletionFormat::Bz.size() != 4 {
            return TestResult::Fail("completion stride must match the descriptor size");
        }

        // The same bytes must decode differently under the two
        // formats — that is the whole hazard. Here rbid is 0x1111 at
        // offset 4 for AX210 and 0xAAAA at offset 0 for Bz.
        let raw = [
            0xAAu8,
            0xAA,
            0x00,
            0x00,
            0x11,
            0x11,
            RX_CD_FLAGS_FRAGMENTED,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        match CompletionFormat::Ax210.decode(&raw) {
            Some((0x1111, true)) => {}
            _ => return TestResult::Fail("AX210 rbid sits at offset 4, flags at 6"),
        }
        match CompletionFormat::Bz.decode(&raw) {
            Some((0xAAAA, false)) => {}
            _ => return TestResult::Fail("Bz rbid sits at offset 0, flags at 2"),
        }
        if CompletionFormat::Ax210.decode(&raw) == CompletionFormat::Bz.decode(&raw) {
            return TestResult::Fail("the two completion formats must not decode alike");
        }

        // A short buffer must be refused rather than read past.
        if CompletionFormat::Ax210.decode(&raw[..31]).is_some() {
            return TestResult::Fail("a truncated AX210 descriptor must not decode");
        }
        if CompletionFormat::Bz.decode(&raw[..3]).is_some() {
            return TestResult::Fail("a truncated Bz descriptor must not decode");
        }
        // Four bytes is enough for Bz but not for AX210.
        if CompletionFormat::Bz.decode(&raw[..4]).is_none() {
            return TestResult::Fail("four bytes is a whole Bz descriptor");
        }
        if CompletionFormat::Ax210.decode(&raw[..4]).is_some() {
            return TestResult::Fail("four bytes is not a whole AX210 descriptor");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwlwifi_rfh_descriptor_layout
    );

    /// The RFH register block is PRPH except for the write-index
    /// shadow, which is a direct CSR. Mixing those up sends an index
    /// through the HBUS window to an address the device does not
    /// decode — the same namespace confusion that put the PRPH
    /// window registers 4.5 MiB outside BAR0.
    fn smoke_iwlwifi_rfh_register_block() -> TestResult {
        use super::rx_rfh::*;

        const BAR0_BYTES: u32 = 16 * 1024;

        // Every RFH register but the shadow is a PRPH address.
        let prph: &[u32] = &[
            RFH_Q0_FRBDCB_BA_LSB,
            RFH_Q0_FRBDCB_WIDX,
            RFH_Q0_FRBDCB_RIDX,
            RFH_Q0_URBDCB_BA_LSB,
            RFH_Q0_URBDCB_WIDX,
            RFH_Q0_URBDCB_VAID,
            RFH_Q0_URBD_STTS_WPTR_LSB,
        ];
        for a in prph {
            if *a < BAR0_BYTES {
                return TestResult::Fail("an RFH PRPH address is small enough to be a CSR offset");
            }
            if a % 4 != 0 {
                return TestResult::Fail("an RFH PRPH address is not 4-byte aligned");
            }
        }
        // The shadow is the exception and must stay inside BAR0.
        if RFH_Q0_FRBDCB_WIDX_TRG >= BAR0_BYTES || RFH_Q0_FRBDCB_WIDX_TRG != 0x1C80 {
            return TestResult::Fail("the write-index shadow is a CSR at 0x1c80");
        }

        // Per-queue striding: 64-bit registers step by 8, 32-bit by 4.
        if rfh_frbdcb_ba_lsb(0) != RFH_Q0_FRBDCB_BA_LSB
            || rfh_frbdcb_ba_lsb(3) != RFH_Q0_FRBDCB_BA_LSB + 24
        {
            return TestResult::Fail("64-bit RFH registers stride by 8");
        }
        if rfh_urbd_stts_wptr_lsb(2) != RFH_Q0_URBD_STTS_WPTR_LSB + 16 {
            return TestResult::Fail("the write-back pointer strides by 8");
        }
        if rfh_frbdcb_widx(0) != RFH_Q0_FRBDCB_WIDX || rfh_frbdcb_widx(3) != RFH_Q0_FRBDCB_WIDX + 12
        {
            return TestResult::Fail("32-bit RFH registers stride by 4");
        }
        if rfh_frbdcb_ridx(1) != RFH_Q0_FRBDCB_RIDX + 4 {
            return TestResult::Fail("the read index strides by 4");
        }
        if rfh_urbdcb_widx(1) != RFH_Q0_URBDCB_WIDX + 4 {
            return TestResult::Fail("the used-list write index strides by 4");
        }
        if rfh_frbdcb_widx_trg(1) != 0x1C84 {
            return TestResult::Fail("the shadow index strides by 4");
        }

        // The free and used lists must not collide: queue 0's used
        // list base has to sit past the last free-list write index.
        if RFH_Q0_URBDCB_BA_LSB <= RFH_Q0_FRBDCB_RIDX {
            return TestResult::Fail("the used-list block should follow the free-list block");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi", smoke_iwlwifi_rfh_register_block);
}
