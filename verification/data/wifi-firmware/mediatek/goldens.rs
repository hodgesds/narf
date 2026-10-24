// Generated factual tables only; no executable or CLC payload.
#[rustfmt::skip]
const PATCH_GOLDENS: &[PatchGolden] = &[
    PatchGolden {
        source: "mediatek/WIFI_MT7961_patch_mcu_1a_2_hdr.bin",
        source_sha256: "a766c4e39815e554c80ce5b1596095ff283a60db93356679fecd6494f71cee23",
        image_len: 100384,
        metadata: include_bytes!("mt7920_patch.metadata.bin"),
        header: Connac2PatchHdr {
            build_date: [50, 48, 50, 54, 48, 50, 50, 52, 49, 49, 48, 56, 53, 55, 97, 10],
            platform: [65, 76, 80, 83],
            hw_sw_ver: 2316339728,
            patch_ver: 4294967295,
            checksum: 0,
            n_region: 1,
        },
        regions: &[
            Connac2PatchSection { sec_type: 262146, offset: 160, size: 100224, addr: 9437184, len: 100224, sec_key_idx: 0 },
        ],
    },
    PatchGolden {
        source: "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin",
        source_sha256: "a276c06c2b772adb50b86639d33c82824ff4c21d617feb78caea74c040b873f6",
        image_len: 92192,
        metadata: include_bytes!("mt7921_patch.metadata.bin"),
        header: Connac2PatchHdr {
            build_date: [50, 48, 50, 54, 48, 50, 50, 52, 49, 49, 48, 57, 48, 57, 97, 10],
            platform: [65, 76, 80, 83],
            hw_sw_ver: 2316339728,
            patch_ver: 4294967295,
            checksum: 0,
            n_region: 1,
        },
        regions: &[
            Connac2PatchSection { sec_type: 262146, offset: 160, size: 92032, addr: 9437184, len: 92032, sec_key_idx: 0 },
        ],
    },
    PatchGolden {
        source: "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin",
        source_sha256: "490f19974ac232b2f95d995091e2e0d578521354c07f41cf9f0c198fce83b46d",
        image_len: 137632,
        metadata: include_bytes!("mt7922_patch.metadata.bin"),
        header: Connac2PatchHdr {
            build_date: [50, 48, 50, 54, 48, 54, 48, 53, 50, 48, 51, 51, 48, 55, 97, 10],
            platform: [65, 76, 80, 83],
            hw_sw_ver: 2316339728,
            patch_ver: 4294967295,
            checksum: 0,
            n_region: 1,
        },
        regions: &[
            Connac2PatchSection { sec_type: 262146, offset: 160, size: 137472, addr: 9437184, len: 137472, sec_key_idx: 16777216 },
        ],
    },
];

#[rustfmt::skip]
const RAM_GOLDENS: &[RamGolden] = &[
    RamGolden {
        source: "mediatek/WIFI_RAM_CODE_MT7961_1a.bin",
        source_sha256: "3edec74ffe341b917e7fa4ddb2b68851411f2416555f10619a5900fa4b141e6c",
        image_len: 802808,
        metadata: include_bytes!("mt7920_ram.metadata.bin"),
        trailer: Connac2FwTrailer {
            chip_id: 13,
            eco_code: 1,
            n_region: 5,
            format_ver: 2,
            format_flag: 1,
            fw_ver: [95, 95, 95, 95, 48, 48, 48, 48, 48, 48],
            build_date: [50, 48, 50, 54, 48, 50, 50, 52, 49, 49, 48, 57, 51, 57, 0],
            crc: 3184882402,
        },
        regions: &[
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 9523200, len: 363536, feature_set: 32, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 33643520, len: 271376, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 4211712, len: 15376, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 3760652288, len: 30224, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 0, len: 121904, feature_set: 64, region_type: 2 },
        ],
    },
    RamGolden {
        source: "mediatek/WIFI_RAM_CODE_MT7961_1.bin",
        source_sha256: "b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9",
        image_len: 792036,
        metadata: include_bytes!("mt7921_ram.metadata.bin"),
        trailer: Connac2FwTrailer {
            chip_id: 13,
            eco_code: 1,
            n_region: 5,
            format_ver: 2,
            format_flag: 1,
            fw_ver: [95, 95, 95, 95, 48, 49, 48, 48, 48, 48],
            build_date: [50, 48, 50, 54, 48, 50, 50, 52, 49, 49, 48, 57, 52, 57, 0],
            crc: 1467327626,
        },
        regions: &[
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 9523200, len: 363536, feature_set: 32, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 33643520, len: 272400, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 4211712, len: 15376, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 3760652288, len: 51920, feature_set: 0, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 0, len: 88416, feature_set: 64, region_type: 2 },
        ],
    },
    RamGolden {
        source: "mediatek/WIFI_RAM_CODE_MT7922_1.bin",
        source_sha256: "d95cef824e8fd6a51324a04eca067c2a005239451f471a96a83d0190b022e7fe",
        image_len: 1122084,
        metadata: include_bytes!("mt7922_ram.metadata.bin"),
        trailer: Connac2FwTrailer {
            chip_id: 16,
            eco_code: 0,
            n_region: 6,
            format_ver: 2,
            format_flag: 1,
            fw_ver: [95, 95, 95, 95, 48, 48, 48, 48, 48, 48],
            build_date: [50, 48, 50, 54, 48, 54, 48, 53, 50, 48, 51, 52, 49, 49, 0],
            crc: 365595124,
        },
        regions: &[
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 9547776, len: 341904, feature_set: 33, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 33643520, len: 292816, feature_set: 1, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 4211712, len: 15312, feature_set: 1, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 34643968, len: 8144, feature_set: 1, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 3760193536, len: 97040, feature_set: 1, region_type: 0 },
            Connac2FwRegion { decomp_crc: 0, decomp_len: 0, decomp_blk_sz: 0, addr: 0, len: 366448, feature_set: 64, region_type: 2 },
        ],
    },
];
