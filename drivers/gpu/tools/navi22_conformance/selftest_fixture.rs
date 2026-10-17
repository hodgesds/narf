// Self-test fixture for check_constants.py (never compiled). Every line tagged
// `expect: bad` must be reported; every other annotated line must pass. The
// two bad values are the boot-blockers the first Navi22 conformance review
// found and every model test accepted.
// linux-ctx: hdr=dcn seg=2
const FB_LOCATION_BASE_WRONG: u32 = 0x475; // linux: mmDCN_VM_FB_LOCATION_BASE  expect: bad
const FB_LOCATION_BASE: u32 = 0x493; // linux: mmDCN_VM_FB_LOCATION_BASE
// linux-ctx: hdr=dcn seg=0
const FB_LOCATION_SEGMENT_WRONG: u32 = 0x493; // linux: mmDCN_VM_FB_LOCATION_BASE  expect: bad
// linux-ctx: reset
const PSP_RING_TYPE_KM_WRONG: u32 = 1 << 16; // linux: PSP_RING_TYPE__KM << 16  expect: bad
const PSP_RING_TYPE_KM: u32 = 2 << 16; // linux: PSP_RING_TYPE__KM << 16
pub const CP_MEC_CNTL: Reg = Reg(0, 0x0f55); // linux: mmCP_MEC_CNTL_Sienna_Cichlid
pub const CP_MEC_CNTL_IDX_WRONG: Reg = Reg(1, 0x0f55); // linux: mmCP_MEC_CNTL  expect: bad
// linux: mmVGT_TF_RING_SIZE_UMD@gc101; mmVGT_TF_RING_SIZE_Sienna_Cichlid
    (Reg(1, 0x224e), Reg(0, 0x0fc3)),
const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
const DIG_MODE: u32 = 0x0007_0000; // linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
const IH_RB_CNTL_ABS: u64 = 0x1120; // linux: abs(mmIH_RB_CNTL)
const C2PMSG_64_BYTES: u64 = 0x58200; // linux: bytes(mmMP0_SMN_C2PMSG_64)
const RLC_V24_SIZE: usize = 244; // linux: sizeof(struct rlc_firmware_header_v2_4)
const RLC_SRM_CNTL_SIZE: usize = 116; // linux: offsetof(struct rlc_firmware_header_v2_1, save_restore_list_cntl_size_bytes)
const TIMEOUT_US: u32 = 100_000; // linux: n/a (NARF policy)
fn kinds() {
    // linux-lit: 22=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL; 0x21=GFX_CMD_ID_AUTOLOAD_RLC
    if matches!(kind, 22 | 20) { submit(command(0x21, &[])); }
    // linux-lit: 6=GFX_CMD_ID_LOAD_IP_FW; 7=GFX_CMD_ID_LOAD_IP_FW  expect: bad
    load_command(6, 7);
}
