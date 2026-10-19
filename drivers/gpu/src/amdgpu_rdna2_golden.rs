//! Discrete RDNA2 golden sequences, in Linux gfx_v10_0_init_golden_registers order.
//! Register names resolve through gc_10_1_0_offset.h plus gfx_v10_0.c's local
//! overrides. check_rdna2_profiles.py compares every compiled row with Linux.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Golden {
    pub base_index: u8,
    pub offset: u32,
    pub and_mask: u32,
    pub or_mask: u32,
}

pub const NAVI21: &[Golden] = &[
    // Linux golden_settings_gc_10_3 (43 rows).
    // mmCGTT_SPI_CS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507c,
        and_mask: 0x78000000,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_PS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507d,
        and_mask: 0xff7f0fff,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_RA0_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507a,
        and_mask: 0xff7f0fff,
        or_mask: 0x30000100,
    },
    // mmCGTT_SPI_RA1_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507b,
        and_mask: 0xff7f0fff,
        or_mask: 0x7e000100,
    },
    // mmCPF_GCR_CNTL
    Golden {
        base_index: 0,
        offset: 0x1f53,
        and_mask: 0x0007ffff,
        or_mask: 0x0000c000,
    },
    // mmDB_DEBUG3
    Golden {
        base_index: 0,
        offset: 0x13ae,
        and_mask: 0xffffffff,
        or_mask: 0x00000280,
    },
    // mmDB_DEBUG4
    Golden {
        base_index: 0,
        offset: 0x13af,
        and_mask: 0xffffffff,
        or_mask: 0x00800000,
    },
    // mmDB_EXCEPTION_CONTROL
    Golden {
        base_index: 0,
        offset: 0x13bf,
        and_mask: 0x7fff0f1f,
        or_mask: 0x00b80000,
    },
    // mmGCEA_SDP_TAG_RESERVE0
    Golden {
        base_index: 0,
        offset: 0x189b,
        and_mask: 0xffffffff,
        or_mask: 0x10100100,
    },
    // mmGCEA_SDP_TAG_RESERVE1
    Golden {
        base_index: 0,
        offset: 0x189c,
        and_mask: 0xffffffff,
        or_mask: 0x17000088,
    },
    // mmGCR_GENERAL_CNTL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x1580,
        and_mask: 0x1ff1ffff,
        or_mask: 0x00000500,
    },
    // mmGCUTCL2_CGTT_CLK_CTRL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x16f3,
        and_mask: 0xff000000,
        or_mask: 0xff008080,
    },
    // mmGCVM_L2_CGTT_CLK_CTRL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x15db,
        and_mask: 0xff000000,
        or_mask: 0xff008080,
    },
    // mmGE_PC_CNTL
    Golden {
        base_index: 0,
        offset: 0x0fe5,
        and_mask: 0x003fffff,
        or_mask: 0x00280400,
    },
    // mmGL2A_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e21,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e03,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_CM_CTRL1
    Golden {
        base_index: 1,
        offset: 0x2e08,
        and_mask: 0xff8fff0f,
        or_mask: 0x580f1008,
    },
    // mmGL2C_CTRL3
    Golden {
        base_index: 1,
        offset: 0x2e0c,
        and_mask: 0xf7ffffff,
        or_mask: 0x10f80988,
    },
    // mmLDS_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a2,
        and_mask: 0x00000020,
        or_mask: 0x00000020,
    },
    // mmPA_CL_ENHANCE
    Golden {
        base_index: 0,
        offset: 0x1025,
        and_mask: 0xf17fffff,
        or_mask: 0x01200007,
    },
    // mmPA_SC_BINNER_TIMEOUT_COUNTER
    Golden {
        base_index: 0,
        offset: 0x1070,
        and_mask: 0xffffffff,
        or_mask: 0x00000800,
    },
    // mmPA_SC_ENHANCE_2
    Golden {
        base_index: 0,
        offset: 0x107c,
        and_mask: 0xffffffbf,
        or_mask: 0x00000820,
    },
    // mmSPI_CONFIG_CNTL_1
    Golden {
        base_index: 0,
        offset: 0x11ef,
        and_mask: 0xffffffff,
        or_mask: 0x00070104,
    },
    // mmSQ_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a0,
        and_mask: 0xe07df47f,
        or_mask: 0x00180070,
    },
    // mmSQ_PERFCOUNTER0_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c0,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER1_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c1,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER10_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ca,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER11_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cb,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER12_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cc,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER13_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cd,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER14_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ce,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER15_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cf,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER2_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c2,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER3_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c3,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER4_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c4,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER5_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c5,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER6_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c6,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER7_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c7,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER8_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c8,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER9_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c9,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSX_DEBUG_1
    Golden {
        base_index: 0,
        offset: 0x11b8,
        and_mask: 0x00010000,
        or_mask: 0x00010020,
    },
    // mmTA_CNTL_AUX
    Golden {
        base_index: 0,
        offset: 0x12e2,
        and_mask: 0xfff7ffff,
        or_mask: 0x01030000,
    },
    // mmUTCL1_CTRL
    Golden {
        base_index: 0,
        offset: 0x1588,
        and_mask: 0xffbfffff,
        or_mask: 0x00a00000,
    },
    // Linux golden_settings_gc_10_3_sienna_cichlid (0 rows).
];

pub const NAVI22: &[Golden] = &[
    // Linux golden_settings_gc_10_3_2 (42 rows).
    // mmCGTT_SPI_CS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507c,
        and_mask: 0xff7f0fff,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_PS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507d,
        and_mask: 0xff7f0fff,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_RA0_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507a,
        and_mask: 0xff7f0fff,
        or_mask: 0x30000100,
    },
    // mmCGTT_SPI_RA1_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507b,
        and_mask: 0xff7f0fff,
        or_mask: 0x7e000100,
    },
    // mmCPF_GCR_CNTL
    Golden {
        base_index: 0,
        offset: 0x1f53,
        and_mask: 0x0007ffff,
        or_mask: 0x0000c000,
    },
    // mmDB_DEBUG3
    Golden {
        base_index: 0,
        offset: 0x13ae,
        and_mask: 0xffffffff,
        or_mask: 0x00000280,
    },
    // mmDB_DEBUG4
    Golden {
        base_index: 0,
        offset: 0x13af,
        and_mask: 0xffffffff,
        or_mask: 0x00800000,
    },
    // mmDB_EXCEPTION_CONTROL
    Golden {
        base_index: 0,
        offset: 0x13bf,
        and_mask: 0x7fff0f1f,
        or_mask: 0x00b80000,
    },
    // mmGCR_GENERAL_CNTL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x1580,
        and_mask: 0x1ff1ffff,
        or_mask: 0x00000500,
    },
    // mmGCUTCL2_CGTT_CLK_CTRL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x16f3,
        and_mask: 0xffffffff,
        or_mask: 0xff008080,
    },
    // mmGCVM_L2_CGTT_CLK_CTRL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x15db,
        and_mask: 0xffff8fff,
        or_mask: 0xff008080,
    },
    // mmGE_PC_CNTL
    Golden {
        base_index: 0,
        offset: 0x0fe5,
        and_mask: 0x003fffff,
        or_mask: 0x00280400,
    },
    // mmGL2A_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e21,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e03,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_CM_CTRL1
    Golden {
        base_index: 1,
        offset: 0x2e08,
        and_mask: 0xff8fff0f,
        or_mask: 0x580f1008,
    },
    // mmGL2C_CTRL3
    Golden {
        base_index: 1,
        offset: 0x2e0c,
        and_mask: 0xf7ffffff,
        or_mask: 0x00f80988,
    },
    // mmPA_CL_ENHANCE
    Golden {
        base_index: 0,
        offset: 0x1025,
        and_mask: 0xf17fffff,
        or_mask: 0x01200007,
    },
    // mmPA_SC_BINNER_TIMEOUT_COUNTER
    Golden {
        base_index: 0,
        offset: 0x1070,
        and_mask: 0xffffffff,
        or_mask: 0x00000800,
    },
    // mmPA_SC_ENHANCE_2
    Golden {
        base_index: 0,
        offset: 0x107c,
        and_mask: 0xffffffbf,
        or_mask: 0x00000820,
    },
    // mmSPI_CONFIG_CNTL_1
    Golden {
        base_index: 0,
        offset: 0x11ef,
        and_mask: 0xffffffff,
        or_mask: 0x00070104,
    },
    // mmSPI_START_PHASE
    Golden {
        base_index: 0,
        offset: 0x11db,
        and_mask: 0x000000ff,
        or_mask: 0x00000004,
    },
    // mmSQ_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a0,
        and_mask: 0xe07df47f,
        or_mask: 0x00180070,
    },
    // mmSQ_PERFCOUNTER0_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c0,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER1_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c1,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER10_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ca,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER11_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cb,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER12_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cc,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER13_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cd,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER14_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ce,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER15_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cf,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER2_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c2,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER3_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c3,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER4_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c4,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER5_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c5,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER6_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c6,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER7_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c7,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER8_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c8,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER9_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c9,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmTA_CNTL_AUX
    Golden {
        base_index: 0,
        offset: 0x12e2,
        and_mask: 0xfff7ffff,
        or_mask: 0x01030000,
    },
    // mmUTCL1_CTRL
    Golden {
        base_index: 0,
        offset: 0x1588,
        and_mask: 0xffbfffff,
        or_mask: 0x00a00000,
    },
    // mmVGT_GS_MAX_WAVE_ID
    Golden {
        base_index: 0,
        offset: 0x1009,
        and_mask: 0x00000fff,
        or_mask: 0x000003ff,
    },
    // mmLDS_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a2,
        and_mask: 0x00000020,
        or_mask: 0x00000020,
    },
];

pub const NAVI23: &[Golden] = &[
    // Linux golden_settings_gc_10_3_4 (36 rows).
    // mmCGTT_SPI_CS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507c,
        and_mask: 0x78000000,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_RA0_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507a,
        and_mask: 0x30000000,
        or_mask: 0x30000100,
    },
    // mmCGTT_SPI_RA1_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507b,
        and_mask: 0x7e000000,
        or_mask: 0x7e000100,
    },
    // mmCPF_GCR_CNTL
    Golden {
        base_index: 0,
        offset: 0x1f53,
        and_mask: 0x0007ffff,
        or_mask: 0x0000c000,
    },
    // mmDB_DEBUG3
    Golden {
        base_index: 0,
        offset: 0x13ae,
        and_mask: 0x00000280,
        or_mask: 0x00000280,
    },
    // mmDB_DEBUG4
    Golden {
        base_index: 0,
        offset: 0x13af,
        and_mask: 0x07800000,
        or_mask: 0x00800000,
    },
    // mmGCR_GENERAL_CNTL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x1580,
        and_mask: 0x00001d00,
        or_mask: 0x00000500,
    },
    // mmGE_PC_CNTL
    Golden {
        base_index: 0,
        offset: 0x0fe5,
        and_mask: 0x003c0000,
        or_mask: 0x00280400,
    },
    // mmGL2A_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e21,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e03,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_CM_CTRL1
    Golden {
        base_index: 1,
        offset: 0x2e08,
        and_mask: 0x40000000,
        or_mask: 0x580f1008,
    },
    // mmGL2C_CTRL3
    Golden {
        base_index: 1,
        offset: 0x2e0c,
        and_mask: 0x00040000,
        or_mask: 0x00f80988,
    },
    // mmPA_CL_ENHANCE
    Golden {
        base_index: 0,
        offset: 0x1025,
        and_mask: 0x01000000,
        or_mask: 0x01200007,
    },
    // mmPA_SC_BINNER_TIMEOUT_COUNTER
    Golden {
        base_index: 0,
        offset: 0x1070,
        and_mask: 0xffffffff,
        or_mask: 0x00000800,
    },
    // mmPA_SC_ENHANCE_2
    Golden {
        base_index: 0,
        offset: 0x107c,
        and_mask: 0x00000800,
        or_mask: 0x00000820,
    },
    // mmSQ_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a0,
        and_mask: 0x0000001f,
        or_mask: 0x00180070,
    },
    // mmSQ_PERFCOUNTER0_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c0,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER1_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c1,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER10_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ca,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER11_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cb,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER12_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cc,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER13_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cd,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER14_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ce,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER15_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cf,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER2_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c2,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER3_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c3,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER4_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c4,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER5_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c5,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER6_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c6,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER7_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c7,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER8_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c8,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER9_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c9,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSX_DEBUG_1
    Golden {
        base_index: 0,
        offset: 0x11b8,
        and_mask: 0x00010000,
        or_mask: 0x00010020,
    },
    // mmTA_CNTL_AUX
    Golden {
        base_index: 0,
        offset: 0x12e2,
        and_mask: 0x01030000,
        or_mask: 0x01030000,
    },
    // mmUTCL1_CTRL
    Golden {
        base_index: 0,
        offset: 0x1588,
        and_mask: 0x03a00000,
        or_mask: 0x00a00000,
    },
    // mmLDS_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a2,
        and_mask: 0x00000020,
        or_mask: 0x00000020,
    },
];

pub const NAVI24: &[Golden] = &[
    // Linux golden_settings_gc_10_3_5 (32 rows).
    // mmCGTT_SPI_CS_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507c,
        and_mask: 0x78000000,
        or_mask: 0x78000100,
    },
    // mmCGTT_SPI_RA0_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507a,
        and_mask: 0xb0000ff0,
        or_mask: 0x30000100,
    },
    // mmCGTT_SPI_RA1_CLK_CTRL
    Golden {
        base_index: 1,
        offset: 0x507b,
        and_mask: 0xff000000,
        or_mask: 0x7e000100,
    },
    // mmCPF_GCR_CNTL
    Golden {
        base_index: 0,
        offset: 0x1f53,
        and_mask: 0x0007ffff,
        or_mask: 0x0000c000,
    },
    // mmDB_DEBUG3
    Golden {
        base_index: 0,
        offset: 0x13ae,
        and_mask: 0xffffffff,
        or_mask: 0x00000280,
    },
    // mmDB_DEBUG4
    Golden {
        base_index: 0,
        offset: 0x13af,
        and_mask: 0xffffffff,
        or_mask: 0x00800000,
    },
    // mmGCR_GENERAL_CNTL_Sienna_Cichlid
    Golden {
        base_index: 0,
        offset: 0x1580,
        and_mask: 0x1ff1ffff,
        or_mask: 0x00000500,
    },
    // mmGL2A_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e21,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_ADDR_MATCH_MASK
    Golden {
        base_index: 1,
        offset: 0x2e03,
        and_mask: 0xffffffff,
        or_mask: 0xffffffcf,
    },
    // mmGL2C_CM_CTRL1
    Golden {
        base_index: 1,
        offset: 0x2e08,
        and_mask: 0xff8fff0f,
        or_mask: 0x580f1008,
    },
    // mmGL2C_CTRL3
    Golden {
        base_index: 1,
        offset: 0x2e0c,
        and_mask: 0xf7ffffff,
        or_mask: 0x00f80988,
    },
    // mmLDS_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a2,
        and_mask: 0x000001ff,
        or_mask: 0x00000020,
    },
    // mmPA_CL_ENHANCE
    Golden {
        base_index: 0,
        offset: 0x1025,
        and_mask: 0xf17fffff,
        or_mask: 0x01200007,
    },
    // mmSQ_CONFIG
    Golden {
        base_index: 0,
        offset: 0x10a0,
        and_mask: 0xe07df47f,
        or_mask: 0x00180070,
    },
    // mmSQ_PERFCOUNTER0_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c0,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER1_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c1,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER10_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ca,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER11_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cb,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER12_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cc,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER13_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cd,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER14_SELECT
    Golden {
        base_index: 1,
        offset: 0x39ce,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER15_SELECT
    Golden {
        base_index: 1,
        offset: 0x39cf,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER2_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c2,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER3_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c3,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER4_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c4,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER5_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c5,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER6_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c6,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER7_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c7,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER8_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c8,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmSQ_PERFCOUNTER9_SELECT
    Golden {
        base_index: 1,
        offset: 0x39c9,
        and_mask: 0xf0f001ff,
        or_mask: 0x00000000,
    },
    // mmTA_CNTL_AUX
    Golden {
        base_index: 0,
        offset: 0x12e2,
        and_mask: 0xfff7ffff,
        or_mask: 0x01030000,
    },
    // mmUTCL1_CTRL
    Golden {
        base_index: 0,
        offset: 0x1588,
        and_mask: 0xffbfffff,
        or_mask: 0x00a00000,
    },
];

/// Unknown GC revisions have no safe default sequence.
pub fn for_gc(version: (u8, u8, u8)) -> Option<&'static [Golden]> {
    match version {
        (10, 3, 0) => Some(NAVI21),
        (10, 3, 2) => Some(NAVI22),
        (10, 3, 4) => Some(NAVI23),
        (10, 3, 5) => Some(NAVI24),
        _ => None,
    }
}
