//! PM4 packet definitions for AMD RDNA GPU command processor.
//!
//! Mechanically translated from:
//!   - /usr/src/linux/drivers/gpu/drm/amd/amdgpu/nvd.h (GFX10/11, primary source)
//!   - /usr/src/linux/drivers/gpu/drm/amd/amdgpu/soc15d.h (GFX9, fallback for missing opcodes)
//!
//! Linux kernel version: 7.3.0-rc4
//!
//! This is a mechanical mirror of the C header definitions.
//! Hand-edits should be avoided; regenerate from headers when updated.

// `clippy::identity_op`: the field encoders mirror C macros of the form
// `((x) & MASK) << SHIFT`, and a SHIFT of 0 is written out in the C. Folding
// `<< 0` away would delete the only statement of which bit the field starts
// at, and make a field at bit 0 look different from its siblings. The whole
// value of a mechanical mirror is that it reads like the header.
#![allow(clippy::identity_op)]

// ── Packet Types ──
pub const PACKET_TYPE0: u32 = 0;
pub const PACKET_TYPE1: u32 = 1;
pub const PACKET_TYPE2: u32 = 2;
pub const PACKET_TYPE3: u32 = 3;

// ── Packet Getters ──
pub const fn cp_packet_get_type(h: u32) -> u32 {
    (h >> 30) & 3
}

pub const fn cp_packet_get_count(h: u32) -> u32 {
    (h >> 16) & 0x3FFF
}

pub const fn cp_packet0_get_reg(h: u32) -> u32 {
    h & 0xFFFF
}

pub const fn cp_packet3_get_opcode(h: u32) -> u32 {
    (h >> 8) & 0xFF
}

// ── Packet Header Constructors ──
pub const fn packet0(reg: u32, n: u32) -> u32 {
    (PACKET_TYPE0 << 30) | (reg & 0xFFFF) | ((n & 0x3FFF) << 16)
}

pub const CP_PACKET2: u32 = 0x80000000;
pub const PACKET2_PAD_SHIFT: u32 = 0;
pub const PACKET2_PAD_MASK: u32 = 0x3fffffff << 0;

pub const fn packet3(op: u32, n: u32) -> u32 {
    (PACKET_TYPE3 << 30) | ((op & 0xFF) << 8) | ((n & 0x3FFF) << 16)
}

pub const fn packet3_compute(op: u32, n: u32) -> u32 {
    packet3(op, n) | (1 << 1)
}

// ── PACKET3 Opcodes ──
pub const PACKET3_NOP: u32 = 0x10;
pub const PACKET3_SET_BASE: u32 = 0x11;
pub const PACKET3_CLEAR_STATE: u32 = 0x12;
pub const PACKET3_INDEX_BUFFER_SIZE: u32 = 0x13;
pub const PACKET3_DISPATCH_DIRECT: u32 = 0x15;
pub const PACKET3_DISPATCH_INDIRECT: u32 = 0x16;
pub const PACKET3_INDIRECT_BUFFER_END: u32 = 0x17;
pub const PACKET3_INDIRECT_BUFFER_CNST_END: u32 = 0x19;
pub const PACKET3_ATOMIC_GDS: u32 = 0x1D;
pub const PACKET3_ATOMIC_MEM: u32 = 0x1E;
pub const PACKET3_OCCLUSION_QUERY: u32 = 0x1F;
pub const PACKET3_SET_PREDICATION: u32 = 0x20;
pub const PACKET3_REG_RMW: u32 = 0x21;
pub const PACKET3_COND_EXEC: u32 = 0x22;
pub const PACKET3_PRED_EXEC: u32 = 0x23;
pub const PACKET3_DRAW_INDIRECT: u32 = 0x24;
pub const PACKET3_DRAW_INDEX_INDIRECT: u32 = 0x25;
pub const PACKET3_INDEX_BASE: u32 = 0x26;
pub const PACKET3_DRAW_INDEX_2: u32 = 0x27;
pub const PACKET3_CONTEXT_CONTROL: u32 = 0x28;
pub const PACKET3_INDEX_TYPE: u32 = 0x2A;
pub const PACKET3_DRAW_INDIRECT_MULTI: u32 = 0x2C;
pub const PACKET3_DRAW_INDEX_AUTO: u32 = 0x2D;
pub const PACKET3_NUM_INSTANCES: u32 = 0x2F;
pub const PACKET3_DRAW_INDEX_MULTI_AUTO: u32 = 0x30;
pub const PACKET3_INDIRECT_BUFFER_PRIV: u32 = 0x32;
pub const PACKET3_INDIRECT_BUFFER_CNST: u32 = 0x33;
pub const PACKET3_COND_INDIRECT_BUFFER_CNST: u32 = 0x33;
pub const PACKET3_STRMOUT_BUFFER_UPDATE: u32 = 0x34;
pub const PACKET3_DRAW_INDEX_OFFSET_2: u32 = 0x35;
pub const PACKET3_DRAW_PREAMBLE: u32 = 0x36;
pub const PACKET3_WRITE_DATA: u32 = 0x37;
pub const PACKET3_DRAW_INDEX_INDIRECT_MULTI: u32 = 0x38;
pub const PACKET3_MEM_SEMAPHORE: u32 = 0x39;
pub const PACKET3_DRAW_INDEX_MULTI_INST: u32 = 0x3A;
pub const PACKET3_COPY_DW: u32 = 0x3B;
pub const PACKET3_WAIT_REG_MEM: u32 = 0x3C;
pub const PACKET3_INDIRECT_BUFFER: u32 = 0x3F;
pub const PACKET3_COND_INDIRECT_BUFFER: u32 = 0x3F;
pub const PACKET3_COPY_DATA: u32 = 0x40;
pub const PACKET3_CP_DMA: u32 = 0x41;
pub const PACKET3_PFP_SYNC_ME: u32 = 0x42;
pub const PACKET3_SURFACE_SYNC: u32 = 0x43;
pub const PACKET3_ME_INITIALIZE: u32 = 0x44;
pub const PACKET3_COND_WRITE: u32 = 0x45;
pub const PACKET3_EVENT_WRITE: u32 = 0x46;
pub const PACKET3_EVENT_WRITE_EOP: u32 = 0x47;
pub const PACKET3_EVENT_WRITE_EOS: u32 = 0x48;
pub const PACKET3_RELEASE_MEM: u32 = 0x49;
pub const PACKET3_PREAMBLE_CNTL: u32 = 0x4A;
pub const PACKET3_DMA_DATA: u32 = 0x50;
pub const PACKET3_CONTEXT_REG_RMW: u32 = 0x51;
pub const PACKET3_GFX_CNTX_UPDATE: u32 = 0x52;
pub const PACKET3_BLK_CNTX_UPDATE: u32 = 0x53;
pub const PACKET3_INCR_UPDT_STATE: u32 = 0x55;
pub const PACKET3_ACQUIRE_MEM: u32 = 0x58;
pub const PACKET3_REWIND: u32 = 0x59;
pub const PACKET3_INTERRUPT: u32 = 0x5A;
pub const PACKET3_GEN_PDEPTE: u32 = 0x5B;
pub const PACKET3_INDIRECT_BUFFER_PASID: u32 = 0x5C;
pub const PACKET3_PRIME_UTCL2: u32 = 0x5D;
pub const PACKET3_LOAD_UCONFIG_REG: u32 = 0x5E;
pub const PACKET3_LOAD_SH_REG: u32 = 0x5F;
pub const PACKET3_LOAD_CONFIG_REG: u32 = 0x60;
pub const PACKET3_LOAD_CONTEXT_REG: u32 = 0x61;
pub const PACKET3_LOAD_COMPUTE_STATE: u32 = 0x62;
pub const PACKET3_LOAD_SH_REG_INDEX: u32 = 0x63;
pub const PACKET3_SET_CONFIG_REG: u32 = 0x68;
pub const PACKET3_SET_CONFIG_REG_START: u32 = 0x00002000;
pub const PACKET3_SET_CONFIG_REG_END: u32 = 0x00002c00;
pub const PACKET3_SET_CONTEXT_REG: u32 = 0x69;
pub const PACKET3_SET_CONTEXT_REG_START: u32 = 0x0000a000;
pub const PACKET3_SET_CONTEXT_REG_END: u32 = 0x0000a400;
pub const PACKET3_SET_CONTEXT_REG_INDEX: u32 = 0x6A;
pub const PACKET3_SET_VGPR_REG_DI_MULTI: u32 = 0x71;
pub const PACKET3_SET_SH_REG_DI: u32 = 0x72;
pub const PACKET3_SET_CONTEXT_REG_INDIRECT: u32 = 0x73;
pub const PACKET3_SET_SH_REG_DI_MULTI: u32 = 0x74;
pub const PACKET3_GFX_PIPE_LOCK: u32 = 0x75;
pub const PACKET3_SET_SH_REG: u32 = 0x76;
pub const PACKET3_SET_SH_REG_START: u32 = 0x00002c00;
pub const PACKET3_SET_SH_REG_END: u32 = 0x00003000;
pub const PACKET3_SET_SH_REG_OFFSET: u32 = 0x77;
pub const PACKET3_SET_QUEUE_REG: u32 = 0x78;
pub const PACKET3_SET_UCONFIG_REG: u32 = 0x79;
pub const PACKET3_SET_UCONFIG_REG_START: u32 = 0x0000c000;
pub const PACKET3_SET_UCONFIG_REG_END: u32 = 0x0000c400;
pub const PACKET3_SET_UCONFIG_REG_INDEX: u32 = 0x7A;
pub const PACKET3_FORWARD_HEADER: u32 = 0x7C;
pub const PACKET3_SCRATCH_RAM_WRITE: u32 = 0x7D;
pub const PACKET3_SCRATCH_RAM_READ: u32 = 0x7E;
pub const PACKET3_LOAD_CONST_RAM: u32 = 0x80;
pub const PACKET3_WRITE_CONST_RAM: u32 = 0x81;
pub const PACKET3_DUMP_CONST_RAM: u32 = 0x83;
pub const PACKET3_INCREMENT_CE_COUNTER: u32 = 0x84;
pub const PACKET3_INCREMENT_DE_COUNTER: u32 = 0x85;
pub const PACKET3_WAIT_ON_CE_COUNTER: u32 = 0x86;
pub const PACKET3_WAIT_ON_DE_COUNTER_DIFF: u32 = 0x88;
pub const PACKET3_SWITCH_BUFFER: u32 = 0x8B;
pub const PACKET3_DISPATCH_DRAW_PREAMBLE: u32 = 0x8C;
pub const PACKET3_DISPATCH_DRAW_PREAMBLE_ACE: u32 = 0x8C;
pub const PACKET3_DISPATCH_DRAW: u32 = 0x8D;
pub const PACKET3_DISPATCH_DRAW_ACE: u32 = 0x8D;
pub const PACKET3_GET_LOD_STATS: u32 = 0x8E;
pub const PACKET3_DRAW_MULTI_PREAMBLE: u32 = 0x8F;
pub const PACKET3_FRAME_CONTROL: u32 = 0x90;
pub const PACKET3_INDEX_ATTRIBUTES_INDIRECT: u32 = 0x91;
pub const PACKET3_WAIT_REG_MEM64: u32 = 0x93;
pub const PACKET3_COND_PREEMPT: u32 = 0x94;
pub const PACKET3_HDP_FLUSH: u32 = 0x95;
pub const PACKET3_COPY_DATA_RB: u32 = 0x96;
pub const PACKET3_INVALIDATE_TLBS: u32 = 0x98;
pub const PACKET3_AQL_PACKET: u32 = 0x99;
pub const PACKET3_DMA_DATA_FILL_MULTI: u32 = 0x9A;
pub const PACKET3_SET_SH_REG_INDEX: u32 = 0x9B;
pub const PACKET3_DRAW_INDIRECT_COUNT_MULTI: u32 = 0x9C;
pub const PACKET3_DRAW_INDEX_INDIRECT_COUNT_MULTI: u32 = 0x9D;
pub const PACKET3_DUMP_CONST_RAM_OFFSET: u32 = 0x9E;
pub const PACKET3_LOAD_CONTEXT_REG_INDEX: u32 = 0x9F;
pub const PACKET3_SET_RESOURCES: u32 = 0xA0;
pub const PACKET3_MAP_PROCESS: u32 = 0xA1;
pub const PACKET3_MAP_QUEUES: u32 = 0xA2;
pub const PACKET3_UNMAP_QUEUES: u32 = 0xA3;
pub const PACKET3_QUERY_STATUS: u32 = 0xA4;
pub const PACKET3_RUN_LIST: u32 = 0xA5;
pub const PACKET3_MAP_PROCESS_VM: u32 = 0xA6;
pub const PACKET3_RUN_CLEANER_SHADER: u32 = 0xD2;
pub const PACKET3_SET_Q_PREEMPTION_MODE: u32 = 0xF0;

// ── SET_BASE Fields ──
pub const fn packet3_base_index(x: u32) -> u32 {
    x << 0
}
pub const CE_PARTITION_BASE: u32 = 3;

// ── ATOMIC_MEM Fields ──
pub const fn packet3_atomic_mem_atomic(x: u32) -> u32 {
    (x & 0x7F) << 0
}

pub const fn packet3_atomic_mem_command(x: u32) -> u32 {
    (x & 0xF) << 8
}

pub const fn packet3_atomic_mem_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_atomic_mem_addr_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_addr_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_src_data_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_src_data_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_cmp_data_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_cmp_data_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_atomic_mem_loop_interval(x: u32) -> u32 {
    (x & 0x1FFF) << 0
}

pub const PACKET3_ATOMIC_MEM_COMMAND_SINGLE_PASS_ATOMIC: u32 = 0;
pub const PACKET3_ATOMIC_MEM_COMMAND_LOOP_UNTIL_COMPARE_SATISFIED: u32 = 1;
pub const PACKET3_ATOMIC_MEM_COMMAND_WAIT_FOR_WRITE_CONFIRMATION: u32 = 2;
pub const PACKET3_ATOMIC_MEM_COMMAND_SEND_AND_CONTINUE: u32 = 3;
pub const PACKET3_ATOMIC_MEM_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_ATOMIC_MEM_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_ATOMIC_MEM_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_ATOMIC_MEM_CACHE_POLICY_BYPASS: u32 = 3;

// ── WRITE_DATA Fields ──
pub const fn write_data_dst_sel(x: u32) -> u32 {
    x << 8
}

pub const WR_ONE_ADDR: u32 = 1 << 16;
pub const WR_CONFIRM: u32 = 1 << 20;

pub const fn write_data_cache_policy(x: u32) -> u32 {
    x << 25
}

pub const fn write_data_engine_sel(x: u32) -> u32 {
    x << 30
}

pub const fn packet3_write_data_dst_sel(x: u32) -> u32 {
    (x & 0xF) << 8
}

pub const fn packet3_write_data_addr_incr(x: u32) -> u32 {
    (x & 0x1) << 16
}

pub const fn packet3_write_data_wr_confirm(x: u32) -> u32 {
    (x & 0x1) << 20
}

pub const fn packet3_write_data_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_write_data_dst_mmreg_addr(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_write_data_dst_gds_addr(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_write_data_dst_mem_addr_lo(x: u32) -> u32 {
    (x & 0x3FFFFFFF) << 2
}

pub const fn packet3_write_data_dst_mem_addr_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_write_data_mode(x: u32) -> u32 {
    (x & 0x1) << 21
}

pub const fn packet3_write_data_aid_id(x: u32) -> u32 {
    (x & 0x3) << 22
}

pub const fn packet3_write_data_temporal(x: u32) -> u32 {
    (x & 0x3) << 24
}

pub const fn packet3_write_data_dst_mmreg_addr_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_write_data_dst_mmreg_addr_hi(x: u32) -> u32 {
    (x & 0xFF) << 0
}

pub const PACKET3_WRITE_DATA_DST_SEL_MEM_MAPPED_REGISTER: u32 = 0;
pub const PACKET3_WRITE_DATA_DST_SEL_TC_L2: u32 = 2;
pub const PACKET3_WRITE_DATA_DST_SEL_GDS: u32 = 3;
pub const PACKET3_WRITE_DATA_DST_SEL_MEMORY: u32 = 5;
pub const PACKET3_WRITE_DATA_DST_SEL_MEMORY_MAPPED_ADC_PERSISTENT_STATE: u32 = 6;
pub const PACKET3_WRITE_DATA_ADDR_INCR_INCREMENT_ADDRESS: u32 = 0;
pub const PACKET3_WRITE_DATA_ADDR_INCR_DO_NOT_INCREMENT_ADDRESS: u32 = 1;
pub const PACKET3_WRITE_DATA_WR_CONFIRM_DO_NOT_WAIT_FOR_WRITE_CONFIRMATION: u32 = 0;
pub const PACKET3_WRITE_DATA_WR_CONFIRM_WAIT_FOR_WRITE_CONFIRMATION: u32 = 1;
pub const PACKET3_WRITE_DATA_MODE_PF_VF_DISABLED: u32 = 0;
pub const PACKET3_WRITE_DATA_MODE_PF_VF_ENABLED: u32 = 1;
pub const PACKET3_WRITE_DATA_TEMPORAL_RT: u32 = 0;
pub const PACKET3_WRITE_DATA_TEMPORAL_NT: u32 = 1;
pub const PACKET3_WRITE_DATA_TEMPORAL_HT: u32 = 2;
pub const PACKET3_WRITE_DATA_TEMPORAL_LU: u32 = 3;
pub const PACKET3_WRITE_DATA_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_WRITE_DATA_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_WRITE_DATA_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_WRITE_DATA_CACHE_POLICY_BYPASS: u32 = 3;

// ── MEM_SEMAPHORE Fields ──
pub const PACKET3_SEM_USE_MAILBOX: u32 = 0x1 << 16;
pub const PACKET3_SEM_SEL_SIGNAL_TYPE: u32 = 0x1 << 20;
pub const PACKET3_SEM_SEL_SIGNAL: u32 = 0x6 << 29;
pub const PACKET3_SEM_SEL_WAIT: u32 = 0x7 << 29;

// ── WAIT_REG_MEM Fields ──
pub const fn wait_reg_mem_function(x: u32) -> u32 {
    x << 0
}

pub const fn wait_reg_mem_mem_space(x: u32) -> u32 {
    x << 4
}

pub const fn wait_reg_mem_operation(x: u32) -> u32 {
    x << 6
}

pub const fn wait_reg_mem_engine(x: u32) -> u32 {
    x << 8
}

pub const fn packet3_wait_reg_mem_function(x: u32) -> u32 {
    (x & 0x7) << 0
}

pub const fn packet3_wait_reg_mem_mem_space(x: u32) -> u32 {
    (x & 0x3) << 4
}

pub const fn packet3_wait_reg_mem_operation(x: u32) -> u32 {
    (x & 0x3) << 6
}

pub const fn packet3_wait_reg_mem_mes_intr_pipe(x: u32) -> u32 {
    (x & 0x3) << 22
}

pub const fn packet3_wait_reg_mem_mes_action(x: u32) -> u32 {
    (x & 0x1) << 24
}

pub const fn packet3_wait_reg_mem_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_wait_reg_mem_temporal(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_wait_reg_mem_mem_poll_addr_lo(x: u32) -> u32 {
    (x & 0x3FFFFFFF) << 2
}

pub const fn packet3_wait_reg_mem_reg_poll_addr(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_wait_reg_mem_reg_write_addr1(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_wait_reg_mem_mem_poll_addr_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_wait_reg_mem_reg_write_addr2(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_wait_reg_mem_reference(x: u32) -> u32 {
    x
}

pub const fn packet3_wait_reg_mem_mask(x: u32) -> u32 {
    x
}

pub const fn packet3_wait_reg_mem_poll_interval(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_wait_reg_mem_optimize_ace_offload_mode(x: u32) -> u32 {
    (x & 0x1) << 31
}

pub const PACKET3_WAIT_REG_MEM_FUNCTION_ALWAYS_PASS: u32 = 0;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_LESS_THAN_REF_VALUE: u32 = 1;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_LESS_THAN_EQUAL_TO_THE_REF_VALUE: u32 = 2;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_EQUAL_TO_THE_REFERENCE_VALUE: u32 = 3;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_NOT_EQUAL_REFERENCE_VALUE: u32 = 4;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_GREATER_THAN_OR_EQUAL_REFERENCE_VALUE: u32 = 5;
pub const PACKET3_WAIT_REG_MEM_FUNCTION_GREATER_THAN_REFERENCE_VALUE: u32 = 6;
pub const PACKET3_WAIT_REG_MEM_MEM_SPACE_REGISTER_SPACE: u32 = 0;
pub const PACKET3_WAIT_REG_MEM_MEM_SPACE_MEMORY_SPACE: u32 = 1;
pub const PACKET3_WAIT_REG_MEM_OPERATION_WAIT_REG_MEM: u32 = 0;
pub const PACKET3_WAIT_REG_MEM_OPERATION_WR_WAIT_WR_REG: u32 = 1;
pub const PACKET3_WAIT_REG_MEM_OPERATION_WAIT_MEM_PREEMPTABLE: u32 = 3;
pub const PACKET3_WAIT_REG_MEM_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_WAIT_REG_MEM_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_WAIT_REG_MEM_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_WAIT_REG_MEM_CACHE_POLICY_BYPASS: u32 = 3;
pub const PACKET3_WAIT_REG_MEM_TEMPORAL_RT: u32 = 0;
pub const PACKET3_WAIT_REG_MEM_TEMPORAL_NT: u32 = 1;
pub const PACKET3_WAIT_REG_MEM_TEMPORAL_HT: u32 = 2;
pub const PACKET3_WAIT_REG_MEM_TEMPORAL_LU: u32 = 3;

// ── INDIRECT_BUFFER Fields ──
pub const INDIRECT_BUFFER_VALID: u32 = 1 << 23;

pub const fn indirect_buffer_cache_policy(x: u32) -> u32 {
    x << 28
}

pub const fn indirect_buffer_pre_enb(x: u32) -> u32 {
    x << 21
}

pub const fn indirect_buffer_pre_resume(x: u32) -> u32 {
    x << 30
}

pub const fn packet3_indirect_buffer_ib_base_lo(x: u32) -> u32 {
    (x & 0x3FFFFFFF) << 2
}

pub const fn packet3_indirect_buffer_ib_base_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_indirect_buffer_ib_size(x: u32) -> u32 {
    (x & 0xFFFFF) << 0
}

pub const fn packet3_indirect_buffer_chain(x: u32) -> u32 {
    (x & 0x1) << 20
}

pub const fn packet3_indirect_buffer_offload_polling(x: u32) -> u32 {
    (x & 0x1) << 21
}

pub const fn packet3_indirect_buffer_valid(x: u32) -> u32 {
    (x & 0x1) << 23
}

pub const fn packet3_indirect_buffer_vmid(x: u32) -> u32 {
    (x & 0xF) << 24
}

pub const fn packet3_indirect_buffer_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 28
}

pub const fn packet3_indirect_buffer_temporal(x: u32) -> u32 {
    (x & 0x3) << 28
}

pub const fn packet3_indirect_buffer_priv(x: u32) -> u32 {
    (x & 0x1) << 31
}

pub const PACKET3_INDIRECT_BUFFER_TEMPORAL_RT: u32 = 0;
pub const PACKET3_INDIRECT_BUFFER_TEMPORAL_NT: u32 = 1;
pub const PACKET3_INDIRECT_BUFFER_TEMPORAL_HT: u32 = 2;
pub const PACKET3_INDIRECT_BUFFER_TEMPORAL_LU: u32 = 3;
pub const PACKET3_INDIRECT_BUFFER_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_INDIRECT_BUFFER_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_INDIRECT_BUFFER_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_INDIRECT_BUFFER_CACHE_POLICY_BYPASS: u32 = 3;

// ── COPY_DATA Fields ──
pub const fn packet3_copy_data_src_sel(x: u32) -> u32 {
    (x & 0xF) << 0
}

pub const fn packet3_copy_data_dst_sel(x: u32) -> u32 {
    (x & 0xF) << 8
}

pub const fn packet3_copy_data_src_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 13
}

pub const fn packet3_copy_data_src_temporal(x: u32) -> u32 {
    (x & 0x3) << 13
}

pub const fn packet3_copy_data_count_sel(x: u32) -> u32 {
    (x & 0x1) << 16
}

pub const fn packet3_copy_data_wr_confirm(x: u32) -> u32 {
    (x & 0x1) << 20
}

pub const fn packet3_copy_data_dst_cache_policy(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_copy_data_pq_exe_status(x: u32) -> u32 {
    (x & 0x1) << 29
}

pub const fn packet3_copy_data_src_reg_offset(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_copy_data_src_32b_addr_lo(x: u32) -> u32 {
    (x & 0x3FFFFFFF) << 2
}

pub const fn packet3_copy_data_src_64b_addr_lo(x: u32) -> u32 {
    (x & 0x1FFFFFFF) << 3
}

pub const fn packet3_copy_data_src_gds_addr_lo(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_copy_data_imm_data(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_src_memtc_addr_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_src_imm_data(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_dst_reg_offset(x: u32) -> u32 {
    (x & 0x3FFFF) << 0
}

pub const fn packet3_copy_data_dst_32b_addr_lo(x: u32) -> u32 {
    (x & 0x3FFFFFFF) << 2
}

pub const fn packet3_copy_data_dst_64b_addr_lo(x: u32) -> u32 {
    (x & 0x1FFFFFFF) << 3
}

pub const fn packet3_copy_data_dst_gds_addr_lo(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_copy_data_dst_addr_hi(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_mode(x: u32) -> u32 {
    (x & 0x1) << 21
}

pub const fn packet3_copy_data_aid_id(x: u32) -> u32 {
    (x & 0x3) << 23
}

pub const fn packet3_copy_data_dst_temporal(x: u32) -> u32 {
    (x & 0x3) << 25
}

pub const fn packet3_copy_data_src_reg_offset_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_src_reg_offset_hi(x: u32) -> u32 {
    (x & 0xFF) << 0
}

pub const fn packet3_copy_data_dst_reg_offset_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_copy_data_dst_reg_offset_hi(x: u32) -> u32 {
    (x & 0xFF) << 0
}

pub const PACKET3_COPY_DATA_SRC_SEL_MEM_MAPPED_REGISTER: u32 = 0;
pub const PACKET3_COPY_DATA_SRC_SEL_TC_L2_OBSOLETE: u32 = 1;
pub const PACKET3_COPY_DATA_SRC_SEL_TC_L2: u32 = 2;
pub const PACKET3_COPY_DATA_SRC_SEL_GDS: u32 = 3;
pub const PACKET3_COPY_DATA_SRC_SEL_PERFCOUNTERS: u32 = 4;
pub const PACKET3_COPY_DATA_SRC_SEL_IMMEDIATE_DATA: u32 = 5;
pub const PACKET3_COPY_DATA_SRC_SEL_ATOMIC_RETURN_DATA: u32 = 6;
pub const PACKET3_COPY_DATA_SRC_SEL_GDS_ATOMIC_RETURN_DATA0: u32 = 7;
pub const PACKET3_COPY_DATA_SRC_SEL_GDS_ATOMIC_RETURN_DATA1: u32 = 8;
pub const PACKET3_COPY_DATA_SRC_SEL_GPU_CLOCK_COUNT: u32 = 9;
pub const PACKET3_COPY_DATA_SRC_SEL_SYSTEM_CLOCK_COUNT: u32 = 10;
pub const PACKET3_COPY_DATA_DST_SEL_MEM_MAPPED_REGISTER: u32 = 0;
pub const PACKET3_COPY_DATA_DST_SEL_TC_L2: u32 = 2;
pub const PACKET3_COPY_DATA_DST_SEL_GDS: u32 = 3;
pub const PACKET3_COPY_DATA_DST_SEL_PERFCOUNTERS: u32 = 4;
pub const PACKET3_COPY_DATA_DST_SEL_TC_L2_OBSOLETE: u32 = 5;
pub const PACKET3_COPY_DATA_DST_SEL_MEM_MAPPED_REG_DC: u32 = 6;
pub const PACKET3_COPY_DATA_SRC_TEMPORAL_RT: u32 = 0;
pub const PACKET3_COPY_DATA_SRC_TEMPORAL_NT: u32 = 1;
pub const PACKET3_COPY_DATA_SRC_TEMPORAL_HT: u32 = 2;
pub const PACKET3_COPY_DATA_SRC_TEMPORAL_LU: u32 = 3;
pub const PACKET3_COPY_DATA_SRC_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_COPY_DATA_SRC_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_COPY_DATA_SRC_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_COPY_DATA_SRC_CACHE_POLICY_BYPASS: u32 = 3;
pub const PACKET3_COPY_DATA_COUNT_SEL_32_BITS_OF_DATA: u32 = 0;
pub const PACKET3_COPY_DATA_COUNT_SEL_64_BITS_OF_DATA: u32 = 1;
pub const PACKET3_COPY_DATA_WR_CONFIRM_DO_NOT_WAIT_FOR_CONFIRMATION: u32 = 0;
pub const PACKET3_COPY_DATA_WR_CONFIRM_WAIT_FOR_CONFIRMATION: u32 = 1;
pub const PACKET3_COPY_DATA_MODE_PF_VF_DISABLED: u32 = 0;
pub const PACKET3_COPY_DATA_MODE_PF_VF_ENABLED: u32 = 1;
pub const PACKET3_COPY_DATA_DST_TEMPORAL_RT: u32 = 0;
pub const PACKET3_COPY_DATA_DST_TEMPORAL_NT: u32 = 1;
pub const PACKET3_COPY_DATA_DST_TEMPORAL_HT: u32 = 2;
pub const PACKET3_COPY_DATA_DST_TEMPORAL_LU: u32 = 3;
pub const PACKET3_COPY_DATA_DST_CACHE_POLICY_LRU: u32 = 0;
pub const PACKET3_COPY_DATA_DST_CACHE_POLICY_STREAM: u32 = 1;
pub const PACKET3_COPY_DATA_DST_CACHE_POLICY_NOA: u32 = 2;
pub const PACKET3_COPY_DATA_DST_CACHE_POLICY_BYPASS: u32 = 3;
pub const PACKET3_COPY_DATA_PQ_EXE_STATUS_DEFAULT: u32 = 0;
pub const PACKET3_COPY_DATA_PQ_EXE_STATUS_PHASE_UPDATE: u32 = 1;

// ── DMA_DATA Fields ──
pub const fn packet3_dma_data_engine(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_dma_data_src_cache_policy(x: u32) -> u32 {
    x << 13
}

pub const fn packet3_dma_data_dst_sel(x: u32) -> u32 {
    x << 20
}

pub const fn packet3_dma_data_dst_cache_policy(x: u32) -> u32 {
    x << 25
}

pub const fn packet3_dma_data_src_sel(x: u32) -> u32 {
    x << 29
}

pub const PACKET3_DMA_DATA_CP_SYNC: u32 = 1 << 31;

pub const fn packet3_dma_data_cmd_sas(x: u32) -> u32 {
    x << 26
}

pub const fn packet3_dma_data_cmd_das(x: u32) -> u32 {
    x << 27
}

pub const fn packet3_dma_data_cmd_saic(x: u32) -> u32 {
    x << 28
}

pub const fn packet3_dma_data_cmd_daic(x: u32) -> u32 {
    x << 29
}

pub const fn packet3_dma_data_cmd_raw_wait(x: u32) -> u32 {
    x << 30
}

pub const PACKET3_DMA_DATA_CMD_SAS: u32 = 1 << 26;
pub const PACKET3_DMA_DATA_CMD_DAS: u32 = 1 << 27;
pub const PACKET3_DMA_DATA_CMD_SAIC: u32 = 1 << 28;
pub const PACKET3_DMA_DATA_CMD_DAIC: u32 = 1 << 29;
pub const PACKET3_DMA_DATA_CMD_RAW_WAIT: u32 = 1 << 30;

// ── EVENT_WRITE Fields ──
pub const fn event_type(x: u32) -> u32 {
    x << 0
}

pub const fn event_index(x: u32) -> u32 {
    x << 8
}

pub const fn packet3_event_write_event_type(x: u32) -> u32 {
    (x & 0x3F) << 0
}

pub const fn packet3_event_write_event_index(x: u32) -> u32 {
    (x & 0xF) << 8
}

pub const fn packet3_event_write_samp_plst_cntr_mode(x: u32) -> u32 {
    (x & 0x3) << 29
}

pub const fn packet3_event_write_offload_enable(x: u32) -> u32 {
    (x & 0x1) << 0
}

pub const fn packet3_event_write_address_lo(x: u32) -> u32 {
    (x & 0x1FFFFFFF) << 3
}

pub const fn packet3_event_write_address_hi(x: u32) -> u32 {
    x
}

pub const PACKET3_EVENT_WRITE_EVENT_INDEX_OTHER: u32 = 0;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_SAMPLE_PIPELINESTAT: u32 = 2;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_CS_PARTIAL_FLUSH: u32 = 4;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_SAMPLE_STREAMOUTSTATS: u32 = 8;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_SAMPLE_STREAMOUTSTATS1: u32 = 9;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_SAMPLE_STREAMOUTSTATS2: u32 = 10;
pub const PACKET3_EVENT_WRITE_EVENT_INDEX_SAMPLE_STREAMOUTSTATS3: u32 = 11;
pub const PACKET3_EVENT_WRITE_SAMP_PLST_CNTR_MODE_LEGACY_MODE: u32 = 0;
pub const PACKET3_EVENT_WRITE_SAMP_PLST_CNTR_MODE_MIXED_MODE1: u32 = 1;
pub const PACKET3_EVENT_WRITE_SAMP_PLST_CNTR_MODE_NEW_MODE: u32 = 2;
pub const PACKET3_EVENT_WRITE_SAMP_PLST_CNTR_MODE_MIXED_MODE3: u32 = 3;

// ── RELEASE_MEM Fields ──
pub const fn packet3_release_mem_event_type(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_release_mem_event_index(x: u32) -> u32 {
    x << 8
}

pub const PACKET3_RELEASE_MEM_GCR_GLM_WB: u32 = 1 << 12;
pub const PACKET3_RELEASE_MEM_GCR_GLM_INV: u32 = 1 << 13;
pub const PACKET3_RELEASE_MEM_GCR_GLV_INV: u32 = 1 << 14;
pub const PACKET3_RELEASE_MEM_GCR_GL1_INV: u32 = 1 << 15;
pub const PACKET3_RELEASE_MEM_GCR_GL2_US: u32 = 1 << 16;
pub const PACKET3_RELEASE_MEM_GCR_GL2_RANGE: u32 = 1 << 17;
pub const PACKET3_RELEASE_MEM_GCR_GL2_DISCARD: u32 = 1 << 19;
pub const PACKET3_RELEASE_MEM_GCR_GL2_INV: u32 = 1 << 20;
pub const PACKET3_RELEASE_MEM_GCR_GL2_WB: u32 = 1 << 21;
pub const PACKET3_RELEASE_MEM_GCR_SEQ: u32 = 1 << 22;

pub const fn packet3_release_mem_cache_policy(x: u32) -> u32 {
    x << 25
}

pub const PACKET3_RELEASE_MEM_EXECUTE: u32 = 1 << 28;

pub const fn packet3_release_mem_data_sel(x: u32) -> u32 {
    x << 29
}

pub const fn packet3_release_mem_int_sel(x: u32) -> u32 {
    x << 24
}

pub const fn packet3_release_mem_dst_sel(x: u32) -> u32 {
    x << 16
}

// ── PREAMBLE_CNTL Fields ──
pub const PACKET3_PREAMBLE_BEGIN_CLEAR_STATE: u32 = 2 << 28;
pub const PACKET3_PREAMBLE_END_CLEAR_STATE: u32 = 3 << 28;

// ── FRAME_CONTROL Fields ──
pub const FRAME_TMZ: u32 = 1 << 0;

pub const fn frame_cmd(x: u32) -> u32 {
    x << 28
}

// ── ACQUIRE_MEM Fields ──
pub const fn packet3_acquire_mem_gcr_cntl_gli_inv(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_acquire_mem_gcr_cntl_gl1_range(x: u32) -> u32 {
    x << 2
}

pub const fn packet3_acquire_mem_gcr_cntl_glm_wb(x: u32) -> u32 {
    x << 4
}

pub const fn packet3_acquire_mem_gcr_cntl_glm_inv(x: u32) -> u32 {
    x << 5
}

pub const fn packet3_acquire_mem_gcr_cntl_glk_wb(x: u32) -> u32 {
    x << 6
}

pub const fn packet3_acquire_mem_gcr_cntl_glk_inv(x: u32) -> u32 {
    x << 7
}

pub const fn packet3_acquire_mem_gcr_cntl_glv_inv(x: u32) -> u32 {
    x << 8
}

pub const fn packet3_acquire_mem_gcr_cntl_gl1_inv(x: u32) -> u32 {
    x << 9
}

pub const fn packet3_acquire_mem_gcr_cntl_gl2_us(x: u32) -> u32 {
    x << 10
}

pub const fn packet3_acquire_mem_gcr_cntl_gl2_range(x: u32) -> u32 {
    x << 11
}

pub const fn packet3_acquire_mem_gcr_cntl_gl2_discard(x: u32) -> u32 {
    x << 13
}

pub const fn packet3_acquire_mem_gcr_cntl_gl2_inv(x: u32) -> u32 {
    x << 14
}

pub const fn packet3_acquire_mem_gcr_cntl_gl2_wb(x: u32) -> u32 {
    x << 15
}

pub const fn packet3_acquire_mem_gcr_cntl_seq(x: u32) -> u32 {
    x << 16
}

pub const PACKET3_ACQUIRE_MEM_GCR_RANGE_IS_PA: u32 = 1 << 18;

pub const fn packet3_acquire_mem_coher_size(x: u32) -> u32 {
    x
}

pub const fn packet3_acquire_mem_coher_size_hi(x: u32) -> u32 {
    (x & 0xFF) << 0
}

pub const fn packet3_acquire_mem_coher_base_lo(x: u32) -> u32 {
    x
}

pub const fn packet3_acquire_mem_coher_base_hi(x: u32) -> u32 {
    (x & 0xFFFFFF) << 0
}

pub const fn packet3_acquire_mem_poll_interval(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_acquire_mem_gcr_cntl(x: u32) -> u32 {
    (x & 0x7FFFF) << 0
}

// ── SET_SH_REG Fields ──
pub const fn packet3_set_sh_reg_reg_offset(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

pub const fn packet3_set_sh_reg_vmid_shift(x: u32) -> u32 {
    (x & 0x1F) << 23
}

pub const fn packet3_set_sh_reg_index(x: u32) -> u32 {
    (x & 0xF) << 28
}

pub const PACKET3_SET_SH_REG_INDEX_DEFAULT: u32 = 0;
pub const PACKET3_SET_SH_REG_INDEX_INSERT_VMID: u32 = 1;

// ── SET_UCONFIG_REG Fields ──
pub const fn packet3_set_uconfig_reg_reg_offset(x: u32) -> u32 {
    (x & 0xFFFF) << 0
}

// ── SET_RESOURCES Fields ──
pub const fn packet3_set_resources_vmid_mask(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_set_resources_unmap_latenty(x: u32) -> u32 {
    x << 16
}

pub const fn packet3_set_resources_queue_type(x: u32) -> u32 {
    x << 29
}

// ── MAP_QUEUES Fields ──
pub const fn packet3_map_queues_queue_sel(x: u32) -> u32 {
    x << 4
}

pub const fn packet3_map_queues_vmid(x: u32) -> u32 {
    x << 8
}

pub const fn packet3_map_queues_queue(x: u32) -> u32 {
    x << 13
}

pub const fn packet3_map_queues_pipe(x: u32) -> u32 {
    x << 16
}

pub const fn packet3_map_queues_me(x: u32) -> u32 {
    x << 18
}

pub const fn packet3_map_queues_queue_type(x: u32) -> u32 {
    x << 21
}

pub const fn packet3_map_queues_alloc_format(x: u32) -> u32 {
    x << 24
}

pub const fn packet3_map_queues_engine_sel(x: u32) -> u32 {
    x << 26
}

pub const fn packet3_map_queues_num_queues(x: u32) -> u32 {
    x << 29
}

pub const fn packet3_map_queues_check_disable(x: u32) -> u32 {
    x << 1
}

pub const fn packet3_map_queues_doorbell_offset(x: u32) -> u32 {
    x << 2
}

// ── UNMAP_QUEUES Fields ──
pub const fn packet3_unmap_queues_action(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_unmap_queues_queue_sel(x: u32) -> u32 {
    x << 4
}

pub const fn packet3_unmap_queues_engine_sel(x: u32) -> u32 {
    x << 26
}

pub const fn packet3_unmap_queues_num_queues(x: u32) -> u32 {
    x << 29
}

pub const fn packet3_unmap_queues_pasid(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_unmap_queues_doorbell_offset0(x: u32) -> u32 {
    x << 2
}

pub const fn packet3_unmap_queues_doorbell_offset1(x: u32) -> u32 {
    x << 2
}

pub const fn packet3_unmap_queues_rb_wptr(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_unmap_queues_doorbell_offset2(x: u32) -> u32 {
    x << 2
}

pub const fn packet3_unmap_queues_doorbell_offset3(x: u32) -> u32 {
    x << 2
}

// ── QUERY_STATUS Fields ──
pub const fn packet3_query_status_context_id(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_query_status_interrupt_sel(x: u32) -> u32 {
    x << 28
}

pub const fn packet3_query_status_command(x: u32) -> u32 {
    x << 30
}

pub const fn packet3_query_status_pasid(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_query_status_doorbell_offset(x: u32) -> u32 {
    x << 2
}

pub const fn packet3_query_status_eng_sel(x: u32) -> u32 {
    x << 25
}

// ── INVALIDATE_TLBS Fields ──
pub const fn packet3_invalidate_tlbs_dst_sel(x: u32) -> u32 {
    x << 0
}

pub const fn packet3_invalidate_tlbs_all_hub(x: u32) -> u32 {
    x << 4
}

pub const fn packet3_invalidate_tlbs_pasid(x: u32) -> u32 {
    x << 5
}

pub const fn packet3_invalidate_tlbs_flush_type(x: u32) -> u32 {
    x << 29
}

// ── SET_Q_PREEMPTION_MODE Fields ──
pub const fn packet3_set_q_preemption_mode_ib_vmid(x: u32) -> u32 {
    x << 0
}

pub const PACKET3_SET_Q_PREEMPTION_MODE_INIT_SHADOW_MEM: u32 = 1 << 0;

// ── kernel tests ────────────────────────────────────────────────────
//
// NARF kernel tests register through a linker section and must therefore be
// compiled in the ordinary build. These were written inside a
// `#[cfg(test)] mod tests` — the host-test convention — so the registration
// was discarded and the test silently never ran.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_amdgpu_pm4_packet_headers() -> TestResult {
    // Test packet3(PACKET3_NOP, 0)
    // Expected: (3 << 30) | ((0x10 & 0xFF) << 8) | ((0 & 0x3FFF) << 16)
    //         = 0xC0000000 | 0x1000 | 0
    //         = 0xC0001000
    if packet3(PACKET3_NOP, 0) != 0xC0001000 {
        return TestResult::Fail("packet3(PACKET3_NOP, 0)");
    }

    // Test packet3(PACKET3_WRITE_DATA, 2)
    // Expected: (3 << 30) | ((0x37 & 0xFF) << 8) | ((2 & 0x3FFF) << 16)
    //         = 0xC0000000 | 0x3700 | 0x20000
    //         = 0xC0023700
    if packet3(PACKET3_WRITE_DATA, 2) != 0xC0023700 {
        return TestResult::Fail("packet3(PACKET3_WRITE_DATA, 2)");
    }

    // Test packet0(0x1234, 15)
    // Expected: (0 << 30) | (0x1234 & 0xFFFF) | ((15 & 0x3FFF) << 16)
    //         = 0x00000000 | 0x1234 | 0xF0000
    //         = 0x000F1234
    if packet0(0x1234, 15) != 0x000F1234 {
        return TestResult::Fail("packet0(0x1234, 15)");
    }

    // Test packet3_compute(PACKET3_DISPATCH_DIRECT, 4)
    // Expected: packet3(0x15, 4) | (1 << 1)
    //         = ((3 << 30) | ((0x15 & 0xFF) << 8) | ((4 & 0x3FFF) << 16)) | 2
    //         = (0xC0000000 | 0x1500 | 0x40000) | 2
    //         = 0xC0041500 | 2 = 0xC0041502
    if packet3_compute(PACKET3_DISPATCH_DIRECT, 4) != 0xC0041502 {
        return TestResult::Fail("packet3_compute(PACKET3_DISPATCH_DIRECT, 4)");
    }

    // Test cp_packet_get_type for a packet3 header
    if cp_packet_get_type(0xC0001000) != 3 {
        return TestResult::Fail("cp_packet_get_type(0xC0001000)");
    }

    // Test cp_packet_get_count for packet with count=2
    if cp_packet_get_count(0xC0023700) != 2 {
        return TestResult::Fail("cp_packet_get_count(0xC0023700)");
    }

    // Test packet3_write_data_dst_sel(5) with shift logic
    // Expected: (5 & 0xF) << 8 = 5 << 8 = 0x500
    if packet3_write_data_dst_sel(5) != 0x500 {
        return TestResult::Fail("packet3_write_data_dst_sel(5)");
    }

    // Test indirect_buffer_cache_policy(1)
    // Expected: 1 << 28 = 0x10000000
    if indirect_buffer_cache_policy(1) != 0x10000000 {
        return TestResult::Fail("indirect_buffer_cache_policy(1)");
    }

    TestResult::Pass
}

kernel_test_in!(
    "drivers/gpu/amdgpu_pm4_defs",
    smoke_amdgpu_pm4_packet_headers
);
