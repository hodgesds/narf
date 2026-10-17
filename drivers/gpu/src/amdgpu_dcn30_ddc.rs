//! Navi22 DCN3.0 native AUX, hardware DDC/I2C and HPD — the register path
//! Linux drives on DCN3.0, not the DMUB inbox.
//!
//! `dc_is_dmub_outbox_supported` (Linux `dc/core/dc.c`) only returns true for
//! DCN3.1 USB4 DPIA and GC11 parts, otherwise `debug.enable_dmub_aux_for_legacy_ddc`
//! which nothing sets; `link_aux_transfer_raw` and `dce_aux_transfer_with_retries`
//! therefore always take `dce_aux_transfer_raw` on Navi22, HDMI DDC goes through
//! `dce_i2c_submit_command` to the hardware I2C engine, and HPD is sensed from
//! `DC_HPD_INT_STATUS` through the GPIO service.
//!
//! Sequences mirror Linux `dce/dce_aux.c` (`acquire`, `submit_channel_request`,
//! `get_channel_status`, `read_channel_reply`, `release_engine`,
//! `dce_aux_configure_timeout`, `dce_aux_transfer_with_retries`),
//! `dce/dce_i2c_hw.c` as constructed by `dcn2_i2c_hw_construct`,
//! `gpio/hw_ddc.c::set_config`, `gpio/hw_gpio.c` store/restore,
//! `gpio/hw_hpd.c`, `dio/dcn30/dcn30_dio_link_encoder.c::enc3_hw_init` (AUX
//! half), `link/protocols/link_hpd.c::program_hpd_filter` and
//! `irq/irq_service.c::hpd0_ack`. Offsets and masks are `dcn_3_0_0_offset.h` /
//! `dcn_3_0_0_sh_mask.h` at DCN base index 2, except
//! `MICROSECOND_TIME_BASE_DIV` at base index 1.
//!
//! One owner covers all six DDC lines because the I2C engine is shared: a
//! single `DC_I2C_CONTROL` selects which pad it drives. Every transaction is
//! bounded in time; a dropped future releases engine arbitration and restores
//! the pads synchronously, as Linux's release path does, so cancellation never
//! leaves a line owned by software. A register read of all ones marks the
//! owner `Failed` and every later operation is refused.
use crate::{amdgpu::AmdGpu, amdgpu_dcn_profile::Profile};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// ── DP_AUX instance block, stride 0x1c ─────────────────────────────────
// linux-ctx: hdr=dcn seg=2
// linux: mmDP_AUX0_AUX_CONTROL
const AUX_CONTROL: u64 = 0x1f50;
// linux: mmDP_AUX0_AUX_SW_CONTROL
const AUX_SW_CONTROL: u64 = 0x1f51;
// linux: mmDP_AUX0_AUX_ARB_CONTROL
const AUX_ARB_CONTROL: u64 = 0x1f52;
// linux: mmDP_AUX0_AUX_INTERRUPT_CONTROL
const AUX_INTERRUPT_CONTROL: u64 = 0x1f53;
// linux: mmDP_AUX0_AUX_SW_STATUS
const AUX_SW_STATUS: u64 = 0x1f54;
// linux: mmDP_AUX0_AUX_SW_DATA
const AUX_SW_DATA: u64 = 0x1f56;
// linux: mmDP_AUX0_AUX_DPHY_TX_CONTROL
const AUX_DPHY_TX_CONTROL: u64 = 0x1f59;
// linux: mmDP_AUX0_AUX_DPHY_RX_CONTROL0
const AUX_DPHY_RX_CONTROL0: u64 = 0x1f5a;
// linux: mmDP_AUX0_AUX_DPHY_RX_CONTROL1
const AUX_DPHY_RX_CONTROL1: u64 = 0x1f5b;
// linux: mmDP_AUX1_AUX_CONTROL - mmDP_AUX0_AUX_CONTROL
const AUX_STRIDE: u64 = 0x1c;
// AUX_CONTROL fields.
// linux: DP_AUX0_AUX_CONTROL__AUX_EN_MASK
const AUX_EN: u32 = 1 << 0;
// linux: DP_AUX0_AUX_CONTROL__AUX_RESET_MASK
const AUX_RESET: u32 = 1 << 4;
// linux: DP_AUX0_AUX_CONTROL__AUX_RESET_DONE_MASK
const AUX_RESET_DONE: u32 = 1 << 5;
// linux: DP_AUX0_AUX_CONTROL__AUX_LS_READ_EN_MASK
const AUX_LS_READ_EN: u32 = 1 << 8;
// linux: DP_AUX0_AUX_CONTROL__AUX_HPD_SEL_MASK
const AUX_HPD_SEL: u32 = 0x0070_0000;
// AUX_ARB_CONTROL fields. RW_CNTL_STATUS is 1 when software may access the
// engine and 2 when the DMCU owns it (`SW_CAN_ACCESS_AUX`/`DMCU_CAN_ACCESS_AUX`).
// linux: DP_AUX0_AUX_ARB_CONTROL__AUX_REG_RW_CNTL_STATUS_MASK
const AUX_REG_RW_CNTL_STATUS: u32 = 0x0000_000c;
// linux: DP_AUX0_AUX_ARB_CONTROL__AUX_SW_USE_AUX_REG_REQ_MASK
const AUX_SW_USE_AUX_REG_REQ: u32 = 1 << 16;
// linux: DP_AUX0_AUX_ARB_CONTROL__AUX_SW_DONE_USING_AUX_REG_MASK
const AUX_SW_DONE_USING_AUX_REG: u32 = 1 << 17;
// linux: n/a (SW_CAN_ACCESS_AUX, local #define in dce_aux.c)
const SW_CAN_ACCESS_AUX: u32 = 1;
// linux: n/a (DMCU_CAN_ACCESS_AUX, local #define in dce_aux.c)
const DMCU_CAN_ACCESS_AUX: u32 = 2;
// AUX_SW_CONTROL / AUX_INTERRUPT_CONTROL.
// linux: DP_AUX0_AUX_SW_CONTROL__AUX_SW_GO_MASK
const AUX_SW_GO: u32 = 1 << 0;
// linux: DP_AUX0_AUX_SW_CONTROL__AUX_SW_START_DELAY_MASK
const AUX_SW_START_DELAY: u32 = 0x0000_00f0;
// linux: DP_AUX0_AUX_SW_CONTROL__AUX_SW_WR_BYTES_MASK
const AUX_SW_WR_BYTES: u32 = 0x001f_0000;
// linux: DP_AUX0_AUX_INTERRUPT_CONTROL__AUX_SW_DONE_ACK_MASK
const AUX_SW_DONE_ACK: u32 = 1 << 1;
// AUX_SW_STATUS fields.
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_DONE_MASK
const AUX_SW_DONE: u32 = 1 << 0;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_TIMEOUT_STATE_MASK
const AUX_SW_RX_TIMEOUT_STATE: u32 = 0x0000_0070;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_TIMEOUT_MASK
const AUX_SW_RX_TIMEOUT: u32 = 1 << 7;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_HPD_DISCON_MASK
const AUX_SW_HPD_DISCON: u32 = 1 << 9;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_INVALID_STOP_MASK
const AUX_SW_RX_INVALID_STOP: u32 = 1 << 14;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_RECV_NO_DET_MASK
const AUX_SW_RX_RECV_NO_DET: u32 = 1 << 20;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_RECV_INVALID_H_MASK
const AUX_SW_RX_RECV_INVALID_H: u32 = 1 << 22;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_RX_RECV_INVALID_L_MASK
const AUX_SW_RX_RECV_INVALID_L: u32 = 1 << 23;
// linux: DP_AUX0_AUX_SW_STATUS__AUX_SW_REPLY_BYTE_COUNT_MASK
const AUX_SW_REPLY_BYTE_COUNT: u32 = 0x1f00_0000;
// AUX_SW_DATA fields.
// linux: DP_AUX0_AUX_SW_DATA__AUX_SW_DATA_RW_MASK
const AUX_SW_DATA_RW: u32 = 1 << 0;
// linux: DP_AUX0_AUX_SW_DATA__AUX_SW_DATA_MASK
const AUX_SW_DATA_FIELD: u32 = 0x0000_ff00;
// linux: DP_AUX0_AUX_SW_DATA__AUX_SW_INDEX_MASK
const AUX_SW_INDEX: u32 = 0x001f_0000;
// linux: DP_AUX0_AUX_SW_DATA__AUX_SW_AUTOINCREMENT_DISABLE_MASK
const AUX_SW_AUTOINCREMENT_DISABLE: u32 = 1 << 31;
// AUX_DPHY_RX_CONTROL0/1 fields.
// linux: DP_AUX0_AUX_DPHY_RX_CONTROL0__AUX_RX_RECEIVE_WINDOW_MASK
const AUX_RX_RECEIVE_WINDOW: u32 = 0x0000_0700;
// linux: DP_AUX0_AUX_DPHY_RX_CONTROL1__AUX_RX_TIMEOUT_LEN_MASK
const AUX_RX_TIMEOUT_LEN: u32 = 0x0000_7f00;
// linux: DP_AUX0_AUX_DPHY_RX_CONTROL1__AUX_RX_TIMEOUT_LEN_MUL_MASK
const AUX_RX_TIMEOUT_LEN_MUL: u32 = 0x0001_8000;
/// `enc3_hw_init` writes these whole: the receiver windows/threshold and the
/// TX settings DCN3.0 uses, before `dcn10_aux_initialize`.
// linux: n/a (literal 0x103d1110 in dcn30_dio_link_encoder.c:enc3_hw_init)
const DCN30_AUX_RX_CONTROL0: u32 = 0x103d_1110;
// linux: n/a (literal 0x21c7a in dcn30_dio_link_encoder.c:enc3_hw_init)
const DCN30_AUX_TX_CONTROL: u32 = 0x0002_1c7a;

// ── DC_I2C (one engine shared across the DDC pads) ─────────────────────
// linux: mmDC_I2C_CONTROL
const DC_I2C_CONTROL: u64 = 0x1e98;
// linux: mmDC_I2C_ARBITRATION
const DC_I2C_ARBITRATION: u64 = 0x1e99;
// linux: mmDC_I2C_SW_STATUS
const DC_I2C_SW_STATUS: u64 = 0x1e9b;
/// `DC_I2C_DDCn_HW_STATUS`, one dword per line.
// linux: mmDC_I2C_DDC1_HW_STATUS
const DC_I2C_DDC1_HW_STATUS: u64 = 0x1e9c;
/// `DC_I2C_DDCn_SPEED` and `_SETUP` pairs, two dwords per line.
// linux: mmDC_I2C_DDC1_SPEED
const DC_I2C_DDC1_SPEED: u64 = 0x1ea2;
// linux: mmDC_I2C_DDC1_SETUP
const DC_I2C_DDC1_SETUP: u64 = 0x1ea3;
// linux: mmDC_I2C_TRANSACTION0
const DC_I2C_TRANSACTION0: u64 = 0x1eae;
// linux: mmDC_I2C_DATA
const DC_I2C_DATA: u64 = 0x1eb2;
/// `regMICROSECOND_TIME_BASE_DIV`, BASE_IDX 1.
// linux-ctx: hdr=dcn seg=1
// linux: mmMICROSECOND_TIME_BASE_DIV
const MICROSECOND_TIME_BASE_DIV: u64 = 0x007b;
// DC_I2C_CONTROL fields.
// linux-ctx: hdr=dcn seg=2
// linux: DC_I2C_CONTROL__DC_I2C_GO_MASK
const I2C_GO: u32 = 1 << 0;
// linux: DC_I2C_CONTROL__DC_I2C_SOFT_RESET_MASK
const I2C_SOFT_RESET: u32 = 1 << 1;
// linux: DC_I2C_CONTROL__DC_I2C_SEND_RESET_MASK
const I2C_SEND_RESET: u32 = 1 << 2;
// linux: DC_I2C_CONTROL__DC_I2C_SW_STATUS_RESET_MASK
const I2C_SW_STATUS_RESET: u32 = 1 << 3;
// linux: DC_I2C_CONTROL__DC_I2C_DDC_SELECT_MASK
const I2C_DDC_SELECT: u32 = 0x0000_0700;
// linux: DC_I2C_CONTROL__DC_I2C_TRANSACTION_COUNT_MASK
const I2C_TRANSACTION_COUNT: u32 = 0x0030_0000;
// DC_I2C_ARBITRATION fields.
// linux: DC_I2C_ARBITRATION__DC_I2C_REG_RW_CNTL_STATUS_MASK
const I2C_REG_RW_CNTL_STATUS: u32 = 0x0000_000c;
// linux: DC_I2C_ARBITRATION__DC_I2C_NO_QUEUED_SW_GO_MASK
const I2C_NO_QUEUED_SW_GO: u32 = 1 << 4;
// linux: DC_I2C_ARBITRATION__DC_I2C_SW_USE_I2C_REG_REQ_MASK
const I2C_SW_USE_I2C_REG_REQ: u32 = 1 << 20;
// linux: DC_I2C_ARBITRATION__DC_I2C_SW_DONE_USING_I2C_REG_MASK
const I2C_SW_DONE_USING_I2C_REG: u32 = 1 << 21;
// DC_I2C_SW_STATUS / DC_I2C_DDCn_HW_STATUS fields and their `dc_i2c_status`.
// linux: DC_I2C_SW_STATUS__DC_I2C_SW_STATUS_MASK
const I2C_SW_STATUS_FIELD: u32 = 0x3;
// linux: DC_I2C_SW_STATUS__DC_I2C_SW_ABORTED_MASK
const I2C_SW_ABORTED: u32 = 1 << 4;
// linux: DC_I2C_SW_STATUS__DC_I2C_SW_TIMEOUT_MASK
const I2C_SW_TIMEOUT: u32 = 1 << 5;
// linux: DC_I2C_SW_STATUS__DC_I2C_SW_STOPPED_ON_NACK_MASK
const I2C_SW_STOPPED_ON_NACK: u32 = 1 << 8;
// linux: DC_I2C_DDC1_HW_STATUS__DC_I2C_DDC1_HW_STATUS_MASK
const I2C_HW_STATUS_FIELD: u32 = 0x3;
// linux: n/a (DC_I2C_STATUS__DC_I2C_STATUS_IDLE = 0, enum dc_i2c_status in dce_i2c_hw.h; not in checker sets)
const I2C_STATUS_IDLE: u32 = 0;
// linux: n/a (DC_I2C_STATUS__DC_I2C_STATUS_USED_BY_SW = 1, dce_i2c_hw.h; not in checker sets)
const I2C_STATUS_USED_BY_SW: u32 = 1;
// linux: n/a (DC_I2C_STATUS__DC_I2C_STATUS_USED_BY_HW = 2, dce_i2c_hw.h; not in checker sets)
const I2C_STATUS_USED_BY_HW: u32 = 2;
/// `DC_I2C_REG_RW_CNTL_STATUS_DMCU_ONLY`.
// linux: n/a (DC_I2C_REG_RW_CNTL_STATUS_DMCU_ONLY = 2, dce_i2c_hw.h; not in checker sets)
const I2C_DMCU_ONLY: u32 = 2;
// DC_I2C_DDCn_SETUP fields.
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_DATA_DRIVE_EN_MASK
const I2C_DATA_DRIVE_EN: u32 = 1 << 0;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_DATA_DRIVE_SEL_MASK
const I2C_DATA_DRIVE_SEL: u32 = 1 << 1;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_SEND_RESET_LENGTH_MASK
const I2C_SEND_RESET_LENGTH: u32 = 1 << 2;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_ENABLE_MASK
const I2C_DDC_ENABLE: u32 = 1 << 6;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_CLK_DRIVE_EN_MASK
const I2C_CLK_DRIVE_EN: u32 = 1 << 7;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_INTRA_BYTE_DELAY_MASK
const I2C_INTRA_BYTE_DELAY: u32 = 0x0000_ff00;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_INTRA_TRANSACTION_DELAY_MASK
const I2C_INTRA_TRANSACTION_DELAY: u32 = 0x00ff_0000;
// linux: DC_I2C_DDC1_SETUP__DC_I2C_DDC1_TIME_LIMIT_MASK
const I2C_TIME_LIMIT: u32 = 0xff00_0000;
// DC_I2C_DDCn_SPEED fields.
// linux: DC_I2C_DDC1_SPEED__DC_I2C_DDC1_THRESHOLD_MASK
const I2C_THRESHOLD: u32 = 0x3;
// linux: DC_I2C_DDC1_SPEED__DC_I2C_DDC1_START_STOP_TIMING_CNTL_MASK
const I2C_START_STOP_TIMING_CNTL: u32 = 0x0000_0300;
// linux: DC_I2C_DDC1_SPEED__DC_I2C_DDC1_PRESCALE_MASK
const I2C_PRESCALE: u32 = 0xffff_0000;
// DC_I2C_TRANSACTIONn fields.
// linux: DC_I2C_TRANSACTION0__DC_I2C_RW0_MASK
const I2C_RW0: u32 = 1 << 0;
// linux: DC_I2C_TRANSACTION0__DC_I2C_STOP_ON_NACK0_MASK
const I2C_STOP_ON_NACK0: u32 = 1 << 8;
// linux: DC_I2C_TRANSACTION0__DC_I2C_START0_MASK
const I2C_START0: u32 = 1 << 12;
// linux: DC_I2C_TRANSACTION0__DC_I2C_STOP0_MASK
const I2C_STOP0: u32 = 1 << 13;
// linux: DC_I2C_TRANSACTION0__DC_I2C_COUNT0_MASK
const I2C_COUNT0: u32 = 0x03ff_0000;
// DC_I2C_DATA fields.
// linux: DC_I2C_DATA__DC_I2C_DATA_RW_MASK
const I2C_DATA_RW: u32 = 1 << 0;
// linux: DC_I2C_DATA__DC_I2C_DATA_MASK
const I2C_DATA_FIELD: u32 = 0x0000_ff00;
// linux: DC_I2C_DATA__DC_I2C_INDEX_MASK
const I2C_INDEX: u32 = 0x03ff_0000;
// linux: DC_I2C_DATA__DC_I2C_INDEX_WRITE_MASK
const I2C_INDEX_WRITE: u32 = 1 << 31;
// MICROSECOND_TIME_BASE_DIV fields.
// linux: MICROSECOND_TIME_BASE_DIV__MICROSECOND_TIME_BASE_DIV_MASK
const TIME_BASE_DIV: u32 = 0x0000_007f;
// linux: MICROSECOND_TIME_BASE_DIV__XTAL_REF_DIV_MASK
const XTAL_REF_DIV: u32 = 0x0000_7f00;
/// `dcn2_i2c_hw_construct`: DCE100 buffer, DCN setup limit, a 9-cycle reset.
/// `SEND_RESET_LENGTH` is a single bit in DCN3.0, so Linux's
/// `set_reg_field_value(9)` lands as `(9 << 2) & 0x4`, which is one.
// linux: n/a (I2C_HW_BUFFER_SIZE_DCE100 = 538, dce_i2c_hw.h; not in checker sets)
const I2C_BUFFER_BYTES: u32 = 538;
// linux: n/a (I2C_SETUP_TIME_LIMIT_DCN = 3, dce_i2c_hw.h; not in checker sets)
const I2C_SETUP_TIME_LIMIT_DCN: u32 = 3;
/// `dc->caps.i2c_speed_in_khz` and `i2c_speed_in_khz_hdcp` for DCN3.0.
// linux: n/a (literal dc->caps.i2c_speed_in_khz = 100 in dcn30_resource.c)
pub const I2C_SPEED_KHZ: u32 = 100;
// linux: n/a (TRANSACTION_TIMEOUT_IN_I2C_CLOCKS = 32, dce_i2c_hw.h; not in checker sets)
const TRANSACTION_TIMEOUT_IN_I2C_CLOCKS: u32 = 32;
/// `EDID_SEGMENT_SIZE`: `link_query_ddc_data` splits I2C payloads at 256.
// linux: n/a (EDID_SEGMENT_SIZE = 256, link/protocols/link_ddc.h; not in checker sets)
const I2C_PAYLOAD_BYTES: usize = 256;
// dce_i2c_transaction_action.
// linux: n/a (DCE_I2C_TRANSACTION_ACTION_I2C_WRITE = 0x00, dce_i2c_hw.h; not in checker sets)
const I2C_ACTION_WRITE: u8 = 0x00;
// linux: n/a (DCE_I2C_TRANSACTION_ACTION_I2C_READ = 0x10, dce_i2c_hw.h; not in checker sets)
const I2C_ACTION_READ: u8 = 0x10;
// linux: n/a (DCE_I2C_TRANSACTION_ACTION_I2C_WRITE_MOT = 0x40, dce_i2c_hw.h; not in checker sets)
const I2C_ACTION_WRITE_MOT: u8 = 0x40;
// linux: n/a (DCE_I2C_TRANSACTION_ACTION_I2C_READ_MOT = 0x50, dce_i2c_hw.h; not in checker sets)
const I2C_ACTION_READ_MOT: u8 = 0x50;

// ── GPIO pads ──────────────────────────────────────────────────────────
/// `DC_GPIO_DDCn_MASK/A/EN/Y`, four dwords per line.
// linux: mmDC_GPIO_DDC1_MASK
const DC_GPIO_DDC1_MASK: u64 = 0x28d0;
// linux: mmDC_GPIO_DDC2_MASK - mmDC_GPIO_DDC1_MASK
const DC_GPIO_DDC_STRIDE: u64 = 4;
// linux: mmDC_GPIO_HPD_MASK
const DC_GPIO_HPD_MASK: u64 = 0x28f4;
// linux: mmPHY_AUX_CNTL
const PHY_AUX_CNTL: u64 = 0x28ff;
// linux: mmDC_GPIO_AUX_CTRL_5
const DC_GPIO_AUX_CTRL_5: u64 = 0x291d;
// DC_GPIO_DDCn_MASK/A/EN fields: the clock pin is bit 0, the data pin bit 8.
// linux: DC_GPIO_DDC1_MASK__DC_GPIO_DDC1CLK_MASK_MASK
const PIN_CLK: u32 = 1 << 0;
// linux: DC_GPIO_DDC1_MASK__DC_GPIO_DDC1DATA_MASK_MASK
const PIN_DATA: u32 = 1 << 8;
// linux: DC_GPIO_DDC1_MASK__DC_GPIO_DDC1CLK_PD_EN_MASK
const DDC_CLK_PD_EN: u32 = 1 << 4;
// linux: DC_GPIO_DDC1_MASK__DC_GPIO_DDC1DATA_PD_EN_MASK
const DDC_DATA_PD_EN: u32 = 1 << 12;
// linux: DC_GPIO_DDC1_MASK__AUX_PAD1_MODE_MASK
const AUX_PAD_MODE: u32 = 1 << 16;
/// `DC_GPIO_HPDn_MASK`: not the A/Y shifts — HPD4 is bit 20 here.
// linux: DC_GPIO_HPD_MASK__DC_GPIO_HPD1_MASK_MASK; DC_GPIO_HPD_MASK__DC_GPIO_HPD2_MASK_MASK; DC_GPIO_HPD_MASK__DC_GPIO_HPD3_MASK_MASK; DC_GPIO_HPD_MASK__DC_GPIO_HPD4_MASK_MASK; DC_GPIO_HPD_MASK__DC_GPIO_HPD5_MASK_MASK; DC_GPIO_HPD_MASK__DC_GPIO_HPD6_MASK_MASK
const HPD_GPIO_MASK: [u32; 6] = [1 << 0, 1 << 8, 1 << 16, 1 << 20, 1 << 24, 1 << 28];
/// `DC_GPIO_AUX_CTRL_5__DDC_PADn_I2CMODE` is bit 12 + n; `PHY_AUX_CNTL`'s
/// two-bit `AUXn_PAD_RXSEL` is at 10 + 2n.
const DDC_PAD_I2CMODE_SHIFT: u32 = 12; // linux: DC_GPIO_AUX_CTRL_5__DDC_PAD1_I2CMODE__SHIFT
const AUX_PAD_RXSEL_SHIFT: u32 = 10; // linux: PHY_AUX_CNTL__AUX1_PAD_RXSEL__SHIFT

// ── HPD instance block, stride 8 ───────────────────────────────────────
// linux: mmHPD0_DC_HPD_INT_STATUS
const DC_HPD_INT_STATUS: u64 = 0x1f14;
// linux: mmHPD0_DC_HPD_INT_CONTROL
const DC_HPD_INT_CONTROL: u64 = 0x1f15;
// linux: mmHPD0_DC_HPD_CONTROL
const DC_HPD_CONTROL: u64 = 0x1f16;
// linux: mmHPD0_DC_HPD_TOGGLE_FILT_CNTL
const DC_HPD_TOGGLE_FILT_CNTL: u64 = 0x1f18;
// linux: mmHPD1_DC_HPD_INT_STATUS - mmHPD0_DC_HPD_INT_STATUS
const HPD_STRIDE: u64 = 8;
// linux: HPD0_DC_HPD_INT_STATUS__DC_HPD_SENSE_MASK
const DC_HPD_SENSE: u32 = 1 << 1;
// linux: HPD0_DC_HPD_INT_STATUS__DC_HPD_SENSE_DELAYED_MASK
const DC_HPD_SENSE_DELAYED: u32 = 1 << 4;
// linux: HPD0_DC_HPD_INT_CONTROL__DC_HPD_INT_ACK_MASK
const DC_HPD_INT_ACK: u32 = 1 << 0;
// linux: HPD0_DC_HPD_INT_CONTROL__DC_HPD_INT_POLARITY_MASK
const DC_HPD_INT_POLARITY: u32 = 1 << 8;
// linux: HPD0_DC_HPD_INT_CONTROL__DC_HPD_INT_EN_MASK
const DC_HPD_INT_EN: u32 = 1 << 16;
// linux: HPD0_DC_HPD_INT_CONTROL__DC_HPD_RX_INT_ACK_MASK
const DC_HPD_RX_INT_ACK: u32 = 1 << 20;
// linux: HPD0_DC_HPD_INT_CONTROL__DC_HPD_RX_INT_EN_MASK
const DC_HPD_RX_INT_EN: u32 = 1 << 24;
// linux: HPD0_DC_HPD_CONTROL__DC_HPD_EN_MASK
const DC_HPD_EN: u32 = 1 << 28;
// linux: HPD0_DC_HPD_TOGGLE_FILT_CNTL__DC_HPD_CONNECT_INT_DELAY_MASK
const DC_HPD_CONNECT_INT_DELAY: u32 = 0x0000_00ff;
// linux: HPD0_DC_HPD_TOGGLE_FILT_CNTL__DC_HPD_DISCONNECT_INT_DELAY_MASK
const DC_HPD_DISCONNECT_INT_DELAY: u32 = 0x0ff0_0000;

/// `res_cap.num_ddc` and the HPD block count for DCN3.0.
// linux-ctx: reset
// linux: n/a (res_cap_dcn3.num_ddc = 6, literal in dcn30_resource.c)
pub const LINES: u8 = 6;
/// The highest dword touched at base index 2, for the bank bound.
const LAST_REG: u32 = DC_GPIO_AUX_CTRL_5 as u32; // linux: mmDC_GPIO_AUX_CTRL_5

// ── Retry policy, `dce_aux.c` ──────────────────────────────────────────
// linux: n/a (AUX_MAX_RETRIES 7, local #define in dce_aux.c)
const AUX_MAX_RETRIES: u32 = 7;
// linux: n/a (AUX_MIN_DEFER_RETRIES 7, local #define in dce_aux.c)
const AUX_MIN_DEFER_RETRIES: u32 = 7;
// linux: n/a (AUX_MAX_DEFER_TIMEOUT_MS 50, local #define in dce_aux.c)
const AUX_MAX_DEFER_TIMEOUT_MS: u32 = 50;
// linux: n/a (AUX_MAX_INVALID_REPLY_RETRIES 2, local #define in dce_aux.c)
const AUX_MAX_INVALID_REPLY_RETRIES: u32 = 2;
// linux: n/a (AUX_MAX_TIMEOUT_RETRIES 3, local #define in dce_aux.c)
const AUX_MAX_TIMEOUT_RETRIES: u32 = 3;
/// `DEFAULT_AUX_MAX_DATA_SIZE`.
// linux: DP_AUX_MAX_PAYLOAD_BYTES
pub const AUX_MAX_BYTES: usize = 16;
/// `SW_AUX_TIMEOUT_PERIOD_MULTIPLIER * AUX_TIMEOUT_PERIOD`, the construct-time
/// software poll budget before `configure_timeout` replaces it.
// linux: n/a (SW_AUX_TIMEOUT_PERIOD_MULTIPLIER * AUX_TIMEOUT_PERIOD = 6 * 400, dce_aux.h enum; not in checker sets)
const DEFAULT_POLL_US: u32 = 6 * 400;
/// `LINK_AUX_DEFAULT_TIMEOUT_PERIOD`, applied by link detection.
// linux: n/a (LINK_AUX_DEFAULT_TIMEOUT_PERIOD = 552, link/protocols/link_ddc.h; not in checker sets)
pub const AUX_TIMEOUT_US: u32 = 552;
// linux: n/a (SW_AUX_TIMEOUT_PERIOD_MULTIPLIER = 6, dce_aux.h enum; not in checker sets)
const SW_AUX_TIMEOUT_PERIOD_MULTIPLIER: u32 = 6;
// aux_transaction_reply, the reply byte's upper nibble.
const REPLY_AUX_ACK: u8 = 0x0; // linux: DP_AUX_NATIVE_REPLY_ACK
const REPLY_AUX_NACK: u8 = 0x1; // linux: DP_AUX_NATIVE_REPLY_NACK
const REPLY_AUX_DEFER: u8 = 0x2; // linux: DP_AUX_NATIVE_REPLY_DEFER
const REPLY_I2C_OVER_AUX_NACK: u8 = 0x4; // linux: DP_AUX_I2C_REPLY_NACK
const REPLY_I2C_OVER_AUX_DEFER: u8 = 0x8; // linux: DP_AUX_I2C_REPLY_DEFER

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    /// The line is not bound, or its owner has failed.
    Busy,
    Revoked,
    DeviceGone,
    /// Firmware (DMCU) or the hardware DDC requester owns the engine.
    Engine,
    /// No completion within the bounded wait.
    Timeout,
    /// The sink dropped HPD during the transaction.
    HpdDisconnected,
    InvalidReply,
    /// Native AUX NACK.
    Nack,
    /// I2C-over-AUX NACK or a hardware I2C stop-on-NACK: nothing at the address.
    I2cNack,
    /// Retries exhausted on DEFER replies.
    Defer,
    /// A read returned a different length than requested.
    ShortReply,
    /// The I2C engine aborted the transaction.
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    /// A register read returned all ones; nothing more is attempted.
    Failed,
}

/// The connector signal, which decides the HPD filter (`program_hpd_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Hdmi,
    DisplayPort,
}

/// Which DDC engine carries an I2C message: the DP AUX channel (I2C-over-AUX)
/// or the hardware I2C engine on an HDMI/DVI pad.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Aux,
    I2c,
}

/// One I2C message. Writes send `data`; reads fill it.
#[derive(Debug)]
pub struct Message<'a> {
    pub address: u8,
    pub write: bool,
    pub data: &'a mut [u8],
}

pub(crate) trait Io: Send {
    /// Absolute BAR dword index.
    fn read(&mut self, dword: u64) -> u32;
    fn write(&mut self, dword: u64, value: u32);
}
#[derive(Debug)]
pub(crate) struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
}
impl Io for Mmio {
    fn read(&mut self, dword: u64) -> u32 {
        // SAFETY: the constructor bounded both DCN banks inside the mapping.
        unsafe { self.regs.read32(dword * 4) }
    }
    fn write(&mut self, dword: u64, value: u32) {
        // SAFETY: same bounded banks; this owner is exclusive.
        unsafe { self.regs.write32(dword * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn field(value: u32, mask: u32) -> u32 {
    (value & mask) >> mask.trailing_zeros()
}
fn put(value: u32, mask: u32, field: u32) -> u32 {
    (value & !mask) | ((field << mask.trailing_zeros()) & mask)
}
async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// The stored pin state `store_registers` captures for both DDC pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pads {
    mask: u32,
    a: u32,
    en: u32,
}

/// `get_channel_status` outcomes, before the retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Success { reply: u8, bytes: usize },
    Timeout,
    InvalidReply,
    HpdDisconnected,
    Acquire,
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    authority: Cap<BusDeviceCap, Write>,
    /// DCN base index 2 and 1, as BAR dword indices.
    base: u64,
    base1: u64,
    state: State,
    /// Per-line `polling_timeout_period`, in microseconds.
    poll_us: [u32; LINES as usize],
    /// I2C transaction bookkeeping (`dce_i2c_hw`).
    transactions: u32,
    used_bytes: u32,
    used_write: u32,
    /// `fw_info.pll_info.crystal_frequency`, zero when unknown.
    pub(crate) crystal_khz: u32,
}

impl<I: Io> Engine<I> {
    pub(crate) fn new_with(
        io: I,
        authority: Cap<BusDeviceCap, Write>,
        base: u64,
        base1: u64,
    ) -> Self {
        Self {
            io,
            authority,
            base,
            base1,
            state: State::Ready,
            poll_us: [DEFAULT_POLL_US; LINES as usize],
            transactions: 0,
            used_bytes: 0,
            used_write: 0,
            crystal_khz: 0,
        }
    }
    fn check(&self, line: u8) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        // linux: n/a (NARF bound: six DDC lines)
        if line >= LINES {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let dword = self.base + reg;
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(dword)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            self.state = State::Failed;
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let dword = self.base + reg;
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(dword, value)))
            .map_err(|_| Error::Revoked)
    }
    /// `REG_UPDATE_N`: read, replace the masked bits, write. Returns the value
    /// written so `REG_SET` chains can continue from it.
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<u32, Error> {
        let new = (self.read(reg)? & !mask) | (value & mask);
        self.write(reg, new)?;
        Ok(new)
    }
    /// `REG_WAIT`: bounded poll of a field, `tries` reads `interval_us` apart.
    /// Returns whether the field reached `expected`.
    async fn wait(
        &mut self,
        reg: u64,
        mask: u32,
        expected: u32,
        interval_us: u64,
        tries: u32,
    ) -> Result<bool, Error> {
        for attempt in 0..tries.max(1) {
            if self.read(reg)? & mask == expected & mask {
                return Ok(true);
            }
            if attempt + 1 < tries {
                sleep_us(interval_us).await;
            }
        }
        Ok(false)
    }
    fn aux(line: u8, reg: u64) -> u64 {
        reg + u64::from(line) * AUX_STRIDE
    }
    fn hpd(index: u8, reg: u64) -> u64 {
        reg + u64::from(index) * HPD_STRIDE
    }
    fn pad(line: u8, offset: u64) -> u64 {
        DC_GPIO_DDC1_MASK + u64::from(line) * DC_GPIO_DDC_STRIDE + offset
    }

    // ── GPIO pad ownership (dal_ddc_open / dal_ddc_close) ──────────────
    /// `dal_hw_gpio_open` for the data then the clock pin in hardware mode,
    /// then `set_config` on the data pin for the requested pad mode.
    async fn open_pads(&mut self, line: u8, mode: Mode) -> Result<Pads, Error> {
        let pins = PIN_DATA | PIN_CLK;
        let pads = Pads {
            mask: self.read(Self::pad(line, 0))? & pins,
            // linux-lit: 1=mmDC_GPIO_DDC1_A - mmDC_GPIO_DDC1_MASK
            a: self.read(Self::pad(line, 1))? & pins,
            // linux-lit: 2=mmDC_GPIO_DDC1_EN - mmDC_GPIO_DDC1_MASK
            en: self.read(Self::pad(line, 2))? & pins,
        };
        // GPIO_MODE_HARDWARE: the pin is tri-stated and driven by the engine.
        self.update(Self::pad(line, 0), PIN_DATA, 0)?;
        self.update(Self::pad(line, 0), PIN_CLK, 0)?;
        let regval = self.read(Self::pad(line, 0))?;
        let i2cmode = 1 << (DDC_PAD_I2CMODE_SHIFT + u32::from(line));
        match mode {
            Mode::Aux => {
                if regval & AUX_PAD_MODE == 0 {
                    self.write(Self::pad(line, 0), regval | AUX_PAD_MODE)?;
                }
                self.update(DC_GPIO_AUX_CTRL_5, i2cmode, 0)?;
            }
            Mode::I2c => {
                // A plug-in transient must be discharged through the pull-downs.
                if regval & DDC_DATA_PD_EN == 0 || regval & DDC_CLK_PD_EN == 0 {
                    self.write(Self::pad(line, 0), regval | DDC_DATA_PD_EN | DDC_CLK_PD_EN)?;
                }
                if regval & AUX_PAD_MODE != 0 {
                    // Let the pins de-assert before switching the pad to I2C.
                    if pads.en != 0 {
                        // linux: n/a (msleep(2), literal in gpio/hw_ddc.c:set_config)
                        sleep_us(2000).await;
                    }
                    self.update(Self::pad(line, 0), AUX_PAD_MODE, 0)?;
                }
                self.update(DC_GPIO_AUX_CTRL_5, i2cmode, i2cmode)?;
                // linux-lit: 0x3=PHY_AUX_CNTL__AUX1_PAD_RXSEL_MASK >> PHY_AUX_CNTL__AUX1_PAD_RXSEL__SHIFT; 2=PHY_AUX_CNTL__AUX2_PAD_RXSEL__SHIFT - PHY_AUX_CNTL__AUX1_PAD_RXSEL__SHIFT
                let rxsel = 0x3 << (AUX_PAD_RXSEL_SHIFT + 2 * u32::from(line));
                self.update(
                    PHY_AUX_CNTL,
                    rxsel,
                    // linux-lit: 2=PHY_AUX_CNTL__AUX2_PAD_RXSEL__SHIFT - PHY_AUX_CNTL__AUX1_PAD_RXSEL__SHIFT
                    1 << (AUX_PAD_RXSEL_SHIFT + 2 * u32::from(line)),
                )?;
            }
        }
        Ok(pads)
    }
    /// `dal_ddc_close`: restore the clock pin, then the data pin.
    fn close_pads(&mut self, line: u8, pads: Pads) -> Result<(), Error> {
        for pin in [PIN_CLK, PIN_DATA] {
            self.update(Self::pad(line, 0), pin, pads.mask)?;
            // linux-lit: 1=mmDC_GPIO_DDC1_A - mmDC_GPIO_DDC1_MASK
            self.update(Self::pad(line, 1), pin, pads.a)?;
            // linux-lit: 2=mmDC_GPIO_DDC1_EN - mmDC_GPIO_DDC1_MASK
            self.update(Self::pad(line, 2), pin, pads.en)?;
        }
        Ok(())
    }

    // ── AUX ────────────────────────────────────────────────────────────
    /// The AUX half of `enc3_hw_init` + `dcn10_aux_initialize`, then
    /// `dce_aux_configure_timeout(LINK_AUX_DEFAULT_TIMEOUT_PERIOD)`.
    fn bind_aux(&mut self, line: u8, hpd_source: u8) -> Result<(), Error> {
        self.write(Self::aux(line, AUX_DPHY_RX_CONTROL0), DCN30_AUX_RX_CONTROL0)?;
        self.write(Self::aux(line, AUX_DPHY_TX_CONTROL), DCN30_AUX_TX_CONTROL)?;
        self.update(
            Self::aux(line, AUX_CONTROL),
            AUX_HPD_SEL | AUX_LS_READ_EN,
            put(0, AUX_HPD_SEL, u32::from(hpd_source)),
        )?;
        // One quarter window, the maximum allowed.
        self.update(
            Self::aux(line, AUX_DPHY_RX_CONTROL0),
            AUX_RX_RECEIVE_WINDOW,
            0,
        )?;
        self.configure_timeout(line, AUX_TIMEOUT_US)
    }
    /// `dce_aux_configure_timeout`. Returns nothing: callers never restore.
    fn configure_timeout(&mut self, line: u8, timeout_us: u32) -> Result<(), Error> {
        self.poll_us[usize::from(line)] = timeout_us * SW_AUX_TIMEOUT_PERIOD_MULTIPLIER;
        let (multiplier, unit) = match timeout_us {
            // linux: n/a (DEFAULT_AUX_ENGINE_MULT 0, local #define in dce_aux.c)
            0 => (0, 0),
            // linux: n/a (TIME_OUT_INCREMENT 1016 / TIME_OUT_MULTIPLIER_8, local #defines in dce_aux.c)
            t if t <= 1016 => (0, 8),
            // linux: n/a (TIME_OUT_INCREMENT / TIME_OUT_MULTIPLIER_16, local #defines in dce_aux.c)
            t if t <= 2 * 1016 => (1, 16),
            // linux: n/a (TIME_OUT_INCREMENT / TIME_OUT_MULTIPLIER_32, local #defines in dce_aux.c)
            t if t <= 4 * 1016 => (2, 32),
            _ => (3, 64), // linux: n/a (TIME_OUT_MULTIPLIER_64, local #define in dce_aux.c)
        };
        let length = if unit == 0 {
            69 // linux: n/a (DEFAULT_AUX_ENGINE_LENGTH 69, local #define in dce_aux.c)
        } else {
            timeout_us.div_ceil(unit)
        }
        .min(127); // linux: n/a (MAX_TIMEOUT_LENGTH 127, local #define in dce_aux.c)
        let reg = Self::aux(line, AUX_DPHY_RX_CONTROL1);
        // REG_UPDATE_SEQ_2: the length, then the multiplier, as two writes.
        let value = self.update(reg, AUX_RX_TIMEOUT_LEN, put(0, AUX_RX_TIMEOUT_LEN, length))?;
        self.write(reg, put(value, AUX_RX_TIMEOUT_LEN_MUL, multiplier))
    }
    /// `acquire`: refuse a DMCU-owned engine, open the pads in AUX mode, then
    /// `acquire_engine`. On refusal the pads and arbitration are released.
    async fn acquire_aux(&mut self, line: u8) -> Result<Option<Pads>, Error> {
        let arb = self.read(Self::aux(line, AUX_ARB_CONTROL))?;
        if field(arb, AUX_REG_RW_CNTL_STATUS) == DMCU_CAN_ACCESS_AUX {
            return Ok(None);
        }
        let pads = self.open_pads(line, Mode::Aux).await?;
        match self.acquire_aux_engine(line).await {
            Ok(true) => Ok(Some(pads)),
            Ok(false) => {
                self.release_aux(line, pads)?;
                Ok(None)
            }
            Err(error) => {
                let _ = self.release_aux(line, pads);
                Err(error)
            }
        }
    }
    async fn acquire_aux_engine(&mut self, line: u8) -> Result<bool, Error> {
        let arb = self.read(Self::aux(line, AUX_ARB_CONTROL))?;
        if field(arb, AUX_REG_RW_CNTL_STATUS) == DMCU_CAN_ACCESS_AUX {
            return Ok(false);
        }
        let control = Self::aux(line, AUX_CONTROL);
        let value = self.read(control)?;
        if value & AUX_EN == 0 {
            // DCN3.0 supplies AUX_RESET_MASK, so enabling includes a reset.
            self.write(control, value | AUX_EN | AUX_RESET)?;
            if !self
                // linux: n/a (REG_WAIT 1 us x 11, literals in dce_aux.c:acquire_engine)
                .wait(control, AUX_RESET_DONE, AUX_RESET_DONE, 1, 11)
                .await?
            {
                return Err(Error::Timeout);
            }
            self.write(control, (value | AUX_EN) & !AUX_RESET)?;
            // linux: n/a (REG_WAIT 1 us x 11, literals in dce_aux.c:acquire_engine)
            if !self.wait(control, AUX_RESET_DONE, 0, 1, 11).await? {
                return Err(Error::Timeout);
            }
        }
        self.update(
            Self::aux(line, AUX_ARB_CONTROL),
            AUX_SW_USE_AUX_REG_REQ,
            AUX_SW_USE_AUX_REG_REQ,
        )?;
        let arb = self.read(Self::aux(line, AUX_ARB_CONTROL))?;
        Ok(field(arb, AUX_REG_RW_CNTL_STATUS) == SW_CAN_ACCESS_AUX)
    }
    /// `release_engine`: close the pads, then hand arbitration back.
    fn release_aux(&mut self, line: u8, pads: Pads) -> Result<(), Error> {
        let closed = self.close_pads(line, pads);
        self.update(
            Self::aux(line, AUX_ARB_CONTROL),
            AUX_SW_DONE_USING_AUX_REG | AUX_SW_USE_AUX_REG_REQ,
            AUX_SW_DONE_USING_AUX_REG,
        )?;
        closed
    }
    /// `submit_channel_request` with a zero start delay.
    async fn submit_aux(
        &mut self,
        line: u8,
        action: u8,
        address: u32,
        data: &[u8],
        write: bool,
    ) -> Result<(), Error> {
        self.update(
            Self::aux(line, AUX_INTERRUPT_CONTROL),
            AUX_SW_DONE_ACK,
            AUX_SW_DONE_ACK,
        )?;
        let poll = self.poll_us[usize::from(line)];
        // Linux proceeds after this bounded wait whatever the result; the
        // completion check below catches an engine that never idled.
        self.wait(
            Self::aux(line, AUX_SW_STATUS),
            AUX_SW_DONE,
            0,
            // linux: n/a (REG_WAIT 10 us, literal in dce_aux.c:submit_channel_request)
            10,
            // linux: n/a (polling_timeout_period/10, literal in dce_aux.c:submit_channel_request)
            poll / 10,
        )
        .await?;
        // Three header bytes, a length byte if any data, and the payload.
        // linux: n/a (length 3 or 4 header bytes, literals in dce_aux.c:submit_channel_request)
        let mut length = if data.is_empty() { 3 } else { 4 };
        if write {
            length += data.len() as u32;
        }
        self.update(
            Self::aux(line, AUX_SW_CONTROL),
            AUX_SW_START_DELAY | AUX_SW_WR_BYTES,
            put(0, AUX_SW_WR_BYTES, length),
        )?;
        let reg = Self::aux(line, AUX_SW_DATA);
        let mut value = self.update(
            reg,
            AUX_SW_INDEX | AUX_SW_DATA_RW | AUX_SW_AUTOINCREMENT_DISABLE | AUX_SW_DATA_FIELD,
            AUX_SW_AUTOINCREMENT_DISABLE
                | put(
                    0,
                    AUX_SW_DATA_FIELD,
                    // linux: n/a (COMPOSE_AUX_SW_DATA_16_20, local macro in dce_aux.c)
                    u32::from(action) | (address >> 16) & 0xf,
                ),
        )?;
        value = put(
            value & !AUX_SW_AUTOINCREMENT_DISABLE,
            AUX_SW_DATA_FIELD,
            // linux: n/a (COMPOSE_AUX_SW_DATA_8_15, local macro in dce_aux.c)
            (address >> 8) & 0xff,
        );
        self.write(reg, value)?;
        // linux: n/a (COMPOSE_AUX_SW_DATA_0_7, local macro in dce_aux.c)
        value = put(value, AUX_SW_DATA_FIELD, address & 0xff);
        self.write(reg, value)?;
        if !data.is_empty() {
            // linux: n/a (request->length - 1, dce_aux.c:submit_channel_request)
            value = put(value, AUX_SW_DATA_FIELD, data.len() as u32 - 1);
            self.write(reg, value)?;
        }
        if write {
            for &byte in data {
                value = put(value, AUX_SW_DATA_FIELD, u32::from(byte));
                self.write(reg, value)?;
            }
        }
        self.update(Self::aux(line, AUX_SW_CONTROL), AUX_SW_GO, AUX_SW_GO)?;
        Ok(())
    }
    /// `get_channel_status`.
    async fn aux_status(&mut self, line: u8) -> Result<Outcome, Error> {
        let reg = Self::aux(line, AUX_SW_STATUS);
        let poll = self.poll_us[usize::from(line)];
        // linux: n/a (REG_WAIT 10 us x polling_timeout_period/10, literals in dce_aux.c:get_channel_status)
        self.wait(reg, AUX_SW_DONE, AUX_SW_DONE, 10, poll / 10)
            .await?;
        let value = self.read(reg)?;
        if value & AUX_SW_HPD_DISCON != 0 {
            return Ok(Outcome::HpdDisconnected);
        }
        if value & AUX_SW_DONE == 0 {
            return Ok(Outcome::Timeout);
        }
        if value & (AUX_SW_RX_TIMEOUT_STATE | AUX_SW_RX_TIMEOUT) != 0 {
            return Ok(Outcome::Timeout);
        }
        if value
            & (AUX_SW_RX_INVALID_STOP
                | AUX_SW_RX_RECV_NO_DET
                | AUX_SW_RX_RECV_INVALID_H
                | AUX_SW_RX_RECV_INVALID_L)
            != 0
        {
            return Ok(Outcome::InvalidReply);
        }
        match field(value, AUX_SW_REPLY_BYTE_COUNT) {
            0 => Ok(Outcome::InvalidReply),
            count => Ok(Outcome::Success {
                reply: 0,
                // linux: n/a (reply byte excluded, dce_aux.c:get_channel_status)
                bytes: count as usize - 1,
            }),
        }
    }
    /// `read_channel_reply`: the reply nibble, then ACKed data when it fits.
    fn aux_reply(&mut self, line: u8, buffer: &mut [u8]) -> Result<Option<u8>, Error> {
        let status = self.read(Self::aux(line, AUX_SW_STATUS))?;
        let mut replied = field(status, AUX_SW_REPLY_BYTE_COUNT) as usize;
        if status & AUX_SW_HPD_DISCON != 0 || replied == 0 {
            return Ok(None);
        }
        let reg = Self::aux(line, AUX_SW_DATA);
        // REG_UPDATE_SEQ_3: index zero, then index load, then read mode.
        let mut value = self.update(reg, AUX_SW_INDEX, 0)?;
        value |= AUX_SW_AUTOINCREMENT_DISABLE;
        self.write(reg, value)?;
        self.write(reg, value | AUX_SW_DATA_RW)?;
        // linux: n/a (reply_result_32 >> 4, literal in dce_aux.c:read_channel_reply)
        let reply = (field(self.read(reg)?, AUX_SW_DATA_FIELD) >> 4) as u8;
        if reply == REPLY_AUX_ACK {
            replied -= 1;
            if replied <= buffer.len() {
                for byte in &mut buffer[..replied] {
                    *byte = field(self.read(reg)?, AUX_SW_DATA_FIELD) as u8;
                }
            }
        }
        Ok(Some(reply))
    }
    /// `dce_aux_transfer_raw`: one transaction, no retries.
    async fn transfer_raw(
        &mut self,
        line: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
        write: bool,
    ) -> Result<Outcome, Error> {
        let Some(pads) = self.acquire_aux(line).await? else {
            return Ok(Outcome::Acquire);
        };
        let mut session = AuxSession {
            engine: self,
            line,
            pads: Some(pads),
        };
        let result = session.run(action, address, data, write).await;
        let release = session.finish();
        let outcome = result?;
        release?;
        Ok(outcome)
    }
    /// `dce_aux_transfer_with_retries`. Returns the replied byte count.
    async fn transfer(&mut self, line: u8, request: &mut AuxRequest<'_>) -> Result<usize, Error> {
        self.check(line)?;
        // linux: n/a (DP AUX 20-bit address space)
        if request.data.len() > AUX_MAX_BYTES || request.address >= 1 << 20 {
            return Err(Error::Invalid);
        }
        let mut write = request.write;
        let mut status_update = false;
        let mut length = request.data.len();
        let (mut ack, mut ack_m, mut defer) = (0, 0, 0);
        let (mut timeouts, mut invalid) = (0, 0);
        let mut defer_ms = 0;
        let mut retry_on_defer = false;
        let mut last = Error::Timeout;
        for _ in 0..AUX_MAX_RETRIES {
            let action = action(request.i2c, write, request.mot, status_update);
            let is_write = write && !status_update;
            let outcome = self
                .transfer_raw(
                    line,
                    action,
                    request.address,
                    &mut request.data[..length],
                    is_write,
                )
                .await?;
            match outcome {
                Outcome::Success { reply, bytes } => {
                    timeouts = 0;
                    invalid = 0;
                    match reply {
                        REPLY_AUX_ACK => {
                            if !write && length != bytes {
                                ack += 1;
                                last = Error::ShortReply;
                                if ack >= AUX_MAX_RETRIES {
                                    return Err(last);
                                }
                                // linux: n/a (udelay(300), literal in dce_aux.c:dce_aux_transfer_with_retries)
                                sleep_us(300).await;
                            } else if write && bytes > 0 {
                                // AUX_ACKM: poll the write status until done.
                                ack_m += 1;
                                last = Error::Defer;
                                if ack_m >= AUX_MAX_RETRIES {
                                    return Err(last);
                                }
                                write = false;
                                status_update = true;
                                length = 0;
                                // linux: n/a (udelay(300), literal in dce_aux.c:dce_aux_transfer_with_retries)
                                sleep_us(300).await;
                            } else {
                                return Ok(bytes);
                            }
                        }
                        REPLY_AUX_DEFER | REPLY_I2C_OVER_AUX_DEFER => {
                            if reply == REPLY_AUX_DEFER {
                                // linux: n/a (us to ms)
                                defer_ms += self.poll_us[usize::from(line)] / 1000;
                                defer += 1;
                            }
                            retry_on_defer = true;
                            last = Error::Defer;
                            if defer >= AUX_MIN_DEFER_RETRIES
                                && defer_ms >= AUX_MAX_DEFER_TIMEOUT_MS
                            {
                                return Err(last);
                            }
                            // The payload's defer delay is zero for native sinks.
                        }
                        REPLY_I2C_OVER_AUX_NACK => return Err(Error::I2cNack),
                        REPLY_AUX_NACK => return Err(Error::Nack),
                        // AUX_TRANSACTION_REPLY_I2C_DEFER (0x20) cannot be
                        // encoded in the reply nibble; anything else is fatal.
                        _ => return Err(Error::InvalidReply),
                    }
                }
                Outcome::InvalidReply => {
                    invalid += 1;
                    last = Error::InvalidReply;
                    if invalid >= AUX_MAX_INVALID_REPLY_RETRIES {
                        return Err(last);
                    }
                    // linux: n/a (udelay(400), literal in dce_aux.c:dce_aux_transfer_with_retries)
                    sleep_us(400).await;
                }
                Outcome::Timeout => {
                    if retry_on_defer {
                        // A timeout after a DEFER counts as another DEFER.
                        defer += 1;
                        last = Error::Defer;
                        if defer >= AUX_MIN_DEFER_RETRIES {
                            return Err(last);
                        }
                    } else {
                        timeouts += 1;
                        last = Error::Timeout;
                        // The hardware already waited 550us between tries.
                        if timeouts >= AUX_MAX_TIMEOUT_RETRIES {
                            return Err(last);
                        }
                    }
                }
                Outcome::HpdDisconnected => return Err(Error::HpdDisconnected),
                Outcome::Acquire => return Err(Error::Engine),
            }
        }
        Err(last)
    }
    /// `link_query_ddc_data` in AUX mode: `submit_aux_command` splits each
    /// message into 16-byte chunks, keeping MOT set until the last one.
    async fn aux_messages(&mut self, line: u8, messages: &mut [Message<'_>]) -> Result<(), Error> {
        let count = messages.len();
        for (index, message) in messages.iter_mut().enumerate() {
            let mot = index + 1 < count;
            let mut done = 0;
            loop {
                let end = (done + AUX_MAX_BYTES).min(message.data.len());
                let last = end == message.data.len();
                let mut request = AuxRequest {
                    i2c: true,
                    write: message.write,
                    mot: if last { mot } else { true },
                    address: u32::from(message.address),
                    data: &mut message.data[done..end],
                };
                self.transfer(line, &mut request).await?;
                done = end;
                if last {
                    break;
                }
            }
        }
        Ok(())
    }

    // ── Hardware I2C engine ────────────────────────────────────────────
    fn i2c_setup(line: u8) -> u64 {
        // linux-lit: 2=mmDC_I2C_DDC2_SETUP - mmDC_I2C_DDC1_SETUP
        DC_I2C_DDC1_SETUP + 2 * u64::from(line)
    }
    fn i2c_speed(line: u8) -> u64 {
        // linux-lit: 2=mmDC_I2C_DDC2_SPEED - mmDC_I2C_DDC1_SPEED
        DC_I2C_DDC1_SPEED + 2 * u64::from(line)
    }
    /// `is_engine_available`.
    fn i2c_available(&mut self, line: u8) -> Result<bool, Error> {
        let hw = self.read(DC_I2C_DDC1_HW_STATUS + u64::from(line))?;
        if field(hw, I2C_HW_STATUS_FIELD) == I2C_STATUS_USED_BY_HW {
            return Ok(false);
        }
        let arb = self.read(DC_I2C_ARBITRATION)?;
        Ok(field(arb, I2C_REG_RW_CNTL_STATUS) != I2C_DMCU_ONLY)
    }
    /// `is_hw_busy`.
    fn i2c_busy(&mut self, line: u8) -> Result<bool, Error> {
        let status = self.read(DC_I2C_SW_STATUS)?;
        if field(status, I2C_SW_STATUS_FIELD) == I2C_STATUS_IDLE {
            return Ok(false);
        }
        Ok(!self.i2c_available(line)?)
    }
    /// `set_speed`. With a zero time-base divider (a DCN not yet through
    /// `dccg2_init`, e.g. after reset-on-init) Linux uses
    /// `reference_frequency * 2`, the VBIOS crystal (`dce_refclk_10khz`).
    fn i2c_set_speed(&mut self, line: u8, khz: u32) -> Result<(), Error> {
        let time_base = {
            let dword = self.base1 + MICROSECOND_TIME_BASE_DIV;
            let io = &mut self.io;
            self.authority
                .invoke(Op(|| io.read(dword)))
                .map_err(|_| Error::Revoked)?
        };
        if time_base == u32::MAX {
            self.state = State::Failed;
            return Err(Error::DeviceGone);
        }
        let reference_div = field(time_base, TIME_BASE_DIV);
        let xtal_div = match field(time_base, XTAL_REF_DIV) {
            0 => 2, // linux: n/a (xtal_ref_div default 2, literal in dce_i2c_hw.c:set_speed)
            div => div,
        };
        let reference_khz = if reference_div == 0 {
            self.crystal_khz
        } else {
            // linux: n/a (ref_base_div * 1000, literal in dce_i2c_hw.c:set_speed)
            reference_div * 1000
        };
        if reference_khz == 0 || khz == 0 {
            return Err(Error::Unsupported);
        }
        let prescale = reference_khz / xtal_div / khz;
        self.update(
            Self::i2c_speed(line),
            I2C_PRESCALE | I2C_THRESHOLD | I2C_START_STOP_TIMING_CNTL,
            put(0, I2C_PRESCALE, prescale)
                // linux: n/a (THRESHOLD 2, literal in dce_i2c_hw.c:set_speed)
                | put(0, I2C_THRESHOLD, 2)
                // linux: n/a (speed > 50 ? 2 : 1, literals in dce_i2c_hw.c:set_speed)
                | put(0, I2C_START_STOP_TIMING_CNTL, if khz > 50 { 2 } else { 1 }),
        )?;
        Ok(())
    }
    /// `acquire_engine`.
    fn i2c_acquire_engine(&mut self) -> Result<bool, Error> {
        match field(self.read(DC_I2C_ARBITRATION)?, I2C_REG_RW_CNTL_STATUS) {
            I2C_STATUS_USED_BY_SW => return Ok(true),
            I2C_STATUS_USED_BY_HW => return Ok(false),
            _ => {}
        }
        self.update(
            DC_I2C_ARBITRATION,
            I2C_SW_USE_I2C_REG_REQ,
            I2C_SW_USE_I2C_REG_REQ,
        )?;
        Ok(field(self.read(DC_I2C_ARBITRATION)?, I2C_REG_RW_CNTL_STATUS) == I2C_STATUS_USED_BY_SW)
    }
    /// `setup_engine`.
    fn i2c_setup_engine(&mut self, line: u8) -> Result<bool, Error> {
        self.update(DC_I2C_CONTROL, I2C_SOFT_RESET, 0)?;
        if !self.i2c_acquire_engine()? {
            return Ok(false);
        }
        self.i2c_set_speed(line, I2C_SPEED_KHZ)?;
        self.update(
            DC_I2C_CONTROL,
            I2C_GO | I2C_SEND_RESET | I2C_SW_STATUS_RESET | I2C_TRANSACTION_COUNT | I2C_DDC_SELECT,
            I2C_SW_STATUS_RESET | put(0, I2C_DDC_SELECT, u32::from(line)),
        )?;
        self.update(
            Self::i2c_setup(line),
            I2C_TIME_LIMIT | I2C_SEND_RESET_LENGTH | I2C_DDC_ENABLE,
            put(0, I2C_TIME_LIMIT, I2C_SETUP_TIME_LIMIT_DCN)
                | I2C_SEND_RESET_LENGTH
                | I2C_DDC_ENABLE,
        )?;
        self.update(DC_I2C_ARBITRATION, I2C_NO_QUEUED_SW_GO, 0)?;
        Ok(true)
    }
    /// `release_engine`. Keeps `DDC_ENABLE` (`engine_keep_power_up_count`).
    fn i2c_release_engine(&mut self, line: u8) -> Result<(), Error> {
        let status = self.read(DC_I2C_SW_STATUS)?;
        if field(status, I2C_SW_STATUS_FIELD) == I2C_STATUS_USED_BY_SW {
            self.update(
                DC_I2C_CONTROL,
                I2C_SOFT_RESET | I2C_SW_STATUS_RESET,
                I2C_SOFT_RESET | I2C_SW_STATUS_RESET,
            )?;
        } else {
            self.update(DC_I2C_CONTROL, I2C_SW_STATUS_RESET, I2C_SW_STATUS_RESET)?;
        }
        // The HDCP-speed reprogramming must not stop arbitration being returned.
        let speed = self.i2c_set_speed(line, I2C_SPEED_KHZ);
        self.update(
            DC_I2C_ARBITRATION,
            I2C_SW_DONE_USING_I2C_REG,
            I2C_SW_DONE_USING_I2C_REG,
        )?;
        // cntl_stuck_hw_workaround: release once more if still held.
        if field(self.read(DC_I2C_ARBITRATION)?, I2C_REG_RW_CNTL_STATUS) == I2C_STATUS_USED_BY_SW {
            self.update(
                DC_I2C_ARBITRATION,
                I2C_SW_DONE_USING_I2C_REG,
                I2C_SW_DONE_USING_I2C_REG,
            )?;
        }
        speed
    }
    /// `get_channel_status`, mapped to a terminal error or busy/success.
    fn i2c_status(&mut self) -> Result<Option<Result<(), Error>>, Error> {
        let value = self.read(DC_I2C_SW_STATUS)?;
        Ok(
            if field(value, I2C_SW_STATUS_FIELD) == I2C_STATUS_USED_BY_SW {
                None
            } else if value & I2C_SW_STOPPED_ON_NACK != 0 {
                Some(Err(Error::I2cNack))
            } else if value & I2C_SW_TIMEOUT != 0 {
                Some(Err(Error::Timeout))
            } else if value & I2C_SW_ABORTED != 0 {
                Some(Err(Error::Aborted))
            } else {
                // DONE, or zero after the hardware requester used the engine.
                Some(Ok(()))
            },
        )
    }
    /// `process_transaction`: queue one transaction; true when it must run.
    fn i2c_queue(&mut self, line: u8, action: u8, address: u8, data: &[u8]) -> Result<bool, Error> {
        if self.i2c_busy(line)? {
            return Err(Error::Engine);
        }
        let read = action & I2C_ACTION_READ != 0;
        // linux: n/a (transaction_count == 3, literal in dce_i2c_hw.c:process_transaction)
        let last = self.transactions == 3 || action == I2C_ACTION_WRITE || read;
        let length = data.len() as u32;
        self.update(
            DC_I2C_TRANSACTION0 + u64::from(self.transactions),
            I2C_STOP_ON_NACK0 | I2C_START0 | I2C_RW0 | I2C_COUNT0 | I2C_STOP0,
            I2C_STOP_ON_NACK0
                | I2C_START0
                | if read { I2C_RW0 } else { 0 }
                | put(0, I2C_COUNT0, length)
                | if last { I2C_STOP0 } else { 0 },
        )?;
        let mut value = put(0, I2C_DATA_FIELD, u32::from(address));
        if self.transactions == 0 {
            value |= I2C_INDEX_WRITE;
            self.used_write = 0;
        }
        self.write(DC_I2C_DATA, value)?;
        self.used_write += 1;
        if !read {
            for &byte in data {
                value = put(value & !I2C_INDEX_WRITE, I2C_DATA_FIELD, u32::from(byte));
                self.write(DC_I2C_DATA, value)?;
                self.used_write += 1;
            }
        }
        self.transactions += 1;
        // linux: n/a (length + 1 address byte, dce_i2c_hw.c:process_transaction)
        self.used_bytes += length + 1;
        Ok(last)
    }
    /// `execute_transaction`.
    fn i2c_execute(&mut self, line: u8) -> Result<(), Error> {
        self.update(
            Self::i2c_setup(line),
            I2C_DATA_DRIVE_EN
                | I2C_CLK_DRIVE_EN
                | I2C_DATA_DRIVE_SEL
                | I2C_INTRA_TRANSACTION_DELAY
                | I2C_INTRA_BYTE_DELAY,
            0,
        )?;
        self.update(
            DC_I2C_CONTROL,
            I2C_SOFT_RESET | I2C_SW_STATUS_RESET | I2C_SEND_RESET | I2C_GO | I2C_TRANSACTION_COUNT,
            // linux: n/a (transaction_count - 1, dce_i2c_hw.c:execute_transaction)
            put(0, I2C_TRANSACTION_COUNT, self.transactions - 1),
        )?;
        self.update(DC_I2C_CONTROL, I2C_GO, I2C_GO)?;
        self.transactions = 0;
        self.used_bytes = 0;
        Ok(())
    }
    /// `dce_i2c_hw_engine_submit_payload`.
    async fn i2c_payload(
        &mut self,
        line: u8,
        message: &mut Message<'_>,
        mot: bool,
    ) -> Result<(), Error> {
        let length = message.data.len() as u32;
        if length >= I2C_BUFFER_BYTES - self.used_bytes {
            return Err(Error::Invalid);
        }
        let action = match (message.write, mot) {
            (false, true) => I2C_ACTION_READ_MOT,
            (false, false) => I2C_ACTION_READ,
            (true, true) => I2C_ACTION_WRITE_MOT,
            (true, false) => I2C_ACTION_WRITE,
        };
        // linux: n/a (7-bit address << 1 | read, dce_i2c_hw.c:dce_i2c_submit_command_hw)
        let address = message.address << 1 | u8::from(!message.write);
        // `get_transaction_timeout_hw`, taken before submission.
        // linux: n/a (1000 * clocks / speed, dce_i2c_hw.c:get_transaction_timeout_hw)
        let period = 1000 * TRANSACTION_TIMEOUT_IN_I2C_CLOCKS / I2C_SPEED_KHZ;
        let stretches =
            // linux: n/a (clock-stretch count, literals in dce_i2c_hw.c:get_transaction_timeout_hw)
            1 + ((length + 1) << 3) + 1 + (self.used_bytes << 3) + (self.transactions << 1);
        let timeout_us = u64::from(period * stretches);
        if self.i2c_queue(line, action, address, message.data)? {
            if self.i2c_busy(line)? {
                return Err(Error::Engine);
            }
            self.update(DC_I2C_CONTROL, I2C_SW_STATUS_RESET, I2C_SW_STATUS_RESET)?;
            self.i2c_execute(line)?;
        }
        let deadline = narf_time::Deadline::after_us(timeout_us);
        let result = loop {
            if let Some(result) = self.i2c_status()? {
                break result;
            }
            if deadline.expired() {
                break Err(Error::Timeout);
            }
            // linux: n/a (NARF poll interval; Linux polls 1 us in dce_i2c_hw_engine_wait_on_operation_result)
            sleep_us(10).await;
        };
        result?;
        if !message.write {
            // process_channel_reply: read from just past the address bytes.
            self.write(
                DC_I2C_DATA,
                put(0, I2C_INDEX, self.used_write) | I2C_DATA_RW | I2C_INDEX_WRITE,
            )?;
            for byte in message.data.iter_mut() {
                *byte = field(self.read(DC_I2C_DATA)?, I2C_DATA_FIELD) as u8;
            }
        }
        Ok(())
    }
    /// `acquire_i2c_hw_engine` + `dce_i2c_submit_command_hw`: every message
    /// in one command, MOT on all but the last.
    async fn i2c_messages(&mut self, line: u8, messages: &mut [Message<'_>]) -> Result<(), Error> {
        self.check(line)?;
        if messages.is_empty() || messages.iter().any(|m| m.data.len() > I2C_PAYLOAD_BYTES) {
            return Err(Error::Invalid);
        }
        if !self.i2c_available(line)? {
            return Err(Error::Engine);
        }
        let pads = self.open_pads(line, Mode::I2c).await?;
        let mut session = I2cSession {
            engine: self,
            line,
            pads: Some(pads),
        };
        let result = session.run(messages).await;
        let release = session.finish();
        result?;
        release
    }

    // ── HPD ────────────────────────────────────────────────────────────
    /// `dal_gpio_open(GPIO_MODE_INTERRUPT)` and `program_hpd_filter`. Linux
    /// leaves `DC_HPD_EN` to the VBIOS transmitter-init table this path does
    /// not run, so an HPD block the firmware left disabled is enabled here.
    /// Returns whether HPD had to be switched on here (its debounced sense
    /// then needs the connect filter's time before it can read connected).
    fn bind_hpd(&mut self, index: u8, signal: Signal) -> Result<bool, Error> {
        self.update(DC_GPIO_HPD_MASK, HPD_GPIO_MASK[usize::from(index)], 0)?;
        let control = Self::hpd(index, DC_HPD_CONTROL);
        let enabled = self.read(control)? & DC_HPD_EN == 0;
        if enabled {
            self.update(control, DC_HPD_EN, DC_HPD_EN)?;
        }
        let (connect_ms, disconnect_ms) = match signal {
            // linux: n/a (500/100 ms, literals in link_hpd.c:program_hpd_filter)
            Signal::Hdmi => (500, 100),
            // linux: n/a (80/0 ms, literals in link_hpd.c:program_hpd_filter)
            Signal::DisplayPort => (80, 0),
        };
        self.update(
            Self::hpd(index, DC_HPD_TOGGLE_FILT_CNTL),
            DC_HPD_CONNECT_INT_DELAY | DC_HPD_DISCONNECT_INT_DELAY,
            // linux: n/a (delay_on_connect / 10, literal in gpio/hw_hpd.c)
            put(0, DC_HPD_CONNECT_INT_DELAY, connect_ms / 10)
                // linux: n/a (delay_on_disconnect / 10, literal in gpio/hw_hpd.c)
                | put(0, DC_HPD_DISCONNECT_INT_DELAY, disconnect_ms / 10),
        )?;
        Ok(enabled)
    }
    fn hpd_sense(&mut self, index: u8) -> Result<bool, Error> {
        Ok(self.read(Self::hpd(index, DC_HPD_INT_STATUS))? & DC_HPD_SENSE_DELAYED != 0)
    }
    fn hpd_raw(&mut self, index: u8) -> Result<bool, Error> {
        Ok(self.read(Self::hpd(index, DC_HPD_INT_STATUS))? & DC_HPD_SENSE != 0)
    }
    /// `hpd0_ack`: acknowledge, then arm the opposite polarity.
    fn hpd_ack(&mut self, index: u8) -> Result<bool, Error> {
        let connected = self.hpd_sense(index)?;
        let control = Self::hpd(index, DC_HPD_INT_CONTROL);
        self.update(control, DC_HPD_INT_ACK, DC_HPD_INT_ACK)?;
        self.update(
            control,
            DC_HPD_INT_POLARITY,
            if connected { 0 } else { DC_HPD_INT_POLARITY },
        )?;
        Ok(connected)
    }
    /// The generic `dal_irq_service_ack` for the HPDn_RX source.
    fn hpd_rx_ack(&mut self, index: u8) -> Result<(), Error> {
        self.update(
            Self::hpd(index, DC_HPD_INT_CONTROL),
            DC_HPD_RX_INT_ACK,
            DC_HPD_RX_INT_ACK,
        )?;
        Ok(())
    }
    /// `dal_irq_service_set_generic` for `DC_HPD_RX_INT_EN`.
    fn hpd_rx_interrupt(&mut self, index: u8, enable: bool) -> Result<(), Error> {
        self.update(
            Self::hpd(index, DC_HPD_INT_CONTROL),
            DC_HPD_RX_INT_EN,
            if enable { DC_HPD_RX_INT_EN } else { 0 },
        )?;
        Ok(())
    }
    /// `dal_irq_service_set_generic` for `DC_HPD_INT_EN`.
    fn hpd_interrupt(&mut self, index: u8, enable: bool) -> Result<(), Error> {
        self.update(
            Self::hpd(index, DC_HPD_INT_CONTROL),
            DC_HPD_INT_EN,
            if enable { DC_HPD_INT_EN } else { 0 },
        )?;
        Ok(())
    }
}

/// `i2caux_action_from_payload`.
fn action(i2c: bool, write: bool, mot: bool, status_update: bool) -> u8 {
    if !i2c {
        // linux-lit: 0x80=DP_AUX_NATIVE_WRITE << 4; 0x90=DP_AUX_NATIVE_READ << 4
        return if write { 0x80 } else { 0x90 };
    }
    let base = if status_update {
        0x20 // linux-lit: 0x20=DP_AUX_I2C_WRITE_STATUS_UPDATE << 4
    } else if write {
        0x00 // linux-lit: 0x00=DP_AUX_I2C_WRITE << 4
    } else {
        0x10 // linux-lit: 0x10=DP_AUX_I2C_READ << 4
    };
    base | if mot { 0x40 } else { 0 } // linux-lit: 0x40=DP_AUX_I2C_MOT << 4
}

/// A raw AUX transaction holding the engine. Dropping it — including when the
/// enclosing future is cancelled — performs Linux's release synchronously.
struct AuxSession<'a, I: Io> {
    engine: &'a mut Engine<I>,
    line: u8,
    pads: Option<Pads>,
}
impl<I: Io> AuxSession<'_, I> {
    async fn run(
        &mut self,
        action: u8,
        address: u32,
        data: &mut [u8],
        write: bool,
    ) -> Result<Outcome, Error> {
        self.engine
            .submit_aux(self.line, action, address, data, write)
            .await?;
        let outcome = self.engine.aux_status(self.line).await?;
        let Outcome::Success { bytes, .. } = outcome else {
            return Ok(outcome);
        };
        let reply = if write {
            self.engine.aux_reply(self.line, &mut [])?
        } else {
            self.engine.aux_reply(self.line, data)?
        };
        Ok(match reply {
            Some(reply) => Outcome::Success { reply, bytes },
            None => Outcome::HpdDisconnected,
        })
    }
    fn finish(mut self) -> Result<(), Error> {
        match self.pads.take() {
            Some(pads) => self.engine.release_aux(self.line, pads),
            None => Ok(()),
        }
    }
}
impl<I: Io> Drop for AuxSession<'_, I> {
    fn drop(&mut self) {
        if let Some(pads) = self.pads.take() {
            let _ = self.engine.release_aux(self.line, pads);
        }
    }
}

/// A hardware I2C command holding the engine, with the same drop release.
struct I2cSession<'a, I: Io> {
    engine: &'a mut Engine<I>,
    line: u8,
    pads: Option<Pads>,
}
impl<I: Io> I2cSession<'_, I> {
    async fn run(&mut self, messages: &mut [Message<'_>]) -> Result<(), Error> {
        self.engine.transactions = 0;
        self.engine.used_bytes = 0;
        if !self.engine.i2c_setup_engine(self.line)? {
            return Err(Error::Engine);
        }
        self.engine.i2c_set_speed(self.line, I2C_SPEED_KHZ)?;
        let count = messages.len();
        for (index, message) in messages.iter_mut().enumerate() {
            self.engine
                .i2c_payload(self.line, message, index + 1 < count)
                .await?;
        }
        Ok(())
    }
    fn release(&mut self) -> Result<(), Error> {
        let Some(pads) = self.pads.take() else {
            return Ok(());
        };
        self.engine.transactions = 0;
        self.engine.used_bytes = 0;
        let released = self.engine.i2c_release_engine(self.line);
        // Linux skips dal_ddc_close when setup fails; closing is always safe.
        let closed = self.engine.close_pads(self.line, pads);
        released.and(closed)
    }
    fn finish(mut self) -> Result<(), Error> {
        self.release()
    }
}
impl<I: Io> Drop for I2cSession<'_, I> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// One AUX request as `aux_payload` describes it: native DPCD or I2C-over-AUX.
#[derive(Debug)]
pub struct AuxRequest<'a> {
    pub i2c: bool,
    pub write: bool,
    pub mot: bool,
    pub address: u32,
    pub data: &'a mut [u8],
}

/// The DCN3.0 DDC owner: all six AUX engines and pads, the shared hardware
/// I2C engine and all six HPD blocks.
#[derive(Debug)]
pub struct Ddc(Engine<Mmio>);
impl Ddc {
    /// # Safety
    /// Caller exclusively owns every DDC/AUX/HPD block and pad of this GPU's
    /// DCN for the object's lifetime (no DMUB AUX client, no other driver),
    /// holds matching PCI authority, and the register mapping is permanent.
    /// `crystal_khz` is the VBIOS crystal (`amdgpu_dcn_inventory::dchub_refclk_khz`).
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        crystal_khz: u32,
    ) -> Result<Self, Error> {
        if Profile::resolve(gpu).map_err(|_| Error::Unsupported)? != Profile::Navi22 {
            return Err(Error::Unsupported);
        }
        let base = Profile::Navi22
            .bank(gpu, 2, LAST_REG) // linux-lit: 2=mmDC_I2C_CONTROL_BASE_IDX
            .map_err(|_| Error::Unsupported)?;
        let base1 = Profile::Navi22
            // linux-lit: 1=mmMICROSECOND_TIME_BASE_DIV_BASE_IDX
            .bank(gpu, 1, MICROSECOND_TIME_BASE_DIV as u32)
            .map_err(|_| Error::Unsupported)?;
        let mut engine = Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
            },
            authority,
            base / 4,
            base1 / 4,
        );
        engine.crystal_khz = crystal_khz;
        Ok(Self(engine))
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Program a connector's AUX engine (DCN3.0 link-encoder init) and, when it
    /// has one, its HPD block and filter. `hpd` is the zero-based HPD block.
    pub fn bind(&mut self, line: u8, hpd: Option<u8>, signal: Signal) -> Result<(), Error> {
        bind(&mut self.0, line, hpd, signal).map(|_| ())
    }
    pub(crate) fn into_engine(self) -> Engine<Mmio> {
        self.0
    }
    /// Debounced sense (`DC_HPD_SENSE_DELAYED`), what `dcn10_get_hpd_state`
    /// reads for a pin opened in interrupt mode.
    pub fn hpd(&mut self, index: u8) -> Result<bool, Error> {
        hpd(&mut self.0, index)
    }
    /// The raw, undebounced pin.
    pub fn hpd_raw(&mut self, index: u8) -> Result<bool, Error> {
        self.0.check(index)?;
        self.0.hpd_raw(index)
    }
    /// Acknowledge an HPD interrupt and re-arm for the opposite edge; returns
    /// the debounced state the acknowledgement observed.
    pub fn hpd_ack(&mut self, index: u8) -> Result<bool, Error> {
        hpd_ack(&mut self.0, index)
    }
    pub fn hpd_rx_ack(&mut self, index: u8) -> Result<(), Error> {
        self.0.check(index)?;
        self.0.hpd_rx_ack(index)
    }
    pub fn hpd_interrupt(&mut self, index: u8, enable: bool) -> Result<(), Error> {
        self.0.check(index)?;
        self.0.hpd_interrupt(index, enable)
    }
    /// One AUX request with Linux's DEFER/NACK/timeout policy.
    pub async fn aux(&mut self, line: u8, request: &mut AuxRequest<'_>) -> Result<usize, Error> {
        self.0.transfer(line, request).await
    }
    pub async fn dpcd_read(
        &mut self,
        line: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        dpcd(&mut self.0, line, address, data, false).await
    }
    pub async fn dpcd_write(&mut self, line: u8, address: u32, data: &[u8]) -> Result<(), Error> {
        let mut copy = [0; AUX_MAX_BYTES];
        let copy = copy.get_mut(..data.len()).ok_or(Error::Invalid)?;
        copy.copy_from_slice(data);
        dpcd(&mut self.0, line, address, copy, true).await
    }
    /// `link_query_ddc_data`: the messages as one I2C transaction on `mode`.
    pub async fn i2c(
        &mut self,
        line: u8,
        mode: Mode,
        messages: &mut [Message<'_>],
    ) -> Result<(), Error> {
        i2c(&mut self.0, line, mode, messages).await
    }
}

/// Program a connector's AUX engine (DCN3.0 link-encoder init) and, when it
/// has one, its HPD block and filter. `hpd` is the zero-based HPD block.
pub(crate) fn bind<I: Io>(
    engine: &mut Engine<I>,
    line: u8,
    hpd: Option<u8>,
    signal: Signal,
) -> Result<bool, Error> {
    engine.check(line)?;
    if hpd.is_some_and(|h| h >= LINES) {
        return Err(Error::Invalid);
    }
    // HPD_SOURCEID_UNKNOWN would leave AUX_HPD_SEL pointing at another pin.
    if let Some(index) = hpd {
        engine.bind_aux(line, index)?;
        return engine.bind_hpd(index, signal);
    } else if signal == Signal::DisplayPort {
        return Err(Error::Unsupported);
    }
    Ok(false)
}
pub(crate) fn hpd<I: Io>(engine: &mut Engine<I>, index: u8) -> Result<bool, Error> {
    engine.check(index)?;
    engine.hpd_sense(index)
}
pub(crate) fn hpd_ack<I: Io>(engine: &mut Engine<I>, index: u8) -> Result<bool, Error> {
    engine.check(index)?;
    engine.hpd_ack(index)
}
pub(crate) fn hpd_rx_ack<I: Io>(engine: &mut Engine<I>, index: u8) -> Result<(), Error> {
    engine.check(index)?;
    engine.hpd_rx_ack(index)
}
/// `dal_irq_service_set(source, enable)`: the source's ack (`hpd0_ack`, with
/// its polarity re-arm, for HPD; the generic ack for HPD_RX), then its enable.
pub(crate) fn hpd_irq_set<I: Io>(
    engine: &mut Engine<I>,
    index: u8,
    rx: bool,
    enable: bool,
) -> Result<(), Error> {
    engine.check(index)?;
    if rx {
        engine.hpd_rx_ack(index)?;
        engine.hpd_rx_interrupt(index, enable)
    } else {
        engine.hpd_ack(index)?;
        engine.hpd_interrupt(index, enable)
    }
}
/// `try_to_configure_aux_timeout` on a bound line: the LTTPR or default
/// AUX reply timeout, in microseconds.
pub(crate) fn aux_timeout<I: Io>(engine: &mut Engine<I>, line: u8, us: u32) -> Result<(), Error> {
    engine.check(line)?;
    engine.configure_timeout(line, us)
}
pub(crate) async fn dpcd<I: Io>(
    engine: &mut Engine<I>,
    line: u8,
    address: u32,
    data: &mut [u8],
    write: bool,
) -> Result<(), Error> {
    if data.is_empty() || data.len() > AUX_MAX_BYTES {
        return Err(Error::Invalid);
    }
    let length = data.len();
    let mut request = AuxRequest {
        i2c: false,
        write,
        mot: false,
        address,
        data,
    };
    let bytes = engine.transfer(line, &mut request).await?;
    if !write && bytes != length {
        return Err(Error::ShortReply);
    }
    Ok(())
}
pub(crate) async fn i2c<I: Io>(
    engine: &mut Engine<I>,
    line: u8,
    mode: Mode,
    messages: &mut [Message<'_>],
) -> Result<(), Error> {
    engine.check(line)?;
    match mode {
        Mode::Aux => engine.aux_messages(line, messages).await,
        Mode::I2c => engine.i2c_messages(line, messages).await,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_ddc_tests.rs"]
pub(crate) mod tests;
