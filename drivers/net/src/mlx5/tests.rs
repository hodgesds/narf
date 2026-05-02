//! mlx5 driver smokes — co-located with the driver per project
//! convention. Wires into `narf-kernel-test` so the runner groups
//! results under `drivers/net/mlx5`.
//!
//! Stage 1 cover:
//! - PCI match table contains an entry for every documented
//!   ConnectX-4..6 device id.
//! - `decode_init_segment` round-trips a synthetic BE-encoded
//!   buffer.
//! - `is_initializing` reads bit 31 of the `0x0FFC` register.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    decode_init_segment, is_initializing,
    INIT_SEGMENT_LEN, MLX5_VENDOR,
    MLX5_DEV_CX4, MLX5_DEV_CX4_LX, MLX5_DEV_CX4_LX_VF,
    MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX,
};

// Helper: build a 4 KiB init-segment buffer with chosen field
// values, BE-encoded as the PRM specifies.
fn synth_segment(
    fw_major: u16, fw_minor: u16, fw_sub: u16,
    cmd_iface: u16,
    cmdq_high: u32, cmdq_low_sz: u32,
    cmd_dbell: u32,
    initializing: bool,
) -> [u8; INIT_SEGMENT_LEN] {
    let mut raw = [0u8; INIT_SEGMENT_LEN];
    raw[0x00..0x02].copy_from_slice(&fw_major.to_be_bytes());
    raw[0x02..0x04].copy_from_slice(&fw_minor.to_be_bytes());
    raw[0x04..0x06].copy_from_slice(&fw_sub.to_be_bytes());
    raw[0x06..0x08].copy_from_slice(&cmd_iface.to_be_bytes());
    raw[0x10..0x14].copy_from_slice(&cmdq_high.to_be_bytes());
    raw[0x14..0x18].copy_from_slice(&cmdq_low_sz.to_be_bytes());
    raw[0x18..0x1C].copy_from_slice(&cmd_dbell.to_be_bytes());
    let init = if initializing { 1u32 << 31 } else { 0 };
    raw[0x0FFC..0x1000].copy_from_slice(&init.to_be_bytes());
    raw
}

// ── PCI match table ────────────────────────────────────────────────

fn smoke_mlx5_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [
        MLX5_DEV_CX4, MLX5_DEV_CX4_LX, MLX5_DEV_CX4_LX_VF,
        MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX,
    ];
    for did in want {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: MLX5_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("mlx5 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_pci_match_table);

// ── Init-segment decoder ───────────────────────────────────────────

fn smoke_mlx5_init_segment_round_trip() -> TestResult {
    // Plausible ConnectX-5 fw_rev: 16.27.4000, cmd-iface rev 5,
    // cmdq at phys 0x0000_0001_8000_0000, log_size 6 (=> 64
    // outstanding cmds). cmdq_low_sz packs (low 28 bits of addr) | sz.
    let cmdq_addr_high = 0x0000_0001u32;
    let cmdq_low_sz    = 0x8000_0006u32; // low addr bits .. | sz=6
    let raw = synth_segment(
        16, 27, 4000,
        5,
        cmdq_addr_high, cmdq_low_sz,
        0xDEAD_BEEF,
        /* initializing */ false,
    );
    let seg = decode_init_segment(&raw);
    if seg.fw_rev_major != 16
       || seg.fw_rev_minor != 27
       || seg.fw_rev_subminor != 4000 {
        return TestResult::Fail("fw_rev decode wrong");
    }
    if seg.cmd_interface_rev != 5 {
        return TestResult::Fail("cmd_interface_rev decode wrong");
    }
    if seg.cmdq_log_size != 6 {
        return TestResult::Fail("cmdq_log_size decode wrong");
    }
    let want_addr =
        ((cmdq_addr_high as u64) << 32) | (cmdq_low_sz as u64 & !0xFu64);
    if seg.cmdq_addr != want_addr {
        return TestResult::Fail("cmdq_addr assembly wrong");
    }
    if seg.cmd_dbell_vector != 0xDEAD_BEEF {
        return TestResult::Fail("cmd_dbell_vector decode wrong");
    }
    if seg.initializing {
        return TestResult::Fail("synthesised !initializing decoded as initializing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_init_segment_round_trip);

// ── initializing-bit reader ────────────────────────────────────────

fn smoke_mlx5_is_initializing_bit() -> TestResult {
    let init_yes = synth_segment(1, 0, 0, 0, 0, 0, 0, true);
    if !is_initializing(&init_yes) {
        return TestResult::Fail("initializing=true buffer read as cleared");
    }
    let init_no = synth_segment(1, 0, 0, 0, 0, 0, 0, false);
    if is_initializing(&init_no) {
        return TestResult::Fail("initializing=false buffer read as set");
    }
    // Verify we're checking the documented bit (31), not bit 0 by
    // mistake: a buffer with bit 0 set MUST not register as
    // initializing.
    let mut bit0 = synth_segment(1, 0, 0, 0, 0, 0, 0, false);
    let v = 0x0000_0001u32;
    bit0[0x0FFC..0x1000].copy_from_slice(&v.to_be_bytes());
    if is_initializing(&bit0) {
        return TestResult::Fail("bit-0 spuriously read as initializing — wrong bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_is_initializing_bit);
