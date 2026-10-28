//! Qualcomm SoC platform layer.
//!
//! The pieces a Qualcomm SoC peripheral driver needs before its own
//! register map is reachable, each a clean module with a narrow trait
//! seam so it can be exercised against RAM/MMIO fixtures:
//!
//! | module      | Linux counterpart                                   |
//! |-------------|-----------------------------------------------------|
//! | [`io`]      | `readl`/`writel`, `readl_poll_timeout` (sleeping)    |
//! | [`dt`]      | `platform_device` + `of_*` resource lookup           |
//! | [`scm`]     | `drivers/firmware/qcom/qcom_scm{,-smc}.c` (PAS)      |
//! | [`mdt`]     | `drivers/soc/qcom/mdt_loader.c`                      |
//! | [`hwlock`]  | `drivers/hwspinlock/qcom_hwspinlock.c` (TCSR mutex)  |
//! | [`smem`]    | `drivers/soc/qcom/smem.c`                            |
//! | [`ipc`]     | `qcom-apcs-ipc-mailbox.c`, `qcom-ipcc.c` (send side) |
//! | [`smp2p`]   | `drivers/soc/qcom/smp2p.c`                           |
//! | [`glink`]   | `drivers/rpmsg/qcom_glink_{native,smem}.c`           |
//! | [`gcc`]     | `drivers/clk/qcom/{reset.c,clk-branch.c,gcc-ipq*.c}` |
//! | [`q6v5`]    | `drivers/remoteproc/qcom_q6v5.c`                     |
//! | [`wcss`]    | `drivers/remoteproc/qcom_q6v5_wcss.c` (IPQ8074 ops)  |
//! | [`pas`]     | `drivers/remoteproc/qcom_q6v5_pas.c` (WPSS)          |
//! | [`rproc`]   | `remoteproc_core.c` boot/shutdown contract           |
//!
//! Nothing here has run on Qualcomm silicon; QEMU emulates no IPQ/SC7280
//! part. Every sequence is checked against recording fakes derived from
//! the Linux sources (`specification/spec.md` §2, §7).
//!
//! Waits never spin on a register: [`io::poll_reg`] sleeps through
//! [`io::Delay`] between reads (the real [`io::NarfDelay`] is
//! `narf_time::SleepUntil`, so the executor runs other tasks).

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod dt;
pub mod gcc;
pub mod glink;
pub mod hwlock;
pub mod io;
pub mod ipc;
pub mod mdt;
pub mod pas;
pub mod platform;
pub mod q6v5;
pub mod rproc;
pub mod scm;
pub mod smem;
pub mod smp2p;
pub mod wcss;

#[cfg(any(test, feature = "kernel-test"))]
pub mod fixtures;
#[cfg(any(test, feature = "kernel-test"))]
mod glink_tests;
#[cfg(any(test, feature = "kernel-test"))]
mod tests;
