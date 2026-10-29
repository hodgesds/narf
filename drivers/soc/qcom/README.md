# drivers/soc/qcom — Qualcomm SoC platform layer

`narf-drivers-qcom-soc` provides the Qualcomm SoC services that sit between
the devicetree and a Qualcomm on-chip peripheral driver: devicetree
platform-device resolution, Secure Channel Manager (SCM) calls into
TrustZone over the SMC calling convention, the MDT/MBN split-firmware
loader, SMEM, SMP2P, the TCSR hardware mutex, outgoing IPC kicks
(APCS/IPCC), the GCC reset and branch-clock bits the WiFi subsystem
needs, and two Hexagon remoteproc loaders: the host-reset Q6 WCSS
(IPQ8074/IPQ6018/IPQ5018) and the TrustZone-authenticated PAS loader
(SC7280 WPSS, which runs WCN6750 firmware). Its first consumer is ath11k
AHB (`drivers/wireless/src/ath11k/ahb.rs`).

Each module mirrors one Linux driver (`qcom_scm*.c`, `mdt_loader.c`,
`smem.c`, `smp2p.c`, `qcom_hwspinlock.c`, `reset.c`/`clk-branch.c`/
`gcc-ipq*.c`, `qcom_q6v5{,_wcss,_pas}.c`) behind a narrow trait seam
(`RegIo`, `Delay`, `SmcConduit`, `ResetLine`, `StopState`, `Kick`), so
every sequence is tested against RAM/MMIO fixtures in kernel-test
smokes. None of it has run on Qualcomm silicon.

Interface contract: [`specification/spec.md`](specification/spec.md).
Sources: [`research/README.md`](research/README.md).
