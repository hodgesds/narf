# drivers/soc/qcom — research reading list

Primary sources. Linux files are cited at tag v6.12 (fetched from
`github.com/torvalds/linux`); each module's doc comment names the
function it mirrors.

| Source | Used for |
|---|---|
| Arm DEN0028E *SMC Calling Convention* v1.5 §2.5–2.6 | Function-id layout, register use; `arch/` `aarch64::smccc` |
| `drivers/firmware/qcom/qcom_scm.c`, `qcom_scm-smc.c`, `qcom_scm.h` | Convention probe, `QCOM_SCM_ARGS`, INTERRUPTED/EBUSY handling, error remap, PIL/PAS calls (`scm.rs`) |
| `drivers/soc/qcom/mdt_loader.c`, `include/linux/soc/qcom/mdt_loader.h` | Hash-segment metadata, split `.bNN` segments, relocation, PAS init (`mdt.rs`) |
| `drivers/soc/qcom/smem.c` | Header/TOC, `$TOC` ptable, `$PRT` partitions, cached/uncached private entries, `SIII` item count (`smem.rs`) |
| `drivers/hwspinlock/qcom_hwspinlock.c` | TCSR mutex stride 0x1000, owner id 1 (`hwlock.rs`) |
| `drivers/soc/qcom/smp2p.c` | Item layout, negotiation, inbound edge detection, SSR ack (`smp2p.rs`) |
| `drivers/mailbox/qcom-apcs-ipc-mailbox.c`, `qcom-ipcc.c` | IPC send registers (`ipc.rs`) |
| `drivers/clk/qcom/reset.c`, `clk-branch.c`, `gcc-ipq8074.c`, `gcc-ipq6018.c`, `gcc-ipq5018.c`; `include/dt-bindings/{clock,reset}/qcom,gcc-ipq*.h` | Reset map entries, branch enable/halt polling (`gcc.rs`) |
| `drivers/remoteproc/qcom_q6v5.c` | Ready/handover/fatal/wdog/stop-ack semantics (`q6v5.rs`) |
| `drivers/remoteproc/qcom_q6v5_wcss.c` | IPQ8074 WCSS start/reset/powerdown sequences (`wcss.rs`) |
| `drivers/remoteproc/qcom_q6v5_pas.c` | `adsp_start`/`adsp_stop`, `sc7280_wpss_resource` (`pas.rs`) |
| `arch/arm64/boot/dts/qcom/ipq6018.dtsi`, `ipq8074.dtsi`, `ipq5018.dtsi`, `sc7280.dtsi` | Node shapes for `platform.rs` and the test fixtures |
| `Documentation/devicetree/bindings/net/wireless/qcom,ath11k.yaml` | ath11k `wifi@` node, interrupt names |

Observations recorded while reading:

- Mainline `ipq8074.dtsi` has no `remoteproc`/`wifi` node and
  `gcc-ipq8074.c` has no `GCC_WCSSAON_RESET`; `ipq6018.dtsi` carries the
  only upstream WCSS node, with compatible `qcom,ipq6018-wcss-pil`, which
  v6.12's `qcom_q6v5_wcss.c` match table does not list. NARF binds it to
  the IPQ8074 data.
- Mainline IPQ WCSS loading is *not* PAS-authenticated
  (`qcom_mdt_load_no_init` + host reset). PAS applies to WPSS (WCN6750).
