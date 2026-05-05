# NARF — Current Status

Snapshot of what's implemented vs. what `STAGE1.md` / `ROADMAP.md` still
asks for. Updated when observable kernel behaviour changes.

## Stage progression

| stage | theme                                     | status |
|-------|-------------------------------------------|--------|
| 1. Skeleton      | Bootloader + async executor + console | **closed** — all 6 exit-gate items met |
| 2. Barrier       | PKS/MTE domain switching + UIPI        | **closed** — both arches boot; higher-half, MTE, GICv3 all landed |
| 3. Flow          | Narf-Ring + capabilities + first VirtIO | **composition complete; enforcement deferred to Stage 4** — caps/epoch, ipc SPSC, drivers framework, io DMA, rcu, tracing, abi, virtio-mmio skeleton all landed; `smoke_exit_gate_*` pass both arches, proving DmaBuffer → Narf-Ring → cap-gated consumer composes end-to-end. Real PKS/MTE enforcement on buffer pages, real virtio device I/O, real IOMMU, real user-mode consumer: Stage 4 items. |
| 4. Compatibility | relibc integration; run standard Rust bins | **structural surfaces landed; exit-gate blocked on host toolchain work** — see §"Stage 4 structural landing" below |

## Working today (both arches on QEMU)

- `cargo xtask run --arch=x86_64` boots, runs the full async demo,
  delivers hardware LAPIC-timer IRQs, exits cleanly.
- `cargo xtask run --arch=aarch64` boots, runs the full async demo
  using CNTPCT_EL0 as the clock, exits via ARM semihosting.
- `cargo xtask test --arch=x86_64` passes **650/0/29** (pass / fail / skip).
- `cargo xtask test --arch=aarch64` passes **354/0/11** (pass / fail / skip).
  Skips are x86_64-specific PCIe surfaces or live-device tests that
  skip cleanly when QEMU doesn't expose the device.
- In-tree PCIe drivers running against real QEMU-emulated devices.
  Every live virtio-PCI driver enables MSI-X on its primary
  completion queue via the shared `pci::enable_msix_queue` helper;
  consumers wait via `narf_interrupts::wait_for_irq(vector).await`.
  The polled-completion fallback stays in place so sync callers and
  IRQ-less environments keep working.

| driver           | scope                                            |
|------------------|--------------------------------------------------|
| NVMe             | Admin queue + IDENTIFY CTRL + IDENTIFY NS + I/O queue + Read/Write + MSI-X-driven completions. |
| virtio-blk-pci   | Polled + IRQ-driven Read/Write. MSI-X (q0). |
| virtio-net-pci   | RX + TX virtqueues; polled `tx`/`rx` + async `rx_irq_async` on receiveq MSI-X. |
| virtio-rng-pci   | Live requestq + polled `read_bytes(out)` entropy fetch. |
| virtio-balloon-pci | Live inflate + deflate queues + `inflate(pfns)` / `deflate(pfns)` polled, ≤1024 PFNs / call. |
| virtio-snd-pci   | Live controlq + tx + rx + eventq; `set_params` / `prepare` / `start` + `play_buffer` / `play_buffer_phys` PCM submit. |
| virtio-9p-pci    | Live requestq + 9P2000.L `tversion` / `tattach` / `twalk` / `tlopen` / `tread` / `tclunk` live ops + R-side decoders + MSI-X (requestq). |
| virtio-fs-pci    | Live hiprio + request[0] queues; FUSE submit + `fuse_init` / `fuse_lookup` / `fuse_read` helpers + MSI-X (request[0]). |
| virtio-console-pci | Modern + legacy match (1AF4:1043 / 1003). receiveq + transmitq + `ConsoleConfig` (cols/rows/emerg_wr) + `ControlEvent` decode. `write_bytes` / `read_bytes`. MSI-X (receiveq). |
| virtio-iommu-pci | PCI match (1AF4:1057). Live requestq + eventq, attach/detach/map/unmap with §5.16.6 tail-status. MSI-X (requestq). |
| virtio-scsi-pci  | PCI match (1AF4:1048). Live controlq + eventq + cmdq[0]; `submit_cmd` + `submit_tmf` + REPORT LUNS helper. MSI-X (cmdq[0]). |
| virtio-vsock-pci | PCI match (1AF4:1053). Live rx + tx + event queues; `VsockHdr` builders, `send` / `recv` / `drain_events`. MSI-X (rx). |
| virtio-gpu-pci   | Modern + legacy match (1AF4:1050 / 1010). controlq + cursorq, 2D pipeline (`init_scanout` / `paint_solid` / `paint_test_pattern` / `flush`). MSI-X (controlQ). |
| virtio-input-pci | PCI match (1AF4:1052). eventQ drain → `narf_input` (KEY + REL events). MSI-X (eventQ). |
| e1000 / e1000e   | Real Intel NIC (8254x + 8257x family). TX + RX.   |
| ixgbe            | Intel 82599 / X540 / X550 10 GbE. PCI match + reset + EEPROM MAC + advanced TX ring + RX ring + MSI-X + `HwNic`. Live bring-up smoke skips on QEMU (no emulated 82599). |
| igc              | Intel I225 / I226 family 2.5 GbE. Clean-room from public Intel datasheets — CTRL.RST + RAL/RAH MAC read + legacy TX/RX descriptor rings + tx/rx. MSI-X + advanced descriptors are follow-ups. |
| rtl8139          | Realtek RTL8139 10/100 Mbps. Clean-room from public Realtek programming guide — CONFIG1 unlock + CR.RST + IDR0..5 MAC + 64 KiB cyclic RX ring + 4 × 2 KiB TX buffers + tx/rx + link-status. |
| HPET             | Intel HPET 1.0a — caps decode at 0xFED00000, counter read + enable/disable + ticks-to-nanos conversion. Used as TSC-validation cross-check + fallback clocksource. |
| SMBus (ICH)      | Intel ICH SMBus controller, PCI class 0x0C/subclass 0x05 (any vendor) — IO BAR4 + byte-data + word-data read/write transactions. |
| TPM 2.0          | TCG PC Client PTP (CRB) + TIS v1.21 (legacy) auto-detect at 0xFED40000 — `submit(cmd)` + `tpm2_get_random` helpers. |
| USB Hub class    | USB 2.0 Chapter 11 — GET_DESCRIPTOR(Hub) + SET_FEATURE(PORT_POWER) + GET_STATUS + per-port reset for downstream device enumeration. |
| ACPI parser (x86_64) | RSDP discovery (EBDA + BIOS area + Limine override) → XSDT walk → MADT / HPET / MCFG / FADT decode. |
| TSC calibration  | CPUID 15h (TSC/crystal ratio) + CPUID 16h (base frequency) + HPET cross-check hook. Replaces 1 GHz fallback. |
| Microcode (Intel + AMD) | Vendor detection + revision read (MSR 0x8B with CPUID handshake) + Intel WRMSR 0x79 / AMD WRMSR 0xC0010020 update path. |
| PSCI + SMCCC (aarch64) | SMC + HVC conduit wrappers + PSCI_VERSION / SYSTEM_OFF / SYSTEM_RESET / CPU_OFF per Arm DEN0022D. HVC default (QEMU virt + KVM); SMC selectable for bare-metal. |
| MCA / MCE (x86_64) | Per SDM Vol 3 Ch 16 — `MCG_CAP` / `MCG_STATUS` decode, per-bank `MCi_STATUS`/`ADDR`/`MISC` snapshot + W1C clear, init-time enable for every architectural bank. |
| MTRR (x86_64)    | Variable + fixed range MTRRs per SDM §12.11 — capabilities decode, `set_variable_range`, `set_write_combining(phys, size)` for framebuffer / GPU BAR claims. |
| Spectre mitigations | IA32_SPEC_CTRL (IBRS / STIBP / SSBD) + IA32_PRED_CMD (IBPB) + IA32_FLUSH_CMD (L1D_FLUSH) per SDM Vol 4 §2.16 — feature probe, default-enable, IBPB barrier, L1D flush. |
| CMOS RTC (MC146818) | IO ports 0x70/0x71 wall-clock read with UIP-poll, BCD/binary + 12/24 h decode, century byte, Unix epoch conversion. |
| i8254 PIT        | Mode 0 (one-shot) + Mode 2 (rate generator) + Mode 3 (square wave) at IO 0x40-0x43 with 1.193182 MHz input clock. Channel 2 latch + PPI gate for free-running boot timer. |
| Generic Timer (aarch64) | `CNTFRQ_EL0` calibration + `CNTPCT_EL0` read with `isb` ordering. Replaces 1 GHz fallback in `narf-time`. |
| P-states (x86_64) | Intel HWP (MSRs 0x770-0x777) primary + SpeedStep (0x198/0x199) fallback + AMD legacy (MSR_PSTATE_* 0xC0010061-0xC0010064). Capabilities decode + `hwp_set(min,max,desired,EPP)` + `legacy_set(id)`. Spec: `power/specification/cpu-power.md` §1. |
| MWAIT idle (x86_64) | CPUID(5) caps decode + `MWAIT EAX = encode_cstate(d)` for C1..C7 entry, falls back to STI;HLT. Spec: `power/specification/cpu-power.md` §2. |
| RAPL (x86_64)    | MSR_RAPL_POWER_UNIT decode → µJ-per-unit, `read_pkg_uj` / `read_pp0_uj` / `read_pp1_uj` / `read_dram_uj` + `read_temp_c` / `read_pkg_temp_c` thermal. Spec: `power/specification/cpu-power.md` §3. |
| Topology (x86_64) | CPUID 0x1F (V2 ext) / 0xB (ext) / 0x04 (cache) / 0x1A (hybrid). Returns `Topology { levels, n_levels, package_count, core_count, thread_count, hybrid, core_type }` + per-level `CacheLevelInfo`. Spec: `arch/specification/smp-topology.md` §1. |
| SMP bring-up (x86_64) | LAPIC ICR INIT/SIPI/SIPI sequence (xAPIC + x2APIC). `aps_from_madt(&Tables, bsp)` extracts AP APIC ids; `start_ap_xapic(...)` blocks until the AP marks itself alive. Spec: `arch/specification/smp-topology.md` §2. |
| HFI / Thread Director | `IA32_HW_FEEDBACK_PTR` / `CONFIG` / `THREAD_FEEDBACK_CHAR` MSRs + per-package feedback-page registration + timestamp polling. Spec: `arch/specification/smp-topology.md` §3. |
| PMU (architectural) | CPUID(0xA) caps + `IA32_PERFEVTSELi` / `IA32_PMCi` / fixed counters + `IA32_PERF_GLOBAL_CTRL` / `STATUS` / `OVF_CTRL`. Pre-baked architectural events (cycles / instr / LLC / branch). Spec: `observability/specification/perfmon.md` §1. |
| LBR              | Last Branch Records — model-classified ring depth (4/8/16/32), `MSR_LBR_SELECT` filter, Skylake+ MSR base (0x680/0x6C0) with legacy fallback (0x40/0x60), `enable` / `disable` / `read_pair(idx)` / `read_tos`. Spec: `observability/specification/perfmon.md` §2. |
| Intel PT         | Processor Trace — CPUID(0x14) caps decode, `topa_entry` builder + single-entry ToPA installation, `enable(os, usr)` with `IA32_RTIT_CTL` + branch filter, `output_offset` / `status` for diagnostics. Spec: `observability/specification/perfmon.md` §3. |
| CET (Control-flow Enforcement) | Shadow stack (`CPUID(7,0).ECX[7]`) + IBT (`CPUID(7,0).EDX[20]`) gate, `enable_supervisor` / `enable_user` MSR programming, `IA32_PL0_SSP` access, CR4.CET enable. Spec: `arch/specification/security-hardening.md` §1. |
| PEBS             | Precise Event-Based Sampling — DS save area install + per-counter PEBS enable + Skylake basic-record buffer builder. Spec: `arch/specification/security-hardening.md` §2. |
| Boot CPU validation | CPUID + CR4 + EFER probe surfaced as `CpuValidation { long_mode, rdtscp, invariant_tsc, nx, smep, smap, umip, wrgsbase, pcid, x2apic, xsave, ... }` + `baseline_ok` guard. Spec: `arch/specification/security-hardening.md` §3. |
| VMX caps (Intel) | `IA32_FEATURE_CONTROL` + `IA32_VMX_BASIC` + `IA32_VMX_PROCBASED_CTLS2` + `IA32_VMX_EPT_VPID_CAP` decode → `VmxCaps { supported, feature_locked, vmxon_outside_smx, basic, ept_supported, vpid_supported, unrestricted_guest, apicv, vmcs_shadowing }`. Spec: `arch/specification/virt-confidential.md` §1. |
| SVM caps (AMD)   | CPUID(0x80000001).ECX[2] gate + CPUID(0x8000000A) capability decode → `SvmCaps { supported, disabled, revision, n_asids, np, lbr_virt, svm_lock, nrip_save, ... }`. Spec: `arch/specification/virt-confidential.md` §2. |
| SGX caps (Intel) | CPUID(0x12, 0/1/N) → `SgxCaps { sgx1, sgx2, miscselect, max_size_64, max_size_32, epc_sections }`. Spec: `arch/specification/virt-confidential.md` §3. |
| Confidential guest | TDX (CPUID(0x21, 0) signature) + SEV / SEV-ES / SEV-SNP (`MSR_AMD64_SEV` 0xC0010131) detection → `ConfidentialEnvironment { Bare, TdxGuest, SevGuest, SevEsGuest, SevSnpGuest }`. Spec: `arch/specification/virt-confidential.md` §4. |
| ASID/PCID isolation | Per-domain page-table root (`memory::per_domain_root`) registers each domain's PML4 (mirrored to `pcid::set_domain_pml4`) at boot. Generation-tagged ASID/PCID allocator (`memory::asid_alloc`). Selective TLB invalidation (INVPCID 0/1/2/3 + `TLBI ASIDE1IS` / `VAE1IS`). Cross-CPU shootdown wired through `narf_interrupts::install_tlb_shootdown_bridge`: x86_64 fans out via existing `ipi::shoot_range` (vector 0xF0), aarch64 broadcasts SGI_TLB_SHOOTDOWN. Spec: `memory/specification/asid-pcid-isolation.md`. |
| Hypervisor detection | CPUID(1).ECX[31] gate + CPUID(0x40000000) signature decode → `Hypervisor { None, Kvm, HyperV, Xen, VMware, QemuTcg, Bhyve, Parallels, Other }` + KVM feature bitmap + Hyper-V version/recommendations. Spec: `arch/specification/modern-cpu.md` §1. |
| XSAVE state      | CPUID(0x0D, 0/1/N) decode → `XsaveCaps { xcr0_supported, xss_supported, area_size, avx, avx512, amx, pkru, ... }`, XCR0 / IA32_XSS read+write, `enable_default()` boot policy, `xsave` / `xrstor` instruction wrappers. Spec: `arch/specification/modern-cpu.md` §2. |
| WAITPKG          | CPUID(7,0).ECX[5] gate, `IA32_UMWAIT_CONTROL` (0xE1) configuration, `umonitor` / `umwait` / `tpause` instruction wrappers with monitor-fired vs timeout return. Spec: `arch/specification/modern-cpu.md` §3. |
| AMD SMCA         | CPUID(0x80000007).EBX[3] gate + per-bank extended MSRs at `0xC0002000+` (CONFIG / IPID / SYND / DESTAT / MISC0) + `SmcaBankInfo` decoder + `BankType` enum (LS / IF / L2 / DE / EX / FP / L3 / MP5 / SMU / PB / UMC / PCIe). Spec: `arch/specification/modern-cpu.md` §4. |
| aarch64 PAC      | `ID_AA64ISAR1` / `ID_AA64ISAR2` decode → `PacCaps { address_auth, generic_auth, enhanced }`. Per-key writers (APIA/APIB/APDA/APDB/APGA) using raw `S3_0_C2_*` MSR encoding. `enable_keys(ia, ib, da, db)` flips SCTLR_EL1 enable bits. Spec: `arch/specification/cpu-security.md` §1. |
| aarch64 BTI      | `ID_AA64PFR1_EL1.BT` detection. Page-flag plumbing for the GP bit lives in `memory/`. Spec: `arch/specification/cpu-security.md` §2. |
| aarch64 SSBS     | `ID_AA64PFR1_EL1.SSBS` detection + `enable()` / `disable()` flipping PSTATE.SSBS via raw `.inst` encoding. Spec: `arch/specification/cpu-security.md` §3. |
| Intel LAM        | CPUID(7, 1).EAX[26] gate + CR3.LAM_U48 / LAM_U57 + CR4.LAM_SUP enable. Spec: `arch/specification/cpu-security.md` §4. |
| Intel UINTR      | CPUID(7, 0).EDX[5] gate + `IA32_UINTR_HANDLER` / `PD` / `STACKADJUST` / `MISC` / `RR` / `TT` MSR programming + `senduipi` / `clui` / `stui` / `testui` instruction wrappers. Spec: `arch/specification/cpu-security.md` §5. |
| Intel KeyLocker  | CPUID(7, 0).ECX[23] gate + CPUID(0x19, 0).EAX bitmap decode. Spec: `arch/specification/cpu-security.md` §6. |
| AMD INVLPGB      | CPUID(0x80000008).EBX[3] gate + `count_max` / `asid_max` decode + raw `INVLPGB` (`0F 01 FE`) / `TLBSYNC` (`0F 01 FF`) wrappers + `invalidate_all_global` / `invalidate_asid(asid)` helpers. Spec: `arch/specification/cpu-perf-niche.md` §1. |
| AMD RDPRU        | CPUID(0x80000008).EBX[4] gate + raw `RDPRU` (`0F 01 FD`) wrapper + `read_mperf` / `read_aperf` (RDPRU when supported, RDMSR fallback). Spec: `arch/specification/cpu-perf-niche.md` §2. |
| CLDEMOTE / MOVDIR | CPUID(7, 0).ECX[25/27/28] gates + `cldemote` / `movdiri32` / `movdiri64` / `movdir64b` instruction wrappers for cache-demote hints + write-combining direct stores. Spec: `arch/specification/cpu-perf-niche.md` §3. |
| WRMSRNS          | CPUID(7, 1).EAX[19] gate + raw `WRMSRNS` (`0F 01 C6`) wrapper + `write(msr, value)` convenience that picks WRMSRNS when available. Spec: `arch/specification/cpu-perf-niche.md` §4. |
| AVX10            | CPUID(7, 1).EDX[19] gate + CPUID(0x24, 0) decode → `Avx10Caps { supported, version, xmm, ymm, zmm, converged_with_avx512 }`. Spec: `arch/specification/cpu-perf-niche.md` §5. |
| aarch64 SVE / SVE2 | `ID_AA64PFR0_EL1.SVE` + `ID_AA64ZFR0_EL1.SVEver` decode → `SveCaps { sve, sve2, sve21 }` (CPACR-safe). `probe_max_vl_bits` / `set_vl_bits` / `read|write_zcr_el1` (require CPACR.ZEN open) using raw `S3_0_*` system-register encoding. Spec: `arch/specification/cpu-perf-niche.md` §6. |
| x86_64 CPU ident | CPUID(0) vendor → `Vendor { Intel, Amd, Hygon, Centaur, Via, Zhaoxin, Other }`, CPUID(1).EAX → family / model / stepping (with extended-family/extended-model fold), CPUID(0x80000002..4) brand-string read + leading-space-trim helper. Spec: `arch/specification/cpu-info-errata.md` §1. |
| x86_64 cache geom | `CacheCaps { clflush, clflushopt, clwb, wbnoinvd, line_bytes }` from CPUID(1).EBX[15:8] + (7,0).EBX[23/24] + (0x80000008).EBX[9]; instruction wrappers for CLFLUSH / CLFLUSHOPT / CLWB / WBNOINVD. Spec: `arch/specification/cpu-info-errata.md` §2. |
| x86_64 errata | `&'static [Errata]` table dispatched on `(vendor, family, model_lo..=hi, stepping_mask)`; `apply_for_current_cpu()` fans out matching workarounds. v0.1 entries: Intel SKL-X TSX-RTM disable + AMD Zen1 erratum 1474. Spec: `arch/specification/cpu-info-errata.md` §3. |
| x86_64 PMI binding | LVT-PC programming primitive at `LAPIC_BASE + 0x340` — `program_lvt_pc(vector, nmi, masked)` + `mask_lvt_pc` / `unmask_lvt_pc`. Wire-once API used by PMU / LBR / Intel-PT subsystems. Spec: `arch/specification/cpu-info-errata.md` §4. |
| aarch64 CPU ident | MIDR_EL1 decode → `AarchIdent { implementer, variant, part, revision, raw }` + REVIDR_EL1 + implementer-name table (Arm / Apple / Ampere / Qualcomm / NVIDIA / …). Spec: `arch/specification/cpu-info-errata.md` §5.1. |
| aarch64 cache geom | CTR_EL0 decode → `AarchCacheCaps { iline_bytes, dline_bytes, cwg_bytes }` (line-size-in-bytes = `4 << field`). Spec: `arch/specification/cpu-info-errata.md` §5.2. |
| Intel RDT        | CPUID(7, 0).EBX[12/15] gates + CPUID(0x0F)/0x10) sub-feature decode → `RdtCaps { monitoring, allocation, l3_monitoring, l3_cat, l2_cat, mba, max_rmid, max_closid }`. `assoc(rmid, closid)` via IA32_PQR_ASSOC, `read_event` via QM_EVTSEL/CTR, `write_l3_mask` / `write_l2_mask` / `write_mba_throttle`. Spec: `arch/specification/cpu-telemetry-qos.md` §1. |
| Intel FRED       | CPUID(7, 1).EAX[17] gate + IA32_FRED_RSP{0..3} / SSP{1..3} / STKLVLS / CONFIG MSR programming + CR4.FRED (bit 32) enable/disable + `write_handler_base(va)`. Spec: `arch/specification/cpu-telemetry-qos.md` §2. |
| aarch64 BRBE     | `ID_AA64DFR0_EL1.BRBE` (bits[55:52]) decode + `BRBCR_EL1` / `BRBFCR_EL1` read/write via raw `S2_1_C9_C0_0/1` encodings + `enable` (E0BRE+E1BRE) / `disable` / `freeze` (PAUSED). Spec: `arch/specification/cpu-telemetry-qos.md` §3. |
| aarch64 TRBE     | `ID_AA64DFR0_EL1.TraceBuffer` (bits[47:44]) gate + `TRBLIMITR_EL1` / `TRBPTR_EL1` / `TRBBASER_EL1` / `TRBIDR_EL1` access via raw `S3_0_C9_C11_*` + `write_base(base, limit)` + `enable`/`disable`. Spec: `arch/specification/cpu-telemetry-qos.md` §4. |
| aarch64 MPAM     | `ID_AA64PFR0_EL1.MPAM` + `ID_AA64PFR1_EL1.MPAM_frac` + `MPAMIDR_EL1` decode → `MpamCaps { supported, revision, frac, max_partid, max_pmg }` + `write_mpam0` / `write_mpam1` (PARTID_D / PARTID_I / PMG_D / PMG_I + MPAMEN). Spec: `arch/specification/cpu-telemetry-qos.md` §5. |
| aarch64 SPE      | `ID_AA64DFR0_EL1.PMSVer` (bits[35:32]) decode + PMSCR / PMSIRR / PMSIDR / PMBLIMITR / PMBPTR programming via raw `S3_0_C9_C9_*` + `S3_0_C9_C10_*` encodings + `program_buffer(base, limit)` + `enable` / `disable`. Spec: `arch/specification/cpu-arch-extensions.md` §1. |
| aarch64 ETE      | `ID_AA64DFR0_EL1.TraceVer` gate + `TRCPRGCTLR` (`S2_1_C0_C1_0`) + `TRCSTATR` (`S2_1_C0_C3_0`) read/write — `enable` (TRCPRGCTLR.EN) / `disable` / `read_status`. Spec: `arch/specification/cpu-arch-extensions.md` §2. |
| aarch64 GCS      | `ID_AA64PFR1_EL1.GCS` (bits[47:44]) decode + GCSCR_EL1 / GCSCRE0_EL1 / GCSPR_EL{0,1} access via raw `S3_0_C2_C5_*` + `S3_3_C2_C5_1` + `enable_el1(rvcheck, exception_push)` / `enable_el0(rvcheck)` / disablers. Spec: `arch/specification/cpu-arch-extensions.md` §3. |
| aarch64 RNDR     | `ID_AA64ISAR0_EL1.RNDR` (bits[63:60]) gate + `try_rndr()` / `try_rndrrs()` returning `Option<u64>` (NZCV.C → `cset` capture). Spec: `arch/specification/cpu-arch-extensions.md` §4. |
| Intel LASS       | CPUID(7, 1).EAX[6] gate + CR4.LASS (bit 27) enable / disable. Spec: `arch/specification/cpu-arch-extensions.md` §5. |
| aarch64 SME      | `ID_AA64PFR1_EL1.SME` (bits[27:24]) decode → `SmeCaps { sme, sme2 }` + SVCR (`S3_3_C4_C2_2`) + SMCR_EL1 (`S3_0_C1_C2_6`) read/write + `enter_streaming` / `leave_streaming` / `enable_za` / `disable_za`. Spec: `arch/specification/cpu-compute-confidential.md` §1. |
| aarch64 RME      | `ID_AA64PFR0_EL1.RME` (bits[55:52]) decode + `supported()` predicate (state-management lives at EL3). Spec: `arch/specification/cpu-compute-confidential.md` §2. |
| aarch64 SPECRES  | `ID_AA64ISAR1_EL1.SPECRES` (bits[43:40]) decode + `cfp_rctx(ctx)` raw `SYS #3, C7, C3, #4, Xt` wrapper. Spec: `arch/specification/cpu-compute-confidential.md` §3. |
| Intel BHI ctrl   | CPUID(7, 2).EDX[4] `BHI_NO` + IA32_SPEC_CTRL.BHI_DIS_S (bit 10) enable / disable. Spec: `arch/specification/cpu-compute-confidential.md` §4. |
| Intel PASID      | CPUID(7, 0).ECX[2] gate + IA32_PASID (`0xD93`) read/write/invalidate (20-bit PASID + VALID bit) for accelerator SVA. Spec: `arch/specification/cpu-compute-confidential.md` §5. |
| Intel VT-d       | DMA-Remap engine register layout (VER / CAP / ECAP / GCMD / GSTS / RTADDR / FSTS / PMEN) + `decode_caps(ver, cap, ecap)` → `VtdCaps { version, num_domains, sagaw, num_fault_regs, queued_invalidation, interrupt_remap }` + `read_caps` / `read_gsts` / `write_gcmd` / `write_rtaddr` MMIO helpers. Spec: `arch/specification/iommu-interconnect.md` §1. |
| AMD-Vi IOMMU     | MMIO register layout (DEV_TAB_BASE / CMD_BUF_BASE / EVT_LOG_BASE / IOMMU_CTRL / EXT_FEATURES / PPR_LOG_BASE) + `decode_caps(ctrl, efr)` → `AmdViCaps { iommu_enabled, event_log_enabled, command_buf_enabled, ppr/gt/xts supported }` + `read_caps` / `read_ctrl` / `write_ctrl` MMIO helpers. Spec: `arch/specification/iommu-interconnect.md` §2. |
| Intel RAR        | CPUID(7, 1).EAX[31] gate + IA32_RAR_INFO_BASE (`0x1024`) / IA32_RAR_CTRL (`0x1025`) read/write + `doorbell(mmio_base, action, target_lpid, payload)` for vector-less remote actions (TLB shootdown / RDPMC / INVD). Spec: `arch/specification/iommu-interconnect.md` §3. |
| ARM SMMUv3       | MMIO register layout (IDR0..5 / CR0..2 / GBPA / STRTAB_BASE) + `decode_caps(idr0, idr1, idr5)` → `SmmuCaps { s1p, s2p, ttf16, ttf64, oas, sid_width, queue_base_share }` + `read_caps` / `read_cr0` / `write_cr0` / `write_strtab_base` MMIO helpers. Spec: `arch/specification/iommu-interconnect.md` §4. |
| Intel IR         | IRTE encode/decode (present / fault-disable / dest-mode / vector / delivery-mode / destination) + `write_irtar(reg_base, table_pa, log2_size)` for IRTAR programming. Spec: `arch/specification/irq-cache-numa.md` §1. |
| AMD GA mode      | `ga_supported(efr)` / `ia_supported(efr)` predicates over the AMD-Vi `EXT_FEATURES` register. Spec: `arch/specification/irq-cache-numa.md` §2. |
| GICv3 ITS        | MMIO register layout (CTLR / IIDR / TYPER / CBASER / CWRITER / CREADR / BASER0) + `decode_caps(typer)` → `GitsCaps { id_bits, dev_bits, hcc, physical }` + `enable` / `disable` / `write_cbaser` MMIO helpers. Spec: `arch/specification/irq-cache-numa.md` §3. |
| x86 cache topo   | CPUID(4) / CPUID(0x8000_001D) per-level enumerator → `CacheLevel { level, kind, line_bytes, partitions, ways, sets, size_bytes, fully_assoc, apic_ids_sharing }` (Intel + AMD share decoded shape). Spec: `arch/specification/irq-cache-numa.md` §4. |
| aarch64 cache topo | CLIDR_EL1 + CSSELR_EL1 + CCSIDR_EL1 enumerator → `CacheLevel { level, kind, line_bytes, ways, sets, size_bytes }`. Spec: `arch/specification/irq-cache-numa.md` §5. |
| NUMA primitives  | x86: `set_apic_to_domain(cb)` hook + `domain_for_apic_id` lookup (SRAT-driven). aarch64: `cluster_id(mpidr)` + `domain_for_current_cpu()` Aff2-derived. Spec: `arch/specification/irq-cache-numa.md` §6. |
| Intel TME / MKTME | CPUID(7, 0).ECX[13] gate + IA32_TME_CAPABILITY (`0x981`) decode → `TmeCaps { aes_xts_128, aes_xts_128_integrity, aes_xts_256, max_keyid_bits, max_keys }` + IA32_TME_ACTIVATE (`0x982`) read/write + LOCK predicate. Spec: `arch/specification/cpu-mem-encrypt-virt.md` §1. |
| Intel RTM-abort  | CPUID(7, 0).EDX[11] gate + IA32_TSX_FORCE_ABORT (`0x10F`) read/write + `force_rtm_abort()` boot-baseline helper. Spec: `arch/specification/cpu-mem-encrypt-virt.md` §2. |
| aarch64 ECV      | `ID_AA64MMFR0_EL1.ECV` (bits[63:60]) decode + `supported()` + `cntpoff_supported()` predicates. Spec: `arch/specification/cpu-mem-encrypt-virt.md` §3. |
| aarch64 NV2      | `ID_AA64MMFR2_EL1.NV` (bits[27:24]) decode + `supported()` (FEAT_NV) / `nv2_supported()` (FEAT_NV2) predicates. Spec: `arch/specification/cpu-mem-encrypt-virt.md` §4. |
| aarch64 E0PD     | `ID_AA64MMFR2_EL1.E0PD` (bits[63:60]) decode + `enable_kernel_half()` / `disable_kernel_half()` flipping `TCR_EL1.E0PD1`. Spec: `arch/specification/cpu-mem-encrypt-virt.md` §5. |
| Intel SLD        | CPUID(7, 0).EDX[5] gate + `IA32_CORE_CAPABILITIES` (`0xCF`) bit 5 + `IA32_TEST_CTRL` (`0x33`) read/write + `enable_ac()` / `disable()` for split-lock-detect AC mode. Spec: `arch/specification/cpu-atomics-mitigations.md` §1. |
| Intel BUS_LOCK   | CPUID(7, 0).ECX[24] gate + IA32_DEBUGCTL (`0x1D9`) bit 2 enable / disable. Spec: `arch/specification/cpu-atomics-mitigations.md` §2. |
| aarch64 LSE / LSE128 | `ID_AA64ISAR0_EL1.Atomic` (bits[23:20]) decode + `lse_supported()` / `lse128_supported()` predicates. Spec: `arch/specification/cpu-atomics-mitigations.md` §3. |
| aarch64 RCPC*    | `ID_AA64ISAR1_EL1.LRCPC` (bits[23:20]) decode + `rcpc_supported()` / `rcpc2_supported()` / `rcpc3_supported()`. Spec: `arch/specification/cpu-atomics-mitigations.md` §4. |
| aarch64 PIE      | `ID_AA64MMFR3_EL1.S1PIE` + `S2PIE` decode → `PieCaps { s1pie, s2pie }` + PIR_EL1 (`S3_0_C10_C2_3`) / PIRE0_EL1 (`S3_0_C10_C2_2`) read+write helpers. Spec: `arch/specification/cpu-atomics-mitigations.md` §5. |
| aarch64 SCTLR2   | `ID_AA64MMFR3_EL1.SCTLRX` decode + SCTLR2_EL1 (`S3_0_C1_C0_3`) read+write helpers. Spec: `arch/specification/cpu-atomics-mitigations.md` §6. |
| ACPI PPTT        | Processor Properties Topology — Type 0 (Processor) → `PpttCpu { acpi_uid, package, thread, leaf }` + Type 1 (Cache) → `PpttCache { line_bytes, ways, sets, size_bytes, kind }`. `parse_pptt(rsdp)` + `copy_pptt_cpus` / `copy_pptt_caches`. Spec: `acpi/specification/tables-iommu-topology.md` §1. |
| ACPI IORT        | IO Remap Table — Type 0 (ITS group) → `IortIts { its_id }` + Type 4 (SMMUv3) → `IortSmmuv3 { base, flags }`. `parse_iort(rsdp)` + `copy_iort_smmuv3` / `copy_iort_its`. Spec: `acpi/specification/tables-iommu-topology.md` §2. |
| ACPI DMAR        | DMA Remap Reporting — DRHD enumeration → `DmarDrhd { register_base, segment, include_all_pci }` + `dmar_intr_remap_supported()`. Spec: `acpi/specification/tables-iommu-topology.md` §3. |
| ACPI IVRS        | I/O Virtualization Reporting (AMD) — IVHD entries (types 0x10/0x11/0x40) → `IvrsIommu { base, pci_segment, capability_off }`. Spec: `acpi/specification/tables-iommu-topology.md` §4. |
| ACPI SPCR        | Serial Port Console Redirection — interface type + GAS base + GSI + baud-code → `SpcrInfo`. Spec: `acpi/specification/tables-iommu-topology.md` §5. |
| ACPI HEST        | Hardware Error Source Table — Type 0 (Machine Check) + Type 9/10 (GHES/GHESv2) decode → `HestMceSource` / `HestGhesSource`. `parse_hest(rsdp)` + `copy_hest_mce` / `copy_hest_ghes`. Spec: `acpi/specification/tables-ras-cxl-locality.md` §1. |
| ACPI PCCT        | Platform Communication Channels — generic / HW-reduced / HW-reduced-v2 channels (types 0/1/2) → `PcctChannel { kind, shmem_base, shmem_length, doorbell_addr, doorbell_write, min_turnaround_us }`. Spec: `acpi/specification/tables-ras-cxl-locality.md` §2. |
| ACPI SLIT        | System Locality Information — N×N distance matrix lookup. `slit_distance(from, to)` + `slit_locality_count()`. Spec: `acpi/specification/tables-ras-cxl-locality.md` §3. |
| ACPI CEDT        | CXL Early Discovery — CHBS (CXL Host Bridge) + CFMWS (CXL Fixed Memory Window) → `CedtChbs` / `CedtCfmws`. Spec: `acpi/specification/tables-ras-cxl-locality.md` §4. |
| ACPI BERT        | Boot Error Record Table — `BertInfo { region_addr, region_length }`. Spec: `acpi/specification/tables-ras-cxl-locality.md` §5. |
| ACPI AEST        | Arm Error Source Table — per-node header walk + interface-block read → `AestNode { kind, iface, base }`. Spec: `acpi/specification/tables-arm-ras-power-pm.md` §1. |
| ACPI SDEI        | Software Delegated Exception Interface — sticky `is_sdei_known()` predicate after table validates. Spec: `acpi/specification/tables-arm-ras-power-pm.md` §2. |
| ACPI WDDT        | Watchdog Description Table — `WddtInfo { timer_max_count, timer_min_count, period_us, status, capability, base }`. Spec: `acpi/specification/tables-arm-ras-power-pm.md` §3. |
| ACPI LPIT        | Low Power Idle Table — Type 0 (Native C-State) → `LpitState { uid, trigger_addr, residency, latency, counter_addr, counter_freq }`. Spec: `acpi/specification/tables-arm-ras-power-pm.md` §4. |
| ACPI NFIT        | NVDIMM Firmware Interface Table — Type 0 (SPA Range) → `NfitSpaRange { range_index, proximity, base, length, mem_attr }`. Spec: `acpi/specification/tables-arm-ras-power-pm.md` §5. |
| ACPI ERST        | Error Record Serialization Table — 32-byte instruction-entry decode → `ErstInstruction { action, instruction, addr, value, mask }`. Spec: `acpi/specification/tables-ras-tpm-debug.md` §1. |
| ACPI EINJ        | Error Injection Table — same instruction-entry shape as ERST → `EinjInstruction`. Spec: `acpi/specification/tables-ras-tpm-debug.md` §2. |
| ACPI TPM2        | Trusted Platform Module 2.0 — `Tpm2Info { platform_class, control_area_addr, start_method }`. Spec: `acpi/specification/tables-ras-tpm-debug.md` §3. |
| ACPI BGRT        | Boot Graphics Resource Table — `BgrtInfo { status, image_address, offset_x, offset_y }`. Spec: `acpi/specification/tables-ras-tpm-debug.md` §4. |
| ACPI DBG2        | Debug Port Table 2 — DeviceInfo walk → `Dbg2Device { port_type, port_subtype, base_addr }`. Spec: `acpi/specification/tables-ras-tpm-debug.md` §5. |
| ACPI WSMT        | Windows SMM Mitigation — flags decode → `WsmtInfo { fixed_comm_buffers, comm_buffer_nested_ptr, system_resource_protection }`. Spec: `acpi/specification/tables-firmware-hpet-prm.md` §1. |
| ACPI WAET        | Windows ACPI Emulated Devices — `WaetInfo { rtc_good, acpi_pmtimer_good }`. Spec: `acpi/specification/tables-firmware-hpet-prm.md` §2. |
| ACPI HPET-desc   | HPET Description Table — `HpetDesc { block_id, base, addr_space_id, hpet_number, main_counter_min, oem_attributes }`. Spec: `acpi/specification/tables-firmware-hpet-prm.md` §3. |
| ACPI FACS        | Firmware ACPI Control Structure — reached via FADT.firmware_ctrl / X_FirmwareCtrl. `FacsInfo { hardware_signature, firmware_waking_vector_{32,64}, global_lock, flags, version }`. Spec: `acpi/specification/tables-firmware-hpet-prm.md` §4. |
| ACPI PRMT        | Platform Runtime Mechanism Table — per-module decode → `PrmtModule { major_revision, minor_revision, handler_count, mmio_range }`. Spec: `acpi/specification/tables-firmware-hpet-prm.md` §5. |
| ACPI CCEL        | Confidential Computing Event Log — `CcelInfo { cc_type, cc_subtype, log_area_min, log_area_phys }`. Spec: `acpi/specification/tables-confidential-power-secure.md` §1. |
| ACPI MPST        | Memory Power State Table — per-node header decode → `MpstNode { node_id, enabled, power_managed, hot_pluggable, base, length_bytes }`. Spec: `acpi/specification/tables-confidential-power-secure.md` §2. |
| ACPI SDEV        | Secure Devices Table — Type 1 (PCI endpoint) → `SdevPci { segment, start_bdf }`. Spec: `acpi/specification/tables-confidential-power-secure.md` §3. |
| ACPI SBST        | Smart Battery Specification — `SbstInfo { warning_level_mwh, low_level_mwh, critical_level_mwh }`. Spec: `acpi/specification/tables-confidential-power-secure.md` §4. |
| ACPI RAS2        | RAS Feature Table — per-PCC descriptor decode → `Ras2Descriptor { pcc_id, feature_type, instance_count }`. Spec: `acpi/specification/tables-confidential-power-secure.md` §5. |
| iwlwifi          | Intel Wi-Fi 6 / 6E (AX200 / AX201 / AX210 / AX211). **Structural probe only** — PCI match table + spec doc. Operational register map (CSR/PRPH offsets, firmware loader, TFD/RBD descriptors, host-command opcodes) is not in any public Intel doc; further stages blocked on public register docs. See `drivers/net/specification/iwlwifi.md`. |
| AHCI (ICH9/10)   | HBA bring-up + IDENTIFY DEVICE + READ/WRITE DMA EXT. |
| xHCI USB host    | HCRST + DCBAA + Command/Event Rings + scratchpad + USBCMD.RS=1 + port reset + Enable Slot + Address Device + GET_DESCRIPTOR + Configure Endpoint + bulk/interrupt IN/OUT. |
| USB HID keyboard | Hot-plug enumeration → Set Protocol(Boot) → interrupt-IN polling → HID Usage 0x07 → `narf_input::KeyCode` press/release diffing, 8-modifier tracking, roll-over filter, feeding the global `InputEvent` ring. |
| fw_cfg (firmware) | QEMU `fw_cfg` interface (x86_64 PIO, selector 0x510 / data 0x511). Magic-string presence probe, file-directory parse (FW_CFG_FILE_DIR=0x0019), `find(name)` / `read(file, &mut buf)` / `read_string(name)` per `docs/specs/fw_cfg.rst`. Stage::Subsys initcall caches presence at boot. aarch64 MMIO TODO. Crate `narf-firmware-fw-cfg` at `firmware/fw_cfg/`. |

Cross-driver integrations:
- `block::registry` — unified `BlockDeviceSync` trait; NVMe +
  virtio-blk-pci + AHCI register adapters (`nvme0`, `vblk0`,
  `sata0`) so the kernel addresses heterogeneous storage uniformly.
- `narf_drivers::bound` — live inventory of bound drivers
  (`name`, `BoundKind`, vendor/device). Boot prints the full
  portfolio.
- `narf_net::pkt` — Ethernet / ARP / IPv4 / ICMP echo
  parse+build helpers + RFC-1071 IP checksum. e1000 round-trip
  smoke confirms the builders interop with QEMU's user-mode
  network backend.

Representative x86_64 boot transcript:

```
$ cargo xtask run --arch=x86_64
NARF Stage 1 Wave 1 — hello from a bare kernel.
  arch: x86_64 | backend: Pks
  idt: loaded — 32 CPU-exception vectors routed
  features: nx=true tsc_inv=false pku=true pks=true uipi=false rdseed=true rdrand=true
  pks: enabled (CR4.PKS=1, IA32_PKRS=0 / all-allow)
  domains: 16 declared (Stage 1 all PKS/MTE-off, rights = all-allow)
  boot info: 9 memory region(s), uart_phys=PhysAddr(0x00000000000003f8)
  usable RAM: 255 MiB
  frames: total 65406 / free 65094 / reserved 312 (254 MiB usable)
  mmu: handoff...
  mmu: installed, PML4 @ PhysAddr(0x000000000ffde000), console remapped
  scheduler: ready queue initialised
  scheduler: spawning 1 task, running to completion
  tick 0: elapsed 100 Mcycles
  tick 1: elapsed 200 Mcycles
  ...
  halting — Stage 1 exit-gate demo complete.
```

```
$ cargo xtask test --arch=x86_64
...
── kernel_test harness ──────────────────────────
  [ OK ] smoke_domain_switch            ← enter_domain scope enforcement
  [ OK ] smoke_nx_enforces_no_exec      ← NX enforces NO_EXEC
  [ OK ] smoke_timer_irq_fires          ← hardware LAPIC-timer IRQ
  [ OK ] smoke_pks_enforces_deny_all    ← live PKS #PF/PK demo
  [ OK ] smoke_probe_catches_page_fault ← recoverable trap
  [ OK ] smoke_pks_set_get_rights
  [ OK ] smoke_pkrs_roundtrip
  [ OK ] smoke_map_preserves_pk_field
  [ OK ] smoke_pte_pk_field
  [ OK ] smoke_paging_map_translate_unmap
  [ OK ] smoke_frame_alloc_roundtrip
  [ OK ] smoke_scheduler_drives_future
  [ OK ] smoke_sleep_future_waits
  [ OK ] smoke_monotonic_advances
  [ OK ] smoke_box_roundtrip
  [ OK ] smoke_spin_lock_cycle
  [ OK ] smoke_bitmap_first_set
  [ OK ] smoke_arch_backend
  [ OK ] smoke_typed_id_sanity
── summary: 17 pass, 0 fail, 0 skip ──
```

## Crates that exist

| crate               | role                                                     |
| ------------------- | -------------------------------------------------------- |
| `narf-lib`          | Typed IDs, SpinLock, OnceLock, Bitmap, IntrusiveList.    |
| `narf-arch`         | HAL: halt, interrupts, io_port, msr/cr, cpuid, pks.      |
| `narf-memory`       | PhysAddr/VirtAddr, bump heap, PhysFrame allocator, paging API, MMU bring-up. |
| `narf-boot`         | RawBootInfo, PVH / FDT memory-map parse.                 |
| `narf-console`      | 16550A / PL011 + `remap_to_virtual` handoff plumbing.    |
| `narf-time`         | Instant from TSC/CNTPCT + `SleepUntil` Future.           |
| `narf-scheduler`    | Cooperative executor: spawn, yield_now, run_until_empty. |
| `narf-verification` | `#[kernel_test]` collector + runtime + 14 built-in tests.|
| `narf-frame`        | Bin: `_start`, long-mode transition, IDT/GDT/TSS, demo.  |
| `xtask`             | `cargo xtask {build,run,test,image}` per arch.           |

## Stage 1 exit-gate status (closed)

| # | requirement                                                    | state |
|---|----------------------------------------------------------------|-------|
| 1 | boot through `boot::_start` → `frame::init_bsp`                | ✓     |
| 2 | print `mmu: handoff...` via `remap_to_virtual`                 | ✓     |
| 3 | Future-on-executor prints per tick, exits cleanly              | ✓     |
| 4 | `verification/` smoke test produces Pass exit                  | ✓     |
| 5 | boot-time domain enumeration                                   | ✓     |
| 6 | no unsafe block outside `arch/` touches privileged MSRs        | ~ design-enforced; Clippy / post-link scan TBD |

## Stage 2 Barrier — what exists

- **CPUID feature probe** (`arch/x86_64/cpuid.rs`): NX, PKU, PKS, UIPI,
  invariant-TSC, RDSEED, RDRAND, x2APIC, APIC detected at boot and
  reported.
- **x2APIC enable** (`narf-interrupts` crate, `apic::init_bsp`):
  IA32_APIC_BASE set with EN + EXTD; SIVR programmed; both legacy
  8259 PICs masked (via I/O ports 0x21 + 0xA1 writing 0xFF);
  LVT timer masked by default; `start_timer` / `stop_timer` for
  periodic-mode configuration; `self_ipi` helper.
- **IRQ-vector IDT entries** (`frame/x86_64`): stubs + IDT installs
  for vectors 32..=47 and 255 (spurious). `rust_trap_handler`
  dispatches IRQ vectors (>= 32) separately from exceptions,
  calling the appropriate subsystem handler and EOI-ing the LAPIC.
- **Hardware timer IRQs live**: LAPIC timer fires vector 32 at the
  configured cadence; `on_timer_tick` increments a counter visible
  via `narf_interrupts::x86_64::apic::timer_ticks()`. Default
  boot runs with IRQs unmasked for the duration of the async demo;
  typical observed tick counts: 15 during a 5-tick demo.
  Regression-guarded by `smoke_timer_irq_fires` kernel test.
- **IRQ-driven scheduler**: `scheduler::run_until_empty` polls every
  ready task once per round; if no task became `Ready` in the round,
  it calls `arch::halt_until_irq` (HLT on x86_64 when IF=1, WFI on
  aarch64, `spin_loop` fallback when IRQs are masked). The LAPIC
  timer IRQ wakes the CPU, a new round runs, progress repeats. On
  the 5-tick demo: 15 timer IRQs delivered vs. the previous busy-
  poll's ~0 IRQs while spinning `Instant::now`.
- **NX enable**: `IA32_EFER.NXE = 1` at boot (gated on CPUID.NX) so
  PTE bit 63 (`PtFlags::NO_EXEC`) actually prevents instruction
  fetch. Regression-guarded by `smoke_nx_enforces_no_exec`: maps a
  page `WRITABLE | NO_EXEC`, jumps to it, catches the `#PF` with
  error-code bit 4 (instruction-fetch) set.
- **Domain switch API**: `arch::x86_64::pks::enter_domain(kernel,
  driver)` + matching `exit_domain` — single-PKRS-write that denies
  every PK domain except the two named. Regression-guarded by
  `smoke_domain_switch`: maps a PK=DRIVER_0 page, verifies
  `enter_domain(FRAME, DRIVER_0)` allows access, then
  `enter_domain(FRAME, DRIVER_1)` denies it (PK-violation #PF).
  This is the Stage-2 canonical "entering driver scope" primitive
  that Stage-3 driver dispatch will call.
- **`DomainPrimitive` trait**: the shape spec'd in `arch/` §3 now
  exists as an actual trait. `narf_arch::x86_64::Pks` impls it
  (forwards to `pks::*`); `narf_arch::aarch64::Mte` is a stub with
  the same signatures (bodies `unimplemented!`). `narf_arch::Domain`
  type alias resolves to the current-arch concrete type so
  arch-agnostic consumers write `Domain::save()` / `Domain::enter_domain(...)`.
- **MSR / CR helpers** (`arch/x86_64/msr.rs`, `.../cr.rs`): `rdmsr`,
  `wrmsr`, `read_cr4`, `write_cr4`, with the compiler_fence(SeqCst)
  pair per `arch/` §4.
- **CR4.PKS + PKRS live**: frame/'s boot path flips the bit when CPUID
  says PKS is available and initialises IA32_PKRS to 0 (all-allow).
- **Domain primitive** (`arch/x86_64/pks.rs`): `save` / `restore` /
  `get_rights` / `set_rights` — matches the shape of `arch/` spec §3's
  `DomainPrimitive` trait without formally declaring the trait yet
  (comes when aarch64 MTE lands the symmetric counterpart).
- **PTE PK field** (`memory/paging.rs`): `PtFlags::pk(domain)` /
  `pk_of()`; `map_4kb` tags a page with any of 16 PK domains.
- **4 KiB page-table walk API**: `map_4kb` / `unmap_4kb` / `translate` /
  `flags_at` / `read_cr3` operating on an arbitrary PML4 — including
  the live one.
- **Recoverable trap handler** (`frame/x86_64/trap.rs` +
  `arch/x86_64/probe.rs`): Linux-style exception-table pattern. Arm
  a probe with a recovery RIP; CPU exceptions redirect there via
  `iretq` instead of panic-exiting. Captures vector + error code.
- **Live PKS enforcement, verified**: `smoke_pks_enforces_deny_all`
  kernel test maps a page with PK=9, sets IA32_PKRS domain 9 to
  DENY_ALL, writes → `#PF` with error-code bit 5 (PK violation) set,
  handler catches, test checks both vector and error-code bit. The
  full PTE-PK → PKRS-rights → hardware-check → #PF → recovery loop
  is exercised every run.

## Stage 2 Barrier — status

**Substantively complete. All core items landed, both arches green.**

- ~~Higher-half kernel~~ ✓ done. Linker scripts place
  `.text`/`.rodata`/`.data`/`.bss` at high virt
  (`0xFFFFFFFF_80000000` on x86_64, `0xFFFFFF80_00000000` on aarch64)
  with `AT()` phys LMA. `.boot` / `.boot.data` stay at low phys for
  the pre-MMU bootstrap. Both arches boot with kernel RIPs at
  high-half.
- ~~aarch64 MTE mirror~~ ✓ done. `arch::aarch64::mte::Mte` impls
  `DomainPrimitive` with live `save` / `restore` on `SCTLR_EL1`.
  `smoke_domain_primitive_trait` exercises the save/restore round-
  trip on aarch64 through the trait. GCR_EL1 access (MTE L2) deferred
  to Stage 3 when QEMU `-machine virt,mte=on` + tag storage lands;
  `enter_domain` is currently a structural save-only (actual
  `SCTLR_EL1.TCF = Sync` flip needs tag storage coherent first,
  else every subsequent access tag-faults).
- ~~GICv3 skeleton on aarch64~~ ✓ done. `init_bsp` programs the
  CPU interface (system registers) + distributor (MMIO 0x0800_0000)
  + redistributor (MMIO 0x080A_0000), enables the generic-timer
  PPI (INTID 30). Default boot delivers ~100 timer IRQs during
  the 5-tick demo; `smoke_aarch64_features` guards the probe.

Remaining Stage 2 items (all additive / out of scope for local test):

- **UIPI** (Sapphire Rapids+ only). QEMU `-cpu max` doesn't expose
  UIPI on this host, so exercising it requires new hardware. The
  IDT / IRQ infrastructure is ready; the actual UIPI MSR programming
  would be <100 lines when there's a test target.
- ~~Proper per-task waker plumbing~~ ✓ done. Each `TaskSlot`
  owns an `Arc<AtomicBool>` awake flag; the `Waker` vtable
  flips it via `wake` / `wake_by_ref`. `run_until_empty`
  `swap(false)`s the flag before polling and skips slots whose
  flag is still `false` on the next round, so a future stashed
  behind an IRQ/IPC signal no longer costs a poll per loop.
  The halt-on-no-progress backstop is kept as the energy-save
  path for self-waking futures (today's `SleepUntil` /
  `yield_now`). Regression-guarded by
  `smoke_scheduler_respects_waker` (both arches).
- **Per-CPU probe state** — this is actually a Stage 3 SMP item
  (current single-CPU state is correct by construction for Stage 2).

## Stage 3 Flow — what exists

- **`capabilities/`**: 128-bit `CapSlot` (`repr(C, align(16))`,
  CMPXCHG16B / LDXP-STXP / CASPAL-sized), `Cap<T, R: Rights>` with
  hand-rolled `Copy`/`Clone`/`Send`/`Sync`, `Read`/`Write`/`Grant`
  + reflexive `SubsetOf<R>` compile-time narrowing, full `CapKind`
  wire registry (§3.1), `CapType` marker, `parse_kind`/`kind_name`.
  Live cap-table runtime: per-object `AtomicU32` epoch in an
  append-only `Vec<Entry>` under `IrqSafeSpinLock`; `check_live`
  compares stored generation to current epoch; `revoke(self)`
  `fetch_add(AcqRel)`s the epoch → O(1) mass invalidation across
  every clone / badged copy / derived narrowing; `invoke<O: CapOp>`
  gates on `check_live` then dispatches `op.execute(cap)`; safe
  `Cap::<T: CapType, R>::bootstrap()` allocates a fresh object
  entry and mints a cap with the right `CapKind` tag.
- **`ipc/`**: Narf-Ring SPSC. `Ring<T, N>` with cache-line-partitioned
  head/tail via `Align64<AtomicU64>`, `MaybeUninit<T>` slot ownership
  transfer (T moves through the ring; no byte-level copy), explicit
  release/acquire pair on every index transition (correct under
  aarch64's weaker ordering model), both-side waker slots
  (`SpinLock` producer-side + `IrqSafeSpinLock` consumer-side for
  driver-IRQ publish contexts), `closed` latch on drop, `Drop for
  Ring` drains undelivered slots. `CapType` → `CapKind::Ring`.
- **`abi/`**: wire shapes. `Submission { op, flags, caps: [CapSlot; 4],
  tag, inline: [u64; 6] }` sized 144 B / 16-aligned (`CapSlot`'s
  16-align forces an 8-byte mid pad + 8-byte tail pad — the naive
  128-byte arithmetic undercounts both), `Completion { tag, status,
  result: [u64; 6] }` at 64 B / 8-aligned, `OpCode` (`repr(u32)`,
  7 variants with pinned discriminants), `SubmissionFlags`
  (`repr(transparent)` u32 bit-set), `NarfStatus` (`repr(u32)`,
  8 pinned variants), `Tag(u64)` correlation newtype,
  `SubmissionQueue` / `CompletionQueue` type aliases over
  `narf-ipc` Producer/Consumer. Stage-3 round lands the §3.1
  cooperative cancellation protocol: `Dispatcher::pending` tracks
  cancel-pending tags; `OpCode::Cancel` reads `target_tag` from
  inline[0], records it, and always completes Ok; the target's
  completion is routed to `Cancelled` (when
  `SubmissionFlags::CANCELLABLE` is set) or `CancelRequested`
  (non-cancellable path) on drain. Mid-op cancellation via
  per-inflight flags remains Stage 4 (needs concurrent dispatch).
- **`drivers/`**: framework. `Driver` trait (async `start`/`quiesce`
  via `Pin<Box<dyn Future>>` so the registry holds heterogeneous
  drivers), `DriverHandle` cap marker → `CapKind::Driver`,
  `DriverManifest` (typed `&[CapKind]`, compile-checked — a manifest
  naming an unknown cap is a build error), `DomainPolicy::{Shared,
  Dedicated}` with §4.1 6-driver-dedicated-domain cap, `DriverEnv`
  handed to `start`, `DriverRegistry` + global `registry()` with
  cap-gated `register()` (Wave-3a fix landed: count+push in one
  critical section), `DriverPhase` state machine providing shared
  exclusivity for both `start_named` and `quiesce_named` (Wave-3a
  aliasing-UB fix), `with_entry` observer accessor, `NoopDriver`
  reference impl, `bootstrap_authority()`.
- **`drivers/virtio/`**: virtio-mmio skeleton. Register constants
  per spec §4.2.2, `VirtioMmioDevice::probe` / `probe_raw`
  validating magic / version / device-id / vendor-id with
  `compiler_fence(SeqCst)` pair per `arch/` §4, `ProbeError`,
  `VirtioSkeletonDriver` implementing the `Driver` trait. Feature
  negotiation, virtqueue ring, doorbells, IRQ binding, subdrivers:
  Stage 4.
- **`io/`**: DMA buffer + IOMMU stub. `DmaBuffer` (backed by a
  single `PhysFrame`, `CapType` → `CapKind::DmaBuffer`, `phys_addr`
  / `len` / `domain` / `coherency` getters), `alloc_coherent` /
  `free_coherent` (page-aligned), `IommuContext` with `map` /
  `unmap` as QEMU-compatible no-ops, `IoError` enum, `p2p_map`
  signature-only placeholder. Multi-frame contig, real VT-d/AMD-Vi/
  SMMUv3, P2P, aarch64 `DC CIVAC`: Stage 4.
- **`rcu/`**: real QSBR (per-CPU reader counters + global epoch +
  per-CPU deferred-drop buckets with `u64::MAX` offline-CPU
  sentinel), Epoch variant (`pin`/`unpin`/`advance`/`min_pinned`),
  Hazard + Sleepable shape-only stubs, `Owned<T>` /
  `Shared<'g, T>` / `Atomic<T>` public surface. `scheduler/`
  calls `narf_rcu::report_quiescent()` after every `Future::poll`
  return per rcu/ §3.7 — every cooperative yield advances the
  grace period.
- **`tracing/`**: static markers + flight recorder + dynamic probes +
  live aggregates. `probe!` macro emits a nop-sled + `.note.narf.probes`
  ELF-note record (KEEP'd on both arches, bounded by
  `__narf_probes_start`/`_end`), `FlightRing<T, N>` with per-slot
  seqlock publish protocol (odd=in-flight, even=published),
  const-asserted non-zero power-of-two `N`. Stage-3 round 5 lands:
  `dispatch::fire(probe_id, args)` with a cap-gated
  `ProbeHandlerInstall` registry (linear-scan, up to 256 handlers),
  `FnTime` scope accumulator with Welford online mean/variance, and a
  log2-bucket `Histogram` stub standing in for the Stage-4 tDigest.
  Real tDigest accuracy contract + per-CPU hazard-pointer handler
  table: Stage 4.
- **`bus/`**: enumeration + BAR sizing + LAPIC-directed MSI-X
  programming. PCIe ECAM walker on x86_64 (q35 default `0xb000_0000`,
  MCFG deferred), FDT bus walker on aarch64 with a QEMU-virt fallback
  layout, `BusDevice` / `BusKind::{Pcie, VirtioMmio}` / `DeviceId`,
  read-only registry, `claim_device` stub. `bus::init` is now wired
  into `frame::_start_rust` after MMU bring-up (x86_64 walks q35 ECAM,
  aarch64 falls back to the virtio-mmio probe). `bus::bar` adds
  `read_bar` (size detection via the standard write-all-1s / read-back
  / restore cycle, decoding 32-bit MMIO / 64-bit MMIO / I/O BARs) and
  `map_bar` returning an `MmioRegion` with volatile `read32`/`write32`.
  `MsixTable::program_vector` writes the four-u32 MSI-X table entry
  (msg_addr_lo = `0xFEE0_0000 | (apic_id<<12)`, msg_addr_hi = 0,
  msg_data = vector, vector_control = 0); `MsixTable::enable` flips
  the Message-Control "MSI-X enable" bit. aarch64 `program_vector`
  returns `Unsupported` until the GIC ITS doorbell path lands.
  Hot-plug, IOMMU-group coordination, real MCFG parsing: still later
  waves.
- **`scheduler/`**: per-task waker plumbing (Wave-0 + Stage-2 close)
  plus Stage-3 §3.3/§3.4 task-spec surface. Each `TaskSlot` owns an
  `Arc<AtomicBool>` awake flag; `Waker` vtable flips it via
  `wake`/`wake_by_ref`. `run_until_empty` `swap(false)`s before polling
  and skips slots whose flag is still false, so IRQ/IPC-driven futures
  no longer cost a poll per loop iteration. `narf_rcu::report_quiescent()`
  invoked after each poll. Stage-3 round adds `TaskSpec` (affinity +
  budget + optional `Cap<CpuBudget, Spend>`), `spawn_with_spec` /
  `spawn_budgeted` entry points, `BudgetAccount` running totals
  (cycles_spent / polls / overruns), `ResourceBudget` + `OverrunPolicy`
  + `Affinity` + `CpuSet` types. Every poll `check_live`-gates the
  attached budget cap — revoking stops the task O(1) on the next round
  — and charges measured `narf_time::Instant` cycles into the account.
  Direct context transfer, work stealing, multi-CPU: Stage 4.
- **`observability/`**: Stage-3 round wires PMU sampling through the
  tracing transport. `sample_pmu(cap, ring)` reads cycles (+
  instructions when available) and records an
  `ObservabilityEvent::Pmu` into a `FlightRing`; `PmuProbeHandler`
  bridges `tracing::ProbeHandler::fire` to a sample, so registering
  one handler on a probe id samples the PMU on every fire.
  `capture_core_dump(regs)` bundles `CrashFrame` + `take_snapshot()`
  into the single struct a panic path emits. Stage-4 items unchanged
  (real arch PMU primitives, multiplexed counter groups).
- **`capabilities/`**: Stage-3 round adds the `Spend` rights marker
  (reflexive under `Grant`, orthogonal to Read/Write) so cap types
  that represent consumable quotas (`CpuBudget`, future `DmaAllowance`)
  can be distinguished from policy-mutation rights at the type level.

### Stage 3 exit-gate integration

`smoke_exit_gate_buffer_handoff` + `smoke_exit_gate_revoked_cap_rejected`
(both arches) compose the spec's Stage-3 criterion: task-1 `alloc_coherent`
→ writes a 17-byte pattern to the buffer's phys address → mints
`Cap::<DmaBuffer, Read>::bootstrap()` → sends `(DmaBuffer, Cap)` through
an `ipc/` channel; task-2 `recv().await` → `cap.check_live()` gate →
volatile-reads the pattern → asserts match. Ownership moves by handle
(no memcpy of the payload). The revoked-cap variant confirms O(1) mass
invalidation on the fast path.

What Stage 4 adds that Stage 3 elides (tracked as follow-ups in each
subsystem's README): real PKS/MTE enforcement on buffer pages, driving
real virtio silicon (feature negotiation, virtqueue rings, doorbells,
IRQ binding, subdrivers), real IOMMU programming, user-mode consumer
via `abi/` submission surface (makes "no Ring-0 trap on the fast path"
literal instead of trivial-in-kernel-AS), `BootstrapRequest` / Reply
slow path in `frame/`, cooperative-cancel state machine in `abi/`.

## Stage 2 design debt (not blocking, worth tracking)

- **Higher-half migration**. Linker script lives at phys 0x100000,
  code-model=small. Every Stage-2+ convention expects -2 GiB kernel.
- **Full buddy allocator**. `memory::frame` is free-stack / 4 KiB only.
  Buddy + `Folio { order, head }` land when 2 MiB / 1 GiB mapping
  gets consumers.
- **Slab heap**. Retires the 1 MiB bump arena. Currently the bump arena
  is ~50% consumed by the frame allocator's free-stack Vec.
- **`frame/` trap-prologue PKRS save**. Scaffolding only. Once the
  scheduler's context-switch save/restore needs it (Stage 3 direct
  context transfer), wire the PKRS save into the trap prologue.

## Deviations from the v0.2 design (in-code comments flag each)

1. **PVH instead of Limine** on x86_64. `boot/` spec §5 pins Limine
   as sole Stage-1 x86_64 bootloader; we use Xen-PVH because it's
   the only ELF64 direct-kernel path `qemu-system-x86_64 -kernel`
   supports. `boot/src/x86_64/multiboot2.rs` is still named
   multiboot2 for future compat, but its contents parse
   `hvm_start_info`.
2. **Low-half linking**. Kernel links at phys 0x100000 today.
3. **Bump heap** under `#[global_allocator]` — not the buddy+slab.
4. **aarch64 FDT walker is a stub** — synthesises a 128-MiB region
   from QEMU-virt defaults.
5. **Formal `DomainPrimitive` trait not declared yet** — the
   `arch::x86_64::pks` module has the shape (save/restore/get/set),
   but the trait itself waits for aarch64 MTE to provide the second
   implementation needed to justify the abstraction.

## How to run

```bash
# Default flavour: async executor demo, 5 ticks, clean exit.
cargo xtask run  --arch=x86_64

# Kernel-test harness: 14 tests, isa-debug-exit signals pass/fail.
cargo xtask test --arch=x86_64

# IDT self-test: deliberately trigger #UD; print trap frame; exit 42.
cargo xtask run  --arch=x86_64 --features=idt-selftest

# Cross-compile for aarch64 (qemu-system-aarch64 not installed locally).
cargo xtask build --arch=aarch64 --package=narf-frame

# Host-side unit tests on narf-lib.
cargo test -p narf-lib
```

## Commit log (high-level)

| commit        | landed                                                       |
|---------------|--------------------------------------------------------------|
| Baseline      | 217-file NARF v0.2 design tree                               |
| Wave 0        | Cargo workspace + nightly + build-std + narf-lib primitives  |
| Wave 1        | arch/ + console/ + boot/ + frame/ ⇒ bootable x86_64          |
| Wave 2a       | IDT + trap dispatch (ud2 self-test verified)                 |
| Wave 3        | time/ + scheduler/ + async executor + timer-driven demo      |
| domains+verif | 16-domain enumeration + verification/ harness + 4 tests      |
| more tests    | 4 additional smoke tests covering scheduler/time/alloc       |
| Wave 2 GDT    | GDT + TSS + 4 IST stacks (NMI/#DF/#MC/#VC)                   |
| Wave 2b       | PhysFrame + free-stack frame allocator                       |
| Wave 2c       | MMU handoff — own PML4, CR3 swap, console::remap_to_virtual  |
| Stage 2 paging| `map_4kb` / `unmap_4kb` / `translate` + kernel test          |
| Stage 2 PKS   | CR4.PKS enable, CPUID probe, `arch::x86_64::pks` module      |
| Stage 2 PK    | PTE PK field, `DomainPrimitive`-shaped save/restore/get/set  |
| probe         | Recoverable trap handler + arm/disarm exception-table probe  |
| PKS live      | `smoke_pks_enforces_deny_all` — end-to-end #PF/PK demo      |
| APIC partial  | `narf-interrupts` + IRQ IDT entries; soft INT 32 works      |
| APIC full     | 8259 PICs masked; hardware LAPIC timer IRQs live + tested   |
| IRQ sched     | run_until_empty halts between no-progress rounds            |
| NX enable     | IA32_EFER.NXE + NO_EXEC enforcement test                    |
| Domain switch | enter_domain/exit_domain API + cross-domain denial test     |
| Domain trait  | DomainPrimitive trait; Pks impl live, Mte stub for aarch64  |
| aarch64 boot  | `virt` machine boots; full async demo runs on aarch64 too   |
| per-task waker| `Arc<AtomicBool>` waker vtable — Pending tasks skip repoll |

## Pickup hint for the next session

The critical-path Stage-2 items remaining:

1. **Interrupt controller bring-up** (`interrupts/`). ✓ landed —
   x2APIC init + LAPIC-timer periodic IRQ + IRQ-vector IDT entries +
   `rust_trap_handler` IRQ dispatch all wired into boot;
   `smoke_timer_irq_fires` proves end-to-end delivery. The follow-up
   "real waker driving the scheduler" remains a Stage-3 polish item;
   today the timer just bumps a counter.

   Adjacent driver-readiness work also closed in this round:
   `bus::init` wired into boot, BAR sizing + MMIO mapping
   (`bus::bar::{read_bar, map_bar, MmioRegion}`), and LAPIC-directed
   MSI-X programming (`MsixTable::{program_vector, enable}`) on
   x86_64. aarch64 `program_vector` returns `Unsupported` until the
   GIC ITS doorbell path lands.

   NVMe admin-queue bring-up landed on top: `Controller::bring_up`
   maps BAR0, decodes CAP/VS, resets the controller, allocates the
   ASQ + ACQ via `narf_io::alloc_coherent`, programs `AQA/ASQ/ACQ`,
   re-enables `CC.EN`, polls `CSTS.RDY=1`, and issues IDENTIFY
   CONTROLLER (CNS=1) — completion is observed via the CQE phase-tag
   flip and acknowledged by ringing the head doorbell. xtask
   attaches a QEMU `nvme,drive=nvm0,serial=narf` device on x86_64
   backed by `target/narf-nvme.img`. End-to-end guarded by
   `smoke_nvme_admin_identify_controller`, which asserts the
   IDENTIFY response carries QEMU's vendor id (0x1B36) and model
   prefix (`"QEMU"`).

   IRQ-driven driver readiness: `narf_interrupts` now exposes a
   generic dispatch table (`on_irq(vector)` + per-vector fire counts
   + waker bridge), an IDT-vector bitmap allocator
   (`vector::alloc/free`), and a `wait_for_irq(vector).await` future
   that bridges IRQ delivery to the async executor. Both arch trap
   paths route vectors ≥ 32 (x86_64) / non-timer SPIs+LPIs (aarch64)
   through `narf_interrupts::on_irq`. `MsixTable::program_vector`
   is now arch-symmetric: x86_64 emits `0xFEE0_0000 | (apic_id<<12)`
   + IDT vector; aarch64 emits the GIC ITS doorbell PA
   (`GITS_TRANSLATER` = 0x0809_0040 on QEMU virt) + EventID. ITS
   bring-up runs at boot under aarch64 — allocates device /
   collection / command-queue tables, programs `GITS_BASER`,
   `GITS_CBASER`, `GICR_PROPBASER`, `GICR_PENDBASER`, enables LPIs,
   submits MAPC for collection 0 → CPU 0. `its::map_event(device,
   event, lpi, collection)` issues MAPD + MAPTI. Smokes:
   `smoke_irq_dispatch_fire_count`, `smoke_vector_alloc_unique`,
   `smoke_wait_for_irq_resolves_after_on_irq`, `smoke_its_doorbell_addr`.

   NVMe end-to-end I/O is now real on x86_64: `Controller::create_io_queue`
   issues Create I/O CQ + Create I/O SQ admin commands and `read_lba`
   / `write_lba` submit NVM Read/Write through the I/O queue, polled.
   `smoke_nvme_io_round_trip` writes a 512-byte pattern at LBA 0 and
   reads it back. IDENTIFY NAMESPACE is also issued during bring_up
   so `Controller::lba_bytes` and `Controller::nsze` are real.

   IRQ-driven NVMe is also live on x86_64: `create_io_queue_msix`
   walks the MSI-X cap, allocates an IDT vector via
   `narf_interrupts::vector::alloc`, programs MSI-X table entry 0
   to deliver that vector to APIC 0, flips the global enable, then
   re-issues Create I/O CQ with `IV=0, IEN=1`. `submit_io_irq`
   spins on `narf_interrupts::fire_count(vector)` (the same atomic
   `wait_for_irq.await` consumes), confirming MSI delivery actually
   reaches the dispatch table. The full IDT now installs vectors
   32..=254 (not just 32..=47) so the allocator pool 48..=240 is
   guaranteed to land on a present gate. End-to-end guarded by
   `smoke_nvme_io_msix_irq_driven`, which verifies the round-trip
   pattern *and* asserts the dispatch table observed at least one
   MSI during the I/O.

   Full PCIe stack now in place. New surfaces:
   - `bus::pci_cap` — generic capability-list walker with
     `find_cap(device, id) -> Option<offset>` and an `iter()`
     iterator. `bus::msix::enable_msix` is refactored to use it.
   - `bus::pci_cap_ext` — PCIe extended capability list walker
     (offset 0x100..0xFFF, 16-bit IDs); reader for AER status
     (correctable + uncorrectable).
   - `bus::pci_express` — PCI Express capability surface: read
     Device Caps / Device Control / Link Status / Link Caps;
     MaxPayload / link-speed / link-width decoders. FLR support
     via `function_level_reset(cap, &dev)` that asserts the FLR
     capability bit, sets DevCtl.InitiateFLR, and waits for the
     device to come back.
   - `bus::msi` — legacy MSI cap (cap ID 0x05) for devices that
     don't expose MSI-X. Same shape as MSI-X with cfg-space-resident
     message-address/data; supports 64-bit address + multi-message
     enable up to 32 vectors.
   - `MsixTable::program_vector_block(start, n, target, irq_base)`
     for per-CPU IO queues; `mask_vector` / `unmask_vector` per
     entry helpers.
   - `narf_interrupts::vector::alloc_block(n)` reserves N
     contiguous IDT vectors with rollback on failure.

   Smokes: smoke_pci_cap_walker_finds_msix,
   smoke_pci_express_cap_link_status, smoke_msix_program_block,
   smoke_pci_cap_ext_walker, smoke_vector_alloc_block_contiguous.

   First in-tree PCIe drivers shipped:
   - **virtio-blk-pci** (modern, vendor 0x1AF4, device 0x1042).
     `drivers/virtio/src/pci.rs` walks the vendor-specific virtio
     caps (Common Cfg, Notify, ISR, Device Cfg) and maps each via
     `bus::map_bar`. `blk_pci.rs` does feature negotiation
     (VIRTIO_F_VERSION_1), queue-0 setup, polled
     `read_sector` / `write_sector`, plus an MSI-X-driven
     `read_sector_irq` that snapshot-checks
     `narf_interrupts::fire_count` after writing the queue's
     notify register. `enable_msix_for_probed(cap, &device)` flips
     the controller into IRQ-driven mode (programs MSI-X table 0,
     writes `queue_msix_vector=0`).
   - **virtio-net-pci** (modern, vendor 0x1AF4, device 0x1041).
     RX + TX virtqueues, RX pre-populated with 8 empty buffers,
     polled `tx(&[u8])` that posts a header + payload + waits for
     the device to consume it.

   xtask attaches both on both arches: `virtio-blk-pci` backed by
   `target/narf-vblk.img`, `virtio-net-pci` over a QEMU user-mode
   net backend. Smokes `smoke_virtio_blk_pci_read_sector`,
   `smoke_virtio_blk_pci_write_then_read`,
   `smoke_virtio_blk_pci_irq_driven`, `smoke_virtio_net_pci_tx`.

   - **e1000** (`drivers/net/src/e1000.rs`). Real Intel NIC driver,
     non-virtio — exercises the generic BAR + MMIO surface end-to-end.
     Probes 5 device IDs covering 8254x and 8257x families
     (0x100C/E/F + 0x10D3 + 0x153A). Bring-up: BAR0 map; CTRL.RST
     reset; read MAC from RAL/RAH; TX + RX descriptor rings (8
     entries each), 8-page RX buffer pool; CTRL.SLU for link up.
     Polled `tx(frame)` posts to TDT and waits for the descriptor's
     DD bit; `rx_recv(out)` reads DD-marked descriptors, copies the
     payload, rearms the slot, advances RDT.
   - **virtio-rng-pci** (`drivers/virtio/src/rng_pci.rs`). Modern
     virtio-rng (vendor 0x1AF4, device 0x1044). Single virtqueue.
     `read_bytes(out)` posts a device-writable descriptor, polls
     used ring, returns entropy. Probe-only smoke (data-path
     under QEMU-version-specific debug).
   - **AHCI HBA** (`drivers/storage/src/ahci.rs`). ICH9 + ICH10
     SATA controllers (0x8086:0x2922 / 0x3A22). Maps ABAR (BAR5),
     forces AHCI mode (GHC.AE), resets the HBA (GHC.HR), enumerates
     PI-implemented ports, classifies each via PORT_SIG +
     PORT_SSTS into None/Sata/Atapi/Semb/Pmp. Per-port command
     list + Received-FIS allocated per-call. ATA `IDENTIFY DEVICE`
     (opcode 0xEC) returns the 512-byte device-data block;
     `identify_model` decodes the byte-swapped 40-byte model
     string. `ahci_read_lba(port, lba, n_sectors, out)` issues
     `READ DMA EXT` (opcode 0x25), polls `PORT_CI`, copies the
     payload out — actual SATA disk reads working.
   - **virtio-balloon-pci** (`drivers/virtio/src/balloon_pci.rs`).
     Memory-pressure cooperative driver (0x1AF4:0x1045). Two
     virtqueues (inflate / deflate) brought up structurally;
     page-handoff hooks land once `narf_memory` exposes a
     pressure callback.

   xtask attaches every driver's exemplar device on both arches.
   Smokes:
   `smoke_virtio_blk_pci_*`, `smoke_virtio_net_pci_tx`,
   `smoke_virtio_rng_pci_probe`, `smoke_e1000_bring_up_and_tx`,
   `smoke_e1000_rx_arp_request`, `smoke_ahci_hba_bring_up`.

   PCIe driver-match registry (`bus::driver_match`) lets drivers
   register `(name, MatchKind, probe_fn)` entries — `MatchKind` is
   `VendorDevice` (most specific), `Class { class, mask }`, or
   `Vendor` (least). `probe_all_pci(authority)` walks the bus
   registry, picks the highest-specificity matching entry per
   device, mints a `Cap<BusDeviceCap, Write>` via
   `claim_device_cap`, and invokes the probe. NVMe registers two
   match entries (exact 0x1B36:0x0010 + class 0x01 storage) plus
   a `probe(device, cap)` fn that brings the controller up and
   stashes it in a static; `narf_drivers_nvme::with_controller`
   exposes the probed controller for inspection. Smokes:
   `smoke_pci_match_specificity`, `smoke_pci_probe_all_dispatches_nvme`.

   PCI command-register helper (`bus::pci::{set_command, clear_command,
   read_command}`) is cap-gated on `Cap<BusDeviceCap, Write>` and
   handles cfg-space offset 0x04 (`MEM_SPACE`, `BUS_MASTER`,
   `INTX_DISABLE`, `IO_SPACE`). NVMe `bring_up` flips on
   `MEM_SPACE | BUS_MASTER | INTX_DISABLE` before allocating queues
   so DMA works on real silicon (not just permissive QEMU).
   `bus::pci::requester_id(device)` packs PCIe BDF into the 16-bit
   value the GIC ITS expects as DeviceID.

   aarch64 MSI-X is now wired end-to-end: `MsixTable::program_vector`
   on aarch64 calls `interrupts::aarch64::its::map_event(device_id,
   event_id, lpi, collection)` before writing the table entry, so
   `(DeviceID, EventID) → LPI` translation is registered in the ITS
   and MSI deliveries actually land.

   PCIe ECAM walker is now shared between arches via `bus::pcie`.
   x86_64 (q35, 256-bus ECAM) walks live. aarch64 also walks live
   via DTB-driven host-bridge discovery: `bus::aarch64::walk_fdt`
   recognises `pcie@…` nodes, parses the `reg` property for the
   ECAM base + size, and calls `pcie::enumerate_n` with the
   DTB-supplied parameters. The DTB itself is generated on demand
   by xtask (`qemu-system-aarch64 …,dumpdtb=…`) and force-loaded
   into RAM at `0x4F00_0000` via `-device loader,…` since QEMU's
   `-kernel <elf>` path doesn't pass a DTB pointer in x0 the way a
   Linux Image would. `boot::aarch64::scan_for_dtb` checks the
   xtask-loaded address first, then falls back to scanning RAM
   for the FDT magic. The QEMU machine line gains
   `highmem-ecam=off` to keep the ECAM in the lo_L1[0] Device-mapped
   1 GiB block and an `nvme,drive=nvm0` device so the walker has
   something to find. `smoke_bus_pcie_dtb_aarch64` asserts the
   00:00.0 host bridge appears in the registry post-walk.

2. **Higher-half kernel relocation**. Conventional -2 GiB layout.
   Touches the linker script, boot.S (far-jump-to-virtual after
   long-mode enable), and `.cargo/config.toml` (code-model back
   to `kernel`). The MMU handoff already owns its own PML4, so
   this is mostly adding high-half PML4/PDPT entries and a
   far-jump.

3. **NX enable**. `IA32_EFER.NXE = 1` so `PtFlags::NO_EXEC` is
   actually honoured. Small (~20 lines + a kernel test that maps
   a page NX and probes a jump-to-that-page).

4. **aarch64 MTE mirror**. SCTLR_EL1.TCF / tag storage /
   replace the `Mte` stub in `arch::aarch64::mte` with a live
   impl. Running end-to-end works now (qemu-system-aarch64 is
   available on the dev host), and `smoke_domain_primitive_trait`
   will exercise the new path once the stub becomes real.

5. **`DomainPrimitive` trait extraction**. Once 4 lands, pull the
   shared shape out of `arch::x86_64::pks` and `arch::aarch64::mte`
   into `arch::DomainPrimitive`.

6. **Per-CPU probe state** (`arch::probe`). Needed for Wave-3 SMP.
   Low-value until APs come up.

Parallel-safe micro-tasks:
- Replace free-stack frame allocator with a buddy.
- `rcu/` stub API so downstream crates don't retrofit.
- `tracing/` USDT marker macro — `.note.narf.probes` section exists.

## Stage 4 structural landing

This session landed a broad Stage-4 **structural** pass — every
subsystem listed in `ROADMAP.md` Stage 4 has its type surface,
cap-type markers, and enough stub bodies to compile, test, and
interop with the rest of the tree. The bodies that actually do
something on real hardware are not yet wired because they depend on
three host-toolchain / deep-arch pieces that were out of scope:

1. **`frame/` syscall entry** — a real `syscall` (x86_64) / `svc
   #0` (aarch64) trap handler that reads `SyscallArgs` off the
   register file, dispatches through a `SyscallTable`, and returns
   a `SyscallReturn`. Needs register save/restore in the trap
   prologue, not just the existing CPU-exception path.
2. **`memory/` per-process address spaces** — every user process
   needs its own PML4/TTBR0 so user-mode mappings don't collide
   with the kernel half. The loader (`userspace::ExecImage`) places
   `PT_LOAD` segments into that address space.
3. **External relibc build** — the Stage-4 exit gate requires a
   relibc compiled against NARF's syscall ABI
   (`narf_userspace::Syscall`). That is a separate repo / build
   artefact outside this tree.

Without those three, the spec's Stage-4 exit criterion ("relibc-
linked standard Rust binary doing block + network I/O through
capability-gated paths") is unreachable from this tree alone.

### Stage 4 structural surfaces landed (both arches green)

| subsystem             | what shipped                                              |
| --------------------- | --------------------------------------------------------- |
| `block::mq`           | `MqDeadlineScheduler` with N-lane round-robin + deadline promotion (`MAX_LANES = 64`). |
| `scheduler::priority` | `SchedClass { Normal, RealTime, Idle }`, `Priority(i8)`, `SmtSharePolicy`; `TaskSpec::realtime(deadline_cycles)`. |
| `scheduler::cpu_lifecycle` | Cap-gated `cpu_bring_up` / `cpu_take_offline` against `Cap<CpuLifecycle, Invoke>` with a 64-wide online bitmap; boot CPU protected. |
| `power::thermal`      | `ThermalZone` registry + `ThermalEvent` subscribers; Normal/Warm/Critical transitions fire exactly once. |
| `power::suspend`      | Nine-phase `SuspendPhase` pipeline + `suspend(cap)` that walks the phases and returns `NotImplemented` until `arch/` exposes S3 / PSCI. |
| `EnergyAware` governor | Three-band DVFS pick keyed off `load_permille`. |
| `time::wall`          | `WallInstant`, `set_wall_offset(cap, ns)`, `begin_leap_smear(cap, delta, window)`, `now_wall()` reader. |
| `observability::gdb`  | `GdbPacket` framing + checksum helper, `GdbCommand` enum covering the RSP subset, `attach(cap)` stub. |
| `observability::peek` | `Provider` trait + cap-gated `sample_all(cap, out)` registry for live-peek metrics. |
| `userspace`           | `ProcessId`, `ExecImage` with `Segment` + `SegmentFlags` matching ELF `PF_*`, `AuxEntry` with `AT_*` tags, `SyscallTable` pinning the canonical numbers (Submit=100, …, Munmap=121). |
| `drivers/nvme`        | BAR0 register offsets, `NvmeCaps::from_raw` bitfield decoder, `AdminOpcode` + `IoOpcode` tables, `Controller::probe(cap)` stub, `NvmeBlockDevice` impl of `BlockDevice`. |
| `drivers/net`         | `NicModel` enum (e1000/igb/ixgbe/mlx5/rtl8139) with `primary_pci_id()` lookup, `NicCaps` feature bitmap, `NicDescriptor`, `HwNic` trait. Live drivers: e1000/e1000e, r8169, qcnfa765, mlx5, ixgbe. |
| `drivers/gpu`         | `GpuFamily` backend list, `Mode { width, height, refresh_hz, bpp }` with `FHD_60` / `XGA_60` presets, `SubmitKind` + `CommandBuffer` + `GpuFence`. |
| `crypto::tpm`         | TCG-spec `TpmCc` command codes (PcrExtend/Read/GetRandom/Startup/SelfTest/…), `TpmAlgHash` enum, `Tpm2Command` wrapper, `submit()` stub. |
| `crypto::pq`          | `MlKem768` / `MlDsa65` / `SphincsPlus` CapType markers, `HybridMode`, runtime `fips_mode()` + `fips_allowed(alg)` gate. |
| `net::stack`          | `StackAttach` / `StackAttachReply` protocol, `AdminCap` marker, `StackDaemon` identity cap, `attach()` stub. |
| `filesystem::page_cache` | `PageKey` + `Page { data: Arc<[u8; 4096]>, dirty, gen }` + `PageCache` with `lookup` / `insert` / `mark_dirty` / `drain_dirty`. |
| `filesystem::fuse`    | `FuseOpcode` values matching Linux UAPI verbatim, `FuseInHeader` / `FuseOutHeader` / `FuseInitIn` / `FuseInitOut` wire structs, `FUSE_KERNEL_VERSION = 7.36`. |
| `bus::acpi_notify`    | `NotifyKind` event table (BusCheck/DeviceCheck/Thermal/…), cap-gated subscriber registry, `dispatch_notify` fan-out. |
| `rcu::batched`        | `BatchedReclaimer` grouping callbacks into capped `ReclaimBatch` (BATCH_CAP = 128), `submit` / `flush`, `pace(node, quantum)` NUMA hint. |
| `tracing::hwtrace`    | `HwTraceConfig` shared between Intel PT + CoreSight ETM, `HwTraceStatus`, `HwTraceMarker` CapType, `start` / `stop` / `status` stubs. |

Test coverage for each of the above: a dedicated `smoke_*`
kernel_test in `verification/src/lib.rs` exercising either the
happy path, the cap-revoke fail-closed, or the structural
invariants. Totals after the Stage-4 round: **x86_64 134 pass,
aarch64 124 pass + 3 skip** (same three skips as Stage 3 —
arch-gated bus test, sleepable-RCU detail, virtio probe without
hardware).
