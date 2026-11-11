# drivers/soc/qcom — Specification

> Status: **v0.1** (Stage 5 "Silicon"). Fixture-tested only; nothing here
> has run on Qualcomm hardware.

## 1. Purpose & scope

**Owns:**
- Devicetree platform-device view of Qualcomm SoC nodes (`reg`/`reg-names`,
  interrupts with inherited parents, `memory-region`, phandle-argument
  lists) and resolution of a Q6 remoteproc node into plain resources.
- Qualcomm SCM calls over SMCCC: convention probe, retry/error semantics,
  PIL/PAS calls.
- MDT/MBN split-firmware parsing and loading.
- SMEM (global heap v11, global partition v12, private partitions), the
  TCSR hardware mutex, SMP2P edges, APCS/IPCC outgoing kicks.
- GCC reset lines and branch clocks used by the WiFi subsystem, as
  per-SoC tables.
- Q6v5 start/stop signalling, the Q6 WCSS (host reset) and PAS
  (TrustZone) remoteproc sequences.
- GLINK over SMEM (`qcom_glink_native.c` + `qcom_glink_smem.c`): FIFO
  transport and the native channel/intent protocol, as a non-blocking
  state machine.

**Does NOT own:**
- The SMC trap itself (`arch/` `aarch64::smccc`).
- MMIO mapping (`memory/` `ioremap`) or DMA allocation (`io/`).
- The GIC distributor itself (`interrupts/` `aarch64::gic`); `irq` binds
  DT SPIs through it and routes GIC/SMP2P/IPCC interrupts into
  `Q6v5::signal` and `Smp2p::handle_interrupt`.
- QRTR framing over GLINK (ath11k `qrtr_glink.rs`), RPMh/AOSS-QMP power votes, SMMU/IOMMU
  programming, sysmon/SSR notifications (not implemented; §8).
- A general clock/reset framework.

## 2. Assumptions
- aarch64 EL1 with a Qualcomm secure monitor implementing SMCCC SiP
  services (ARM64 or ARM32 convention; legacy is refused).
- The boot DTB follows the upstream bindings for `qcom,smem`,
  `qcom,smp2p`, `qcom,tcsr-mutex`, `qcom,*-apcs-apps-global`, `qcom,ipcc`,
  `qcom,gcc-ipq{8074,6018,5018}`, `qcom,ipq{8074,6018}-wcss-pil`,
  `qcom,sc7280-wpss-pas`.
- `soc@0` buses use identity `ranges` (true for every supported SoC).
- Register windows are accessed with 32-bit aligned loads/stores.

## 3. Public interface

### 3.1 Seams (`io`)
```rust
pub trait RegIo { fn read32(&self, off: u32) -> u32; fn write32(&self, off: u32, v: u32);
                  fn update32(&self, off: u32, mask: u32, v: u32); }
pub struct MmioRegs;  // map(phys, len) via ioremap Device; unsafe from_raw(virt, len)
pub trait Delay { fn sleep_us(&self, us: u32) -> impl Future<Output = ()> + Send; fn now_us(&self) -> u64; }
pub struct NarfDelay; // narf_time::SleepUntil
pub async fn poll_reg(io, delay, off, cond, sleep_us, timeout_us) -> Result<u32, u32>;
pub fn read_bytes<M: RegIo + ?Sized>(mem, off, buf: &mut [u8]);   // memcpy_fromio
pub fn write_bytes<M: RegIo + ?Sized>(mem, off, data: &[u8]);     // memcpy_toio (RMW edges)
```
`poll_reg` is `readl_poll_timeout`: it sleeps between reads; nothing in
this crate spins on a register.

### 3.2 Devicetree (`dt`, `platform`)
```rust
pub struct PlatformDevice { path, compatible, phandle, enabled, regs, reg_names, irqs, irq_names, memory_regions, .. }
impl PlatformDevice { reg, reg_by_name, irq_by_name, memory_region, prop*, phandle_args, phandle_args_by_name }
pub fn find_compatible(blob, compat) -> Vec<PlatformDevice>;
pub fn find_phandle(blob, ph) -> Result<PlatformDevice, DtError>;
pub fn children(blob, parent_path) -> Vec<PlatformDevice>;

pub fn platform::q6_platform(blob, rproc_phandle) -> Result<Q6Platform, DtError>;
pub fn platform::smp2p_edge(blob, path) -> Result<Smp2pDt, DtError>;
pub fn platform::smp2p_entry(blob, phandle) -> Option<(edge_path, entry_name)>;
pub fn platform::smem(blob) -> Result<SmemDt, DtError>;
pub fn platform::pas_power(blob, &PlatformDevice) -> Result<PasPowerDt, DtError>;
pub struct PasPowerDt { rsc: RscDt, cmd_db: (u64, u64), rails: Vec<&'static str>, qmp: Option<QmpDt> }
pub struct RscDt { drv: (u64, u64), drv_id: u32, tcs_offset: u32, active_tcs: u32 }
pub struct QmpDt { msgram: (u64, u64), kick: KickDt }
```
`Q6Platform` carries kind (`Wcss` | `Pas { pas_id }`), firmware name,
crash-reason item, carve-out, `qdsp6`/`rmb`/halt-regs windows, resolved
GCC resets, each interrupt as `Gic(hwirq)` or `Smp2p { edge, entry, bit }`,
the outbound `stop` bit, the SMP2P edges (config, kick, IPC irq), SMEM
and, for PAS, `power: Some(PasPowerDt)`. `pas_power` resolves
`power-domains`/`power-domain-names` (SC7280 rpmhpd index 0 → `cx`,
4 → `mx`; other SoCs' tables are not transcribed and are refused), all
under one `qcom,rpmh-rsc` whose `drv-<qcom,drv-id>` window,
`qcom,tcs-offset` and first ACTIVE TCS (`qcom,tcs-config` in DT order,
CONTROL taking no index, `rpmh_probe_tcs_config`) it records; the `xo`
clock must be `RPMH_CXO_CLK` (0) on the `*-rpmh-clk` child of that RSC;
`qcom,cmd-db` is the reserved-memory node; `qcom,qmp` (optional, as
`qcom_q6v5_init`) gives the AOSS message RAM and its `mboxes` kick.
Missing proxy domains or `xo` fail resolution, as `qcom_q6v5_pas.c`
fails probe.

### 3.3 SCM (`scm`)
```rust
pub trait SmcConduit { fn smc(&self, regs: &mut [u64; 8]); }
pub struct ArchSmc;                       // aarch64::smccc::smc_call
pub struct Scm<C> { .. }                  // &mut self per call (Linux qcom_scm_lock)
impl Scm { probe_convention, call(desc, fast, delay), is_call_available,
           pas_supported, pas_init_image(periph, meta_phys), pas_mem_setup,
           pas_auth_and_reset, pas_shutdown }
pub trait ScmAlloc / ScmBuffer;  pub struct CoherentAlloc;  // narf_io 32-bit coherent
pub enum ScmError { Io, Invalid, NotSupported, NoMem, Busy, Result(u64),
                    LegacyConvention, TooManyArgs, WaitQueue, Interrupted, Alloc }
```

### 3.4 Firmware (`mdt`)
```rust
pub trait SegmentSource { fn read_into(&self, name: &str, dst: &mut [u8]) -> Option<usize>; }
pub struct Mdt<'a>;  impl Mdt { parse, entry, size, is_split, read_metadata, load, pas_init }
pub fn segment_name(fw_name, n) -> Result<String, MdtError>;
```

### 3.5 Shared memory and signalling (`hwlock`, `smem`, `smp2p`, `ipc`)
```rust
pub trait HwSpinlock { fn lock(&self, ms) -> impl Future<..> + Send; fn unlock(&self) -> Result<..>; }
pub struct TcsrMutex<R, D>;
pub struct Smem<R>;  impl Smem { probe(mem, size), get(host, item), alloc(lock, host, item, size), read_bytes }
pub trait Kick { fn kick(&self); }  pub struct ApcsIpc<R>;  pub struct Ipcc<R>;
pub enum DtKick<R> { Apcs(ApcsIpc<R>), Ipcc(Ipcc<R>) }   // impl Kick: the DT `mboxes` kick, either block
pub struct Smp2p<K>; impl Smp2p { new(smem, lock, cfg, kick), add_outbound, update_bits,
    outbound_value, add_inbound, enable_irq, disable_irq, handle_interrupt -> Vec<Smp2pIrq> }
```

### 3.6 Clocks/resets (`gcc`)
```rust
pub struct GccDesc { compatible, resets: &[ResetEntry], branches: &[BranchEntry] }
pub const IPQ8074, IPQ6018, IPQ5018: GccDesc;  pub fn desc_for(compatibles) -> Option<&GccDesc>;
pub trait ResetLine { fn assert(&self); fn deassert(&self); }
pub struct Gcc<R>; impl Gcc { set_reset, reset_line, enable_branch, disable_branch }
```

### 3.7 Remoteprocs (`q6v5`, `wcss`, `pas`, `rproc`)
```rust
pub struct Q6v5;  impl Q6v5 { prepare, unprepare, signal(Q6Event), wait_for_start, wait_for_stop, crash }
pub trait StopState { fn set_stop(&self, on: bool); }
pub struct Carveout<'a> { phys, mem: &'a mut [u8] }
pub struct Q6Wcss<R> { pub q6: &'static Q6v5, .. }; impl Q6Wcss { new(WcssRegs), load, start(WcssResets, delay, pump), stop(.., &(dyn StopState + Sync), ..) }
pub struct PasRproc { pub q6: &'static Q6v5, .. };  impl PasRproc { new(pas_id), start(scm, alloc, fw, mdt, src, carveout, delay, pump), stop }
pub struct WcssResets<'a> { aon, wcss, q6: &'a (dyn ResetLine + Sync) }
// pump: &mut (dyn FnMut(&Q6v5) + Send); src: &(dyn SegmentSource + Sync)
pub enum RprocState { Offline, Running, Crashed }
pub enum RprocError { .. }
```
`platform::glink_edge(blob, rproc_path) -> Result<GlinkEdgeDt, DtError>`
resolves a remoteproc's `glink-edge` child: `GlinkEdgeDt { path, label,
remote_pid, irq: IrqSpec, kick: KickDt, channels }` (the same `mboxes`
decoding as SMP2P edges: APCS global IPC or IPCC).

### 3.8 GLINK (`glink`)
```rust
pub trait GlinkPipe { rx_avail, rx_peek(buf, offset), rx_advance(n), tx_avail, tx_len,
                      tx_write(hdr, data), kick }        // struct qcom_glink_pipe
pub struct GlinkSmem<M: RegIo, K: Kick>;                 // items 478/479/480
impl GlinkSmem { async register(smem: Smem<M>, lock, remote_pid, kick) -> Result<Self, GlinkError>;
                 smem, remote_pid, descriptor, tx_fifo, rx_fifo }
pub struct Glink<P: GlinkPipe>;                          // struct qcom_glink
impl Glink { new(pipe, features) /* sends VERSION */, accept(name, intents), open(name, intents) -> lcid,
             close(lcid), send(lcid, data), service_tx, process_rx /* edge IRQ */,
             take_event, lcid_of, is_open, remote_intents, negotiated, features, tx_backlog, stats }
pub enum GlinkEvent { Negotiated, Open, RemoteOpen, Data, Closed, SendFailed, Flow }
pub enum GlinkError { Smem, BadDescriptor, NoChannel, NotOpen, TooBig, BadName, NoCid }
pub const GLINK_FEATURE_INTENT_REUSE, GLINK_DEFAULT_INTENTS /* 5 x 1 KiB */, GLINK_CMD_*;
```
`Glink` never blocks: commands go through one ordered queue flushed while
the TX FIFO has room (a full FIFO sends one `READ_NOTIF`); payloads wait
per channel for the smallest free remote intent, sending one
`RX_INTENT_REQ` when none fits (a refusal drops the message as
`SendFailed`). Payloads over 8 KiB go out as `TX_DATA` + `TX_DATA_CONT`.
Received data completes into a local intent and is answered with
`RX_DONE_W_REUSE` (base intents) or `RX_DONE` (one-shot intents granted
to a remote `RX_INTENT_REQ`). Remote-initiated channels follow the rpmsg
probe order: `OPEN_ACK` + `OPEN` once claimed, base intents after the
remote's `OPEN_ACK`. Linux's deferred commands (`VERSION`, `OPEN`,
`CLOSE`, …) are processed inline in FIFO order.

### 3.9 Interrupt delivery (`irq`)
```rust
pub trait IrqLine { fn wait(&self, ms) -> impl Future<Output = bool> + Send; }
pub struct GicSpi;   impl GicSpi { bind(intid, edge) -> Result<Self, IrqBindError>, intid, vector,
                                   install(name, cookie, SyncHandler), set_enabled(on), release(name, cookie) }  // impl IrqLine
pub fn spi_set_enabled(intid, on);   // enable_irq / disable_irq_nosync at the distributor (hard-IRQ safe)
pub enum IrqBindError { OutOfRange(u32), SlotTaken(u8), NotSupported }
pub const fn dt_flags_edge(flags) -> bool;
pub enum Q6Route { Gic { intid, event }, Smp2p { edge, entry, bit, event } }
pub struct Q6Irqs { routes }  impl Q6Irqs { from_platform(&Q6Platform), gic_lines, attach_smp2p(edge, &mut Smp2p),
                                route_smp2p(edge, handles, fired, &Q6v5), bind_gic(&'static Q6v5) }
pub fn q6v5_cookie(&'static Q6v5, Q6Event) -> u64;  pub fn q6v5_gic_handler(cookie) -> IrqStatus;
pub fn smp2p_dispatch(smp2p, smem, edge, handles, routes, q6) -> usize;   // one qcom_smp2p_intr pass
pub async fn service_smp2p(smp2p, smem, line, edge, handles, routes, q6, poll_ms, keep_going);
pub fn ipcc_pending(regs, max) -> Vec<(client, signal)>;  pub fn ipcc_set_enabled(regs, client, signal, on);
```
GIC lines run `q6v5_gic_handler` in hard-IRQ context (atomics only). SMP2P
is threaded: the edge's interrupt only wakes the task running
`service_smp2p`, which calls `Smp2p::handle_interrupt` (SMEM reads,
allocation) and signals each routed rising edge. On x86_64 `GicSpi::bind`
is `NotSupported`.

`pump` is called on every wait iteration; fixtures use it to play the
remote, and the ath11k AHB bring-up runs one `qcom_smp2p_intr` pass per
edge from it (GIC lines still call `Q6v5::signal` from hard IRQ). The
`Send` / `Sync` bounds on `pump`, `src`, `StopState` and `ResetLine` keep
the start / stop futures `Send`, so a spawned task can boot the remote.
`new` leaks the `Q6v5` so `Q6Irqs::bind_gic` can chain its `&'static`.

### 3.10 RPMh votes and AOSS QMP (`cmd_db`, `rpmh`, `aoss`, `wpss`)
```rust
pub struct CmdDb<'a>;  impl CmdDb { parse(data) -> Result<Self, CmdDbError>, read_addr(id) -> Option<u32>,
                                   read_aux_data(id) -> Option<&'a [u8]> }
pub enum CmdDbError { Truncated, BadMagic }
pub struct Rsc<R>;  impl Rsc { probe(regs, tcs_base) -> Self, with_active_tcs(self, tcs) -> Self,
                               write_active(delay, cmds: &[(u32, u32)], wait) -> Result<(), RscError> }
pub enum RscError { Empty, TooManyCmds, Timeout }
pub struct Rpmh<'a, R>;  impl Rpmh { new(db, rsc), vote(delay, id, value),
                                     vote_rail(delay, rail, level), vote_xo(delay, on),
                                     rail_max_corner(rail) -> Result<u32, VoteError> }
pub fn rpmh::arc_max_corner(aux: &[u8]) -> Option<u32>;
pub enum VoteError { UnknownResource, BadRail, BadLevels, Rsc(RscError) }
pub struct Qmp<R, K>;  impl Qmp { open(msgram, kick, delay) -> Result<Self, QmpError>,
                                 close(&self), send(delay, msg), load_state(delay, name, on),
                                 mbox_size(&self) -> u32 }
pub enum QmpError { BadMagic, BadVersion, BadMbox, Timeout, TooLong }
pub struct WpssPower<'a, R1, R2, K>;  impl WpssPower { new(rpmh, qmp: Option<Qmp>, rails),
    start(delay), load_state(delay, on), proxy_enable(delay), proxy_disable(delay) }
pub enum WpssPowerError { Vote(VoteError), Qmp(QmpError) }
```
`CmdDb::read_addr` is `cmd_db_read_addr` (magic `0xdb 0x30 0x03 0x0c`,
8-byte NUL-padded ids, scan stops at the first zero `slv_id`).
`Rsc::write_active` programs the first ACTIVE TCS only (TCS 0 unless
`with_active_tcs` names the DT-derived index; the proxy-vote path is
the sole RSC user; a second user must add TCS allocation first) with
`CMD_MSGID = 8 | WRITE | RESP_REQ`, the slot mask in `CMD_ENABLE`,
and the AMC ENABLE then ENABLE|TRIGGER sequence; completion polls
`IRQ_STATUS` through `Delay` (Linux waits on the TCS IRQ) and the
teardown mirrors `tcs_tx_done`. The register table follows the DRV ID
register (major >= 3 selects the 3.0 table, else 2.7); the TCS region
base is the DT `qcom,tcs-offset`, never guessed. Votes are ACTIVE_ONLY
only — wake/sleep peer aggregation is rpmhpd policy, out of scope.
`rail_max_corner` is the corner `rpmhpd_set_performance_state(INT_MAX)`
selects: `level_count - 1` of the cmd-db aux level map (u16 vlvl per
hlvl; trailing zeros after hlvl 0 end it, a retention entry does not;
more than 32 levels is refused, `rpmhpd_update_level_mapping`).
`xo.lvl` enables with data `0x3` (`clk-rpmh.c` ARC `res_on_val`).
`Qmp::open` runs the `qcom_aoss.c` link/channel handshake over the
msgram descriptor (`MAIL` magic, version 1, MCORE mailbox fields)
with the `Kick` trait as the mailbox doorbell; `send` writes the
64-byte zero-padded message at mbox+4, the length word at mbox, and
waits for AOSS to clear it. `load_state` is the `qcom_q6v5.c` image
message (`{class: image, res: load_state, name: %s, val: %s}`).
`WpssPower` follows `qcom_q6v5_pas.c`: `start` sends load-state `on`
for `wpss` (`qcom_q6v5_prepare`), then `proxy_enable` votes each rail
at `rail_max_corner` and `xo` on (`qcom_pas_pds_enable` +
`clk_prepare_enable`); a vote failure returns the voted rails to corner
0 and sends load-state `off`. `proxy_disable` is `qcom_pas_handover`
(`xo` off, then each rail to 0); `load_state(false)` is
`qcom_q6v5_unprepare`. Without `qcom,qmp` the load-state message is
skipped. The ath11k AHB bring-up drives these around `PasRproc`.

## 4. Invariants
- No busy waits on hardware registers: every poll sleeps via `Delay`.
- SCM: at most four register arguments; `x6` starts 0 and is echoed on an
  `INTERRUPTED` re-issue; `EBUSY` retries ≤ 20 × 30 ms; the PAS metadata
  buffer outlives `auth_and_reset` (released after start completes or
  fails).
- SMP2P outbound item: header fully written before `version = 1`; an
  update kicks only on change.
- SMEM private allocation writes the entry header before advancing
  `offset_free_uncached`, under the TCSR mutex.
- WCSS start on failure re-asserts `wcss_q6_reset` and `wcss_reset` and
  leaves the remoteproc `Offline`; stop from `Running` sets and then
  clears the SMP2P `stop` bit around the stop-ack wait.
- GCC indices outside the per-SoC tables are refused, never guessed.

## 5. Architecture notes
- **aarch64:** the only architecture these SoCs use; `ArchSmc` issues
  `smc #0` through `narf_arch::aarch64::smccc`.
- **x86_64:** builds (fixtures and tests run there too); `ArchSmc`
  reports SMCCC `NOT_SUPPORTED`, so the convention probe yields `Legacy`
  and every SCM call is refused.

## 6. Dependencies
`narf-arch` (MMIO accessors, SMCCC), `narf-memory` (`ioremap`), `narf-io`
(coherent DMA), `narf-time` (sleeping), `narf-firmware-fdt` (FDT walker),
`narf-lib`. Consumer: `narf-drivers-wireless` (ath11k AHB).

## 7. Stage assignment
Stage 5 "Silicon" (ath11k IPQ8074/IPQ6018/IPQ5018/WCN6750 enablement).
Tests: `cargo xtask test --subsystem drivers/soc/qcom --kernel-tests-only`.

## 8. Open questions
- **GLINK**: intentless edges (RPM `qcom,glink-rpm`), the `qcom,intents`
  DT property (callers pass intent groups explicitly) and the glink
  chrdev/`rpmsg_ctrl` are not implemented. The edge interrupt is
  delivered by the caller (`Glink::process_rx` on each SPI).
- **RPMh** proxy votes are ACTIVE_ONLY: `rpmhpd_aggregate_corner` also
  writes the WAKE_ONLY and SLEEP_ONLY sets and aggregates with the
  `*_ao` peer; neither is done here. Nothing has run on SC7280 silicon.
- **IPQ8074 AON reset:** mainline has no `GCC_WCSSAON_RESET` for IPQ8074
  and no WCSS DT node; IPQ8074 boards need a binding decision.
- **IPQ5018 WCSS** has no upstream DT node or Linux match data; the GCC
  table is present, the remoteproc binding is not.
- SCM `WAITQ_SLEEP` (firmware wait queues), the legacy convention and
  >4-argument calls (tzmem) are refused with typed errors.
- Sysmon/SSR notifications, coredump segments and `qcom_pil_info` are
  not implemented.
