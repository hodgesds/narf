use super::*;
use crate::amdgpu_navi48_boot::mst;
use crate::dp_mst_mgr::tests::Hub;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};
const ROOT: Sink = Sink { branch: 0, port: 1 };
const CHILD: Sink = Sink { branch: 1, port: 1 };
const DECODER: [u8; 16] = [
    3, 0x21, 0x0b, 0x0f, 0x7f, 3, 1, 0, 0, 0x1f, 0x0e, 0x88, 0x10, 0, 0, 0,
];
fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn timing(vic: u8) -> Timing {
    crate::amdgpu_dcn_display::timing_from_edid(
        &narf_edid::modes::cea_mode(vic).unwrap().detailed(),
    )
    .unwrap()
}
fn edid(dsc: bool) -> Vec<u8> {
    let mut e = alloc::vec![0;256];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    (e[18], e[19], e[20]) = (1, 4, 0xb5);
    e[54..72].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[126] = 1;
    e[127] = narf_edid::compute_checksum(&e[..128]);
    let c = &mut e[128..];
    c[0] = 2;
    c[1] = 3;
    let vsdb = [3 << 5 | 7, 3, 0x0c, 0, 0x10, 0, 0x30, 120];
    let mut hf = [
        3 << 5 | 13,
        0xd8,
        0x5d,
        0xc4,
        1,
        120,
        0x80,
        0x60,
        0,
        0,
        0,
        0x81,
        0x64,
        19,
    ];
    if !dsc {
        hf[11] = 0;
    }
    let vdb = [2 << 5 | 3, 199, 97, 16];
    let mut at = 4;
    for b in [&vsdb[..], &hf[..], &vdb[..]] {
        c[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    }
    c[2] = at as u8;
    c[127] = narf_edid::compute_checksum(c);
    e
}
fn converter() -> BTreeMap<u32, u8> {
    let mut d: BTreeMap<_, _> = DECODER
        .into_iter()
        .enumerate()
        .map(|(i, b)| (0x60 + i as u32, b))
        .collect();
    d.extend([
        (0, 0x14),
        (5, 0x15),
        (0x80, 3),
        (0x81, 240),
        (0x82, 6 << 2 | 2),
        (0x83, 0),
        (0x305a, 0),
        (0x303c, 0x80),
        (0x303b, 2),
        (0x3036, 0x88),
    ]);
    d
}
fn topology(hub: &mut Hub) -> (Manager, Topology) {
    hub.port_rev = 0x14;
    for key in [(1, 1), (1, 2), (2, 1)] {
        hub.resources.insert(key, (10000, 10000));
    }
    let mut m = Manager::new();
    let mut t = run(m.probe(hub)).unwrap();
    let p = t.branches[0]
        .ports
        .iter_mut()
        .find(|p| p.info.port == 1)
        .unwrap();
    p.info.peer_device_type = dp_mst::PEER_DP_LEGACY_CONV;
    p.info.legacy_plug = true;
    p.info.mcs = false;
    hub.remote.insert((1, 1), converter());
    (m, t)
}
fn endpoint(hub: &mut Hub, m: &mut Manager, t: &Topology, dsc: bool) -> MstDsc {
    run(super::super::read_endpoint(m, hub, t, ROOT, &edid(dsc))).unwrap()
}
fn caps() -> modeset::DpCaps {
    modeset::DpCaps {
        lanes: 4,
        rate: crate::dp_link_training::LinkRate::Hbr3,
        uhbr: 4,
        fec: true,
        dsc: None,
    }
}
fn soc() -> crate::amdgpu_dcn401_dml::Soc {
    crate::amdgpu_dcn401_dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    }
}
fn navi48_mst_pcon_intersects_caps_and_autonomous_state() -> TestResult {
    let mut h = Hub::new();
    let (mut m, t) = topology(&mut h);
    let e = endpoint(&mut h, &mut m, &t, true);
    let p = e.pcon.unwrap();
    assert_eq!((p.state, p.raw_rate, p.dsc_rate), (State::Frl, 3, 3));
    assert!(p.passthrough && e.caps.unwrap().is_frl && e.synaptics.is_none());
    assert!(p.raw_allowed(&timing(16), 8));
    assert!(!p.raw_allowed(&timing(199), 8));
    for (address, value, state) in [
        (0x305a, 8, State::SourceControlled),
        (0x303c, 0x81, State::Training),
        (0x303b, 0, State::Training),
        (0x3036, 8, State::Training),
        (0x3036, 0x80, State::Unavailable),
    ] {
        let saved = h.remote[&(1, 1)][&address];
        h.remote.get_mut(&(1, 1)).unwrap().insert(address, value);
        let current = run(refresh(&mut m, &mut h, &t, p)).unwrap();
        assert_eq!(current.state, state);
        assert!(!current.raw_allowed(&timing(16), 8));
        h.remote.get_mut(&(1, 1)).unwrap().insert(address, saved);
    }
    // Linux deliberately ignores FRL_MODE if a valid bandwidth is present.
    h.remote.get_mut(&(1, 1)).unwrap().insert(0x3036, 0xc0);
    assert_eq!(run(refresh(&mut m, &mut h, &t, p)).unwrap().raw_rate, 6);
    // An autonomous, active TMDS fallback is bounded by converter and EDID.
    h.remote
        .get_mut(&(1, 1))
        .unwrap()
        .extend([(0x3036, 0x80), (0x303b, 3)]);
    let tmds = run(refresh(&mut m, &mut h, &t, p)).unwrap();
    assert_eq!(tmds.state, State::Tmds);
    assert!(tmds.raw_allowed(&timing(16), 8));
    assert!(!tmds.raw_allowed(&timing(199), 8));
    // No HDMI DSC declaration, or no converter passthrough, keeps its DP
    // decompressor and requires raw downstream capacity after decompression.
    h.remote
        .get_mut(&(1, 1))
        .unwrap()
        .extend([(0x3036, 0x88), (0x303b, 2), (0x60, 1)]);
    let local = endpoint(&mut h, &mut m, &t, true);
    assert!(!local.pcon.unwrap().passthrough && !local.caps.unwrap().is_frl);
    let mut integral = local.caps.unwrap();
    integral.bpp_increment_div = 1;
    integral.max_bpp_x16 = 205;
    let local_stream = DscStream {
        sink: ROOT,
        timing: timing(16),
        dsc: Some(integral),
        bpc: 8,
    };
    let link = mst::dsc_link(caps(), 2_000_000).unwrap();
    let (limit, _) = local.pcon.unwrap().profile(&local_stream, &link);
    assert_eq!(limit.dsc_range.unwrap().max_bpp_x16, 192);
    h.remote.get_mut(&(1, 1)).unwrap().insert(0x60, 0);
    let raw = endpoint(&mut h, &mut m, &t, false);
    assert!(raw.caps.is_none() && raw.pcon.is_some());
    assert!(raw.pcon.unwrap().raw_allowed(&timing(16), 8));
    assert!(!super::super::port_supports_mode(
        &timing(199),
        8,
        &t,
        ROOT,
        Some(&raw),
        &mst::dsc_link(caps(), 2_000_000).unwrap()
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_pcon_intersects_caps_and_autonomous_state
);

fn navi48_mst_pcon_fairness_forces_downstream_dsc_and_preserves_dp_source() -> TestResult {
    let mut h = Hub::new();
    let (mut m, t) = topology(&mut h);
    let e = endpoint(&mut h, &mut m, &t, true);
    let link = mst::dsc_link(caps(), 2_000_000).unwrap();
    let s = DscStream {
        sink: ROOT,
        timing: timing(199),
        dsc: e.caps,
        bpc: 8,
    };
    assert!(amdgpu_dsc::stream_kbps(&mst_dsc_timing(&s.timing, 8), link.encoding) < link.kbps);
    let streams = [
        s,
        DscStream {
            sink: CHILD,
            timing: timing(16),
            dsc: None,
            bpc: 8,
        },
    ];
    let endpoint_of = |sink| (sink == ROOT).then_some(e);
    let result = super::super::compute_endpoints(&streams, &link, &|_| true, &endpoint_of).unwrap();
    let cfg = result[0].dsc.unwrap();
    assert_eq!((cfg.slices_h, cfg.bpp_x16, cfg.frl), (8, 159, None));
    assert!(result[1].dsc.is_none());
    assert!(e.pcon.unwrap().allows(&s.timing, 8, Some(&cfg)));
    let fixed = super::super::config_in_payload(&s.timing, 8, &e, &link, result[0].pbn).unwrap();
    assert_eq!(fixed.bpp_x16, 159);
    assert!(fixed.frl.is_none());
    let mut variable = e;
    let hdmi = variable.pcon.as_mut().unwrap();
    hdmi.hdmi.dsc.as_mut().unwrap().all_bpp = true;
    variable.caps = hdmi.hdmi.dsc.as_ref().map(DscSinkCaps::from_hdmi);
    let variable_stream = DscStream {
        dsc: variable.caps,
        ..s
    };
    let (limits, _) = variable.pcon.unwrap().profile(&variable_stream, &link);
    let range = limits.dsc_range.unwrap();
    assert_eq!((range.min_bpp_x16, range.max_bpp_x16), (128, 161));
    let mut low = e;
    low.pcon.as_mut().unwrap().dsc_rate = 2;
    assert!(
        super::super::compute_endpoints(&streams, &link, &|_| true, &|sink| (sink == ROOT)
            .then_some(low))
        .is_none()
    );
    // The real selected AUX owner enables passthrough, with no PCON FRL
    // control/encoder writes; the native source remains its DP pipeline.
    h.remote_writes.clear();
    run(super::super::set_rx(&mut m, &mut h, &t, &e, true, false)).unwrap();
    assert!(run(super::super::rx_enabled(&mut m, &mut h, &t, &e)).unwrap());
    run(super::super::set_rx(&mut m, &mut h, &t, &e, false, false)).unwrap();
    assert_eq!(
        h.remote_writes
            .iter()
            .map(|w| (w.2, w.3.clone()))
            .collect::<Vec<_>>(),
        alloc::vec![(0x160, alloc::vec![2]), (0x160, alloc::vec![0])]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_pcon_fairness_forces_downstream_dsc_and_preserves_dp_source
);

fn navi48_mst_pcon_offered_and_final_configurations_share_limits() -> TestResult {
    let mut h = Hub::new();
    let (mut m, t) = topology(&mut h);
    let e = endpoint(&mut h, &mut m, &t, true);
    let devices = alloc::vec![(ROOT, edid(true), 10000)];
    let endpoint_of = |sink| (sink == ROOT).then_some(e);
    let ctx = mst::MstDscContext {
        topology: &t,
        dsc_of: &endpoint_of,
        max_dispclk_khz: 2_000_000,
        max_bpc: &|_| 8,
    };
    let budget = |_, _: &[(Sink, u16)]| 10000;
    let selected = mst::select_mst_dsc(
        0,
        caps(),
        &devices,
        &|_| Some(timing(199)),
        &budget,
        &ctx,
        &[],
    )
    .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].timing, timing(199));
    assert_eq!(selected[0].dsc.unwrap().bpp_x16, 159);
    assert_eq!(selected[0].mst.unwrap().pcon, e.pcon);
    let offered = mst::dark_mst_modes_with(
        &soc(),
        0,
        caps(),
        &devices[0].1,
        10000,
        &[],
        Some((ROOT, &ctx)),
    );
    assert!(offered.contains(&timing(199)));
    let mut final_config = selected.clone();
    mst::refine_mst_link_payloads(
        &soc(),
        0,
        caps(),
        &devices,
        &ctx,
        &mut final_config,
        &[false],
    )
    .unwrap();
    assert_eq!(final_config[0].dsc, selected[0].dsc);
    assert!(modeset::admit_displays(&soc(), &final_config).is_ok());
    let mut failed = e;
    failed.pcon.as_mut().unwrap().state = State::SourceControlled;
    let failed_of = |sink| (sink == ROOT).then_some(failed);
    let failed_ctx = mst::MstDscContext {
        dsc_of: &failed_of,
        ..ctx
    };
    assert!(
        mst::select_mst_dsc(0, caps(), &devices, &|_| None, &budget, &failed_ctx, &[])
            .unwrap()
            .is_empty()
    );
    assert!(mst::dark_mst_modes_with(
        &soc(),
        0,
        caps(),
        &devices[0].1,
        10000,
        &[],
        Some((ROOT, &failed_ctx))
    )
    .is_empty());
    assert!(mst::refine_mst_link_payloads(
        &soc(),
        0,
        caps(),
        &devices,
        &failed_ctx,
        &mut final_config,
        &[true]
    )
    .is_err());
    assert_eq!(final_config[0].dsc, selected[0].dsc);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_pcon_offered_and_final_configurations_share_limits
);

fn navi48_mst_pcon_live_loss_and_cancelled_query_retain_owners() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    let mut h = Hub::new();
    let (mut m, t) = topology(&mut h);
    let e = endpoint(&mut h, &mut m, &t, true);
    let device_edid = edid(true);
    h.edid.copy_from_slice(&device_edid);
    let mut link = MstLink {
        manager: m,
        topology: t,
        ..MstLink::default()
    };
    // Obtain real native selections, then retain both payloads unchanged.
    let endpoint_of = |sink| (sink == ROOT).then_some(e);
    let ctx = mst::MstDscContext {
        topology: &link.topology,
        dsc_of: &endpoint_of,
        max_dispclk_khz: 2_000_000,
        max_bpc: &|_| 8,
    };
    let devices = alloc::vec![
        (ROOT, device_edid.clone(), 10000),
        (CHILD, device_edid.clone(), 10000)
    ];
    let running = mst::select_mst_dsc(
        0,
        caps(),
        &devices,
        &|k| Some(timing(if k == 0 { 199 } else { 16 })),
        &|_, _| 10000,
        &ctx,
        &[],
    )
    .unwrap();
    assert_eq!(running.len(), 2);
    link.payloads = running
        .iter()
        .enumerate()
        .map(|(k, s)| {
            let stream = s.mst.unwrap();
            mst::MstPayload {
                sink: stream.sink,
                vcpi: k as u8 + 1,
                start: 1,
                slots: stream.slots,
                pbn: stream.pbn,
                stream: k as u8 + 1,
                allocation: mst::PayloadAllocation::Remote,
            }
        })
        .collect();
    let branch = &link.topology.branches[0];
    link.outputs[0] = Some(mst::MstOutput {
        id: mst::MstOutputId {
            root: branch.guid,
            branch: branch.guid,
            lct: branch.lct,
            rad: branch.rad,
            port: 1,
        },
        sink: Some(ROOT),
        edid: device_edid,
        modes: Vec::new(),
        dsc: Some(e),
    });
    let payloads = link.payloads.clone();
    let kept = running[1];
    h.remote.get_mut(&(1, 1)).unwrap().insert(0x305a, 8);
    let (changed, lost) = run(link.refresh_pcon_outputs(&mut h, &running)).unwrap();
    assert!(changed);
    assert_eq!(lost, alloc::vec![1]);
    assert_eq!(link.payloads, payloads);
    assert_eq!(running[1], kept);
    assert!(link.require_transaction_idle::<()>().is_ok());
    // Cancellation after the actual remote request, before its sideband
    // reply: no successor may reuse/release this retained AUX session.
    struct Cancel(Hub);
    impl MstAux for Cancel {
        type Error = ();
        async fn read(&mut self, a: u32, b: &mut [u8]) -> Result<(), ()> {
            if a == dp_mst::DOWN_REP_BASE {
                core::future::pending::<()>().await;
            }
            self.0.read(a, b).await
        }
        async fn write(&mut self, a: u32, b: &[u8]) -> Result<(), ()> {
            self.0.write(a, b).await
        }
        async fn delay(&mut self, _: u64) {}
    }
    let mut cancel = Cancel(h);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut query = alloc::boxed::Box::pin(mst::query_pcon(
            &mut link,
            &mut cancel,
            ROOT,
            e.pcon.unwrap(),
        ));
        assert!(query.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(link.endpoint_query, Some(ROOT));
    assert!(link.has_stream_resources());
    assert!(link.require_transaction_idle::<()>().is_err());
    assert_eq!(link.payloads, payloads);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_pcon_live_loss_and_cancelled_query_retain_owners
);

fn navi48_mst_pcon_failed_capability_reads_never_erase_limits() -> TestResult {
    struct Direct {
        dpcd: BTreeMap<u32, u8>,
        fault: Option<(u32, bool)>,
    }
    impl MstAux for Direct {
        type Error = ();
        async fn read(&mut self, at: u32, bytes: &mut [u8]) -> Result<(), ()> {
            if self.fault == Some((at, false)) {
                return Err(());
            }
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = self.dpcd.get(&(at + i as u32)).copied().unwrap_or(0);
            }
            Ok(())
        }
        async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        async fn delay(&mut self, _: u64) {}
    }
    let mut h = Hub::new();
    let (mut manager, tree) = topology(&mut h);
    let link = mst::dsc_link(caps(), 2_000_000).unwrap();
    // Exact base identity: PRESENT | TMDS(2<<1) | DETAILED. Failed first
    // or detailed reads propagate uncertainty, never Option::None.
    for address in [5, 0x80] {
        let mut a = Direct {
            dpcd: converter(),
            fault: Some((address, false)),
        };
        assert_eq!(
            run(probe(
                &mut manager,
                &mut a,
                &tree,
                DscAux::Root,
                &edid(true),
                3
            )),
            Err(MstError::Aux(()))
        );
    }
    for (base, detail) in [(5, 3), (0x15, 0), (0x15, 2), (0x17, 3)] {
        let mut a = Direct {
            dpcd: converter(),
            fault: None,
        };
        a.dpcd.extend([(5, base), (0x80, detail)]);
        let p = run(probe(
            &mut manager,
            &mut a,
            &tree,
            DscAux::Root,
            &edid(true),
            3,
        ))
        .unwrap()
        .unwrap();
        let stream = DscStream {
            sink: ROOT,
            timing: timing(16),
            dsc: Some(DscSinkCaps::from_hdmi(&p.hdmi.dsc.unwrap())),
            bpc: 8,
        };
        let (constraints, cfg) = p.profile(&stream, &link);
        assert_eq!(p.state, State::Unavailable);
        assert!(!p.raw_allowed(&stream.timing, 8));
        assert!(!constraints.raw_allowed && constraints.dsc_range.is_none() && cfg.is_none());
    }
    struct RemoteNak {
        hub: Hub,
        at: u32,
        reply: Vec<u8>,
        active: bool,
    }
    impl MstAux for RemoteNak {
        type Error = ();
        async fn read(&mut self, at: u32, bytes: &mut [u8]) -> Result<(), ()> {
            if self.active && (dp_mst::DOWN_REP_BASE..dp_mst::DOWN_REP_BASE + 48).contains(&at) {
                let from = (at - dp_mst::DOWN_REP_BASE) as usize;
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = self.reply.get(from + i).copied().unwrap_or(0);
                }
                Ok(())
            } else {
                self.hub.read(at, bytes).await
            }
        }
        async fn write(&mut self, at: u32, bytes: &[u8]) -> Result<(), ()> {
            self.hub.write(at, bytes).await?;
            if at == 0x2003 {
                self.active = false;
            }
            if at == dp_mst::DOWN_REQ_BASE {
                if let Some(body) = self
                    .hub
                    .bodies
                    .last()
                    .filter(|b| b[0] == dp_mst::REMOTE_DPCD_READ)
                {
                    let address = u32::from(body[1] & 15) << 16
                        | u32::from(body[2]) << 8
                        | u32::from(body[3]);
                    self.active = address == self.at;
                }
            }
            Ok(())
        }
        async fn delay(&mut self, _: u64) {}
    }
    for address in [5, 0x80] {
        let mut hub = Hub::new();
        let (mut manager, tree) = topology(&mut hub);
        let mut nak = alloc::vec![dp_mst::REMOTE_DPCD_READ | 0x80];
        nak.extend_from_slice(&[0; 16]);
        nak.extend_from_slice(&[1, 0]);
        let mut aux = RemoteNak {
            hub,
            at: address,
            reply: dp_mst::chunks(1, &[0; 8], false, &nak).remove(0),
            active: false,
        };
        let e = run(super::super::read_endpoint_checked(
            &mut manager,
            &mut aux,
            &tree,
            ROOT,
            &edid(true),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(e.pcon.unwrap().state, State::Unavailable);
        assert!(!super::super::port_supports_mode(
            &timing(16),
            8,
            &tree,
            ROOT,
            Some(&e),
            &link
        ));
    }
    // A truncated/malformed actual REMOTE_DPCD_READ reply is propagated by
    // checked endpoint discovery; it cannot reuse otherwise-valid DSC caps.
    h.remote.remove(&(1, 1));
    assert!(matches!(
        run(super::super::read_endpoint_checked(
            &mut manager,
            &mut h,
            &tree,
            ROOT,
            &edid(true)
        )),
        Err(MstError::Malformed)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_pcon_failed_capability_reads_never_erase_limits
);
