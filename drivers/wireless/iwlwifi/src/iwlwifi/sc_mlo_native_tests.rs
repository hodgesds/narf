//! Actual native FWlink0/STA0 projections surrounding an MLO-capable peer.
use super::super::super::bz_fixture;
use super::*;
use narf_wireless::association::mlo::{BasicMultiLink, Context as MldContext, Local};
const AP_MLD: [u8; 6] = [2, 0x93, 2, 3, 4, 5];
const PASSWORD: &[u8] = b"native-single-link-MLD-SAE24-PMF";
#[derive(Default)]
pub(super) struct TxState {
    key: Option<[u8; 16]>,
    pn: u64,
}
#[derive(Clone, Copy)]
pub(super) struct Model {
    pub context: MldContext,
    pub bad_response: bool,
}
impl Model {
    fn packet_key(commands: &[(u8, u8, Vec<u8>)]) -> R<[u8; 16]> {
        let (_, _, body) = commands
            .iter()
            .rev()
            .find(|(g, c, b)| {
                (*g, *c) == (5, 0x18) && b.len() == 80 && word(b, 8) == 0 && word(b, 12) & 0x48 == 0
            })
            .ok_or("native MLD actual pairwise key owner absent")?;
        require(
            word(body, 0) == 1 && word(body, 4) == 1,
            "native MLD packet key was removed or belongs to another station",
        )?;
        Ok(body[16..32].try_into().unwrap())
    }
    fn new(link: u8) -> R<Self> {
        let mut body = vec![0x10, 0, 8];
        body.extend_from_slice(&AP_MLD);
        body.push(link);
        let peer = BasicMultiLink::parse(&body).map_err(|_| "native MLD authored BasicML")?;
        let context = Local::single_link(OWN)
            .and_then(|own| own.context(OWN, AP, &peer))
            .map_err(|_| "native MLD authored distinct context")?;
        Ok(Self {
            context,
            bad_response: false,
        })
    }
    pub fn observed(self, commands: &[(u8, u8, Vec<u8>)]) -> R {
        let mac = commands
            .iter()
            .enumerate()
            .find(|(_, (g, c, b))| {
                (*g, *c) == (3, 8)
                    && b.len() == 52
                    && b[12..18] == self.context.own_mld()
                    && b[24] == 1
                    && b[26] == 1
            })
            .map(|(i, _)| i)
            .ok_or("native MLD translation lacks actual MAC HE/EHT receipt")?;
        // The associated MAC is the last (3,8) carrying an association id
        // (byte 36): only the post-response MAC is built with
        // `station_api::mac(2, local, Some(response.aid))`. The
        // pre-association MAC (connection.rs:692) and the disconnect MAC
        // (connection.rs:3770) carry aid None, so bytes 36..40 of those are
        // template zeros and must never be read as the associated MAC's esr
        // fields. Until an associated MAC exists, association has not
        // completed and none of the post-association invariants below apply.
        let associated = commands
            .iter()
            .rev()
            .find(|(g, c, b)| (*g, *c) == (3, 8) && b.len() == 52 && b[36] == 1)
            .map(|(_, _, b)| b);
        let Some(associated) = associated else {
            return Ok(());
        };
        require(
            associated[12..18] == self.context.own_mld()
                && associated[24] == 1
                && associated[26] == 1,
            "native MLD translation outlived current MAC EHT setup",
        )?;
        // mld/iface.c iwl_mld_mac_cmd_fill_sta: the FakeAp response Basic
        // MLE (control 0x0110: link id + MLD capabilities) has neither EML
        // capabilities nor a medium sync delay, so the associated MAC
        // carries esr_transition_timeout 0 and the 0x10ac default delay.
        require(
            associated[37] == 0 && associated[38..40] == [0xac, 0x10],
            "native MLD associated MAC lacks the default esr fields",
        )?;
        let link = commands
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (g, c, b))| {
                (*g, *c) == (3, 9)
                    && b.len() == 208
                    && word(b, 0) == 1
                    && word(b, 4) == 0
                    && b[16..22] == OWN
                    && b[166] == self.context.link_id()
            })
            .map(|(i, _)| i)
            .ok_or("native MLD translation lacks ADD-time FW/spec link mapping")?;
        let sta = commands
            .iter()
            .enumerate()
            .find(|(_, (g, c, b))| {
                (*g, *c) == (3, 10)
                    && b.len() == 104
                    && word(b, 0) == 0
                    && word(b, 4) == 0
                    && b[8..14] == AP_MLD
                    && b[16..22] == AP
            })
            .map(|(i, _)| i)
            .ok_or("native MLD translation lacks distinct actual AP STA addresses")?;
        require(
            commands
                .iter()
                .enumerate()
                .rev()
                .find(|(_, (g, c, _))| (*g, *c) == (3, 0xc))
                .is_none_or(|(removed, _)| removed < sta),
            "native MLD translation outlived AP STA removal",
        )?;
        require(
            mac < sta && link < sta,
            "native MLD AP STA preceded actual MAC/LINK translation setup",
        )
    }
    pub fn transmit(self, commands: &[(u8, u8, Vec<u8>)], frame: &mut [u8]) -> R {
        self.observed(commands)?;
        require(frame.len() >= 24, "native MLD TX header extent")?;
        if frame[0] & 12 == 0 {
            require(
                frame[4..10] == AP && frame[10..16] == OWN && frame[16..22] == AP,
                "native MLD explicit-link management was not physically projected",
            )?;
            frame[4..10].copy_from_slice(&AP_MLD);
            frame[16..22].copy_from_slice(&AP_MLD);
        } else {
            require(
                frame[0] & 12 == 8 && frame[4..10] == AP_MLD && frame[10..16] == OWN,
                "native MLD data did not use exact firmware-facing logical identity",
            )?;
            frame[4..10].copy_from_slice(&AP);
            if frame[0] & 0x80 != 0 && frame.get(24).is_some_and(|qos| qos & 0x80 != 0) {
                require(
                    frame[16..22] == AP_MLD,
                    "native MLD A-MSDU outer BSSID was not logical before encryption",
                )?;
                frame[16..22].copy_from_slice(&AP);
            }
        }
        Ok(())
    }
    pub fn radio_transmit(
        self,
        commands: &[(u8, u8, Vec<u8>)],
        frame: &[u8],
        state: &mut TxState,
    ) -> R<Vec<u8>> {
        if frame[0] & 12 != 8 || frame[1] & 0x40 == 0 {
            return Ok(frame.to_vec());
        }
        require(
            frame[4..10] == AP && frame[10..16] == OWN,
            "native MLD radio TX lost physical tuple",
        )?;
        let key = Self::packet_key(commands)?;
        if state.key != Some(key) {
            state.key = Some(key);
            state.pn = 0;
        }
        state.pn += 1;
        require(
            state.pn < 1 << 48,
            "native MLD fixture packet number exhausted",
        )?;
        let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
        let mut logical = frame[..header].to_vec();
        logical[4..10].copy_from_slice(&AP_MLD);
        logical[10..16].copy_from_slice(&self.context.own_mld());
        if header == 26 && frame[24] & 0x80 != 0 {
            logical[16..22].copy_from_slice(&AP_MLD);
        }
        let tid = if header == 26 { frame[24] & 15 } else { 0 };
        let nonce = narf_wireless::ccmp::build_nonce(tid, false, &self.context.own_mld(), state.pn);
        let mut body = frame[header..].to_vec();
        let tag = narf_crypto::aes_ccm::seal(
            &key,
            &nonce,
            &narf_wireless::ccmp::build_aad(&logical),
            &mut body,
        )
        .map_err(|_| "native MLD logical unicast TX CCMP seal")?;
        let mut radio = frame[..header].to_vec();
        radio.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(state.pn, 0));
        radio.extend_from_slice(&body);
        radio.extend_from_slice(&tag);
        Ok(radio)
    }
    pub fn receive(
        self,
        commands: &[(u8, u8, Vec<u8>)],
        frame: &[u8],
        decrypted: bool,
    ) -> R<Vec<u8>> {
        require(frame.len() >= 24, "native MLD AP frame extent")?;
        let mut frame = frame.to_vec();
        if matches!(frame[0], 0x80 | 0x50) {
            require(
                frame[10..16] == AP && frame[16..22] == AP,
                "native MLD beacon lost physical identity",
            )?;
            return Ok(frame);
        }
        self.observed(commands)?;
        if frame[0] & 12 == 0 {
            if frame[4] & 1 != 0 {
                require(
                    frame[10..16] == AP && frame[16..22] == AP,
                    "native MLD group management changed physical AAD",
                )?;
                return Ok(frame);
            }
            require(
                frame[4..10] == OWN && frame[10..16] == AP_MLD && frame[16..22] == AP_MLD,
                "native MLD AP management interface changed logical peer",
            )?;
            frame[10..16].copy_from_slice(&AP);
            frame[16..22].copy_from_slice(&AP);
            if self.bad_response && matches!(frame[0], 0x10 | 0x30) {
                // Corrupt only the unauthenticated response MLE's peer MAC.
                let mut at = 30;
                while at + 2 <= frame.len() {
                    let end = at + 2 + usize::from(frame[at + 1]);
                    if end > frame.len() {
                        return Err("native MLD response authored IE extent");
                    }
                    if frame[at] == 255 && frame.get(at + 2) == Some(&107) {
                        require(
                            end >= at + 12,
                            "native MLD response authored Basic common extent",
                        )?;
                        frame[at + 11] ^= 2;
                    }
                    at = end;
                }
            }
        } else if frame[0] & 12 == 8 {
            let group = frame[4] & 1 != 0;
            require(
                (group || frame[4..10] == OWN) && frame[10..16] == AP,
                "native MLD radio DATA lost original physical owner",
            )?;
            if frame[1] & 0x40 != 0 {
                let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
                let iv = frame
                    .get(header..header + 8)
                    .and_then(|iv| iv.try_into().ok())
                    .ok_or("native MLD physical CCMP IV extent")?;
                let (pn, id) = narf_wireless::ccmp::decode_ccmp_header(iv)
                    .map_err(|_| "native MLD physical CCMP IV invalid")?;
                let key = if group {
                    let (_, _, body) = commands
                        .iter()
                        .rev()
                        .find(|(g, c, b)| {
                            (*g, *c) == (5, 0x18)
                                && b.len() == 80
                                && word(b, 8) == u32::from(id)
                                && word(b, 12) == 0x4a
                        })
                        .ok_or("native MLD group DATA has no actual selected-link GTK owner")?;
                    require(
                        word(body, 0) == 1 && word(body, 4) == 1,
                        "native MLD group DATA GTK was retired",
                    )?;
                    body[16..32].try_into().unwrap()
                } else {
                    require(id == 0, "native MLD unicast radio frame used group key")?;
                    Self::packet_key(commands)?
                };
                let tid = if header == 26 { frame[24] & 15 } else { 0 };
                let mut logical = frame[..header].to_vec();
                if !group {
                    logical[4..10].copy_from_slice(&self.context.own_mld());
                    logical[10..16].copy_from_slice(&AP_MLD);
                }
                let nonce = narf_wireless::ccmp::build_nonce(
                    tid,
                    false,
                    if group { &AP } else { &AP_MLD },
                    pn,
                );
                let aad = narf_wireless::ccmp::build_aad(&logical);
                let physical_nonce = narf_wireless::ccmp::build_nonce(tid, false, &AP, pn);
                let physical_aad = narf_wireless::ccmp::build_aad(&frame[..header]);
                let (mut cipher, tag) = if decrypted {
                    let mut cipher = frame
                        .get(header + 8..)
                        .ok_or("native MLD decrypted body extent")?
                        .to_vec();
                    let tag = narf_crypto::aes_ccm::seal(&key, &nonce, &aad, &mut cipher)
                        .map_err(|_| "native MLD logical DATA CCMP seal")?;
                    (cipher, tag)
                } else {
                    let end = frame
                        .len()
                        .checked_sub(8)
                        .ok_or("native MLD radio MIC extent")?;
                    let cipher = frame
                        .get(header + 8..end)
                        .ok_or("native MLD radio cipher extent")?
                        .to_vec();
                    let tag = frame[end..]
                        .try_into()
                        .map_err(|_| "native MLD radio MIC size")?;
                    (cipher, tag)
                };
                if !group {
                    require(
                        narf_crypto::aes_ccm::open(
                            &key,
                            &physical_nonce,
                            &physical_aad,
                            &mut cipher.clone(),
                            &tag,
                        )
                        .is_err(),
                        "native MLD physical address incorrectly authenticated unicast DATA",
                    )?;
                }
                narf_crypto::aes_ccm::open(&key, &nonce, &aad, &mut cipher, &tag)
                    .map_err(|_| "native MLD logical DATA CCMP authentication")?;
                frame.truncate(header + 8);
                frame.extend_from_slice(&cipher);
            }
            // The exact physical/FW-link owner precedes logical DATA crypto;
            // only after that validated offload result is the RFH header logical.
            // KDEs, IV/PN, LLC and EAPOL MIC bytes are never rewritten.
            if !group {
                frame[10..16].copy_from_slice(&AP_MLD);
            }
        }
        Ok(frame)
    }
}

fn policy(six: bool) -> narf_wireless::reg::RegulatoryDomain {
    if six {
        wide_six_tests::policy()
    } else {
        he_tests::policy()
    }
}
#[inline(never)]
fn setup(model: Model, bz: Option<bz_fixture::Case>, six: bool, fault: Fault) -> R<Box<Guard>> {
    let guard = Guard::build_native_eht(
        true,
        fault,
        None,
        None,
        Some(PhyModel {
            width: if six { 0 } else { 2 },
            streams: 2,
            rates: 3,
            mcc_he: true,
            response_he: true,
        }),
        NativeModel {
            receive_model: ReceiveModel::NativeSc,
            tx_model: None,
            api89: None,
            bz,
            six: six.then_some(SixModel {
                channel: 5,
                regulatory: 0,
                nvm_flags: 0x6001,
                mcc_flags: 0x600d,
                api59: true,
                tpe: 20,
                alias: false,
            }),
        },
        Some(eht_tests::Model::wide_source(
            bz.is_some_and(|b| b.wh()),
            false,
            0x0050,
        )),
    )?;
    guard.policy_db.install(policy(six));
    let ap = FakeAp::wpa3_sae(
        NETWORK,
        SSID,
        if six { 5 } else { 36 },
        7,
        PASSWORD,
        narf_wifi_fixtures::ApSaePwe::HashToElement,
        ANONCE,
    )
    .and_then(|ap| ap.with_akms(&[24]))
    .and_then(|ap| ap.with_igtk([0x6b; 16], 5, 0x0102_0304_0506))
    .and_then(|ap| ap.with_single_link_mld(model.context))
    .map_err(|_| "native MLD actual SAE24/PMF/MLO peer")?;
    {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        wire.ap = ap;
        wire.mld = Some(model);
        wire.igtk_expected = Some(([0x6b; 16], 5, 0x0102_0304_0506));
    }
    Ok(Box::new(guard))
}
fn request_mld(six: bool) -> AssociateRequest {
    let mut req = request(true);
    req.channel = if six { 5 } else { 36 };
    req.frequency_mhz = if six { 5975 } else { 5180 };
    req.security = narf_wireless::SecurityConfig::Wpa3 {
        password: PASSWORD.to_vec(),
    };
    req
}
fn discover(guard: &Guard, six: bool) -> R {
    let mut scan = scan_request();
    scan.channels = vec![if six { 5 } else { 36 }];
    scan.frequencies_mhz = vec![if six { 5975 } else { 5180 }];
    require(
        run(guard.device().scan(scan), service)?
            .map_err(|_| "native MLD physical-band scan")?
            .len()
            == 1,
        "native MLD physical candidate count",
    )
}
fn join(guard: &Guard, six: bool) -> R {
    discover(guard, six)?;
    run(
        guard
            .device()
            .associate_in_domain(request_mld(six), &policy(six)),
        service,
    )?
    .map_err(|_| "native MLD actual station association")?;
    carrier(guard.device(), true)
}
fn close(guard: &Guard) -> R {
    run(guard.device().disassociate(), service)?.map_err(|_| "native MLD terminal teardown")?;
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        wire.commands
            .iter()
            .rev()
            .find(|(g, c, _)| (*g, *c) == (3, 9))
            .is_some_and(|(_, _, b)| {
                word(b, 0) == 1 && word(b, 4) == 0 && word(b, 12) == u32::MAX && b[166] == 0
            }),
        "native MLD terminal teardown did not restore ordinary inactive default link",
    )?;
    Ok(())
}
fn smoke_iwl_mld_native_sc_bz_sae24_pmf_dhcp_and_literal_single_link_ownership() -> TestResult {
    check(|| {
        for (bz, six, spec) in [
            (None, false, 3),
            (None, true, 14),
            (Some(bz_fixture::Case::FmDiscrete), false, 14),
            (Some(bz_fixture::Case::WhIntegrated), true, 3),
        ] {
            let model = Model::new(spec)?;
            let guard = setup(model, bz, six, Fault::None)?;
            join(&guard, six)?;
            {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                model.observed(&wire.commands)?;
                require(
                    wire.ap.single_link_mld() == Some(&model.context) && wire.keys == 3 && wire.m4,
                    "native MLD did not complete actual logical peer/key conversation",
                )?;
            }
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "native MLD encrypted DHCP")?;
            require(
                NETWORK.matches_lease(&lease),
                "native MLD physical/FW-owned DHCP lease",
            )?;
            // Bare deferred bytes cannot reuse the already-consumed capture
            // proof, even when the actual M3 MIC/replay would hit its cache.
            let (bare, before) = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                let raw = wire
                    .mld_m3
                    .as_ref()
                    .ok_or("native MLD captured initial M3 absent")?;
                let mut eth = OWN.to_vec();
                eth.extend_from_slice(&AP_MLD);
                eth.extend_from_slice(&[0x88, 0x8e]);
                eth.extend_from_slice(
                    raw.get(32..)
                        .ok_or("native MLD captured initial EAPOL extent")?,
                );
                (eth, wire.air.len())
            };
            {
                let mut state = guard
                    .device()
                    .state
                    .try_lock()
                    .ok_or("native MLD deferred proof owner")?;
                let State {
                    hardware,
                    connection,
                    ..
                } = &mut *state;
                run(
                    connection
                        .as_mut()
                        .ok_or("native MLD live connection absent")?
                        .handle_eapol(hardware, &bare),
                    service,
                )??;
            }
            let unchanged = HARNESS.lock().as_ref().unwrap().1.air.len() == before;
            require(
                unchanged,
                "native MLD bare deferred bytes bypassed actual captured-link proof",
            )?;
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_native_sc_bz_sae24_pmf_dhcp_and_literal_single_link_ownership
);

fn payload(frame: &[u8], fw_link: u8, station: u8, band: u8, pn: u64) -> Vec<u8> {
    let mut mpdu = vec![0; 64];
    mpdu[7] = fw_link | (band << 6);
    mpdu[40..43].copy_from_slice(&[40, 50, 36]);
    let mut body = vec![8, 0x42, 0, 0];
    body.extend_from_slice(&OWN);
    body.extend_from_slice(&AP_MLD);
    body.extend_from_slice(&frame[6..12]);
    body.extend_from_slice(&((pn as u16) << 4).to_le_bytes());
    body.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    body.extend_from_slice(&frame[12..]);
    mpdu[..2].copy_from_slice(&(body.len() as u16).to_le_bytes());
    mpdu[12..16].copy_from_slice(&(0x247u32 | (u32::from(station) << 24)).to_le_bytes());
    mpdu[36..40].copy_from_slice(&0x500u32.to_le_bytes());
    mpdu.extend_from_slice(&body);
    mpdu
}
fn inject(frame: &[u8], fw_link: u8, station: u8, band: u8, pn: u64) {
    let mpdu = payload(frame, fw_link, station, band, pn);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &mpdu);
}
fn smoke_iwl_mld_original_fwlink_station_band_and_same_pn_remain_physical_owner_bound() -> TestResult
{
    check(|| {
        let guard = setup(Model::new(14)?, None, false, Fault::None)?;
        join(&guard, false)?;
        for (i, (link, station, band)) in [(1, 0, 0), (0, 1, 0), (0, 0, 1)].into_iter().enumerate()
        {
            let frame = udp_ipv4(
                OWN,
                AP,
                NETWORK.server_ip,
                NETWORK.lease_ip,
                7,
                49152,
                &[b'M', i as u8],
            );
            let pn = 200 + i as u64;
            inject(&frame, link, station, band, pn);
            flush()?;
            require(
                !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                "native MLD unowned original RFH acquired PN/delivery",
            )?;
            inject(&frame, 0, 0, 0, pn);
            flush()?;
            inject(&frame, 0, 0, 0, pn);
            flush()?;
            require(
                HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .received
                    .iter()
                    .filter(|seen| **seen == frame)
                    .count()
                    == 1,
                "native MLD original RFH refusal consumed valid same-PN owner or replay escaped",
            )?;
        }
        let frame = udp_ipv4(
            OWN,
            AP,
            NETWORK.server_ip,
            NETWORK.lease_ip,
            7,
            49152,
            b"MLD-stale-copy",
        );
        {
            let mut state = guard
                .device()
                .state
                .try_lock()
                .ok_or("native MLD stale capture owner")?;
            let epoch = state
                .hardware
                .receive_capture_epoch()
                .ok_or("native MLD current capture epoch absent")?;
            let payload = payload(&frame, 0, 0, 0, 250);
            let packet = super::super::super::runtime::Packet {
                header: super::super::super::rx::RxPacketHeader {
                    len_n_flags: (4 + payload.len()) as u32,
                    cmd: 0xc1,
                    group_id: 0,
                    sequence: 0x8000,
                },
                payload,
                receive_epoch: Some(epoch.wrapping_sub(1)),
                receive_queue: 0,
            };
            require(
                state
                    .connection
                    .as_mut()
                    .ok_or("native MLD stale capture connection absent")?
                    .receive_packet(&packet)?
                    .is_empty(),
                "native MLD stale physical capture acquired a later epoch",
            )?;
        }
        inject(&frame, 0, 0, 0, 250);
        flush()?;
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .received
                .iter()
                .filter(|seen| **seen == frame)
                .count()
                == 1,
            "native MLD stale-copy rejection consumed current same-PN owner",
        )?;
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_original_fwlink_station_band_and_same_pn_remain_physical_owner_bound
);

fn smoke_iwl_mld_response_context_and_queued_bound_ml_change_stop_native_data() -> TestResult {
    check(|| {
        {
            let model = Model {
                bad_response: true,
                ..Model::new(3)?
            };
            let guard = setup(model, None, false, Fault::None)?;
            discover(&guard, false)?;
            require(
                run(
                    guard
                        .device()
                        .associate_in_domain(request_mld(false), &policy(false)),
                    service,
                )?
                .is_err(),
                "native MLD changed response identity reached keys/port",
            )?;
            let no_keys = HARNESS.lock().as_ref().unwrap().1.keys == 0;
            require(
                no_keys,
                "native MLD response refusal installed a native key",
            )?;
        }
        let guard = setup(Model::new(3)?, None, false, Fault::None)?;
        join(&guard, false)?;
        let packet = tx_amsdu_tests::packet(0xd7, 100, false);
        let owner = guard
            .device()
            .state
            .try_lock()
            .ok_or("native MLD queued data owner")?;
        narf_net::iface::send_on(guard.device().name(), &packet)
            .map_err(|_| "native MLD queued IPC frame")?;
        drop(owner);
        let before = {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            wire.firmware
                .inject_packed(&vec![(0xab, 5, 0x8000, &[][..]); 64]);
            let mut beacon = wire.ap.beacon();
            let at = beacon
                .windows(6)
                .position(|mac| mac == AP_MLD)
                .ok_or("native MLD bound BasicML absent")?;
            beacon[at + 5] ^= 2;
            wire.mpdu(&beacon, false);
            wire.data.len()
        };
        drain();
        let owner = guard
            .device()
            .state
            .try_lock()
            .ok_or("native MLD final publication owner")?;
        require(
            owner.hardware.is_failed() && owner.needs_reset,
            "native MLD queued context loss did not close native TX",
        )?;
        drop(owner);
        let stopped = HARNESS.lock().as_ref().unwrap().1.data.len() == before;
        require(
            stopped,
            "native MLD queued context loss escaped receive-budget publication fence",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_response_context_and_queued_bound_ml_change_stop_native_data
);

fn smoke_iwl_mld_real_group_pairwise_rekey_and_dropped_igtk_owner_keep_native_keys_scoped(
) -> TestResult {
    check(|| {
        {
            let guard = setup(Model::new(3)?, None, false, Fault::None)?;
            join(&guard, false)?;
            let keys = narf_wifi_fixtures::MldGroupKeys {
                gtk: [0x88; 16],
                gtk_id: 2,
                gtk_pn: 9,
                igtk: [0x91; 16],
                igtk_id: 4,
                igtk_ipn: 11,
            };
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                wire.gtk_expected = Some((2, keys.gtk));
                wire.igtk_expected = Some((keys.igtk, 4, 11));
                let frame = wire
                    .ap
                    .start_mld_group_rekey(keys)
                    .map_err(|_| "native MLD actual group challenge")?;
                wire.mpdu(&frame, false);
            }
            let deadline = narf_time::Deadline::after_ms(3000);
            loop {
                flush()?;
                let done = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.keys == 5 && wire.ap.retransmit_mld().is_err()
                };
                if done
                    && guard
                        .device()
                        .state
                        .try_lock()
                        .is_some_and(|state| !state.needs_reset)
                {
                    break;
                }
                if deadline.expired() {
                    return Err("native MLD group key native receipt bound");
                }
            }
            let multicast = udp_ipv4(
                [0xff; 6],
                AP,
                NETWORK.server_ip,
                [255; 4],
                7,
                49152,
                b"MLD-group-PN",
            );
            let group_frame = {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let frame = wire
                    .ap
                    .transmit_mld_data(&multicast)
                    .map_err(|_| "native MLD actual group DATA producer")?;
                wire.mpdu(&frame, false);
                frame
            };
            flush()?;
            HARNESS.lock().as_mut().unwrap().1.mpdu(&group_frame, false);
            flush()?;
            require(
                HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .received
                    .iter()
                    .filter(|f| **f == multicast)
                    .count()
                    == 1,
                "native MLD physical group DATA crypto/GTK PN floor or replay changed",
            )?;
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let frame = wire
                    .ap
                    .start_mld_pairwise_rekey([0x61; 32])
                    .map_err(|_| "native MLD actual pairwise challenge")?;
                wire.mpdu(&frame, false);
            }
            let deadline = narf_time::Deadline::after_ms(3000);
            loop {
                flush()?;
                let done = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.keys == 6 && wire.ap.retransmit_mld().is_err()
                };
                if done
                    && guard
                        .device()
                        .state
                        .try_lock()
                        .is_some_and(|state| !state.needs_reset)
                {
                    break;
                }
                if deadline.expired() {
                    return Err("native MLD pairwise key native receipt bound");
                }
            }
            carrier(guard.device(), true)?;
            close(&guard)?;
        }
        let guard = setup(Model::new(14)?, None, false, Fault::HoldIgtk)?;
        discover(&guard, false)?;
        let domain = policy(false);
        let mut future = Box::pin(
            guard
                .device()
                .associate_in_domain(request_mld(false), &domain),
        );
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "native MLD held IGTK escaped",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("native MLD held IGTK publication bound");
            }
            narf_scheduler::sleep_pumps::run();
        }
        drop(future);
        let mut denied = domain;
        denied.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
        guard.policy_db.install(denied);
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (cmd, group, sequence) = wire
                .held
                .take()
                .ok_or("native MLD held key receipt absent")?;
            wire.fault = Fault::None;
            wire.firmware.inject(cmd, group, sequence, &[]);
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        loop {
            drain();
            if guard
                .device()
                .state
                .try_lock()
                .is_some_and(|state| state.stop_completed)
            {
                break;
            }
            if deadline.expired() {
                return Err("native MLD dropped key owner stop bound");
            }
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
        }
        carrier(guard.device(), false)?;
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("native MLD dropped key owner retained lock")?;
        require(
            state.hardware.is_failed()
                && state.needs_reset
                && model::retained(&state.hardware).1 != 0,
            "native MLD dropped key owner released uncertain native DMA",
        )?;
        drop(state);
        let unexposed = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            !wire.m4 && wire.data.is_empty()
        };
        require(unexposed, "native MLD held key lost native port/peer scope")
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_real_group_pairwise_rekey_and_dropped_igtk_owner_keep_native_keys_scoped
);
