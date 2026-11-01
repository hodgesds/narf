//! Real JoinPlan/EHT/RSN transitions with distinct MLD and physical link MACs.
use super::*;
use crate::association::{mlo, JoinOptions, Phase, Pmf, SaePwe};
use crate::rsn::{RsnIe, Suite};
const OWN_MLD: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const AP_MLD: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
fn mle() -> Vec<u8> {
    let mut value = vec![107, 0x10, 1, 10];
    value.extend_from_slice(&AP_MLD);
    value.extend_from_slice(&[3, 0, 0]);
    value
}
fn protected(akm: u8) -> Bss {
    let mut ap = eht_ap();
    ap.capability |= 0x10;
    let mut rsn = RsnIe::wpa2_psk_ccmp();
    rsn.akms = vec![Suite::standard(akm)];
    rsn.rsn_capabilities = crate::rsn::RSN_CAP_MFP_CAPABLE | crate::rsn::RSN_CAP_MFP_REQUIRED;
    element(&mut ap.information_elements, 48, &rsn.encode_body());
    element(&mut ap.information_elements, 255, &mle());
    ap
}
fn mld(ap: &Bss, phy: LocalPhy) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_mld(
        ap,
        OWN,
        b"narf",
        SecurityMode::Wpa2Psk,
        phy,
        JoinOptions::default().with_pmf(Pmf::Required),
        mlo::Local::single_link(OWN_MLD).unwrap(),
    )
}
fn auth() -> Vec<u8> {
    let mut f = vec![0; 30];
    f[0] = 0xb0;
    f[4..10].copy_from_slice(&OWN_MLD);
    f[10..16].copy_from_slice(&AP_MLD);
    f[16..22].copy_from_slice(&AP_MLD);
    f[26] = 2;
    f.extend_from_slice(
        &mlo::Local::single_link(AP_MLD)
            .unwrap()
            .authentication_element(),
    );
    f
}
fn reply(ap: &Bss) -> Vec<u8> {
    let mut f = response(ap);
    f[4..10].copy_from_slice(&OWN_MLD);
    f[10..16].copy_from_slice(&AP_MLD);
    f[16..22].copy_from_slice(&AP_MLD);
    f[24] = 0x11;
    f
}
fn selected() -> Result<(), &'static str> {
    let ap = protected(2);
    let mut plan =
        mld(&ap, local(Some(local_eht()))).map_err(|_| "MLD EHT/PMF candidate refused")?;
    let context = *plan.mld().ok_or("missing boxed MLD context")?;
    check!(
        context.own_mld() == OWN_MLD
            && context.peer_mld() == AP_MLD
            && context.own_link() == OWN
            && context.peer_link() == AP
            && context.link_id() == 3,
        "MLD identities were conflated with physical link identity"
    );
    let first = plan
        .start_authentication()
        .map_err(|_| "MLD open authentication")?;
    check!(
        first[4..10] == AP_MLD && first[10..16] == OWN_MLD && first[16..22] == AP_MLD,
        "MLD authentication did not use logical management identities"
    );
    let mut physical_alias = auth();
    physical_alias[10..16].copy_from_slice(&AP);
    check!(
        plan.authentication_response(&physical_alias) == Ok(None),
        "physical peer aliased MLD authentication"
    );
    let request = plan
        .authentication_response(&auth())
        .map_err(|_| "MLD auth response")?
        .ok_or("MLD auth ignored")?
        .to_vec();
    let expected = mlo::Local::single_link(OWN_MLD).unwrap().request_element();
    check!(
        request
            .windows(expected.len())
            .filter(|w| *w == expected)
            .count()
            == 1,
        "single-link Basic MLE request common-info/capability layout changed"
    );
    check!(
        plan.association_response(&reply(&ap)) == Ok(Some(7))
            && plan.phase() == Phase::Associated { aid: 7 }
            && plan.mld() == Some(&context),
        "matching MLD association did not commit exact context"
    );
    let mut no_id = reply(&ap);
    let original = mle();
    let at = no_id
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let canonical = mlo::Local::single_link(AP_MLD).unwrap().request_element();
    no_id.splice(at - 2..at + original.len(), canonical);
    let mut optional = mld(&ap, local(Some(local_eht()))).unwrap();
    optional.start_authentication().unwrap();
    optional.authentication_response(&auth()).unwrap();
    check!(
        optional.association_response(&no_id) == Ok(Some(7)) && optional.mld() == Some(&context),
        "canonical response without Link-ID lost beacon-selected physical context"
    );
    // Ordinary constructors keep their physical identities even on an MLD AP.
    let mut ordinary = JoinPlan::prepare_with_options(
        &ap,
        OWN,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(local(Some(local_eht()))),
        JoinOptions::default().with_pmf(Pmf::Required),
    )
    .map_err(|_| "ordinary EHT/PMF candidate changed")?;
    check!(
        ordinary.mld().is_none() && ordinary.start_authentication().unwrap()[4..10] == AP,
        "ordinary JoinPlan silently became an MLD association"
    );
    // UHR is admitted only through the explicit MLD/key-delivery contract.
    let mut uhr_ap = ap.clone();
    element(
        &mut uhr_ap.information_elements,
        255,
        &[152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    element(
        &mut uhr_ap.information_elements,
        255,
        &[151, 0, 0, 0x11, 0, 0, 0],
    );
    element(&mut uhr_ap.information_elements, 50, &[0x80 | 120]);
    let uhr = local(Some(local_eht()))
        .with_uhr(crate::association::uhr::LocalUhr::new([0; 6], 0))
        .unwrap();
    let mut uhr_plan =
        mld(&uhr_ap, uhr).map_err(|_| "explicit single-link MLD did not unblock UHR")?;
    check!(
        uhr_plan.offered_phy().is_some_and(|p| p.uhr().is_some()),
        "MLD UHR profile absent"
    );
    uhr_plan.start_authentication().unwrap();
    uhr_plan.authentication_response(&auth()).unwrap();
    check!(
        uhr_plan.association_response(&reply(&uhr_ap)) == Ok(Some(7))
            && uhr_plan.negotiated_phy().is_some_and(|p| p.uhr().is_some()),
        "MLD response lost negotiated UHR"
    );
    Ok(())
}
smoke!(
    smoke_mld_single_link_joinplan_identity_eht_pmf_and_uhr,
    selected
);

fn boundaries() -> Result<(), &'static str> {
    let ap = protected(2);
    let good = mle();
    let plan = mld(&ap, local(Some(local_eht()))).unwrap();
    let context = *plan.mld().unwrap();
    let mut physical = vec![0x88, 0x7a, 0, 0];
    physical.extend_from_slice(&OWN);
    physical.extend_from_slice(&AP);
    physical.extend_from_slice(&AP);
    physical.extend_from_slice(&[0x30, 0, 0x93, 0]);
    let projected = context
        .data_crypto_header(&physical)
        .map_err(|_| "MLD class crypto projection")?;
    check!(
        projected[..4] == physical[..4] && projected[22..] == physical[22..]
            && projected[4..10] == OWN_MLD && projected[10..16] == AP_MLD
            && projected[16..22] == AP_MLD
            && context.data_crypto_header(&projected).is_err(),
        "MLD crypto projection altered flags/SC/QC or accepted already-logical alias as raw physical"
    );
    physical[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 0x77]);
    check!(
        context.data_crypto_header(&physical).is_err(),
        "foreign unicast A-MSDU BSSID projected into selected MLD"
    );
    let crypto = [19, 0, 0xdd, 10, 0, 0];
    let mut authentication = crypto.to_vec();
    authentication.extend_from_slice(
        &mlo::Local::single_link(AP_MLD)
            .unwrap()
            .authentication_element(),
    );
    check!(
        context.authentication_body(&authentication) == Ok(crypto.as_slice()),
        "opaque SAE crypto bytes were parsed as an IE stream"
    );
    *authentication.last_mut().unwrap() ^= 1;
    check!(
        context.authentication_body(&authentication).is_err()
            && context.authentication_body(&crypto).is_err(),
        "foreign or absent authentication MLD trailer admitted"
    );
    let mut all_common = vec![0xf0, 7, 18];
    all_common.extend_from_slice(&AP_MLD);
    all_common.extend_from_slice(&[14, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    check!(
        mlo::BasicMultiLink::parse(&all_common).is_ok_and(|m| m.link_id() == Some(14)),
        "optional Basic common-info field order/extent lost highest valid link"
    );
    all_common.pop();
    check!(
        mlo::BasicMultiLink::parse(&all_common).is_err(),
        "truncated optional Basic common-info admitted"
    );
    for at in [1usize, 2, 3, 4, 10] {
        let mut malformed = good.clone();
        malformed[at] = 255;
        check!(
            mlo::BasicMultiLink::parse(&malformed[1..]).is_err(),
            "Basic MLE accepted type/presence/common/MAC/link corruption"
        );
    }
    let mut reserved = good.clone();
    reserved[10] = 15;
    check!(
        mlo::BasicMultiLink::parse(&reserved[1..]).is_err(),
        "reserved common Link ID15 admitted"
    );
    let mut reserved_profile = good.clone();
    reserved_profile.extend_from_slice(&[0, 3, 15, 0, 1]);
    check!(
        mlo::BasicMultiLink::parse(&reserved_profile[1..]).is_err(),
        "reserved affiliated profile Link ID15 admitted"
    );
    let mut duplicate = ap.clone();
    element(&mut duplicate.information_elements, 255, &good);
    check!(
        mld(&duplicate, local(Some(local_eht()))).is_err(),
        "duplicate Basic MLE admitted"
    );
    let mut fragment = ap.clone();
    element(&mut fragment.information_elements, 242, &[0]);
    check!(
        mld(&fragment, local(Some(local_eht()))).is_err(),
        "fragmented MLE admitted without reassembly"
    );
    for at in [0usize, 1, 7, 10] {
        let mut plan = mld(&ap, local(Some(local_eht()))).unwrap();
        plan.start_authentication().unwrap();
        plan.authentication_response(&auth()).unwrap();
        let mut response = reply(&ap);
        let start = response
            .windows(good.len())
            .position(|w| w == good)
            .ok_or("response MLE missing")?;
        response[start + at] = 255;
        check!(
            plan.association_response(&response).is_err() && plan.phase() == Phase::Failed,
            "corrupt MLD response committed a partial AID/identity"
        );
    }
    let mut missing = reply(&ap);
    let start = missing.windows(good.len()).position(|w| w == good).unwrap();
    missing.drain(start - 2..start + good.len());
    let mut plan = mld(&ap, local(Some(local_eht()))).unwrap();
    plan.start_authentication().unwrap();
    plan.authentication_response(&auth()).unwrap();
    check!(
        plan.association_response(&missing).is_err() && plan.phase() == Phase::Failed,
        "MLD response omission downgraded to ordinary association"
    );
    // SAE commits are built over MLD identities; link-address sessions fail.
    let ap = protected(8);
    let mut plan = JoinPlan::prepare_mld(
        &ap,
        OWN,
        b"narf",
        SecurityMode::Wpa3Sae {
            pwe: SaePwe::HuntAndPeck,
        },
        local(Some(local_eht())),
        JoinOptions::default(),
        mlo::Local::single_link(OWN_MLD).unwrap(),
    )
    .map_err(|_| "MLD SAE profile")?;
    let mut wrong =
        crate::sae::SaeSession::new_hunt_and_peck(b"secret", OWN, AP).with_test_seed([0x31; 64]);
    wrong.build_commit();
    check!(
        plan.start_sae_authentication(&wrong) == Err(Error::UnsupportedSecurity),
        "physical SAE session aliased MLD PMK identity"
    );
    let mut sta = crate::sae::SaeSession::new_hunt_and_peck(b"secret", OWN_MLD, AP_MLD)
        .with_test_seed([0x32; 64]);
    sta.build_commit();
    let frame = plan
        .start_sae_authentication(&sta)
        .map_err(|_| "MLD SAE commit rejected")?
        .to_vec();
    check!(
        frame[4..10] == AP_MLD
            && frame[10..16] == OWN_MLD
            && frame[30..frame.len() - 12] == sta.commit_body(None)
            && frame[frame.len() - 12..]
                == mlo::Local::single_link(OWN_MLD)
                    .unwrap()
                    .authentication_element(),
        "MLD SAE commit changed logical frame/crypto identities"
    );
    let mut peer = crate::sae::SaeSession::new_hunt_and_peck(b"secret", AP_MLD, OWN_MLD)
        .with_test_seed([0x42; 64]);
    let peer_commit = peer.build_commit();
    peer.on_commit(&sta.commit_body(None))
        .map_err(|_| "MLD AP SAE commit")?;
    let sae_frame = |seq: u16, body: &[u8]| {
        let mut value = auth();
        value.truncate(30);
        value[24..26].copy_from_slice(&3u16.to_le_bytes());
        value[26..28].copy_from_slice(&seq.to_le_bytes());
        value.extend_from_slice(body);
        value.extend_from_slice(
            &mlo::Local::single_link(AP_MLD)
                .unwrap()
                .authentication_element(),
        );
        value
    };
    let confirm = match plan.sae_authentication_response(&sae_frame(1, &peer_commit), &mut sta) {
        Ok(crate::association::SaeStep::Transmit(bytes)) => bytes.to_vec(),
        _ => return Err("MLD peer SAE commit/trailer not accepted"),
    };
    let peer_confirm = peer.build_confirm();
    peer.on_confirm(&confirm[30..confirm.len() - 12])
        .map_err(|_| "MLD AP SAE confirm")?;
    if !matches!(
        plan.sae_authentication_response(&sae_frame(2, &peer_confirm), &mut sta),
        Ok(crate::association::SaeStep::Associate(_))
    ) || sta.pmk() != peer.pmk()
        || plan.association_response(&reply(&ap)) != Ok(Some(7))
    {
        return Err("MLD SAE common-info stripping, PMK agreement or final association failed");
    }
    Ok(())
}
smoke!(
    smoke_mld_basic_response_and_sae_address_boundaries,
    boundaries
);
