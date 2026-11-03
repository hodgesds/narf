//! Real JoinPlan/EHT/RSN transitions with distinct MLD and physical link MACs.
use super::*;
use crate::association::{mlo, JoinOptions, MldLinkPhy, MldLinkRequest, Phase, Pmf, SaePwe};
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

/// Linux ieee80211-eht.h common-info order and EML helpers; affiliated
/// per-STA headers are retained but grant no link.
fn eml_and_affiliated() -> Result<(), &'static str> {
    // Link ID, medium sync, EML and MLD capabilities present.
    let mut body = vec![0xd0, 1, 14];
    body.extend_from_slice(&AP_MLD);
    body.push(2);
    body.extend_from_slice(&0x0a12u16.to_le_bytes());
    // EMLSR, pad 64us (code2), transition 128us (code4), timeout 1TU (code4).
    let eml = 1 | (2 << 1) | (4 << 4) | (4 << 11);
    body.extend_from_slice(&(eml as u16).to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    // Complete profile for link 5 with STA MAC, STA info length 7.
    body.extend_from_slice(&[0, 9, 0x35, 0, 7]);
    body.extend_from_slice(&[2, 0x73, 2, 3, 4, 5]);
    // Partial profile for link 9 without MAC.
    body.extend_from_slice(&[0, 3, 9, 0, 1]);
    let parsed = mlo::BasicMultiLink::parse(&body).map_err(|_| "EML Basic MLE refused")?;
    let caps = parsed.eml_capabilities().ok_or("EML capabilities lost")?;
    check!(
        parsed.link_id() == Some(2)
            && parsed.medium_sync_delay() == Some(0x0a12)
            && caps.emlsr()
            && caps.padding_delay_us() == 64
            && caps.transition_delay_us() == 128
            && caps.transition_timeout_us() == 1024
            && caps.transition_timeout_code() == 4
            && parsed.mld_capabilities().map(mlo::max_simultaneous_links) == Some(2),
        "EML/MLD common-info fields decoded out of presence order"
    );
    let five = parsed
        .affiliated(5)
        .ok_or("complete affiliated link lost")?;
    let nine = parsed.affiliated(9).ok_or("partial affiliated link lost")?;
    check!(
        five.complete()
            && five.address() == Some([2, 0x73, 2, 3, 4, 5])
            && !nine.complete()
            && nine.address().is_none()
            && parsed.affiliated(2).is_none()
            && parsed.profile_links() == (1 << 5) | (1 << 9),
        "affiliated per-STA headers misattributed"
    );
    let off = mlo::EmlCapabilities(eml as u16 & !1);
    check!(
        !off.emlsr() && off.padding_delay_us() == 0 && off.transition_delay_us() == 0,
        "EMLSR delays reported without EMLSR support"
    );
    check!(
        mlo::EmlCapabilities((7 << 1) | 1).padding_delay_us() == 0
            && mlo::EmlCapabilities((7 << 4) | 1).transition_delay_us() == 0
            && mlo::EmlCapabilities(15 << 11).transition_timeout_code() == 10
            && mlo::EmlCapabilities(15 << 11).transition_timeout_us() == 0,
        "reserved EML encodings not treated as Linux invalid values"
    );
    check!(
        mlo::EmlCapabilities::INTEL_MLD_LOCAL.emlsr()
            && mlo::EmlCapabilities::INTEL_MLD_LOCAL.padding_delay_us() == 32
            && mlo::EmlCapabilities::INTEL_MLD_LOCAL.transition_delay_us() == 64,
        "Intel MLD local EMLSR capability differs from IWL_MLD_EMLSR_CAPA"
    );
    // A selected single-link context still refuses any affiliated profile.
    let context = mlo::Local::single_link(OWN_MLD)
        .unwrap()
        .context(OWN, AP, &parsed)
        .map_err(|_| "context from EML MLE")?;
    let mut response = vec![255, (body.len() + 1) as u8, 107];
    response.extend_from_slice(&body);
    check!(
        context.response(&response).is_err(),
        "single-link response admitted extra affiliated links"
    );
    Ok(())
}
smoke!(
    smoke_mld_basic_eml_capabilities_and_affiliated_profiles,
    eml_and_affiliated
);

const OWN2: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
const AP2: [u8; 6] = [2, 0, 0, 0, 0, 0x22];
/// The same AP MLD's affiliated link `link_id` on 5GHz channel149 (VHT80
/// segment155), with its own Basic MLE.
fn second_link(link_id: u8) -> Bss {
    let mut ap = protected(2);
    ap.bssid = AP2;
    ap.channel = 149;
    let mut rewritten = Vec::new();
    let mut rest = &ap.information_elements[..];
    while let [id, len, tail @ ..] = rest {
        let mut body = tail[..usize::from(*len)].to_vec();
        match *id {
            61 => body[0] = 149,
            192 => body[1] = 155,
            255 if body[0] == 107 => body[10] = link_id,
            _ => {}
        }
        element(&mut rewritten, *id, &body);
        rest = &tail[usize::from(*len)..];
    }
    ap.information_elements = rewritten;
    ap
}
fn multi(first: &Bss, second: &Bss) -> Result<JoinPlan, Error> {
    let phy = MldLinkPhy::Phy(local(Some(local_eht())));
    JoinPlan::prepare_mld_links(
        MldLinkRequest {
            bss: first,
            own_link: OWN,
            phy,
        },
        &[MldLinkRequest {
            bss: second,
            own_link: OWN2,
            phy,
        }],
        b"narf",
        SecurityMode::Wpa2Psk,
        JoinOptions::default().with_pmf(Pmf::Required),
        mlo::Local::single_link(OWN_MLD).unwrap(),
    )
}
/// Elements of `ap` an AP repeats inside a per-STA profile (no SSID, RSN or
/// Multi-Link element).
fn link_only(ap: &Bss) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = &ap.information_elements[..];
    while let [id, len, tail @ ..] = rest {
        let body = &tail[..usize::from(*len)];
        if !(matches!(*id, 0 | 48) || *id == 255 && body[0] == 107) {
            element(&mut out, *id, body);
        }
        rest = &tail[usize::from(*len)..];
    }
    out
}
/// Association response on link3 with a link5 per-STA profile.
fn multi_reply(ap: &Bss, second: &Bss, status: u16, outer_change: bool, peer: [u8; 6]) -> Vec<u8> {
    let mut frame = reply(ap);
    let original = mle();
    let at = frame
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let control: u16 = 0x0110 | if outer_change { 0x20 } else { 0 };
    let mut body = vec![107];
    body.extend_from_slice(&control.to_le_bytes());
    body.push(if outer_change { 11 } else { 10 });
    body.extend_from_slice(&AP_MLD);
    body.push(3);
    if outer_change {
        body.push(0);
    }
    body.extend_from_slice(&[0, 0]);
    let mut profile = 0x0835u16.to_le_bytes().to_vec();
    profile.push(8);
    profile.extend_from_slice(&peer);
    profile.push(0);
    profile.extend_from_slice(&0x11u16.to_le_bytes());
    profile.extend_from_slice(&status.to_le_bytes());
    if status == 0 {
        profile.extend_from_slice(&link_only(second));
    }
    element(&mut body, 0, &profile);
    let mut replacement = Vec::new();
    element(&mut replacement, 255, &body);
    frame.splice(at - 2..at + original.len(), replacement);
    frame
}
fn associate(plan: &mut JoinPlan) -> Result<Vec<u8>, &'static str> {
    plan.start_authentication()
        .map_err(|_| "multi-link open authentication")?;
    Ok(plan
        .authentication_response(&auth())
        .map_err(|_| "multi-link auth response")?
        .ok_or("multi-link auth ignored")?
        .to_vec())
}
fn multiple_links() -> Result<(), &'static str> {
    let (first, second) = (protected(2), second_link(5));
    let mut plan = multi(&first, &second).map_err(|_| "two-link MLD request refused")?;
    check!(
        plan.mld_links().len() == 1
            && plan.mld_links()[0].link_id() == 5
            && plan.mld_links()[0].context().own_link() == OWN2
            && plan.mld_links()[0].context().peer_link() == AP2
            && plan.mld_links()[0].context().peer_mld() == AP_MLD
            && plan.mld_links()[0].status().is_none(),
        "affiliated link offer lost its per-link identity"
    );
    let request = associate(&mut plan)?;
    let parsed = mlo::BasicMultiLink::from_ies(&request[28..])
        .map_err(|_| "multi-link request MLE unparsable")?;
    let profile = parsed
        .affiliated(5)
        .ok_or("link5 per-STA profile missing")?;
    check!(
        parsed.address() == OWN_MLD
            && parsed.link_id().is_none()
            && parsed.eml_capabilities().is_none()
            && parsed.mld_capabilities() == Some(0)
            && parsed.profile_links() == 1 << 5
            && profile.complete()
            && profile.address() == Some(OWN2),
        "request per-STA profile header differs from ieee80211_assoc_add_ml_elem"
    );
    // Control (link5|COMPLETE|STA MAC), STA info length7, link MAC, then the
    // ESS|privacy capability and the link's own rates before HT/VHT/HE/EHT.
    let mut head = vec![0x35, 0x00, 7];
    head.extend_from_slice(&OWN2);
    head.extend_from_slice(&[0x11, 0x00, 1]);
    check!(
        request.windows(head.len()).any(|w| w == head),
        "per-STA profile STA info/capability layout"
    );
    check!(
        !request
            .windows(3)
            .any(|w| w[0] == 255 && w[2] == mlo::EXT_NON_INHERITANCE),
        "identical link element sets emitted a Non-Inheritance element"
    );
    // Accepted link: both links commit with their own negotiated PHY.
    check!(
        plan.association_response(&multi_reply(&first, &second, 0, true, AP2)) == Ok(Some(7)),
        "valid two-link association response refused"
    );
    let link = &plan.mld_links()[0];
    check!(
        link.accepted()
            && link.status() == Some(0)
            && link.negotiated_phy().is_some()
            && link.channel() == 149
            && plan.negotiated_phy().is_some(),
        "accepted affiliated link did not commit its own negotiation"
    );
    // A per-STA rejection drops only that link.
    let mut rejected = multi(&first, &second).unwrap();
    associate(&mut rejected)?;
    check!(
        rejected.association_response(&multi_reply(&first, &second, 1, true, AP2)) == Ok(Some(7))
            && rejected.mld_links()[0].status() == Some(1)
            && !rejected.mld_links()[0].accepted()
            && rejected.mld_links()[0].negotiated_phy().is_none(),
        "per-STA status rejection was not link-local"
    );
    // Missing outer change count, a wrong affiliated AP address and a missing
    // requested profile each fail the whole association.
    for (frame, message) in [
        (
            multi_reply(&first, &second, 0, false, AP2),
            "missing BSS parameter change count admitted",
        ),
        (
            multi_reply(&first, &second, 0, true, [2, 0, 0, 0, 0, 0x44]),
            "profile for a different affiliated AP admitted",
        ),
        (
            reply(&first),
            "requested link missing from response admitted",
        ),
    ] {
        let mut failed = multi(&first, &second).unwrap();
        associate(&mut failed)?;
        if failed.association_response(&frame).is_ok() || failed.phase() != Phase::Failed {
            return Err(message);
        }
    }
    // Same link id, own MAC reuse and a different AP MLD are refused.
    check!(
        multi(&first, &second_link(3)).is_err()
            && JoinPlan::prepare_mld_links(
                MldLinkRequest {
                    bss: &first,
                    own_link: OWN,
                    phy: MldLinkPhy::Phy(local(Some(local_eht()))),
                },
                &[MldLinkRequest {
                    bss: &second,
                    own_link: OWN,
                    phy: MldLinkPhy::Phy(local(Some(local_eht()))),
                }],
                b"narf",
                SecurityMode::Wpa2Psk,
                JoinOptions::default().with_pmf(Pmf::Required),
                mlo::Local::single_link(OWN_MLD).unwrap(),
            )
            .is_err(),
        "conflicting affiliated link identities admitted"
    );
    let mut other_mld = second_link(5);
    let mle_at = other_mld
        .information_elements
        .windows(3)
        .position(|w| w[0] == 255 && w[2] == 107)
        .unwrap();
    other_mld.information_elements[mle_at + 9] ^= 0x40;
    check!(
        multi(&first, &other_mld).is_err(),
        "link of a different AP MLD admitted"
    );
    Ok(())
}
smoke!(smoke_mld_multiple_link_association, multiple_links);

fn inheritance() -> Result<(), &'static str> {
    let mut outer = Vec::new();
    element(&mut outer, 0, b"narf");
    element(&mut outer, 1, &[0x8c]);
    element(&mut outer, 45, &[1, 2]);
    element(&mut outer, 191, &[3, 4]);
    element(&mut outer, 255, &[35, 5]);
    element(&mut outer, 255, &[107, 0, 0]);
    let mut profile = Vec::new();
    element(&mut profile, 1, &[0x98]);
    element(&mut profile, 255, &[35, 6]);
    element(&mut profile, 255, &[mlo::EXT_NON_INHERITANCE, 1, 191, 0]);
    let mut expected = Vec::new();
    element(&mut expected, 0, b"narf");
    element(&mut expected, 45, &[1, 2]);
    element(&mut expected, 1, &[0x98]);
    element(&mut expected, 255, &[35, 6]);
    check!(
        mlo::link_elements(&outer, &profile).as_deref() == Ok(&expected[..]),
        "per-link view differs from parse.c inheritance/override rules"
    );
    let mut malformed = Vec::new();
    element(&mut malformed, 255, &[mlo::EXT_NON_INHERITANCE, 2, 191]);
    check!(
        mlo::link_elements(&outer, &malformed).is_err(),
        "truncated Non-Inheritance element admitted"
    );
    // EML is only placed in a request when EMLSR/EMLMR is supported.
    let local = mlo::Local::single_link(OWN_MLD).unwrap();
    let eml = local
        .with_capabilities(1, mlo::EmlCapabilities::INTEL_MLD_LOCAL)
        .request_element();
    let parsed = mlo::BasicMultiLink::from_ies(&eml).map_err(|_| "EML request unparsable")?;
    check!(
        parsed.eml_capabilities() == Some(mlo::EmlCapabilities::INTEL_MLD_LOCAL)
            && parsed.mld_capabilities() == Some(1)
            && local
                .with_capabilities(0, mlo::EmlCapabilities(0x0e))
                .request_element()
                == local.request_element(),
        "request EML presence differs from ieee80211_assoc_add_ml_elem"
    );
    Ok(())
}
smoke!(smoke_mld_per_link_element_inheritance, inheritance);
