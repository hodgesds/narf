//! Independently authored H2 records through the retained C22 radio, actual
//! packet Core, native TXBD/CCX/RXD and original public station interface.
use super::*;
use crate::rtw88::firmware_transport::Io;
use cases::Fixture;
use narf_net::{Interface, TxMeta};

fn record(r: &ht::Request, mcs: u16, sgi: bool) -> Vec<u8> {
    let r = r.two_streams.as_deref().expect("fixture2SS factory fields");
    let mut b = vec![0; 256];
    b[..16].copy_from_slice(&[
        b'N', b'2', b'2', b'H', 2, 0, 0, 1, 0, 1, 0, 0, 0xec, 0x10, 0x22, 0xc8,
    ]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    b[56..58].copy_from_slice(&4i16.to_le_bytes());
    b[58..60].copy_from_slice(&76i16.to_le_bytes());
    b[60..62].copy_from_slice(&60i16.to_le_bytes());
    b[62..64].copy_from_slice(&48i16.to_le_bytes());
    b[65] = 63;
    b[66..68].copy_from_slice(&mcs.to_le_bytes());
    b[68] = u8::from(sgi);
    b[69] = 2;
    b[70..86].copy_from_slice(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);
    for at in (86..174).step_by(2) {
        b[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
    }
    b
}
fn make(protected: bool, mcs: u16, sgi: bool, peer_two: bool) -> Result<Case, &'static str> {
    let e = setup_paths(protected, true, true, None, true)?;
    let cap = Cap::bootstrap();
    let mut elements = cases::elements(true);
    if peer_two {
        elements[6] = 255;
    } else {
        // AP RX1SS, TX2SS: defined unequal TX/RX MCS and max TX NSS2.
        // Our TX selection must narrow without erasing local RX2SS.
        elements[17] = 7;
    }
    let beacon = {
        let mut peer = e.h.peer.lock();
        peer.ht = Some(elements.clone());
        let mut b = peer.ap.beacon();
        b.extend_from_slice(peer.wmm.as_ref().unwrap());
        b.extend_from_slice(&elements);
        b
    };
    e.h.model(|io| io.packets.receive(&beacon, false, false));
    let proposal = e.h.model(|io| io.ht_request()).map_err(|_| "H2 request")?;
    e.h.model(|io| {
        io.qualify_ht(ht::Source::Verified {
            bytes: record(&proposal, mcs, sgi),
            signer: Some([12; 32]),
            cap,
        })
    })
    .map_err(|_| "H2 distinct synthetic qualification")?;
    Ok(Case { e, cap })
}
fn composition(protected: bool) -> Result<(), &'static str> {
    for (mask, sgi) in [
        (0x0100, false),
        (0x0200, true),
        (0x0400, false),
        (0x0800, true),
        (0x1000, false),
        (0x2000, true),
        (0x4000, false),
        (0xffff, true),
    ] {
        let f = make(protected, mask, sgi, true)?;
        let retained = f.retained();
        cases::join(&f)?;
        let assoc = f
            .peer()
            .lock()
            .association
            .clone()
            .ok_or("H2 association absent")?;
        let at = assoc
            .windows(2)
            .position(|w| w == [45, 26])
            .ok_or("H2 local IE absent")?;
        if assoc[at + 5..at + 7] != [255, 255] || assoc[at + 2] & 0x80 != 0 {
            return Err("H2 RX16 or uncoded local promise");
        }
        if f.register(0x820) & 255 != 0x31
            || f.register(0x1e2c) & 0xffff != 0x400
            || f.register(0x3a14) != 0x04030201
            || f.register(0x3a18) != 0x08070605
            || f.register(0x18e8) & 0x1fc00 != 9 << 10
            || f.register(0x41e8) & 0x1fc00 != 9 << 10
            || f.register(0x522) & 255 != 0
            || f.register(0x284) & (1 << 18) != 0
        {
            return Err("H2 native two-path/signed16 gain/resume readbacks");
        }
        let selected = 15 - mask.leading_zeros() as u8;
        let rate = 12 + selected;
        let ra = f
            .mailboxes()
            .into_iter()
            .rev()
            .find(|b| b[0] == 0x40)
            .ok_or("H2 actual RA absent")?;
        let expected = (0xfffu32 | (u32::from(mask) << 12)).to_le_bytes();
        // RAID2 (BGN_20M_2SS), INIT_RA_LVL1 (bit5: fw.c rtw_fw_send_ra_info
        // with si->init_ra_lv = 1 from rtw_sta_add), SGI_EN bit7.
        if ra[2] != 2 | 1 << 5 | (u8::from(sgi) << 7) || ra[4..8] != expected {
            return Err("H2 native RA2/full28-bit mask/SGI");
        }
        let lease = narf_net::dhcp::dhcp_acquire(f.device().name(), 0).map_err(|_| "H2 DHCP")?;
        if !f.peer().lock().plan.matches_lease(&lease) {
            return Err("H2 original lease");
        }
        let _ = f.received();
        let up = cases::packet(selected);
        f.device()
            .enqueue(&up, TxMeta::default())
            .map_err(|_| "H2 enqueue")?;
        f.pump();
        let d = f.descriptor().ok_or("H2 actual TXWD absent")?;
        if d[16] != rate
            || d[6] != 2
            || d[20] != u8::from(sgi) << 4
            || f.peer().lock().uplink.last() != Some(&up)
        {
            return Err("H2 actual MCS8..15 descriptor/CCMP uplink");
        }
        let mut down = up.clone();
        down[..6].copy_from_slice(&cases::OWN);
        down[6..12].copy_from_slice(&cases::AP);
        let raw = f.peer().lock().downlink(&down)?;
        f.inject(&raw, rate, 0);
        f.pump();
        if f.received() != vec![down] || f.retained() != retained || !f.device().link_up() {
            return Err("H2 RX16/native key/rings changed");
        }
    }
    Ok(())
}
fn smoke_rtw8822ce_ht2_open_all_native_mcs_and_dhcp() -> TestResult {
    result(|| composition(false))
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht2",
    smoke_rtw8822ce_ht2_open_all_native_mcs_and_dhcp
);
fn smoke_rtw8822ce_ht2_wpa2_all_native_mcs_and_dhcp() -> TestResult {
    result(|| composition(true))
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht2",
    smoke_rtw8822ce_ht2_wpa2_all_native_mcs_and_dhcp
);

fn smoke_rtw8822ce_ht2_original_v1_and_peer_one_stream_rx16() -> TestResult {
    result(|| {
        {
            let old = Case::make(false, 255, true, true)?;
            if old.request()?.two_streams.is_some() {
                return Err("erased2SS factory admitted");
            }
            cases::join(&old)?;
            let frame = cases::packet(71);
            let raw = old.peer().lock().downlink(&frame)?;
            old.inject(&raw, 27, 0);
            old.pump();
            if !old.received().is_empty() {
                return Err("original H1 widened RX16");
            }
        }
        let f = make(true, 0xffff, true, false)?;
        cases::join(&f)?;
        let up = cases::packet(72);
        f.device()
            .enqueue(&up, TxMeta::default())
            .map_err(|_| "H2 peer1 enqueue")?;
        f.pump();
        if f.descriptor().ok_or("peer1 descriptor")?[16] != 19 {
            return Err("peer1 TX selection widened");
        }
        let mut down = up;
        down[..6].copy_from_slice(&cases::OWN);
        down[6..12].copy_from_slice(&cases::AP);
        let raw = f.peer().lock().downlink(&down)?;
        f.inject(&raw, 27, 0);
        f.pump();
        if f.received() != vec![down] {
            return Err("peer1 TX narrowed independent local RX16");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht2",
    smoke_rtw8822ce_ht2_original_v1_and_peer_one_stream_rx16
);

fn smoke_rtw8822ce_ht2_distinct_signed_factory_and_measured_bounds() -> TestResult {
    result(|| {
        let f = make(false, 0xffff, true, true)?;
        let r = f.request()?;
        let baseline = f.register(0x820);
        for fault in 0..10 {
            let cap = Cap::bootstrap();
            let mut bytes = record(&r, 0xffff, true);
            match fault {
                0 => bytes[16] ^= 1,
                1 => bytes[48] ^= 1,
                2 => bytes[67] = 0,
                3 => bytes[69] = 1,
                4 => bytes[78] = 41,
                5 => bytes[174] = 1,
                6 => bytes[86..88].copy_from_slice(&61i16.to_le_bytes()),
                7 => bytes[60..62].copy_from_slice(&77i16.to_le_bytes()),
                8 => bytes[4] = 1,
                _ => {
                    bytes.pop();
                }
            }
            if f.stage(bytes, cap).is_ok() || f.register(0x820) != baseline {
                return Err("bad H2 signature identity/factory/peak accepted or touched IO");
            }
        }
        let unsigned = f.e.h.model(|io| {
            io.qualify_ht(ht::Source::Verified {
                bytes: record(&r, 0xffff, true),
                signer: None,
                cap: Cap::bootstrap(),
            })
        });
        if unsigned.is_ok() {
            return Err("unsigned H2 accepted");
        }
        // Linux's second-stream difference is additive and signed.
        let mut p = [0; 42];
        p[6] = 40;
        p[11] = 0x20;
        p[12] = 0x0f;
        if ht::factory_limit_2ss(&p) != Some(42) {
            return Err("2SS cumulative factory nibbles");
        }
        p[12] = 255;
        if ht::factory_limit_2ss(&p).is_some() {
            return Err("erased2SS factory inferred");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht2",
    smoke_rtw8822ce_ht2_distinct_signed_factory_and_measured_bounds
);

fn smoke_rtw8822ce_ht2_native_source_loss_and_partial_path_readback() -> TestResult {
    result(|| {
        {
            let f = make(false, 0xffff, true, true)?;
            cases::scan(&f)?;
            if !f
                .e
                .h
                .model(|io| {
                    crate::rtw88::firmware_transport::ready_now(Io::station_ht_program_quiet(io))
                })
                .map_err(|_| "H2 quiet owner")?
            {
                return Err("actual drained H2 owner not quiet");
            }
            f.e.h
                .model(|io| {
                    crate::rtw88::firmware_transport::ready_now(Io::mailbox_submit(
                        io,
                        [1, 0, 0, 0, 0, 0, 0, 0],
                    ))
                })
                .map_err(|_| "H2 native pending mailbox")?;
            if f.e
                .h
                .model(|io| {
                    crate::rtw88::firmware_transport::ready_now(Io::station_ht_program_quiet(io))
                })
                .map_err(|_| "H2 pending receipt")?
            {
                return Err("unconsumed original mailbox admitted path mutation");
            }
        }
        {
            let f = make(false, 0xffff, true, true)?;
            cases::scan(&f)?;
            f.lose(0x820);
            if cases::run(f.device().associate(cases::request(&f)))?.is_ok() || f.device().link_up()
            {
                return Err("H2 lost path write opened port");
            }
        }
        let f = make(true, 0xffff, true, true)?;
        cases::join(&f)?;
        let retained = f.retained();
        let cap = f.cap();
        f.after_descriptor(Arc::new(move || cap.revoke()));
        let up = cases::packet(73);
        let _ = f.device().enqueue(&up, TxMeta::default());
        f.pump();
        if f.peer().lock().uplink.last() == Some(&up)
            || f.device().link_up()
            || f.retained() != retained
        {
            return Err("H2 publication source loss escaped original authority/retention");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtw88/ht2",
    smoke_rtw8822ce_ht2_native_source_loss_and_partial_path_readback
);
