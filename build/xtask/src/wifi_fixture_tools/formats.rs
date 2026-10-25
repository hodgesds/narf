//! Standalone checked wire decoders, without production-driver parser imports.
use super::*;

pub(super) fn intel(raw: &[u8]) -> Result<Extracted> {
    ensure!(bytes(raw, 0, 8)? == b"\0\0\0\0IWL\n", "bad Intel TLV magic");
    bytes(raw, 0, 88)?;
    let mut ranges = vec![(0, 88)];
    let mut sections = Vec::new();
    let mut api = [0u32; 8];
    let mut capabilities = [0u32; 8];
    let mut calibration = [0u32; 2];
    let (mut phy, mut cpu, mut iml, mut pnvm) = (0, 1, 0, 0);
    let mut version = Value::Null;
    let mut commands = String::new();
    let mut counts = BTreeMap::<String, usize>::new();
    let mut at = 88;
    while at < raw.len() {
        ensure!(
            ranges.len() + 2 <= MAX_FRAGMENTS,
            "too many Intel metadata fragments"
        );
        let tag = u32le(raw, at)?;
        let len = u32le(raw, at + 4)? as usize;
        let start = at + 8;
        let end = start.checked_add(len).context("TLV overflow")?;
        let stop = start
            .checked_add(len.checked_add(3).context("TLV alignment overflow")? & !3)
            .context("TLV overflow")?;
        bytes(raw, start, stop - start)?;
        let data = bytes(raw, start, len)?;
        match tag {
            22 | 36 => ensure!(len == 12, "invalid fixed triple metadata extent"),
            23 | 27 | 62 => ensure!(len == 4, "invalid fixed scalar metadata extent"),
            29 | 30 => ensure!(len == 8, "invalid bitmap metadata extent"),
            48 => ensure!(
                len % 4 == 0 && len <= 4 * 65536,
                "invalid command metadata table extent"
            ),
            _ => {}
        }
        ranges.push((at, 8));
        *counts.entry(tag.to_string()).or_default() += 1;
        if matches!(tag, 19 | 20 | 24 | 25) {
            let destination = u32le(data, 0)?;
            sections.push(json!([tag, destination, len - 4]));
            ranges.push((start, 4));
        } else if matches!(tag, 22 | 23 | 27 | 29 | 30 | 36 | 48 | 62) {
            ranges.push((start, len));
        }
        match tag {
            22 => {
                ensure!(len == 12, "bad calibration extent");
                if u32le(data, 0)? == 0 {
                    calibration = [u32le(data, 4)?, u32le(data, 8)?];
                }
            }
            23 => phy = u32le(data, 0)?,
            27 => {
                cpu = u32le(data, 0)?;
                ensure!(matches!(cpu, 1 | 2), "invalid firmware CPU count");
            }
            29 | 30 => {
                ensure!(len == 8, "bad API bitmap extent");
                let index = u32le(data, 0)? as usize;
                if index < 8 {
                    let words = if tag == 29 {
                        &mut api
                    } else {
                        &mut capabilities
                    };
                    words[index] |= u32le(data, 4)?;
                }
            }
            36 => version = json!([u32le(data, 0)?, u32le(data, 4)?, u32le(data, 8)?]),
            48 => {
                ensure!(len % 4 == 0, "bad command table extent");
                commands = hex(data);
            }
            52 => iml = len,
            74 => pnvm = len,
            _ => {}
        }
        ensure!(end <= stop, "TLV geometry");
        at = stop;
    }
    let human = bytes(raw, 8, 64)?.split(|x| *x == 0).next().unwrap();
    ensure!(
        human.iter().all(|x| x.is_ascii_graphic() || *x == b' '),
        "non-printable Intel human version"
    );
    packed(
        raw,
        &ranges,
        json!({"version":u32le(raw,72)?,"build":u32le(raw,76)?,
        "human":std::str::from_utf8(human)?,"num_cpu":cpu,"fw_version":version,
        "sections":sections,"api_changes":api,"capabilities":capabilities,
        "calibration":calibration,"phy_config":phy,"commands_hex":commands,
        "iml_len":iml,"pnvm_len":pnvm,"tlv_counts":counts}),
    )
}

pub(super) fn mediatek(raw: &[u8], patch: bool) -> Result<Extracted> {
    if patch {
        bytes(raw, 0, 96)?;
        let count = u32be(raw, 44)? as usize;
        ensure!((1..=64).contains(&count), "invalid patch region count");
        let end = 96 + count * 64;
        bytes(raw, 0, end)?;
        let mut regions = Vec::new();
        for i in 0..count {
            let at = 96 + i * 64;
            let kind = u32be(raw, at)?;
            let offset = u32be(raw, at + 4)? as usize;
            let len = u32be(raw, at + 16)? as usize;
            ensure!(
                kind & 0xffff == 2 && offset >= end,
                "invalid patch section type/offset"
            );
            bytes(raw, offset, len)?;
            regions.push(
                json!({"sec_type":kind,"offset":offset,"size":u32be(raw,at+8)?,
                "addr":u32be(raw,at+12)?,"len":len,"sec_key_idx":u32be(raw,at+20)?}),
            );
        }
        packed(
            raw,
            &[(0, end)],
            json!({"build_date":&raw[..16],"platform":&raw[16..20],
            "hw_sw_ver":u32be(raw,20)?,"patch_ver":u32be(raw,24)?,
            "checksum":u16::from_be_bytes(bytes(raw,28,2)?.try_into()?),"n_region":count,"regions":regions}),
        )
    } else {
        let trailer = raw.len().checked_sub(36).context("truncated RAM trailer")?;
        let tail = &raw[trailer..];
        let count = tail[2] as usize;
        ensure!((1..=64).contains(&count), "invalid RAM region count");
        let start = trailer
            .checked_sub(count * 40)
            .context("truncated RAM table")?;
        let mut regions = Vec::new();
        let mut payload_end = 0usize;
        for i in 0..count {
            let at = start + i * 40;
            let len = u32le(raw, at + 20)? as usize;
            payload_end = payload_end
                .checked_add(len)
                .context("RAM payload overflow")?;
            regions.push(
                json!({"decomp_crc":u32le(raw,at)?,"decomp_len":u32le(raw,at+4)?,
                "decomp_blk_sz":u32le(raw,at+8)?,"addr":u32le(raw,at+16)?,"len":len,
                "feature_set":raw[at+24],"region_type":raw[at+25]}),
            );
        }
        ensure!(payload_end <= start, "RAM regions overlap trailer table");
        packed(
            raw,
            &[(start, raw.len() - start)],
            json!({"chip_id":tail[0],"eco_code":tail[1],"n_region":count,
            "format_ver":tail[3],"format_flag":tail[4],"fw_ver":&tail[7..17],"build_date":&tail[17..32],
            "crc":u32le(tail,32)?,"regions":regions,"payload_end":payload_end,"table_start":start}),
        )
    }
}

fn ies(raw: &[u8], start: usize, end: usize) -> Result<Vec<(usize, u32, usize, usize)>> {
    ensure!(
        start <= end && end <= raw.len(),
        "invalid IE container extent"
    );
    let mut result = Vec::new();
    let mut at = start;
    while at < end {
        ensure!(result.len() < MAX_FRAGMENTS, "too many container IEs");
        ensure!(end - at >= 8, "truncated IE header");
        let kind = u32le(raw, at)?;
        let len = u32le(raw, at + 4)? as usize;
        let data = at + 8;
        let stop = data
            .checked_add(len.checked_add(3).context("IE alignment overflow")? & !3)
            .context("IE extent overflow")?;
        ensure!(stop <= end, "truncated IE body/padding");
        result.push((at, kind, data, len));
        at = stop;
    }
    Ok(result)
}
pub(super) fn qualcomm(raw: &[u8], key: &str) -> Result<Extracted> {
    let mut ranges = Vec::new();
    let mut facts = json!({});
    if key.contains("_api") {
        ensure!(
            bytes(raw, 0, 11)? == b"QCA-ATH10K\0",
            "bad ath10k container magic"
        );
        ranges.push((0, 12));
        let mut entries = Vec::new();
        for (header, kind, offset, size) in ies(raw, 12, raw.len())? {
            ranges.push((header, 8));
            if matches!(kind, 0 | 1 | 2 | 5 | 6) && size > 0 {
                ranges.push((offset, size));
            }
            entries.push(json!({"id":kind,"offset":offset,"size":size}));
            if let Some(field) = match kind {
                2 => Some("features"),
                5 => Some("wmi"),
                6 => Some("htt"),
                _ => None,
            } {
                ensure!(size <= 8, "oversized scalar metadata");
                let mut scalar = [0; 8];
                scalar[..size].copy_from_slice(bytes(raw, offset, size)?);
                facts[field] = json!(u64::from_le_bytes(scalar));
            }
            if let Some(field) = match kind {
                3 => Some("image"),
                4 => Some("otp"),
                7 => Some("codeswap"),
                _ => None,
            } {
                facts[field] = json!([offset, size]);
            }
        }
        facts["entries"] = json!(entries);
        facts["api"] = json!(key
            .rsplit("api")
            .next()
            .context("missing API")?
            .parse::<u8>()?);
    } else if key.ends_with("board2") {
        let magic = if key.starts_with("qca6174") {
            b"QCA-ATH10K-BOARD\0"
        } else {
            b"QCA-ATH11K-BOARD\0"
        };
        ensure!(
            bytes(raw, 0, magic.len())? == magic,
            "bad board container magic"
        );
        let start = (magic.len() + 3) & !3;
        ranges.push((0, start));
        let mut records = Vec::new();
        let mut count = 0;
        for (header, kind, offset, size) in ies(raw, start, raw.len())? {
            ranges.push((header, 8));
            let mut names = Vec::new();
            for (subheader, subkind, suboffset, subsize) in ies(raw, offset, offset + size)? {
                ranges.push((subheader, 8));
                if subkind == 0 {
                    ensure!(subsize > 0, "empty board name");
                    let name = bytes(raw, suboffset, subsize)?;
                    ensure!(
                        name.iter().all(|x| x.is_ascii_graphic() || *x == b' '),
                        "non-printable board name"
                    );
                    ranges.push((suboffset, subsize));
                    names.push(std::str::from_utf8(name)?.to_owned());
                } else if subkind == 1 {
                    for name in names.drain(..) {
                        records.push(
                            json!({"kind":kind,"name":name,"offset":suboffset,"size":subsize}),
                        );
                    }
                }
            }
            count += 1;
        }
        let mut kinds = std::collections::BTreeSet::new();
        for item in &records {
            kinds.insert(uint(item, "kind")?);
        }
        let mut samples = Vec::new();
        for kind in kinds {
            let same = records
                .iter()
                .filter(|x| x["kind"] == kind)
                .collect::<Vec<_>>();
            let indices = std::collections::BTreeSet::from([0, same.len() / 2, same.len() - 1]);
            for index in indices {
                samples.push(same[index].clone());
            }
        }
        facts =
            json!({"top_level_ie_count":count,"board_name_count":records.len(),"samples":samples});
    } else {
        ensure!(
            bytes(raw, 0, 7)? == b"\x7fELF\x01\x01\x01",
            "not ELF32 little-endian"
        );
        bytes(raw, 0, 52)?;
        ensure!(u16le(raw, 40)? == 52, "invalid ELF header size");
        ranges.push((0, 52));
        facts = json!({"format":"ELF32 little-endian raw image; not firmware-2 IE container"});
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (at, len) in ranges {
        if let Some(last) = merged.last_mut() {
            if last.0 + last.1 == at {
                last.1 += len;
                continue;
            }
        }
        merged.push((at, len));
    }
    packed(raw, &merged, facts)
}
pub(super) fn broadcom(raw: &[u8]) -> Result<Extracted> {
    let vector = u32le(raw, 0)?;
    let magic = u32le(raw, 108)?;
    let candidate = u32le(raw, 112)?;
    packed(
        raw,
        &[(0, 4), (108, 8)],
        json!({"reset_vector_word":vector,"ram_metadata_offset":108,
        "ram_metadata_magic":magic,"embedded_ramsize":if magic==0x534d4152 {Some(candidate)} else {None},"trx_wrapped":vector==0x30524448}),
    )
}
