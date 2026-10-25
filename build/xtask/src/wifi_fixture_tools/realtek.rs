//! Independent checked legacy/CE/AX metadata extraction; no executable bytes retained.
use super::*;
fn fragment(raw: &[u8], out: &mut Vec<Value>, offset: usize, length: usize) -> Result<()> {
    ensure!(length > 0, "empty fragment");
    out.push(json!({"offset":offset,"hex":hex(bytes(raw,offset,length)?)}));
    Ok(())
}
fn ax(raw: &[u8], entry: Value, out: &mut Vec<Value>) -> Result<Value> {
    let start = uint(&entry, "offset")?;
    let size = uint(&entry, "length")?;
    let body = bytes(raw, start, size)?;
    let version = *bytes(body, 15, 1)?.first().unwrap();
    ensure!(version <= 1, "unsupported AX header");
    let base = if version == 0 { 32 } else { 48 };
    let count = *bytes(body, 25, 1)?.first().unwrap() as usize;
    ensure!((1..=10).contains(&count), "invalid AX section count");
    let fixed = base + count * 16;
    let dynamic = u32le(body, 28)? & (1 << 16) != 0;
    let header = if !dynamic {
        fixed
    } else if version == 0 {
        ((u32le(body, 12)? >> 16) & 255) as usize
    } else {
        (u32le(body, 20)? >> 16) as usize
    };
    ensure!(
        fixed <= header && header <= size,
        "invalid AX header extent"
    );
    if dynamic {
        ensure!(
            header - fixed >= 8 && u32le(body, fixed)? as usize == header - fixed,
            "invalid AX dynamic extent"
        );
    }
    fragment(raw, out, start, fixed + if dynamic { 8 } else { 0 })?;
    let mut sections = Vec::new();
    let mut position = header;
    for i in 0..count {
        let desc = base + i * 16;
        let flags = u32le(body, desc + 4)?;
        let checksum = flags & (1 << 28) != 0;
        let length = (flags & 0xffffff) as usize + if checksum { 8 } else { 0 };
        let kind = (flags >> 24) & 15;
        let content = position;
        position = position
            .checked_add(length)
            .context("AX section overflow")?;
        ensure!(position <= size, "truncated AX section");
        let mut section = json!({"kind":kind,"address":u32le(body,desc)? & if version==0 {0x1fffffff} else {u32::MAX},
            "length":length,"checksum":checksum,"redownload":flags&(1<<29)!=0,"offset":content,"pool":null});
        let mssc = u32le(body, desc + 8)? & if version == 0 { u32::MAX } else { 255 };
        if kind == 9 && mssc != 0 {
            let pool_start = position;
            let bitmap = mssc & 255 == 255;
            let (prefix, sig_count, mut sig_length) = if bitmap {
                let pool = bytes(body, pool_start, 32)?;
                ensure!(
                    &pool[..8] == b"MSSKPOOL" && pool[20] == 0,
                    "invalid MSS pool"
                );
                let bits = usize::from(pool[21])
                    * usize::from(u16le(pool, 24)?)
                    * usize::from(u16le(pool, 26)?);
                ensure!(bits % 8 == 0, "invalid MSS bitmap geometry");
                let prefix = 32 + bits / 8 + if pool[16] != 0 { 8 } else { 0 };
                ensure!(
                    u32le(pool, 8)? == 32 && u32le(pool, 12)? as usize == prefix,
                    "invalid MSS pool header lengths"
                );
                ensure!(
                    length >= 62,
                    "security header shorter than signature length field"
                );
                let signature = usize::from(u16le(body, content + 60)? >> 2);
                fragment(raw, out, start + content + 60, 2)?;
                fragment(raw, out, start + pool_start, 32)?;
                (
                    prefix,
                    usize::from(u16le(pool, 22)?),
                    if signature == 0 { 512 } else { signature },
                )
            } else {
                (0, mssc as usize, 512)
            };
            if version == 1 && u32le(body, 24)? & (1 << 24) != 0 {
                sig_length += 8;
            }
            let length = prefix
                .checked_add(
                    sig_count
                        .checked_mul(sig_length)
                        .context("signature pool overflow")?,
                )
                .context("signature pool overflow")?;
            section["pool"] = json!({"offset":pool_start,"length":length,"signatures_offset":pool_start+prefix,
                "signature_length":sig_length,"signature_count":sig_count,"bitmap":bitmap});
            position = position
                .checked_add(length)
                .context("signature pool extent overflow")?;
            ensure!(position <= size, "truncated signature pool");
        }
        sections.push(section);
    }
    ensure!(position == size, "AX image has unaccounted tail");
    let mut result = entry;
    for (key,value) in json!({"version":version,"major":body[4],"minor":body[5],"header_length":header,"dynamic":dynamic,"sections":sections}).as_object().unwrap() {result[key]=value.clone();}
    Ok(result)
}
pub(super) fn extract(raw: &[u8], name: &str) -> Result<Value> {
    let mut fragments = Vec::new();
    let mut images = Vec::new();
    let mut result = json!({"name":name,"sha256":hex(&Sha256::digest(raw)),"length":raw.len()});
    if name.starts_with("rtlwifi/") {
        fragment(raw, &mut fragments, 0, 32)?;
        ensure!(
            u16le(raw, 0)? == 0x88e1 && usize::from(u16le(raw, 12)?) == raw.len() - 32,
            "bad legacy firmware geometry"
        );
        result["legacy"] = json!({"signature":u16le(raw,0)?,"version":u16le(raw,4)?,"subversion":raw[6],"payload":raw.len()-32});
    } else if name.starts_with("rtw88/") {
        fragment(raw, &mut fragments, 0, 64)?;
        ensure!(u16le(raw, 0)? == 0x8822, "bad CE signature");
        let mut sections = Vec::new();
        let mut position = 64;
        for (addr, len) in [(0x20, 0x24), (0x3c, 0x30), (0x38, 0x34)] {
            if len == 0x34 && !(raw[0x18] & 0x10 != 0 && u32le(raw, len)? != 0) {
                continue;
            }
            let size = u32le(raw, len)? as usize + 8;
            bytes(raw, position, size)?;
            sections.push(
                json!({"address":u32le(raw,addr)?&0x7fffffff,"length":size,"offset":position}),
            );
            position += size;
        }
        ensure!(position == raw.len(), "CE image has unaccounted tail");
        result["ce"] = json!({"version":u16le(raw,4)?,"subversion":raw[6],"h2c":u16le(raw,0x1c)?,"sections":sections});
    } else {
        ensure!(
            name.starts_with("rtw89/") && bytes(raw, 0, 2)?[0] == 255,
            "bad AX MFW signature/name"
        );
        let count = raw[1] as usize;
        ensure!(count > 0, "empty MFW directory");
        let end = 16 + count * 16;
        fragment(raw, &mut fragments, 0, end)?;
        let mut extents = Vec::new();
        for index in 0..count {
            let at = 16 + index * 16;
            let start = u32le(raw, at + 4)? as usize;
            let length = u32le(raw, at + 8)? as usize;
            ensure!(start >= end && length > 0, "invalid AX image extent");
            bytes(raw, start, length)?;
            ensure!(
                extents
                    .iter()
                    .all(|&(a, b)| start >= b || start + length <= a),
                "overlapping AX images"
            );
            extents.push((start, start + length));
            let entry = json!({"cut":raw[at],"kind":raw[at+1],"manufacturing":raw[at+2]!=0,"offset":start,"length":length});
            if matches!(raw[at + 1], 1 | 3 | 5 | 64 | 65) {
                images.push(ax(raw, entry, &mut fragments)?);
            }
        }
    }
    fragments.sort_by_key(|x| x["offset"].as_u64().unwrap());
    let mut end = 0;
    for part in &fragments {
        let offset = uint(part, "offset")?;
        ensure!(offset >= end, "overlapping Realtek fragments");
        end = offset + string(part, "hex")?.len() / 2;
    }
    result["fragments"] = json!(fragments);
    result["images"] = json!(images);
    Ok(result)
}
