#!/usr/bin/env python3
"""Generate rtw88 phy/rtl8822b_tables.rs from Linux rtw8822b_table.c.

Usage: python3 -I gen_rtl8822b_tables.py <linux>/drivers/net/wireless/realtek/rtw88/rtw8822b_table.c rtl8822b_tables.rs
       rustfmt --edition 2021 rtl8822b_tables.rs

Mirrors phy.c::rtw_parse_tbl_phy_cond / check_positive for PCIe
(intf=INTF_PCIE, pkg=15 because 8822B never sets hal->pkg_type,
cut = cut_version or 15 when 0) for every supported rtw8822b_rfe_defs
index (2, 3, 5) and every 4-bit chip cut. Output is verbatim rows.
"""
import re, sys
src = open(sys.argv[1]).read()
out = sys.argv[2]
TABLES = [("rtw8822b_mac", 0), ("rtw8822b_bb", 1), ("rtw8822b_agc", 2),
          ("rtw8822b_rf_a", 3), ("rtw8822b_rf_b", 4)]
def words(name):
    m = re.search(r"static const u32 %s\[\] = \{(.*?)\};" % name, src, re.S)
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    w = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", body)]
    assert len(w) % 2 == 0, name
    # every literal must be a hex constant
    assert len(re.findall(r"[0-9A-Za-z_]+", body)) == len(w), name
    return [(w[i], w[i + 1]) for i in range(0, len(w), 2)]
def fields(c):
    return dict(rfe=c & 0xff, intf=(c >> 8) & 15, pkg=(c >> 12) & 15,
                cut=(c >> 24) & 15, branch=(c >> 28) & 3,
                neg=(c >> 30) & 1, pos=(c >> 31) & 1)
def positive(cond, drv):
    f = fields(cond)
    if f["cut"] and f["cut"] != drv["cut"]: return False
    if f["pkg"] and f["pkg"] != drv["pkg"]: return False
    if f["intf"] and f["intf"] != drv["intf"]: return False
    return f["rfe"] == drv["rfe"]
def parse(rows, drv):
    pos = 0; matched = True; skipped = False; outrows = []
    for a, d in rows:
        f = fields(a)
        if f["pos"]:
            if f["branch"] == 3:   # BRANCH_ENDIF
                matched, skipped = True, False
            elif f["branch"] == 2: # BRANCH_ELSE
                matched = not skipped
            else:
                pos = a
        elif f["neg"]:
            if not skipped:
                if positive(pos, drv): matched, skipped = True, True
                else: matched, skipped = False, False
            else:
                matched = False
        elif matched:
            outrows.append((a, d))
    return outrows
# branch encodings: verify against main.h
# BRANCH_IF 0, ELIF 1, ELSE 2, ENDIF 3 (main.h).
CUTS = range(16); RFES = [2, 3, 5]
uniq = []; index = {}
profiles = {}
for name, kind in TABLES:
    rows = words(name)
    for cut in CUTS:
        for rfe in RFES:
            drv = dict(cut=cut if cut else 15, pkg=15, intf=1, rfe=rfe)
            sel = tuple(parse(rows, drv))
            assert all(a <= 0xffff for a, _ in sel)
            if kind == 0: assert all(d <= 0xff for _, d in sel)
            if kind >= 3: assert all(d <= 0xfffff for _, d in sel)
            if sel not in index:
                index[sel] = len(uniq); uniq.append(sel)
            profiles[(cut, rfe, kind)] = index[sel]
with open(out, "w") as f:
    f.write("// SPDX-License-Identifier: GPL-2.0-or-later\n")
    f.write("// Frozen RTL8822B PCIe table selections generated verbatim from Linux\n")
    f.write("// rtw8822b_table.c by phy.c::rtw_parse_tbl_phy_cond/check_positive\n")
    f.write("// (intf PCIe, pkg 15, cut 0 -> 15, rfe_defs 2/3/5). Do not edit by hand.\n")
    for i, t in enumerate(uniq):
        f.write("const TABLE_%d: &[(u16, u32)] = &[\n" % i)
        for a, d in t:
            f.write("    (0x%x, 0x%x),\n" % (a, d))
        f.write("];\n")
    f.write("const TABLES: [&[(u16, u32)]; %d] = [%s];\n" % (len(uniq), ", ".join("TABLE_%d" % i for i in range(len(uniq)))))
    f.write("/// `[cut][rfe 2/3/5][kind]`: kind 0 MAC, 1 BB, 2 AGC, 3 RF-A, 4 RF-B.\n")
    f.write("const PROFILES: [[[u8; 5]; 3]; 16] = [\n")
    for cut in CUTS:
        f.write("    [\n")
        for rfe in RFES:
            f.write("        [%s],\n" % ", ".join(str(profiles[(cut, rfe, k)]) for k in range(5)))
        f.write("    ],\n")
    f.write("];\n")
    f.write("""pub(super) fn select(cut: u8, rfe: u8, kind: usize) -> Option<&'static [(u16, u32)]> {
    let rfe = match rfe {
        2 => 0,
        3 => 1,
        5 => 2,
        _ => return None,
    };
    if cut > 15 || kind > 4 {
        return None;
    }
    Some(TABLES[usize::from(PROFILES[usize::from(cut)][rfe][kind])])
}
""")
print("unique tables", len(uniq), [len(t) for t in uniq])
