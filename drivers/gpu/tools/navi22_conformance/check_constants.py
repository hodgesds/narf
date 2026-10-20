#!/usr/bin/env python3
"""Navi22 (RX 6750 XT) constant conformance checker.

Every register offset / BASE_IDX / field mask / mailbox message / PSP command
/ packet opcode a Navi22-path Rust module claims to mirror from Linux is
compared against the exact Linux header for the IP version on this card.
Model tests cannot catch a wrong constant when the fake encodes the same
wrong value; this check reads the Linux headers directly.

Annotation convention (comment-only, see drivers/gpu/research/navi22-conformance.md):

    pub const RB_CNTL: u32 = 0x80; // linux: mmIH_RB_CNTL
    // linux: mmCP_MEC_CNTL_Sienna_Cichlid@gc101
    pub const CP_MEC_CNTL: Reg = Reg(0, 0x0f55);
    (Reg(1, 0x224e), Reg(0, 0x0fc3)), // linux: mmVGT_TF_RING_SIZE_UMD; mmVGT_TF_RING_SIZE_Sienna_Cichlid
    const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
    const DIG_MODE: u32 = 0x0007_0000; // linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
    const TIMEOUT_US: u32 = 100_000; // linux: n/a (NARF policy)

* `// linux: E1[; E2 ...]` trails the checked line, or sits alone on the line(s)
  directly above it. Each `E` is a C expression over Linux symbols (macros,
  function-like macros and enum constants) and matches one value item on the
  Rust line in order. A `Reg(idx, off)` item is one item; its idx is checked
  against `<sym>_BASE_IDX`.
* `SYM@key` pins the header set (see HEADER_SETS) when a symbol is ambiguous.
* `abs(mmFOO)` expects the absolute BAR5 dword (discovery base + offset);
  `bytes(mmFOO)` the absolute BAR5 byte address.
* `// linux-ctx: hdr=k1,k2 seg=N` restricts symbol lookup and asserts that the
  following register constants are applied to SOC15 segment N, until the next
  `linux-ctx` line (`// linux-ctx: reset` clears it).
* `// linux: n/a [reason]` marks a non-Linux constant (policy, sizes, NARF ids).
* `// linux-lit: 22=GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL; 0x21=GFX_CMD_ID_AUTOLOAD_RLC`
  checks integer literals inside arbitrary code (match arms, call arguments,
  `matches!` lists): each literal must occur in the line and equal the
  expression.
* `offsetof(struct T, f)` / `sizeof(struct T)` are evaluated by compiling a C
  probe against the Linux layout headers (LAYOUT_HEADERS).

Unannotated integer constants are auto-matched by name (NAME, mmNAME, regNAME,
...) against a unique Linux symbol; an auto-mismatch fails the run until the
constant is annotated with the symbol it really mirrors. Constants with
neither an annotation nor an auto-match are listed as unmapped (report only).
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
GPU_SRC = REPO / "drivers" / "gpu" / "src"

AMD = "drivers/gpu/drm/amd"
AR = AMD + "/include/asic_reg"
AG = AMD + "/amdgpu"

# key -> (discovery IP for absolute addresses or None, [header files]).
# Versions are the ones THIS card's Linux driver path uses (see the doc).
HEADER_SETS = {
    # GC 10.3.2: gfxhub_v2_1.c / sdma_v5_2.c / amdkfd use gc_10_3_0.
    "gc": ("GC", [AR + "/gc/gc_10_3_0_offset.h", AR + "/gc/gc_10_3_0_sh_mask.h",
                  AR + "/gc/gc_10_3_0_default.h", AG + "/gfx_v10_0.c"]),
    # gfx_v10_0.c itself compiles against gc_10_1_0 + local _Sienna_Cichlid
    # overrides; nv.c also includes gc_10_1_0.
    "gc101": ("GC", [AR + "/gc/gc_10_1_0_offset.h", AR + "/gc/gc_10_1_0_sh_mask.h",
                     AG + "/gfx_v10_0.c"]),
    "dcn": ("DMU", [AR + "/dcn/dcn_3_0_0_offset.h", AR + "/dcn/dcn_3_0_0_sh_mask.h"]),
    # MMHUB 2.1.0 is driven by mmhub_v2_0.c (mmhub_2_0_0 + locals).
    "mmhub": ("MMHUB", [AR + "/mmhub/mmhub_2_0_0_offset.h", AR + "/mmhub/mmhub_2_0_0_sh_mask.h",
                        AR + "/mmhub/mmhub_2_0_0_default.h", AG + "/mmhub_v2_0.c"]),
    "oss": ("OSSSYS", [AR + "/oss/osssys_5_0_0_offset.h", AR + "/oss/osssys_5_0_0_sh_mask.h",
                       AG + "/navi10_ih.c"]),
    "nbio": ("NBIF", [AR + "/nbio/nbio_2_3_offset.h", AR + "/nbio/nbio_2_3_sh_mask.h",
                      AG + "/nbio_v2_3.c"]),
    "hdp": ("HDP", [AR + "/hdp/hdp_5_0_0_offset.h", AR + "/hdp/hdp_5_0_0_sh_mask.h"]),
    "mp": ("MP0", [AR + "/mp/mp_11_0_offset.h", AR + "/mp/mp_11_0_sh_mask.h"]),
    # psp_v11_0.c locals (mmRLC_GPM_UCODE_ADDR_NV10 is a GC register).
    "psp11": ("GC", [AG + "/psp_v11_0.c"]),
    "smuio": ("SMUIO", [AR + "/smuio/smuio_11_0_6_offset.h", AR + "/smuio/smuio_11_0_6_sh_mask.h"]),
    # gfx_v10_0.c includes smuio_11_0_0 (mmSMUIO_GFX_MISC_CNTL etc.).
    "smuio0": ("SMUIO", [AR + "/smuio/smuio_11_0_0_offset.h", AR + "/smuio/smuio_11_0_0_sh_mask.h"]),
    # THM 11.0.5 is driven by smu_v11_0.c with thm_11_0_2.
    "thm": ("THM", [AR + "/thm/thm_11_0_2_offset.h", AR + "/thm/thm_11_0_2_sh_mask.h"]),
    "vcn": ("VCN", [AR + "/vcn/vcn_3_0_0_offset.h", AR + "/vcn/vcn_3_0_0_sh_mask.h",
                    AG + "/vcn_v3_0.c", AG + "/jpeg_v3_0.c", AG + "/jpeg_v2_0.h"]),
    "athub": ("ATHUB", [AR + "/athub/athub_2_1_0_offset.h", AR + "/athub/athub_2_1_0_sh_mask.h"]),
    "df": ("DF", [AR + "/df/df_3_6_offset.h", AR + "/df/df_3_6_sh_mask.h"]),
    "psp": (None, [AG + "/psp_gfx_if.h", AG + "/amdgpu_psp.h"]),
    "ppsmc": (None, [AMD + "/pm/swsmu/inc/pmfw_if/smu_v11_0_7_ppsmc.h",
                     AMD + "/pm/swsmu/inc/pmfw_if/smu11_driver_if_sienna_cichlid.h",
                     AMD + "/pm/swsmu/inc/smu_v11_0.h",
                     AMD + "/pm/swsmu/smu11/smu_v11_0.c",
                     AMD + "/pm/swsmu/smu11/sienna_cichlid_ppt.c"]),
    "pm4": (None, [AG + "/nvd.h"]),
    "soc15d": (None, [AG + "/soc15d.h"]),
    "sdma": (None, [AG + "/navi10_sdma_pkt_open.h"]),
    "ih": (None, [AMD + "/include/soc15_ih_clientid.h",
                  AMD + "/include/ivsrcid/gfx/irqsrcs_gfx_10_1.h",
                  AMD + "/include/ivsrcid/sdma0/irqsrcs_sdma0_5_0.h",
                  AMD + "/include/ivsrcid/sdma1/irqsrcs_sdma1_5_0.h",
                  AMD + "/include/ivsrcid/sdma2/irqsrcs_sdma2_5_0.h",
                  AMD + "/include/ivsrcid/sdma3/irqsrcs_sdma3_5_0.h",
                  AMD + "/include/ivsrcid/vcn/irqsrcs_vcn_2_0.h",
                  AMD + "/include/ivsrcid/vmc/irqsrcs_vmc_1_0.h",
                  AMD + "/include/ivsrcid/dcn/irqsrcs_dcn_1_0.h",
                  AMD + "/include/ivsrcid/smuio/irqsrcs_smuio_9_0.h",
                  AMD + "/include/ivsrcid/thm/irqsrcs_thm_9_0.h"]),
    "dmub": (None, [AMD + "/display/dmub/inc/dmub_cmd.h",
                    AMD + "/display/dmub/dmub_srv.h",
                    AMD + "/display/dmub/src/dmub_dcn30.h",
                    AMD + "/display/dmub/src/dmub_dcn20.h",
                    AMD + "/display/dmub/src/dmub_dcn30.c",
                    AMD + "/display/dmub/src/dmub_dcn20.c",
                    AMD + "/display/dmub/src/dmub_srv.c"]),
    "amdgpu": (None, [AG + "/amdgpu_vm.h", AG + "/amdgpu_gmc.h", AG + "/amdgpu_ih.h",
                      AG + "/amdgpu_doorbell.h", AG + "/amdgpu_ring.h", AG + "/amdgpu_irq.h",
                      AG + "/amdgpu_ucode.h", AG + "/amdgpu_vcn.h", AG + "/amdgpu_sdma.h",
                      AG + "/amdgpu_gfx.h", AG + "/amdgpu_rlc.h", AG + "/amdgpu_mes.h",
                      AG + "/amdgpu_nbio.h", AG + "/amdgpu_ttm.h", AG + "/amdgpu_object.h",
                      AG + "/amdgpu.h", AG + "/amdgpu_reset.h", AG + "/gmc_v10_0.c",
                      AG + "/gfxhub_v2_1.c", AG + "/sdma_v5_2.c", AG + "/nv.c", AG + "/amdgpu_gmc.c",
                      AG + "/amdgpu_vcn.c", AG + "/amdgpu_psp.c", AG + "/amdgpu_ucode.c",
                      AMD + "/include/v10_structs.h", AMD + "/include/navi10_enum.h",
                      AMD + "/include/amd_shared.h", AMD + "/pm/swsmu/inc/smu_types.h",
                      AG + "/amdgpu_gart.h", AG + "/amdgpu_ids.h", AG + "/sdma_common.h"]),
    "atom": (None, [AMD + "/include/atomfirmware.h", AMD + "/include/atombios.h", AG + "/ObjectID.h"]),
    "uapi": (None, ["include/uapi/drm/amdgpu_drm.h", "include/uapi/drm/drm_fourcc.h",
                    "include/uapi/linux/pci_regs.h"]),
    "dc": (None, [AMD + "/display/dc/dc_hw_types.h", AMD + "/display/dc/dc_types.h",
                  AMD + "/display/include/signal_types.h",
                  AMD + "/display/include/grph_object_id.h",
                  AMD + "/display/include/grph_object_defs.h",
                  AMD + "/display/dc/inc/hw/clk_mgr_internal.h",
                  AMD + "/display/dc/clk_mgr/dcn30/dcn30_smu11_driver_if.h",
                  AMD + "/display/dc/clk_mgr/dcn30/dalsmc.h",
                  AMD + "/display/dc/inc/core_types.h",
                  AMD + "/display/dc/dc_dp_types.h",
                  "include/drm/display/drm_dp.h",
                  "include/drm/display/drm_hdmi_helper.h",
                  "include/drm/display/drm_scdc.h",
                  "include/sound/hda_verbs.h",
                  AMD + "/display/dc/inc/hw/mpc.h", AMD + "/display/dc/inc/hw/hw_shared.h",
                  AMD + "/display/dc/inc/hw/stream_encoder.h", AMD + "/display/dc/inc/hw/hubp.h",
                  AMD + "/display/include/link_service_types.h",
                  AMD + "/display/include/ddc_service_types.h",
                  AMD + "/display/dc/dc_ddc_types.h", AMD + "/display/dc/dc_hdmi_types.h",
                  AMD + "/display/dc/clk_mgr/dcn30/dcn30_clk_mgr.h",
                  AMD + "/display/dc/clk_mgr/dcn30/dcn30_clk_mgr_smu_msg.c",
                  AMD + "/display/dc/dce/dce_aux.h", AMD + "/display/dc/dce/dce_i2c_hw.h",
                  AMD + "/display/dc/link/protocols/link_ddc.h", AMD + "/display/include/dpcd_defs.h",
                  AMD + "/display/dc/link/protocols/link_dp_training_8b_10b.h",
                  AMD + "/display/dc/link/protocols/link_dp_training.c",
                  AMD + "/display/dc/link/link_dpms.c", AMD + "/display/dc/link/link_detection.c",
                  AMD + "/display/dc/dc_dmub_srv.c",
                  "include/drm/drm_edid.h", "include/linux/hdmi.h"]),
}
# Lookup priority when a symbol exists in several sets with different values.
PRIORITY = list(HEADER_SETS)

# Live IP discovery of this card (navi22_common.md): dword segment bases.
DISCOVERY = {
    "GC": [0x1260, 0xA000, 0x1C000, 0x2402C00],
    "DMU": [0x12, 0xC0, 0x34C0, 0x9000, 0x2403C00],
    "MMHUB": [0x1A000, 0x2408800],
    "MP0": [0x16000, 0xDC0000, 0xE00000, 0xE40000, 0x243FC00],
    "MP1": [0x16000, 0xDC0000, 0xE00000, 0xE40000, 0x243FC00],
    "NBIF": [0x0, 0x14, 0xD20, 0x10400, 0x241B000, 0x4040000],
    "HDP": [0xF20, 0x240A400],
    "OSSSYS": [0x10A0, 0x240A000],
    "SMUIO": [0x16800, 0x16A00, 0x440000, 0x2401000],
    "THM": [0x16600, 0x2400C00],
    "ATHUB": [0xC00, 0x2408C00],
    "DF": [0x7000, 0x240B800],
}
BAR5_DWORDS = (1 << 20) // 4

# Structure layouts for offsetof()/sizeof() annotations, compiled in a C probe.
LAYOUT_HEADERS = [AG + "/amdgpu_ucode.h", AG + "/psp_gfx_if.h", AMD + "/include/v10_structs.h",
                  AMD + "/pm/swsmu/inc/pmfw_if/smu11_driver_if_sienna_cichlid.h",
                  AMD + "/include/atomfirmware.h", AMD + "/display/dmub/inc/dmub_cmd.h"]
LAYOUT_INCLUDES = [AG, AMD + "/include", AMD + "/display/dmub/inc", AMD + "/display/include",
                   AMD + "/display/dc", AMD + "/pm/swsmu/inc/pmfw_if"]
LAYOUT_PRELUDE = """#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32; typedef uint8_t u8; typedef uint16_t u16; typedef uint64_t u64;
typedef int32_t s32; typedef int8_t s8; typedef int16_t s16; typedef int64_t s64;
struct mutex { int x; };
#define __printf(a, b)
#define __counted_by(x)
#define READ_ONCE(x) (x)
"""
LAYOUT = re.compile(r"\b(offsetof|sizeof)\s*\(((?:[^()]|\([^()]*\))*)\)")

# Files on the Navi22 path (globs relative to drivers/gpu/src). Tests excluded.
MODULE_GLOBS = [
    "amdgpu_*navi22*.rs", "amdgpu_dcn30_*.rs", "amdgpu_dml30.rs", "amdgpu_psp*.rs",
    "amdgpu_vram_boot.rs", "amdgpu_dcn_*.rs", "amdgpu_gfx_firmware.rs",
    "amdgpu_smc_firmware.rs", "amdgpu_dmub_firmware.rs",
    "amdgpu_rdna2_power_controls.rs",
]

# --------------------------------------------------------------------------
# Expression evaluation (shared by C and Rust sides).

TOKEN = re.compile(r"\s*(?:(0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*)([uUlL]*|(?:u|i)(?:8|16|32|64|128|size))?"
                   r"|([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)|(<<|>>|[-+*/%&|^~!()?:,@]))")


class EvalError(Exception):
    pass


def tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise EvalError("bad token at %r" % text[pos:pos + 20])
        pos = m.end()
        if m.group(1):
            lit = m.group(1).replace("_", "")
            if lit[:2] in ("0b", "0B"):
                v = int(lit[2:], 2)
            elif lit[:2] in ("0o", "0O"):
                v = int(lit[2:], 8)
            elif lit[:2] in ("0x", "0X"):
                v = int(lit, 16)
            elif len(lit) > 1 and lit.startswith("0"):
                v = int(lit, 8)
            else:
                v = int(lit)
            out.append(("n", v))
        elif m.group(3):
            out.append(("id", m.group(3)))
        else:
            out.append(("op", m.group(4)))
    return out


class Parser:
    """Recursive-descent integer expression parser. `resolve(name)` returns an
    int for identifiers; `call(name, args)` evaluates function-like macros."""

    BIN = [("|",), ("^",), ("&",), ("<<", ">>"), ("+", "-"), ("*", "/", "%")]

    def __init__(self, tokens, resolve, call=None, rust=False):
        self.t, self.i, self.resolve, self.call, self.rust = tokens, 0, resolve, call, rust

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, op=None):
        tok = self.peek()
        if op is not None and tok != ("op", op):
            raise EvalError("expected %s got %r" % (op, tok))
        self.i += 1
        return tok

    def parse(self):
        v = self.ternary()
        if self.i != len(self.t):
            raise EvalError("trailing tokens %r" % (self.t[self.i:],))
        return v

    def ternary(self):
        c = self.binary(0)
        if self.peek() == ("op", "?"):
            self.take()
            a = self.ternary()
            self.take(":")
            b = self.ternary()
            return a if c else b
        return c

    def binary(self, level):
        if level == len(self.BIN):
            return self.cast()
        v = self.binary(level + 1)
        while self.peek()[0] == "op" and self.peek()[1] in self.BIN[level]:
            op = self.take()[1]
            r = self.binary(level + 1)
            if op == "|":
                v |= r
            elif op == "^":
                v ^= r
            elif op == "&":
                v &= r
            elif op == "<<":
                v <<= r
            elif op == ">>":
                v >>= r
            elif op == "+":
                v += r
            elif op == "-":
                v -= r
            elif op == "*":
                v *= r
            elif op == "/":
                v //= r
            elif op == "%":
                v %= r
        return v

    def cast(self):
        v = self.unary()
        # Rust `x as u32`: truncate.
        while self.rust and self.peek() == ("id", "as"):
            self.take()
            ty = self.take()[1]
            width = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64, "i64": 64, "i32": 32}.get(ty)
            if width is None:
                raise EvalError("cast to %s" % ty)
            v &= (1 << width) - 1
        return v

    def unary(self):
        tok = self.peek()
        if tok == ("op", "-"):
            self.take()
            return -self.unary()
        if tok == ("op", "+"):
            self.take()
            return self.unary()
        if tok in (("op", "~"), ("op", "!")):
            self.take()
            return ~self.unary()
        return self.primary()

    def primary(self):
        tok = self.take()
        if tok[0] == "n":
            return tok[1]
        if tok == ("op", "("):
            # C casts: (uint32_t)x, (u32)(x).
            nxt = self.peek()
            if nxt[0] == "id" and nxt[1] in C_TYPES and self.t[self.i + 1:self.i + 2] == [("op", ")")]:
                self.take()
                self.take(")")
                return self.unary()
            v = self.ternary()
            self.take(")")
            return v
        if tok[0] == "id":
            name = tok[1]
            if self.peek() == ("op", "("):
                self.take()
                args, depth, cur = [], 0, []
                while True:
                    t = self.take()
                    if t == (None, None):
                        raise EvalError("unterminated call")
                    if t == ("op", "(") :
                        depth += 1
                    elif t == ("op", ")"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif t == ("op", ",") and depth == 0:
                        args.append(cur)
                        cur = []
                        continue
                    cur.append(t)
                if cur or args:
                    args.append(cur)
                if self.call is None:
                    raise EvalError("call %s" % name)
                return self.call(name, args)
            return self.resolve(name)
        raise EvalError("unexpected %r" % (tok,))


C_TYPES = {"uint32_t", "uint64_t", "uint16_t", "uint8_t", "u32", "u64", "u16", "u8",
           "int", "unsigned", "long", "int32_t", "int64_t"}

# --------------------------------------------------------------------------
# Linux header database.


def strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", lambda m: " " * 0 + "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


class LinuxDb:
    def __init__(self, root):
        self.root = Path(root)
        # name -> list of (key, kind, payload, file)
        self.defs = defaultdict(list)
        self.missing = []
        for key, (_, files) in HEADER_SETS.items():
            for rel in files:
                path = self.root / rel
                if not path.exists():
                    self.missing.append(rel)
                    continue
                self._load(key, path)
        self.cache = {}

    def _load(self, key, path):
        raw = path.read_text(errors="replace")
        text = strip_c_comments(raw.replace("\\\n", " "))
        for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\(([^)]*)\))?[ \t]*(.*)$", text, re.M):
            name, params, body = m.group(1), m.group(3), m.group(4).strip()
            if m.group(2) is not None and text[m.start(1) + len(name)] == "(":
                self.defs[name].append((key, "fn", ([p.strip() for p in params.split(",") if p.strip()], body), path.name))
            elif body:
                self.defs[name].append((key, "obj", body, path.name))
        for m in re.finditer(r"\benum\b\s*(\w+)?\s*\{(.*?)\}", text, re.S):
            body = re.sub(r"^\s*#.*$", "", m.group(2), flags=re.M)
            prev = None
            for entry in body.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                em = re.match(r"([A-Za-z_]\w*)\s*(?:=\s*(.+))?$", entry, re.S)
                if not em:
                    continue
                name, expr = em.group(1), em.group(2)
                if expr is not None:
                    payload = expr.strip()
                elif prev is None:
                    payload = "0"
                else:
                    payload = "(%s) + 1" % prev
                self.defs[name].append((key, "enum", payload, path.name))
                prev = name

    def prepare_layouts(self, texts):
        """Compile one C probe evaluating every offsetof()/sizeof() text."""
        self.layout = {}
        texts = sorted(set(texts))
        if not texts:
            return
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub" / "linux"
            stub.mkdir(parents=True)
            for h in ("delay.h",):
                (stub / h).write_text("")
            head = [LAYOUT_PRELUDE] + ['#include "%s"' % (self.root / h) for h in LAYOUT_HEADERS]
            head.append("int main(void) {")
            live = list(range(len(texts)))
            self.layout_errors = {}
            c = Path(tmp) / "probe.c"
            exe = Path(tmp) / "probe"
            cmd = [os.environ.get("CC", "cc"), "-w", "-I", str(Path(tmp) / "stub")]
            for inc in LAYOUT_INCLUDES:
                cmd += ["-I", str(self.root / inc)]
            cmd += [str(c), "-o", str(exe)]
            for _ in range(len(texts) + 1):
                first = len("\n".join(head).split("\n")) + 1
                lines = ['    printf("%d %%llu\\n", (unsigned long long)(%s));' % (n, texts[n]) for n in live]
                c.write_text("\n".join(head + lines + ["    return 0;", "}"]) + "\n")
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode == 0:
                    break
                # Drop the probe lines the compiler rejected and retry, so one
                # bad annotation cannot hide every other layout check.
                bad = set()
                for m in re.finditer(r"probe\.c:(\d+):\d+: error: (.*)", r.stderr):
                    idx = int(m.group(1)) - first
                    if 0 <= idx < len(live):
                        bad.add(idx)
                        self.layout_errors.setdefault(texts[live[idx]], m.group(2))
                if not bad:
                    self.layout_error = r.stderr[-4000:]
                    return
                live = [n for i, n in enumerate(live) if i not in bad]
            out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout
            for line in out.splitlines():
                n, v = line.split()
                self.layout[texts[int(n)]] = int(v)

    def layout_value(self, text):
        key = LAYOUT.match(text).group(0)
        if key in getattr(self, "layout_errors", {}):
            raise EvalError("C probe rejected %s: %s" % (key, self.layout_errors[key]))
        if key not in getattr(self, "layout", {}):
            raise EvalError("layout probe failed for %s: %s" % (text, getattr(self, "layout_error", "not prepared")))
        return self.layout[key]

    def candidates(self, name, keys=None):
        out = []
        for key, kind, payload, fname in self.defs.get(name, []):
            if keys and key not in keys:
                continue
            out.append((key, kind, payload, fname))
        return out

    def value_in(self, name, key, depth=0):
        """Evaluate `name` using definitions from header set `key` (falling
        back to any set for referenced helper macros)."""
        ck = (name, key)
        if ck in self.cache:
            return self.cache[ck]
        if depth > 40:
            raise EvalError("recursion at %s" % name)
        cands = [c for c in self.defs.get(name, []) if c[0] == key and c[1] != "fn"]
        if not cands:
            cands = [c for c in self.defs.get(name, []) if c[1] != "fn"]
            if not cands:
                raise EvalError("undefined %s" % name)
        k, kind, payload, _ = cands[0]
        v = self.eval_text(payload, key, depth + 1)
        self.cache[ck] = v
        return v

    def eval_text(self, text, key, depth=0, env=None):
        env = env or {}

        def resolve(n):
            if n in env:
                return self.eval_tokens(env[n], key, depth + 1)
            return self.value_in(n, key, depth + 1)

        def call(n, args):
            fns = [c for c in self.defs.get(n, []) if c[1] == "fn"]
            fns = [c for c in fns if c[0] == key] or fns
            if not fns:
                raise EvalError("undefined macro %s()" % n)
            params, body = fns[0][2]
            if len(params) != len(args):
                raise EvalError("arity %s" % n)
            local = dict(env)
            local.update(dict(zip(params, args)))
            return self.eval_text(body, key, depth + 1, local)

        return Parser(tokenize(text), resolve, call).parse()

    def eval_tokens(self, toks, key, depth):
        return Parser(list(toks), lambda n: self.value_in(n, key, depth + 1),
                      lambda n, a: self.eval_text("%s(%s)" % (n, ",".join(detok(x) for x in a)), key, depth + 1)).parse()

    def lookup(self, name, keys=None):
        """[(key, value, file)] for every header set defining `name`."""
        out, seen = [], set()
        for key, kind, payload, fname in self.candidates(name, keys):
            if kind == "fn" or key in seen:
                continue
            seen.add(key)
            try:
                out.append((key, self.value_in(name, key), fname))
            except EvalError:
                pass
        out.sort(key=lambda r: PRIORITY.index(r[0]))
        return out


def detok(toks):
    return " ".join(str(v) for _, v in toks)

# --------------------------------------------------------------------------
# Rust source extraction.


ANNOT = re.compile(r"//+!?\s*linux:\s*(.*?)\s*$")
LIT = re.compile(r"//+!?\s*linux-lit:\s*(.*?)\s*$")
CTX = re.compile(r"//+\s*linux-ctx:\s*(.*?)\s*$")
CONST = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*([^=]+?)\s*=\s*(.*)$")
FIELD = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*:\s*(.+?),?\s*$")
INT_TYPES = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64, "i64": 64, "i32": 32, "Reg": 32}
# Auto-match prefixes: register prefixes only accept register symbols.
AUTO_PREFIXES = ["mm", "reg", "PPSMC_MSG_", "PACKET3_", "GFX_FW_TYPE_", "SOC15_IH_CLIENTID_"]
REG_PREFIXES = ("mm", "reg")


def split_code_comment(line):
    """(code, comment) ignoring `//` inside string literals."""
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and line.startswith("//", i):
            return line[:i], line[i:]
        i += 1
    return line, ""


def split_top(text, sep=","):
    parts, depth, cur = [], 0, ""
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def items_of(expr):
    """Flatten a Rust value expression into checkable items: ('reg', idx, off)
    for Reg(i, o)-style constructors, ('val', text) otherwise."""
    expr = expr.strip().rstrip(",;").strip()
    m = re.match(r"^(?:[A-Za-z_]\w*::)*Reg\s*\((.*)\)$", expr, re.S)
    if m:
        args = split_top(m.group(1))
        if len(args) == 2:
            return [("reg", args[0], args[1])]
    if (expr.startswith("(") and expr.endswith(")")) or (expr.startswith("[") and expr.endswith("]")):
        inner = expr[1:-1]
        if ";" not in inner and balanced(inner):
            parts = split_top(inner)
            if len(parts) > 1 or expr.startswith("["):
                out = []
                for p in parts:
                    out.extend(items_of(p))
                return out
    return [("val", expr)]


def balanced(text):
    depth = 0
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


class RustFile:
    def __init__(self, path):
        self.path = path
        self.lines = path.read_text().split("\n")
        self.consts = {}
        self._collect_consts()

    def _collect_consts(self):
        for i, line in enumerate(self.lines):
            code, _ = split_code_comment(line)
            m = CONST.match(code)
            if m:
                expr = self.full_expr(i, m.group(3))
                self.consts[m.group(1)] = (m.group(2).strip(), expr)

    def full_expr(self, i, start):
        expr = start
        j = i
        while not expr.rstrip().endswith(";") and j + 1 < len(self.lines) and j - i < 40:
            j += 1
            expr += " " + split_code_comment(self.lines[j])[0].strip()
        return expr.rstrip().rstrip(";")

    def eval_rust(self, text, depth=0, width=64):
        def resolve(n):
            n = n.split("::")[-1]
            if n in self.consts and depth < 20:
                ty, e = self.consts[n]
                return self.eval_rust(e, depth + 1, INT_TYPES.get(ty, 64))
            raise EvalError("unknown rust ident %s" % n)
        v = Parser(tokenize(text), resolve, None, rust=True).parse()
        return v & ((1 << width) - 1)


def classify(rf, idx):
    """Return (kind, name, type, expr) for the code on line idx."""
    code, _ = split_code_comment(rf.lines[idx])
    m = CONST.match(code)
    if m:
        return ("const", m.group(1), m.group(2).strip(), rf.full_expr(idx, m.group(3)))
    m = FIELD.match(code)
    if m and not code.strip().startswith(("let ", "pub fn", "fn ")):
        return ("field", m.group(1), None, m.group(2))
    stripped = code.strip()
    if stripped:
        return ("line", None, None, stripped)
    return None


# --------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.errors, self.warnings, self.notes = [], [], []
        self.per_file = defaultdict(lambda: defaultdict(int))
        self.unmapped = defaultdict(list)
        self.regs = []

    def err(self, where, msg):
        self.errors.append("%s: %s" % (where, msg))

    def warn(self, where, msg):
        self.warnings.append("%s: %s" % (where, msg))


def parse_annotation(text):
    text = EXPECT.sub("", text).strip()
    if text.lower().startswith("n/a"):
        return "na"
    return [e.strip() for e in text.split(";") if e.strip()]


EXPECT = re.compile(r"\s+expect:\s*\w+\s*$")
ATKEY = re.compile(r"([A-Za-z_]\w*)@([a-z0-9]+)")


def eval_linux(db, expr, ctx_keys):
    """Evaluate an annotation expression. Returns (value, register_info) where
    register_info is (sym, key, base_idx) when expr is a single register
    symbol, or wrapped by abs()/bytes()."""
    mode = None
    m = re.match(r"^(abs|bytes)\((.*)\)$", expr)
    if m:
        mode, expr = m.group(1), m.group(2).strip()
    layout = {}

    def sub_layout(mm):
        name = "__layout%d" % len(layout)
        layout[name] = db.layout_value(mm.group(0))
        return name
    expr = LAYOUT.sub(sub_layout, expr)
    pins = dict((s, k) for s, k in ATKEY.findall(expr))
    plain = ATKEY.sub(lambda mm: mm.group(1), expr)
    names = [v for t, v in tokenize(plain) if t == "id"]
    if not names or all(n in layout for n in names):
        return Parser(tokenize(plain), lambda n: layout[n]).parse(), None, []
    # Choose a header set for each top-level symbol.
    chosen, notes = {}, []
    for n in names:
        if n in layout:
            continue
        keys = [pins[n]] if n in pins else (ctx_keys or None)
        found = db.lookup(n, keys)
        if not found:
            # Maybe a function-like macro (evaluated in the first set defining it).
            fns = [c for c in db.defs.get(n, []) if c[1] == "fn" and (not keys or c[0] in keys)]
            if fns:
                chosen[n] = fns[0][0]
                continue
            raise EvalError("Linux symbol %s not found%s" % (n, " in %s" % keys if keys else ""))
        vals = set(v for _, v, _ in found)
        if len(vals) > 1 and n not in pins:
            notes.append("%s differs across header sets: %s (using %s)" % (
                n, ", ".join("%s=%#x" % (k, v) for k, v, _ in found), found[0][0]))
        chosen[n] = found[0][0]

    def resolve(n):
        if n in layout:
            return layout[n]
        return db.value_in(n, chosen.get(n, PRIORITY[0]))

    def call(n, args):
        return db.eval_text("%s(%s)" % (n, ",".join(detok(a) for a in args)), chosen.get(n, PRIORITY[0]))

    value = Parser(tokenize(plain), resolve, call).parse()
    reg = None
    if len(names) == 1 and re.fullmatch(r"\s*[A-Za-z_]\w*\s*", plain):
        sym = names[0]
        key = chosen[sym]
        bidx = db.lookup(sym + "_BASE_IDX", [key])
        if bidx:
            reg = (sym, key, bidx[0][1])
    if mode:
        if not reg:
            raise EvalError("%s() needs a register symbol with _BASE_IDX" % mode)
        ip = HEADER_SETS[reg[1]][0]
        if ip not in DISCOVERY:
            raise EvalError("no discovery base for IP %s" % ip)
        segs = DISCOVERY[ip]
        if reg[2] >= len(segs):
            raise EvalError("%s BASE_IDX %d beyond %s segments" % (reg[0], reg[2], ip))
        value = segs[reg[2]] + value
        if mode == "bytes":
            value *= 4
    return value, reg, notes


def check_file(db, path, rep, auto_symbols):
    rf = RustFile(path)
    where0 = path.name
    pending, pending_lit = [], []   # annotations waiting for the next code line
    ctx_keys, ctx_seg = None, None
    stats = rep.per_file[where0]
    annotated_lines = set()
    for i, line in enumerate(rf.lines):
        code, comment = split_code_comment(line)
        cm = CTX.search(comment)
        if cm:
            ctx_keys, ctx_seg = parse_ctx(cm.group(1), where0, i, rep)
            continue
        am = ANNOT.search(comment)
        lm = LIT.search(comment)
        if (am or lm) and not code.strip():
            if am:
                pending.append((i, am.group(1)))
            else:
                pending_lit.append((i, lm.group(1)))
            continue
        if not code.strip():
            if comment.strip().startswith("//"):
                continue  # other comment lines between annotation and code
            if pending or pending_lit:
                rep.err("%s:%d" % (where0, pending and pending[0][0] + 1 or pending_lit[0][0] + 1),
                        "annotation not followed by code")
            pending, pending_lit = [], []
            continue
        annots, lits = list(pending), list(pending_lit)
        pending, pending_lit = [], []
        if am:
            annots.append((i, am.group(1)))
        if lm:
            lits.append((i, lm.group(1)))
        if lits:
            annotated_lines.add(i)
            check_lits(db, rf, i, "; ".join(EXPECT.sub("", t) for _, t in lits), ctx_keys, rep, stats)
        if not annots:
            continue
        annotated_lines.add(i)
        exprs = []
        na = False
        for _, a in annots:
            p = parse_annotation(a)
            if p == "na":
                na = True
            else:
                exprs.extend(p)
        if na and not exprs:
            stats["n/a"] += 1
            continue
        check_line(db, rf, i, exprs, ctx_keys, ctx_seg, rep, stats)
    # Unannotated candidates: auto-match or list as unmapped.
    for i, line in enumerate(rf.lines):
        if i in annotated_lines:
            continue
        c = classify(rf, i)
        if not c:
            continue
        kind, name, ty, expr = c
        where = "%s:%d" % (where0, i + 1)
        if kind == "field":
            # Integer literal fields of const struct literals (register tables).
            if re.fullmatch(r"\s*0x[0-9a-fA-F_]+\s*,?\s*", expr) or re.fullmatch(r"\s*Reg\(.*\)\s*,?\s*", expr):
                rep.unmapped[where0].append("%d .%s = %s" % (i + 1, name, expr.strip().rstrip(",")))
                stats["unmapped"] += 1
            continue
        if kind != "const":
            continue
        base_ty = ty.strip()
        if base_ty not in INT_TYPES:
            continue
        items = items_of(expr)
        try:
            vals = [(it, eval_item(rf, it, base_ty)) for it in items]
        except EvalError:
            continue
        hit = auto_match(db, name, auto_symbols) if len(vals) == 1 else None
        if hit is None:
            if not re.search(r"[A-Za-z_]", re.sub(r"\bas [ui]\w+|\b0x[0-9a-fA-F_]+|\d[\w]*", "", expr)) \
                    or re.search(r"\b0x", expr):
                rep.unmapped[where0].append("%d %s = %s" % (i + 1, name, expr.strip()))
                stats["unmapped"] += 1
            continue
        sym, key, value, bidx = hit
        it, got = vals[0]
        width = INT_TYPES.get(base_ty, 64)
        ok = (got & mask(width)) == (value & mask(width))
        if it[0] == "reg":
            idx = rf.eval_rust(it[1])
            if bidx is not None and idx != bidx:
                ok = False
        if ok:
            stats["auto"] += 1
            if bidx is not None:
                record_reg(rep, where, sym, key, bidx, value)
        else:
            rep.err(where, "AUTO-MISMATCH %s = %s but Linux %s@%s = %#x%s (annotate the symbol it really mirrors)" % (
                name, expr.strip(), sym, key, value, "" if bidx is None else " BASE_IDX %d" % bidx))
            stats["mismatch"] += 1


def check_lits(db, rf, i, text, ctx_keys, rep, stats):
    where = "%s:%d" % (rf.path.name, i + 1)
    code = split_code_comment(rf.lines[i])[0]
    present = []
    for t, v in tokenize_loose(code):
        if t == "n":
            present.append(v)
    for part in [p.strip() for p in text.split(";") if p.strip()]:
        if "=" not in part:
            rep.err(where, "linux-lit entry `%s` needs LITERAL=EXPR" % part)
            stats["error"] += 1
            continue
        lit, e = part.split("=", 1)
        try:
            lv = Parser(tokenize(lit), lambda n: (_ for _ in ()).throw(EvalError(n))).parse()
            want, reg, notes = eval_linux(db, e.strip(), ctx_keys)
        except EvalError as ex:
            rep.err(where, "linux-lit `%s`: %s" % (part, ex))
            stats["error"] += 1
            continue
        if lv not in present:
            rep.err(where, "linux-lit literal %s not found in the code on this line" % lit.strip())
            stats["error"] += 1
        elif lv not in (want, want & mask(32), want & mask(64)):
            rep.err(where, "MISMATCH literal %s: Linux `%s` = %#x" % (lit.strip(), e.strip(), want))
            stats["mismatch"] += 1
        else:
            stats["checked"] += 1


def tokenize_loose(code):
    out = []
    for m in re.finditer(r"\b(0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*)(?:[uiUL]\w*)?\b", code):
        lit = m.group(1).replace("_", "")
        out.append(("n", int(lit, 0) if not (len(lit) > 1 and lit[0] == "0" and lit[1].isdigit()) else int(lit)))
    return out


def mask(w):
    return (1 << w) - 1


def parse_ctx(text, where, i, rep):
    if text.strip() == "reset":
        return None, None
    keys, seg = None, None
    for part in text.split():
        if part.startswith("hdr="):
            keys = part[4:].split(",")
            for k in keys:
                if k not in HEADER_SETS:
                    rep.err("%s:%d" % (where, i + 1), "unknown header set %s" % k)
        elif part.startswith("seg="):
            seg = int(part[4:], 0)
        else:
            rep.err("%s:%d" % (where, i + 1), "bad linux-ctx token %s" % part)
    return keys, seg


def eval_item(rf, it, ty):
    width = INT_TYPES.get(ty, 64) if ty else 64
    if it[0] == "reg":
        return rf.eval_rust(it[2], width=32)
    return rf.eval_rust(it[1], width=width)


def check_line(db, rf, i, exprs, ctx_keys, ctx_seg, rep, stats):
    where = "%s:%d" % (rf.path.name, i + 1)
    c = classify(rf, i)
    if c is None:
        rep.err(where, "annotation not followed by code")
        return
    kind, name, ty, expr = c
    if kind == "line":
        expr = re.sub(r"^(?:pub\s+)?(?:let\s+)?[A-Za-z_]\w*\s*(?::[^=]+)?=\s*", "", expr) if "=" in expr and "==" not in expr else expr
        expr = re.sub(r"^\s*(?:Self::)?[A-Za-z_]\w*\s*=>\s*", "", expr)
    base_ty = (ty or "").strip()
    items = items_of(expr)
    if len(items) != len(exprs):
        rep.err(where, "%d annotation expressions for %d value items in `%s`" % (len(exprs), len(items), expr.strip()))
        stats["error"] += 1
        return
    for it, e in zip(items, exprs):
        try:
            got = eval_item(rf, it, base_ty if base_ty in INT_TYPES else None)
        except EvalError as ex:
            rep.err(where, "cannot evaluate Rust value `%s`: %s" % (it[-1], ex))
            stats["error"] += 1
            continue
        try:
            want, reg, notes = eval_linux(db, e, ctx_keys)
        except EvalError as ex:
            rep.err(where, "annotation `%s`: %s" % (e, ex))
            stats["error"] += 1
            continue
        for n in notes:
            rep.notes.append("%s: %s" % (where, n))
        width = INT_TYPES.get(base_ty, 64) if it[0] != "reg" else 32
        if width == 64 and want >= 0 and got >= 0:
            width = max(want.bit_length(), got.bit_length(), 1)
        ok = (got & mask(width)) == (want & mask(width))
        detail = ""
        if it[0] == "reg":
            idx = rf.eval_rust(it[1])
            if reg is None:
                rep.err(where, "Reg(...) annotated with non-register `%s`" % e)
                ok = False
            elif idx != reg[2]:
                ok = False
                detail = " (BASE_IDX: Rust %d, Linux %d)" % (idx, reg[2])
        if reg is not None and ctx_seg is not None and it[0] != "reg" and reg[2] != ctx_seg:
            ok = False
            detail += " (code applies segment %d, Linux BASE_IDX %d)" % (ctx_seg, reg[2])
        if ok:
            stats["checked"] += 1
            if reg is not None and not e.startswith(("abs(", "bytes(")):
                record_reg(rep, where, reg[0], reg[1], reg[2], want)
        else:
            stats["mismatch"] += 1
            rep.err(where, "MISMATCH %s: Rust %#x, Linux `%s` = %#x%s" % (name or expr.strip(), got, e, want & mask(64), detail))


def record_reg(rep, where, sym, key, bidx, off):
    ip = HEADER_SETS[key][0]
    segs = DISCOVERY.get(ip)
    if segs is None:
        rep.regs.append((where, sym, key, bidx, off, None))
        return
    if bidx >= len(segs):
        rep.err(where, "%s BASE_IDX %d but %s has only %d discovery segments" % (sym, bidx, ip, len(segs)))
        return
    absd = segs[bidx] + off
    rep.regs.append((where, sym, key, bidx, off, absd))
    if absd >= BAR5_DWORDS:
        rep.warn(where, "%s resolves to dword %#x (byte %#x), outside the 1 MiB BAR5 window: needs indirect/SMN access"
                 % (sym, absd, absd * 4))


def auto_match(db, name, auto_symbols):
    hits = []
    for p in AUTO_PREFIXES:
        sym = p + name
        if sym not in auto_symbols:
            continue
        found = db.lookup(sym)
        if not found:
            continue
        key, value, _ = found[0]
        b = db.lookup(sym + "_BASE_IDX", [key])
        if p in REG_PREFIXES and not b:
            continue
        hits.append((sym, key, value, b[0][1] if b else None))
    if len(hits) != 1:
        return None
    return hits[0]


def module_files(only=None):
    files = set()
    for g in MODULE_GLOBS:
        for p in GPU_SRC.glob(g):
            if p.name.endswith("_tests.rs") or "_model" in p.name:
                continue
            files.add(p)
    files = sorted(files)
    if only:
        files = [f for f in files if any(o in f.name for o in only)]
    return files


def selftest(db, auto_symbols):
    fixture = HERE / "selftest_fixture.rs"
    lines = fixture.read_text().split("\n")
    texts = [mm.group(0) for l in lines for m in [ANNOT.search(l) or LIT.search(l)] if m
             for mm in LAYOUT.finditer(m.group(1))]
    db.prepare_layouts(texts)
    rep = Report()
    check_file(db, fixture, rep, auto_symbols)
    bad = set()
    for e in rep.errors:
        m = re.match(r"[^:]+:(\d+):", e)
        bad.add(int(m.group(1)))
    want = set()
    for i, l in enumerate(lines):
        if "expect: bad" in l:
            # A standalone annotation applies to the next code line.
            j = i
            while not split_code_comment(lines[j])[0].strip():
                j += 1
            want.add(j + 1)
    ok = bad == want
    for e in rep.errors:
        print("  " + e)
    print("selftest: %s (flagged lines %s, expected %s; %d checks passed)" % (
        "PASS" if ok else "FAIL", sorted(bad), sorted(want), rep.per_file[fixture.name]["checked"]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--linux", default=os.environ.get("LINUX_SRC", str(Path.home() / "git" / "linux")))
    ap.add_argument("--only", nargs="*", help="substring filter on module file names")
    ap.add_argument("--unmapped", action="store_true", help="list unannotated constants")
    ap.add_argument("--regs", action="store_true", help="print the resolved absolute register table")
    ap.add_argument("--notes", action="store_true", help="print header-set ambiguity notes")
    ap.add_argument("--lookup", nargs="*", help="print Linux values for symbols and exit")
    ap.add_argument("--json", help="write a machine-readable report here")
    ap.add_argument("--files", nargs="*", help="check these files instead of the Navi22 module set")
    ap.add_argument("--selftest", action="store_true",
                    help="check selftest_fixture.rs: exactly the `expect: bad` lines must fail")
    args = ap.parse_args()

    db = LinuxDb(args.linux)
    if db.missing:
        print("error: missing Linux headers under %s:\n  %s" % (args.linux, "\n  ".join(db.missing)), file=sys.stderr)
        return 2
    if args.lookup:
        for s in args.lookup:
            for key, v, f in db.lookup(s):
                b = db.lookup(s + "_BASE_IDX", [key])
                print("%-48s %-7s %#10x %s%s" % (s, key, v, f, " BASE_IDX %d" % b[0][1] if b else ""))
        return 0
    auto_symbols = set(db.defs)
    rep = Report()
    if args.selftest:
        return selftest(db, auto_symbols)
    files = [Path(f).resolve() for f in args.files] if args.files else module_files(args.only)
    if args.selftest:
        files = [HERE / "selftest_fixture.rs"]
    texts = []
    for f in files:
        for line in f.read_text().split("\n"):
            m = ANNOT.search(line) or LIT.search(line)
            if m:
                texts += [mm.group(0) for mm in LAYOUT.finditer(m.group(1))]
    db.prepare_layouts(texts)
    for f in files:
        check_file(db, f, rep, auto_symbols)

    print("navi22 constant conformance (Linux tree: %s)" % args.linux)
    print("%-40s %8s %6s %6s %8s %6s" % ("module", "checked", "auto", "n/a", "unmapped", "bad"))
    tot = defaultdict(int)
    for f in files:
        s = rep.per_file[f.name]
        bad = s["mismatch"] + s["error"]
        for k in ("checked", "auto", "n/a", "unmapped"):
            tot[k] += s[k]
        tot["bad"] += bad
        print("%-40s %8d %6d %6d %8d %6d" % (f.name, s["checked"], s["auto"], s["n/a"], s["unmapped"], bad))
    print("%-40s %8d %6d %6d %8d %6d" % ("TOTAL", tot["checked"], tot["auto"], tot["n/a"], tot["unmapped"], tot["bad"]))
    outside = [r for r in rep.regs if r[5] is not None and r[5] >= BAR5_DWORDS]
    print("registers resolved: %d (%d without a discovery base, %d outside BAR5)" % (
        len(rep.regs), sum(1 for r in rep.regs if r[5] is None), len(outside)))
    if args.regs:
        for where, sym, key, bidx, off, absd in sorted(rep.regs, key=lambda r: (r[5] or 0)):
            print("  %-44s %-6s idx%d off %#07x abs %s  %s" % (sym, key, bidx, off,
                  "%#09x" % absd if absd is not None else "   ?    ", where))
    if args.notes:
        for n in sorted(set(rep.notes)):
            print("note: " + n)
    for w in rep.warnings:
        print("warning: " + w)
    if args.unmapped:
        for f, lst in sorted(rep.unmapped.items()):
            for u in lst:
                print("unmapped: %s:%s" % (f, u))
    for e in rep.errors:
        print("error: " + e)
    if args.json:
        Path(args.json).write_text(json.dumps({
            "per_file": {k: dict(v) for k, v in rep.per_file.items()},
            "errors": rep.errors, "warnings": rep.warnings,
            "unmapped": rep.unmapped, "registers": rep.regs}, indent=1))
    print("result: %s (%d errors, %d warnings)" % ("FAIL" if rep.errors else "PASS", len(rep.errors), len(rep.warnings)))
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
