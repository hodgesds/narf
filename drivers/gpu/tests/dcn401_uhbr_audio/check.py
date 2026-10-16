#!/usr/bin/env python3
"""Check/generate UHBR LPCM bandwidth vectors using Linux dce_audio.c.

Extract the actual static bandwidth routines; compile with Linux's fixed31_32.
Supply the native programmed HBLANK_MIN_SYMBOL_WIDTH (not hwseq's differently
scaled derived value). These vectors check bandwidth arithmetic, not that
separate populate_audio_dp_link_info field. Run: check.py [--generate] [linux].
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--generate', action='store_true')
parser.add_argument('--mst', action='store_true', help='check legacy 8b/10b MST instead')
parser.add_argument('linux', nargs='?', default='/usr/src/linux', type=Path)
args = parser.parse_args()
here = Path(__file__).resolve().parent
display = args.linux / 'drivers/gpu/drm/amd/display'
source = (display / 'dc/dce/dce_audio.c').read_text()
helpers = source[source.index('static struct fixed31_32 get_link_symbol_clk_freq_mhz'):source.index('static void check_audio_bandwidth(\n')]
shim = r'''
#include <stdlib.h>
#include "include/fixed31_32.h"
enum dc_link_rate { LINK_RATE_LOW=6, LINK_RATE_HIGH=10, LINK_RATE_HIGH2=20,
LINK_RATE_HIGH3=30, LINK_RATE_UHBR10=1000, LINK_RATE_UHBR13_5=1350, LINK_RATE_UHBR20=2000 };
enum dp_link_encoding { DP_8b_10b_ENCODING, DP_128b_132b_ENCODING };
enum { COLOR_DEPTH_666=6, COLOR_DEPTH_888=8, COLOR_DEPTH_101010=10, COLOR_DEPTH_121212=12 };
enum { PIXEL_ENCODING_RGB, PIXEL_ENCODING_YCBCR422, PIXEL_ENCODING_YCBCR420 };
enum dc_lane_count { LANE_COUNT_ONE=1, LANE_COUNT_TWO=2, LANE_COUNT_FOUR=4 };
struct audio_crtc_info { uint32_t requested_pixel_clock_100Hz, h_total, h_active,
 dsc_bits_per_pixel, color_depth, pixel_encoding, dsc_num_slices; };
struct audio_dp_link_info { enum dc_link_rate link_rate; enum dp_link_encoding encoding;
 enum dc_lane_count lane_count; bool is_mst; uint32_t link_bandwidth_kbps, hblank_min_symbol_width; };
union audio_sample_rates { uint32_t all; struct { uint32_t RATE_32:1, RATE_44_1:1,
 RATE_48:1, RATE_88_2:1, RATE_96:1, RATE_176_4:1, RATE_192:1; } rate; };
'''
main = r'''
int main(int argc, char **argv) {
 if (argc != 8) return 2;
 struct audio_crtc_info t = {0}; struct audio_dp_link_info l = {0};
 t.requested_pixel_clock_100Hz = strtoul(argv[1], 0, 10) * 10;
 t.h_active = strtoul(argv[2], 0, 10); t.h_total = strtoul(argv[3], 0, 10);
 t.color_depth = strtoul(argv[4], 0, 10); l.link_rate = atoi(argv[5]);
 l.lane_count = atoi(argv[6]); l.encoding = DP_128b_132b_ENCODING;
 l.link_bandwidth_kbps = dc_fixpt_floor(dc_fixpt_mul(dc_fixpt_from_int(
   l.link_rate * l.lane_count * 9641), dc_fixpt_from_fraction(10000, 9975)));
 unsigned bits = t.h_active * t.color_depth * 3;
 uint64_t kbps = t.requested_pixel_clock_100Hz / 10 * t.color_depth * 3;
 kbps = (kbps * ((bits + 127) / 128) * 128 + bits - 1) / bits;
 l.hblank_min_symbol_width = (uint64_t)(t.h_total - t.h_active) * kbps /
   (t.requested_pixel_clock_100Hz / 10 * 128ull);
 union audio_sample_rates r = {.all=127};
 check_audio_bandwidth_dp(&t, &l, atoi(argv[7]), &r);
 printf("%u\n", r.all); return 0;
}
'''
if args.mst:
    start = main.index(' l.lane_count =')
    end = main.index(' union audio_sample_rates')
    main = main[:start] + r'''
 l.lane_count = atoi(argv[6]); l.encoding = DP_8b_10b_ENCODING;
 l.is_mst = true;
 /* hwseq removes FEC overhead for this pessimistic blanking budget. */
 l.link_bandwidth_kbps = l.link_rate * 27000 * 8 * l.lane_count;
''' + main[end:]
vectors = here.parent / 'dcn401_mst_audio/vectors.txt' if args.mst else here / 'vectors.txt'
with tempfile.TemporaryDirectory(prefix='narf-uhbr-audio-') as tmp:
    work = Path(tmp)
    (work / 'harness.c').write_text(shim + helpers + main)
    binary = work / 'check'
    subprocess.run(['cc', '-O1', '-w', '-include', 'os_types.h',
                    '-I' + str(here.parent / 'dcn401_dsc/include'),
                    '-I' + str(display / 'dc'), '-I' + str(display / 'dc/inc'),
                    '-I' + str(display / 'include'), '-I' + str(display),
                    str(work / 'harness.c'), str(display / 'dc/basics/fixpt31_32.c'),
                    '-o', str(binary)], check=True)
    if args.generate:
        print('# Linux check_audio_bandwidth_dp; see dcn401_uhbr_audio/check.py.')
        # Normal timings and short blanking/low-clock boundaries that filter rates.
        modes = [(27000, 720, 858), (148500, 1920, 2200), (594000, 3840, 4400),
                 (1188000, 3840, 4400), (2376000, 7680, 9000), (1333000, 3840, 3920)]
        modes += [(clock, 1920, 1920 + blank) for clock in [25000, 148500, 594000]
                  for blank in [16, 32, 64, 80, 128]]
        cases = [(*m, bpc, rate, lanes, channels) for m in modes
                 for bpc in [8, 10, 12] for rate in ([6, 10, 20, 30] if args.mst else [1000, 1350, 2000])
                 for lanes in [1, 2, 4] for channels in [2, 6, 8]]
        for case in cases:
            result = subprocess.check_output([str(binary), *map(str, case)], text=True).strip()
            print(*case, '=', result)
    else:
        passed = 0
        for line in vectors.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            inputs, expected = line.split(' = ')
            got = subprocess.check_output([str(binary), *inputs.split()], text=True).strip()
            if got != expected:
                raise SystemExit(f'MISMATCH: {line} (Linux: {got})')
            passed += 1
        print(f'{passed} matched, 0 mismatched')
