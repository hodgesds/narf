"""Compile verbatim primary implementations, with minimal host type stubs."""
from pathlib import Path
import sys
linux, output = map(Path, sys.argv[1:])
def function(source, name):
    end = source.index('{', source.index(name+'('))
    start = source.rfind('\nstatic ', 0, end)+1
    depth = 1
    cursor = end+1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[start:cursor]
source = (linux/'drivers/gpu/drm/amd/display/modules/freesync/freesync.c').read_text()
header = (linux/'drivers/gpu/drm/amd/display/dmub/inc/dmub_cmd.h').read_text()
structs = header[header.index('struct dmub_cmd_send_edid_cea {'):header.index('/**\n * struct dmub_cmd_cable_id_input')]
stubs = '''#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define DMUB_EDID_CEA_DATA_CHUNK_BYTES 8
#define DC_HDMI_INFOFRAME_TYPE_SPD 0x83
#pragma pack(push, 1)
struct dmub_cmd_header { uint8_t type, sub_type, flags, payload_bytes; };
'''
checks = '''
_Static_assert(sizeof(struct dmub_rb_cmd_edid_cea) == 20, "EDID_CEA command");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.input.offset) == 4, "offset");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.input.length) == 6, "length");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.input.cea_total_length) == 7, "total");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.input.payload) == 9, "payload");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.amd_vsdb.amd_vsdb_version) == 7, "version");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.amd_vsdb.min_frame_rate) == 9, "min");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.amd_vsdb.max_frame_rate) == 11, "max");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.amd_vsdb.freesync_mccs_vcp_code) == 13, "vcp");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.ack.offset) == 5, "ack offset");
_Static_assert(offsetof(struct dmub_rb_cmd_edid_cea, data.output.ack.success) == 7, "ack success");
#pragma pack(pop)
enum signal_type { SIGNAL_TYPE_HDMI_TYPE_A, SIGNAL_TYPE_DISPLAY_PORT };
enum state { VRR_STATE_UNSUPPORTED, VRR_STATE_DISABLED, VRR_STATE_INACTIVE, VRR_STATE_ACTIVE_VARIABLE, VRR_STATE_ACTIVE_FIXED };
struct mod_vrr_params { enum state state; uint32_t min_refresh_in_uhz, max_refresh_in_uhz; };
struct dc_info_packet { uint8_t hb0,hb1,hb2,hb3,sb[32]; bool valid; };
static bool dc_is_hdmi_signal(enum signal_type signal) { return signal == SIGNAL_TYPE_HDMI_TYPE_A; }
static bool dc_is_dp_signal(enum signal_type signal) { return signal == SIGNAL_TYPE_DISPLAY_PORT; }
'''
functions = '\n'.join(function(source, name) for name in ['build_vrr_infopacket_data_v1','build_vrr_infopacket_header_v1','build_vrr_infopacket_checksum','build_vrr_infopacket_v1'])
main = '''
int main(void) {
 for (unsigned hdmi=0; hdmi<2; hdmi++) for (unsigned active=0; active<2; active++) {
  struct mod_vrr_params v = {.state=active ? VRR_STATE_ACTIVE_VARIABLE : VRR_STATE_INACTIVE, .min_refresh_in_uhz=48000000,.max_refresh_in_uhz=143994000};
  struct dc_info_packet p = {0};
  build_vrr_infopacket_v1(hdmi ? SIGNAL_TYPE_HDMI_TYPE_A : SIGNAL_TYPE_DISPLAY_PORT, &v, &p, false);
  printf("%u %u", hdmi, active);
  uint8_t bytes[36] = {p.hb0,p.hb1,p.hb2,p.hb3};
  for (unsigned j=0;j<32;j++) bytes[j+4]=p.sb[j];
  for (unsigned j=0;j<36;j++) printf(" %02x", bytes[j]);
  puts("");
 }
 return 0;
}
'''
output.write_text(stubs+structs+checks+functions+main)
