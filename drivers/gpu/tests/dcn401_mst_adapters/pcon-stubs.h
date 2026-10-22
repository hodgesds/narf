#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#define min(a,b) ((a)<(b)?(a):(b))
union hdmi_encoded_link_bw { struct { uint8_t FRL_MODE:1,BW_9Gbps:1,BW_18Gbps:1,BW_24Gbps:1,BW_32Gbps:1,BW_40Gbps:1,BW_48Gbps:1,FRL_LINK_TRAINING_FINISHED:1; } bits; uint8_t raw; };
struct dc { struct {bool dp_hdmi21_pcon_support;} caps; };
struct dc_link { struct dc *dc; };
struct dc_sink { struct {unsigned max_frl_rate,frl_dsc_max_frl_rate;} edid_caps; };
struct amdgpu_dm_connector { struct dc_link *dc_link; struct dc_sink *dc_sink; struct { struct { struct {struct {unsigned DWN_STRM_PORTX_TYPE;} bits;} byte0; struct {struct {unsigned MAX_ENCODED_LINK_BW_SUPPORT;} bits;} byte2;} bytes;} mst_downstream_port_caps; };
#define DOWN_STREAM_DETAILED_HDMI 3
static unsigned dc_link_bw_kbps_from_raw_frl_link_rate_data(struct dc *dc,unsigned r) { (void)dc; static const unsigned rates[]={0,9000000,18000000,24000000,32000000,40000000,48000000};return r<7?rates[r]:0; }
