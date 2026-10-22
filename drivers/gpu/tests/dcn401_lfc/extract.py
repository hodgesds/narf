"""Compile primary FreeSync BTR/preflip/VUPDATE functions verbatim.
Host stubs cover unrelated allocation, timestamp and static-ramp paths only.
No reference tree mutations or network access.
"""
from pathlib import Path
import re
import sys
linux, output = map(Path, sys.argv[1:])
source = (linux/'drivers/gpu/drm/amd/display/modules/freesync/freesync.c').read_text()
def function(name):
    pattern = re.compile(r'^(?:static )?(?:unsigned (?:long long|int)|void) '+name+r'\(', re.M)
    match = pattern.search(source)
    if not match: raise SystemExit('missing primary symbol: '+name)
    brace = source.index('{', match.start())
    pos, depth = brace+1, 1
    while depth:
        depth += (source[pos]=='{')-(source[pos]=='}')
        pos += 1
    return source[match.start():pos]
stubs = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#define BTR_DRIFT_MARGIN 2000
#define ASSERT(x) ((void)0)
#define div_u64(a,b) ((a)/(b))
#define div64_u64(a,b) ((a)/(b))
enum signal_type { SIGNAL_TYPE_DISPLAY_PORT, SIGNAL_TYPE_HDMI_TYPE_A };
enum state { VRR_STATE_INACTIVE, VRR_STATE_ACTIVE_VARIABLE, VRR_STATE_ACTIVE_FIXED };
struct dc { void *ctx; };
struct core_freesync { struct dc *dc; };
struct mod_freesync { int unused; };
static struct dc dc;
static struct core_freesync core = { .dc=&dc };
#define MOD_FREESYNC_TO_CORE(x) (&core)
struct dc_stream_state {
 enum signal_type signal;
 struct { unsigned h_total,v_total,pix_clk_100hz,min_refresh_in_uhz,max_refresh_in_uhz; } timing;
};
struct mod_vrr_params {
 bool supported;
 enum state state;
 unsigned min_refresh_in_uhz,max_refresh_in_uhz,min_duration_in_us,max_duration_in_us;
 struct { unsigned v_total_min,v_total_max; } adjust;
 struct { bool btr_active; unsigned frame_counter,frames_to_insert,inserted_duration_in_us,margin_in_us,mid_point_in_us; } btr;
 struct { unsigned vsyncs_between_flip,v_update_timestamp_in_us,flip_interval_detect_counter,vsync_to_flip_in_us;
  bool flip_interval_workaround_active,program_flip_interval_workaround,do_flip_interval_workaround_cleanup; } flip_interval;
 struct { bool ramping_active; } fixed;
};
static bool dc_is_hdmi_signal(enum signal_type s) { return s==SIGNAL_TYPE_HDMI_TYPE_A; }
static unsigned long long dm_get_timestamp(void *ctx) { (void)ctx; return 0; }
static unsigned long long dm_get_elapse_time_in_ns(void *ctx,unsigned long long a,unsigned long long b) { (void)ctx;(void)a;(void)b;return 0; }
static void update_v_total_for_static_ramp(struct core_freesync *c,const struct dc_stream_state *s,struct mod_vrr_params *v) { (void)c;(void)s;(void)v; }
'''
functions='\n'.join(function(name) for name in ['calc_duration_in_us_from_refresh_in_uhz','mod_freesync_calc_v_total_from_refresh','calc_v_total_from_duration','apply_below_the_range','mod_freesync_handle_v_update'])
main=r'''
static void row(unsigned hdmi,unsigned lo,unsigned hi,unsigned op,unsigned input,const struct mod_vrr_params *v) {
 printf("%u %u %u %u %u %u %u %u %u %u %u\n", hdmi,lo,hi,op,input,v->btr.btr_active,v->btr.inserted_duration_in_us,v->btr.frames_to_insert,v->btr.frame_counter,v->adjust.v_total_min,v->adjust.v_total_max);
}
int main(void) {
 const unsigned ranges[][2]={{48,144},{72,144},{24,144},{100,240}};
 const unsigned renders[]={6944,8500,17000,18000,19000,19500,20500,21000,24000,30000,32000,37000,42500,48000,50000,61000,75000,90000,120000,200000,1000000,12000,18000,19000,18500,18000,17000,8000};
 for (unsigned hdmi=0;hdmi<2;hdmi++) for(unsigned r=0;r<sizeof(ranges)/sizeof(*ranges);r++) {
  unsigned lo=ranges[r][0],hi=ranges[r][1];
  struct dc_stream_state s={.signal=hdmi?SIGNAL_TYPE_HDMI_TYPE_A:SIGNAL_TYPE_DISPLAY_PORT,.timing={.h_total=2720,.v_total=1497,.pix_clk_100hz=5863220}};
  unsigned nominal=(uint64_t)s.timing.pix_clk_100hz*100000000/(s.timing.h_total*s.timing.v_total);
  unsigned max=hi*1000000<nominal?hi*1000000:nominal,min=lo*1000000;
  if(hi==2*lo && hi*1000000==((nominal+50000)/100000)*100000)min=nominal/2;
  // Last range deliberately does not support this nominal mode; this
  // suite exercises BTR math only where native effective range admits it.
  if(hi<144 || lo>144 || max<2*min)continue;
  struct mod_vrr_params v={.supported=true,.state=VRR_STATE_ACTIVE_VARIABLE,.min_refresh_in_uhz=min,.max_refresh_in_uhz=max};
  v.min_duration_in_us=calc_duration_in_us_from_refresh_in_uhz(max);
  v.max_duration_in_us=calc_duration_in_us_from_refresh_in_uhz(min);
  v.btr.mid_point_in_us=(v.min_duration_in_us+v.max_duration_in_us)/2;
  unsigned margin=v.max_duration_in_us-2*v.min_duration_in_us;
  v.btr.margin_in_us=margin<2500?margin:2500;
  v.adjust.v_total_min=mod_freesync_calc_v_total_from_refresh(&s,max);
  v.adjust.v_total_max=mod_freesync_calc_v_total_from_refresh(&s,min);
  for(unsigned i=0;i<sizeof(renders)/sizeof(*renders);i++) {
   apply_below_the_range(&core,&s,renders[i],&v);row(hdmi,lo,hi,0,renders[i],&v);
   unsigned frames=v.btr.frame_counter+2;
   for(unsigned f=0;f<frames;f++) {
    mod_freesync_handle_v_update((struct mod_freesync*)&core,&s,&v);row(hdmi,lo,hi,1,0,&v);
   }
  }
 }
}
'''
output.write_text(stubs+functions+main)
