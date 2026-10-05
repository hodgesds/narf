#include <alsa/asoundlib.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
extern int snd_pcm_hw_open(snd_pcm_t **, const char *, int, int, int, snd_pcm_stream_t, int, int, int);
extern int snd_ctl_hw_open(snd_ctl_t **, const char *, int, int);
#define CHECK(x) do { int err = (x); if (err < 0) { printf("ALSA FAIL %s: %d %s\n", #x, err, snd_strerror(err)); exit(1); } } while(0)
static void playback(int card, int mmap_access) {
  snd_pcm_t *p;
  CHECK(snd_pcm_hw_open(&p, "narf", card, 0, -1, SND_PCM_STREAM_PLAYBACK, 0, 0, 0));
  snd_pcm_hw_params_t *hw;
  snd_pcm_hw_params_alloca(&hw);
  CHECK(snd_pcm_hw_params_any(p, hw));
  CHECK(snd_pcm_hw_params_set_access(p, hw, mmap_access ? SND_PCM_ACCESS_MMAP_INTERLEAVED : SND_PCM_ACCESS_RW_INTERLEAVED));
  CHECK(snd_pcm_hw_params_set_format(p, hw, SND_PCM_FORMAT_S16_LE));
  CHECK(snd_pcm_hw_params_set_channels(p, hw, 2));
  CHECK(snd_pcm_hw_params_set_rate(p, hw, 48000, 0));
  snd_pcm_uframes_t period = 1024, buffer = 4096;
  CHECK(snd_pcm_hw_params_set_period_size_near(p, hw, &period, 0));
  CHECK(snd_pcm_hw_params_set_buffer_size_near(p, hw, &buffer));
  CHECK(snd_pcm_hw_params(p, hw));
  printf("ALSA configured card=%d mmap=%d period=%lu buffer=%lu\n", card, mmap_access, period, buffer);
  snd_pcm_sw_params_t *sw;
  snd_pcm_sw_params_alloca(&sw);
  CHECK(snd_pcm_sw_params_current(p, sw));
  CHECK(snd_pcm_sw_params_set_avail_min(p, sw, period));
  CHECK(snd_pcm_sw_params_set_start_threshold(p, sw, buffer));
  CHECK(snd_pcm_sw_params(p, sw));
  CHECK(snd_pcm_prepare(p));
  struct pollfd fd;
  CHECK(snd_pcm_poll_descriptors(p, &fd, 1));
  CHECK(poll(&fd, 1, 1000));
  if (!(fd.revents & POLLOUT)) { puts("ALSA FAIL poll not writable"); exit(1); }
  short samples[8192] = {0};
  snd_pcm_sframes_t written = mmap_access ? snd_pcm_mmap_writei(p, samples, buffer) : snd_pcm_writei(p, samples, buffer);
  if (written != (snd_pcm_sframes_t)buffer) { printf("ALSA FAIL write %ld\n", written); exit(1); }
  CHECK(snd_pcm_drain(p));
  CHECK(snd_pcm_close(p));
  printf("ALSA playback complete card=%d mmap=%d\n", card, mmap_access);
}
static void capture(int mmap_access) {
  snd_pcm_t *p;
  CHECK(snd_pcm_hw_open(&p, "narf-capture", 0, 0, -1,
      SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK, 0, 0));
  CHECK(snd_pcm_set_params(p, SND_PCM_FORMAT_S16_LE,
      mmap_access ? SND_PCM_ACCESS_MMAP_INTERLEAVED : SND_PCM_ACCESS_RW_NONINTERLEAVED,
      2, 48000, 0, 200000));
  CHECK(snd_pcm_start(p));
  int ready = snd_pcm_wait(p, 2000);
  if (ready <= 0) { printf("ALSA FAIL capture poll %d\n", ready); exit(1); }
  short samples[512] = {0};
  void *planes[2] = {samples, samples + 256};
  snd_pcm_sframes_t count = mmap_access ? snd_pcm_mmap_readi(p, samples, 256)
                                      : snd_pcm_readn(p, planes, 256);
  if (count != 256) { printf("ALSA FAIL capture read %ld\n", count); exit(1); }
  CHECK(snd_pcm_drop(p));
  CHECK(snd_pcm_close(p));
  printf("ALSA capture complete mmap=%d\n", mmap_access);
}
static void require_state(snd_pcm_t *p, snd_pcm_state_t state) {
  if (snd_pcm_state(p) != state) { printf("ALSA FAIL state wanted=%d actual=%d\n",state,snd_pcm_state(p)); exit(1); }
}
static void linked_pause(void) {
  snd_pcm_t *p, *c;
  CHECK(snd_pcm_hw_open(&p,"linked-playback",0,0,-1,SND_PCM_STREAM_PLAYBACK,0,0,0));
  CHECK(snd_pcm_hw_open(&c,"linked-capture",0,0,-1,SND_PCM_STREAM_CAPTURE,0,0,0));
  CHECK(snd_pcm_set_params(p,SND_PCM_FORMAT_S16_LE,SND_PCM_ACCESS_RW_INTERLEAVED,2,48000,0,200000));
  CHECK(snd_pcm_set_params(c,SND_PCM_FORMAT_S16_LE,SND_PCM_ACCESS_RW_INTERLEAVED,2,48000,0,200000));
  snd_pcm_sw_params_t *sw; snd_pcm_sw_params_alloca(&sw);
  CHECK(snd_pcm_sw_params_current(p,sw));
  snd_pcm_uframes_t boundary; CHECK(snd_pcm_sw_params_get_boundary(sw,&boundary));
  CHECK(snd_pcm_sw_params_set_start_threshold(p,sw,boundary)); CHECK(snd_pcm_sw_params(p,sw));
  CHECK(snd_pcm_link(p,c));
  short samples[8192] = {0}; CHECK(snd_pcm_writei(p,samples,4096));
  CHECK(snd_pcm_start(p)); require_state(c,SND_PCM_STATE_RUNNING);
  CHECK(snd_pcm_pause(c,1)); require_state(p,SND_PCM_STATE_PAUSED);
  CHECK(snd_pcm_pause(p,0)); require_state(c,SND_PCM_STATE_RUNNING);
  CHECK(snd_pcm_drop(c)); require_state(p,SND_PCM_STATE_SETUP);
  CHECK(snd_pcm_unlink(p));
  CHECK(snd_pcm_close(p)); CHECK(snd_pcm_close(c));
  puts("ALSA linked pause complete");
}
static void free_running(int card) {
  snd_pcm_t *p;
  CHECK(snd_pcm_hw_open(&p,"free-running",card,0,-1,SND_PCM_STREAM_PLAYBACK,0,0,0));
  CHECK(snd_pcm_set_params(p,SND_PCM_FORMAT_S16_LE,SND_PCM_ACCESS_MMAP_INTERLEAVED,2,48000,0,100000));
  snd_pcm_sw_params_t *sw; snd_pcm_sw_params_alloca(&sw);
  CHECK(snd_pcm_sw_params_current(p,sw));
  snd_pcm_uframes_t boundary; CHECK(snd_pcm_sw_params_get_boundary(sw,&boundary));
  CHECK(snd_pcm_sw_params_set_start_threshold(p,sw,boundary));
  CHECK(snd_pcm_sw_params_set_stop_threshold(p,sw,boundary));
  CHECK(snd_pcm_sw_params_set_silence_threshold(p,sw,0));
  CHECK(snd_pcm_sw_params_set_silence_size(p,sw,boundary));
  CHECK(snd_pcm_sw_params(p,sw)); CHECK(snd_pcm_prepare(p));
  CHECK(snd_pcm_start(p)); // no commits: cyclic silence must remain RUNNING
  usleep(250000);
  require_state(p,SND_PCM_STATE_RUNNING);
  CHECK(snd_pcm_pause(p,1)); require_state(p,SND_PCM_STATE_PAUSED);
  snd_pcm_sframes_t first, second;
  CHECK(snd_pcm_delay(p,&first)); usleep(20000); CHECK(snd_pcm_delay(p,&second));
  if (first != second) { puts("ALSA FAIL pointer advanced while paused"); exit(1); }
  CHECK(snd_pcm_reset(p)); require_state(p,SND_PCM_STATE_PAUSED);
  CHECK(snd_pcm_pause(p,0)); CHECK(snd_pcm_drop(p)); CHECK(snd_pcm_close(p));
  printf("ALSA free-running pause complete card=%d\n",card);
}
static void user_controls(void) {
  snd_ctl_t *c; CHECK(snd_ctl_hw_open(&c,"user-controls",0,0));
  CHECK(snd_ctl_subscribe_events(c,1));
  snd_ctl_elem_info_t *info; snd_ctl_elem_info_alloca(&info);
  snd_ctl_elem_info_set_interface(info,SND_CTL_ELEM_IFACE_MIXER);
  snd_ctl_elem_info_set_name(info,"NARF Probe Volume");
  snd_ctl_elem_info_set_read_write(info,1,1); snd_ctl_elem_info_set_tlv_read_write(info,1,1);
  CHECK(snd_ctl_add_integer_elem_set(c,info,1,2,0,100,1));
  snd_ctl_elem_id_t *id; snd_ctl_elem_id_alloca(&id); snd_ctl_elem_info_get_id(info,id);
  CHECK(snd_ctl_elem_info(c,info));
  snd_ctl_elem_value_t *value; snd_ctl_elem_value_alloca(&value);
  snd_ctl_elem_value_set_id(value,id); snd_ctl_elem_value_set_integer(value,0,25); snd_ctl_elem_value_set_integer(value,1,75);
  CHECK(snd_ctl_elem_write(c,value)); CHECK(snd_ctl_elem_read(c,value));
  if (snd_ctl_elem_value_get_integer(value,1) != 75) { puts("ALSA FAIL user control value"); exit(1); }
  unsigned int tlv[4] = {1,8,0,100}, readback[4] = {0};
  CHECK(snd_ctl_elem_tlv_write(c,id,tlv)); CHECK(snd_ctl_elem_tlv_read(c,id,readback,sizeof(readback)));
  if (memcmp(tlv,readback,sizeof(tlv))) { puts("ALSA FAIL TLV roundtrip"); exit(1); }
  snd_ctl_event_t *event; snd_ctl_event_alloca(&event); CHECK(snd_ctl_read(c,event));
  if ((snd_ctl_event_elem_get_mask(event)&15) != 15) { puts("ALSA FAIL event mask"); exit(1); }
  CHECK(snd_ctl_elem_remove(c,id));
  CHECK(snd_ctl_read(c,event));
  if (snd_ctl_event_elem_get_mask(event) != SND_CTL_EVENT_MASK_REMOVE) { puts("ALSA FAIL remove event"); exit(1); }
  const char *names[] = {"Mic","Aux"};
  snd_ctl_elem_id_set_numid(id,0); snd_ctl_elem_id_set_name(id,"NARF Probe Route");
  CHECK(snd_ctl_elem_add_enumerated(c,id,1,2,names));
  snd_ctl_elem_info_clear(info); snd_ctl_elem_info_set_id(info,id); snd_ctl_elem_info_set_item(info,1);
  CHECK(snd_ctl_elem_info(c,info));
  if (strcmp(snd_ctl_elem_info_get_item_name(info),"Aux")) { puts("ALSA FAIL enum label"); exit(1); }
  CHECK(snd_ctl_elem_remove(c,id)); CHECK(snd_ctl_close(c));
  puts("ALSA user controls complete");
}
int main(void) {
  setbuf(stdout, NULL);
  puts("ALSA probe starting");
  int cards = 0;
  for (int card=0; card<2; card++) {
    snd_ctl_t *ctl;
    int err=snd_ctl_hw_open(&ctl,"narf",card,0);
    if (err<0) continue;
    cards++;
    snd_ctl_card_info_t *info;
    snd_ctl_card_info_alloca(&info);
    CHECK(snd_ctl_card_info(ctl,info));
    printf("ALSA card %d %s\n",card,snd_ctl_card_info_get_name(info));
    snd_ctl_elem_list_t *list;
    snd_ctl_elem_list_alloca(&list);
    CHECK(snd_ctl_elem_list(ctl,list));
    printf("ALSA controls %u\n",snd_ctl_elem_list_get_count(list));
    CHECK(snd_ctl_close(ctl));
    playback(card,0);
    playback(card,1);
  }
  if (cards != 2) { printf("ALSA FAIL expected HDA and VirtIO, found %d cards\n", cards); return 1; }
  capture(0);
  capture(1);
  linked_pause();
  free_running(0);
  free_running(1);
  user_controls();
  puts("alsa-compat-ok");
  return 0;
}
