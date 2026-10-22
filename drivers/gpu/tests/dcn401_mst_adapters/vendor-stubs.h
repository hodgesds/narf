#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#define STATIC_IFN_KUNIT static
#define drm_dbg_dp(...) ((void)0)
#define DRM_ERROR(...) ((void)0)
struct drm_dp_aux { void *drm_dev; };
struct command { unsigned char cmd; unsigned offset,length; unsigned char data[16]; };
static struct command commands[32];
static unsigned count,offset,length;
static unsigned char buffer[16],cmd;
static int drm_dp_dpcd_write(struct drm_dp_aux *aux,unsigned at,const void *data,unsigned n) {
 (void)aux;
 if(at==SYNAPTICS_RC_OFFSET) memcpy(&offset,data,4);
 else if(at==SYNAPTICS_RC_LENGTH) { length=0; memcpy(&length,data,2); }
 else if(at==SYNAPTICS_RC_DATA) memcpy(buffer,data,n);
 else if(at==SYNAPTICS_RC_COMMAND) {
  cmd=*(const unsigned char*)data & 0x7f;
  commands[count]=(struct command){cmd,offset,length,{0}};
  memcpy(commands[count++].data,buffer,16);
 }
 return (int)n;
}
static int drm_dp_dpcd_read(struct drm_dp_aux *aux,unsigned at,void *data,unsigned n) {
 (void)aux;
 memset(data,0,n);
 if(at==SYNAPTICS_RC_COMMAND) *(unsigned char*)data=cmd;
 if(at==SYNAPTICS_RC_DATA) memset(data,0xff,n);
 return (int)n;
}
static void msleep(unsigned ms) { assert(ms==10); }
