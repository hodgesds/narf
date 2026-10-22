// SPDX-License-Identifier: MIT
// Transport adapters only: actual libdrm and Mesa own initialization/query logic.
#include "ac_gpu_info.h"
#include "native_version.h"
#include "ac_linux_drm.h"
#include <xf86drm.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
extern void narf_init(bool);
extern int narf_dispatch(uintptr_t);
extern uint64_t narf_cap(uint64_t);
extern void narf_vcn_firmware(uint32_t);
extern void narf_media_ready(bool);
extern void narf_withdraw_vcn_firmware(void);
extern void narf_unsupported_vcn(void);
static bool hypothetical;
static bool host_accel;
static unsigned fail_query=~0u;
static unsigned fail_fw=~0u;
static unsigned info_calls;
static uint16_t device_id;

int drmGetNodeTypeFromFd(int fd){(void)fd;return DRM_NODE_RENDER;}
drmVersionPtr drmGetVersion(int fd){
    (void)fd;drmVersionPtr v=calloc(1,sizeof(*v));assert(v);
    v->version_major=NARF_DRM_MAJOR;v->version_minor=hypothetical?54:NARF_DRM_MINOR;v->version_patchlevel=NARF_DRM_PATCH;
    v->name=strdup("amdgpu");v->name_len=6;return v;
}
int drmGetCap(int fd,uint64_t cap,uint64_t*value){(void)fd;*value=narf_cap(cap);return 0;}
int drmGetDevice2(int fd,uint32_t flags,drmDevicePtr*device){
    (void)fd;(void)flags;drmDevicePtr d=calloc(1,sizeof(*d));assert(d);
    d->bustype=DRM_BUS_PCI;d->available_nodes=1<<DRM_NODE_RENDER;
    d->nodes=calloc(DRM_NODE_MAX,sizeof(char*));assert(d->nodes);d->nodes[DRM_NODE_RENDER]=strdup("/dev/dri/renderD128");
    d->businfo.pci=calloc(1,sizeof(*d->businfo.pci));d->deviceinfo.pci=calloc(1,sizeof(*d->deviceinfo.pci));assert(d->businfo.pci&&d->deviceinfo.pci);
    d->deviceinfo.pci->vendor_id=0x1002;d->deviceinfo.pci->device_id=device_id;*device=d;return 0;
}
void drmFreeDevice(drmDevicePtr *p){
    if(!p||!*p)return;
    drmDevicePtr d=*p;
    for(unsigned i=0;i<DRM_NODE_MAX;i++){free(d->nodes[i]);}
    free(d->nodes);free(d->businfo.pci);free(d->deviceinfo.pci);free(d);*p=NULL;
}
static int info(void *request){
    struct drm_amdgpu_info*r=request;++info_calls;
    uint32_t p[4];memcpy(p,(uint8_t*)r+16,sizeof(p));
    int result=(r->query==fail_query || (r->query==AMDGPU_INFO_FW_VERSION&&p[0]==fail_fw))?-EINVAL:narf_dispatch((uintptr_t)r);
    if(!result&&host_accel&&r->query==AMDGPU_INFO_ACCEL_WORKING){
        // Explicit host-only ABI envelope; this is never a production answer.
        assert(r->return_size==4);*(uint32_t*)(uintptr_t)r->return_pointer=1;
    }
    fprintf(stderr,"query=%u payload=%u,%u,%u,%u bytes=%u result=%d\n",r->query,p[0],p[1],p[2],p[3],r->return_size,result);
    return result;
}
int drmCommandWrite(int fd,unsigned long command,void *data,unsigned long size){
    (void)fd;if(command!=DRM_AMDGPU_INFO||size!=sizeof(struct drm_amdgpu_info))return -ENOTTY;return info(data);
}
int drmIoctl(int fd,unsigned long request,void *arg){
    (void)fd;if(request==DRM_IOCTL_AMDGPU_INFO){int r=info(arg);if(r){errno=-r;return -1;}return 0;}
    errno=ENOTTY;return -1;
}
int ioctl(int fd,unsigned long request,...){
    va_list ap;va_start(ap,request);void *arg=va_arg(ap,void*);va_end(ap);
    return drmIoctl(fd,request,arg);
}
int main(int argc,char **argv){
    assert(argc>=3);device_id=strcmp(argv[1],"gfx1201")==0?0x7550:0x7590;narf_init(device_id==0x7590);
    hypothetical=strcmp(argv[2],"hypothetical-3.54")==0||strcmp(argv[2],"abi-only")==0;
    host_accel=strcmp(argv[2],"hypothetical-3.54")==0||strcmp(argv[2],"accel-only")==0;
    for(int i=3;i<argc;i++){if(!strncmp(argv[i],"query=",6))fail_query=strtoul(argv[i]+6,NULL,0);else if(!strncmp(argv[i],"firmware=",9))fail_fw=strtoul(argv[i]+9,NULL,0);else if(!strncmp(argv[i],"vcn=",4))narf_vcn_firmware(strtoul(argv[i]+4,NULL,0));else if(!strcmp(argv[i],"no-media"))narf_media_ready(false);else if(!strcmp(argv[i],"withdraw-fw"))narf_withdraw_vcn_firmware();else if(!strcmp(argv[i],"unsupported-vcn"))narf_unsupported_vcn();else abort();}
    int fd=open("/dev/null",O_RDWR);assert(fd>=0);struct radeon_info gpu={0};ac_drm_device*dev=NULL;
    int init=ac_drm_device_initialize(fd,false,&gpu.drm_major,&gpu.drm_minor,&dev);
    if(init){printf("libdrm-init=%d envelope=%s query_calls=%u\n",init,argv[2],info_calls);close(fd);return 2;}
    enum ac_query_gpu_info_result result=ac_query_gpu_info(fd,dev,&gpu,true,false);
    printf("mesa-query=%d envelope=%s family=%s gfx=%u pci=%04x CU=%u SE=%u VRAM=%llu visible=%llu GTT=%llu FW_VCN=%u.%u.%u queues=%u/%u/%u/%u/%u query_calls=%u\n",
        result,argv[2],result==AC_QUERY_GPU_INFO_SUCCESS?ac_get_family_name(gpu.family):"unknown",gpu.gfx_level,device_id,gpu.num_cu,gpu.num_se,
        (unsigned long long)gpu.vram_size_kb,(unsigned long long)gpu.vram_vis_size_kb,(unsigned long long)gpu.gart_size_kb,
        gpu.vcn_dec_version,gpu.vcn_enc_major_version,gpu.vcn_enc_minor_version,
        gpu.ip[AMD_IP_GFX].num_queues,gpu.ip[AMD_IP_COMPUTE].num_queues,gpu.ip[AMD_IP_SDMA].num_queues,gpu.ip[AMD_IP_VCN_UNIFIED].num_queues,gpu.ip[AMD_IP_VCN_JPEG].num_queues,info_calls);
    ac_drm_device_deinitialize(dev);close(fd);return result==AC_QUERY_GPU_INFO_SUCCESS?0:3;
}
