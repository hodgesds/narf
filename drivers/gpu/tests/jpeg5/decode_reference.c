// SPDX-License-Identifier: GPL-2.0-or-later
// Capture unchanged IGT JPEG5 selection/builders without opening a GPU.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define AMDGPU_HW_IP_VCN_JPEG 7
#define AMDGPU_FAMILY_RV 142
#define AMDGPU_FAMILY_AI 141
#define igt_info(...) ((void)0)
typedef void *amdgpu_device_handle;
struct mmd_context {uint32_t *ib_cpu;};
struct mmd_shared_context {
    unsigned family_id,chip_id,chip_rev,vcn_ip_version_major,vcn_ip_version_minor;
    bool jpeg_direct_reg;
};
struct drm_amdgpu_info_hw_ip {unsigned hw_ip_version_major,hw_ip_version_minor,available_rings;};
static int amdgpu_query_hw_ip_info(amdgpu_device_handle device,unsigned ip,unsigned instance,
        struct drm_amdgpu_info_hw_ip *info)
{*info=(struct drm_amdgpu_info_hw_ip){5,0,1};return 0;}
#include "native_picture.h"
int main(int argc,char **argv)
{
    assert(argc==3);
    struct mmd_shared_context shared={.family_id=143};
    assert(is_jpeg_tests_enable(NULL,&shared));
    assert(shared.jpeg_direct_reg && shared.vcn_ip_version_major==5);
    uint32_t words[1024]={0},length=0;
    struct mmd_context context={words};
    send_cmd_bitstream_direct(&context,strtoull(argv[1],NULL,0),&length);
    send_cmd_target_direct(&context,strtoull(argv[2],NULL,0),&length);
    assert(length%2==0);
    while(length%16) {words[length++]=0x60000000;words[length++]=0;}
    for(unsigned n=0;n<length;n++)printf("%08x\n",words[n]);
    return 0;
}
