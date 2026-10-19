// SPDX-License-Identifier: GPL-2.0-or-later
// Compile unchanged Linux JPEG packet constructors against capture-only stubs.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
#define IP_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define MMHUB_HWIP 0
#define GET_INST(...) 0
#define WARN_ON(n) assert(!(n))
#define AMDGPU_FENCE_FLAG_64BIT 1
#define AMDGPU_JOB_GET_VMID(job) ((job)->vmid)
#define upper_32_bits(n) ((uint32_t)((uint64_t)(n)>>32))
#define lower_32_bits(n) ((uint32_t)(n))
#define NORMALIZE_JPEG_REG_OFFSET(n) ((n)&0x1ffff)
#define AMDGPU_IB_POOL_DIRECT 0
#define AMDGPU_KERNEL_JOB_ID_VCN_RING_TEST 0
struct dma_fence {int dummy;};
struct amdgpu_ib {uint32_t *ptr; uint32_t length_dw; uint64_t gpu_addr;};
struct amdgpu_job {unsigned vmid; struct amdgpu_ib ibs[1];};
struct amdgpu_device { struct { struct {uint32_t jpeg_pitch[1];} internal; } jpeg; };
struct amdgpu_ring_funcs {bool parse_cs;};
struct amdgpu_ring {struct amdgpu_device *adev; unsigned me,pipe; uint64_t gpu_addr,wptr; const struct amdgpu_ring_funcs *funcs;};
static uint32_t captured[128], kernel_words[16];
static unsigned count;
static struct amdgpu_job job;
static struct dma_fence done;
static unsigned amdgpu_ip_version(struct amdgpu_device *adev,unsigned ip,unsigned instance) {return IP_VERSION(4,1,0);}
static bool amdgpu_sriov_vf(struct amdgpu_device *adev) {return false;}
static bool jpeg_v4_0_3_normalizn_reqd(struct amdgpu_device *adev) {return true;}
static void amdgpu_ring_write(struct amdgpu_ring *ring,uint32_t word) {assert(count<128);captured[count++]=word;}
static int amdgpu_job_alloc_with_ib(struct amdgpu_device *adev,void *vm,void *entity,
        unsigned bytes,unsigned pool,unsigned id,struct amdgpu_job **out)
{assert(bytes==sizeof(kernel_words));job.ibs[0].ptr=kernel_words;*out=&job;return 0;}
static int amdgpu_job_submit_direct(struct amdgpu_job *j,struct amdgpu_ring *ring,struct dma_fence **f)
{*f=&done;return 0;}
static struct dma_fence *dma_fence_get(struct dma_fence *f) {return f;}
static void dma_fence_put(struct dma_fence *f) {}
static void amdgpu_job_free(struct amdgpu_job *j) {}
#include "native_jpeg.h"
static void dump(const char *name,const uint32_t *words,unsigned length)
{printf("%s",name);for(unsigned i=0;i<length;i++)printf(" %08x",words[i]);puts("");}
int main(void)
{
    struct amdgpu_device adev={.jpeg.internal.jpeg_pitch[0]=regUVD_JPEG_PITCH_INTERNAL_OFFSET};
    struct amdgpu_ring_funcs funcs={.parse_cs=true};
    struct amdgpu_ring ring={.adev=&adev,.gpu_addr=0x810001000ull,.funcs=&funcs};
    jpeg_v4_0_3_dec_ring_insert_start(&ring);
    amdgpu_ring_write(&ring,PACKETJ(regUVD_JPEG_PITCH_INTERNAL_OFFSET,0,0,PACKETJ_TYPE0));
    amdgpu_ring_write(&ring,0xabadcafe);
    jpeg_v4_0_3_dec_ring_insert_end(&ring);
    dump("direct",captured,count);
    assert(amdgpu_jpeg_dec_set_reg(&ring,1,NULL)==0);
    dump("ib",job.ibs[0].ptr,job.ibs[0].length_dw);
    struct amdgpu_ib ib={.gpu_addr=0x810003000ull,.length_dw=16};
    count=0;
    jpeg_v4_0_3_dec_ring_insert_start(&ring);
    jpeg_v4_0_3_dec_ring_emit_wreg(&ring,0x7f000/4,0);
    jpeg_v4_0_3_dec_ring_emit_ib(&ring,&job,&ib,0);
    jpeg_v4_0_3_dec_ring_emit_fence(&ring,0x810002000ull,9,0);
    jpeg_v4_0_3_dec_ring_insert_end(&ring);
    dump("frame",captured,count);
    return 0;
}
