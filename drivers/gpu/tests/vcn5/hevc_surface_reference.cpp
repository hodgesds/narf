// SPDX-License-Identifier: MIT
// CPU-only real GFX12 Addrlib surface and address computation.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include "addrinterface.h"
#include "plane_helpers.h"
static void *allocate(const ADDR_ALLOCSYSMEM_INPUT *in) {return calloc(1,in->sizeInBytes);}
static ADDR_E_RETURNCODE release(const ADDR_FREESYSMEM_INPUT *in) {free(in->pVirtAddr);return ADDR_OK;}
static ADDR3_COMPUTE_SURFACE_INFO_OUTPUT plane(ADDR_HANDLE lib,pipe_format fmt,unsigned p,unsigned policy) {
    auto rgb=si_get_plane_format(fmt,p);
    ADDR3_COMPUTE_SURFACE_INFO_INPUT in={};in.size=sizeof(in);
    in.swizzleMode=ADDR3_LINEAR;in.resourceType=ADDR_RSRC_TEX_2D;
    in.width=util_format_get_plane_width(fmt,p,128);in.height=util_format_get_plane_height(fmt,p,128);
    in.format=ADDR_FMT_INVALID;in.bpp=bits_per_element(rgb);in.numMipLevels=in.numSlices=in.numSamples=1;
    // 0 uses Addrlib's real128-byte linear minimum. Mesa's 256-byte interop
    // policy is independently exercised as well, and is not the compact fixture.
    in.pitchInElement=policy?((in.width+policy/(in.bpp/8)-1)/(policy/(in.bpp/8)))*(policy/(in.bpp/8)):0;
    ADDR3_COMPUTE_SURFACE_INFO_OUTPUT out={};out.size=sizeof(out);
    assert(Addr3ComputeSurfaceInfo(lib,&in,&out)==ADDR_OK);
    for(unsigned y: {1u,in.height-1}) {
        ADDR3_COMPUTE_SURFACE_ADDRFROMCOORD_INPUT a={};a.size=sizeof(a);
        a.swizzleMode=in.swizzleMode;a.resourceType=in.resourceType;a.bpp=in.bpp;
        a.unAlignedDims={in.width,in.height,1};a.numMipLevels=a.numSamples=1;
        a.pitchInElement=out.pitch;a.x=in.width-1;a.y=y;
        ADDR3_COMPUTE_SURFACE_ADDRFROMCOORD_OUTPUT b={};b.size=sizeof(b);
        assert(Addr3ComputeSurfaceAddrFromCoord(lib,&a,&b)==ADDR_OK);
        assert(b.addr==(uint64_t(y)*out.pitch+a.x)*(in.bpp/8));
    }
    return out;
}
int main() {
    // Actual primary GFX1200/1201 external-revision ranges.
    for(unsigned rev: {0x40u,0x50u}) {
        ADDR_CREATE_INPUT in={};in.size=sizeof(in);in.chipEngine=0xd;in.chipFamily=0x98;in.chipRevision=rev;
        in.callbacks.allocSysMem=allocate;in.callbacks.freeSysMem=release;in.regValue.gbAddrConfig=0x545;
        ADDR_CREATE_OUTPUT out={};out.size=sizeof(out);assert(AddrCreate(&in,&out)==ADDR_OK);
        for(unsigned depth: {8u,10u})for(unsigned policy: {0u,256u}) {
            auto fmt=depth==8?PIPE_FORMAT_Y8_U8V8_420_UNORM:PIPE_FORMAT_X6Y10_X6U10X6V10_420_UNORM;
            auto y=plane(out.hLib,fmt,0,policy),uv=plane(out.hLib,fmt,1,policy);
            uint64_t offset=(y.surfSize+uv.baseAlign-1)&~uint64_t(uv.baseAlign-1);
            printf("%u %u %u %u %u %llu %llu %llu %llu %u %u %llu %llu %u %u\n",rev,depth,policy,y.pitch,uv.pitch,
                (unsigned long long)y.sliceSize,(unsigned long long)uv.sliceSize,(unsigned long long)y.surfSize,(unsigned long long)uv.surfSize,
                y.baseAlign,uv.baseAlign,(unsigned long long)offset,(unsigned long long)(offset+uv.surfSize),y.height,uv.height);
        }
        assert(AddrDestroy(out.hLib)==ADDR_OK);
    }
}
