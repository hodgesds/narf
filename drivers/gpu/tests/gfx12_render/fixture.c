/* NARF pinned Mesa26.2.4 META rectangle fixture adapter.
 * SPDX-License-Identifier: MIT */
#include "ac_cmdbuf_cp.h"
#include "ac_descriptors.h"
#include "meta/radv_meta.h"
#include "radv_cmd_buffer.h"
#include "radv_cs.h"
#include "radv_device.h"
#include "radv_entrypoints.h"
#include "radv_image.h"
#include "radv_pipeline.h"
#include "radv_queue.h"
#include "radv_shader.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern PFN_vkVoidFunction VKAPI_CALL vk_icdGetInstanceProcAddr(VkInstance,
                                                               const char *);
#include "narf_render_fixture.h"

#define BASE UINT64_C(0x2000000)
#define NGG BASE
#define PS (BASE + 0x1000)
#define UPLOAD (BASE + 0x10000)
#define DESC (BASE + 0x30000)
#define TARGET (BASE + 0x40000)
#define BORDER (BASE + 0x50000)
#define GE (BASE + 0x200000)
#define API(n) ((PFN_vk##n)vk_icdGetInstanceProcAddr(instance, "vk" #n))
#define OK(x)                                                                  \
  do {                                                                         \
    VkResult result = (x);                                                     \
    if (result != VK_SUCCESS) {                                                \
      fprintf(stderr, "%s: %d\n", #x, result);                                 \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static void words(FILE *f, const char *name, const void *bytes, unsigned size) {
  assert(!(size & 3));
  const uint32_t *p = bytes;
  fprintf(f, "\"%s\":[", name);
  for (unsigned i = 0; i < size / 4; i++)
    fprintf(f, "%s%u", i ? "," : "", p[i]);
  fputs("]", f);
}

__attribute__((visibility("default"))) int
narf_render_fixture(const char *output, unsigned target, unsigned pfp_version) {
  assert(target == 1200 || target == 1201);
  VkInstance instance;
  VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
                           .pApplicationName = "narf-render-fixture",
                           .apiVersion = VK_API_VERSION_1_3};
  VkInstanceCreateInfo ici = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
                              .pApplicationInfo = &app};
  OK(((PFN_vkCreateInstance)vk_icdGetInstanceProcAddr(
      NULL, "vkCreateInstance"))(&ici, NULL, &instance));
  uint32_t count = 1;
  VkPhysicalDevice physical;
  OK(API(EnumeratePhysicalDevices)(instance, &count, &physical));
  if (count != 1) {
    fprintf(stderr, "no DRM-shim device\n");
    return 1;
  }
  struct radv_physical_device *pdev =
      radv_physical_device_from_handle(physical);
  assert(pdev->info.family == CHIP_GFX1201 && pdev->info.gfx_level == GFX12);
  /* Explicit compiler/profile test inputs, not a recorded Navi44 board. */
  pdev->info.family = target == 1200 ? CHIP_GFX1200 : CHIP_GFX1201;
  pdev->info.max_se = pdev->info.num_se = target == 1200 ? 2 : 4;
  pdev->info.address32_hi = 0;
  pdev->info.pfp_fw_version = pfp_version;
  pdev->gfx12_hiz_wa = RADV_GFX12_HIZ_WA_FULL;
  pdev->info.pos_ring_offset =
      pdev->info.attribute_ring_size_per_se * pdev->info.max_se;
  pdev->info.prim_ring_offset = pdev->info.pos_ring_offset +
                                align(pdev->info.pos_ring_size_per_se *
                                          pdev->info.max_se * pdev->info.max_se,
                                      65536);
  pdev->info.total_attribute_pos_prim_ring_size =
      pdev->info.prim_ring_offset +
      align(pdev->info.prim_ring_size_per_se * pdev->info.max_se *
                pdev->info.max_se,
            65536);
  float priority = 0;
  VkDeviceQueueCreateInfo qi = {.sType =
                                    VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                                .queueFamilyIndex = 0,
                                .queueCount = 1,
                                .pQueuePriorities = &priority};
  VkPhysicalDeviceDynamicRenderingFeatures dr = {
      .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DYNAMIC_RENDERING_FEATURES,
      .dynamicRendering = VK_TRUE};
  VkDeviceCreateInfo di = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
                           .pNext = &dr,
                           .queueCreateInfoCount = 1,
                           .pQueueCreateInfos = &qi};
  VkDevice dev;
  OK(API(CreateDevice)(physical, &di, NULL, &dev));
  struct radv_device *device = radv_device_from_handle(dev);
  assert(device->compiler_info.key.family == CHIP_UNKNOWN);
  assert(device->compiler_info.debug.family == pdev->info.family);
  assert(device->compiler_info.hw.address32_hi == 0);
  VkPipeline pipeline;
  VkPipelineLayout layout;
  OK(narf_get_color_pipeline(device, 1, 0, VK_FORMAT_R8G8B8A8_UNORM, &pipeline,
                             &layout));
  struct radv_pipeline *pipe = radv_pipeline_from_handle(pipeline);
  struct radv_shader *vs = pipe->shaders[MESA_SHADER_VERTEX],
                     *fs = pipe->shaders[MESA_SHADER_FRAGMENT];
  assert(vs && fs && vs->info.is_ngg &&
         vs->config.scratch_bytes_per_wave == 0 &&
         fs->config.scratch_bytes_per_wave == 0);
  vs->va = NGG;
  fs->va = PS;
  if (device->border_color_data.bo)
    device->border_color_data.bo->va = BORDER;

  VkImage image;
  VkImageCreateInfo ii = {.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
                          .imageType = VK_IMAGE_TYPE_2D,
                          .format = VK_FORMAT_R8G8B8A8_UNORM,
                          .extent = {64, 64, 1},
                          .mipLevels = 1,
                          .arrayLayers = 1,
                          .samples = VK_SAMPLE_COUNT_1_BIT,
                          .tiling = VK_IMAGE_TILING_LINEAR,
                          .usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
                          .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
                          .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED};
  OK(API(CreateImage)(dev, &ii, NULL, &image));
  struct radv_image *img = radv_image_from_handle(image);
  assert(!radv_image_has_dcc(img));
  VkImageSubresource sub = {.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT};
  VkSubresourceLayout surface;
  API(GetImageSubresourceLayout)(dev, image, &sub, &surface);
  /* Validate every native readback address with Addrlib3 itself.  This is
   * deliberately a linear image, so no guessed tile/address equation enters
   * the kernel fixture, including for the explicit gfx1200 compiler input. */
  const struct ac_surf_info surf_info = {.width = 64,
                                         .height = 64,
                                         .depth = 1,
                                         .samples = 1,
                                         .storage_samples = 1,
                                         .levels = 1,
                                         .num_channels = 4,
                                         .array_size = 1};
  for (unsigned y = 0; y < 64; ++y)
    for (unsigned x = 0; x < 64; ++x)
      assert(ac_surface_addr_from_coord(pdev->addrlib, &pdev->info,
                                        &img->planes[0].surface, &surf_info, 0,
                                        x, y, 0, false) ==
             surface.offset + y * surface.rowPitch + x * 4);
  struct radeon_winsys_bo *target_bo = NULL, *ge_bo = NULL, *desc_bo = NULL;
  OK(device->ws->buffer_create(device->ws, img->size, 65536, RADEON_DOMAIN_GTT,
                               RADEON_FLAG_CPU_ACCESS, 0, 0, &target_bo));
  OK(device->ws->buffer_create(device->ws,
                               pdev->info.total_attribute_pos_prim_ring_size,
                               2 * 1024 * 1024, RADEON_DOMAIN_GTT,
                               RADEON_FLAG_CPU_ACCESS, 0, 0, &ge_bo));
  OK(device->ws->buffer_create(device->ws, 4096, 4096, RADEON_DOMAIN_GTT,
                               RADEON_FLAG_CPU_ACCESS, 0, 0, &desc_bo));
  target_bo->va = TARGET;
  ge_bo->va = GE;
  desc_bo->va = DESC;
  img->bindings[0] = (struct radv_image_binding){
      .bo = target_bo, .addr = TARGET, .range = img->size};
  VkImageView view;
  VkImageViewCreateInfo vi = {
      .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
      .image = image,
      .viewType = VK_IMAGE_VIEW_TYPE_2D,
      .format = VK_FORMAT_R8G8B8A8_UNORM,
      .subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1}};
  OK(API(CreateImageView)(dev, &vi, NULL, &view));
  VkCommandPool pool;
  VkCommandPoolCreateInfo ci = {.sType =
                                    VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
                                .queueFamilyIndex = 0};
  OK(API(CreateCommandPool)(dev, &ci, NULL, &pool));
  VkCommandBuffer command;
  VkCommandBufferAllocateInfo ai = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
      .commandPool = pool,
      .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
      .commandBufferCount = 1};
  OK(API(AllocateCommandBuffers)(dev, &ai, &command));
  struct radv_cmd_buffer *cmd = radv_cmd_buffer_from_handle(command);
  unsigned upload_offset;
  void *upload_map;
  assert(radv_cmd_buffer_upload_alloc(cmd, 16, &upload_offset, &upload_map));
  cmd->upload.upload_bo->va = UPLOAD;
  memset(cmd->upload.map, 0, cmd->upload.size);
  VkCommandBufferBeginInfo bi = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
  OK(API(BeginCommandBuffer)(command, &bi));
  radeon_check_space(device->ws, cmd->cs->b, 4096);
  radv_emit_graphics(device, cmd->cs);
  narf_emit_ge_rings(device, cmd->cs, ge_bo);
  uint32_t descriptors[128] = {0};
  narf_fill_shader_rings(device, descriptors, NULL, 0, NULL, 0, NULL, NULL,
                         NULL, NULL, ge_bo);
  narf_emit_graphics_shader_pointers(device, cmd->cs, desc_bo);

  VkRenderingAttachmentInfo attachment = {
      .sType = VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO,
      .imageView = view,
      .imageLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
      .loadOp = VK_ATTACHMENT_LOAD_OP_LOAD,
      .storeOp = VK_ATTACHMENT_STORE_OP_STORE};
  VkRenderingInfo ri = {.sType = VK_STRUCTURE_TYPE_RENDERING_INFO,
                        .renderArea = {{0, 0}, {64, 64}},
                        .layerCount = 1,
                        .colorAttachmentCount = 1,
                        .pColorAttachments = &attachment};
  API(CmdBeginRendering)(command, &ri);
  VkClearAttachment clear = {
      .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
      .colorAttachment = 0,
      .clearValue.color.float32 = {1.0f, 0.0f, 0.0f, 1.0f}};
  VkClearRect rect = {
      .rect = {{7, 11}, {29, 23}}, .baseArrayLayer = 0, .layerCount = 1};
  API(CmdClearAttachments)(command, 1, &clear, 1, &rect);
  API(CmdEndRendering)(command);
  VkMemoryBarrier2 mb = {
      .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2,
      .srcStageMask = VK_PIPELINE_STAGE_2_COLOR_ATTACHMENT_OUTPUT_BIT,
      .srcAccessMask = VK_ACCESS_2_COLOR_ATTACHMENT_WRITE_BIT,
      .dstStageMask = VK_PIPELINE_STAGE_2_HOST_BIT,
      .dstAccessMask = VK_ACCESS_2_HOST_READ_BIT};
  VkDependencyInfo dep = {.sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO,
                          .memoryBarrierCount = 1,
                          .pMemoryBarriers = &mb};
  API(CmdPipelineBarrier2)(command, &dep);
  /* Pixel completion, independent of the outer kernel job's compute EOP. */
  radeon_check_space(device->ws, cmd->cs->b, 64);
  ac_emit_cp_release_mem_pws(cmd->cs->b, GFX12, AMD_IP_GFX,
                             V_028A90_BOTTOM_OF_PIPE_TS, 0);
  ac_emit_cp_acquire_mem_pws(cmd->cs->b, GFX12, AMD_IP_GFX,
                             V_028A90_BOTTOM_OF_PIPE_TS, V_581B_CP_ME, 0, 0);
  OK(API(EndCommandBuffer)(command));
  assert(cmd->upload.offset <= 65536);
  assert(cmd->vk.state == MESA_VK_COMMAND_BUFFER_STATE_EXECUTABLE);
  FILE *f = fopen(output, "w");
  assert(f);
  fprintf(f,
          "{\"target\":%u,\"pfp_version\":%u,\"gb_addr_config\":%u,\"max_se\":%"
          "u,\"surface_size\":%" PRIu64 ",\"row_pitch\":%" PRIu64
          ",\"surface_offset\":%" PRIu64
          ",\"pixel_addresses_checked\":4096,\"swizzle\":%u,\"ge_size\":%u,"
          "\"pos_offset\":%u,\"prim_offset\":%u,\"ngg_rsrc1\":%u,\"ngg_"
          "rsrc2\":%u,\"ps_rsrc1\":%u,\"ps_rsrc2\":%u,",
          target, pfp_version, pdev->info.gb_addr_config, pdev->info.max_se,
          img->size, surface.rowPitch, surface.offset,
          img->planes[0].surface.u.gfx9.swizzle_mode,
          pdev->info.total_attribute_pos_prim_ring_size,
          pdev->info.pos_ring_offset, pdev->info.prim_ring_offset,
          vs->config.rsrc1, vs->config.rsrc2, fs->config.rsrc1,
          fs->config.rsrc2);
  words(f, "ngg", vs->code, vs->code_size);
  fputc(',', f);
  words(f, "ps", fs->code, fs->code_size);
  fputc(',', f);
  words(f, "descriptors", descriptors, sizeof(descriptors));
  fputc(',', f);
  words(f, "upload", cmd->upload.map, align(cmd->upload.offset, 4));
  fputc(',', f);
  words(f, "pm4", cmd->cs->b->buf, cmd->cs->b->cdw * 4);
  fputs("}\n", f);
  fclose(f);
  return 0;
}
