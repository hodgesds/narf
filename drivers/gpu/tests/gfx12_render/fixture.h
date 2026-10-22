extern VkResult narf_get_color_pipeline(struct radv_device *, uint32_t,
                                        uint32_t, VkFormat, VkPipeline *,
                                        VkPipelineLayout *);
extern void narf_fill_shader_rings(
    struct radv_device *, uint32_t *, struct radeon_winsys_bo *, uint32_t,
    struct radeon_winsys_bo *, uint32_t, struct radeon_winsys_bo *,
    struct radeon_winsys_bo *, struct radeon_winsys_bo *,
    struct radeon_winsys_bo *, struct radeon_winsys_bo *);
extern void narf_emit_ge_rings(struct radv_device *, struct radv_cmd_stream *,
                               struct radeon_winsys_bo *);
extern void narf_emit_graphics_shader_pointers(struct radv_device *,
                                               struct radv_cmd_stream *,
                                               struct radeon_winsys_bo *);

int narf_render_fixture(const char *, unsigned, unsigned);
