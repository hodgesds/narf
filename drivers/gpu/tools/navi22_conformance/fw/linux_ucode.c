/* Linux-side expectations for the Navi22 (navy_flounder) firmware files.
 *
 * Mirrors, with the Linux structs from amdgpu_ucode.h and the enums from
 * psp_gfx_if.h / amdgpu_psp.h, what Linux computes for the same blobs:
 *   SOS   psp_init_sos_microcode + psp_init_sos_base_fw (v1.x), psp_hw_start
 *         bootloader order (KDB, SPL, SYS_DRV, SOS; psp_v11_0 has no other
 *         bootloader hooks).
 *   SMC   smu_v11_0_init_microcode + amdgpu_ucode_init_single_fw default case;
 *         smu_v11_0_set_pptable_v2_0 for the soft PPTable.
 *   GFX   amdgpu_sdma_init_microcode, gfx_v10_0_init_microcode,
 *         amdgpu_gfx_rlc_init_microcode_v2_{0..4}, amdgpu_vcn_setup_ucode,
 *         amdgpu_dm dm_dmub_sw_init; per-upload size/address from
 *         amdgpu_ucode_init_single_fw (PSP load type), skip rules from
 *         fw_load_skip_check/psp_load_non_psp_fw for MP0 11.0.11 with
 *         autoload (MEC JT skipped, SDMA1..3 skipped), type from
 *         psp_get_fw_type. Order = AMDGPU_UCODE_ID order.
 *   DMCUB dm_dmub_sw_init + dmub_srv_get_fw_meta_info_from_raw_fw.
 *
 * Usage: linux_ucode <fw-dir>   (NARF-wrapped files: trailer is stripped)
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32; typedef uint8_t u8; typedef uint16_t u16; typedef uint64_t u64;
struct mutex { int x; };
struct amdgpu_device;
struct firmware;
#define __printf(a, b)
#include "amdgpu_ucode.h"
#include "psp_gfx_if.h"

/* amdgpu_psp.h is not userspace-includable; these come from its enum
 * psp_bootloader_cmd and are cross-checked by check_constants.py. */
#define PSP_BL__LOAD_SYSDRV 0x10000
#define PSP_BL__LOAD_SOSDRV 0x20000
#define PSP_BL__LOAD_KEY_DATABASE 0x80000
#define PSP_BL__LOAD_TOS_SPL_TABLE 0x10000000
/* amdgpu_dm.c / dmub_srv.c / dmub_cmd.h */
#define PSP_HEADER_BYTES_256 0x100
#define PSP_FOOTER_BYTES_256 0x100
#define DMUB_FW_META_MAGIC 0x444D5542
#define DMUB_FW_META_OFFSET 0x24

#define le32(x) (x)
#define le16(x) (x)

static u8 *load(const char *dir, const char *name, size_t *len)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/navy_flounder_%s.bin", dir, name);
	FILE *f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "missing %s\n", path);
		exit(2);
	}
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	u8 *b = malloc(n);
	if (fread(b, 1, n, f) != (size_t)n)
		exit(2);
	fclose(f);
	/* NARF trailer: payload | sig(64) | signer(32) | meta | mlen(4) | "NRFW". */
	if (n >= 104 && !memcmp(b + n - 4, "NRFW", 4)) {
		u32 mlen;
		memcpy(&mlen, b + n - 8, 4);
		n -= 8 + mlen + 96;
	}
	*len = n;
	return b;
}

#define OFF(base, p) ((unsigned long)((const u8 *)(p) - (const u8 *)(base)))

static void sos(const char *dir)
{
	size_t n;
	u8 *b = load(dir, "sos", &n);
	const struct psp_firmware_header_v1_0 *h = (const void *)b;
	const u8 *start = b + le32(h->header.ucode_array_offset_bytes);
	struct { const char *name; u32 cmd; unsigned long off, size; } part[4];
	int count = 0;
	printf("sos header %u.%u size %lu\n", h->header.header_version_major,
	       h->header.header_version_minor, (unsigned long)n);
	if (h->header.header_version_major != 1) {
		printf("sos unsupported\n");
		return;
	}
	/* psp_init_sos_base_fw */
	unsigned long sys_off = OFF(b, start), sys_size = le32(h->sos.offset_bytes);
	unsigned long sos_off = OFF(b, start + le32(h->sos.offset_bytes)), sos_size = le32(h->sos.size_bytes);
	unsigned long kdb_off = 0, kdb_size = 0, spl_off = 0, spl_size = 0, toc_off = 0, toc_size = 0;
	printf("sos version 0x%08x\n", le32(h->header.ucode_version));
	if (h->header.header_version_minor == 1) {
		const struct psp_firmware_header_v1_1 *h1 = (const void *)b;
		toc_size = le32(h1->toc.size_bytes);
		toc_off = OFF(b, b + sys_off + le32(h1->toc.offset_bytes));
		kdb_size = le32(h1->kdb.size_bytes);
		kdb_off = OFF(b, b + sys_off + le32(h1->kdb.offset_bytes));
	}
	if (h->header.header_version_minor == 2) {
		const struct psp_firmware_header_v1_2 *h2 = (const void *)b;
		kdb_size = le32(h2->kdb.size_bytes);
		kdb_off = OFF(b, b + sys_off + le32(h2->kdb.offset_bytes));
	}
	if (h->header.header_version_minor == 3) {
		const struct psp_firmware_header_v1_3 *h3 = (const void *)b;
		toc_size = le32(h3->v1_1.toc.size_bytes);
		toc_off = OFF(b, start + le32(h3->v1_1.toc.offset_bytes));
		kdb_size = le32(h3->v1_1.kdb.size_bytes);
		kdb_off = OFF(b, start + le32(h3->v1_1.kdb.offset_bytes));
		spl_size = le32(h3->spl.size_bytes);
		spl_off = OFF(b, start + le32(h3->spl.offset_bytes));
	}
	/* psp_hw_start order; is_psp_fw_valid() == size_bytes != 0. */
	if (kdb_size)
		part[count++] = (typeof(part[0])){ "KDB", PSP_BL__LOAD_KEY_DATABASE, kdb_off, kdb_size };
	if (spl_size)
		part[count++] = (typeof(part[0])){ "SPL", PSP_BL__LOAD_TOS_SPL_TABLE, spl_off, spl_size };
	if (sys_size)
		part[count++] = (typeof(part[0])){ "SYS_DRV", PSP_BL__LOAD_SYSDRV, sys_off, sys_size };
	part[count++] = (typeof(part[0])){ "SOS", PSP_BL__LOAD_SOSDRV, sos_off, sos_size };
	for (int i = 0; i < count; i++)
		printf("sos load %s cmd 0x%08x off 0x%lx size 0x%lx\n", part[i].name, part[i].cmd,
		       part[i].off, part[i].size);
	if (toc_size)
		printf("sos toc off 0x%lx size 0x%lx\n", toc_off, toc_size);
	else
		printf("sos toc none\n");
}

static void smc(const char *dir)
{
	size_t n;
	u8 *b = load(dir, "smc", &n);
	const struct smc_firmware_header_v2_0 *h = (const void *)b;
	printf("smc header %u.%u size %lu\n", h->v1_0.header.header_version_major,
	       h->v1_0.header.header_version_minor, (unsigned long)n);
	printf("smc version 0x%08x\n", le32(h->v1_0.header.ucode_version));
	printf("smc upload type %u off 0x%x size 0x%x\n", GFX_FW_TYPE_SMU,
	       le32(h->v1_0.header.ucode_array_offset_bytes), le32(h->v1_0.header.ucode_size_bytes));
	if (h->v1_0.header.header_version_major == 2 && le32(h->ppt_size_bytes))
		printf("smc pptable off 0x%x size 0x%x\n", le32(h->ppt_offset_bytes), le32(h->ppt_size_bytes));
	else
		printf("smc pptable none\n");
}

struct upload {
	int id;
	const char *file;
	u32 type;
	unsigned long off, size;
};
static struct upload ups[64];
static int nups;

static void add(int id, const char *file, u32 type, const u8 *base, const u8 *addr, unsigned long size)
{
	if (!size) /* fw_load_skip_check: !ucode->ucode_size */
		return;
	ups[nups++] = (struct upload){ id, file, type, OFF(base, addr), size };
}

static int cmp(const void *a, const void *b)
{
	const struct upload *x = a, *y = b;
	return x->id - y->id;
}

static void gfx(const char *dir, unsigned vcn_mask)
{
	size_t n;
	nups = 0;
	/* SDMA: v1 header, duplicate=true; MP0 11.0.11 autoload skips SDMA1..3. */
	u8 *sd = load(dir, "sdma", &n);
	const struct sdma_firmware_header_v1_0 *sh = (const void *)sd;
	add(AMDGPU_UCODE_ID_SDMA0, "sdma", GFX_FW_TYPE_SDMA0, sd,
	    sd + le32(sh->header.ucode_array_offset_bytes), le32(sh->header.ucode_size_bytes));
	printf("sdma version 0x%08x\n", le32(sh->header.ucode_version));
	static const struct { const char *f; int id; u32 type; } cp[] = {
		{ "ce", AMDGPU_UCODE_ID_CP_CE, GFX_FW_TYPE_CP_CE },
		{ "pfp", AMDGPU_UCODE_ID_CP_PFP, GFX_FW_TYPE_CP_PFP },
		{ "me", AMDGPU_UCODE_ID_CP_ME, GFX_FW_TYPE_CP_ME },
		{ "mec", AMDGPU_UCODE_ID_CP_MEC1, GFX_FW_TYPE_CP_MEC },
		{ "mec2", AMDGPU_UCODE_ID_CP_MEC2, GFX_FW_TYPE_CP_MEC },
	};
	for (unsigned i = 0; i < sizeof(cp) / sizeof(cp[0]); i++) {
		u8 *b = load(dir, cp[i].f, &n);
		const struct gfx_firmware_header_v1_0 *h = (const void *)b;
		unsigned long size = le32(h->header.ucode_size_bytes);
		if (cp[i].id == AMDGPU_UCODE_ID_CP_MEC1 || cp[i].id == AMDGPU_UCODE_ID_CP_MEC2)
			size -= le32(h->jt_size) * 4; /* MEC*_JT skipped with autoload */
		add(cp[i].id, cp[i].f, cp[i].type, b, b + le32(h->header.ucode_array_offset_bytes), size);
		printf("%s version 0x%08x\n", cp[i].f, le32(h->header.ucode_version));
	}
	/* RLC */
	u8 *r = load(dir, "rlc", &n);
	const struct rlc_firmware_header_v2_0 *r0 = (const void *)r;
	u16 minor = le16(r0->header.header_version_minor);
	printf("rlc header %u.%u version 0x%08x\n", r0->header.header_version_major, minor,
	       le32(r0->header.ucode_version));
	add(AMDGPU_UCODE_ID_RLC_G, "rlc", GFX_FW_TYPE_RLC_G, r,
	    r + le32(r0->header.ucode_array_offset_bytes), le32(r0->header.ucode_size_bytes));
	if (minor >= 1) {
		const struct rlc_firmware_header_v2_1 *h = (const void *)r;
		add(AMDGPU_UCODE_ID_RLC_RESTORE_LIST_CNTL, "rlc", GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_CNTL, r,
		    r + le32(h->save_restore_list_cntl_offset_bytes), le32(h->save_restore_list_cntl_size_bytes));
		add(AMDGPU_UCODE_ID_RLC_RESTORE_LIST_GPM_MEM, "rlc", GFX_FW_TYPE_RLC_RESTORE_LIST_GPM_MEM, r,
		    r + le32(h->save_restore_list_gpm_offset_bytes), le32(h->save_restore_list_gpm_size_bytes));
		add(AMDGPU_UCODE_ID_RLC_RESTORE_LIST_SRM_MEM, "rlc", GFX_FW_TYPE_RLC_RESTORE_LIST_SRM_MEM, r,
		    r + le32(h->save_restore_list_srm_offset_bytes), le32(h->save_restore_list_srm_size_bytes));
	}
	if (minor >= 2) {
		const struct rlc_firmware_header_v2_2 *h = (const void *)r;
		add(AMDGPU_UCODE_ID_RLC_IRAM, "rlc", GFX_FW_TYPE_RLC_IRAM, r,
		    r + le32(h->rlc_iram_ucode_offset_bytes), le32(h->rlc_iram_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_RLC_DRAM, "rlc", GFX_FW_TYPE_RLC_DRAM_BOOT, r,
		    r + le32(h->rlc_dram_ucode_offset_bytes), le32(h->rlc_dram_ucode_size_bytes));
	}
	if (minor == 3) {
		const struct rlc_firmware_header_v2_3 *h = (const void *)r;
		add(AMDGPU_UCODE_ID_RLC_P, "rlc", GFX_FW_TYPE_RLC_P, r,
		    r + le32(h->rlcp_ucode_offset_bytes), le32(h->rlcp_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_RLC_V, "rlc", GFX_FW_TYPE_RLC_V, r,
		    r + le32(h->rlcv_ucode_offset_bytes), le32(h->rlcv_ucode_size_bytes));
	}
	if (minor == 4) {
		const struct rlc_firmware_header_v2_4 *h = (const void *)r;
		add(AMDGPU_UCODE_ID_GLOBAL_TAP_DELAYS, "rlc", GFX_FW_TYPE_GLOBAL_TAP_DELAYS, r,
		    r + le32(h->global_tap_delays_ucode_offset_bytes), le32(h->global_tap_delays_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_SE0_TAP_DELAYS, "rlc", GFX_FW_TYPE_SE0_TAP_DELAYS, r,
		    r + le32(h->se0_tap_delays_ucode_offset_bytes), le32(h->se0_tap_delays_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_SE1_TAP_DELAYS, "rlc", GFX_FW_TYPE_SE1_TAP_DELAYS, r,
		    r + le32(h->se1_tap_delays_ucode_offset_bytes), le32(h->se1_tap_delays_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_SE2_TAP_DELAYS, "rlc", GFX_FW_TYPE_SE2_TAP_DELAYS, r,
		    r + le32(h->se2_tap_delays_ucode_offset_bytes), le32(h->se2_tap_delays_ucode_size_bytes));
		add(AMDGPU_UCODE_ID_SE3_TAP_DELAYS, "rlc", GFX_FW_TYPE_SE3_TAP_DELAYS, r,
		    r + le32(h->se3_tap_delays_ucode_offset_bytes), le32(h->se3_tap_delays_ucode_size_bytes));
	}
	/* VCN: one upload of the whole common payload per unharvested instance. */
	u8 *v = load(dir, "vcn", &n);
	const struct common_firmware_header *vh = (const void *)v;
	printf("vcn version 0x%08x\n", le32(vh->ucode_version));
	if (vcn_mask & 1)
		add(AMDGPU_UCODE_ID_VCN, "vcn", GFX_FW_TYPE_VCN, v,
		    v + le32(vh->ucode_array_offset_bytes), le32(vh->ucode_size_bytes));
	if (vcn_mask & 2)
		add(AMDGPU_UCODE_ID_VCN1, "vcn", GFX_FW_TYPE_VCN1, v,
		    v + le32(vh->ucode_array_offset_bytes), le32(vh->ucode_size_bytes));
	/* DMCUB: PSP gets inst_const_bytes from the array offset. */
	u8 *d = load(dir, "dmcub", &n);
	const struct dmcub_firmware_header_v1_0 *dh = (const void *)d;
	add(AMDGPU_UCODE_ID_DMCUB, "dmcub", GFX_FW_TYPE_DMUB, d,
	    d + le32(dh->header.ucode_array_offset_bytes), le32(dh->inst_const_bytes));
	qsort(ups, nups, sizeof(ups[0]), cmp);
	printf("gfx vcn_mask %u\n", vcn_mask);
	for (int i = 0; i < nups; i++)
		printf("gfx upload type %u file %s off 0x%lx size 0x%lx\n", ups[i].type, ups[i].file,
		       ups[i].off, ups[i].size);
}

static const u8 *meta_from_blob(const u8 *blob, u32 size, u32 off)
{
	if (!blob || !size || size < 64 + off)
		return NULL;
	const u8 *m = blob + size - off - 64;
	u32 magic;
	memcpy(&magic, m, 4);
	return magic == DMUB_FW_META_MAGIC ? m : NULL;
}

static void dmcub(const char *dir)
{
	size_t n;
	u8 *d = load(dir, "dmcub", &n);
	const struct dmcub_firmware_header_v1_0 *h = (const void *)d;
	u32 arr = le32(h->header.ucode_array_offset_bytes);
	printf("dmcub header %u.%u ip %u.%u version 0x%08x\n", h->header.header_version_major,
	       h->header.header_version_minor, h->header.ip_version_major, h->header.ip_version_minor,
	       le32(h->header.ucode_version));
	printf("dmcub signed off 0x%x size 0x%x\n", arr, le32(h->inst_const_bytes));
	/* dm_dmub_sw_init */
	const u8 *inst = d + arr + PSP_HEADER_BYTES_256;
	u32 inst_size = le32(h->inst_const_bytes) - PSP_HEADER_BYTES_256;
	u32 bss_size = le32(h->bss_data_bytes);
	const u8 *bss = bss_size ? d + arr + le32(h->inst_const_bytes) : NULL;
	/* dmub_srv_get_fw_meta_info_from_raw_fw (no custom footer) */
	const u8 *meta = NULL;
	for (int attempt = 0; attempt < 2 && !meta; attempt++) {
		inst_size -= PSP_FOOTER_BYTES_256;
		if (bss && bss_size)
			meta = meta_from_blob(bss, bss_size, DMUB_FW_META_OFFSET);
		else
			for (u32 i = 0; i < 16 && !meta; i++)
				meta = meta_from_blob(inst, inst_size, i);
	}
	if (!meta)
		inst_size = le32(h->inst_const_bytes) - PSP_HEADER_BYTES_256 - PSP_FOOTER_BYTES_256;
	printf("dmcub inst off 0x%lx size 0x%x\n", OFF(d, inst), inst_size);
	printf("dmcub bss off 0x%lx size 0x%x\n", bss ? OFF(d, bss) : OFF(d, d + arr + le32(h->inst_const_bytes)),
	       bss_size);
	if (meta) {
		u32 w[8];
		memcpy(w, meta, 32);
		printf("dmcub meta fw_region 0x%x trace 0x%x version 0x%08x dal %u shared 0x%x features %u bits 0x%x\n",
		       w[1], w[2], w[3], meta[16], w[5], (unsigned)(w[6] & 0xffff), w[7]);
	} else {
		printf("dmcub meta none\n");
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <fw-dir>\n", argv[0]);
		return 2;
	}
	sos(argv[1]);
	smc(argv[1]);
	gfx(argv[1], 1);
	gfx(argv[1], 3);
	dmcub(argv[1]);
	return 0;
}
