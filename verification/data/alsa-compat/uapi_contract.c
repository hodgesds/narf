/* Compile against /usr/src/linux/include/uapi, not alsa-lib's header copies.
 * These external assertions pin the 64-bit wire contract used by the ALSA bridge. */
/* Raw source headers retain annotations removed by headers_install. */
#define __EXPORTED_HEADERS__
#define __user
#define __force
#define __packed __attribute__((packed))
#include <stddef.h>
#include <sys/ioctl.h>
#include <sound/asound.h>
#include <asm-generic/errno.h>

#define SIZE(name, value) _Static_assert(sizeof(struct name) == value, #name)
#define OFFSET(name, member, value) _Static_assert(offsetof(struct name, member) == value, #name "." #member)
#define VALUE(name, value) _Static_assert(name == value, #name)

SIZE(snd_pcm_info, 288);
SIZE(snd_pcm_hw_params, 608);
SIZE(snd_pcm_sw_params, 136);
SIZE(snd_pcm_status, 152);
SIZE(snd_pcm_sync_ptr, 136);
SIZE(snd_pcm_channel_info, 24);
SIZE(snd_xferi, 24);
SIZE(snd_xfern, 24);
SIZE(snd_ctl_card_info, 376);
SIZE(snd_ctl_elem_list, 80);
SIZE(snd_ctl_elem_info, 272);
SIZE(snd_ctl_elem_value, 1224);
SIZE(snd_ctl_event, 72);
OFFSET(snd_pcm_hw_params, intervals, 260);
OFFSET(snd_pcm_hw_params, rmask, 512);
OFFSET(snd_pcm_sw_params, boundary, 64);
OFFSET(snd_pcm_sync_ptr, s, 8);
OFFSET(snd_pcm_sync_ptr, c, 72);
OFFSET(snd_ctl_elem_value, value, 72);
OFFSET(snd_ctl_elem_info, value, 80);
VALUE(SNDRV_PCM_IOCTL_HW_PARAMS, 0xc2604111U);
VALUE(SNDRV_PCM_IOCTL_SYNC_PTR, 0xc0884123U);
VALUE(SNDRV_CTL_IOCTL_ELEM_READ, 0xc4c85512U);
VALUE(EPERM, 1);
VALUE(ENOENT, 2);
VALUE(EIO, 5);
VALUE(ENXIO, 6);
VALUE(EBADF, 9);
VALUE(EAGAIN, 11);
VALUE(ENOMEM, 12);
VALUE(EACCES, 13);
VALUE(EFAULT, 14);
VALUE(EBUSY, 16);
VALUE(ENODEV, 19);
VALUE(EINVAL, 22);
VALUE(ENOTTY, 25);
VALUE(EPIPE, 32);
VALUE(ENOSYS, 38);
VALUE(EBADFD, 77);
VALUE(ESTRPIPE, 86);
VALUE(ENOPROTOOPT, 92);
VALUE(EALREADY, 114);

SIZE(snd_aes_iec958, 176);
OFFSET(snd_ctl_elem_info, value.enumerated.names_ptr, 152);
OFFSET(snd_ctl_elem_info, value.enumerated.names_length, 160);
VALUE(SNDRV_PCM_IOCTL_LINK, 0x40044160U);
VALUE(SNDRV_PCM_IOCTL_PAUSE, 0x40044145U);
VALUE(SNDRV_PCM_INFO_PAUSE, 0x80000);
VALUE(SNDRV_PCM_INFO_RESUME, 0x40000);
VALUE(SNDRV_CTL_EVENT_MASK_ADD, 4);
VALUE(SNDRV_CTL_EVENT_MASK_INFO, 2);
VALUE(SNDRV_CTL_EVENT_MASK_TLV, 8);
VALUE(SNDRV_CTL_EVENT_MASK_REMOVE, ~0U);
VALUE(ENOSPC, 28);

int main(void) { return 0; }
