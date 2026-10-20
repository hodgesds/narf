/* Compile against the unmodified Linux atomfirmware.h. */
#include <stdint.h>
#include <stddef.h>
#include "atomfirmware.h"
#define AT(type, field, value) _Static_assert(offsetof(struct type, field) == value, #type "." #field)
AT(atom_master_list_of_data_tables_v2_1, vram_info, 28 * 2);
AT(atom_vram_info_header_v2_3, vram_module_num, 20);
AT(atom_vram_info_header_v2_3, vram_module, 24);
AT(atom_vram_info_header_v2_4, vram_module_num, 20);
AT(atom_vram_info_header_v2_4, vram_module, 24);
AT(atom_vram_info_header_v2_5, vram_module_num, 20);
AT(atom_vram_info_header_v2_5, vram_module, 24);
AT(atom_vram_info_header_v2_6, vram_module_num, 20);
AT(atom_vram_info_header_v2_6, vram_module, 24);
#define MODULE(type, size, kind, channels, width) \
 AT(type, vram_module_size, size); AT(type, memory_type, kind); \
 AT(type, channel_num, channels); AT(type, channel_width, width)
MODULE(atom_vram_module_v9, 20, 23, 24, 25);
MODULE(atom_vram_module_v10, 20, 23, 24, 25);
MODULE(atom_vram_module_v11, 10, 13, 14, 15);
int main(void) { return 0; }
