#ifndef _NT_OFFSETS
#define _NT_OFFSETS
#include <Windows.h>


// PC
//#define ORIG_SD_OFFSET 0xd55f20
//#define SD_PTR_OFFSET 0xd55658

// Xbox - 4478
#define ORIG_SD_OFFSET_4478 0xC62B8
#define SD_PTR_OFFSET_4478 0xC5A58

// Xbox - 4908/4909
#define ORIG_SD_OFFSET_4908 0xC62B8
#define SD_PTR_OFFSET_4908 0xC5A48

#define HEADER_KEYS_SIGNATURE { 0x49, 0xb9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x49, 0x8b, 0xc9, 0x48, 0xba }
// inside a randomized page :(
#define HEADER_KEY_1_OFFSET (0x264c10 + 0x120)
#define HEADER_KEY_2_OFFSET (HEADER_KEY_1_OFFSET + 0xd)


#define GET_PTE_ADDRESS_SIGNATURE { 0x48, 0xc1, 0xe9, 0xff, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x23, 0xc8, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc1 }
// works on 4909, haven't tested other versions
#define APPROX_NTOSKRNL_TEXT_OFFSET 0x206000
#define APPROX_NTOSKRNL_TEXT_SIZE 0x53a000
#define GET_PTE_ADDRESS_OFFSET 0x1efb60 // defo only 4909



VOID set_build_rev(ULONG rev);
UINT64 get_sd_ptr_offset();
UINT64 get_orig_sd_offset();


#endif
