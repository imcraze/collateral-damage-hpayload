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

// works on 4909, haven't tested other versions
#define APPROX_NTOSKRNL_TEXT_OFFSET 0x206000
#define APPROX_NTOSKRNL_TEXT_SIZE 0x53a000

VOID set_build_rev(ULONG rev);
UINT64 get_sd_ptr_offset();
UINT64 get_orig_sd_offset();


#endif
