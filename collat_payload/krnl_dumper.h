#ifndef _KRNL_DUMPER_H_
#define _KRNL_DUMPER_H_
#include <winsock2.h>

typedef struct _HEADER_KEYS {
	UINT64 key1;
	UINT64 key2;
} HEADER_KEYS;

void dump_kmodules(SOCKET sock);
void hdump_get_keys(UINT64 ntBase);
void hdump_rtlimagentheaderex(SOCKET s, UINT64 ntBase);
UINT64 krnl_header_address(UINT64 baseAddress, UINT64 data, UINT64 key1, UINT64 key2);
HEADER_KEYS get_header_keys();

#endif // _KRNL_DUMPER_H_