#ifndef _UTIL_H_
#define _UTIL_H_

#include <WinSock2.h>

#define HEXDUMP_LINE_SIZE 74 // 9 (address) + 48 (hex bytes) + 16 (ASCII) + 1 (newline)

void hex_dump(const void* data, size_t size, char* output);
char* get_error_name(DWORD errorCode);
void sock_log(SOCKET sock, char* msg);
char* int64ToBinaryString(UINT64 value);

#endif // _UTIL_H_