#ifndef _UTIL_H_
#define _UTIL_H_

#include <WinSock2.h>

void hex_dump(const void* data, size_t size, char* output);
char* get_error_name(DWORD errorCode);
void sock_log(SOCKET sock, char* msg);

#endif // _UTIL_H_