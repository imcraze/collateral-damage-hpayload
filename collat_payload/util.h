#ifndef _UTIL_H_
#define _UTIL_H_

void hex_dump(const void* data, size_t size, char* output);
char* get_error_name(DWORD errorCode);

#endif // _UTIL_H_