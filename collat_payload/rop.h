#ifndef _ROP_H_
#define _ROP_H_

#include <Windows.h>
#include "dict.h"
#include <WinSock2.h>

HANDLE create_dummy_thread();

void execute_ropchain(SOCKET s, HANDLE thread, UINT64 ntBase, UINT64* ropChain, SIZE_T chainSize);

dict_t get_gadget_dict();

// may take a while
dict_t scan_gadgets();


#endif // _ROP_H_