#include "krnl_dumper.h"
#include <stdio.h>

#include "win_defs.h"
#include "util.h"
#include "nt_offsets.h"
#include "ioring.h"

// grab addresses of image header structures and their items
// still doesn't work despite dynamically grabbing keys?
UINT64 krnl_header_address(UINT64 baseAddress, UINT64 data, UINT64 key1, UINT64 key2) {
    UINT64 addrOfData = _byteswap_uint64(baseAddress ^ _rotl64(data ^ key1, 110)) ^ key2;
    return addrOfData;
}

int dump_bin(SOCKET s, char* name, UINT64 base, SIZE_T size) { // just for testing
    CHAR ptr_msg[1024] = { 0 };

    char* pBuffer = (char*)malloc(size);
    for (SIZE_T i = 0; i < size; i += 0x1000) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "\r[?] Reading %s page [0x%llx]", name, base + i);
        sock_log(s, ptr_msg);
        if (krnl_read_s(base + i, pBuffer + i, 0x1000) == 0x5adface) {
            sock_log(s, " (dead page)\n");
        }
    }

    char* dumpDirectory = "D:\\hpayload\\dump_bin\\";
    size_t pathLen = strlen(dumpDirectory) + strlen(name) + 1;

    char* filePath = (char*)malloc(pathLen * sizeof(char));
    strcpy(filePath, dumpDirectory);
    strcat(filePath, name);
    strcat(filePath, ".bin");

    FILE* file = fopen(filePath, "wb");

    if (fwrite(pBuffer, 1, size, file) != size) {
        sock_log(s, "[!] Failed to write to file.\n");
        fclose(file);
        return 1;
    }

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "\n[?] Dumped binary '%s' to %s\n", name, filePath);
    sock_log(s, ptr_msg);
    fclose(file);
    free(pBuffer);
    return 0;
}

HEADER_KEYS ulpHeaderKeys;
HEADER_KEYS get_header_keys() {
    return ulpHeaderKeys;
}


// perhaps keys are per function?
void hdump_get_keys(UINT64 ntBase) {
    CHAR keySignature[] = HEADER_KEYS_SIGNATURE;
    UINT64 key1Address;
    UINT64 page = 0x0;
    do {
        key1Address = krnl_sigscan_s(ntBase + 0x200000 + page, 0x1000, keySignature, sizeof(keySignature)); // hopefully is kernel executable bounds, i really dont want to scan a whole image
        page += 0x1000;
    } while (key1Address == NULL && page < 0x58a000);
    krnl_read_s(key1Address, &ulpHeaderKeys.key1, sizeof(UINT64));
    krnl_read_s(key1Address + 0xd, &ulpHeaderKeys.key2, sizeof(UINT64));
}

void hdump_rtlimagentheaderex(SOCKET s, UINT64 ntBase) {
    CHAR ptr_msg[1024] = { 0 };
    char byteBuffer[0x10] = { 0 };
    krnl_read_s(ntBase + HEADER_KEY_1_OFFSET, byteBuffer, sizeof(byteBuffer));

    char out[256] = { 0 }; // probably should malloc this ngl
    hex_dump(byteBuffer, sizeof(byteBuffer), out);

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] RtlImageNtHeaderEx:\n%s\n", out);
    sock_log(s, ptr_msg);
}

int dump_kmodule(SOCKET s, char* name, SYSTEM_MODULE_INFORMATION_ENTRY moduleInfo) {

    // skipping, i need to get the image headers reading
    if (strcmp(name, "ntoskrnl.exe") == 0)
        return 1337; 

    CHAR ptr_msg[1024] = { 0 };
    PVOID pRegBuffer = NULL;
    pRegBuffer = 0x65007500;
    char* dumpDirectory = "D:\\hpayload\\dumped_modules\\";

    IMAGE_DOS_HEADER dosHeader;


    int ret = krnl_read_s((ULONG64)moduleInfo.Base, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    if (ret != 0) {
        sock_log(s, "[!] Failed to read DOS Header (incorrect permissions?)!\n");
        return 4;
    }
    if (!dosHeader.e_lfanew) {
        sock_log(s, "[!] Invalid DOS Header.\n");
        return 4;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid DOS Header signature: 0x%lx\n", dosHeader.e_magic);
        sock_log(s, ptr_msg);
        return 5;
    }
    sock_log(s, "[?] DOS Header validated.\n");

    IMAGE_NT_HEADERS ntHeader;
    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Reading NT Header from 0x%llx... ", (ULONG64)moduleInfo.Base + dosHeader.e_lfanew);
    sock_log(s, ptr_msg);
    krnl_read_s((ULONG64)moduleInfo.Base + dosHeader.e_lfanew, &ntHeader, sizeof(IMAGE_NT_HEADERS));
    sock_log(s, "Done!\n");

    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid NT Header signature: 0x%lx\n", dosHeader.e_magic);
        sock_log(s, ptr_msg);
        return 6;
    }

    DWORD imageSize = ntHeader.OptionalHeader.SizeOfImage;
    if (!imageSize) {
        sock_log(s, "[!] Invalid image size.\n");
        return 6;
    }

    sock_log(s, "[?] NT Header validated.\n");

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Image size: 0x%lx\n", imageSize);
    sock_log(s, ptr_msg);

    BYTE* pModuleBuffer = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pModuleBuffer == NULL) {
        sock_log(s, "[!] Failed to allocate module buffer.\n");
        return 2;
    }

    ULONG64 base = moduleInfo.Base;
    for (UINT32 page = 0x0; page < imageSize; page += 0x1000) {
        ULONG64 readAddr = base + page;
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "\r[?] Dumping page [0x%llx]", readAddr);
        sock_log(s, ptr_msg);
        krnl_read_s(readAddr, pModuleBuffer + page, 0x1000);
    }

    sock_log(s, "[?] Done!.\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid DOS Header signature: 0x%lx\n", pDosHeader->e_magic);
        sock_log(s, ptr_msg);
        VirtualFree(pModuleBuffer, imageSize, MEM_RELEASE);
        return 7;
    }

    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(pModuleBuffer + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid NT Header signature: 0x%lx\n", pNtHeader->Signature);
        sock_log(s, ptr_msg);
        VirtualFree(pModuleBuffer, imageSize, MEM_RELEASE);
        return 8;
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < ntHeader.FileHeader.NumberOfSections; ++i, section++) {
        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData = section->Misc.VirtualSize;
        

        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[?] [%s] 0x%06lX (0x%06lX)\n", section->Name, section->PointerToRawData, section->SizeOfRawData);
        sock_log(s, ptr_msg);
    }

    sock_log(s, "[?] Done.\n");

    size_t pathLen = strlen(dumpDirectory) + strlen(name) + 1;

    char* filePath = (char*)malloc(pathLen * sizeof(char));
    strcpy(filePath, dumpDirectory);
    strcat(filePath, name);

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Writing to %s... ", filePath);
    sock_log(s, ptr_msg);
    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        sock_log(s, "Failed!\n");
        VirtualFree(pModuleBuffer, 0, MEM_RELEASE);
        return GetLastError();
    }
    sock_log(s, "Done!\n");

    if (!WriteFile(hFile, pModuleBuffer, imageSize, NULL, NULL)) {
        VirtualFree(pModuleBuffer, 0, MEM_RELEASE);
        return GetLastError();
    }

    VirtualFree(pModuleBuffer, 0, MEM_RELEASE);
    CloseHandle(hFile);
    free(filePath);
    return 0;
}

void dump_kmodules(SOCKET sock) {
    if (!CreateDirectoryA("D:\\hpayload", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        sock_log(sock, "[!] Failed to create hpayload directory, skipping dump.\n");
        return;
    }

    if (!CreateDirectoryA("D:\\hpayload\\dumped_modules", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        sock_log(sock, "[!] Failed to create dump directory, skipping dump.\n");
        return;
    }

    CHAR ptr_msg[1024] = { 0 };

    sock_log(sock, "[?] Attempting to grab System Module Information... ");

    ULONG len = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (status != 0xC0000004) {
        sprintf_s(ptr_msg, sizeof(ptr_msg), "ERROR!\nFailed querying sysinfo length, error code: 0x%llx\n", status);
        sock_log(sock, ptr_msg);
        return;
    }

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(len);
    status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);
    if (status) {
        sprintf_s(ptr_msg, sizeof(ptr_msg), "ERROR!\nFailed to retrieve system module information, error code: 0x%llx\n", status);
        sock_log(sock, ptr_msg);
        free(pModuleInfo);
        return;
    }

    sock_log(sock, "Done!\n[?] time to grab modules :)\n");

    for (ULONG i = 0; i < pModuleInfo->NumberOfModules; i++) {
        char* moduleName = strrchr(pModuleInfo->Module[i].ImageName, '\\');
        if (moduleName) {
            moduleName++; 
        }
        else {
            moduleName = pModuleInfo->Module[i].ImageName;
        }

        BOOL b = FALSE;
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "    - %s\n        - base_addr: 0x%llx\n        - size: %lu\n",
            moduleName,
            pModuleInfo->Module[i].Base,
            pModuleInfo->Module[i].Size);
        sock_log(sock, ptr_msg);
        int res = dump_kmodule(sock, moduleName, pModuleInfo->Module[i]);
        if (res == 0) {
            sprintf_s(ptr_msg,
                sizeof(ptr_msg),
                "[?] %s -> D:\\dumped_modules\\%s\n",
                moduleName,
                moduleName);
            sock_log(sock, ptr_msg);
            b = TRUE;
        }
        else {
            sprintf_s(ptr_msg,
                sizeof(ptr_msg),
                "[!] Failed to dump %s, error code: 0x%llx\n",
                moduleName,
                res);
            sock_log(sock, ptr_msg);
        }
    }

    sock_log(sock, "[?] Finished.\n");
    free(pModuleInfo);
}