#include "krnl_dumper.h"
#include <stdio.h>

#include "win_defs.h"
#include "util.h"



char* read_null_terminated_string(UINT64 addr) {
    // Allocate a buffer for reading data
    // Start with a reasonable initial buffer size
    SIZE_T buffer_size = 256;
    char* buffer = (char*)malloc(buffer_size);
    if (!buffer) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    // Read data from the given address
    SIZE_T offset = 0;
    char* temp_buffer = buffer;
    while (1) {
        // Read a chunk of data into the buffer
        if (krnl_read(addr + offset, temp_buffer, buffer_size - offset) != 0) {
            // If reading fails, free allocated memory and return NULL
            free(buffer);
            return NULL;
        }

        // Find the null terminator in the buffer
        char* null_terminator = (char*)memchr(temp_buffer, '\0', buffer_size - offset);
        if (null_terminator != NULL) {
            // Null terminator found, return the string
            *null_terminator = '\0'; // Ensure the string is properly null-terminated
            return buffer;
        }

        // No null terminator found, expand the buffer and continue reading
        buffer_size *= 2; // Double the buffer size
        char* new_buffer = (char*)realloc(buffer, buffer_size);
        if (!new_buffer) {
            // If realloc fails, free the old buffer and return NULL
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;
        temp_buffer = buffer + offset;
    }
}

// should get header address for ntoskrnl.exe (currently doesn't work)
// perhaps xor keys(?) change each reboot
UINT64 krnl_header_address(UINT64 baseAddress, UINT64 data) {
    UINT64 addrOfData = _byteswap_uint64(baseAddress ^ _rotl64(data ^ 0xB0837D93C0205F6E, 110)) ^ 0x1CD8854010D69B96;
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
    //sock_log(sock, "[?] dump_kmodules\n")

    HANDLE hFile = CreateFile(
        L"D:\\hpayload\\dump_modules.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        sock_log(sock, "[!] Unable to open D:\\hpayload\\dump_modules.txt, skipping kernel dump.\n");
        return;
    }

    HANDLE hForceDumpInit = CreateFile(
        L"D:\\hpayload\\force_dump_init",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    BOOL forceDumpInit = FALSE;
    if (hForceDumpInit != INVALID_HANDLE_VALUE) {
        sock_log(sock, "[?] force_dump_init found, will attempt to dump INIT segment despite discard flag.\n");
        forceDumpInit = TRUE;
        CloseHandle(hForceDumpInit);
    }

    char buffer[256];
    DWORD bytesRead;
    char line[256];
    int linePos = 0;

    CHAR ptr_msg[1024] = { 0 };

    CHAR* modules[64] = { 0 };
    int moduleCnt = 0;

    sock_log(sock, "[?] Reading requested modules... ");
    while (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        for (DWORD i = 0; i < bytesRead; i++) {
            if (buffer[i] == '\n') {
                line[linePos] = '\0';
                // potential overflow, i know, and i dont care
                modules[moduleCnt] = malloc(strlen(line) + 1);
                strcpy(modules[moduleCnt], line);
                moduleCnt++;
                linePos = 0;
            }
            else if (buffer[i] != '\r') {
                line[linePos++] = buffer[i];


            }
        }
    }

    if (linePos > 0) {
        line[linePos] = '\0'; // Null-terminate the last line if it doesn't end with a newline
        modules[moduleCnt] = malloc(strlen(line) + 1);
        strcpy(modules[moduleCnt], line);
        moduleCnt++;
    }

    sock_log(sock, "Done!\n");

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Module count: %i\n", moduleCnt);
    sock_log(sock, ptr_msg);
    sock_log(sock, "[?] Requested modules:\n");
    for (int i = 0; i < moduleCnt; i++) {
        //if (!modules[i]) sock_log(sock, "shit\n");
        sprintf_s(ptr_msg, sizeof(ptr_msg), "   - %i:%s\n", i, modules[i]);
        sock_log(sock, ptr_msg);
    }

    CloseHandle(hFile);//



    sock_log(sock, "\n[?] Attempting to grab System Module Information... ");

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

    int dmpCnt = 0;
    for (ULONG i = 0; i < pModuleInfo->NumberOfModules; i++) {
        if (dmpCnt > moduleCnt)
            break;
        char* moduleName = strrchr(pModuleInfo->Module[i].ImageName, '\\');
        if (moduleName) {
            moduleName++; // Skip the backslash character
        }
        else {
            moduleName = pModuleInfo->Module[i].ImageName;
        }

        BOOL b = FALSE;
        for (int i2 = 0; i2 < moduleCnt; i2++) {
            if (_stricmp(moduleName, modules[i2]) == 0) {
                sprintf_s(ptr_msg,
                    sizeof(ptr_msg),
                    "    - %s\n        - base_addr: 0x%llx\n        - size: %lu\n",
                    moduleName,
                    pModuleInfo->Module[i].Base,
                    pModuleInfo->Module[i].Size);
                sock_log(sock, ptr_msg);
                int res = dump_kmodule(sock, moduleName, pModuleInfo->Module[i], forceDumpInit);
                //int res = 1;
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
                dmpCnt++;
                break;
            }
            if (b)
                break;
        }

    }

    sock_log(sock, "[?] Finished.\n");
    free(pModuleInfo);



}