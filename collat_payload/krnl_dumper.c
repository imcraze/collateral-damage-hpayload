#include "krnl_dumper.h"
#include <stdio.h>

#include "win_defs.h"
#include "util.h"



BOOL match_sig(CHAR* buffer, CHAR* signature, SIZE_T signatureSize) {
    for (SIZE_T i = 0; i < signatureSize; i++) {
        if (signature[i] != 0xff && buffer[i] != signature[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

UINT64 kernel_sigscan(UINT64 baseAddress, UINT64 size, CHAR* signature, SIZE_T signatureSize) {
    if (baseAddress == NULL || size == 0 || signature == NULL || signatureSize == 0) 
        return NULL;
    
    CHAR* buffer = (CHAR*)malloc(size);
    if (krnl_read(baseAddress, buffer, size) != 0) {
        free(buffer);
        return NULL;
    }

    for (SIZE_T i = 0; i <= size - signatureSize; i++) {
        if (match_sig(buffer + i, signature, signatureSize)) {
            return baseAddress + i;
        }
    }

    free(buffer);
    return NULL;
}

UINT64 GetPteAddress(UINT64 virtualAddress) { // offsets from Windows 10.0.19045.4651 (will take a look at xbox ntoskrnl.exe once dumped)
    virtualAddress >>= 9;
    virtualAddress &= 0x7FFFFFFFF8;

    UINT64 pageTableAddress = 0xFFFFF68000000000;
    return pageTableAddress += virtualAddress;
}

int dump_kmodule2(SOCKET s, char* name, SYSTEM_MODULE_INFORMATION_ENTRY moduleInfo, BOOL forceDumpInit) {

    if (strcmp(name, "ntoskrnl.exe") == 0) { // will take a look at once driver dumper works for normal drivers
        sock_log(s, "[?] Skipping ntoskrnl.exe (i think it does nifty shit)\n");
        return 1337;
    }

    CHAR ptr_msg[1024] = { 0 };

    /*SIZE_T headersSize = 4096 / 2; // should contain headers
    char* headersBuffer = (char*)malloc(headersSize);
    if (!headersBuffer) {
        sock_log(s, "[!] Failed to allocate headers buffer.\n");
        return 1;
    }*/

    IMAGE_DOS_HEADER dosHeader;
    sock_log(s, "[?] Reading DOS header... ");
    if (krnl_read(moduleInfo.Base, &dosHeader, sizeof(IMAGE_DOS_HEADER)) != 0) {
        sock_log(s, "Failed!\n");
        return 2;
    }
    sock_log(s, "Done!\n");

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        sock_log(s, "[!] Invalid DOS signature.\n");
        return 2;
    }

    IMAGE_NT_HEADERS64 ntHeader;
    sock_log(s, "[?] Reading NT header... ");
    if (krnl_read((UINT64)moduleInfo.Base + dosHeader.e_lfanew, &ntHeader, sizeof(IMAGE_NT_HEADERS64)) != 0) {
        sock_log(s, "Failed!\n");
        return 2;
    }
    sock_log(s, "Done!\n");

    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        sock_log(s, "[!] Invalid NT signature.\n");
        return 2;
    }

    SIZE_T sectionHeaderTableSize = sizeof(IMAGE_SECTION_HEADER) * ntHeader.FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)malloc(sectionHeaderTableSize);
    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Reading section header table at 0x%llx... ", (UINT64)moduleInfo.Base + dosHeader.e_lfanew + 0x24 + ntHeader.FileHeader.SizeOfOptionalHeader);
    sock_log(s, ptr_msg);
    if (krnl_read((UINT64)moduleInfo.Base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), sectionHeader, sectionHeaderTableSize) != 0) {
        sock_log(s, "Failed!\n");
        return 2;
    }

    
    sock_log(s, "Done!\n");

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] logging: %s\n", sectionHeader[0].Name);
    sock_log(s, ptr_msg);


    if (!sectionHeader[0].Name) {
        free(sectionHeader);
        sock_log(s, "[!] Invalid section header.\n");
        return 2;
    }

    //sock_log(s, "Done!\n");

    char* dumpDirectory = "D:\\hpayload\\dumped_modules\\";
    size_t pathLen = strlen(dumpDirectory) + strlen(name) + 1;

    char* filePath = (char*)malloc(pathLen * sizeof(char));
    strcpy(filePath, dumpDirectory);
    strcat(filePath, name);

    FILE* file = fopen(filePath, "wb");
    if (!file) {
        sock_log(s, "[!] Failed to open output file.\n");
        free(filePath);
        free(sectionHeader);
        return 3;
    }

    /*for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) {
        //break; // skip for testing
        PIMAGE_SECTION_HEADER pSection = &sectionHeader[i];
        pSection->PointerToRawData = pSection->VirtualAddress;
        pSection->SizeOfRawData = pSection->Misc.VirtualSize;
    }*/
    
    unsigned char dosStub[] = {
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
        0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
        0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65,
        0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    SIZE_T richHeaderAndPadSize = dosHeader.e_lfanew - (sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub));
    char* richHeaderAndPad = (char*)malloc(richHeaderAndPadSize);
    if (krnl_read((UINT64)moduleInfo.Base + (sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub)), richHeaderAndPad, richHeaderAndPadSize) != 0) {
        sock_log(s, "[!] Failed to read rich header!\n");

        free(richHeaderAndPad);
        free(filePath);
        free(sectionHeader);
        return 2;
    }

    SIZE_T headerSize = sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub) + richHeaderAndPadSize + sizeof(IMAGE_NT_HEADERS64) + sectionHeaderTableSize;
    char* headers = (char*)malloc(headerSize);
    memcpy(headers, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    memcpy(headers + sizeof(IMAGE_DOS_HEADER), dosStub, sizeof(dosStub));
    memcpy(headers + sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub), richHeaderAndPad, richHeaderAndPadSize);
    memcpy(headers + sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub) + richHeaderAndPadSize, &ntHeader, sizeof(IMAGE_NT_HEADERS64));
    memcpy(headers + sizeof(IMAGE_DOS_HEADER) + sizeof(dosStub) + richHeaderAndPadSize + sizeof(IMAGE_NT_HEADERS64), sectionHeader, sectionHeaderTableSize);
    
    if (fwrite(headers, 1, headerSize, file) != headerSize) {
        sock_log(s, "[!] Failed to headers write to output file.\n");
        fclose(file);
        free(headers);
        free(richHeaderAndPad);
        free(filePath);
        free(sectionHeader);
        return 4;
    }

    
    
    free(headers);
    free(richHeaderAndPad);
    


    //PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    //PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((char*)pDosHeader + pDosHeader->e_lfanew);
    //PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((char*)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    sock_log(s, "[?] Dumping sections...\n");
    for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) { // TODO: segments being doubled for some reason?? also, file header is malformed, check header code
        //break; // skip for testing
        PIMAGE_SECTION_HEADER pSection = &sectionHeader[i];
        UINT64 sectionStart = (UINT64)moduleInfo.Base + pSection->VirtualAddress;
        SIZE_T sectionSize = pSection->Misc.VirtualSize;
        
        if ((pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) { // look into MiGetPteAddress, perhaps remnants of discarded sections can be found? otherwise we're out of luck
            //if (!(forceDumpInit && strcmp(pSection->Name, "INIT") == 0)) {
                sprintf_s(ptr_msg,
                    sizeof(ptr_msg),
                    "[?] [%s/0x%llx/%zu] (discarded)\n", pSection->Name, sectionStart, sectionSize);
                sock_log(s, ptr_msg);
                continue;
            //}
        }

        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[?] [%s/0x%llx/%zu]\n", pSection->Name, sectionStart, sectionSize);
        sock_log(s, ptr_msg);
 
        /*if (strcmp(pSection->Name, "GFIDS") == 0 || strcmp(pSection->Name, ".rsrc") == 0 || strcmp(pSection->Name, ".reloc") == 0) {
            //sock_log(s, "[?] Skipping GFIDS.\n");
            sprintf_s(ptr_msg,
                sizeof(ptr_msg),
                "[?] Skipping %s (to avoid crash?)\n", pSection->Name);
            sock_log(s, ptr_msg);
            char* nullSection = (char*)calloc(sectionSize, 1);
            fwrite(nullSection, 1, sizeof(nullSection), file);
            free(nullSection);
            continue;
        }*/

        char* sectionBuffer = (char*)malloc(sectionSize);
        if (!sectionBuffer) {
            sock_log(s, "[!] Failed to allocation section buffer.\n");
            fclose(file);
            free(sectionHeader);
            return 5;
        }

        if (krnl_read(sectionStart, sectionBuffer, sectionSize) != 0) {
            sock_log(s, "[!] Failed to read section.\n");
            free(sectionBuffer);
            fclose(file);
            free(sectionHeader);
            return 6;
        }

        
        fseek(file, pSection->VirtualAddress, SEEK_SET);
        if (fwrite(sectionBuffer, 1, sectionSize, file) != sectionSize) {
            sock_log(s, "[!] Failed to write section to file\n");
            free(sectionBuffer);
            fclose(file);
            free(sectionHeader);
            return 7;
        }

        free(sectionBuffer);
        
    }

    fclose(file);
    free(filePath);
    free(sectionHeader);
    return 0;
}


int dump_kmodule(SOCKET s, char* name, SYSTEM_MODULE_INFORMATION_ENTRY moduleInfo) {

    CHAR ptr_msg[1024] = { 0 };
    PVOID pRegBuffer = NULL;
    pRegBuffer = 0x65007500;
    char* dumpDirectory = "D:\\hpayload\\dumped_modules\\";

    IMAGE_DOS_HEADER dosHeader;


    int ret = ioring_read(pRegBuffer, (ULONG64)moduleInfo.Base, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    if (ret != 0) {
        sock_log(s, "[!] ioring_read failed whilst reading DOS Header!\n");
        return 4;
    }
    if (!dosHeader.e_lfanew) {
        sock_log(s, "[!] Invalid DOS Header.\n");
        return 4;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { // ignore dos header?
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid DOS Header signature: 0x%lx\n", dosHeader.e_magic);
        sock_log(s, ptr_msg);
        return 5;
    }
    sock_log(s, "[?] DOS Header read and validated.\n");
    if (name == "ntoskrnl.exe") { // will take a look at once driver dumper works for normal drivers
        sock_log(s, "[?] Skipping ntoskrnl.exe (i think it does nifty shit)\n");
        return 9;
    }

    IMAGE_NT_HEADERS ntHeader;
    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Reading NT Header from 0x%llx... ", (ULONG64)moduleInfo.Base + dosHeader.e_lfanew);
    sock_log(s, ptr_msg);
    krnl_read((ULONG64)((ULONG64)moduleInfo.Base + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS));
    sock_log(s, "Done!\n");

    //char ntHexDump[4096*2] = { 0 };
    //hex_dump(&ntHeader, sizeof(ntHeader), ntHexDump);

    //sprintf_s(ptr_msg,
    //    sizeof(ptr_msg),
    //    "[?] NT Header dump:\n%s\n", ntHexDump);
    //sock_log(s, ptr_msg);

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

    sock_log(s, "[?] NT Header read and validated.\n");

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "[?] Image size: 0x%lx\n", imageSize);
    sock_log(s, ptr_msg);

    BYTE* pModuleBuffer = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pModuleBuffer == NULL) {
        sock_log(s, "[!] Failed to allocate module buffer.\n");
        return 2;
    }

    BYTE* testBuffer = (BYTE*)VirtualAlloc(NULL, 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


    ULONG64 base = moduleInfo.Base;
    sock_log(s, "[!] Testing read.\n");
    krnl_read(base + 0xa000, testBuffer, 1);
    sock_log(s, "[!] Test read success, dumping.\n");
    char ntHexDump[4096 * 2] = { 0 };
    hex_dump(testBuffer, sizeof(testBuffer), ntHexDump);

    sprintf_s(ptr_msg,
        sizeof(ptr_msg),
        "%s\n", ntHexDump);
    sock_log(s, ptr_msg);

    for (UINT32 page = 0x0; page < ntHeader.OptionalHeader.SizeOfImage; page += 0x1000) {
        if (page > 0x8000) // doing a little dump first, will fix this later
            break;
        ULONG64 readAddr = base + page;
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[?] Reading page from 0x%llx... ", readAddr);
        sock_log(s, ptr_msg);
        int res = krnl_read(readAddr, pModuleBuffer + page, 0x1000);
        sock_log(s, "Done!\n");
        if (res != 0) {
            sprintf_s(ptr_msg,
                sizeof(ptr_msg),
                "[!] Failed to read section: 0x%lx [ERR:0x%llx]\n", page, res);
            sock_log(s, ptr_msg);
        }
    }

    sock_log(s, "[?] horray.\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid DOS Header signature: 0x%lx\n", pDosHeader->e_magic);
        sock_log(s, ptr_msg);
        VirtualFree(pModuleBuffer, imageSize, MEM_RELEASE);
        return 7;
    }

    sock_log(s, "[?] DOS Header validated.\n");

    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(pModuleBuffer + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[!] Invalid NT Header signature: 0x%lx\n", pNtHeader->Signature);
        sock_log(s, ptr_msg);
        VirtualFree(pModuleBuffer, imageSize, MEM_RELEASE);
        return 8;
    }

    sock_log(s, "[?] NT Header validated.\n");

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);

    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, section++) {

        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData = section->Misc.VirtualSize;

        sprintf_s(ptr_msg,
            sizeof(ptr_msg),
            "[?] [%s] 0x%06lX (0x%06lX)\n", section->Name, section->PointerToRawData, section->SizeOfRawData);
        sock_log(s, ptr_msg);
    }

    sock_log(s, "[?] Done.\n");

    //char* dumpDirectory = "D:\\hpayload\\dumped_modules\\";

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

    if (!WriteFile(hFile, pModuleBuffer, 0x8000, NULL, NULL)) {
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

        if (0 && _stricmp(moduleName, "ntoskrnl.exe")) { // need to iterate through sections and only read .text otherwise crash. therefore, i need to fix ntoskrnl header parsing or whatever
            CHAR getPteAddressSignature[] = { 0x48, 0xc1, 0xe9, 0xff, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x23, 0xc8, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc1 };
            UINT64 getPteAddress_addr = kernel_sigscan((UINT64)(pModuleInfo->Module[i].Base) + 0x200000, 0x3cd000, getPteAddressSignature, sizeof(getPteAddressSignature)); // hopefully .text and no crash?
            sprintf_s(ptr_msg,
                sizeof(ptr_msg),
                "[?] MiGetPteAddress: 0x%llx\n",
                getPteAddress_addr);
            sock_log(sock, ptr_msg);
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
                int res = dump_kmodule2(sock, moduleName, pModuleInfo->Module[i], forceDumpInit);
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