#include <iostream>
#include <windows.h>

#pragma code_seg("shell")
//#pragma commnet(linker, "/entry:myMain") // 这样也行, 行个屁
// 1. 修改入口点		Propoties -> Linker -> Advanced -> Entry Point -> myMain
// 2. 指定代码段		#pragma code_seg("shell")
// 3. 安全检查关闭	Propoties -> C/C++ -> Code Generation -> Security Check -> Disable Security Check (/GS-)
// 4. 扩展功能关掉	Propoties -> C/C++ -> Language -> Conformance mode -> No (/permissive)


/// <summary>
/// PEB 可以找到进程加载的所有 DLL
/// </summary>
void myMain()
{
	// 1. 获取 Kernel32.dll 基地址 或者 ntdll.dll | Kernel32.dll | user32.dll, 有顺序的加载

	DWORD dwKernel32 = 0;
	// 通过 TEB 获取 PEB
	_TEB* pTeb = NtCurrentTeb();
	PDWORD pPeb = (PDWORD) * (PDWORD)((DWORD)pTeb + 0x60); // _PEB
	// 通过 PEB 获取 模块链表 Ldr
	PDWORD pLdr = (PDWORD) * (PDWORD)((DWORD)pPeb + 0x18); // _PEB_LDR_DATA
	// 通过 Ldr 获取 已加载的模块链表 InLoadOrderModuleList
	PDWORD InLoadOrderModuleList = (PDWORD)((DWORD)pLdr + 0x10); // _LIST_ENTRY 里面存的是 _LDR_DATA_TABLE_ENTRY
	/*
	nt!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY				// 模块链表
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING			// exe path
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 FlagGroup        : [4] UChar
   +0x068 Flags            : Uint4B
   +0x068 PackagedBinary   : Pos 0, 1 Bit
   +0x068 MarkedForRemoval : Pos 1, 1 Bit
   +0x068 ImageDll         : Pos 2, 1 Bit
   +0x068 LoadNotificationsSent : Pos 3, 1 Bit
   +0x068 TelemetryEntryProcessed : Pos 4, 1 Bit
   +0x068 ProcessStaticImport : Pos 5, 1 Bit
   +0x068 InLegacyLists    : Pos 6, 1 Bit
   +0x068 InIndexes        : Pos 7, 1 Bit
   +0x068 ShimDll          : Pos 8, 1 Bit
   +0x068 InExceptionTable : Pos 9, 1 Bit
   +0x068 ReservedFlags1   : Pos 10, 2 Bits
   +0x068 LoadInProgress   : Pos 12, 1 Bit
   +0x068 LoadConfigProcessed : Pos 13, 1 Bit
   +0x068 EntryProcessed   : Pos 14, 1 Bit
   +0x068 ProtectDelayLoad : Pos 15, 1 Bit
   +0x068 ReservedFlags3   : Pos 16, 2 Bits
   +0x068 DontCallForThreads : Pos 18, 1 Bit
   +0x068 ProcessAttachCalled : Pos 19, 1 Bit
   +0x068 ProcessAttachFailed : Pos 20, 1 Bit
   +0x068 CorDeferredValidate : Pos 21, 1 Bit
   +0x068 CorImage         : Pos 22, 1 Bit
   +0x068 DontRelocate     : Pos 23, 1 Bit
   +0x068 CorILOnly        : Pos 24, 1 Bit
   +0x068 ChpeImage        : Pos 25, 1 Bit
   +0x068 ReservedFlags5   : Pos 26, 2 Bits
   +0x068 Redirected       : Pos 28, 1 Bit
   +0x068 ReservedFlags6   : Pos 29, 2 Bits
   +0x068 CompatDatabaseProcessed : Pos 31, 1 Bit
   +0x06c ObsoleteLoadCount : Uint2B
   +0x06e TlsIndex         : Uint2B
   +0x070 HashLinks        : _LIST_ENTRY
   +0x080 TimeDateStamp    : Uint4B
   +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
   +0x090 Lock             : Ptr64 Void
   +0x098 DdagNode         : Ptr64 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY
   +0x0b0 LoadContext      : Ptr64 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : Ptr64 Void
   +0x0c0 SwitchBackContext : Ptr64 Void
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : Uint8B
   +0x100 LoadTime         : _LARGE_INTEGER
   +0x108 BaseNameHashValue : Uint4B
   +0x10c LoadReason       : _LDR_DLL_LOAD_REASON
   +0x110 ImplicitPathOptions : Uint4B
   +0x114 ReferenceCount   : Uint4B
   +0x118 DependentLoadFlags : Uint4B
   +0x11c SigningLevel     : UChar

	*/
	PDWORD pModExe = (PDWORD)*InLoadOrderModuleList;
	PDWORD pModNtDll = (PDWORD)*pModExe;
	PDWORD pModKernel32 = (PDWORD)*pModNtDll;
	dwKernel32 = *(pModKernel32 + 0x30); // DllBase

	DWORD dwBase = dwKernel32;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwKernel32;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + dwKernel32);
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	// 导出表
	pExportDir = &pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	DWORD dwOffset = pExportDir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwOffset + dwBase);
	// 导出表数据弄出来
	DWORD dwFuncCount = pExport->NumberOfFunctions; // 导出函数的个数
	DWORD dwFuncNameCount = pExport->NumberOfNames;	// 导出函数名字个数
	// 两个表的地址
	PDWORD pEnt = (PDWORD)(dwBase + pExport->AddressOfNames);
	PDWORD pEat = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	// 序号表
	PDWORD pEit = (PDWORD)(dwBase + pExport->AddressOfNameOrdinals);

	DWORD dwFuncAddress; // GetProcAddress
	for (size_t i = 0; i < dwFuncCount; i++) {
		if (!pEat[i]) {
			continue;
		}
		for (size_t index = 0; index < dwFuncNameCount; index++) {
			// 序号表里的值为地址表里的索引
			if (!pEit[index] == i) {
				DWORD dwNameOffset = pEnt[index]; // 函数名字字符串的偏移量
				char* szFuncName = (char*)(dwBase + dwNameOffset);
				// 局部变量
				char szGetProcAddress[] = {
					'G',
					'e',
					't',
					'P',
					'r',
					'o',
					'c',
					'A',
					'd',
					'd',
					'r',
					'e',
					's',
					's',
				};
				int nFlag = 0;
				for (size_t j = 0; j < 14; j++) {
					if (szFuncName[j] == szGetProcAddress[j]) {
						nFlag++;
					}
					if (nFlag == 14) {
						dwFuncAddress = pEat[pEit[index]] + dwBase;
					}
				}
			}

		}
	}

	char szLoadLibrary[] = {
	'L',
	'o',
	'a',
	'd',
	'L',
	'i',
	'b',
	'r',
	'a',
	'r',
	'y',
	'\0',
	};
	char szGetProcAddress[] = {
	'G',
	'e',
	't',
	'P',
	'r',
	'o',
	'c',
	'A',
	'd',
	'd',
	'r',
	'e',
	's',
	's',
	'\0',
	};
	char szMessageBox[] = {
	'M',
	'e',
	's',
	's',
	'a',
	'g',
	'e',
	'B',
	'o',
	'x',
	'A',
	'\0',
	};
	char szKernel32[] = {
	'K',
	'e',
	'l',
	'n',
	'e',
	'l',
	'3',
	'2',
	'.',
	'd',
	'l',
	'l',
	'\0',
	};
	char szUser32[] = {
	'U',
	's',
	'e',
	'r',
	'3',
	'2',
	'.',
	'd',
	'l',
	'l',
	'\0',
	};
	char szMyMain[] = {
	'm',
	'y',
	'M',
	'a',
	'i',
	'n',
	'\0',
	};

	typedef HMODULE(WINAPI* MyLoadLibraryA)(LPCSTR lpLibFileName);
	typedef FARPROC(WINAPI* MyGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	typedef int(WINAPI* MyMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

	HMODULE hKner32 = (HMODULE)dwKernel32;
	MyGetProcAddress pFunGetProcAddress = (MyGetProcAddress)dwFuncAddress;
	MyLoadLibraryA pFunLoadLibraryAddress;
	pFunLoadLibraryAddress = (MyLoadLibraryA)pFunGetProcAddress(hKner32, szLoadLibrary);

	HMODULE hUser32 = pFunLoadLibraryAddress(szUser32);
	MyMessageBoxA pFuncMegBox;
	pFuncMegBox = (MyMessageBoxA)pFunGetProcAddress(hUser32, szMessageBox);
	pFuncMegBox(NULL, szMyMain, szMyMain, MB_OK);
}

