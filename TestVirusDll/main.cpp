#include "main.h"


typedef struct _PEB_LDR_DATA32   //xp sp3 x86
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32 { //xp sp3 x86
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

char* FunctionArray[1404];
int  sub_1001229F(BYTE* _this)
{
	int i; // [esp+4h] [ebp-8h]

	for (i = 0; *_this; ++_this)
		i = (i << 16) + (i << 6) + (char)*_this - i;
	return i;
}

int __fastcall sub_10008C7D(int a1, int a2)
{
	int(__stdcall * SomeFunction)(int); // eax

	SomeFunction = (int(__stdcall*)(int))GetSomeFunction(726, 8210, -854358180);
	return SomeFunction(a2);
}
int __fastcall sub_100011AF(int a2)
{
	int(__stdcall * SomeFunction)(int); // eax

	SomeFunction = (int(__stdcall*)(int))GetSomeFunction(679, 27840, -854358180);
	return SomeFunction(a2);
}
typedef DWORD _DWORD;
DWORD IntIndex = 0;
char* sub_1000F100(char* _this)
{
	char* v2; // ecx
	char v3; // al
	char* v4; // esi
	char* result; // eax
	char v6[260]; // [esp+8h] [ebp-140h] BYREF
	int v7; // [esp+10Ch] [ebp-3Ch]
	int v8; // [esp+110h] [ebp-38h]
	int v9; // [esp+114h] [ebp-34h]
	int v10; // [esp+118h] [ebp-30h]
	int v11; // [esp+11Ch] [ebp-2Ch]
	int v12; // [esp+120h] [ebp-28h]
	int v13; // [esp+124h] [ebp-24h]
	int v14; // [esp+128h] [ebp-20h]
	int v15; // [esp+12Ch] [ebp-1Ch]
	int v16; // [esp+130h] [ebp-18h]
	int v17; // [esp+134h] [ebp-14h]
	int v18; // [esp+138h] [ebp-10h]
	int v19; // [esp+13Ch] [ebp-Ch]
	int v20; // [esp+140h] [ebp-8h]
	int v21; // [esp+144h] [ebp-4h]

	v9 = 0;
	v10 = 0;
	v7 = 2429013;
	v8 = 1518794;
	v21 = 30305;
	v16 = 25220;
	v15 = 10730;
	v20 = 407;
	v19 = 13913;
	v17 = 1072;
	v18 = 14969;
	v12 = 19011;
	v13 = 4161;
	v11 = 22723;
	v2 = v6;
	v14 = 27861;
	while (1)
	{
		v3 = *_this;
		if (!*_this)
			break;
		if (v3 == 46)
		{
			*v2 = 0;
			break;
		}
		*v2++ = v3;
		++_this;
	}
	v4 = (char*)GetModuleHandleA(v6);
	if (v4 || (result = (char*)LoadLibraryA(v6), (v4 = result) != 0))
	{
		int x = sub_1001229F((BYTE*)(_this + 1));
		IntIndex = (int)x ^ 0x69D5B12D;
		return GetFunctionAddress(v11, (int)v4);
	}
	return result;
}
char* __cdecl GetFunctionAddress(int a1, int a2)
{
	int v2; // ecx
	char* v3; // esi
	int v4; // ebp
	char* v5; // edi
	int v6; // ecx
	int v8; // [esp+14h] [ebp-14h]
	int v9; // [esp+18h] [ebp-10h]
	int v10; // [esp+1Ch] [ebp-Ch]
	int v11; // [esp+20h] [ebp-8h]
	int v12; // [esp+24h] [ebp-4h]

	v3 = 0;
	v4 = 0;
	v12 = *(_DWORD*)(a2 + 60);
	v5 = (char*)(a2 + *(_DWORD*)(v12 + a2 + 120));
	v11 = a2 + *((_DWORD*)v5 + 7);
	v6 = a2 + *((_DWORD*)v5 + 8);
	v9 = v6;
	v10 = a2 + *((_DWORD*)v5 + 9);
	if (*((_DWORD*)v5 + 6))
	{
		while ((sub_1001229F((BYTE*)(a2 + *(_DWORD*)(v6 + 4 * v4))) ^ 0x69D5B12D) != IntIndex)
		{
			v6 = v9;
			if ((unsigned int)++v4 >= *((_DWORD*)v5 + 6))
				return v3;
		}
		v3 = (char*)(a2 + *(_DWORD*)(v11 + 4 * *(unsigned __int16*)(v10 + 2 * v4)));
		if (v3 >= v5 && v3 < &v5[*(_DWORD*)(v12 + a2 + 124)])
			return (char*)sub_1000F100(v3);
	}
	return v3;
}
char* __cdecl GetSomeFunction(int FunctionIndex, int a2, int a3)
{
	struct _LIST_ENTRY* DllBase; // eax

	if (!FunctionArray[FunctionIndex])
	{
		DllBase = GetDllBase(17, a3);
		FunctionArray[FunctionIndex] = GetFunctionAddress(11759, (int)DllBase);
	}
	return FunctionArray[FunctionIndex];
}
_PEB* NtCurrentPeb() {
	__asm {
		mov eax, fs: [0x30] ;
	}
}
int  GetStrToIntLower(WORD* a5)
{
	WORD* v5; // esi
	unsigned int v6; // eax
	int v8; // [esp+8h] [ebp-4h]

	v5 = a5;
	v8 = 0;
	if (*a5)
	{
		do
		{
			v6 = (unsigned __int16)*v5;
			if (v6 >= 0x41 && v6 <= 0x5A)
				v6 += 32;
			++v5;
			v8 = (v8 << 16) + (v8 << 6) + v6 - v8;
		} while (*v5);
	}
	return v8;
}
struct _LIST_ENTRY* GetDllBase(int a1, int StrInt)
{
	struct _LDR_DATA_TABLE_ENTRY32** p_InLoadOrderModuleList; // edi
	struct _LDR_DATA_TABLE_ENTRY32* i; // esi
	_PEB* v6; // [esp+0h] [ebp-30h]
	PPEB_LDR_DATA32 x = (PPEB_LDR_DATA32)NtCurrentPeb()->Ldr;
	p_InLoadOrderModuleList = (struct _LDR_DATA_TABLE_ENTRY32**)&x->InLoadOrderModuleList;
	for (i = *p_InLoadOrderModuleList; ; i = (struct _LDR_DATA_TABLE_ENTRY32*)i->InLoadOrderLinks.Flink)
	{
		if (i == (struct _LDR_DATA_TABLE_ENTRY32*)p_InLoadOrderModuleList)
			return 0;
		if ((GetStrToIntLower((WORD*)i->BaseDllName.Buffer) ^ 0x426D612E) == StrInt)
			break;
	}
	return (struct _LIST_ENTRY*)i->DllBase;
}

void printFunctionNameAddress(const char* dllName, char* FunctionAddress) {
	HMODULE hModule = LoadLibraryA(dllName);
	FARPROC pFunc;
	DWORD numFunctions = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
	DWORD exportRVA = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportRVA);

	if (pExportDirectory == NULL) {
		std::cerr << "Failed to get export directory." << std::endl;
	}

	DWORD* pFuncAddresses = (DWORD*)((DWORD)hModule + pExportDirectory->AddressOfFunctions);
	DWORD* pFuncNames = (DWORD*)((DWORD)hModule + pExportDirectory->AddressOfNames);
	WORD* pOrdinals = (WORD*)((DWORD)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i) {
		pFunc = (FARPROC)((DWORD)hModule + pFuncAddresses[pOrdinals[i]]);
		if (FunctionAddress == (char*)pFunc) {
			std::string functionName = (char*)((DWORD)hModule + pFuncNames[i]);
			std::cout
				<< pFunc << " | "
				<< pOrdinals[i] + pExportDirectory->Base << " | "
				<< dllName << " | "
				<< functionName << " | "
				<< std::hex << IntIndex << " | "
				<< std::endl;
			//return;
		}
	}
}
#include <DbgHelp.h>
#include <stdio.h>
#pragma comment(lib, "Dbghelp.lib")
int main()
{
	// 加载 DLL 文件

	/*
	// 获取导出表地址
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
	DWORD exportRVA = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportRVA);

	// 获取函数名称
	DWORD* pFuncNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
	DWORD* pFuncAddrs = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
	WORD* pFuncIndexs = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);
	printf("functionAddr:%p %p\n", pExportDirectory->Base, hModule);

	for (DWORD i = 0; i < 6; ++i) {
		char* functionAddr = (char*)((BYTE*)hModule + pFuncAddrs[i]);
		char* functionName = (char*)((BYTE*)hModule + pFuncNames[i]);
		int functionIndex = (int)(pFuncIndexs[i]);
		printf("functionAddr:%p %p Function Name: %s\n", functionAddr, functionIndex, functionName);
	}
	*/


	// 获取导出函数地址


	/*
	// 打印函数地址、序号和名称
	std::cout << "函数地址 | 序号 | 函数名" << std::endl;
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i) {
		pFunc = (FARPROC)((DWORD)hModule + pFuncAddresses[pOrdinals[i]]);
		std::string functionName = (char*)((DWORD)hModule + pFuncNames[i]);
		std::cout << pFunc << " | " << pOrdinals[i] + pExportDirectory->Base << " | " << functionName << std::endl;
	}
	*/
	LoadLibraryA("apphelp.dll");
	LoadLibraryA("mpr.dll");
	LoadLibraryA("version.dll");
	LoadLibraryA("winspool.drv");
	LoadLibraryA("acwow64.dll");
	LoadLibraryA("cryptbase.dll");
	LoadLibraryA("sspicli.dll");
	LoadLibraryA("user32.dll");
	LoadLibraryA("shlwapi.dll");
	LoadLibraryA("msvcrt.dll");
	LoadLibraryA("imm32.dll");
	LoadLibraryA("kernel32.dll");
	LoadLibraryA("oleaut32.dll");
	LoadLibraryA("imagehlp.dll");
	LoadLibraryA("ole32.dll");
	LoadLibraryA("lpk.dll");
	LoadLibraryA("kernelbase.dll");
	LoadLibraryA("rpcrt4.dll");
	LoadLibraryA("profapi.dll");
	LoadLibraryA("usp10.dll");
	LoadLibraryA("gdi32.dll");
	LoadLibraryA("shell32.dll");
	LoadLibraryA("sechost.dll");
	LoadLibraryA("advapi32.dll");
	LoadLibraryA("userenv.dll");
	LoadLibraryA("ntdll.dll");

	LoadLibraryA("uxtheme.dll");
	LoadLibraryA("dwmapi.dll");
	LoadLibraryA("aclayers.dll");
	LoadLibraryA("msctf.dll");
	LoadLibraryA("urlmon.dll");
	LoadLibraryA("crypt32.dll");
	LoadLibraryA("wininet.dll");
	LoadLibraryA("wtsapi32.dll");

	char* ntdllBase = (char*)LoadLibraryA("ntdll");
	printf("ntdll.dll address%p \n", ntdllBase);
	DWORD IntIndexArray[][2] = {
		{0x0B40E19A6, -854358180},// ReadDirectoryChangesW
		{0x0B6FE0AC1, -854358180},// LoadLibraryA
		{0x09EED0E1A, -854358180},// SetFileInformationByHandle
		{0x19B8D8C0, -854358180},// RtlAllocateHeap
		{0xCDBCE024, -854358180},// VirtualFree
		{0x93276E7A, -854358180},// lstrcmpiA
		{0x0EFB053D4, -854358180},
		{0x2DE05E88, -854358180},
		{0x91421276, -854358180},
		{0x7FB8533D, -854358180},// 0x7fb8533d | 773397B0 | 63d | kernel32.dll | lstrcpynW | 7fb8533d |
		{0x2639E314, -854358180},// 0x2639e314 | 77342EC0 | c4 | kernel32.dll | CreateEventW | 2639e314 |
		{0x80DFA2C7, -854358180},// GetNativeSystemInfo
		{0xF471A684, -854358180},// QueryFullProcessImageNameW
		{0x630E0808, -854358180},// OpenProcess
		{0xED4220F5, -854358180},// CreateToolhelp32Snapshot
		{0x4AC68538, -854358180},// Process32FirstW
		{0xE4BEBFDB, -854358180},// Process32NextW
		{0x7292F52D, -854358180},// CloseHandle
		{0xE834AEDD, -854358180},// lstrcpyW
		{0x2F853903, -854358180},// GetModuleFileNameW
		{0x8AA3CCF1, -854358180},// GetTickCount
		{0x73D8A436, -854358180},// WaitForSingleObject
		{0xEB46EC77, -854358180},// GetTickCount64
		{0x35196635, -854358180},// SetEvent
		{0x630DF485, -854358180},// 
		{0x16AAD9C3, -854358180},// 
		{0xF0655F80, -854358180},// 
		{0x8038A632, -854358180},// 
		{0x50041767, -854358180},// 
		{0x0F776DBA2, -854358180},// 
		{0x978F749E, -854358180},// 
		{0x76FD784A, -854358180},// 
		{0x76FD787C, -854358180},// 
		{0x543A6D4B, -854358180},// 
		{0x0D71D6A2A, -854358180},// 
		{0x0E93CD4A5, -854358180},// GetProcAddress
		{0x4520BABA, -854358180},// GetWindowsDirectoryW
		{0x0E421F432, -854358180},// CreateFileW
		{0x0ACA81DF6, -854358180},// GetVolumeInformationW
		{0x2F3F9068, -854358180},// MultiByteToWideChar
		{0x0BCCD2D6B, -854358180},// GetTempFileNameW
		{0x0A266EB88, -854358180},// GetComputerNameA
		{0x0BF021AD, -854358180},// WTSGetActiveConsoleSessionId
		{0x0D1A331A9, -854358180},// FindFirstFileW
		{0x0EFB05222, -854358180},// lstrcmpiW
		{0x2CF59F5D, -854358180},// DeleteFileW
		{0x2C1130D0, -854358180},// WideCharToMultiByte
		{0x822A56C1, -854358180},// ProcessIdToSessionId
		{0x0DBBF57BC, -854358180},// ExitProcess
		{0x7C9EF81, -854358180},// GetCurrentProcess
		{0x0D940F2C1, -854358180},// GetFileInformationByHandleEx
		{0x25C25F5, -854358180},// HeapFree
		{0x0B6FE0D2F, -854358180},// LoadLibraryW
		{0x5B0D091A, -854358180},// LocalFree
		{0x0EF2048C9, -854358180},// LocalFree
		{0x0D712D7A3, -854358180},// RemoveDirectoryW

		{0x6C5B5F03, 1569665320}, // wininet.dll InternetConnectW 这个找不到dll 5D8F3128
		{0x4DED1132, 1569665320}, // InternetCloseHandle wininet.dll
		{0x628D91A4, 1569665320}, // HttpQueryInfoW
		{0x0A6D2C43E, 1569665320}, // InternetReadFile
		{0x0E5A91877, 1569665320}, // HttpOpenRequestW
		{0x0E380A9E1, 1569665320}, // InternetOpenW
		{0x3CB036D5, 1569665320}, // HttpSendRequestW
		{0x0CD9A7D2C, 1569665320}, // InternetSetOptionW

		{0x0E83D5DBB, -1874640582}, // _snwprintf ntdll.dll
		{0x0B55FA47E, -1874640582},	// _snprintf
		{0x2C4665E0, -1874640582},  // memset
		{0x4D7B55E1, -1874640582},  // RtlGetVersion
		{0x54686E5A, -1874640582},  // memcpy

		{0x1B8D4B3F, 51638654},

		{0xC703AA7A, 1884158258},//	0xc703aa7a | 76EFE160 | 4bf | advapi32.dll | CryptGetHashParam | c703aa7a |
		{0x7B1B0670, 1884158258},//	CryptGenKey
		{0x44988881, 1884158258},//	
		{0x6338F192, 1884158258},//	
		{0x4E9D36B, 1884158258},//	
		{0x8F3EE481, 1884158258},//	
		{0x0E6ECDBF3, 1884158258},// CreateServiceW
		{0x74C36548, 1884158258},// CloseServiceHandle
		{0x4AEB041, 1884158258},// OpenServiceW
		{0x5E35216, 1884158258},// RegCloseKey
		{0x0C1722B5A, 1884158258},// CryptEncrypt
		{0x0BB9F65A7, 1884158258},// DeleteService
		{0x15F02EAA, 1884158258},// CreateProcessAsUserW
		{0x63F069DB, 1884158258},// CryptReleaseContext
		{0x310AE18C, 1884158258},// RegSetValueExW
		{0x95805506, 1884158258},// CryptDuplicateHash
		{0x440996BE, 1884158258},// CryptDestroyKey
		{0xA1BD, 1884158258},// CryptAcquireContextW
		{0x8AFBBAF7, 1884158258},// CryptDestroyHash
		{0x561BCCDE, 1884158258},// EnumServicesStatusExW
		{0x650ABE95, 1884158258},// CryptCreateHash
		{0x0F592B1F0, 1884158258},// CryptExportKey
		{0x0BA21E8C8, 1884158258},// RegDeleteValueW
		{0x0CCDD5B39, 1884158258},// QueryServiceConfig2W
		{0x5BF6FC69, 1884158258},// OpenSCManagerW
		{0x5E334258, 1884158258},// RegCreateKeyExW
		{0x6BC240CC, 1884158258},// DuplicateTokenEx

		{0x325DF611, -362109705},//	WTSQueryUserToken 这个也找不到dll EA6AA4F7

		{0xF5F4270B, 652473373},//	

		{0x23205D39, 366789366},//	userenv.dll DestroyEnvironmentBlock
		{0x17F54FFB, 366789366},//	CreateEnvironmentBlock

		{0x0B4E30391, 1318148045},// CryptStringToBinaryW	crypt32.dll
		{0x0D347E391, 1318148045},// CryptBinaryToStringW	crypt32.dll
		{0x8CA9B8E3, 1318148045},// CryptDecodeObjectEx	crypt32.dll

		{0x7466E12C, -1880554421},// SHFileOperationW shell32.dll
		{0x3C5A3F10, -1880554421},// CommandLineToArgvW shell32.dll
		{0x465AA26E, -1880554421},// SHGetFolderPathW shell32.dll

	};
	for (int j = 0; j < sizeof(IntIndexArray) / sizeof(DWORD) / 2; j++) {
		IntIndex = IntIndexArray[j][0];
		int dllStrInt = IntIndexArray[j][1];
		printf("%#x | ", IntIndex);
		char* FunctionAddress = GetSomeFunction(j, 0, dllStrInt);
		printFunctionNameAddress("apphelp.dll", FunctionAddress);
		printFunctionNameAddress("mpr.dll", FunctionAddress);
		printFunctionNameAddress("version.dll", FunctionAddress);
		printFunctionNameAddress("winspool.drv", FunctionAddress);
		printFunctionNameAddress("acwow64.dll", FunctionAddress);
		printFunctionNameAddress("cryptbase.dll", FunctionAddress);
		printFunctionNameAddress("sspicli.dll", FunctionAddress);
		printFunctionNameAddress("user32.dll", FunctionAddress);
		printFunctionNameAddress("shlwapi.dll", FunctionAddress);
		printFunctionNameAddress("msvcrt.dll", FunctionAddress);
		printFunctionNameAddress("imm32.dll", FunctionAddress);
		printFunctionNameAddress("kernel32.dll", FunctionAddress);
		printFunctionNameAddress("oleaut32.dll", FunctionAddress);
		printFunctionNameAddress("imagehlp.dll", FunctionAddress);
		printFunctionNameAddress("ole32.dll", FunctionAddress);
		printFunctionNameAddress("lpk.dll", FunctionAddress);
		printFunctionNameAddress("kernelbase.dll", FunctionAddress);
		printFunctionNameAddress("rpcrt4.dll", FunctionAddress);
		printFunctionNameAddress("profapi.dll", FunctionAddress);
		printFunctionNameAddress("usp10.dll", FunctionAddress);
		printFunctionNameAddress("gdi32.dll", FunctionAddress);
		printFunctionNameAddress("shell32.dll", FunctionAddress);
		printFunctionNameAddress("sechost.dll", FunctionAddress);
		printFunctionNameAddress("advapi32.dll", FunctionAddress);
		printFunctionNameAddress("userenv.dll", FunctionAddress);
		printFunctionNameAddress("ntdll.dll", FunctionAddress);

		printFunctionNameAddress("uxtheme.dll", FunctionAddress);
		printFunctionNameAddress("dwmapi.dll", FunctionAddress);
		printFunctionNameAddress("aclayers.dll", FunctionAddress);
		printFunctionNameAddress("msctf.dll", FunctionAddress);
		printFunctionNameAddress("urlmon.dll", FunctionAddress);
		printFunctionNameAddress("crypt32.dll", FunctionAddress);
		printFunctionNameAddress("wininet.dll", FunctionAddress);
		printFunctionNameAddress("wtsapi32.dll", FunctionAddress);

		//printf("FunctionAddress: %p \n", FunctionAddress);
	}

	system("pause");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
