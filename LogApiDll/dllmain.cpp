#include "pch.h"
#include <windows.h>
#include "include\detours.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <fstream>
#include <vector>
#include <string>
#include <locale>
#include <codecvt>
//#include <winhttp.h> // 有问题
#include <iostream>
#include <Wincrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <sstream>
#include <shlwapi.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shlobj.h>
#include <wininet.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")

std::string ByteArrayToStringNoOperator(const BYTE* data, DWORD dataSize) {
	std::stringstream ss;
	for (DWORD i = 0; i < dataSize; ++i) {
		char hexStr[3];
		sprintf(hexStr, "%02X", data[i]);
		ss.write(hexStr, 2);
		ss << " ";
	}
	return ss.str();
}
void WriteToLogFile(std::string message);
char* WideCharToMultiByteString(const WCHAR* wideStr);
typedef HMODULE(WINAPI* PGETMODULEHANDLEA)(LPCSTR lpModuleName);
PGETMODULEHANDLEA pOriginalGetModuleHandleA = NULL;
HMODULE WINAPI MyGetModuleHandleA(LPCSTR lpModuleName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)lpModuleName);
	return pOriginalGetModuleHandleA(lpModuleName);
}

typedef DWORD(WINAPI* PWAITFORSINGLEOBJECT)(HANDLE hHandle, DWORD dwMilliseconds);
PWAITFORSINGLEOBJECT pOriginalWaitForSingleObject = NULL;
DWORD WINAPI MyWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)hHandle) + " " + std::to_string((int)dwMilliseconds));
	return pOriginalWaitForSingleObject(hHandle, dwMilliseconds);
}

typedef DWORD(WINAPI* PGETTICKCOUNT)(void);
PGETTICKCOUNT pOriginalGetTickCount = NULL;
DWORD WINAPI MyGetTickCount(void) {
	DWORD x = pOriginalGetTickCount();
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(x));
	return x;
}

typedef HMODULE(WINAPI* PLOADLIBRARYW)(LPCWSTR lpLibFileName);
PLOADLIBRARYW pOriginalLoadLibraryW = NULL;
HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpLibFileName));
	return pOriginalLoadLibraryW(lpLibFileName);
}

typedef HANDLE(WINAPI* PGETPROCESSHEAP)(void);
PGETPROCESSHEAP pOriginalGetProcessHeap = NULL;
HANDLE WINAPI MyGetProcessHeap(void) {
	WriteToLogFile(__FUNCTION__);
	return pOriginalGetProcessHeap();
}

typedef BOOL(WINAPI* PReadDirectoryChangesW)(HANDLE hDirectory, LPVOID lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree, DWORD dwNotifyFilter, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
PReadDirectoryChangesW pOrigReadDirectoryChangesW = NULL;
BOOL WINAPI MyReadDirectoryChangesW(HANDLE hDirectory, LPVOID lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree, DWORD dwNotifyFilter, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
	WriteToLogFile(__FUNCTION__);
	return pOrigReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped);
}

typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR lpLibFileName);
PLoadLibraryA pOrigLoadLibraryA = NULL;
HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)lpLibFileName);
	return pOrigLoadLibraryA(lpLibFileName);
}

typedef BOOL(WINAPI* PSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);
PSetFileInformationByHandle pOrigSetFileInformationByHandle = NULL;
BOOL WINAPI MySetFileInformationByHandle(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(FileInformationClass));
	return pOrigSetFileInformationByHandle(hFile, FileInformationClass, lpFileInformation, dwBufferSize);
}

typedef int(WINAPI* PlstrcmpiA)(LPCSTR lpString1, LPCSTR lpString2);
PlstrcmpiA pOriglstrcmpiA = NULL;
int WINAPI MylstrcmpiA(LPCSTR lpString1, LPCSTR lpString2) {
	WriteToLogFile((std::string)__FUNCTION__ + (std::string)(lpString1)+" | " + (std::string)(lpString2));
	return pOriglstrcmpiA(lpString1, lpString2);
}
typedef BOOL(WINAPI* PWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
PWriteFile pOrigWriteFile = NULL;
BOOL WINAPI MyWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	WriteToLogFile(__FUNCTION__);
	return pOrigWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
typedef BOOL(WINAPI* PVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
PVirtualFree pOrigVirtualFree = NULL;
BOOL WINAPI MyVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	WriteToLogFile(__FUNCTION__);
	return pOrigVirtualFree(lpAddress, dwSize, dwFreeType);
}

typedef LPWSTR(WINAPI* PlstrcpynW)(LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength);
PlstrcpynW pOriglstrcpynW = NULL;
LPWSTR WINAPI MylstrcpynW(LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpString2));
	return pOriglstrcpynW(lpString1, lpString2, iMaxLength);
}
typedef HANDLE(WINAPI* PCreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
PCreateEventW pOrigCreateEventW = NULL;
HANDLE WINAPI MyCreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName) {
	HANDLE x = pOrigCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)x));
	return x;
}
typedef VOID(WINAPI* PGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
PGetNativeSystemInfo pOrigGetNativeSystemInfo = NULL;
VOID WINAPI MyGetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + "获取系统架构, 判断是x64还是x32");
	return pOrigGetNativeSystemInfo(lpSystemInfo);
}
typedef BOOL(WINAPI* PQueryFullProcessImageNameW)(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
PQueryFullProcessImageNameW pOrigQueryFullProcessImageNameW = NULL;
BOOL WINAPI MyQueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) {
	BOOL x = pOrigQueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpExeName));
	return x;
}
typedef HANDLE(WINAPI* POpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
POpenProcess pOrigOpenProcess = NULL;
HANDLE WINAPI MyOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(dwProcessId));
	return pOrigOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}
typedef HANDLE(WINAPI* PCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
PCreateToolhelp32Snapshot pOrigCreateToolhelp32Snapshot = NULL;
HANDLE WINAPI MyCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(th32ProcessID));
	return pOrigCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}
typedef BOOL(WINAPI* PProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
PProcess32FirstW pOrigProcess32FirstW = NULL;
BOOL WINAPI MyProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
	WriteToLogFile(__FUNCTION__);
	return pOrigProcess32FirstW(hSnapshot, lppe);
}
typedef BOOL(WINAPI* PProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
PProcess32NextW pOrigProcess32NextW = NULL;
BOOL WINAPI MyProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
	WriteToLogFile(__FUNCTION__);
	return pOrigProcess32NextW(hSnapshot, lppe);
}
typedef LPWSTR(WINAPI* PlstrcpyW)(LPWSTR lpString1, LPCWSTR lpString2);
PlstrcpyW pOriglstrcpyW = NULL;
LPWSTR WINAPI MyLstrcpyW(LPTSTR lpString1, LPCWSTR lpString2) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpString2));
	return pOriglstrcpyW(lpString1, lpString2);
}
typedef DWORD(WINAPI* PGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
PGetModuleFileNameW pOrigGetModuleFileNameW = NULL;
DWORD WINAPI MyGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
	DWORD x = pOrigGetModuleFileNameW(hModule, lpFilename, nSize);
	if (x != 0) {
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpFilename));
	}
	return x;
}
typedef ULONGLONG(WINAPI* PGetTickCount64)(VOID);
PGetTickCount64 pOrigGetTickCount64 = NULL;
ULONGLONG WINAPI MyGetTickCount64(VOID) {
	ULONGLONG x = pOrigGetTickCount64();
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(x));
	return x;
}
typedef DWORD(WINAPI* PGetTempPathW)(DWORD nBufferLength, LPWSTR lpBuffer);
PGetTempPathW pOrigGetTempPathW = NULL;
DWORD WINAPI MyGetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer) {
	DWORD x = pOrigGetTempPathW(nBufferLength, lpBuffer);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpBuffer));
	return x;
}
typedef LPWSTR(WINAPI* PGetCommandLineW)(VOID);
PGetCommandLineW pOrigGetCommandLineW = NULL;
LPWSTR WINAPI MyGetCommandLineW(VOID) {
	LPWSTR x = pOrigGetCommandLineW();
	if (x != NULL) {
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(x));
	}
	return x;
}
typedef VOID(WINAPI* PGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);
PGetSystemTimeAsFileTime pOrigGetSystemTimeAsFileTime = NULL;
VOID WINAPI MyGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
	//WriteToLogFile(__FUNCTION__);
	return pOrigGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}
typedef BOOL(WINAPI* PFindClose)(HANDLE hFindFile);
PFindClose pOrigFindClose = NULL;
BOOL WINAPI MyFindClose(HANDLE hFindFile) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)hFindFile));
	return pOrigFindClose(hFindFile);
}
typedef LPVOID(WINAPI* PVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
PVirtualAlloc pOrigVirtualAlloc = NULL;
LPVOID WINAPI MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	WriteToLogFile(__FUNCTION__);
	return pOrigVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}
typedef BOOL(WINAPI* PFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
PFindNextFileW pOrigFindNextFileW = NULL;
BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
	WriteToLogFile(__FUNCTION__);
	return pOrigFindNextFileW(hFindFile, lpFindFileData);
}
typedef BOOL(WINAPI* PDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
PDuplicateHandle pOrigDuplicateHandle = NULL;
BOOL WINAPI MyDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)hSourceHandle));
	return pOrigDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}
typedef int(WINAPI* PlstrlenW)(LPCWSTR lpString);
PlstrlenW pOriglstrlenW = NULL;
int WINAPI MylstrlenW(LPCWSTR lpString) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpString));
	return pOriglstrlenW(lpString);
}
typedef int(WINAPI* PlstrlenA)(LPCSTR lpString);
PlstrlenA pOriglstrlenA = NULL;
int WINAPI MylstrlenA(LPCSTR lpString) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)(lpString));
	return pOriglstrlenA(lpString);
}
typedef HANDLE(WINAPI* PCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
PCreateThread pOrigCreateThread = NULL;
HANDLE WINAPI MyCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	HANDLE x = pOrigCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	if (x != NULL)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)x));
	return x;
}
typedef DWORD(WINAPI* PGetCurrentProcessId)(VOID);
PGetCurrentProcessId pOrigGetCurrentProcessId = NULL;
DWORD WINAPI MyGetCurrentProcessId(VOID) {
	DWORD x = pOrigGetCurrentProcessId();
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string(x));
	return pOrigGetCurrentProcessId();
}
typedef FARPROC(WINAPI* PGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
PGetProcAddress pOrigGetProcAddress = NULL;
FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)lpProcName);
	return pOrigGetProcAddress(hModule, lpProcName);
}
typedef UINT(WINAPI* PGetWindowsDirectoryW)(LPWSTR lpBuffer, UINT uSize);
PGetWindowsDirectoryW pOrigGetWindowsDirectoryW = NULL;
UINT WINAPI MyGetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize) {
	UINT x = pOrigGetWindowsDirectoryW(lpBuffer, uSize);
	if (x != 0)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpBuffer));
	return x;
}
typedef HANDLE(WINAPI* PCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
PCreateFileW pOrigCreateFileW = NULL;
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpFileName));
	return pOrigCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
typedef BOOL(WINAPI* PGetVolumeInformationW)(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
PGetVolumeInformationW pOrigGetVolumeInformationW = NULL;
BOOL WINAPI MyGetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpRootPathName));
	return pOrigGetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
}
typedef int(WINAPI* PMultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
PMultiByteToWideChar pOrigMultiByteToWideChar = NULL;
int WINAPI MyMultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)lpMultiByteStr);
	return pOrigMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}
typedef UINT(WINAPI* PGetTempFileNameW)(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
PGetTempFileNameW pOrigGetTempFileNameW = NULL;
UINT WINAPI MyGetTempFileNameW(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpPathName));
	return pOrigGetTempFileNameW(lpPathName, lpPrefixString, uUnique, lpTempFileName);
}
typedef BOOL(WINAPI* LPFN_GETCOMPUTERNAMEA)(LPSTR, LPDWORD);
LPFN_GETCOMPUTERNAMEA pOrigGetComputerNameA = NULL;
BOOL WINAPI MyGetComputerNameA(LPSTR lpBuffer, LPDWORD nSize) {
	BOOL x = pOrigGetComputerNameA(lpBuffer, nSize);
	if (x)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)lpBuffer);
	return x;
}
typedef DWORD(WINAPI* PWTSGetActiveConsoleSessionId)(VOID);
PWTSGetActiveConsoleSessionId pOrigWTSGetActiveConsoleSessionId = NULL;
DWORD WINAPI MyWTSGetActiveConsoleSessionId(VOID) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigWTSGetActiveConsoleSessionId();
}
typedef HANDLE(WINAPI* PFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
PFindFirstFileW pOrigFindFirstFileW = NULL;
HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
	HANDLE hFind = pOrigFindFirstFileW(lpFileName, lpFindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpFileName));
	}
	return hFind;
}
typedef int(WINAPI* PlstrcmpiW)(LPCWSTR lpString1, LPCWSTR lpString2);
PlstrcmpiW pOriglstrcmpiW = NULL;
int WINAPI MylstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " +
		(std::string)WideCharToMultiByteString(lpString1) + (std::string)" | " +
		(std::string)WideCharToMultiByteString(lpString2)
	);
	return pOriglstrcmpiW(lpString1, lpString2);
}
typedef BOOL(WINAPI* PDeleteFileW)(LPCWSTR lpFileName);
PDeleteFileW pOrigDeleteFileW = NULL;
BOOL WINAPI MyDeleteFileW(LPCWSTR lpFileName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpFileName));
	return pOrigDeleteFileW(lpFileName);
}
typedef int(WINAPI* PWideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
PWideCharToMultiByte pOrigWideCharToMultiByte = NULL;
int WINAPI MyWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpWideCharStr));
	return pOrigWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}
typedef BOOL(WINAPI* PProcessIdToSessionId)(DWORD dwProcessId, DWORD* pSessionId);
PProcessIdToSessionId pOrigProcessIdToSessionId = NULL;
BOOL WINAPI MyProcessIdToSessionId(DWORD dwProcessId, DWORD* pSessionId) {
	BOOL x = pOrigProcessIdToSessionId(dwProcessId, pSessionId);
	if (x)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)dwProcessId) + " | threadId " + std::to_string(*pSessionId));
	return x;
}
typedef VOID(WINAPI* PExitProcess)(UINT uExitCode);
PExitProcess pOrigExitProcess = NULL;
VOID WINAPI MyExitProcess(UINT uExitCode) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigExitProcess(uExitCode);
}
typedef BOOL(WINAPI* PGetFileInformationByHandleEx)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);
PGetFileInformationByHandleEx pOrigGetFileInformationByHandleEx = NULL;
BOOL WINAPI MyGetFileInformationByHandleEx(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigGetFileInformationByHandleEx(hFile, FileInformationClass, lpFileInformation, dwBufferSize);
}
typedef BOOL(WINAPI* PHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
PHeapFree pOrigHeapFree = NULL;
BOOL WINAPI MyHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigHeapFree(hHeap, dwFlags, lpMem);
}
typedef HLOCAL(WINAPI* PLocalFree)(HLOCAL hMem);
PLocalFree pOrigLocalFree = NULL;
HLOCAL WINAPI MyLocalFree(HLOCAL hMem) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigLocalFree(hMem);
}
typedef BOOL(WINAPI* PCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
PCreateProcessW pOrigCreateProcessW = NULL;
BOOL WINAPI MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpApplicationName));
	if (lpCommandLine)
		WriteToLogFile((std::string)__FUNCTION__ + " ----> " + (std::string)WideCharToMultiByteString(lpCommandLine));
	return pOrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
typedef BOOL(WINAPI* PRemoveDirectoryW)(LPCWSTR lpPathName);
PRemoveDirectoryW pOrigRemoveDirectoryW = NULL;
BOOL WINAPI MyRemoveDirectoryW(LPCWSTR lpPathName) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpPathName));
	return pOrigRemoveDirectoryW(lpPathName);
}
typedef BOOL(WINAPI* PCryptGetHashParam)(HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pdwDataLen, DWORD dwFlags);
PCryptGetHashParam pOrigCryptGetHashParam = NULL;
BOOL WINAPI MyCryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pdwDataLen, DWORD dwFlags) {
	BOOL x = pOrigCryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)dwParam));
	return x;
}
typedef BOOL(WINAPI* PCryptGenKey)(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey);
PCryptGenKey pOrigCryptGenKey = NULL;
BOOL WINAPI MyCryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)Algid) + " |  " + std::to_string(dwFlags));
	return pOrigCryptGenKey(hProv, Algid, dwFlags, phKey);
}
typedef BOOL(WINAPI* PChangeServiceConfig2W)(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
PChangeServiceConfig2W pOrigChangeServiceConfig2W = NULL;
BOOL WINAPI MyChangeServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)dwInfoLevel));
	return pOrigChangeServiceConfig2W(hService, dwInfoLevel, lpInfo);
}
typedef BOOL(WINAPI* PCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
PCryptDecrypt pOrigCryptDecrypt = NULL;
BOOL WINAPI MyCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
	BOOL x = pOrigCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
	if (x)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)(char*)pbData);
	return x;
}
typedef BOOL(WINAPI* PCryptVerifySignatureW)(HCRYPTPROV hProv, BYTE* pbSignature, DWORD dwSigLen, HCRYPTHASH hHash, LPCWSTR sDescription, DWORD dwFlags);
PCryptVerifySignatureW pOrigCryptVerifySignatureW = NULL;
BOOL WINAPI MyCryptVerifySignatureW(HCRYPTPROV hProv, BYTE* pbSignature, DWORD dwSigLen, HCRYPTHASH hHash, LPCWSTR sDescription, DWORD dwFlags) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigCryptVerifySignatureW(hProv, pbSignature, dwSigLen, hHash, sDescription, dwFlags);
}
typedef BOOL(WINAPI* PCryptImportKey)(HCRYPTPROV hProv, CONST BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
PCryptImportKey pOrigCryptImportKey = NULL;
BOOL WINAPI MyCryptImportKey(HCRYPTPROV hProv, CONST BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigCryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}
typedef SC_HANDLE(WINAPI* PCreateServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
PCreateServiceW pOrigCreateServiceW = NULL;
SC_HANDLE WINAPI MyCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpServiceName));
	return pOrigCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}
typedef SC_HANDLE(WINAPI* POpenServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
POpenServiceW pOrigOpenServiceW = NULL;
SC_HANDLE WINAPI MyOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpServiceName));
	return pOrigOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
}
typedef BOOL(WINAPI* PCryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
PCryptEncrypt pOrigCryptEncrypt = NULL;
BOOL WINAPI MyCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
	std::string y = ByteArrayToStringNoOperator((BYTE*)pbData, *pdwDataLen);
	WriteToLogFile((std::string)__FUNCTION__ + " ----> " + y);
	BOOL x = pOrigCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
	y = ByteArrayToStringNoOperator((BYTE*)pbData, *pdwDataLen);
	WriteToLogFile((std::string)__FUNCTION__ + " -----> " + y);
	return x;
}
typedef BOOL(WINAPI* PDeleteService)(SC_HANDLE hService);
PDeleteService pOrigDeleteService = NULL;
BOOL WINAPI MyDeleteService(SC_HANDLE hService) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigDeleteService(hService);
}
typedef BOOL(WINAPI* PCreateProcessAsUserW)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
PCreateProcessAsUserW pOrigCreateProcessAsUserW = NULL;
BOOL WINAPI MyCreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	if (lpApplicationName)
		WriteToLogFile((std::string)__FUNCTION__ + " lpApplicationName ---> " + (std::string)WideCharToMultiByteString(lpApplicationName));
	if (lpCommandLine)
		WriteToLogFile((std::string)__FUNCTION__ + " lpCommandLine ----> " + (std::string)WideCharToMultiByteString(lpCommandLine));
	return pOrigCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
typedef LONG(WINAPI* LPFN_REGSETVALUEEXW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
LPFN_REGSETVALUEEXW pOrigRegSetValueExW = NULL;
LONG WINAPI MyRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
	std::string x = ByteArrayToStringNoOperator(lpData, cbData);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpValueName));
	WriteToLogFile((std::string)__FUNCTION__ + " ----> " + x);
	return pOrigRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

typedef BOOL(WINAPI* PCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
PCryptCreateHash pOrigCryptCreateHash = NULL;
BOOL WINAPI MyCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)Algid) + " |  " + std::to_string(dwFlags));
	return pOrigCryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
}
typedef BOOL(WINAPI* PCryptExportKey)(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
PCryptExportKey pOrigCryptExportKey = NULL;
BOOL WINAPI MyCryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigCryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}
typedef BOOL(WINAPI* PQueryServiceConfig2W)(SC_HANDLE hService, DWORD dwInfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
PQueryServiceConfig2W pOrigQueryServiceConfig2W = NULL;
BOOL WINAPI MyQueryServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)dwInfoLevel));
	return pOrigQueryServiceConfig2W(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);
}
typedef SC_HANDLE(WINAPI* POpenSCManagerW)(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
POpenSCManagerW pOrigOpenSCManagerW = NULL;
SC_HANDLE WINAPI MyOpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
	if (lpMachineName)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpMachineName));
	if (lpDatabaseName)
		WriteToLogFile((std::string)__FUNCTION__ + " ----> " + (std::string)WideCharToMultiByteString(lpDatabaseName));
	return pOrigOpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
}
typedef LONG(WINAPI* LPFN_REGCREATEKEYEXW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
LPFN_REGCREATEKEYEXW pOrigRegCreateKeyExW = NULL;
LONG WINAPI MyRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpSubKey) + std::to_string((unsigned long)hKey));
	return pOrigRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
		lpSecurityAttributes, phkResult, lpdwDisposition);
}
typedef BOOL(WINAPI* PDuplicateTokenEx)(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
PDuplicateTokenEx pOrigDuplicateTokenEx = NULL;
BOOL WINAPI MyDuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigDuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);
}
typedef BOOL(WINAPI* LPFN_WTSQUERYUSERTOKEN)(ULONG, PHANDLE);
LPFN_WTSQUERYUSERTOKEN pOrigWTSQueryUserToken = NULL;
BOOL WINAPI MyWTSQueryUserToken(ULONG SessionId, PHANDLE phToken)
{
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigWTSQueryUserToken(SessionId, phToken);
}
typedef BOOL(WINAPI* PCryptStringToBinaryW)(LPCWSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
PCryptStringToBinaryW pOrigCryptStringToBinaryW = NULL;
BOOL WINAPI MyCryptStringToBinaryW(LPCWSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(pszString));
	return pOrigCryptStringToBinaryW(pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags);
}
typedef BOOL(WINAPI* PCryptBinaryToStringW)(BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD* pcchString);
PCryptBinaryToStringW pOrigCryptBinaryToStringW = NULL;
BOOL WINAPI MyCryptBinaryToStringW(BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD* pcchString) {
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigCryptBinaryToStringW(pbBinary, cbBinary, dwFlags, pszString, pcchString);
}
typedef BOOL(WINAPI* PCryptDecodeObjectEx)(DWORD dwCertEncodingType, LPCSTR lpszStructType, BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo);
PCryptDecodeObjectEx pOrigCryptDecodeObjectEx = NULL;
BOOL WINAPI MyCryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) {
	BOOL x = pOrigCryptDecodeObjectEx(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo);
	if (x) {
		std::string y = ByteArrayToStringNoOperator((BYTE*)pvStructInfo, *pcbStructInfo);
		WriteToLogFile((std::string)__FUNCTION__ + " ----> " + y);
	}
	return x;
}

typedef BOOL(WINAPI* LPFN_SETEVENT)(HANDLE);
LPFN_SETEVENT pOrigSetEvent = NULL;
BOOL WINAPI MySetEvent(HANDLE hEvent)
{
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + std::to_string((int)hEvent));
	return pOrigSetEvent(hEvent);
}

typedef int(__cdecl* LPFN__SNWPRINTF)(wchar_t*, size_t, const wchar_t*, ...);
LPFN__SNWPRINTF pOrig_snwprintf = NULL;
int __cdecl My_snwprintf(wchar_t* buffer, size_t count, const wchar_t* format, ...)
{
	// 在进行字符串格式化之前，可以做一些自定义的操作
	// 例如，记录格式化的内容或者修改内容

	// 调用原始的_snwprintf函数，注意这里是通过保存的函数指针来调用
	va_list args;
	va_start(args, format);
	int result = pOrig_snwprintf(buffer, count, format, args);
	va_end(args);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(buffer));

	return result;
}

typedef int(__cdecl* LPFN_SNPRINTF)(char*, size_t, const char*, ...);
LPFN_SNPRINTF pOrig_snprintf = NULL;
int __cdecl My_snprintf(char* buffer, size_t count, const char* format, ...)
{
	// 在进行字符串格式化之前，可以做一些自定义的操作
	// 例如，记录格式化的内容或者修改内容

	// 调用原始的_snprintf函数，注意这里是通过保存的函数指针来调用
	va_list args;
	va_start(args, format);
	int result = pOrig_snprintf(buffer, count, format, args);
	va_end(args);
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)(buffer));

	return result;
}

typedef VOID(WINAPI* LPFN_RTLGETVERSION)(LPOSVERSIONINFOEXW);
LPFN_RTLGETVERSION pOrigRtlGetVersion = NULL;
VOID WINAPI MyRtlGetVersion(LPOSVERSIONINFOEXW lpVersionInformation)
{
	WriteToLogFile((std::string)__FUNCTION__);
	pOrigRtlGetVersion(lpVersionInformation);
	WriteToLogFile((std::string)__FUNCTION__ +
		" ---> " +
		std::to_string(lpVersionInformation->dwMajorVersion) + " | " +
		std::to_string(lpVersionInformation->dwMinorVersion) + " | " +
		std::to_string(lpVersionInformation->dwBuildNumber)
	);
}

typedef LPWSTR(WINAPI* LPFN_PATHFINDFILENAMEW)(LPCWSTR);
LPFN_PATHFINDFILENAMEW pOrigPathFindFileNameW = NULL;
LPWSTR WINAPI MyPathFindFileNameW(LPCWSTR pszPath)
{
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(pszPath));
	return pOrigPathFindFileNameW(pszPath);
}

typedef BOOL(WINAPI* LPFN_ENUMSERVICESSTATUSEXW)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
LPFN_ENUMSERVICESSTATUSEXW pOrigEnumServicesStatusExW = NULL;
BOOL WINAPI MyEnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState,
	LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned,
	LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize,
		pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
}

typedef LONG(WINAPI* LPFN_REGDELETEVALUEW)(HKEY, LPCWSTR);
LPFN_REGDELETEVALUEW pOrigRegDeleteValueW = NULL;
LONG WINAPI MyRegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpValueName));
	return pOrigRegDeleteValueW(hKey, lpValueName);
}

typedef BOOL(WINAPI* LPFN_INTERNETREADFILE)(HINTERNET, LPVOID, DWORD, LPDWORD);
LPFN_INTERNETREADFILE pOrigInternetReadFile = NULL;
BOOL WINAPI MyInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	BOOL x = pOrigInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	if (x) {
		std::string y = ByteArrayToStringNoOperator((BYTE*)lpBuffer, *lpdwNumberOfBytesRead);
		WriteToLogFile((std::string)__FUNCTION__ + " ----> " + y);
	}
	return x;
}

typedef BOOL(WINAPI* LPFN_CREATEENVIRONMENTBLOCK)(LPVOID*, HANDLE, BOOL);
LPFN_CREATEENVIRONMENTBLOCK pOrigCreateEnvironmentBlock = NULL;
BOOL WINAPI MyCreateEnvironmentBlock(LPVOID* lpEnvironment, HANDLE hToken, BOOL bInherit)
{
	WriteToLogFile((std::string)__FUNCTION__);
	return pOrigCreateEnvironmentBlock(lpEnvironment, hToken, bInherit);
}

typedef int(WINAPI* LPFN_SHFILEOPERATIONW)(LPSHFILEOPSTRUCTW);
LPFN_SHFILEOPERATIONW pOrigSHFileOperationW = NULL;
int WINAPI MySHFileOperationW(LPSHFILEOPSTRUCTW lpFileOp)
{
	if (lpFileOp->pFrom)
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpFileOp->pFrom));
	if (lpFileOp->pTo)
		WriteToLogFile((std::string)__FUNCTION__ + " ----> " + (std::string)WideCharToMultiByteString(lpFileOp->pTo));
	WriteToLogFile((std::string)__FUNCTION__ + " -----> " + std::to_string(lpFileOp->wFunc));
	return pOrigSHFileOperationW(lpFileOp);
}

typedef HRESULT(WINAPI* LPFN_SHGETFOLDERPATHW)(HWND, int, HANDLE, DWORD, LPWSTR);
LPFN_SHGETFOLDERPATHW pOrigSHGetFolderPathW = NULL;
HRESULT WINAPI MySHGetFolderPathW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath)
{
	WriteToLogFile((std::string)__FUNCTION__ + " -----> " + std::to_string(csidl));
	HRESULT hr = pOrigSHGetFolderPathW(hwnd, csidl, hToken, dwFlags, pszPath);
	if (SUCCEEDED(hr)) {
		WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(pszPath));
	}
	return hr;
}

typedef HINTERNET(WINAPI* LPFN_InternetOpenW)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
LPFN_InternetOpenW TrueInternetOpenW = NULL;
HINTERNET WINAPI MyInternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
	WriteToLogFile((std::string)__FUNCTION__);
	return TrueInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}
typedef HINTERNET(WINAPI* LPFN_InternetConnectW)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUsername, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
LPFN_InternetConnectW TrueInternetConnectW = NULL;
HINTERNET WINAPI MyInternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUsername, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpszServerName) + "|" + std::to_string((int)nServerPort));
	return TrueInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext);
}

typedef BOOL(WINAPI* LPFN_HttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
LPFN_HttpSendRequestW TrueHttpSendRequestW = NULL;
BOOL WINAPI MyHttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
	WriteToLogFile((std::string)__FUNCTION__ + " -----> " + std::to_string(dwOptionalLength));
	std::string y = ByteArrayToStringNoOperator((BYTE*)lpOptional, dwOptionalLength);
	WriteToLogFile((std::string)__FUNCTION__ + " ----> " + y);
	return TrueHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}
typedef HINTERNET(WINAPI* LPFN_HttpOpenRequestW)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
LPFN_HttpOpenRequestW TrueHttpOpenRequestW = NULL;
HINTERNET WINAPI MyHttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
	WriteToLogFile((std::string)__FUNCTION__ + " ---> " + (std::string)WideCharToMultiByteString(lpszVerb) + "|" + (std::string)WideCharToMultiByteString(lpszObjectName));
	return TrueHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
}

typedef LONG(__stdcall* fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
void MyDetourAttach(void** oriFunc, void* newFunc, void* func)
{
	/*
	MessageBoxA(NULL, (
		std::to_string((int)oriFunc) + " " +
		std::to_string((int)newFunc) + " " +
		std::to_string((int)func)).data(), "OK", MB_OK);
	*/

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	*oriFunc = func;
	DetourAttach(oriFunc, newFunc);

	DetourTransactionCommit();
}
#include <chrono>
#include <ctime>
#include <iomanip>
// 将十六进制数字转换为字符串
void hexToString(int hexNumber, char* hexString) {
	// 字符映射表，用于将十六进制数字转换为字符
	char hexMap[] = "0123456789ABCDEF";

	// 循环处理每一位十六进制数字
	for (int i = 0; i < 8; ++i) { // 这里假设 int 类型是 4 字节
		// 取出当前位的值
		int nibble = (hexNumber >> (4 * (7 - i))) & 0xF;
		// 使用映射表将当前位的值转换为字符并存储到字符串中
		hexString[i] = hexMap[nibble];
	}
	// 添加字符串结尾的空字符
	hexString[8] = '\0';
}
void WriteToLogFile(std::string message) {
	// 获取当前时间
	time_t now = time(nullptr);

	message = std::to_string(now) + " " + message + "\r\n";

	// 打开日志文件
	std::wstring filename = L"C:\\LogFile.txt";
	HANDLE hFile = pOrigCreateFileW(filename.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
	}

	// 移动文件指针到文件末尾
	SetFilePointer(hFile, 0, NULL, FILE_END);

	// 写入消息到日志文件
	DWORD bytesWritten;
	bool success = pOrigWriteFile(hFile, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL);

	// 关闭文件句柄
	CloseHandle(hFile);

}
char* WideCharToMultiByteString(const WCHAR* wideStr) {
	// 计算转换后的字符串所需的缓冲区大小
	int bufferSize = pOrigWideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);

	// 分配足够的缓冲区
	char* multiByteStr = new char[bufferSize];

	// 将宽字符转换为多字节字符
	pOrigWideCharToMultiByte(CP_UTF8, 0, wideStr, -1, multiByteStr, bufferSize, NULL, NULL);

	return multiByteStr;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		fnRtlGetVersion pRtlGetVersion;
		HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
		pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");

		MyDetourAttach(&(PVOID&)pOrigWideCharToMultiByte, MyWideCharToMultiByte, WideCharToMultiByte);
		MyDetourAttach(&(PVOID&)pOrigCreateFileW, MyCreateFileW, CreateFileW);
		MyDetourAttach(&(PVOID&)pOrigWriteFile, MyWriteFile, WriteFile); // 这个程序不写文件
		MyDetourAttach(&(PVOID&)pOriginalGetModuleHandleA, MyGetModuleHandleA, GetModuleHandleA);
		MyDetourAttach(&(PVOID&)pOriginalWaitForSingleObject, MyWaitForSingleObject, WaitForSingleObject);
		MyDetourAttach(&(PVOID&)pOriginalGetTickCount, MyGetTickCount, GetTickCount);
		MyDetourAttach(&(PVOID&)pOriginalLoadLibraryW, MyLoadLibraryW, LoadLibraryW);
		MyDetourAttach(&(PVOID&)pOriginalGetProcessHeap, MyGetProcessHeap, GetProcessHeap);
		MyDetourAttach(&(PVOID&)pOrigReadDirectoryChangesW, MyReadDirectoryChangesW, ReadDirectoryChangesW);
		MyDetourAttach(&(PVOID&)pOrigLoadLibraryA, MyLoadLibraryA, LoadLibraryA);
		MyDetourAttach(&(PVOID&)pOrigSetFileInformationByHandle, MySetFileInformationByHandle, SetFileInformationByHandle);
		//MyDetourAttach(&(PVOID&)pOrigRtlAllocateHeap, MyRtlAllocateHeap, RtlAllocateHeap); // 没用
		MyDetourAttach(&(PVOID&)pOrigVirtualFree, MyVirtualFree, VirtualFree);
		MyDetourAttach(&(PVOID&)pOriglstrcmpiA, MylstrcmpiA, lstrcmpiA);
		MyDetourAttach(&(PVOID&)pOriglstrcpynW, MylstrcpynW, lstrcpynW);
		MyDetourAttach(&(PVOID&)pOrigCreateEventW, MyCreateEventW, CreateEventW);
		MyDetourAttach(&(PVOID&)pOrigGetNativeSystemInfo, MyGetNativeSystemInfo, GetNativeSystemInfo);
		MyDetourAttach(&(PVOID&)pOrigQueryFullProcessImageNameW, MyQueryFullProcessImageNameW, QueryFullProcessImageNameW);
		MyDetourAttach(&(PVOID&)pOrigOpenProcess, MyOpenProcess, OpenProcess);
		MyDetourAttach(&(PVOID&)pOrigCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot, CreateToolhelp32Snapshot);
		MyDetourAttach(&(PVOID&)pOrigProcess32FirstW, MyProcess32FirstW, Process32FirstW);
		MyDetourAttach(&(PVOID&)pOrigProcess32NextW, MyProcess32NextW, Process32NextW);
		//MyDetourAttach(&(PVOID&)pOrigCloseHandle, MyCloseHandle, CloseHandle); // 没用
		MyDetourAttach(&(PVOID&)pOriglstrcpyW, MyLstrcpyW, lstrcpyW);
		MyDetourAttach(&(PVOID&)pOrigGetModuleFileNameW, MyGetModuleFileNameW, GetModuleFileNameW);
		MyDetourAttach(&(PVOID&)pOrigGetTickCount64, MyGetTickCount64, GetTickCount64);
		MyDetourAttach(&(PVOID&)pOrigSetEvent, MySetEvent, SetEvent); // 没用
		MyDetourAttach(&(PVOID&)pOrigGetTempPathW, MyGetTempPathW, GetTempPathW);
		MyDetourAttach(&(PVOID&)pOrigGetCommandLineW, MyGetCommandLineW, GetCommandLineW);
		MyDetourAttach(&(PVOID&)pOrigGetSystemTimeAsFileTime, MyGetSystemTimeAsFileTime, GetSystemTimeAsFileTime);
		MyDetourAttach(&(PVOID&)pOrigFindClose, MyFindClose, FindClose);
		MyDetourAttach(&(PVOID&)pOrigVirtualAlloc, MyVirtualAlloc, VirtualAlloc);
		MyDetourAttach(&(PVOID&)pOrigFindNextFileW, MyFindNextFileW, FindNextFileW);
		MyDetourAttach(&(PVOID&)pOrigDuplicateHandle, MyDuplicateHandle, DuplicateHandle);
		MyDetourAttach(&(PVOID&)pOriglstrlenW, MylstrlenW, lstrlenW);
		MyDetourAttach(&(PVOID&)pOriglstrlenA, MylstrlenA, lstrlenA);

		// 刚刚是这里 2下
		MyDetourAttach(&(PVOID&)pOrigCreateThread, MyCreateThread, CreateThread);
		MyDetourAttach(&(PVOID&)pOrigGetCurrentProcessId, MyGetCurrentProcessId, GetCurrentProcessId);
		// 这里不行 不知道为啥 , 这里是过几十秒崩
		//MyDetourAttach(&(PVOID&)pOrigGetProcAddress, MyGetProcAddress, GetProcAddress);
		//MyDetourAttach(&(PVOID&)pOrigGetWindowsDirectoryW, MyGetWindowsDirectoryW, GetWindowsDirectoryW);

		// 刚刚是这里 4丄
		MyDetourAttach(&(PVOID&)pOrigGetVolumeInformationW, MyGetVolumeInformationW, GetVolumeInformationW);
		MyDetourAttach(&(PVOID&)pOrigMultiByteToWideChar, MyMultiByteToWideChar, MultiByteToWideChar);
		MyDetourAttach(&(PVOID&)pOrigGetTempFileNameW, MyGetTempFileNameW, GetTempFileNameW);
		MyDetourAttach(&(PVOID&)pOrigGetComputerNameA, MyGetComputerNameA, GetComputerNameA);
		// 刚刚是这里 3
		MyDetourAttach(&(PVOID&)pOrigWTSGetActiveConsoleSessionId, MyWTSGetActiveConsoleSessionId, WTSGetActiveConsoleSessionId);
		MyDetourAttach(&(PVOID&)pOrigFindFirstFileW, MyFindFirstFileW, FindFirstFileW);
		MyDetourAttach(&(PVOID&)pOriglstrcmpiW, MylstrcmpiW, lstrcmpiW);
		MyDetourAttach(&(PVOID&)pOrigDeleteFileW, MyDeleteFileW, DeleteFileW);
		MyDetourAttach(&(PVOID&)pOrigProcessIdToSessionId, MyProcessIdToSessionId, ProcessIdToSessionId);
		MyDetourAttach(&(PVOID&)pOrigExitProcess, MyExitProcess, ExitProcess);
		//MyDetourAttach(&(PVOID&)pOrigGetCurrentProcess, MyGetCurrentProcess, GetCurrentProcess); // 没用
		MyDetourAttach(&(PVOID&)pOrigGetFileInformationByHandleEx, MyGetFileInformationByHandleEx, GetFileInformationByHandleEx);
		//MyDetourAttach(&(PVOID&)pOrigHeapFree, MyHeapFree, HeapFree); // 这俩开局就崩
		//MyDetourAttach(&(PVOID&)pOrigLocalFree, MyLocalFree, LocalFree); // 这俩会崩

		MyDetourAttach(&(PVOID&)pOrigCreateProcessW, MyCreateProcessW, CreateProcessW);
		MyDetourAttach(&(PVOID&)pOrigRemoveDirectoryW, MyRemoveDirectoryW, RemoveDirectoryW);
		MyDetourAttach(&(PVOID&)pOrig_snwprintf, My_snwprintf, _snwprintf);
		MyDetourAttach(&(PVOID&)pOrig_snprintf, My_snprintf, _snprintf);
		//MyDetourAttach(&(PVOID&)pOrigmemset, Mymemset, memset); // 没用
		MyDetourAttach(&(PVOID&)pOrigRtlGetVersion, MyRtlGetVersion, pRtlGetVersion);
		//MyDetourAttach(&(PVOID&)pOrigmemcpy, Mymemcpy, memcpy); // 没用
		MyDetourAttach(&(PVOID&)pOrigPathFindFileNameW, MyPathFindFileNameW, PathFindFileNameW);
		// 刚刚是这里
		MyDetourAttach(&(PVOID&)pOrigCryptGetHashParam, MyCryptGetHashParam, CryptGetHashParam);
		MyDetourAttach(&(PVOID&)pOrigCryptGenKey, MyCryptGenKey, CryptGenKey);
		MyDetourAttach(&(PVOID&)pOrigChangeServiceConfig2W, MyChangeServiceConfig2W, ChangeServiceConfig2W);
		MyDetourAttach(&(PVOID&)pOrigCryptDecrypt, MyCryptDecrypt, CryptDecrypt);
		MyDetourAttach(&(PVOID&)pOrigCryptVerifySignatureW, MyCryptVerifySignatureW, CryptVerifySignatureW);
		MyDetourAttach(&(PVOID&)pOrigCryptImportKey, MyCryptImportKey, CryptImportKey);
		MyDetourAttach(&(PVOID&)pOrigCreateServiceW, MyCreateServiceW, CreateServiceW);
		//MyDetourAttach(&(PVOID&)pOrigCloseServiceHandle, MyCloseServiceHandle, CloseServiceHandle); // 没用
		MyDetourAttach(&(PVOID&)pOrigOpenServiceW, MyOpenServiceW, OpenServiceW);
		//MyDetourAttach(&(PVOID&)pOrigRegCloseKey, MyRegCloseKey, RegCloseKey); // 没用
		MyDetourAttach(&(PVOID&)pOrigCryptEncrypt, MyCryptEncrypt, CryptEncrypt);
		MyDetourAttach(&(PVOID&)pOrigDeleteService, MyDeleteService, DeleteService);
		MyDetourAttach(&(PVOID&)pOrigCreateProcessAsUserW, MyCreateProcessAsUserW, CreateProcessAsUserW);
		//MyDetourAttach(&(PVOID&)pOrigCryptReleaseContext, MyCryptReleaseContext, CryptReleaseContext); // 用于释放一个加密服务提供者（CSP）的句柄, 没用!
		MyDetourAttach(&(PVOID&)pOrigRegSetValueExW, MyRegSetValueExW, RegSetValueExW);
		//MyDetourAttach(&(PVOID&)pOrigCryptDuplicateHash, MyCryptDuplicateHash, CryptDuplicateHash); // 用于复制哈希对象的句柄, 没用!
		//MyDetourAttach(&(PVOID&)pOrigCryptDestroyKey, MyCryptDestroyKey, CryptDestroyKey); // 释放用, 没用!
		//MyDetourAttach(&(PVOID&)pOrigCryptAcquireContextW, MyCryptAcquireContextW, CryptAcquireContextW); // 用于获取加密服务提供者（CSP）的句柄, 没用!
		//MyDetourAttach(&(PVOID&)pOrigCryptDestroyHash, MyCryptDestroyHash, CryptDestroyHash); // 释放用, 没用
		MyDetourAttach(&(PVOID&)pOrigEnumServicesStatusExW, MyEnumServicesStatusExW, EnumServicesStatusExW); // 只是看看执行在哪里了
		MyDetourAttach(&(PVOID&)pOrigCryptCreateHash, MyCryptCreateHash, CryptCreateHash);
		MyDetourAttach(&(PVOID&)pOrigCryptExportKey, MyCryptExportKey, CryptExportKey);
		MyDetourAttach(&(PVOID&)pOrigRegDeleteValueW, MyRegDeleteValueW, RegDeleteValueW); // 只是看看删了什么
		MyDetourAttach(&(PVOID&)pOrigQueryServiceConfig2W, MyQueryServiceConfig2W, QueryServiceConfig2W);
		MyDetourAttach(&(PVOID&)pOrigOpenSCManagerW, MyOpenSCManagerW, OpenSCManagerW);
		MyDetourAttach(&(PVOID&)pOrigRegCreateKeyExW, MyRegCreateKeyExW, RegCreateKeyExW);
		MyDetourAttach(&(PVOID&)pOrigDuplicateTokenEx, MyDuplicateTokenEx, DuplicateTokenEx);
		//MyDetourAttach(&(PVOID&)pOrigWTSQueryUserToken, MyWTSQueryUserToken, WTSQueryUserToken); // 获取该会话的用户令牌, 说重复定义
		//MyDetourAttach(&(PVOID&)pOrigObtainUserAgentString, MyObtainUserAgentString, ObtainUserAgentString); // detours不让hook
		//MyDetourAttach(&(PVOID&)pOrigDestroyEnvironmentBlock, MyDestroyEnvironmentBlock, DestroyEnvironmentBlock); // 没用
		MyDetourAttach(&(PVOID&)pOrigCreateEnvironmentBlock, MyCreateEnvironmentBlock, CreateEnvironmentBlock);
		MyDetourAttach(&(PVOID&)pOrigCryptStringToBinaryW, MyCryptStringToBinaryW, CryptStringToBinaryW);
		MyDetourAttach(&(PVOID&)pOrigCryptBinaryToStringW, MyCryptBinaryToStringW, CryptBinaryToStringW);
		MyDetourAttach(&(PVOID&)pOrigCryptDecodeObjectEx, MyCryptDecodeObjectEx, CryptDecodeObjectEx);
		MyDetourAttach(&(PVOID&)pOrigSHFileOperationW, MySHFileOperationW, SHFileOperationW);
		//MyDetourAttach(&(PVOID&)pOrigCommandLineToArgvW, MyCommandLineToArgvW, CommandLineToArgvW); // 将命令行参数字符串转换为参数数组 , 没用
		MyDetourAttach(&(PVOID&)pOrigSHGetFolderPathW, MySHGetFolderPathW, SHGetFolderPathW);
		MyDetourAttach(&(PVOID&)pOrigInternetReadFile, MyInternetReadFile, InternetReadFile); // 不知道为啥不能加载 winnet
		MyDetourAttach(&(PVOID&)TrueHttpOpenRequestW, MyHttpOpenRequestW, HttpOpenRequestW); // 
		MyDetourAttach(&(PVOID&)TrueHttpSendRequestW, MyHttpSendRequestW, HttpSendRequestW); // 
		MyDetourAttach(&(PVOID&)TrueInternetOpenW, MyInternetOpenW, InternetOpenW); // 
		MyDetourAttach(&(PVOID&)TrueInternetConnectW, MyInternetConnectW, InternetConnectW); // 

		// HttpOpenRequestW		// GET && 路径
		// HttpQueryInfoW		// 用于检索 HTTP 请求或响应的头信息
		// HttpSendRequestW		// 发送请求
		// InternetCloseHandle	// 关闭
		// InternetConnectW		// IP && Port
		// InternetOpenW		// 打开 Internet 句柄
		// InternetSetOptionW	// 设置一些东西 函数设置了一个选项标志 INTERNET_FLAG_RELOAD。如果设置成功，函数将返回非零值。最后，我们关闭 Internet 句柄，释放资源。
	}

	return TRUE;
}

