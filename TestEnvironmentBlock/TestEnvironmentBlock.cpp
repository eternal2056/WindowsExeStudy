#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

// 环境变量
// Advanced system settings -> Environment Variables.
int main() {
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
		return 1;
	}

	PVOID pEnv = NULL;
	if (!CreateEnvironmentBlock(&pEnv, hToken, TRUE)) {
		std::cerr << "Failed to create environment block: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return 1;
	}

	// 打印环境变量
	LPWSTR lpEnvironmentStrings = static_cast<LPWSTR>(pEnv);
	while (*lpEnvironmentStrings) {
		std::wcout << lpEnvironmentStrings << std::endl;
		lpEnvironmentStrings += lstrlenW(lpEnvironmentStrings) + 1;
	}

	// 释放环境块
	DestroyEnvironmentBlock(pEnv);

	// 关闭令牌句柄
	CloseHandle(hToken);






	WCHAR volumeName[MAX_PATH + 1];
	WCHAR fileSystemName[MAX_PATH + 1];
	DWORD serialNumber;
	DWORD maxComponentLength;
	DWORD fileSystemFlags;

	// 获取当前目录所在逻辑驱动器的卷标、文件系统名称、序列号等信息
	if (!GetVolumeInformationW(NULL, volumeName, MAX_PATH + 1, &serialNumber, &maxComponentLength, &fileSystemFlags, fileSystemName, MAX_PATH + 1)) {
		printf("GetVolumeInformationW failed: %d\n", GetLastError());
		return 1;
	}

	// 打印获取到的信息
	wprintf(L"Volume Name: %s\n", volumeName);
	wprintf(L"File System Name: %s\n", fileSystemName);
	printf("Serial Number: %lu\n", serialNumber);
	printf("Max Component Length: %lu\n", maxComponentLength);
	printf("File System Flags: 0x%lX\n", fileSystemFlags);






	system("pause");
	return 0;
}