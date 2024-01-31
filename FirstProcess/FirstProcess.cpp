#include <iostream>
#include <windows.h>

void ErrorFunction() {
	// 模拟一个发生错误的情况
	SetLastError(ERROR_FILE_NOT_FOUND);

	// 获取错误代码
	DWORD errorCode = GetLastError();

	// 输出错误代码
	std::cout << "Last Error Code: " << errorCode << std::endl;

	// 使用 FormatMessage 函数获取错误消息
	LPVOID errorMessage;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		errorCode,
		0, // Default language
		(CHAR*)&errorMessage,
		0,
		NULL
	);
	// 输出错误消息
	std::cout << "Error Message: " << static_cast<CHAR*>(errorMessage) << std::endl;

	// 释放消息缓冲区
	LocalFree(errorMessage);
}

int main() {
	ErrorFunction();
	return 0;
}