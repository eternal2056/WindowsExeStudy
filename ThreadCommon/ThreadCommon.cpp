#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

DWORD ThreadCallBackA(LPVOID lpThreadParameter) {
	for (int i = 0; i < 100; i++) {
		printf("ThreadCallBackA %d\r\n", i);
	}
	return 0;
}
DWORD ThreadCallBackB(LPVOID lpThreadParameter) {
	for (int i = 0; i < 100; i++) {
		printf("ThreadCallBackB %d\r\n", i);
	}
	return 0;
}

int main()
{
	DWORD lpThreadIdA = 0;
	HANDLE hThreadA = CreateThread(
		NULL, // 安全属性
		NULL, // 堆栈的初始大小
		(LPTHREAD_START_ROUTINE)ThreadCallBackA, // 函数地址, 线程开启的时候调用的函数
		NULL, // ThreadCallBackA 函数的参数
		NULL, // 0 -> 立即执行函数 4 -> 需要调用 ResumeThread
		&lpThreadIdA // 返回线程ID
	);
	DWORD lpThreadIdB = 0;
	HANDLE hThreadB = CreateThread(
		NULL, // 安全属性
		NULL, // 堆栈的初始大小
		(LPTHREAD_START_ROUTINE)ThreadCallBackB, // 函数地址, 线程开启的时候调用的函数
		NULL, // ThreadCallBackA 函数的参数
		NULL, // 0 -> 立即执行函数 4 -> 需要调用 ResumeThread
		&lpThreadIdB // 返回线程ID
	);
	for (int i = 0; i < 100; i++) {
		printf("main %d\r\n", i); // main也是一个线程, 所以有三个线程
	}
	WaitForSingleObject(hThreadA, INFINITE); // 永久等待, 等待线程执行完
	WaitForSingleObject(hThreadB, INFINITE); // 永久等待, 等待线程执行完

	DWORD dwProcessId = 53192; // 指定进程id
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
	THREADENTRY32 th32;
	th32.dwSize = sizeof(THREADENTRY32);
	BOOL bRet = Thread32First(hSnap, &th32); // 遍历的是所有线程
	while (bRet) {
		if (th32.th32OwnerProcessID == dwProcessId) {
			printf("th32ThreadID %d\r\n", th32.th32ThreadID); // 当前线程id
			printf("th32OwnerProcessID %d\r\n", th32.th32OwnerProcessID); // 所属进程id
			printf("tpBasePri %d\r\n", th32.tpBasePri); // 线程优先级
			printf("-----------------------\r\n");

			// 结束线程
			//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // 获取线程句柄
			//TerminateThread(hThread, -1); // -1 -> 异常退出

			// 挂起线程
			//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // 获取线程句柄
			//SuspendThread(hThread);

			// 恢复线程
			//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // 获取线程句柄
			//ResumeThread(hThread);
		}

		bRet = Thread32Next(hSnap, &th32);
	}


	//printf("End!\r\n");
	system("pause"); // 不调用这个会导致进程结束, 导致线程没运行完就死掉
	return 0;
}