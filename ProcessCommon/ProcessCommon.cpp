#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

/*
typedef struct _STARTUPINFOA {
	DWORD   cb;						当前结构的大小, 事先填充
	LPSTR   lpReserved;				保留字段, 未使用
	LPSTR   lpDesktop;				指定桌面名称
	LPSTR   lpTitle;				控制台程序的窗口标题
	DWORD   dwX;					新窗口位置信息, 尺寸信息
	DWORD   dwY;
	DWORD   dwXSize;
	DWORD   dwYSize;
	DWORD   dwXCountChars;			控制台可以显示的行数和列数
	DWORD   dwYCountChars;
	DWORD   dwFillAttribute;		指定控制台程序的背景色
	DWORD   dwFlags;				指定当前结构哪个成员是有效的
	WORD    wShowWindow;			窗口的显示方式
	WORD    cbReserved2;			保留
	LPBYTE  lpReserved2;			保留
	HANDLE  hStdInput;				标准的输入句柄
	HANDLE  hStdOutput;				标准的输出句柄
	HANDLE  hStdError;				标准的错误句柄
} STARTUPINFOA, *LPSTARTUPINFOA;
*/

/*
typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;		当前进程用 CreateProcess 创建的进程句柄
	HANDLE hThread;			线程句柄
	DWORD dwProcessId;		进程ID
	DWORD dwThreadId;		线程ID
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

*/

int main()
{
	// 进程需要两个
	// 1. 管理用的内核对象 -> 进程句柄
	// 2. 包含代码数据的地址空间
	STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };
	//StartupInfo.cb = sizeof(STARTUPINFO); // 这个会报错, 好像不能这么搞
	PROCESS_INFORMATION ProcessInformation;
	BOOL bRet = CreateProcess(
		"C:\\Windows\\SysWOW64\\calc.exe", // 可执行模块路径
		NULL,	// 传递给可执行模块的参数
		NULL,	// 安全特性->进程  NULL -> 默认安全属性
		NULL,	// 安全特性->线程
		FALSE,	// 通过这个进程打开的子进程能不能继承 可继承句柄
		0,		// 指定 优先级 
		NULL,	// 指定 环境变量
		NULL,	// 指定 新进程创建的 当前目录
		&StartupInfo, // 启动信息 IN 我们自己写的
		&ProcessInformation // 进程相关信息 OUT
	);
	if (!bRet) {
		printf("CreateProcess Failed!\n");
	}
	else {
		printf("hProcess %d\n", ProcessInformation.hProcess);
		printf("hProcess %d\n", ProcessInformation.hThread);
		printf("dwProcessId %d\n", ProcessInformation.dwProcessId);
		printf("dwThreadId %d\n", ProcessInformation.dwThreadId);
		CloseHandle(ProcessInformation.hProcess); // 句柄不用的话可以关闭掉, 防止内存泄露啥的安全问题
		CloseHandle(ProcessInformation.hThread);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 59196); // FALSE -> 返回的句柄是否可以继承
	if (hProcess != INVALID_HANDLE_VALUE) { // 判断句柄是否有效
		printf("OpenProcess Success!\n");
		TerminateProcess(hProcess, 0); // 关闭进程, 通过句柄
	}
	else {
		printf("OpenProcess Failed!\n");
	}

	/*
	#define TH32CS_SNAPHEAPLIST 0x00000001	堆
	#define TH32CS_SNAPPROCESS  0x00000002	进程 这个不需要指定进程ID
	#define TH32CS_SNAPTHREAD   0x00000004	线程
	#define TH32CS_SNAPMODULE   0x00000008	模块
	*/

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	/*
	typedef struct tagPROCESSENTRY32
{
	DWORD   dwSize;					// 本结构的尺寸
	DWORD   cntUsage;				// 进程的引用计数
	DWORD   th32ProcessID;          // 进程id
	ULONG_PTR th32DefaultHeapID;	// 当前进程默认堆的ID
	DWORD   th32ModuleID;           // 模块ID
	DWORD   cntThreads;				// 当前进程的线程总数
	DWORD   th32ParentProcessID;    // 父进程ID
	LONG    pcPriClassBase;         // 当前进程创建的线程基本优先级
	DWORD   dwFlags;				// 标志位
	CHAR    szExeFile[MAX_PATH];    // 进程对应的文件名
} PROCESSENTRY32;
	*/

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	bRet = Process32First(hSnap, &pe32); // 遍历的是所有线程
	while (bRet) {
		printf("szExeFile %s\r\n", pe32.szExeFile); // 当前线程id
		printf("th32ProcessID %d\r\n", pe32.th32ProcessID); // 所属进程id
		printf("th32ParentProcessID %d\r\n", pe32.th32ParentProcessID); // 线程优先级
		printf("-----------------------\r\n");

		bRet = Process32Next(hSnap, &pe32);
	}
	ExitProcess(0); // 0 -> 正常退出 控制台会关掉
	system("pause"); // 不调用这个会导致进程结束, 导致线程没运行完就死掉
	return 0;
}
