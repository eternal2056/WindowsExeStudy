///
///
///
#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>

#pragma comment( lib, "dbghelp.lib" )

void dump_callstack(CONTEXT* context)
{
	STACKFRAME sf;
	memset(&sf, 0, sizeof(STACKFRAME));

	sf.AddrPC.Offset = context->Eip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrStack.Offset = context->Esp;
	sf.AddrStack.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = context->Ebp;
	sf.AddrFrame.Mode = AddrModeFlat;

	DWORD machineType = IMAGE_FILE_MACHINE_IA64;

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = GetCurrentThread();

	for (; ; )
	{
		if (!StackWalk(machineType, hProcess, hThread, &sf, context, 0, SymFunctionTableAccess, SymGetModuleBase, 0))
		{
			break;
		}

		if (sf.AddrFrame.Offset == 0)
		{
			break;
		}
		BYTE symbolBuffer[sizeof(SYMBOL_INFO) + 1024];
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;

		pSymbol->SizeOfStruct = sizeof(symbolBuffer);
		pSymbol->MaxNameLen = 1024;

		DWORD64 symDisplacement = 0;
		if (SymFromAddr(hProcess, sf.AddrPC.Offset, 0, pSymbol))
		{
			printf("Function : %s\n", pSymbol->Name);
		}
		else
		{
			printf("SymFromAdd failed!\n");
		}

		IMAGEHLP_LINE lineInfo = { sizeof(IMAGEHLP_LINE) };
		DWORD dwLineDisplacement;

		if (SymGetLineFromAddr(hProcess, sf.AddrPC.Offset, &dwLineDisplacement, &lineInfo))
		{
			printf("[Source File : %s]\n", lineInfo.FileName);
			printf("[Source Line : %u]\n", lineInfo.LineNumber);
		}
		else
		{
			printf("SymGetLineFromAddr failed!\n");
		}
	}
}

DWORD excep_filter(LPEXCEPTION_POINTERS lpEP)
{
	/// init dbghelp.dll
	if (SymInitialize(GetCurrentProcess(), NULL, TRUE))
	{
		printf("Init dbghelp ok.\n");
	}

	dump_callstack(lpEP->ContextRecord);

	if (SymCleanup(GetCurrentProcess()))
	{
		printf("Cleanup dbghelp ok.\n");
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

void func1(int i)
{
	int* p = 0;
	*p = i;
}

void func2(int i)
{
	func1(i - 1);
}

void func3(int i)
{
	func2(i - 1);
}

void test(int i)
{
	func3(i - 1);
}

int main()
{
	if (SymInitialize(GetCurrentProcess(), NULL, TRUE))
	{
		printf("Init dbghelp ok.\n");
	}

	dump_callstack(GetExceptionInformation()->ContextRecord);

	if (SymCleanup(GetCurrentProcess()))
	{
		printf("Cleanup dbghelp ok.\n");
	}

	return 0;
}