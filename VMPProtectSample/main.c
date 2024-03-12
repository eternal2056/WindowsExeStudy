//#include <iostream>
#include <windows.h>

int main()
{
	//std::cout << "Hello World!\n";
	MessageBoxA(NULL, "这是一个MessageBoxA的例子！", "MessageBoxA示例", MB_OK | MB_ICONINFORMATION);
	return 1;
}
