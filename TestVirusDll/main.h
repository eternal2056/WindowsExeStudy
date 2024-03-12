#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <winnt.h>



int  sub_1001229F(BYTE* _this);
int __fastcall sub_10008C7D(int a1, int a2);
int __fastcall sub_100011AF(int a2);
struct _LIST_ENTRY* GetDllBase(int a1, int StrInt);
char* __cdecl GetFunctionAddress(int a1, int a2);
char* __cdecl GetSomeFunction(int FunctionIndex, int a2, int a3);