#include "pch.h"

void __declspec(naked) hook(void) {
	MessageBox(
		NULL,
		L"In hook function",
		L"hook code is happening",
		MB_OK);
}

void main() {
	HMODULE hApiDll;
	if (hApiDll = GetModuleHandle(L"kernel32.dll") == 0) {
		printf("Error: GetModuleHandle, Code: &d\n", GetLastError());
		return;
	}

	HANDLE pVictim;
	if (pVictim = GetProcAddress(hApiDll, L"GetModuleHandle") == NULL) {
		printf("Error: GetProcAddress, Code: &d\n", GetLastError());
		return;
	}

	PDWORD oldMemoryProtection;
	if (VirtualProtect(pVictim, 5, PAGE_EXECUTE_READWRITE, &oldMemoryProtection) == 0) {
		printf("Error: VirtualProtect, Code: &d\n", GetLastError());
		return;
	}

	// rewriting the win32 function's prologue
	*(BYTE*)pVictim = 0xE9;
	char* fp = &hook;
	*(DWORD*)((BYTE*)pVictim + 1) = (char*)&hook - (char*)pVictim - 5;

	HANDLE retVal = GetModuleHandle(L"kernel32");
	printf("reVal = &p\n", retVal);
}