// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#define BUFFERSIZE 100 // used for i/o, irrelevant for the hook

void hookSetup();
void testHook(HMODULE AddressOfModuleBeforeHook);


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);
		HMODULE hApiDll = GetModuleHandle(L"kernel32.dll");
		if (hApiDll == 0) {
			MessageBoxA(NULL, "Error in DllMain at GetModuleHandle", "Error In DllMain", MB_OK);
			return;
		}
		hookSetup();
		testHook(hApiDll);

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


// global variable, holds return address so the hook function knows to where it should return
void* getModuleHandle_addressToContinue;


// Hook function
void __declspec(naked) hook(void) {

	__asm {
		// setting up the win32 api function's stack frame
		PUSH ebp
		MOV ebp, esp
		// setting up this function's stuck frame
		PUSH ebp
		MOV ebp, esp
		//SUB esp, 8

	}

	//printf("In hook\nEnter a number: ");
	//double num;
	//num = 5;
	MessageBoxA(NULL, "In hook function", "In hook function", MB_OK);

	// epilogue
	__asm {
		//ADD esp, 8
		MOV esp, ebp
		POP ebp
		JMP getModuleHandle_addressToContinue
	}
}


void hookSetup() {
	HMODULE hApiDll = GetModuleHandle(L"kernel32.dll");
	if (hApiDll == 0) {
		MessageBoxA(NULL, "Error at GetModuleHandle", "", MB_OK);
		//printf("Error: GetModuleHandle, Code: %d\n", GetLastError());
		return;
	}

	HANDLE pVictim = GetProcAddress(hApiDll, "GetModuleHandleW");
	if (pVictim == NULL) {
		MessageBoxA(NULL, "Error at GetProcAddress", "", MB_OK);
		//printf("Error: GetProcAddress, Code: %d\n", GetLastError());
		return;
	}
	// global variable, holds return address so the hook function knows to where it should return
	getModuleHandle_addressToContinue = (BYTE*)pVictim + 5;

	PDWORD oldMemoryProtection;
	if (VirtualProtect(pVictim, 5, PAGE_EXECUTE_READWRITE, &oldMemoryProtection) == 0) {
		MessageBoxA(NULL, "Error at VirtualProtect", "", MB_OK);
		//printf("Error: VirtualProtect, Code: %d\n", GetLastError());
		return;
	}

	// rewriting the win32 function's prologue
	*(BYTE*)pVictim = 0xE9; // JMP opcode
	*(DWORD*)((BYTE*)pVictim + 1) = (BYTE*)&hook - (BYTE*)pVictim - 5; // relative address of the hook function
}


void testHook(HMODULE AddressOfModuleBeforeHook) {
	HANDLE retVal = GetModuleHandle(L"kernel32");
	if (AddressOfModuleBeforeHook == retVal) {
		MessageBoxA(NULL, "Hook succeeded", "", MB_OK);
	}
	else {
		MessageBoxA(NULL, "Hook failed", "", MB_OK);
	}
	char message[BUFFERSIZE] = { 0 };
	sprintf_s(message, BUFFERSIZE, "address of module before hook: %p\naddress after hook: %p", AddressOfModuleBeforeHook, retVal);
	MessageBoxA(NULL, message, "", MB_OK);
}