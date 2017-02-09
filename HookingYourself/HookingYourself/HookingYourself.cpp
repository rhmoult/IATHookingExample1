// HookingYourself.cpp : The simplest example of Import Address Table Hooking I could think of.
// Programmed in Visual Studio 2015 Community Edition for Windows x64 (www.visualstudio.com)

#include "stdafx.h"
//#include "afxwin.h"
#include <stdio.h>

// The following function was copied almost verbatim from Jeffrey Richter's
// Windows via C/C++.  Normally, you have to inject a DLL into the victim
// process in order to have the function become available.
// In this case, we are simply hooking our own process space.  Thus,
// we do not need DLL injection.

/*
	\param pszCalleeModName the name of the DLL whose function you want to hook
	\param pfnCurrent the address of the function to be hooked inside the DLL
	\param pfnNew the address of the function intended to replace the hooked function
	\param hmodCaller the name of the program whose IAT table is to be hooked
	\return Side-effects only
*/
void ReplaceIATEntryInOneMod(PCSTR pszCalleeModName,
	PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller) {
	// Get the address of the module's import section
	ULONG ulSize;

	// Maybe not be thread safe: the list of modules from Toolhelp might
	// not be accurate if FreeLibrary is called during the enumeration.
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	// DANGER AHEAD: In production quality code, this ImageDirectoryEntryToData call
	// should be inside a try/except block
	
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
		hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
	
	if (pImportDesc == NULL)
		return;  // This module has no import section or is no longer loaded

	// Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) {
		PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);
		if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {

			// Get caller's import address table (IAT) for the callee's functions
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PBYTE)hmodCaller + pImportDesc->FirstThunk);
			// Replace current function address with new function address
			for (; pThunk->u1.Function; pThunk++) {

				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;

				// Is this the function we're looking for?
				BOOL bFound = (*ppfn == pfnCurrent);
				if (bFound) {
					if (!WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
						sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError())) {
						DWORD dwOldProtect;
						if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_WRITECOPY,
							&dwOldProtect)) {

							WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
								sizeof(pfnNew), NULL);
							VirtualProtect(ppfn, sizeof(pfnNew), dwOldProtect,
								&dwOldProtect);
						}
					}
					return;  // We did it, get out
				}
			}
		}  // Each import section is parsed until the right entry is found and patched
	}
}

void MyExitProcess(int retValue) {

	printf("Having hooked the ExitProcess function in our process space,\nwe can now call the real address or rehook and fix the IAT!\n");

	/* First, we have the option of just calling the real ExitProcess address directly*/
	//typedef int (WINAPI *PFNEXITPROCESS)(UINT uExitCode);	
	//PFNEXITPROCESS pfnExitProcess = (PFNEXITPROCESS)GetProcAddress(GetModuleHandle(L"Kernel32"), "ExitProcess");
	//pfnExitProcess(0);

	// Second, we have the option of changing the IAT address to point back to ExitProcess
	// Choose one or the other
	PROC pfnOrig = GetProcAddress(GetModuleHandle(L"Kernel32"), "ExitProcess");
	HMODULE hmodCaller = GetModuleHandle(L"HookingYourself.exe");

	ReplaceIATEntryInOneMod(
		"Kernel32.dll",			// Module containing the function (ANSI)
		(PROC)MyExitProcess,    // Address of function in callee
		pfnOrig,				// Address of new function to be called
		hmodCaller);			// Handle of module that should call the new function

	ExitProcess(0);
}

int main()
{
	PROC pfnOrig = GetProcAddress(GetModuleHandle(L"Kernel32"), "ExitProcess");
	HMODULE hmodCaller = GetModuleHandle(L"HookingYourself.exe");

	ReplaceIATEntryInOneMod(
		"Kernel32.dll",			// Module containing the function (ANSI)
		pfnOrig,				// Address of function in callee
		(PROC)MyExitProcess,	// Address of new function to be called
		hmodCaller);			// Handle of module that should call the new function

	printf("This is HookingYourself.exe, a simple command-line based program.\n");
    ExitProcess(0);
}

