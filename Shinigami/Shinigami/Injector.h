#pragma once

#include <Windows.h>
#include <cstring>
#include <string>
#include <iostream>

#include "PipeLogger.h"

#define INJECTED_SIZE 0x100

typedef HMODULE(WINAPI* mLoadLibraryW) (
	_In_ LPCWSTR lpLibFileName
);


struct ThreadData {
	mLoadLibraryW loadLibrary;
	wchar_t DllName[MAX_PATH];
};


class Injector
{
public:
	Injector(_In_ const std::wstring& procName) : procName(procName) {}
	bool InjectSuspended(_In_ const std::wstring& dllPath);
	bool APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName) const;

private:
	std::wstring procName;


};

