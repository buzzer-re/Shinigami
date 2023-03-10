#pragma once

#include <Windows.h>
#include <cstring>
#include <string>
#include <iostream>

#include "PipeLogger.h"

#define INJECTED_SIZE 0x100

struct ThreadData {
	decltype(LoadLibraryW) *LoadLibraryW;
	wchar_t DllName[MAX_PATH];
};


class Injector
{
public:
	Injector(_In_ const std::wstring& ProcName) : ProcName(ProcName) {}
	BOOL InjectSuspended(_In_ const std::wstring& DLLPath);
	BOOL APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName) const;

private:
	std::wstring ProcName;
};

