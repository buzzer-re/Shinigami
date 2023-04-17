#pragma once

#include <Windows.h>
#include <cstring>
#include <string>
#include <iostream>

#include "PipeLogger.h"
#include "ShinigamiArguments.h"

#define INJECTED_SIZE 0x100
#define SET_ICHIGO_ARGS_FUNC_NAME "SetIchigoArguments"
#define START_ICHIGO_FUNC_NAME "StartIchigo"

typedef void (*SetIchigoArguments)(const IchigoArguments*);
typedef void (*StartIchigo)();

struct ThreadData {
	decltype(LoadLibraryW)	  *LoadLibraryW;
	decltype(GetProcAddress)  *GetProcAddress;
	decltype(ExitProcess)	  *ExitProcess;

	wchar_t DllName[MAX_PATH];


	char SetArgumentsFuncName[MAX_PATH];
	char StartIchigoFuncName[MAX_PATH];
	IchigoArguments Arguments;
};


class Injector
{
public:
	Injector(_In_ const std::wstring& ProcName) : ProcName(ProcName) {}
	BOOL InjectSuspended(_In_ const std::wstring& DLLPath, _In_ const IchigoArguments& DLLArguments);
	BOOL APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName, _In_ const IchigoArguments& DLLArguments) const;

private:
	std::wstring ProcName;
};

