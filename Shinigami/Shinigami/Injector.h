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
#define DEFAULT_TARGET_NAME  L"rundll32.exe" 

typedef void (*SetIchigoArguments)(const IchigoArguments*);
typedef void (*StartIchigo)();

#pragma pack(push, 1)
struct ThreadData {
	decltype(LoadLibraryW)	  *LoadLibraryW;
	decltype(GetProcAddress)  *GetProcAddress;
	decltype(ExitProcess)	  *ExitProcess;
	decltype(GetLastError)	  *GetLastError;

	wchar_t DllName[MAX_PATH];

	char SetArgumentsFuncName[MAX_PATH];
	char StartIchigoFuncName[MAX_PATH];
	IchigoArguments Arguments;
};
#pragma pack(pop)


class Injector
{
public:
	Injector(_In_ const std::wstring& ProcName);
	BOOL InjectSuspended(_In_ const std::wstring& DLLPath, _In_ const IchigoArguments& DLLArguments, _In_ BOOL IsDLL, _In_ const std::wstring& ExportedFunction);
	BOOL APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName, _In_ const IchigoArguments& DLLArguments) const;
private:
	std::wstring BuildRunDLLCommand(const std::wstring& DLLPath, const std::wstring& ExportedFunction);
private:
	std::wstring ProcName;
	BOOL IsDLL;
};

