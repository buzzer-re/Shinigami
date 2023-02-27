#pragma once
#include "Mem.h"
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace Utils
{
	BOOL SaveToFile(const wchar_t* filename, Memory* data);
	SIZE_T GetPESize(PIMAGE_NT_HEADERS pDOSHeader);
	
	std::wstring BuildFilenameFromProcessName(const wchar_t* suffix);
}