#pragma once
#include "Mem.h"
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

enum MEM_ERROR
{
	ERROR_NO_ERROR = TRUE,
	INVALID_MEMORY_AREA
};

namespace Utils
{
	BOOL SaveToFile(const wchar_t* filename, Memory* data, BOOL Paginate);
	SIZE_T GetPESize(PIMAGE_NT_HEADERS pDOSHeader);
	std::wstring PathJoin(const std::wstring& BasePath, const std::wstring& FileName);
	
	std::wstring BuildFilenameFromProcessName(const wchar_t* suffix);

	MEM_ERROR IsReadWritable(ULONG_PTR* Address);
}