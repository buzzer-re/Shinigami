#pragma once
#include <Windows.h>
#include "Mem.h"
#include "Utils.h"

namespace PEDumper 
{
	Memory* FindRemotePE(HANDLE hProcess, const Memory* mem);
	Memory* DumpPE(ULONG_PTR* Address);
	PIMAGE_DOS_HEADER FindPE(Memory* Mem);
	PIMAGE_DOS_HEADER HeuristicSearch(Memory* Mem);
	PIMAGE_DOS_HEADER RebuildDOSHeader(Memory* Mem, ULONG_PTR NtHeaderOffset);
	BOOL IsValidNT(PIMAGE_NT_HEADERS pNtHeader);
	SIZE_T GetPESize(PIMAGE_NT_HEADERS pNTHeader);
	VOID FixPESections(Memory* pNTHeader);
};

