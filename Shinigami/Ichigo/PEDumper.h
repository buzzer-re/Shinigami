#pragma once
#include <Windows.h>
#include "Mem.h"
#include "Utils.h"

namespace PEDumper 
{
	Memory* FindRemotePE(HANDLE hProcess, const Memory* mem);
	Memory* DumpPE(ULONG_PTR* Address);
	PIMAGE_DOS_HEADER FindPE(Memory* Mem);

	SIZE_T GetPESize(PIMAGE_NT_HEADERS pNTHeader);
	VOID FixPESections(Memory* pNTHeader);
};

