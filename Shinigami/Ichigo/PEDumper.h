#pragma once
#include <Windows.h>
#include "Mem.h"

namespace PEDumper 
{
	Memory* FindRemotePE(HANDLE hProcess, const Memory* mem);
	Memory* DumpPE(ULONG_PTR* Address);
};

