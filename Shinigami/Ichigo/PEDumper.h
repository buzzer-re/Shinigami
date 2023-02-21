#pragma once
#include <Windows.h>
#include "Mem.h"

class PEDumper
{
public:
	Memory* FindRemotePE(HANDLE hProcess, const Memory* mem) const;
};

