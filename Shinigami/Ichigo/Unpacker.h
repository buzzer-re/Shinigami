#pragma once
#include <windows.h>
#include "HookManager.h"
#include "Logger.h"
#include "defs.h"

namespace Unpacker
{
    static NTSTATUS WINAPI hkNtAllocateVirtualMemory(
        HANDLE      ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR   ZeroBits,
        PSIZE_T     RegionSize,
        ULONG       AllocationType,
        ULONG       Protect
    );

    struct
    {
        WinAPIPointers Win32Pointers;
    } Unpacker;
}


BOOL InitUnpackerHooks(HookManager& hkManager);

