#pragma once

#include <list>
#include <vector>
#include <sstream>
#include <algorithm>
#include <windows.h>

#include "Ichigo.h"
#include "HookManager.h"
#include "Logger.h"
#include "Mem.h"
#include "Utils.h"
#include "defs.h"
#include "PEDumper.h"

#define TF 0x100
#define PAGE_SIZE 0x1000

namespace GenericUnpacker
{
    static NTSTATUS WINAPI hkNtAllocateVirtualMemory(
        HANDLE      ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR   ZeroBits,
        PSIZE_T     RegionSize,
        ULONG       AllocationType,
        ULONG       Protect
    );

    static NTSTATUS WINAPI hkNtWriteVirtualMemory (
        HANDLE    ProcessHandle,
        PVOID     BaseAddress,
        PVOID     Buffer,
        ULONG     NumberOfBytesToWrite,
        PULONG    NumberOfBytesWritten
    );

    static NTSTATUS WINAPI hkNtProtectVirtualMemory (
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );  

    static class Unpacker
    {
    public:
        Memory* IsBeingMonitored(ULONG_PTR Address);
        BOOL Dump(Memory* StartAddress);
        VOID RemoveMonitor(Memory* Mem);
        VOID CleanMonitor();

    public:
        WinAPIPointers Win32Pointers;
        std::list<Memory> Watcher;
        std::vector<std::wstring> StagesPath;
    } cUnpacker;


    LONG WINAPI VEHandler(EXCEPTION_POINTERS* pExceptionPointers);

    BOOL InitUnpackerHooks(HookManager& hkManager, Ichigo::Arguments& Arguments);
    // Perform an scan in all unvisited memory regions
    VOID FinalScan();

    VOID RemoveGuard(ULONG_PTR Address);
    VOID Shutdown();

    static BOOL Ready;
    // Used for toggle on/off when the unpacker inject in itself 
    static std::unordered_map<ULONG_PTR, BOOL> IgnoreMap;

    static Ichigo::Arguments* IchigoOptions;
}



