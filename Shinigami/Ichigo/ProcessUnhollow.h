#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>

// Our libs
#include "PEDumper.h"
#include "Mem.h"
#include "HookManager.h"
#include "defs.h"
#include "Utils.h"
#include "Logger.h"

//
// Unhollow namespace containing the Information struct which holds the hooks and system pointers
//
namespace Unhollow
{
    static struct Information
    {
        HookManager hkManager;
        HMODULE NTDLL;
        BOOL DumptAtResume;
        PROCESS_INFORMATION pi;
        std::vector<Memory*> Watcher;

        struct {
            NtAllocateVirtualMemory*    NtAllocateVirtualMemory;
            NtWriteVirtualMemory*       NtWriteVirtualMemory;
            NtCreateUserProcess*        NtCreateUserProcess;
            NtResumeThread*             NtResumeThread;
        } Win32Pointers;

    } ProcessInformation;

    static NTSTATUS WINAPI hkNtAllocateVirtualMemory(
        HANDLE      ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR   ZeroBits,
        PSIZE_T     RegionSize,
        ULONG       AllocationType,
        ULONG       Protect
    );

    static NTSTATUS WINAPI hkNtWriteVirtualMemory(
        HANDLE    ProcessHandle,
        PVOID     BaseAddress,
        PVOID     Buffer,
        ULONG     NumberOfBytesToWrite,
        PULONG    NumberOfBytesWritten
    );

    static NTSTATUS WINAPI hkNtCreateUserProcess
    (
            PHANDLE ProcessHandle,
            PHANDLE ThreadHandle,
            ACCESS_MASK ProcessDesiredAccess,
            ACCESS_MASK ThreadDesiredAccess,
            POBJECT_ATTRIBUTES ProcessObjectAttributes,
            POBJECT_ATTRIBUTES ThreadObjectAttributes,
            ULONG ProcessFlags,
            ULONG ThreadFlags,
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
            PPS_CREATE_INFO CreateInfo,
            PPS_ATTRIBUTE_LIST AttributeList
     );

    static NTSTATUS WINAPI hkNtResumeThread(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );

    Memory* HuntPE();
}

// Place our hooks
BOOL InitHooks();
// Clean
VOID Shutdown();