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
#include "Logger.h"

static HookManager manager;

// Real hooked function address
static pVirtualAllocEx       oVirtualAllocEx;
static pCreateFileW          oCreateFileW;
static pCreateProcessternalW oCreateProcessternalW;
static pResumeThread         oResumeThread;
static pWriteProcessMemory   oWriteProcessMemory;

// Stolen structures
static PROCESS_INFORMATION cPI;

// Modules handles
static HMODULE hKernelBase;
static HMODULE hKernel32;

// flags
static BOOL DumpAtResume = FALSE;



// Used to monitor all allocations
static std::vector<Memory*> watcher;


LPVOID WINAPI hkVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

BOOL WINAPI hkCreateProcessInternalW(
    HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupinfo,
    LPPROCESS_INFORMATION lpProcessformation,
    PHANDLE hNewToken
);

BOOL WINAPI hkWriteProcessMemory (
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);


DWORD WINAPI hkResumeThread(
    HANDLE hThread
);

// Hunt for implants using the watcher list
Memory* HuntPE();

// Place our hooks
VOID InitHooks();
// Clean
VOID Shutdown();