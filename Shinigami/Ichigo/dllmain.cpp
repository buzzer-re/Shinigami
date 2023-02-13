// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "HookManager.h"


#define DLL_NAME "Ichigo v0.1"

HookManager manager;

typedef LPVOID (WINAPI* pVirtualAlloc) (
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

pVirtualAlloc oVirtualAlloc;

LPVOID WINAPI hkVirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
)
{
    std::cout << "Called hooked VirtualAlloc\n";

    LPVOID alloc = oVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    std::printf("Allocated memory at 0x%lx\n", (ULONG_PTR) alloc);
    return alloc;
}


VOID InitHooks()
{
    // Hook VirtualAlloc
    // Hook CreateProcess, CreateProcessInternal
    // Hook WriteProcessMemory to create a mirror memory
    // Hook ReadProcess memory either
    // Hook ResumeThread
    // Hook GetThreadContext

    oVirtualAlloc = (pVirtualAlloc)manager.AddHook((BYTE*)VirtualAlloc, (BYTE*)hkVirtualAlloc, (BYTE*)NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

