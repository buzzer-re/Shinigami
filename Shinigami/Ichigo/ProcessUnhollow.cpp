#include "pch.h"
#include "ProcessUnhollow.h"

//
// Monitore every remote allocation on the suspended process
// 
LPVOID WINAPI hkVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID alloc = oVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    
    if (alloc == NULL)
    {
        std::printf("Error => %d\n", GetLastError());
        return alloc;
    }

    auto it = std::find(watcher.begin(), watcher.end(), alloc);
    if (it == watcher.end())
    {
        // Create entry
        Memory* mem = new Memory;
        mem->Addr = reinterpret_cast<uint8_t*>(alloc);
        mem->Size = dwSize;

        watcher.push_back(mem);
    }

    return alloc;
}

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
)
{

    // Verify if is suspended
    // change to suspended
    // Inject itself here too

    BOOL status = oCreateProcessternalW(
        hUserToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupinfo,
        lpProcessformation,
        hNewToken
    );

    if (status && dwCreationFlags == CREATE_SUSPENDED) {
        // Copy process information, also notify the Shinigami process that this is happened
        // TODO: Log system to the remote process
        DumpAtResume = TRUE;
        memcpy(&cPI, lpProcessformation, sizeof(cPI));
    }


    return status;
}


//
// Dump the implant before resume thread
//
DWORD WINAPI hkResumeThread(HANDLE hThread)
{
    // TODO: Refactore this
    if (DumpAtResume && cPI.hThread == hThread) {
        Memory* Hollow = HuntPE();
        if (Hollow)
        {
            std::printf("Dumped hollow of %d bytes\n", Hollow->Size);
            std::ofstream outfile("dumped.bin", std::ios::binary);

            if (!outfile)
            {
                std::printf("Error opening dump!"); // notify via IPC;
            }
            else {
                outfile.write(reinterpret_cast<const char*>(Hollow->Addr), Hollow->Size);
                outfile.close();
                std::puts("Saved as dumped.bin!");
            }
        }
        
        // Kill hollowed process
        TerminateProcess(cPI.hProcess, 0);
        // 
        ExitProcess(0);
    }

    return 0;
}

Memory* HuntPE()
{
    Memory* PE = nullptr;
    // Walk the watch list and Hunt for the PE headers
    // TODO: Handle erased PE headers
    if (watcher.size() == 1)
    {
        // Perfect, the implant probably is here
        Memory* mem = watcher.back();
        PEDumper dumper;
        PE = dumper.FindRemotePE(cPI.hProcess, mem);
    } 

    return PE;
}


VOID InitHooks()
{
    // TODO: Hook ntdll functions instead kernelbase
    hKernelBase = LoadLibraryA("kernelbase.dll");
    if (hKernelBase == NULL) return;

    BYTE* pRealVirtualAllocEx = reinterpret_cast<BYTE*>(GetProcAddress(hKernelBase, "VirtualAllocEx"));
    BYTE* pRealCreateProcessW = reinterpret_cast<BYTE*>(GetProcAddress(hKernelBase, "CreateProcessInternalW"));
    BYTE* pRealResumeThread   = reinterpret_cast<BYTE*>(GetProcAddress(hKernelBase, "ResumeThread"));

    oVirtualAllocEx = (pVirtualAllocEx)manager.AddHook(pRealVirtualAllocEx, (BYTE*)hkVirtualAllocEx);
    oCreateProcessternalW = (pCreateProcessternalW)manager.AddHook(pRealCreateProcessW, (BYTE*)hkCreateProcessInternalW);
    oResumeThread = (pResumeThread)manager.AddHook(pRealResumeThread, (BYTE*)hkResumeThread);
}


VOID Shutdown()
{
    for (auto& addr : watcher)
    {
        delete addr;
    }
}

