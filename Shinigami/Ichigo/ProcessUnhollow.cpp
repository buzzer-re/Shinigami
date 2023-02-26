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
        PipeLogger::LogInfo(L"VirtualAlloc -- Error (%d) while calling VirtualAlloc! --", GetLastError());
        return alloc;
    }

    auto it = std::find(watcher.begin(), watcher.end(), alloc);
    if (it == watcher.end())
    {
        PipeLogger::LogInfo(L"VirtualAlloc -- Monitoring allocation at 0x%llx --", alloc);
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


BOOL WINAPI hkWriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
)
{
    if (nSize >= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS))
    {
        PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)lpBuffer;
        PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((BYTE*)lpBuffer + pDOSHdr->e_lfanew);
        if (pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE && pNTHdr->Signature == IMAGE_NT_SIGNATURE)
        {
            PipeLogger::LogInfo(L"WriteProcessMemory -- Detected an attempt to write a PE file in another process!");
            Memory* hollow = PEDumper::DumpPE((ULONG_PTR*) lpBuffer);
            if (hollow)
            {
                PipeLogger::LogInfo(L"Extracted implant of %d bytes before it been written, saving!", 12341234);
                TerminateProcess(cPI.hProcess, 0);
                ExitProcess(1);
                // SaveToFile()
            }


        }
    }

    BOOL success = oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    if (!success)
    {
        PipeLogger::LogInfo(L"WriteProcessMemory -- Error on writing process memory: %d --", GetLastError());
        return success;
    }

    

    return success;
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
            PipeLogger::LogInfo(L"ResumeThread -- Dumped hollow of %d bytes --", Hollow->Size);
            std::ofstream outfile("dumped.bin", std::ios::binary);

            if (!outfile)
            {
                PipeLogger::LogInfo(L"ResumeThread -- Error opening dump! --"); // notify via IPC;
            }
            else {
                outfile.write(reinterpret_cast<const char*>(Hollow->Addr), Hollow->Size);
                outfile.close();
                PipeLogger::LogInfo(L"ResumeThread -- Saved as dumped.bin! --");
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
        PE = PEDumper::FindRemotePE(cPI.hProcess, mem);
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
    BYTE* pRealWriteProcessMemory = reinterpret_cast<BYTE*>(GetProcAddress(hKernelBase, "WriteProcessMemory"));

    oVirtualAllocEx = (pVirtualAllocEx)manager.AddHook(pRealVirtualAllocEx, (BYTE*)hkVirtualAllocEx);
    oCreateProcessternalW = (pCreateProcessternalW)manager.AddHook(pRealCreateProcessW, (BYTE*)hkCreateProcessInternalW);
    oResumeThread = (pResumeThread)manager.AddHook(pRealResumeThread, (BYTE*)hkResumeThread);
    oWriteProcessMemory = (pWriteProcessMemory)manager.AddHook(pRealWriteProcessMemory, (BYTE*)hkWriteProcessMemory);
   // MessageBoxA(NULL, "DF", "DF", MB_OK); Just to "break" the execution and give me time to open x64dbg :p
}


VOID Shutdown()
{
    for (auto& addr : watcher)
    {
        delete addr;
    }
}

