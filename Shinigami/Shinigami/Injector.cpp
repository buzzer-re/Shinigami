#include "Injector.h"


VOID __stdcall LoadDLL(ULONG_PTR Params)
{
    ThreadData* ThData = reinterpret_cast<ThreadData*>(Params);
    ThData->LoadLibraryW(ThData->DllName);
}

// Create a suspended process
// Inject the DLL using APC callbacks
BOOL Injector::InjectSuspended(_In_ const std::wstring& DLLPath)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&si, sizeof(pi));
    si.cb = sizeof(si);

    // Create process suspended
    bool status = CreateProcess(
        nullptr,
        (LPWSTR)ProcName.c_str(),
        NULL,
        NULL,
        NULL,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!status) return false;

    // Inject DLL using APC
    status = APCLoadDLL(pi, DLLPath);

    if (!status)
    {
        TerminateProcess(pi.hProcess, EXIT_FAILURE);
        goto quit;
    }

    Logger::LogInfo(L"Injection finished, waiting connection...");
    PipeLogger::InitPipe();

    
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hThread, INFINITE);

quit:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    PipeLogger::ClosePipe();

    return status;
}

// Inject a APC callback to be called before the suspended process entrypoint that will load the target DLL by calling LoadLibrary
BOOL Injector::APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName) const
{
    // Setup thread data
    ThreadData th;
    SIZE_T BytesWritten;
    th.LoadLibraryW = LoadLibraryW;

    wmemcpy_s(th.DllName, MAX_PATH, DLLName.c_str(), DLLName.size() + 1);
    
    LPVOID pThreadData = VirtualAllocEx(pi.hProcess, NULL, sizeof(th), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pThreadData == nullptr) return false;

    if (!WriteProcessMemory(pi.hProcess, pThreadData, &th, sizeof(th), &BytesWritten))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        return false;
    }

    LPVOID pLoadDLLCode = VirtualAllocEx(pi.hProcess, NULL, INJECTED_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pLoadDLLCode)
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, pLoadDLLCode, LoadDLL, INJECTED_SIZE, &BytesWritten))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pLoadDLLCode, 0, MEM_RELEASE);
        return false;
    }

    if (!QueueUserAPC((PAPCFUNC)pLoadDLLCode, pi.hThread, (ULONG_PTR)pThreadData))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pLoadDLLCode, 0, MEM_RELEASE);
        return false;
    }

    return true;
}
