#include "Injector.h"

//
// Load the ichigo.dll library, set it's options and start the hooks
//
VOID __stdcall LoadDLL(ULONG_PTR Params)
{
    ThreadData* ThData = reinterpret_cast<ThreadData*>(Params);
    HMODULE hModule = ThData->LoadLibraryW(ThData->DllName);
    
    if (!hModule)
    {
        ThData->ExitProcess(ThData->GetLastError());
    }
    SetIchigoArguments SetArgsFunc = reinterpret_cast<SetIchigoArguments>(ThData->GetProcAddress(hModule, ThData->SetArgumentsFuncName));
    StartIchigo StartIchigoFunc = reinterpret_cast<StartIchigo>(ThData->GetProcAddress(hModule, ThData->StartIchigoFuncName));
    if (!SetArgsFunc || !StartIchigoFunc)
    {
        ThData->ExitProcess(1);
    }

    SetArgsFunc(&ThData->Arguments);
    StartIchigoFunc();
}

// Create a suspended process
// Inject the DLL using APC callbacks
BOOL Injector::InjectSuspended(_In_ const std::wstring& DLLPath, _In_ const IchigoArguments& DLLArguments)
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
    status = APCLoadDLL(pi, DLLPath, DLLArguments);

    if (!status)
    {
        TerminateProcess(pi.hProcess, EXIT_FAILURE);
        goto quit;
    }

    Logger::LogInfo(L"Injection finished, waiting connection...");
    if (!PipeLogger::InitPipe())
    {
        Logger::LogInfo(L"Unable to initialize log pipes! Error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        goto quit;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hThread, INFINITE);
    DWORD ExitCode;
    GetExitCodeProcess(pi.hProcess, &ExitCode);
    Logger::LogInfo(L"Child process exited with code %d, closing...", ExitCode);

quit:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    PipeLogger::ClosePipe();

    return status;
}

// Inject a APC callback to be called before the suspended process entrypoint that will load the target DLL by calling LoadLibrary
BOOL Injector::APCLoadDLL(_In_ const PROCESS_INFORMATION& pi, _In_ const std::wstring& DLLName, _In_ const IchigoArguments& DLLArguments) const
{
    // Setup thread data
    ThreadData th;
    SIZE_T BytesWritten;

    ZeroMemory(&th, sizeof(th));
    // Maybe it's better to handle this function differently in the future
    th.LoadLibraryW     = LoadLibraryW;
    th.GetProcAddress   = GetProcAddress;
    th.ExitProcess      = ExitProcess;
    th.GetLastError     = GetLastError;

    //
    // Exported DLL functions to be called inside the injected code
    //
    memcpy_s(th.SetArgumentsFuncName, MAX_PATH, SET_ICHIGO_ARGS_FUNC_NAME, sizeof(SET_ICHIGO_ARGS_FUNC_NAME));
    memcpy_s(th.StartIchigoFuncName, MAX_PATH, START_ICHIGO_FUNC_NAME, sizeof(START_ICHIGO_FUNC_NAME));

    RtlCopyMemory(&th.Arguments, &DLLArguments, sizeof(th.Arguments));
    wmemcpy_s(th.DllName, MAX_PATH, DLLName.c_str(), DLLName.size());
    th.Arguments.PID = pi.dwProcessId;

    
    LPVOID pThreadData = VirtualAllocEx(pi.hProcess, NULL, sizeof(th), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pThreadData == nullptr) return FALSE;

    if (!WriteProcessMemory(pi.hProcess, pThreadData, &th, sizeof(th), &BytesWritten))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        return FALSE;
    }

    LPVOID pLoadDLLCode = VirtualAllocEx(pi.hProcess, NULL, INJECTED_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pLoadDLLCode)
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!WriteProcessMemory(pi.hProcess, pLoadDLLCode, LoadDLL, INJECTED_SIZE, &BytesWritten))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pLoadDLLCode, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!QueueUserAPC((PAPCFUNC)pLoadDLLCode, pi.hThread, (ULONG_PTR)pThreadData))
    {
        VirtualFreeEx(pi.hProcess, pThreadData, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, pLoadDLLCode, 0, MEM_RELEASE);
        return FALSE;
    }

    return TRUE;
}
