#include <iostream>
#include <windows.h>
#include <tchar.h>

#define DLL_MAX_NAME 32

typedef HMODULE (WINAPI* mLoadLibraryW) (
    _In_ LPCWSTR lpLibFileName
);


struct ThreadData {
    mLoadLibraryW loadLibrary;
    wchar_t DllName[DLL_MAX_NAME];
};


VOID __stdcall loadIchigo(ULONG_PTR Parameter)
{
    ThreadData* thData = reinterpret_cast<ThreadData*>(Parameter);
    thData->loadLibrary(thData->DllName);
}

BOOL InjectDLL(PROCESS_INFORMATION& pi)
{

    ThreadData thData;
    lstrcpyW(thData.DllName, L"ichigo.dll");

    thData.loadLibrary = reinterpret_cast<mLoadLibraryW>(LoadLibraryW);

    // Alloc shellcode
    SIZE_T bytesWritten;
    LPVOID pLoadIchigo = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pLoadIchigo == nullptr) return FALSE;

    if (!WriteProcessMemory(pi.hProcess, pLoadIchigo, loadIchigo, 0x1000, &bytesWritten))
    {
        VirtualFreeEx(pi.hProcess, pLoadIchigo, NULL, MEM_RELEASE);
        return FALSE;
    }

    LPVOID pDllName = VirtualAllocEx(pi.hProcess, NULL, sizeof(thData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pDllName, (LPVOID) &thData, sizeof(thData), &bytesWritten);

    QueueUserAPC((PAPCFUNC)pLoadIchigo, pi.hThread, (ULONG_PTR) pDllName);
    return TRUE;
}

int _tmain(int argc, TCHAR** argv)
{
    wchar_t target[] = L"notepad.exe";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
   
    BOOL success = CreateProcessW(
        NULL,
        (LPWSTR) target,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success)
    {
        std::printf("Error creating process: %d\n", GetLastError());
        return EXIT_FAILURE;
    }


    if (InjectDLL(pi))
    {
        std::printf("Injected!");
    }

    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
