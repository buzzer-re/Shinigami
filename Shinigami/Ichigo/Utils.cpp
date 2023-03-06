#include "pch.h"
#include "Utils.h"
#include "Logger.h"

BOOL Utils::SaveToFile(const wchar_t* filename, Memory* data)
{
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesWritten;
    bool success = WriteFile(hFile, data->Addr, data->Size, &bytesWritten, NULL) && (bytesWritten == data->Size);

    CloseHandle(hFile);

    return success;
}



std::wstring Utils::BuildFilenameFromProcessName(const wchar_t* suffix)
{
    //
    // Get the name of the process executing 
    //
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(nullptr, exePath, MAX_PATH);
    //
    // Get filename
    //
    wchar_t* exeName = PathFindFileNameW(exePath);
    
    // 
    // Get the . pos
    //
    wchar_t* dot = wcsrchr(exeName, L'.');

    //
    // Quick hack
    //
    if (dot != nullptr && _wcsicmp(dot, L".exe") == 0) {
        *dot = L'\0'; // Replace the dot with a null terminator
    }


    return std::wstring(exeName) + suffix;
}

MEM_ERROR Utils::IsReadWritable(ULONG_PTR* Address)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (!VirtualQuery(Address, &mbi, sizeof(mbi)))
    {
        return INVALID_MEMORY_AREA;
    }

    return (MEM_ERROR) (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_READWRITE);
}

