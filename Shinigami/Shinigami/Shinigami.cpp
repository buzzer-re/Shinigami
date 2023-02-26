#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>

#include "Injector.h"

#pragma comment(lib, "Shlwapi.lib")

#define DLL_NAME L".\\Ichigo.dll"


int PrintError()
{
    DWORD error_code = GetLastError();
    LPWSTR error_msg_buffer = nullptr;

    DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&error_msg_buffer, 0, NULL);

    if (error_msg_buffer) {
        std::wcerr << "Error: " << error_msg_buffer << std::endl;
        LocalFree(error_msg_buffer);
    }
    else {
        std::cerr << "Unknown error " << error_code << std::endl;
    }

    return EXIT_FAILURE;
}


int _tmain(int argc, TCHAR** argv)
{
    std::wstring target;
    if (argc < 2)
    {
        std::wprintf(L"Usage: %s \"<executable> <executable_args>\"\n", PathFindFileNameW(argv[0]));
        return EXIT_FAILURE;
    }

    target = argv[1];

    if (argc > 2)
    {
        // Well, it could only has used "prog.exe args" between quotes, right ?
        for (int i = 2; i < argc; ++i)
        {
            target += L" " + std::wstring(argv[i]);
        }
    } 

    Injector injector(target);
    
    if (!injector.InjectSuspended(DLL_NAME))
        return PrintError();
    
    return EXIT_SUCCESS;
}
