#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>

#include "Injector.h"

#pragma comment(lib, "Shlwapi.lib")

#define DLL_NAME L".\\Ichigo.dll"


int PrintError()
{
    DWORD ErrorCode         = GetLastError();
    LPWSTR ErrorMsgBuffer   = nullptr;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&ErrorMsgBuffer, 0, NULL);

    if (ErrorMsgBuffer) {
        std::wcerr << "Error: " << ErrorMsgBuffer << std::endl;
        LocalFree(ErrorMsgBuffer);
    }
    else {
        std::cerr << "Unknown error " << ErrorCode << std::endl;
    }

    return EXIT_FAILURE;
}


int _tmain(int argc, TCHAR** argv)
{
    std::wstring Target;
    if (argc < 2)
    {
        std::wprintf(L"Usage: %s \"<executable> <executable_args>\"\n", PathFindFileNameW(argv[0]));
        return EXIT_FAILURE;
    }

    Target = argv[1];

    if (argc > 2)
    {
        // Well, it could only has used "prog.exe args" between quotes, right ?
        for (int i = 2; i < argc; ++i)
        {
            Target += L" " + std::wstring(argv[i]);
        }
    } 

    Injector injector(Target);
    
    if (!injector.InjectSuspended(DLL_NAME))
        return PrintError();
    
    return EXIT_SUCCESS;
}
