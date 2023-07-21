#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <vector>
#include <string>

#include "Injector.h"
#include "argparse.h"
#include "ShinigamiArguments.h"
#include "EncodingUtils.h"
#include "SimplePE.h"

#pragma comment(lib, "Shlwapi.lib")

#define DLL_NAME L".\\Ichigo.dll"
#define PROG_NAME "Shinigami"


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


int main(int argc, char** argv)
{
    ShinigamiArguments Arguments;

    try
    {
        Arguments.ParseArguments(argc, argv, PROG_NAME);
    }
    catch (const std::runtime_error& error)
    {
        std::cerr << "Exception\n" << std::endl;
        std::cerr << error.what() << std::endl;
        return EXIT_FAILURE;
    }

    const std::wstring& Target = Arguments.GetTarget();
    SimplePE PE(Target);

    if (!PE.IsValid())
    {
        std::cerr << "Is not a PE file\n";
        return EXIT_FAILURE;
    }

    Injector injector(Arguments.TargetExecutableName);
    
    if (!injector.InjectSuspended(DLL_NAME, Arguments.GetIchigoArguments(), PE.IsDLL(), Arguments.ExportedFunction))
        return PrintError();
    
    return EXIT_SUCCESS;
}
