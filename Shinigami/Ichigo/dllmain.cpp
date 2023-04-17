// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Ichigo.h"
#include "ProcessUnhollow.h"
#include "Unpacker.h"
#include "Logger.h"

#define DLL_NAME "Ichigo v0.1"
#define MESSAGEBOX_ERROR_TITLE "Ichigo error"
#define ERR_ICON MB_OK | MB_ICONERROR
#define DLL_EXPORT __declspec(dllexport)


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!PipeLogger::InitPipe())
        {
            MessageBoxA(NULL, "Unable to initialize log pipes! Exiting for safety...", MESSAGEBOX_ERROR_TITLE, ERR_ICON);
            ExitProcess(1);
        }

        PipeLogger::LogInfo(L"Starting " DLL_NAME "..");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        PipeLogger::LogInfo(L"Exiting...");
        PipeLogger::ClosePipe();
        Shutdown();
        break;
    }
    return TRUE;
}


extern "C"
{
    DLL_EXPORT void SetIchigoArguments(Ichigo::Arguments* args)
    {
        Ichigo::Options = args;
        PipeLogger::LogInfo(L"Setting arguments\nOutput path => %s ...\n", Ichigo::Options->WorkDirectory);
    }

    DLL_EXPORT void InitIchigo()
    {
        if (!InitUnhollowHooks(Ichigo::hkManager) || !InitUnpackerHooks(Ichigo::hkManager))
        {
            MessageBoxA(NULL, "Unable to place the needed hooks! Exiting for safety...", MESSAGEBOX_ERROR_TITLE, ERR_ICON);
            ExitProcess(1);
        }
    }
}
