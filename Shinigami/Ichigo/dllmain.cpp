// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ProcessUnhollow.h"
#include "Unpacker.h"
#include "Logger.h"

#define DLL_NAME "Ichigo v0.1"

static HookManager hkManager;

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
            MessageBoxA(NULL, "Unable to initialize log pipes! Exiting for safety...", "Ichigo error", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
        if (!InitUnhollowHooks(hkManager) || !InitUnpackerHooks(hkManager))
        {
            MessageBoxA(NULL, "Unable to place our hooks! Exiting for safety...", "Ichigo erro", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
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

