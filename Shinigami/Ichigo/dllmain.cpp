// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "ProcessUnhollow.h"

#define DLL_NAME "Ichigo v0.1"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Create some kind of switch here to another type of unpackers, cli args idk
        InitHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        std::printf("Bye bye\n");
        Shutdown();
        break;
    }
    return TRUE;
}

