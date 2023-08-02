// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Ichigo.h"
#include "ProcessUnhollow.h"
#include "Unpacker.h"
#include "Logger.h"

#define DLL_NAME "Ichigo v1.2"
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

        GenericUnpacker::FinalScan();

        GenericUnpacker::Shutdown();
        Unhollow::Shutdown();
        PipeLogger::LogInfo(L"Exiting...");
        PipeLogger::ClosePipe();

        break;
    }
    return TRUE;
}

extern "C"
{
    DLL_EXPORT void SetIchigoArguments(Ichigo::Arguments* args)
    {
        // Maybe we should copy it ? think about if this DLL somehow is injected in a different manner
        wmemcpy_s(Ichigo::Options.WorkDirectory, MAX_PATH, args->WorkDirectory, MAX_PATH);
        Ichigo::Options.Unhollow.StopAtWrite = args->Unhollow.StopAtWrite;
        Ichigo::Options.Quiet                = args->Quiet;
        Ichigo::Options.OnlyPE               = args->OnlyPE;
        Ichigo::Options.PID                  = args->PID;
        
        PipeLogger::BeQuiet(args->Quiet);
        PipeLogger::LogInfo(L"Loaded user aguments");
    }

    DLL_EXPORT void StartIchigo()
    {

        if (!Unhollow::InitUnhollowHooks(Ichigo::hkManager, Ichigo::Options)  || !GenericUnpacker::InitUnpackerHooks(Ichigo::hkManager, Ichigo::Options))
        {
            MessageBoxA(NULL, "Unable to place the needed hooks! Exiting for safety...", MESSAGEBOX_ERROR_TITLE, ERR_ICON);
            ExitProcess(1);
        }

        PipeLogger::Log(L"Ichigo is ready!");
    }
}
