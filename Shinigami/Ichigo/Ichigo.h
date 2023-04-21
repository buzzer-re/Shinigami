#pragma once
#include <Windows.h>
#include "HookManager.h"

// Global options
namespace Ichigo
{
    enum State
    {
        IDLE = 0,
        RUNNING,
        FINISHED
    };

    #pragma pack(push, 1)
    struct Arguments
    {
        wchar_t WorkDirectory[MAX_PATH];
        BOOL Quiet;
        BOOL OnlyPE;
        DWORD PID;
        struct
        {
            BOOL StopAtWrite;
        } Unhollow;
    };
    #pragma pack(pop)
    
    static HookManager hkManager;
    static Arguments Options;
}

