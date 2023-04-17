#pragma once
#include <Windows.h>


// Global options
namespace Ichigo
{
    struct Arguments
    {
        wchar_t WorkDirectory[MAX_PATH];
    };

    static HookManager hkManager;
    static Arguments* Options;
}

