#pragma once
#include <Windows.h>

// Unpack structures
struct Memory
{
    uint8_t* Addr;
    DWORD Size;
    DWORD prot;
};
