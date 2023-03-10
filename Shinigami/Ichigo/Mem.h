#pragma once
#include <Windows.h>

// Unpack structures
struct Memory
{
    ~Memory()
    {
        if (safe)
        {
            if (cAlloc)
                delete Addr;
            else
                VirtualFree(Addr, NULL, MEM_RELEASE);
        }
    }
    uint8_t* Addr;
    DWORD Size;
    DWORD prot;
    bool safe;
    DWORD ProcessID;
    bool cAlloc;
};
