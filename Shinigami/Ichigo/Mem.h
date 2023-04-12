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

    bool operator==(const Memory& other) const
    {
        return Addr == other.Addr && End == other.End && Size == other.Size
            && prot == other.prot && safe == other.safe && ProcessID == other.ProcessID
            && cAlloc == other.cAlloc;
    }

    uint8_t* Addr;
    ULONG_PTR End;
    SIZE_T Size;
    DWORD prot;
    bool safe;
    DWORD ProcessID;
    bool cAlloc;
};
