#include <iostream>
#include <Windows.h>

#define JUMP 0xE9

typedef BOOL (WINAPI* pVirtualProtect) (
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

pVirtualProtect oVirtualAlloc;

BOOL WINAPI hkVirtualProtect (
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
)
{
    std::cout << "Hooked\n";
    return oVirtualAlloc(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}


bool Detour32(BYTE* src, BYTE* dst, const ULONG_PTR len)
{
    // min jmp size
    if (len < 5) return false;

    BYTE* gateway = (BYTE*)VirtualAlloc(NULL, len * 2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (gateway == nullptr) return false;


    memcpy_s(gateway, len, src, len);
    ULONG_PTR relativeADDR = src - gateway - 5;

    gateway[(uint8_t) len] = JUMP;
    gateway[len + 1] = relativeADDR;

    *(ULONG_PTR*) ((ULONG_PTR)gateway + len + 1) = relativeADDR;

    oVirtualAlloc = (pVirtualProtect)gateway;

    DWORD curProtection;
    VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);

    ULONG_PTR relativeAddress = dst - src - 5;
    *src = JUMP;
    *(ULONG_PTR*)(src + 1) = relativeAddress;

    VirtualProtect(src, len, curProtection, &curProtection);

    return true;
}


int main()
{
    DWORD dwOld;

    oVirtualAlloc = (pVirtualProtect) GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "VirtualProtect");

    Detour32((BYTE*)VirtualProtect, (BYTE*)hkVirtualProtect, 5);

    VirtualProtect(NULL, NULL, NULL, NULL);
}

