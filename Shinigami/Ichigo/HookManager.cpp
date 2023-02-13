#include "pch.h"
#include "HookManager.h"
#include <iostream>

ULONG_PTR* __stdcall HookManager::AddHook(BYTE* Src, BYTE* Dst, BYTE* OriginalAddr)
{
    // TODO: Verify if is a valid executable area
    // 
    // Verify if it's a hook already exists


    DWORD curProtection;
    ULONG_PTR gatewayDelta;
    ULONG_PTR relativeAddrHook;

    auto it = hooks.find(Src);
    if (it != hooks.end()) return nullptr;

    // Allocate the gateway code that will run the override bytes by the trampoline
    BYTE* gateway = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, HOOK_MAX_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (gateway == nullptr) return nullptr;

    memcpy_s(gateway, TRAMPOLINE_SIZE, Src, TRAMPOLINE_SIZE);

    // Calculate the delta to jump back
    gatewayDelta = Src - gateway - TRAMPOLINE_SIZE;
    relativeAddrHook = Dst - Src - TRAMPOLINE_SIZE;

    *(BYTE*) (gateway + TRAMPOLINE_SIZE) = 0xE9;
    *(ULONG_PTR*)((ULONG_PTR)gateway + TRAMPOLINE_SIZE + 1) = gatewayDelta;
    // Write the trampoline

    VirtualProtect(Src, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &curProtection);
    
    *Src = 0xE9;
    *(ULONG_PTR*)(Src + 1) = relativeAddrHook;
    
    VirtualProtect(Src, TRAMPOLINE_SIZE, curProtection, &curProtection);


    return (ULONG_PTR*) gateway;
}
