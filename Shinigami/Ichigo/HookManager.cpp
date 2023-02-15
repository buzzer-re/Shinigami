#include "pch.h"
#include "HookManager.h"
#include <iostream>

LPVOID
HookManager::AddHook(
    _In_ BYTE* Src,
    _In_ BYTE* Dst
)
{
    auto it = hooks.find(Src);
    if (it != hooks.end()) return nullptr;
    LPVOID pGatewayAddr;

#ifndef _WIN32
    pGatewayAddr = Hook32(Src, Dst);
#else
    pGatewayAddr = Hook64(Src, Dst);
#endif

    // 
    // Insert new hook on the manager map
    //
    Hook hk;
    hk.OriginalAddr = Src;
    hk.HookAddr = Dst;
    hk.GatewayAddr = pGatewayAddr;

    hooks[Src] = hk;

    return pGatewayAddr;
}

LPVOID 
HookManager::Hook64(
    _In_ BYTE* Src, 
    _In_ BYTE* Dst
)
{
    // mov rax, <addr>
    // jmp rax

    return nullptr;
}

LPVOID 
HookManager::Hook32(
    _In_ BYTE* Src, 
    _In_ BYTE* Dst
)
{
    DWORD dwOldCodeDelta;
    DWORD dwOldProtection;
    DWORD dwRelativeAddrDstDelta;

    // 
    // Allocate a memory to store the code overwritten and the jump back
    //
    BYTE* pOldCode = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, 2 * X86_TRAMPOLINE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (pOldCode == nullptr) return nullptr;
    // 
    // Copy the old code before overwrite
    //
    memcpy_s(pOldCode, X86_TRAMPOLINE_SIZE, Src, TRAMPOLINE_SIZE);

    //
    // Build code: jmp OldCodeDelta
    //
    dwOldCodeDelta = Src - pOldCode - TRAMPOLINE_SIZE;
    
    //
    // Write relative jump
    //
    pOldCode[(uint8_t)X86_TRAMPOLINE_SIZE] = JUMP;
    
    //
    // Write destination, relative address to Dst 
    //
    *(DWORD_PTR*)(pOldCode + X86_TRAMPOLINE_SIZE + 1) = dwOldCodeDelta;
    
    //
    // Change protections to for writing
    //
    if (!VirtualProtect(Src, X86_TRAMPOLINE_SIZE, PAGE_READWRITE, &dwOldProtection))
    {
        std::printf("Error on replacing protection!\n");
        VirtualFree(pOldCode, NULL, MEM_RELEASE);
        return nullptr;
    }

    //
    // Calculate relative address
    //
    dwRelativeAddrDstDelta = Dst - Src - X86_TRAMPOLINE_SIZE;

    //
    // Write jump instruction
    //
    *Src = JUMP;
    //
    // Write destination
    //
    *(DWORD_PTR*)(Src + 1) = dwRelativeAddrDstDelta;
    //
    // Recover old protections
    //
    if (!VirtualProtect(Src, X86_TRAMPOLINE_SIZE, dwOldProtection, &dwOldProtection))
    {
        std::printf("Error on replacing protection!\n");
        VirtualFree(pOldCode, NULL, MEM_RELEASE);
        return nullptr;
    }

    return (LPVOID) pOldCode;
}
