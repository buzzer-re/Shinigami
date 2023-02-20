#include "pch.h"
#include "HookManager.h"
#include <iostream>

HookManager::HookManager()
{
    ZydisDecoderInit(&zDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
}

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
HookManager::Hook64(_In_ BYTE* Src, _In_ BYTE* Dst)
{
    //
    // Base template trampoline code to be used on next operations
    //
    BYTE TrampolineCode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ??
        0xFF, 0xE0                                                  // jmp rax
    };
    // 
    // Pointer to the Src, as this will be incremented later
    //
    BYTE* pSrc = Src;
    // 
    // Holds how many bytes should be copied before place the trampoline
    //
    BYTE overlap = 0;
    
    //
    // Where will hold the stolen bytes to execute
    //
    BYTE JumpBackCode[X64_TRAMPOLINE_SIZE];
    
    //
    // Our hook itself in the Dst
    //
    BYTE JumpToHookCode[X64_TRAMPOLINE_SIZE];
    memcpy_s(JumpBackCode, X64_TRAMPOLINE_SIZE, TrampolineCode, X64_TRAMPOLINE_SIZE);
    memcpy_s(JumpToHookCode, X64_TRAMPOLINE_SIZE, TrampolineCode, X64_TRAMPOLINE_SIZE);

    // 
    // Dissasemble and analyze the instructions make sure that everything is aligned and working properly
    //
    ZydisDecodedInstruction inst;
    
    //
    // Disassemble to pick the instructions length 
    //
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&zDecoder, pSrc, X64_TRAMPOLINE_SIZE, &inst)) && overlap < X64_TRAMPOLINE_SIZE)
    {
        overlap += inst.length;
        pSrc += inst.length;
    }

    // Allocate memory to store the overwritten bytes and the jump back trampoline
    BYTE* pOldCode = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, overlap + X64_TRAMPOLINE_SIZE + NOP_SLIDE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (pOldCode == nullptr) {
        return nullptr;
    }

    DWORD dwOldProtect;

    //
    // Store the original code, nop everything and build the trampoline code to jump back
    //
    VirtualProtect(Src, overlap, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    //
    // Copy the exactly instructions that should be executed, extracted by Zydis
    //
    memcpy_s(pOldCode, overlap + X64_TRAMPOLINE_SIZE + NOP_SLIDE, Src, overlap);
    //
    // Nop to avoid execute invalid instructions
    //
    memset(Src, NOP, overlap);
    // 
    // Add a NOP slide to avoid that the trampoline code mess up with some opcode
    //
    memset(pOldCode + overlap, NOP, NOP_SLIDE);
    //
    // Add the jump back to the next instruction
    //
    *(ULONG_PTR*)(JumpBackCode + 2) = (ULONG_PTR)(Src + X64_TRAMPOLINE_SIZE);

    memcpy_s(pOldCode + X64_TRAMPOLINE_SIZE + NOP_SLIDE, X64_TRAMPOLINE_SIZE, JumpBackCode, X64_TRAMPOLINE_SIZE);

    //
    // Build the trampoline code to jump to the hook function
    //
    *(ULONG_PTR*)(JumpToHookCode + 2) = (ULONG_PTR)Dst;

    memcpy_s(Src, X64_TRAMPOLINE_SIZE, JumpToHookCode, X64_TRAMPOLINE_SIZE);
    VirtualProtect(Src, X64_TRAMPOLINE_SIZE, dwOldProtect, &dwOldProtect);

    return pOldCode;
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
