#include "pch.h"
#include "HookManager.h"
#include <iostream>

HookManager::HookManager()
{
#if defined(_WIN64)
    ZydisDecoderInit(&ZDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
    ZydisDecoderInit(&ZDecoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
}


LPVOID
HookManager::AddHook(
    _In_ BYTE* Src,
    _In_ BYTE* Dst,
    _In_ BOOL IgnoreProt
)
{
    Hook* NewHook;
    auto it = HookChain.find(Src);

    if (it != HookChain.end())
    {
        Hook* LastHook = it->second.back();
    //
    // Add new hook in the hook chain, so that way all the hooks are called recursively 
    //
#if defined(_WIN64)
        NewHook = Hook64((BYTE*) LastHook->GatewayAddr, Dst, IgnoreProt);
#else
        NewHook = Hook32((BYTE*)LastHook->GatewayAddr, Dst, IgnoreProt);
#endif
    }
    else 
    {
#if defined(_WIN64)
        NewHook = Hook64(Src, Dst, IgnoreProt);
#else
        NewHook = Hook32(Src, Dst, IgnoreProt);
#endif
    }
    //
    // Sad, we failed ;-;
    //
    if (NewHook == nullptr)
        return nullptr;

    // 
    // Insert new hook on the manager map
    //
    HookChain[Src].push_back(NewHook);

    return NewHook->GatewayAddr;
}


VOID HookManager::DisassambleAt(_In_ ULONG_PTR* Address, _In_ SIZE_T NumberOfInstructions)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    CHAR Buffer[256];


    for (SIZE_T i = 0; i < NumberOfInstructions; i++)
    {
        // Decode the instruction at the specified address
        ZydisDecodedInstruction instruction;
        ZydisDecoderDecodeBuffer(&ZDecoder, reinterpret_cast<const void*>(Address), 16, &instruction);

        // Format the instruction and print it to the console

        ZydisFormatterFormatInstruction(&formatter, &instruction, Buffer, sizeof(Buffer), (ZyanU64)Address);
        std::printf("0x%x - %s\n", Address, Buffer);
        Address = (ULONG_PTR*)((BYTE*)Address + instruction.length);
    }
}

Hook*
HookManager::Hook64(_In_ BYTE* Src, _In_ BYTE* Dst, _In_ BOOL IgnoreProt)
{
    //
    // This is the base template trampoline code that will be used in future operations. 
    // The "pop rax" instruction is necessary to restore the original value of the register and ensure that we don't mess up the function's logic.
    // We don't use the "push" instruction here because this is the beginning of the function. 
    // If this hook is going to be used in the middle of a function in the future, 
    // we will need to push rax to the stack first to preserve its value.
    //
    BYTE JumpToHookCode[] = {
        0x48, 0xB8 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov rax, <Address>
        0xFF, 0xE0,                                                    // jmp rax
        0x58,                                                          // pop rax
    };
    //
    // The stolen bytes will be saved in this buffer to execute later
    // We push rax to preserve its value, which will be recovered by the pop rax instruction in the trampoline code
    //
    BYTE JumpBackCode[] = {
        0x50,                                                          // push rax
        0x48, 0xB8 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov rax, <Address>
        0xFF, 0xE0,                                                    // jmp rax
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
    // Dissasemble and analyze the instructions make sure that everything is aligned and working properly
    //
    ZydisDecodedInstruction inst;

    //
    // Hook structure to store core information about this hook 
    //
    Hook* HookStructure;

    //
    // Disassemble to pick the instructions length 
    //
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&ZDecoder, pSrc, X64_TRAMPOLINE_SIZE, &inst)) && overlap < X64_TRAMPOLINE_SIZE)
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
    // Add a NOP slide to give a good space to the HookChain structure
    //
    memset(pOldCode, NOP, NOP_SLIDE);
    //
    // Copy the exactly instructions that should be executed, extracted by Zydis
    //
    memcpy_s(pOldCode + NOP_SLIDE, overlap + X64_TRAMPOLINE_SIZE, Src, overlap);
    //
    // Nop Src to avoid execute invalid instructions
    //
    memset(Src, NOP, overlap);
    //
    // Add the jump back to the next instruction
    //
    *(ULONG_PTR*)(JumpBackCode + 3) = (ULONG_PTR)(Src + X64_TRAMPOLINE_SIZE - 1);

    memcpy_s(pOldCode + overlap + NOP_SLIDE, X64_TRAMPOLINE_SIZE, JumpBackCode, X64_TRAMPOLINE_SIZE);

    //
    // Build the trampoline code to jump to the hook function
    //
    *(ULONG_PTR*)(JumpToHookCode + 2) = (ULONG_PTR)Dst;

    memcpy_s(Src, X64_TRAMPOLINE_SIZE, JumpToHookCode, X64_TRAMPOLINE_SIZE);
    
    if (!IgnoreProt)
        VirtualProtect(Src, X64_TRAMPOLINE_SIZE, dwOldProtect, &dwOldProtect);

    HookStructure                    = new Hook;
    HookStructure->HookAddr          = Dst;
    HookStructure->OriginalAddr      = Src;
    HookStructure->GatewayAddr       = pOldCode;
    HookStructure->NumInstLeftToExec = overlap;
    
    return HookStructure;
}

Hook*
HookManager::Hook32(
    _In_ BYTE* Src,
    _In_ BYTE* Dst,
    _In_ BOOL IgnoreProt
)
{
    ULONG_PTR dwOldCodeDelta;
    ULONG_PTR dwRelativeAddrDstDelta;

    DWORD dwOldProtection;
    DWORD overlap = 0;
    BYTE* pSrc = Src;
    Hook* HookStructure;

    ZydisDecodedInstruction inst;

    //
    // Disassemble to pick the instructions length 
    //
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&ZDecoder, pSrc, X64_TRAMPOLINE_SIZE, &inst)) && overlap < X86_TRAMPOLINE_SIZE)
    {
        overlap += inst.length;
        pSrc += inst.length;
    }

    //
    // Change protections to for writing
    //
    if (!VirtualProtect(Src, X86_TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection))
    {
        std::printf("Error on replacing protection!\n");
        return nullptr;
    }

    // 
    // Allocate a memory to store the code overwritten and the jump back
    //
    DWORD allocSize = overlap + NOP_SLIDE + X86_TRAMPOLINE_SIZE;
    BYTE* pOldCode = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (pOldCode == nullptr)
    {
        VirtualProtect(Src, X86_TRAMPOLINE_SIZE, dwOldProtection, &dwOldProtection);
        return nullptr;
    }

    // 
    // Copy the old code before overwrite
    //
    memcpy_s(pOldCode, overlap, Src, TRAMPOLINE_SIZE);
    //
    // Set old code opcodes to NOP
    //
    memset(Src, NOP, overlap);
    //
    // Build the NOP slide
    //
    memset(pOldCode + overlap, NOP, NOP_SLIDE);
    //
    // Build code: jmp OldCodeDelta
    //
    dwOldCodeDelta = Src - pOldCode - TRAMPOLINE_SIZE - NOP_SLIDE;
    //
    // Write relative jump
    //
    *(BYTE*)(pOldCode + overlap + NOP_SLIDE) = JUMP;
    //
    // Write destination, relative address to Dst 
    //
    *(DWORD_PTR*)(pOldCode + overlap + NOP_SLIDE + 1) = dwOldCodeDelta;
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
    if (!IgnoreProt && !VirtualProtect(Src, X86_TRAMPOLINE_SIZE, dwOldProtection, &dwOldProtection))
    {
        std::printf("Error on replacing protection!\n");
        VirtualFree(pOldCode, NULL, MEM_RELEASE);
        return nullptr;
    }

    HookStructure                       = new Hook;
    HookStructure->Gateway32Delta       = dwRelativeAddrDstDelta;
    HookStructure->Trampoline32Delta    = dwOldCodeDelta;
    HookStructure->HookAddr             = Dst;
    HookStructure->OriginalAddr         = Src;
    HookStructure->GatewayAddr          = pOldCode;
    HookStructure->NumInstLeftToExec    = overlap;

    
    return HookStructure;
}
