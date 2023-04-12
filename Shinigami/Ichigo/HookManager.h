#pragma once

#include <windows.h>
#include <unordered_map>
#include <Zydis/Zydis.h>

#define X86_TRAMPOLINE_SIZE 5
#define X64_TRAMPOLINE_SIZE 13
#define X64_JUMP_BACK_SIZE X64_TRAMPOLINE_SIZE

#define HOOK_MAX_SIZE 2*5
#define NOP_SLIDE 32  // Nop slide helps with the HookChain structure
#define TRAMPOLINE_SIZE 5

#define NOP 0x90
#define JUMP 0xE9

enum HOOK_STATUS {
    HOOK_STATUS_SUCCESS,
    HOOK_STATUS_ALREADY_HOOKED,
    HOOK_STATUS_NOT_ENOUGH_MEMORY
};

struct Hook {
    LPVOID OriginalAddr;
    LPVOID HookAddr;
    LPVOID GatewayAddr;

    DWORD NumInstLeftToExec;
    // Only used for 32 bit hooks
    DWORD Trampoline32Delta;
    DWORD Gateway32Delta;
};


class HookManager
{
public:
    HookManager();
    LPVOID AddHook(_In_ BYTE* Src, _In_ BYTE* Dst,_In_ BOOL IgnoreProt);
    VOID DisassambleAt(_In_ ULONG_PTR* Address, _In_ SIZE_T NumberOfInstructions);

private:
    Hook* Hook64(_In_ BYTE* Src, _In_ BYTE* Dst, _In_ BOOL IgnoreProt);
    Hook* Hook32(_In_ BYTE* Src, _In_ BYTE* Dst, _In_ BOOL IgnoreProt);
private:
    ZydisDecoder ZDecoder;
    std::unordered_map<LPVOID, std::vector<Hook*>> HookChain;
};

