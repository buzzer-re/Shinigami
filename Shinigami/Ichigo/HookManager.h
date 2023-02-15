#pragma once
#include <windows.h>
#include <unordered_map>

#define X86_TRAMPOLINE_SIZE 5
#define X64_TRAMPOLINE_SIZE 16

#define HOOK_MAX_SIZE 2*5
#define TRAMPOLINE_SIZE 5

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
};

class HookManager
{
public:
	LPVOID AddHook(_In_ BYTE* Src, _In_ BYTE* Dst);
private:
	LPVOID Hook64(_In_ BYTE* Src, _In_ BYTE* Dst);
	LPVOID Hook32(_In_ BYTE* Src, _In_ BYTE* Dst);

private:
	std::unordered_map<LPVOID, Hook> hooks;
};

