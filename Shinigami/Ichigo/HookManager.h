#pragma once
#include <windows.h>
#include <unordered_map>

#define HOOK_MAX_SIZE 2*5
#define TRAMPOLINE_SIZE 5

enum HOOK_STATUS {
	HOOK_STATUS_SUCCESS,
	HOOK_STATUS_ALREADY_HOOKED,
	HOOK_STATUS_NOT_ENOUGH_MEMORY
};


struct Hook {
	ULONG_PTR* OriginalAddr;
	ULONG_PTR* HookAddr;
	ULONG_PTR* GatewayAddr;
};

class HookManager
{
public:
	ULONG_PTR* __stdcall AddHook(BYTE* Dst, BYTE* Src, BYTE* OriginalAddr);
private:
	std::unordered_map<BYTE*, Hook> hooks;
};

