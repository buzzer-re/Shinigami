#include "pch.h"
#include "Unpacker.h"


NTSTATUS WINAPI Unpacker::hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    PipeLogger::LogInfo(L"Allocating at 0x%llx with protections %d\n", BaseAddress, Protect);

    if ((Protect & PAGE_GUARD) != PAGE_GUARD)
        Protect |= PAGE_GUARD;
   
    return Unpacker::Unpacker.Win32Pointers.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}



//
// Hook NtUserAllocateMemory and VirtualProtect to add the PAGE_GUARD bit to handle when the memory allocated is going
// to be executed
//
BOOL InitUnpackerHooks(HookManager& hkManager)
{
    HMODULE NTDLL = GetModuleHandleA("NTDLL.DLL");
    if (NTDLL == NULL)
        return FALSE;

	BYTE* NtAllocateVirtualMemoryPointer = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtAllocateVirtualMemory"));
    
    //
    // Here we might trigger the HookChain, so we need to be very carefully with the operations on this hook
    // Since it will be from an already hooked function
    //
    Unpacker::Unpacker.Win32Pointers.NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory*>(hkManager.AddHook(NtAllocateVirtualMemoryPointer, (BYTE*)Unpacker::hkNtAllocateVirtualMemory));

    PipeLogger::LogInfo(L"Did we hook ? %d", Unpacker::Unpacker.Win32Pointers.NtAllocateVirtualMemory != nullptr);
	return TRUE;
}

