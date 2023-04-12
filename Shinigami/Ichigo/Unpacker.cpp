#include "pch.h"
#include "Unpacker.h"


NTSTATUS WINAPI GenericUnpacker::hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    SIZE_T AllocatedSize = *RegionSize;
    BOOL Track = FALSE;
    if (Protect == PAGE_EXECUTE_READWRITE || (Protect & PAGE_EXECUTE) == PAGE_EXECUTE)
    {
        PipeLogger::LogInfo(L"Added the PAGE_GUARD bit at 0x%llx", *BaseAddress);
        Protect |= PAGE_GUARD;
        Track = TRUE;
    }

    NTSTATUS status = GenericUnpacker::cUnpacker.Win32Pointers.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    
    if (status == STATUS_SUCCESS && Track)
    {
        GenericUnpacker::cUnpacker.Watcher.push_back({});
        Memory& memory  = GenericUnpacker::cUnpacker.Watcher.back();
        memory.Addr     = reinterpret_cast<uint8_t*>(*BaseAddress);
        memory.End      = reinterpret_cast<ULONG_PTR>(memory.Addr + AllocatedSize);
        memory.Size     = AllocatedSize;
        memory.prot     = Protect;
        PipeLogger::LogInfo(L"Tracking memory at 0x%llx with protections 0x%x", *BaseAddress, Protect);
        PipeLogger::LogInfo(L"Look at 0x%llx", GenericUnpacker::hkNtAllocateVirtualMemory);
    }

    return status;
}

//
// Toggle on/off the PAGE_GUARD bit to avoid memory write errors, as we are more concerning about code execution than writing
//
NTSTATUS WINAPI GenericUnpacker::hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(BaseAddress, &mbi, NumberOfBytesToWrite);
    DWORD OldProtection = mbi.Protect;

    if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD && GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR) BaseAddress))
    {
        // Remove the PAGE_GUARD bit
        VirtualProtect(BaseAddress, NumberOfBytesToWrite, mbi.Protect & ~PAGE_GUARD, &OldProtection);
    }

    NTSTATUS status = GenericUnpacker::cUnpacker.Win32Pointers.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    VirtualProtect(BaseAddress, NumberOfBytesToWrite, OldProtection, &OldProtection);
    return status;
}


// Thanks a lot Hoang Bui -> https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6 
LONG WINAPI GenericUnpacker::VEHandler(EXCEPTION_POINTERS* pExceptionPointers)
{
    DWORD dwOldProt;
    MEMORY_BASIC_INFORMATION mbi;
    PEXCEPTION_RECORD ExceptionRecord = pExceptionPointers->ExceptionRecord;

    switch (ExceptionRecord->ExceptionCode)
    {
    case STATUS_GUARD_PAGE_VIOLATION:
        //
        // Verify if it's being monitored and executing
        //
        if (GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)ExceptionRecord->ExceptionAddress) && 
            GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)pExceptionPointers->ContextRecord->Rip))
        {
            PipeLogger::LogInfo(L"STATUS_GUARD_PAGE_VIOLATION: Attempt to execute a monitored memory area at address 0x%llx, starting dumping...", ExceptionRecord->ExceptionAddress);
            ULONG_PTR StartAddress = (ULONG_PTR)pExceptionPointers->ContextRecord->Rip;
            Memory* Mem = GenericUnpacker::cUnpacker.IsBeingMonitored(StartAddress);
            GenericUnpacker::RemoveGuard((ULONG_PTR) Mem->Addr);
            if (GenericUnpacker::cUnpacker.Dump(Mem))
            {
                PipeLogger::LogInfo(L"Saved stage %d as %s", GenericUnpacker::cUnpacker.StagesPath.size(), GenericUnpacker::cUnpacker.StagesPath.back().c_str());
                GenericUnpacker::cUnpacker.RemoveMonitor(Mem);
            }
            // TODO: Check user arguments if we should continue here
        }
        pExceptionPointers->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    
    case STATUS_SINGLE_STEP:
        // Add the PAGE_GUARD again
        if (GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)ExceptionRecord->ExceptionAddress))
        {
            VirtualQuery(ExceptionRecord->ExceptionAddress, &mbi, 0x1000);
            mbi.Protect |= PAGE_GUARD;
            VirtualProtect(ExceptionRecord->ExceptionAddress, 0x1000, mbi.Protect, &dwOldProt);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

VOID GenericUnpacker::RemoveGuard(ULONG_PTR Address)
{
    DWORD dwOldProt;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery((LPCVOID) Address, &mbi, 0x1000);
    VirtualProtect((LPVOID) Address, 0x1000, mbi.Protect & ~PAGE_GUARD , &dwOldProt);
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
    BYTE* NtWriteVirtualMemoryPointer = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtWriteVirtualMemory"));


    //
    // Register the VEH handler
    //
    AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)GenericUnpacker::VEHandler);

    //
    // Here we might trigger the HookChain, so we need to be very carefully with the operations on this hook
    // Since it will be from an already hooked function
    //
    GenericUnpacker::cUnpacker.Win32Pointers.NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory*>(hkManager.AddHook(NtAllocateVirtualMemoryPointer, (BYTE*)GenericUnpacker::hkNtAllocateVirtualMemory));
    GenericUnpacker::cUnpacker.Win32Pointers.NtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory*>(hkManager.AddHook(NtWriteVirtualMemoryPointer, (BYTE*)GenericUnpacker::hkNtWriteVirtualMemory));
    

    return TRUE;
}



BOOL GenericUnpacker::Unpacker::Dump(Memory* Mem)
{
    // Save the raw dump of the suspicious code
    // Also scan searching for MZ/PE headers
    
    if (Mem == nullptr) return FALSE;
    std::wstring suffix = L"_shellcode." + std::to_wstring(StagesPath.size() + 1) + L".bin";
    
    PIMAGE_DOS_HEADER dosHeader= reinterpret_cast<PIMAGE_DOS_HEADER>(Mem->Addr);
    PIMAGE_NT_HEADERS NTHeaders;
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        // Check NT
        NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR) dosHeader + dosHeader->e_lfanew);
        if (NTHeaders->Signature == IMAGE_NT_SIGNATURE) 
        {
            PEDumper::FixPESections(Mem);
            suffix = L"_stage_" + std::to_wstring(StagesPath.size() + 1) + std::wstring(L".exe");
        }
    }
    
    std::wstring SaveName = Utils::BuildFilenameFromProcessName(suffix.c_str());

    if (Utils::SaveToFile(SaveName.c_str(), Mem, TRUE))
    {
        StagesPath.push_back(SaveName);
        return TRUE;
    }
    
    return FALSE;
}


//
// Verify if the exception happened in one of our monitered addresses
//
Memory* GenericUnpacker::Unpacker::IsBeingMonitored(ULONG_PTR Address)
{
    for (auto& Mem: Watcher)
    {
        if (Address >= (ULONG_PTR)Mem.Addr && Address <= Mem.End)
            return &Mem;            
    }

    return nullptr;
}


VOID GenericUnpacker::Unpacker::RemoveMonitor(Memory* Mem)
{
    Watcher.remove(*Mem);
}
