#include "pch.h"
#include "Unpacker.h"

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif

NTSTATUS WINAPI GenericUnpacker::hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    if (!GenericUnpacker::Ready)
        return GenericUnpacker::cUnpacker.Win32Pointers.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    SIZE_T AllocatedSize = *RegionSize;
    BOOL Track = FALSE;
    BOOL AddAfter = *BaseAddress == 0;
    
    if ((ProcessHandle == NULL || GetProcessId(ProcessHandle) == GenericUnpacker::IchigoOptions->PID) && (Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect & PAGE_EXECUTE))
    {
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
        PipeLogger::LogInfo(L"Tracking newly allocated memory 0x%p with protections 0x%x", *BaseAddress, Protect);
    }

    return status;
}

//
// Toggle on/off the PAGE_GUARD bit to avoid memory write errors, as we are more concerning about code execution than writing
// This only exists in the case when for some reason the loader write in itself using OpenProcess + WriteProcessMemory
//
NTSTATUS WINAPI GenericUnpacker::hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
    if (!GenericUnpacker::Ready)
        return GenericUnpacker::cUnpacker.Win32Pointers.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(BaseAddress, &mbi, NumberOfBytesToWrite);
DWORD OldProtection = mbi.Protect;

if ((ProcessHandle == NULL || GetProcessId(ProcessHandle) == GenericUnpacker::IchigoOptions->PID) && (mbi.Protect & PAGE_GUARD) && GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)BaseAddress))
{
    // Remove the PAGE_GUARD bit
    IgnoreMap[(ULONG_PTR)BaseAddress] = TRUE;
    VirtualProtect(BaseAddress, NumberOfBytesToWrite, mbi.Protect & ~PAGE_GUARD, &OldProtection);
    IgnoreMap[(ULONG_PTR)BaseAddress] = FALSE;
}

NTSTATUS status = GenericUnpacker::cUnpacker.Win32Pointers.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

VirtualProtect(BaseAddress, NumberOfBytesToWrite, OldProtection, &OldProtection);
return status;
}

NTSTATUS WINAPI GenericUnpacker::hkNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    // Verify that shit
    if (!GenericUnpacker::Ready)
        ignore:
    return GenericUnpacker::cUnpacker.Win32Pointers.NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (IgnoreMap.size() > 0)
    {
        auto IgnoreIter = IgnoreMap.find((ULONG_PTR)*BaseAddress);
        if (IgnoreIter != IgnoreMap.end() && IgnoreIter->second)
            goto ignore;
    }

    // Detect if it will change to a executable memory
    BOOL Track = FALSE;
    if ((ProcessHandle == NULL || GetProcessId(ProcessHandle) == GenericUnpacker::IchigoOptions->PID) && (NewProtect == PAGE_EXECUTE_READWRITE || NewProtect == PAGE_EXECUTE_READ || (NewProtect & PAGE_EXECUTE)))
    {
        // Add the PAGE_GUARD bit as well
        NewProtect |= PAGE_GUARD;
        Track = TRUE;
    }

    NTSTATUS status = GenericUnpacker::cUnpacker.Win32Pointers.NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (!NT_ERROR(status) && Track)
    {
        // Check if we already monitor this memory
        Memory* mem = GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)*BaseAddress);

        if (mem == nullptr)
        {
            // Monitor this address as well
            GenericUnpacker::cUnpacker.Watcher.push_back({});
            Memory& memory = GenericUnpacker::cUnpacker.Watcher.back();
            memory.Addr = reinterpret_cast<uint8_t*>(*BaseAddress);
            memory.End = reinterpret_cast<ULONG_PTR>(memory.Addr + *RegionSize);
            memory.Size = *RegionSize;
            memory.prot = NewProtect;
            PipeLogger::LogInfo(L"VirtualProtect: Tracking memory at 0x%p with protections 0x%x", *BaseAddress, NewProtect);
        }
    }

    return status;
}


// Thanks a lot Hoang Bui -> https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6 
LONG WINAPI GenericUnpacker::VEHandler(EXCEPTION_POINTERS* pExceptionPointers)
{
    if (!GenericUnpacker::Ready)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD dwOldProt;
    ULONG_PTR GuardedAddress;
    static ULONG_PTR LastValidExceptionAddress;
    MEMORY_BASIC_INFORMATION mbi;
    PEXCEPTION_RECORD ExceptionRecord = pExceptionPointers->ExceptionRecord;
    //PipeLogger::Log(L"Exception at 0x%x code %lx\n", ExceptionRecord->ExceptionAddress, ExceptionRecord->ExceptionCode);

    switch (ExceptionRecord->ExceptionCode)
    {
    case STATUS_GUARD_PAGE_VIOLATION:
        //
        // Verify if it's being monitored and executing
        //
        GuardedAddress = ExceptionRecord->ExceptionInformation[1]; 
        if (GenericUnpacker::cUnpacker.IsBeingMonitored((ULONG_PTR)pExceptionPointers->ContextRecord->XIP))
        {
            PipeLogger::LogInfo(L"STATUS_GUARD_PAGE_VIOLATION: Attempt to execute a monitored memory area at address 0x%lx, starting dumping...", ExceptionRecord->ExceptionAddress);
            ULONG_PTR StartAddress = (ULONG_PTR)pExceptionPointers->ContextRecord->XIP;
            Memory* Mem = GenericUnpacker::cUnpacker.IsBeingMonitored(StartAddress);

            if (GenericUnpacker::cUnpacker.Dump(Mem))
            {
                PipeLogger::Log(L"Saved stage %d as %s ", GenericUnpacker::cUnpacker.StagesPath.size(), GenericUnpacker::cUnpacker.StagesPath.back().c_str());
                GenericUnpacker::cUnpacker.RemoveMonitor(Mem);
            }
            
        }
        // An exception happened, but we are not monitoring this code and this code is operating inside our monitored memory
        // like an shellcode decryption process, we need to save this address to place the page_guard bit again
        else if (GenericUnpacker::cUnpacker.IsBeingMonitored(GuardedAddress))
        {
            LastValidExceptionAddress = GuardedAddress;
        }

        pExceptionPointers->ContextRecord->EFlags |= TF;
        return EXCEPTION_CONTINUE_EXECUTION;
    
    case STATUS_SINGLE_STEP:
        // Add the PAGE_GUARD again
        if (GenericUnpacker::cUnpacker.IsBeingMonitored(LastValidExceptionAddress))
        {
            VirtualQuery((LPCVOID) LastValidExceptionAddress, &mbi, PAGE_SIZE);
            mbi.Protect |= PAGE_GUARD;
            VirtualProtect((LPVOID) LastValidExceptionAddress, PAGE_SIZE, mbi.Protect, &dwOldProt);
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
    
    if (mbi.Protect & PAGE_GUARD)
        VirtualProtect((LPVOID) Address, 0x1000, mbi.Protect & ~PAGE_GUARD , &dwOldProt);
}


//
// Hook NtUserAllocateMemory and VirtualProtect to add the PAGE_GUARD bit to handle when the memory allocated is going
// to be executed
//
BOOL GenericUnpacker::InitUnpackerHooks(HookManager& hkManager, Ichigo::Arguments& Arguments)
{
    HMODULE NTDLL = GetModuleHandleA("NTDLL.DLL");
    if (NTDLL == NULL)
        return FALSE;

	BYTE* NtAllocateVirtualMemoryPointer = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtAllocateVirtualMemory"));
    BYTE* NtWriteVirtualMemoryPointer    = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtWriteVirtualMemory"));
    BYTE* NtProtectVirtualMemoryPointer  = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtProtectVirtualMemory"));

    //
    // Here we might trigger the HookChain, so we need to be very carefully with the operations on this hook
    // Since it will be from an already hooked function
    //
    GenericUnpacker::cUnpacker.Win32Pointers.NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory*>(hkManager.AddHook(NtAllocateVirtualMemoryPointer, (BYTE*)GenericUnpacker::hkNtAllocateVirtualMemory, FALSE));
    GenericUnpacker::cUnpacker.Win32Pointers.NtWriteVirtualMemory    = reinterpret_cast<NtWriteVirtualMemory*>(hkManager.AddHook(NtWriteVirtualMemoryPointer, (BYTE*)GenericUnpacker::hkNtWriteVirtualMemory, FALSE));
    GenericUnpacker::cUnpacker.Win32Pointers.NtProtectVirtualMemory  = reinterpret_cast<NtProtectVirtualMemory*>(hkManager.AddHook(NtProtectVirtualMemoryPointer, (BYTE*)GenericUnpacker::hkNtProtectVirtualMemory, TRUE));
    
    //
    // Register the VEH handler
    //
    AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)GenericUnpacker::VEHandler);

    PipeLogger::LogInfo(L"Unpacker: -- Hooked functions and added the VEH callback --");
    GenericUnpacker::Ready          = TRUE;
    GenericUnpacker::IchigoOptions  = &Arguments;

    return TRUE;
}

//
// Save the raw dump of the suspicious code
// Also scan searching for MZ/PE headers
//
BOOL GenericUnpacker::Unpacker::Dump(Memory* Mem)
{
    if (Mem == nullptr) return FALSE;
    std::wstring suffix = L"_shellcode." + std::to_wstring(StagesPath.size() + 1) + L".bin";
    
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Mem->Addr);
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
    else 
    {   
        // Search a PE file within the region
        PIMAGE_DOS_HEADER pDosHeader = PEDumper::FindPE(Mem);

        if (pDosHeader != nullptr)
        {
            // Found it, save as part of this stage as well
            Memory PeMem;
            PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);

            std::wstring EmbededPESuffix = L"_artefact_inside_stage_" + std::to_wstring(StagesPath.size() + 1) + L"_area.exe";
            std::wstring FileName = Utils::BuildFilenameFromProcessName(EmbededPESuffix.c_str());
            std::wstring SaveName = Utils::PathJoin(GenericUnpacker::IchigoOptions->WorkDirectory, FileName);
            
  
            PeMem.Addr = reinterpret_cast<uint8_t*>(pDosHeader);
            PeMem.Size = PEDumper::GetPESize(pNtHeaders);
            PeMem.End  = reinterpret_cast<ULONG_PTR>(PeMem.Size + PeMem.Addr);
            if (Utils::SaveToFile(SaveName.c_str(), &PeMem, FALSE))
            {
                PipeLogger::Log(L"Found a embedded PE file inside the newly executed memory are, saved as %s!", SaveName.c_str());
                if (Ichigo::Options.OnlyPE)
                {
                    StagesPath.push_back(SaveName);
                    return TRUE;
                }
            }
        }
    }
    
    if (Ichigo::Options.OnlyPE) return FALSE;

    std::wstring FileName = Utils::BuildFilenameFromProcessName(suffix.c_str());
    std::wstring SaveName = Utils::PathJoin(GenericUnpacker::IchigoOptions->WorkDirectory, FileName);

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

//
// Remove memory area from the monitor list
//
VOID GenericUnpacker::Unpacker::RemoveMonitor(Memory* Mem)
{
    Watcher.remove(*Mem);
}

//
// Remove all memory entries page guards
//
VOID GenericUnpacker::Unpacker::CleanMonitor()
{
    for (auto& Mem: Watcher)
    {
        GenericUnpacker::RemoveGuard((ULONG_PTR)Mem.Addr);
    }
}

//
// Clean our data
//
VOID GenericUnpacker::Shutdown()
{
    GenericUnpacker::cUnpacker.CleanMonitor();
}