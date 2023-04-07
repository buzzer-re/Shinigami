#include "pch.h"
#include "ProcessUnhollow.h"

//
// Monitore Allocation and saves the target PID
// 
NTSTATUS WINAPI Unhollow::hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    NTSTATUS status = ProcessInformation.Win32Pointers.NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
   
    DWORD ProcessPID = GetProcessId(ProcessHandle);
    if (ProcessPID == Unhollow::ProcessInformation.pi.dwProcessId && NT_SUCCESS(status))
    {
        if (BaseAddress == nullptr)
        {
            PipeLogger::LogInfo(L"NtAllocateVirtualMemory -- Error: returned allocation address is null Last error code: %d!", GetLastError());
            return status;
        }
        //
        // Search if we already have this entry
        //
        auto& Watcher = Unhollow::ProcessInformation.Watcher;
        auto it = std::find_if(Watcher.begin(), Watcher.end(), [BaseAddress](Memory* mem) { return mem->Addr == (uint8_t*) BaseAddress; });
        if (it == Watcher.end())
        {
            PipeLogger::LogInfo(L"NtAllocateVirtualMemory -- Monitoring memory at 0x%llx --", BaseAddress);
            //
            // Create a memoryu entry that will be used later when hunting the PE in memory
            //
            Memory* mem = new Memory;
            mem->Addr = reinterpret_cast<uint8_t*>(*BaseAddress);
            mem->Size = (DWORD)*RegionSize;
            mem->safe = false;
            mem->ProcessID = GetProcessId(ProcessHandle);

            Watcher.push_back(mem);
        }
    }
    
    return status;
}

NTSTATUS WINAPI Unhollow::hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
    DWORD MonitoredPID = Unhollow::ProcessInformation.pi.dwProcessId;//Unhollow::ProcessInformation.pi.dwProcessId;

    if (GetProcessId(ProcessHandle) == MonitoredPID &&
        NumberOfBytesToWrite >= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS))
    {
        PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)Buffer;

        if (pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE)
        {   
            PipeLogger::LogInfo(L"NtWriteVirtualMemory -- Detected an attempt to write a PE file in another process!");
            Memory* hollow = PEDumper::DumpPE((ULONG_PTR*)Buffer);
            if (hollow)
            {
                // TODO: Add a INPUT option here to continue or not, because i've seem some loaders that fix the ImageBase field with the reloc delta before write the process
                // if the PE has a realocation table
                // In this scenario is good to continue, since the resume one will already be fixed
                PipeLogger::LogInfo(L"Extracted implant of %d bytes before it been written, saving!", hollow->Size);
                std::wstring SaveName = Utils::BuildFilenameFromProcessName(L"_dumped_before_write.bin");

                if (Utils::SaveToFile(SaveName.c_str(), hollow))
                {
                    PipeLogger::LogInfo(L"NtWriteVirtualMemory: -- Saved as %s! --", SaveName.c_str());
                }
                else {
                    PipeLogger::LogInfo(L"NtWriteVirtualMemory: -- Error saving file: %d --", GetLastError());
                }

                delete hollow;
                TerminateProcess(Unhollow::ProcessInformation.pi.hProcess, 0);
                ExitProcess(1);
            }
        }

    }

    NTSTATUS success = Unhollow::ProcessInformation.Win32Pointers.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    if (!NT_SUCCESS(success))
    {
        PipeLogger::LogInfo(L"NtWriteVirtualMemory -- Error on writing process memory: %d --", GetLastError());
    }

    return success;
}


//
// Monitor every process creation until find a suspended
//
NTSTATUS WINAPI Unhollow::hkNtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
) {
    PipeLogger::LogInfo(L"NtCreateUserProcess -- Called for: %s --", ProcessParameters->ImagePathName.Buffer);
    // Call the original function and store its return value
    NTSTATUS status = Unhollow::ProcessInformation.Win32Pointers.NtCreateUserProcess(
        ProcessHandle,
        ThreadHandle,
        ProcessDesiredAccess,
        ThreadDesiredAccess,
        ProcessObjectAttributes,
        ThreadObjectAttributes,
        ProcessFlags,
        ThreadFlags,
        ProcessParameters,
        CreateInfo,
        AttributeList
    );

    // Check if the process was successfully created and is suspended
    if (NT_SUCCESS(status) && (ProcessFlags & CREATE_SUSPENDED) == CREATE_SUSPENDED) {
        // Copy the process information to the global ProcessInformation object
        Unhollow::ProcessInformation.DumptAtResume  = TRUE;
        Unhollow::ProcessInformation.pi.dwProcessId = GetProcessId(*ProcessHandle);
        Unhollow::ProcessInformation.pi.dwThreadId  = GetThreadId(*ThreadHandle);
        Unhollow::ProcessInformation.pi.hProcess    = *ProcessHandle;

        // Log information about the newly created process
        PipeLogger::LogInfo(L"NtCreateUserProcess: -- Monitoring suspended process %d for memory writes... --", Unhollow::ProcessInformation.pi.dwProcessId);
    } 
    
    else if (!NT_SUCCESS(status))
    {
        PipeLogger::LogInfo(L"NtCreateUserProcess: -- Error creating %s -> %d --", ProcessParameters->ImagePathName.Buffer, GetLastError());
    }

    // Return the status code from the original function
    return status;
}

NTSTATUS WINAPI Unhollow::hkNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{

    // TODO: Refactore this
    DWORD ThreadId = GetThreadId(ThreadHandle);

    if (Unhollow::ProcessInformation.DumptAtResume && Unhollow::ProcessInformation.pi.dwThreadId == ThreadId) {
        PipeLogger::LogInfo(L"NtResumeThread -- Called resume in the injected target, starting dump! --");
        Memory* Hollow = Unhollow::HuntPE();
        if (Hollow)
        {
            PipeLogger::LogInfo(L"NtResumeThread -- Dumped hollow of %d bytes --", Hollow->Size);
            std::wstring saveName = Utils::BuildFilenameFromProcessName(L"_dumped.bin");

            if (Utils::SaveToFile(saveName.c_str(), Hollow))
                PipeLogger::LogInfo(L"NtResumeThread -- Saved PE as %s --", saveName.c_str());
            else
                PipeLogger::LogInfo(L"NtResumeThread -- Unable to save PE file! --");

            delete Hollow;
        }
        else
        {
            PipeLogger::LogInfo(L"NtResumeThread -- Unable to dump, error code: %d. Exiting for safety --", GetLastError());
        }
        //
        // Kill hollowed process
        //
        TerminateProcess(Unhollow::ProcessInformation.pi.hProcess, 0);
        ExitProcess(0);
    }

    return Unhollow::ProcessInformation.Win32Pointers.NtResumeThread(ThreadHandle, SuspendCount);
}


Memory* Unhollow::HuntPE()
{
    Memory* PE = nullptr;
    // Walk the watch list and Hunt for the PE headers
    // TODO: Handle erased PE headers

    for (auto& MemEntry : Unhollow::ProcessInformation.Watcher)
    {
        if (MemEntry->ProcessID == Unhollow::ProcessInformation.pi.dwProcessId)
        {
            PE = PEDumper::FindRemotePE(Unhollow::ProcessInformation.pi.hProcess, MemEntry);
                
            if (PE != nullptr)
                break;
        }
    }

    return PE;
}


//
// Hook every NT function related to the Process Hollowing technique
//
BOOL InitUnhollowHooks(HookManager& hkManager)
{
    HMODULE NTDLL = GetModuleHandleA("NTDLL.DLL");
    if (NTDLL == NULL)
        return FALSE;

    Unhollow::ProcessInformation.NTDLL = NTDLL;
    BYTE* NtResumeThreadPointer                                         = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtResumeThread"));
    BYTE* NtAllocateVirtualMemoryPointer                                = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtAllocateVirtualMemory"));
    BYTE* NtWriteVirtualMemoryPointer                                   = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtWriteVirtualMemory"));
    BYTE* NtCreateUserProcessPointer                                    = reinterpret_cast<BYTE*>(GetProcAddress(NTDLL, "NtCreateUserProcess"));

    Unhollow::ProcessInformation.Win32Pointers.NtAllocateVirtualMemory  = (NtAllocateVirtualMemory*)hkManager.AddHook(NtAllocateVirtualMemoryPointer, (BYTE*)Unhollow::hkNtAllocateVirtualMemory);
    Unhollow::ProcessInformation.Win32Pointers.NtWriteVirtualMemory     = (NtWriteVirtualMemory*)hkManager.AddHook(NtWriteVirtualMemoryPointer, (BYTE*)Unhollow::hkNtWriteVirtualMemory);
    Unhollow::ProcessInformation.Win32Pointers.NtCreateUserProcess      = (NtCreateUserProcess*)hkManager.AddHook(NtCreateUserProcessPointer, (BYTE*)Unhollow::hkNtCreateUserProcess);
    Unhollow::ProcessInformation.Win32Pointers.NtResumeThread           = (NtResumeThread*)hkManager.AddHook(NtResumeThreadPointer, (BYTE*)Unhollow::hkNtResumeThread);
    
    PipeLogger::LogInfo(L"Unhollow: -- Hooked Process Unhollow functions --");
    return TRUE;
}


VOID Shutdown()
{
    for (auto& addr : Unhollow::ProcessInformation.Watcher)
    {
        delete addr;
    }
}

