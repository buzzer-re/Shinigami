#include "pch.h"
#include "PEDumper.h"
#include "Logger.h"

Memory* PEDumper::FindRemotePE(HANDLE hProcess, const Memory* mem)
{
    // Check PE headers

    IMAGE_DOS_HEADER dosHdr;
    SIZE_T dwBytesRead;

    if (!ReadProcessMemory(hProcess, mem->Addr, &dosHdr, sizeof(dosHdr), &dwBytesRead)) return nullptr;

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    {
        // ScanPEHeaders((ULONG_PTR) dosHdr);
        return nullptr;
    }


    LPVOID pPE = VirtualAlloc(NULL, mem->Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pPE == nullptr) return nullptr;


    if (!ReadProcessMemory(hProcess, mem->Addr, pPE, mem->Size, &dwBytesRead)) return nullptr;


    Memory* dumped = new Memory;

    dumped->Addr = (uint8_t*) pPE;
    dumped->Size = mem->Size;
    dumped->prot = PAGE_READWRITE;
    dumped->safe = true;
    dumped->cAlloc = false; 


    // 
    // Make the Raw sections become the Virtual, since we are in memory
    //
    FixPESections(dumped);
   
    return dumped;
}

Memory* PEDumper::DumpPE(ULONG_PTR* Address)
{

    PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)Address;
    PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((BYTE*)Address + pDOSHdr->e_lfanew);
    Memory* mem = nullptr;

    if (pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE && pNTHdr->Signature == IMAGE_NT_SIGNATURE)
    {
        mem = new Memory;
        mem->Addr = (uint8_t*) Address;
        mem->Size = GetPESize(pNTHdr);
        mem->safe = false;
    }
    
    return mem;
}

PIMAGE_DOS_HEADER PEDumper::FindPE(Memory* Mem)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    MEMORY_BASIC_INFORMATION mbi;

    for (uint8_t* Curr = reinterpret_cast<uint8_t*>(Mem->Addr); (ULONG_PTR)Curr < Mem->End - sizeof(IMAGE_DOS_HEADER); Curr++)
    {
        pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Curr);

        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);

            if ((ULONG_PTR)pNtHeader <= Mem->End)
            {
                if (!VirtualQuery((LPCVOID)pNtHeader, &mbi, 0x1000))
                    continue;
                
                if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
                    return pDosHeader;
            }
        }
    }
    // Search for detached headers
    return PEDumper::HeuristicSearch(Mem);
}

PIMAGE_DOS_HEADER PEDumper::HeuristicSearch(Memory* Mem)
{
    PipeLogger::LogInfo(L"Starting heuristic scan for detached headers at 0x%p...", Mem->Addr);
    // Search for NT headers
    // If found, validated sections offset and if it has code
    PIMAGE_NT_HEADERS pNtHeader;
    MEMORY_BASIC_INFORMATION mbi;

    for (uint8_t* Curr = reinterpret_cast<uint8_t*>(Mem->Addr); (ULONG_PTR)Curr < Mem->End - sizeof(IMAGE_NT_HEADERS); Curr++)
    {
        pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(Curr);
        if  (IsValidNT(pNtHeader))
        {
            // So far so good
            PipeLogger::LogInfo(L"Found possible NT header at 0x%p", Curr);

            if (!VirtualQuery((LPCVOID)&pNtHeader->OptionalHeader, &mbi, sizeof(IMAGE_OPTIONAL_HEADER)))
                continue;

            if ((ULONG_PTR) Mem->Addr + pNtHeader->OptionalHeader.AddressOfEntryPoint == Mem->IP)
            {
                // We are at this executable entrypoint, rebuild the DOS header
                if (Mem->Addr - Curr <= sizeof(IMAGE_DOS_HEADER))
                {
                    // We dont have space
                    // TODO: Resize Mem struct
                }

                PIMAGE_DOS_HEADER DosHdr = RebuildDOSHeader(Mem, (ULONG_PTR) Curr);
                if (DosHdr != nullptr)
                {
                    PipeLogger::LogInfo(L"DOS header rebuilded!");
                    return DosHdr;
                }
            } 
            else
            {
                // Parse each section in this possible header, verify if is at a valided the section struct data (permissions, offset...)
                // If looks valid verify if the current EIP is between some of them 
                // If it is, log that, else log that it found valid sections mapped but the code might be hidden somehow
                // Save the current NT address and proceed to the brute-force part of this code, if the brute-force fail
                // use this saved NT address and tell the user
                IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
                bool Invalid = true;
                bool IPInBetween = false;
                ULONG_PTR VirtualMemAddr;
                for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
                    // Invalid memory area
                    if (Utils::IsReadWritable((ULONG_PTR*)sectionHeader) == INVALID_MEMORY_AREA) {
                        Invalid = true;
                        break;
                    }

                    VirtualMemAddr = sectionHeader->VirtualAddress + (ULONG_PTR)Mem->Addr;
                    // Check if there is any overflow here
                    if (sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData + (ULONG_PTR) Mem->Addr >= Mem->End || 
                        sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize + (ULONG_PTR) Mem->Addr >= Mem->End)
                    {
                        Invalid = true;
                        break;
                    }          

                    // Check if the Instruction pointer is between this image
                    if (Mem->IP >= VirtualMemAddr && Mem->IP <= VirtualMemAddr + sectionHeader->Misc.VirtualSize)
                        IPInBetween = true;
                   
                }

                if (Invalid)
                    continue;
                
                if (!Invalid && IPInBetween)
                {
                    PipeLogger::LogInfo(L"Possible NT found at 0x%p! Trying to rebuild...", pNtHeader);
                    PIMAGE_DOS_HEADER DosHdr = RebuildDOSHeader(Mem, (ULONG_PTR)Curr);
                    if (DosHdr != nullptr)
                    {
                        PipeLogger::LogInfo(L"DOS header rebuilded!");
                        return DosHdr;
                    }
                }
            }
        }
    }


    // We failed to search detached DOS headers
    // Search for common sections names such: .text, .data, .rdata
    // If found, walk back and try to rebuild the DOS headers and NT headers



    // We failed, return nullptr

    return nullptr;
}


// Verify NT headers fields to validate if is valid
BOOL PEDumper::IsValidNT(PIMAGE_NT_HEADERS pNtHeader)
{
    return pNtHeader->Signature == IMAGE_NT_SIGNATURE &&
            (
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_OS2_CUI ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_POSIX_CUI ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI ||
                pNtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN
            )
        &&
        (
            pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
            pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
        );
}


PIMAGE_DOS_HEADER PEDumper::RebuildDOSHeader(Memory* Mem, ULONG_PTR NtHeaderOffset)
{
    // This function rely in the fact that we already have space allocated, if there is no space in the beginning of this file
    // the memory must be resized calling the mem.IncreaseSize(sizeof(IMAGE_DOS_HEADER), SHIFT_BEGIN) before call this function
    // Check if we have space
    DWORD OldProt;

    if (Mem->Size < sizeof(IMAGE_DOS_HEADER) || NtHeaderOffset >= Mem->End) return nullptr;

    PIMAGE_DOS_HEADER DosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(Mem->Addr);
    // Rebuild basic fields only

    if (!VirtualProtect(Mem->Addr, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &OldProt))
        return nullptr;

    DosHdr->e_magic  = IMAGE_DOS_SIGNATURE;
    DosHdr->e_lfanew = NtHeaderOffset - (ULONG_PTR) DosHdr;

    VirtualProtect(Mem->Addr, sizeof(IMAGE_DOS_HEADER), OldProt, &OldProt);
    FixPESections(Mem);

    return DosHdr;
}


SIZE_T PEDumper::GetPESize(PIMAGE_NT_HEADERS pNTHeader)
{
    // Get the first section header
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

    // Calculate the raw size of the image
    size_t rawSize = pNTHeader->OptionalHeader.SizeOfHeaders;
    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
        // Calculate the raw size of the section
        size_t rawSectionSize = sectionHeader->SizeOfRawData;
        if (rawSectionSize == 0) {
            // If the section has no raw data, use the size of one page instead
            rawSectionSize = pNTHeader->OptionalHeader.FileAlignment;
        }

        // Add the raw size of the section to the total
        rawSize += rawSectionSize;
    }

    return rawSize;
}

std::wstring AsciiToWide(const std::string& strAscii)
{
    int nLen = static_cast<int>(strAscii.length());
    int nWideLen = MultiByteToWideChar(CP_ACP, 0, strAscii.c_str(), nLen, nullptr, 0);
    std::wstring strWide(nWideLen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, strAscii.c_str(), nLen, &strWide[0], nWideLen);
    return strWide;
}

//
// Fix in memory PE file to match the section information address in disk
//
VOID PEDumper::FixPESections(Memory* mem)
{
    PIMAGE_DOS_HEADER pDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(mem->Addr);
    PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)mem->Addr + pDosHdr->e_lfanew);

    // Check if the PE headers are within a valid memory region
    if (Utils::IsReadWritable((ULONG_PTR*)pNtHeader) == INVALID_MEMORY_AREA) {
        return;
    }
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(pNtHeader);

    // Modify the section headers
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        // Check if the section header is within a valid memory region
        if (Utils::IsReadWritable((ULONG_PTR*)sectionHeaders) == INVALID_MEMORY_AREA) {
            break;
        }

        // Change the section header's protection to read-write if necessary
        DWORD dwOldProtection;
        if (!VirtualProtect(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), PAGE_READWRITE, &dwOldProtection)) {
            break;
        }

        // Modify the section header's fields
        sectionHeaders[i].PointerToRawData = sectionHeaders[i].VirtualAddress;
        sectionHeaders[i].SizeOfRawData = sectionHeaders[i].Misc.VirtualSize;

        // Restore the section header's original protection
        VirtualProtect(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), dwOldProtection, &dwOldProtection);

    }
}

