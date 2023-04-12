#include "pch.h"
#include "PEDumper.h"

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

#include "Logger.h"
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

