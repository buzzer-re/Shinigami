#include "pch.h"
#include "PEDumper.h"

Memory* PEDumper::FindRemotePE(HANDLE hProcess, const Memory* mem) const
{
    // Check PE headers

    IMAGE_DOS_HEADER dosHdr;
    SIZE_T dwBytesRead;

    if (!ReadProcessMemory(hProcess, mem->Addr, &dosHdr, sizeof(dosHdr), &dwBytesRead)) return nullptr;


    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    {
        // Deep search, implement
    }

    LPVOID pPE = VirtualAlloc(NULL, mem->Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pPE == nullptr) return nullptr;


    if (!ReadProcessMemory(hProcess, mem->Addr, pPE, mem->Size, &dwBytesRead)) return nullptr;


    Memory* dumped = new Memory;

    dumped->Addr = (uint8_t*) pPE;
    dumped->Size = mem->Size;
    dumped->prot = PAGE_READWRITE;

    return dumped;
}
