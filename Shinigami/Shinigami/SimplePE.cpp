#include "SimplePE.h"

SimplePE::SimplePE(const std::wstring& Path)
	: Path(Path)
{
	Valid = Load();
}

BOOL SimplePE::Load()
{
    HANDLE fileHandle = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        std::printf("Unable to open PE\n");
        return FALSE;
    }

    // Read the DOS header
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, &DosHdr, sizeof(IMAGE_DOS_HEADER), &bytesRead, nullptr) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(fileHandle);
        std::printf("Unable to read IMAGE_DOS_HEADER\n");
        return FALSE;
    }

    if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(fileHandle);
        std::puts("IMAGE_DOS_SIGNATURE mismatch");
        return FALSE;
    }

    // Move to the NT headers
    SetFilePointer(fileHandle, DosHdr.e_lfanew, nullptr, FILE_BEGIN);

    // Read the NT headers
    if (!ReadFile(fileHandle, &NtHeader, sizeof(IMAGE_NT_HEADERS), &bytesRead, nullptr) || bytesRead != sizeof(IMAGE_NT_HEADERS)) {
        CloseHandle(fileHandle);
        std::puts("Unable to read NT signature");
        return FALSE;
    }

    if (NtHeader.Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(fileHandle);
        std::puts("NT signature mismatch");
        return FALSE;
    }

    // Check if it is a DLL
    DLL = (NtHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        NtHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) &&
        (NtHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    CloseHandle(fileHandle);

    return TRUE;

}


BOOL SimplePE::IsDLL() const
{
	return DLL;
}
