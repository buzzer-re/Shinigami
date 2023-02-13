#include <windows.h>
#include <iostream>

int main()
{
    std::printf("Verify me\n");
    getchar();
    LPVOID alloc = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (alloc == nullptr) {
        std::printf("Error allocating memory! => %d\n", GetLastError());
        return EXIT_FAILURE;
    }

    std::printf("[+] Allocated a couple of memory at 0x%lx ![+]\n", (ULONG_PTR) alloc);

    
    return EXIT_SUCCESS;
}
