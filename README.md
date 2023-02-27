# Shinigami

Shinigami is a tool to detect and dump malware implants that are injected via process hollowing technique. It works by hooking common functions like CreateProcessInternal, WriteProcessMemory, and ResumeThread. It creates the target executable in a suspended state and injects a DLL library called "Ichigo," which will hook every needed function to detect and dump the implant. The library automatically kills the process once the implant is extracted.

## How it works

When Shinigami is run with an executable and its arguments, it creates a process in a suspended state using CreateProcessInternal. Once the process is created, Shinigami injects the Ichigo library into it using WriteProcessMemory and CreateRemoteThread. The Ichigo library hooks the necessary functions and waits for the implant to be detected.

The implant can be detected by hooking the ResumeThread function and hunting in the injected process for some PE injected, or on the first WriteProcessMemory when the injector tries to write the PE headers. If it is found, Ichigo searches for the injected PE in the injector's memory and dumps it to the disk.

Remember that the ResumeThread function's sections are fixed and realigned and will be greater than the real one. The WriteProcessMemory will have the exact PE file.

## Usage

Shinigami is easy to use. Simply run shinigami.exe with the executable you want to analyze as the first argument, followed by any arguments you want to pass to it.

Example usage: shinigami.exe calc.exe

The detected implant will be dumped to a file named dumped_file.bin in the same directory as the Shinigami executable.
License

## Development Setup

- Install Visual Studio with the C++ workload.
- Install vcpkg, a package manager for C++ libraries.
- Use vcpkg to install the Zydis library by running the following command: vcpkg install zydis:x64-windows.
- Open the Shinigami.sln solution file in Visual Studio and build the project.


# Contributions

Contributions are welcome! Please open an issue or pull request for any changes you would like to make.
Contact
