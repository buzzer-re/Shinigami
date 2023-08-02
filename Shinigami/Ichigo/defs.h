#pragma once
#include <windows.h>

typedef ULONG_PTR NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#define STATUS_SUCCESS 0

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    HANDLE                  ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StandardInput;
    HANDLE                  StandardOutput;
    HANDLE                  StandardError;
    CURDIR                  CurrentDirectory;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingPositionLeft;
    ULONG                   StartingPositionTop;
    ULONG                   Width;
    ULONG                   Height;
    ULONG                   CharWidth;
    ULONG                   CharHeight;
    ULONG                   ConsoleTextAttributes;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopInfo;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG                   EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[ANYSIZE_ARRAY];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG Reserved : 31;
        };
    };
    HANDLE ParentProcess;
    HANDLE DebugPort;
    HANDLE ExceptionPort;
    LARGE_INTEGER CreateTime;
    SIZE_T CommandLineLength;
    PWCH CommandLine;
    PVOID Environment;
    UNICODE_STRING CurrentDirectory;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImageName;
    ULONG_PTR DlpBase; // Deprecated
    ULONG_PTR DlpSize; // Deprecated
    ULONG_PTR DlpSectionBase; // Deprecated
    ULONG_PTR DlpSectionSize; // Deprecated
    PS_ATTRIBUTE_LIST AttributeList;
    PS_ATTRIBUTE_LIST* AttributeListPtr;
} PS_CREATE_INFO, * PPS_CREATE_INFO;


typedef BOOL(WINAPI* pCreateProcessternalW) (
    HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupinfo,
    LPPROCESS_INFORMATION lpProcessformation,
    PHANDLE hNewToken
);

typedef DWORD (WINAPI* pResumeThread) (
    HANDLE hThread
);

typedef NTSTATUS (WINAPI NtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

typedef NTSTATUS (WINAPI NtAllocateVirtualMemory) (
    HANDLE      ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
);

typedef NTSTATUS (WINAPI NtWriteVirtualMemory) (
    HANDLE    ProcessHandle,
    PVOID     BaseAddress,
    PVOID     Buffer,
    ULONG     NumberOfBytesToWrite,
    PULONG    NumberOfBytesWritten
);

typedef NTSTATUS (WINAPI NtCreateUserProcess)
(
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
);

typedef NTSTATUS (WINAPI NtProtectVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);


typedef LONG (WINAPI mPTOP_LEVEL_EXCEPTION_FILTER)(
    EXCEPTION_POINTERS* ExceptionInfo
);

struct WinAPIPointers {
    NtAllocateVirtualMemory* NtAllocateVirtualMemory;
    NtWriteVirtualMemory* NtWriteVirtualMemory;
    NtCreateUserProcess* NtCreateUserProcess;
    NtResumeThread* NtResumeThread;
    NtProtectVirtualMemory* NtProtectVirtualMemory;
    mPTOP_LEVEL_EXCEPTION_FILTER* PTOP_LEVEL_EXCEPTION_FILTER;
};
