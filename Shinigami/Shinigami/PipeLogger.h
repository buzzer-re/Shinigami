#pragma once

#include <windows.h>
#include <iostream>

#define MAX_MESSAGE_SIZE 1024
#define PIPE_NAME L"\\\\.\\pipe\\PipeLogger"

enum Messages
{
	INFO_LOG,
	USER_LOG,
	ERROR_LOG,
	INPUT_LOG,
	LOG_SUCCESS,
	EXITING
};


struct LogMsg
{
	BYTE MessageType;
	wchar_t message[MAX_MESSAGE_SIZE];
};


namespace PipeLogger
{
	static HANDLE hPipe;
	static HANDLE hThread;
	static wchar_t* PipeName;

	BOOL InitPipe();
	VOID LoggerThread(ULONG_PTR* params);
	VOID ClosePipe();
};


namespace Logger
{
	VOID LogInfo(const wchar_t* message, ...);
}