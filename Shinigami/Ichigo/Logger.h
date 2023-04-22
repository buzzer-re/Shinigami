#pragma once
#include <windows.h>
#include <iostream>
#include "Ichigo.h"

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
	static BOOL Quiet;

	VOID BeQuiet(BOOL quiet);
	BOOL InitPipe();

	BOOL Log(const wchar_t* message, ...);
	BOOL LogInfo(const wchar_t* message, ...);
	BOOL SendMsg(Messages level, const wchar_t* message, va_list args);
	BOOL WriteToPipe(const LogMsg& logMsg);
	
	VOID ClosePipe();
};
