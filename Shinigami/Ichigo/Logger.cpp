#include "pch.h"
#include "Logger.h"


using namespace PipeLogger;

BOOL 
PipeLogger::InitPipe(Ichigo::Arguments& Options)
{
	hPipe = CreateFile(
		PIPE_NAME,
		GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	return TRUE;
}


VOID PipeLogger::ClosePipe()
{
	LogMsg msg;
	msg.MessageType = Messages::EXITING;

	WriteToPipe(msg);

	if (hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(hPipe);
}

//
// Write the message into the pipe
//
BOOL
PipeLogger::WriteToPipe(const LogMsg& logMsg)
{
	if (hPipe == INVALID_HANDLE_VALUE) return false;

	DWORD dwWritten, dwRead;
	LogMsg response;

	if (!WriteFile(hPipe, &logMsg, sizeof(logMsg), &dwWritten, NULL)) return false;
	if (!ReadFile(hPipe, &response, sizeof(response), &dwRead, NULL)) return false;


	return response.MessageType == LOG_SUCCESS;
}


BOOL
PipeLogger::Log(const wchar_t* message, ...)
{
	va_list args;
	
	va_start(args, message);
	BOOL status = SendMsg(USER_LOG, message, args);
	va_end(args);

	return status;
}

BOOL 
PipeLogger::LogInfo(const wchar_t* message, ...)
{
	if (Quiet)
		return TRUE;

	va_list args;

	va_start(args, message);
	BOOL status = SendMsg(USER_LOG, message, args);
	va_end(args);

	return status;
}

BOOL
PipeLogger::SendMsg(Messages level, const wchar_t* message, va_list args)
{
	LogMsg logMsg;
	logMsg.MessageType = level;
	ZeroMemory(logMsg.message, MAX_MESSAGE_SIZE);

	size_t msgLen = wcslen(message);


	vswprintf(logMsg.message, MAX_MESSAGE_SIZE, message, args);


	return WriteToPipe(logMsg);


}


