#include "pch.h"
#include "Logger.h"


using namespace PipeLogger;

BOOL 
PipeLogger::InitPipe()
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
PipeLogger::LogInfo(const wchar_t* message, ...)
{
	/*if (Ichigo::options.quiet)
		return TRUE;
	*/

	LogMsg logMsg;
	logMsg.MessageType = INFO_LOG;
	ZeroMemory(logMsg.message, MAX_MESSAGE_SIZE);
	
	size_t msgLen = wcslen(message);

	va_list args;
	va_start(args, message);

	vswprintf(logMsg.message, MAX_MESSAGE_SIZE, message, args);

	va_end(args);

	return WriteToPipe(logMsg);
}



