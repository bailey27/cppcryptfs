#include "stdafx.h"
#include "client.h"
#include "server.h"

bool SendArgsToRunningInstance(LPCWSTR args)
{
	auto hPipe = CreateFile(
		CMD_NAMED_PIPE,   // pipe name 
		GENERIC_READ |  // read and write access 
		GENERIC_WRITE,
		0,              // no sharing 
		NULL,           // default security attributes
		OPEN_EXISTING,  // opens existing pipe 
		0,              // default attributes 
		NULL);          // no template file 

	if (hPipe == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwMode = PIPE_READMODE_MESSAGE;
	auto fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess) {
		return false;
	}

	// Send a message to the pipe server. 

	auto cbToWrite = (lstrlen(args) + 1) * sizeof(TCHAR);

	DWORD cbWritten = 0;
	fSuccess = WriteFile(
		hPipe,                  // pipe handle 
		args,                   // message 
		static_cast<DWORD>(cbToWrite),              // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped 

	CloseHandle(hPipe);

	if (!fSuccess || cbWritten != cbToWrite) {
		return false;
	}
	return true;
}