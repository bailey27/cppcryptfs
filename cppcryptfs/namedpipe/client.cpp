#include <windows.h>
#include <string>
#include "client.h"
#include "server.h"

bool SendArgsToRunningInstance(LPCWSTR args, std::wstring& result)
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

	if (hPipe == INVALID_HANDLE_VALUE) {
		DWORD lastErr = GetLastError();
		return false;
	}
		

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

	DWORD cbRead = 0;

	const size_t read_buf_size = 10 * 1024 * 1024;

	TCHAR* readBuf = new WCHAR[read_buf_size];

	*readBuf = 0;

	fSuccess = TransactNamedPipe(
		hPipe,                  // pipe handle 
		(LPVOID)args,                   // message 
		static_cast<DWORD>(cbToWrite),              // message length 
		readBuf, 
		read_buf_size*sizeof(WCHAR),
		&cbRead,             // bytes written 
		NULL);                  // not overlapped 

	CloseHandle(hPipe);

	if (!fSuccess) {	
		delete[] readBuf;
		return false;
	}

	if (cbRead > 0) {
		result = readBuf;
	}
	
	delete[] readBuf;

	return true;
}