#include "pch.h"

#include <string>
#include <vector>
#include "client.h"
#include "certutil.h"
#include "../libcppcryptfs/util/LockZeroBuffer.h"

using namespace std;

wstring GetWindowsErrorStr(DWORD dwLastErr);

static wstring FormatErr(const WCHAR *basemes, DWORD lastErr)
{
	return wstring(basemes) + L" lastErr = " + to_wstring(lastErr) + L" " + GetWindowsErrorStr(lastErr);
}

int SendArgsToRunningInstance(LPCWSTR args, std::wstring& result, std::wstring& err)
{
	HANDLE hPipe;

	auto args_len = wcslen(args);

	if (args_len < 1)
		return SEND_ARGS_STATUS_SUCCESS;

	static_assert(CMD_PIPE_MAX_ARGS_LEN_USER < CMD_PIPE_MAX_ARGS_LEN, "problem with CMD_PIPE_MAX_ARGS_LEN_USER");

	if (args_len > CMD_PIPE_MAX_ARGS_LEN_USER) {
		err = L"command to long.  max length is " + to_wstring(CMD_PIPE_MAX_ARGS_LEN_USER) + L" characters.";
		return SEND_ARGS_STATUS_ERROR;
	}

	LockZeroBuffer<WCHAR> buf(static_cast<DWORD>(args_len + CMD_PIPE_VERSION_LEN + 1));

	if (!buf.IsLocked()) {
		err = L"cannot lock command buffer.";
		return SEND_ARGS_STATUS_ERROR;
	}

	memcpy(buf.m_buf, CMD_PIPE_VERSION_STR, CMD_PIPE_VERSION_LEN * sizeof(WCHAR));

	memcpy(buf.m_buf + CMD_PIPE_VERSION_LEN, args, (args_len + 1) * sizeof(WCHAR));
	
	while (true) {
		hPipe = CreateFile(
			CMD_NAMED_PIPE,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// break if we have a pipe
		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		// return false if an error other than ERROR_PIPE_BUSY occurs. 
		if (GetLastError() != ERROR_PIPE_BUSY) {
			DWORD lastErr = GetLastError();
			err = FormatErr(L"Unable to open pipe.", lastErr);
			if (lastErr == ERROR_FILE_NOT_FOUND) {
				err += L" Is cppcryptfs already running?";
				return SEND_ARGS_STATUS_CANNOT_CONNECT;
			} else {
				return SEND_ARGS_STATUS_ERROR;
			}
		}

		// All pipe instances are busy, so wait for 2 seconds. 
		if (!WaitNamedPipe(CMD_NAMED_PIPE, 2000)) {
			err = L"Named pipe connection timed out.";
			return SEND_ARGS_STATUS_ERROR;
		}
	}

	ULONG server_process_id;

	if (!GetNamedPipeServerProcessId(hPipe, &server_process_id)) {
		err = L"Unable to get process id of already running cppcryptfs.";
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}

	if (!ValidateNamedPipeConnection(server_process_id)) {
		err = L"Unable to validate signature of already running cppcryptfs.";
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}
	
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	auto fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess) {
		err = FormatErr(L"Unable to set state of named pipe.", GetLastError());
		CloseHandle(hPipe);
		return SEND_ARGS_STATUS_ERROR;
	}

	// Send a message to the pipe server. 

	auto cbToWrite = buf.m_len*sizeof(buf.m_buf[0]);

	DWORD cbRead = 0;

	result.clear();

	const size_t read_buf_size = 64*1024; // must be multiple of 2 bytes

	vector<BYTE> read_buf(read_buf_size); 

	// this lamba handles appending data to result
	// it returns SEND_ARGS_STATUS_SUCCESS on success
	// on error it sets err and closes the pipe handle and returns an error value
	auto append_data = [&]() -> int {

		if (!fSuccess && (GetLastError() != ERROR_MORE_DATA)) {
			err = FormatErr(L"TransactNamedPipe failed.", GetLastError());
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		// we expect to read whole WCHARS
		if ((cbRead % sizeof(result[0])) != 0) {
			err = L"malformed response (not integral number of WCHARs) from already running cppcryptfs.";
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		auto chars_read = cbRead / sizeof(result[0]);

		const WCHAR* pRead = reinterpret_cast<WCHAR*>(&read_buf[0]);

		if (fSuccess && (chars_read == 0 || pRead[chars_read - 1] != L'\0')) {
			err = L"malformed response (not null-terminated) from already running cppcryptfs.";
			result.clear();
			CloseHandle(hPipe);
			return SEND_ARGS_STATUS_ERROR;
		}

		result += fSuccess ? pRead : wstring(pRead, chars_read);

		return SEND_ARGS_STATUS_SUCCESS;
	};

	int ret;

	fSuccess = TransactNamedPipe(
		hPipe,                          // pipe handle 
		(LPVOID)buf.m_buf,                   // message 
		static_cast<DWORD>(cbToWrite),  // message length 
		&read_buf[0], 
		static_cast<DWORD>(read_buf.size()),
		&cbRead,                        // bytes written 
		NULL);                          // not overlapped 

	if ((ret = append_data()) != SEND_ARGS_STATUS_SUCCESS)
		return ret;

	while (!fSuccess) {
		// Read from the pipe if there is more data in the message.
		fSuccess = ReadFile(
			hPipe,         // pipe handle 
			&read_buf[0],  // buffer to receive reply 
			static_cast<DWORD>(read_buf.size()),  // size of buffer 
			&cbRead,       // number of bytes read 
			NULL);         // not overlapped 

		if ((ret = append_data()) != SEND_ARGS_STATUS_SUCCESS)
			return ret;
	}

	CloseHandle(hPipe);

	return SEND_ARGS_STATUS_SUCCESS;
}

// we have the same code in util, but were having linkage issues
// linking cppcryptfsctl with util, so instead of making another
// util library the code was copy and pasted here and the name
// was changed from GetWindowsErrorStr to GetWindowsErrorStr
// if we need more stuff from util then we'll consider breaking
// out the really simple stuff from the stuff that depends
// on openssl, for example

// ALSO: we eat the trailing newline here
static wstring GetWindowsErrorStr(DWORD dwLastErr)
{
	wstring mes;

	if (dwLastErr == 0) {
		mes += L"unknown windows error 0";
		return mes;
	}

	LPTSTR errorText = NULL;

	if (!::FormatMessageW(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		dwLastErr,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL)) {   // arguments - see note 

		mes += L"unable to get message for error " + to_wstring(dwLastErr);

		if (errorText) {
			LocalFree(errorText);
		}

		return mes;
	}

	if (errorText) {
		// ... do something with the string `errorText` - log it, display it to the user, etc.
		mes += errorText;
		// release memory allocated by FormatMessage()
		LocalFree(errorText);
		errorText = NULL;
	} else {
		mes += L"got null message for error " + to_wstring(dwLastErr);
	}

	// eat trailing newline chars
	while (mes.length() && (mes.back() == '\n' || mes.back() == '\r')) {
		mes.pop_back();
	}

	return mes;
}