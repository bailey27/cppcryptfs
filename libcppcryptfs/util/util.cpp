/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2021 Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "stdafx.h"

#include <stdio.h>

#include "util/util.h"
#include "crypt/cryptdefs.h"
#include "crypt/crypt.h"
#include <openssl/rand.h>

#include <iostream>

#include "crypt/randombytes.h"
#include "context/cryptcontext.h"

#ifdef _WIN32
#include <wincrypt.h>
#include <tlhelp32.h>
#include <atlenc.h>
#include <shellapi.h>
#endif


template<typename T>
T swapBytesVal(T x)
{
	T y;
	char* px = (char*)&x;
	char* py = (char*)&y;
	for (int i = 0; i<sizeof(T); i++)
		py[i] = px[sizeof(T) - 1 - i];
	return y;
}

template<typename T>
T MakeBigEndian(T n)
{

	if (!IsBigEndianMachine()) {
		return swapBytesVal(n);
	} else {
		return n;
	}
}

template unsigned long long MakeBigEndian(unsigned long long);

template<typename T>
T MakeBigEndianNative(T n)
{
	return MakeBigEndian(n);
}

template unsigned short MakeBigEndianNative(unsigned short);

template unsigned long long MakeBigEndianNative(unsigned long long);

BOOL
IsBigEndianMachine()
{
	const unsigned int a = 1;

	const unsigned char *p = (const unsigned char *)&a;

	return !p[0];
}

const char *
unicode_to_utf8(const WCHAR *unicode_str, char *buf, int buflen)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, NULL, 0, NULL, NULL);

	if (len == 0)
		return NULL;

	// len includes space for null char
	if (len > buflen)
		return NULL;

	if (WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, buf, len, NULL, NULL) == 0) {
		return NULL;
	}

	return buf;
}

const char *
unicode_to_utf8(const WCHAR *unicode_str, string& storage)
{

	int len = WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, NULL, 0, NULL, NULL);

	if (len == 0)
		return NULL;

	TempBuffer<char, 4096> utf8(len);

	// len includes space for null char
	char *p_utf8 = utf8.get();

	if (!p_utf8)
		return NULL;

	if (WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, p_utf8, len, NULL, NULL) == 0) {		
		return NULL;
	}

	storage = p_utf8;

	return &storage[0];
}


const WCHAR *
utf8_to_unicode(const char *utf8_str, wstring& storage)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);

	if (len == 0)
		return NULL;

	// len includes space for null char
	TempBuffer<WCHAR, 2048> unicode(len);
	WCHAR* p_unicode = unicode.get();

	if (!p_unicode)
		return NULL;

	if (MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, p_unicode, len) == 0) {		
		return NULL;
	}

	storage = p_unicode;	

	return &storage[0];
}

static const char *
add_base64_padding(const char *str, string& storage)
{
	// storage won't contain padded string if no padding needed

	size_t len = strlen(str);

	if (len % 4 == 0)
		return str;

	size_t npad = 4 - len % 4;

	storage.reserve(len + npad);

	storage = str;

	storage.resize(len + npad, '=');

	return storage.c_str();
}

static const char *
remove_base64_padding(string& str)
{

	while (str.length() > 0 && str[str.length() - 1] == '=')
		str.pop_back();

	return str.c_str();
}

bool
base64_decode(const char *str, vector<unsigned char>& storage, bool urlTransform, bool padding)
{
	if (!urlTransform) {
		_ASSERT(padding);
	}

	string padded_storage;

	if (!padding)
		str = add_base64_padding(str, padded_storage);

	size_t str_len;

	if (!str || (str_len = strlen(str)) < 1)
		return false;
	
	char *p = NULL;
	
	if (urlTransform) {

		p = _strdup(str);

		if (!p)
			return false;
	}

	if (urlTransform) {	

		size_t i;
		for (i = 0; i < str_len; i++) {
			if (p[i] == '-')
				p[i] = '+';
			else if (p[i] == '_')
				p[i] = '/';
		}
	}

	DWORD len = (DWORD)str_len;

	BOOL bResult = FALSE;

	try {

		storage.resize(len);

		// CryptStringToBinary() is supposedly a little faster than ATL Base64Decode()

		bResult = CryptStringToBinaryA(p ? p : str, 0, CRYPT_STRING_BASE64, &storage[0], &len, NULL, NULL);

	} catch (...) {
		bResult = FALSE;
	}

	if (p)
		::free(p);

	if (bResult) {
		storage.resize(len);
		return true;
	} else {
		return false;
	}
}

bool
base64_decode(const WCHAR *str, vector<unsigned char>& storage, bool urlTransform, bool padding)
{

	// profiling shows that the WCHAR versions of the windows
	// base64 conversions just convert to utf8 anyway

	string utf8;

	size_t len = wcslen(str);

	bool error = false;

	try {

		// can do trivial conversion to utf8 because it's a base64 string
		utf8.reserve(len);

		size_t i;

		for (i = 0; i < len; i++) {
			utf8.push_back((char)str[i]);
		}
	} catch (...) {
		error = true;
	}

	if (error)
		return false;

	return base64_decode(&utf8[0], storage, urlTransform, padding);
}


const char *
base64_encode(const BYTE *data, DWORD datalen, string& storage, bool urlTransform, bool padding)
{

	if (!urlTransform) {
		_ASSERT(padding);
	}

	if (!data || datalen < 1)
		return NULL;

	int base64len = (int)datalen*2;

	char *base64str = NULL;

	BOOL bResult = FALSE;

	TempBuffer<char, 4096> base64(base64len + 1);

	if (base64str = base64.get()) {		

		// ATL Base64Encode() is supposedly way faster than CryptBinaryToString()
	
		bResult = Base64Encode(data, (int)datalen, base64str, &base64len, ATL_BASE64_FLAG_NOCRLF);

		// ATL Base64Encode() doesn't null terminate the string
		if (bResult)
			base64str[base64len] = '\0';

	} else {
		bResult = FALSE;
	}
	if (bResult) {

		if (urlTransform) {
			size_t len = strlen(base64str);
			size_t i;
			for (i = 0; i < len; i++) {
				if (base64str[i] == '+')
					base64str[i] = '-';
				else if (base64str[i] == '/')
					base64str[i] = '_';
			}
		}
		storage = base64str;
		
		if (!padding)
			remove_base64_padding(storage);
		return storage.c_str();
	} else {		
		return NULL;
	}
}

const WCHAR *
base64_encode(const BYTE *data, DWORD datalen, wstring& storage, bool urlTransform, bool padding)
{

	// profiling shows that the WCHAR versions of the windows
	// base64 conversion functions just convert from utf8 anyway

	const WCHAR *rs = NULL;

	try {
		string utf8;

		if (base64_encode(data, datalen, utf8, urlTransform, padding)) {

			// can do trivial conversion to unicode because it's a base64 string

			size_t len = utf8.size();

			storage.clear();

			storage.reserve(len);

			size_t i;

			for (i = 0; i < len; i++)
				storage.push_back(utf8[i]);

			rs = &storage[0];

		} else {
			throw (-1);
		}
	} catch (...) {
		rs = NULL;
	}

	return rs;
}

bool read_password(WCHAR *pwbuf, int pwbuflen, const WCHAR *prompt)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	if (!hStdin)
		return false;

	wcerr << (prompt ? prompt : L"Password: ");

	DWORD old_mode = 0;
	if (!GetConsoleMode(hStdin, &old_mode))
		return false;

	if (!SetConsoleMode(hStdin, old_mode & (~ENABLE_ECHO_INPUT)))
		return false;

	DWORD nRead = 0;

	ReadConsole(hStdin, pwbuf, pwbuflen - 1, &nRead, NULL);

	if (nRead >= 2 && pwbuf[nRead - 2] == L'\r' && pwbuf[nRead - 1] == L'\n')
		pwbuf[nRead - 2] = '\0';

	SetConsoleMode(hStdin, old_mode);

	wcerr << L"\n";

	return true;
}


bool
get_sys_random_bytes(unsigned char *buf, DWORD len)
{
	
	HCRYPTPROV hProvider = NULL;

	if (!CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		return false;
	}

	if (!CryptGenRandom(hProvider, len, buf)) {
		CryptReleaseContext(hProvider, 0);
		return false;
	}

	CryptReleaseContext(hProvider, 0);

	return true;

}



bool
get_random_bytes(CryptContext *con, unsigned char *buf, DWORD len)
{
	if (con)
		return con->m_prand_bytes->GetRandomBytes(buf, len);
	else
		return get_sys_random_bytes(buf, len);
}


DWORD 
getppid(DWORD dwPid)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = dwPid;

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	__try{
		if( hSnapshot == INVALID_HANDLE_VALUE ) __leave;

		ZeroMemory( &pe32, sizeof( pe32 ) );
		pe32.dwSize = sizeof( pe32 );
		if( !Process32First( hSnapshot, &pe32 ) ) __leave;

		do{
			if( pe32.th32ProcessID == pid ){
				ppid = pe32.th32ParentProcessID;
				break;
			}
		}while( Process32Next( hSnapshot, &pe32 ) );

	}
	__finally{
		if( hSnapshot != INVALID_HANDLE_VALUE ) CloseHandle( hSnapshot );
	}
	return ppid;
}


bool 
have_args()
{
	int argc = 1;

	LPCWSTR cmdLine = GetCommandLineW();

	LPTSTR *argv = NULL;

	if (cmdLine)
		argv = CommandLineToArgvW(cmdLine, &argc);

	if (argv)
		LocalFree(argv);
	else
		argc = 1;

	return argc > 1;
}

bool 
OpenConsole(DWORD pid)
{
	FreeConsole();

	if (AttachConsole(pid ? pid : ATTACH_PARENT_PROCESS)) {
#pragma warning( push )
#pragma warning(disable : 4996)
		if (!freopen("CONOUT$", "wt", stdout)) {
			FreeConsole();
			return false;
		}
		if (!freopen("CONOUT$", "wt", stderr)) {
			fclose(stdout);
			FreeConsole();
			return false;
		}
#pragma warning( pop )
		return true;
	} else {
		return false;
	}
}

void
CloseConsole()
{
	fclose(stderr);
	fclose(stdout);
	
	FreeConsole();
}

void 
ConsoleErrMesPipe(LPCWSTR err, HANDLE hPipe)
{
	// Send a message to the pipe client. 

	wstring mes = wstring(L"cppcryptfs: ") + err;

	auto cbToWrite = (mes.length() + 1) * sizeof(WCHAR);

	DWORD cbWritten = 0;
	BOOL fSuccess = WriteFile(
		hPipe,                  // pipe handle 
		mes.c_str(),                   // message 
		static_cast<DWORD>(cbToWrite),              // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped 

	CloseHandle(hPipe);
}

bool touppercase(LPCWSTR in, wstring& out)
{

	WCHAR *buf;

	TempBuffer<WCHAR, 2048> tmp(wcslen(in) + 1);

	bool bRet = true;

	if (buf = tmp.get()) {

		size_t len = wcslen(in);		

		wcscpy_s(buf, len+1, in);

		CharUpperBuff(buf, (DWORD)len);

		out = buf;

	} else {
		bRet = false;
	}	

	return bRet;
}

int compare_names(CryptContext *con, LPCWSTR name1, LPCWSTR name2)
{
	if (con->IsCaseInsensitive()) {
		return lstrcmpi(name1, name2);
	} else {
		return wcscmp(name1, name2);
	}
}

template <typename T> bool test_zero_bytes(const BYTE *buf, size_t len)
{
	return *((T *)buf) == 0 && !memcmp(buf, buf + sizeof(T), len - sizeof(T));
}

#define TESTZERO(T) \
	if ((UINT_PTR)buf % sizeof(T) == 0) { \
		return test_zero_bytes<T>(buf, len); \
	}

bool is_all_zeros(const BYTE *buf, size_t len)
{

	if (len <= sizeof(uint64_t)) {
		const BYTE zeros[sizeof(uint64_t)] = { 0 };
		return !memcmp(buf, zeros, len);
	}

	TESTZERO(uint64_t);

	TESTZERO(uint32_t);

	TESTZERO(uint16_t);
	
	return test_zero_bytes<uint8_t>(buf, len);
}



BOOL GetPathHash(LPCWSTR path, wstring& hashstr)
{

	hashstr = L"";

	wstring ucpath;

	if (!touppercase(path, ucpath))
		return FALSE;

	size_t len = ucpath.length();

	while (len > 3) {
		
		if (ucpath[len - 1] == '\\') {
			ucpath.resize(len - 1);
		} else {
			break;
		}
		len = ucpath.length();
	}

	if (len < 1)
		return FALSE;

	path = ucpath.c_str();

	string str;

	if (!unicode_to_utf8(path, str))
		return FALSE;

	BYTE sum[32];

	if (!sha256(str, sum))
		return FALSE;

	int i;

	// use only 128bits of the sha256 to keep registry key length shorter

	for (i = 0; i < 16; i++) {
		WCHAR buf[3];
		swprintf_s(buf, L"%02x", sum[i]);
		hashstr += buf;
	}

	return TRUE;
}

void SetOverlapped(LPOVERLAPPED pOv, LONGLONG offset)
{
	LARGE_INTEGER l;

	l.QuadPart = offset;

	memset(pOv, 0, sizeof(*pOv));

	pOv->Offset = l.LowPart;
	pOv->OffsetHigh = l.HighPart;
}

void IncOverlapped(LPOVERLAPPED pOv, DWORD increment)
{
	LARGE_INTEGER l;

	l.LowPart = pOv->Offset;
	l.HighPart = pOv->OffsetHigh;

	l.QuadPart += increment;

	memset(pOv, 0, sizeof(*pOv));

	pOv->Offset = l.LowPart;
	pOv->OffsetHigh = l.HighPart;
}

const wchar_t* get_command_line_usage()
{
	return

LR"(Usage: cppcryptfs/cppcryptfsctl [OPTIONS]

Mounting:
  -m, --mount=PATH            mount filesystem located at PATH
  -d, --drive=D               mount to drive letter D or empty dir DIR
  -p, --password=PASS         use password PASS
  -P, --saved-password        use saved password
  -r, --readonly              mount read-only
  -c, --config=PATH           path to config file for init/mount
  -s, --reverse               init/mount reverse fs (implies siv for init)
  --deny-other-sessions [1|0] enable/disable deny other sessions from accessing
  --deny-services [1|0]       enable/disable deny services from accessing

Unmounting:
  -u, --unmount=D             unmount drive letter D or dir DIR
  -u, --unmount=all           unmount all drives
  -f, --force                 force unmounting if in use

Misc:
  -t, --tray                  hide in system tray
  -x, --exit                  exit if no drives mounted
  -l, --list                  list avail drive letters and mounted fs 
  -ld:\p, --list=d:\p         list plaintext and encrypted filenames
  -C, --csv                   file list is comma-delimited
  -D, --dir                   file list dirs first and w/ trailing \"\\\"
  -i, --info=D                show information about mounted filesystem
  -v, --version               print ver (use --init -v for cppcryptfsctl ver)
  -h, --help                  display this help message

Initializing (cppcryptfsctl only):
  -I, --init=PATH             Initialize encrypted filesystem located at PATH
  -V, --volumename=NAME       specify volume name for filesystem
  -T, --plaintext             use plaintext filenames (default is AES256-EME)
  -S, --siv                   use AES256-SIV for data encr (default is GCM)
  -L, --longnames [1|0]       enable/disable LFNs. defaults to enabled (1)
  -b, --streams   [1|0]       enable/disable streams. defaults to enabled (1)

Recovery/Maintenance (cppcryptfsctl only):
  --changepassword=PATH       Change password used to protect master key
  --printmasterkey=PATH       Print master key in human-readable format
  --recover=PATH              Prompt for master key and new password to recover
)";
	// --changepassword short form is 1
}


static BOOL s_DebugMode = FALSE;
static BOOL s_UseStdErr = FALSE;
static BOOL s_UseLogFile = FALSE;

static FILE* s_DebugLogFile = NULL;

void SetDbgVars(BOOL DebugMode, BOOL UseStdErr, BOOL UseLogFile, FILE* logfile)
{
	s_DebugMode = DebugMode;
	s_UseStdErr = UseStdErr;
	s_UseLogFile = UseLogFile;
	s_DebugLogFile = logfile;
}

void DbgPrint(LPCWSTR format, ...) {
	if (s_DebugMode) {
		const WCHAR* outputString;
		WCHAR* buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = (WCHAR*)_malloca(length * sizeof(WCHAR));
		if (buffer) {
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		} else {
			outputString = format;
		}
		if (s_UseStdErr) {
			fputws(outputString, stderr);
		} else if (s_UseLogFile && s_DebugLogFile) {
			fputws(outputString, s_DebugLogFile);
			fflush(s_DebugLogFile);
		} else {
			OutputDebugStringW(outputString);
		}
		if (buffer)
			_freea(buffer);
		va_end(argp);
	}
}
#if 1
void DbgPrintAlways(LPCWSTR format, ...) {
	
		const WCHAR* outputString;
		WCHAR* buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = (WCHAR*)_malloca(length * sizeof(WCHAR));
		if (buffer) {
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		} else {
			outputString = format;
		}
		if (s_UseStdErr) {
			fputws(outputString, stderr);
		} else if (s_UseLogFile && s_DebugLogFile) {
			fputws(outputString, s_DebugLogFile);
			fflush(s_DebugLogFile);
		} else {
			OutputDebugStringW(outputString);
		}
		if (buffer)
			_freea(buffer);
		va_end(argp);	
}
#endif


HANDLE OpenTokenForCurrentProcess()
{
	HANDLE handle = NULL;

	// getting errors using the pseudo-handle on some systems.
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	if (!hProc) {
		return NULL;
	}

	const BOOL op_result = OpenProcessToken(hProc, TOKEN_QUERY, &handle);

	CloseHandle(hProc);
	
	return op_result ? handle : NULL;
}

bool GetUserNameFromToken(HANDLE handle, wstring& user, wstring& domain)
{

	UCHAR buffer[1024];
	DWORD returnLength;
	WCHAR accountName[256];
	WCHAR domainName[256];
	DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
	DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
	PTOKEN_USER tokenUser;
	SID_NAME_USE snu;			

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
		&returnLength)) {
		//DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
		return false;
	}

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
		domainName, &domainLength, &snu)) {
		//DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
		return false;
	}

	//DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);

	if (snu != SidTypeUser)
		return false;

	user = accountName;
	domain = domainName;

	DWORD sessionid = 0;

	if (GetTokenInformation(handle, TokenSessionId, &sessionid, sizeof(sessionid), &returnLength)) {
		DbgPrint(L"SessionId = %u\n", sessionid);
	} else {
		DbgPrint(L"failed to get SessionId\n");
	}

	return true;
}

bool GetSessionIdFromToken(HANDLE handle, DWORD &sessionid)
{
	DWORD returnLength;

	if (GetTokenInformation(handle, TokenSessionId, &sessionid, sizeof(sessionid), &returnLength) && 
			returnLength == sizeof(sessionid)) {
		DbgPrint(L"SessionId = %u\n", sessionid);
		return true;
	} else {
		DWORD lastErr = GetLastError();
		DbgPrint(L"failed to get SessionId, LastErr = %u\n", lastErr);
		return false;
	}	
}

bool CanGetSessionIdOk()
{
	DWORD sessionid1 = 0;
	DWORD sessionid2 = 0;

	// using GetCurrentProcessToken() fails on some systems
	HANDLE h = OpenTokenForCurrentProcess();
	if (h == NULL)
		return false;
	const bool got1ok = GetSessionIdFromToken(h, sessionid1);
	CloseHandle(h);
	if (!got1ok)
		return false;

	const bool got2ok = ProcessIdToSessionId(GetCurrentProcessId(), &sessionid2);

	return got2ok && sessionid1 == sessionid2;
}