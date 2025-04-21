/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2025 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "pch.h"
#include <string>
#include <mutex>

#include "common.h"

#include "../libcppcryptfs/util/util.h"

using namespace std;

const wchar_t* GetNamedPipeName(bool check_env)
{
	static wstring pipe_name;
	static once_flag once;

	call_once(once, [&]() {
		wstring session_decoration;
		if (check_env) {
			wchar_t ses_env[128];
			size_t retlen = 0;
			auto err = _wgetenv_s(&retlen, ses_env, L"CPPCRYPTFS_SESSIONID");
			if (err == 0 && retlen > 0) {
				session_decoration = ses_env;
			}
		}
		if (session_decoration.length() == 0) {
			DWORD sessionid;
			if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionid)) {
				session_decoration = to_wstring(sessionid);
			}
		}		
		pipe_name = CMD_NAMED_PIPE_BASE + wstring(L"_") + session_decoration;		
	});

	return pipe_name.c_str();
}