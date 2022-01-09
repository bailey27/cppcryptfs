/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2022 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#pragma once

#define CMD_NAMED_PIPE_BASE L"\\\\.\\pipe\\cppcryptfs_cmd"

#define CMD_PIPE_VERSION_STR L"CPPCRYPTFS_CMD_PIPE_0001"
#define CMD_PIPE_VERSION_LEN (_countof(CMD_PIPE_VERSION_STR)-1)

#define CMD_PIPE_SUCCESS 0
#define CMD_PIPE_ERROR   1
#define CMD_PIPE_RESPONSE_LENGTH 7
#define CMD_PIPE_SUCCESS_STR L"SUCCESS"
#define CMD_PIPE_ERROR_STR   L"ERROR  " // pad to 7 characters

#define CMD_PIPE_MAX_ARGS_LEN 4096
#define CMD_PIPE_MAX_ARGS_LEN_USER 4000 // show this limit to the user
#define CMD_NAMED_PIPE_BUFSIZE (CMD_PIPE_MAX_ARGS_LEN*sizeof(WCHAR))

const wchar_t* GetNamedPipeName(bool check_env);