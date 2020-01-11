/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <windows.h>
#include <iostream>
#include <string>
#include "../libipc/client.h"
#include "../libipc/certutil.h"
#include "../libcommonutil/commonutil.h"

using namespace std;

int wmain(int argc, const wchar_t *argv[])
{
    if (argc < 2)
        return 0;

    wstring result;

    wstring err;

    if (argc == 2 && !lstrcmp(argv[1], L"-V")) {
        wstring prodname, prodver, copyright;
        if (GetProductVersionInfo(prodname, prodver, copyright)) {
            wcerr << prodname + L" " + prodver + L" " + copyright << endl;
        } else {
            wcerr << wstring(argv[0]) + L" error getting version" << endl;
        }
        return 1;
    }

    const WCHAR* args = GetCommandLine();
    
    if (auto ret = SendArgsToRunningInstance(args, result, err)) {
        if (err.length() > 0)
            wcerr << err << endl;
        else
            wcerr << L"cppcryptfsctl: Unable to send command." << endl;
        return ret;
    }

    if (result.length() >= CMD_PIPE_RESPONSE_LENGTH) {
        if (wcsncmp(result.c_str(), CMD_PIPE_SUCCESS_STR, CMD_PIPE_RESPONSE_LENGTH) == 0) {
            wcout << wstring(result.c_str() + CMD_PIPE_RESPONSE_LENGTH);
            return 0;
        } else {
            wcerr << wstring(result.c_str() + CMD_PIPE_RESPONSE_LENGTH);
            return 1;
        }
    } else {
        wcerr << "cppcryptfsctl: got a mal-formed response from cppcryptfs\n";
        return 1;
    }
}

