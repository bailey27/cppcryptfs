// cppcryptfsctl.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <iostream>
#include <string>
#include "../libipc/client.h"

using namespace std;

int wmain(int argc, const wchar_t *argv[])
{
    if (argc < 2)
        return 0;

    wstring result;
    
    if (!SendArgsToRunningInstance(GetCommandLine(), result)) {
        wcerr << L"cppcryptfsctl: Unable to send command. Is cppcryptfs running?\n";
        return 1;
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

