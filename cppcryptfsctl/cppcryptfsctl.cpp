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
#include <Shlwapi.h>
#include <iostream>
#include <io.h>
#include <string>
#include "../libipc/client.h"
#include "../libipc/certutil.h"
#include "../libcommonutil/commonutil.h"
#include "../libcppcryptfs/config/cryptconfig.h"
#include "../libcppcryptfs/util/getopt.h"
#include "../libcppcryptfs/util/util.h"
#include "../libcppcryptfs/util/fileutil.h"
#include "../libcppcryptfs/crypt/cryptdefs.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;


#define PASSWORD_BUFLEN (MAX_PASSWORD_LEN+5)

static void show_help()
{
    wcerr << get_command_line_usage();
}


static int get_binary_flag(const char *option, const wchar_t* s, bool& f)
{

    if (wcscmp(s, L"0") == 0 || wcscmp(s, L"1") == 0) {
        f = *s == L'1';
        return 0;
    } else {
        wcerr << L"argument must be 0 or 1 for option " << option << endl;
        return -1;
    }
        
}
static int do_init(int argc, wchar_t* const argv[])
{    
    CryptConfig config;

    // need to intialize these getop variables before we process a command line
    getopt_init();

    int c;
    int option_index = 0;

    bool invalid_opt = false;

    bool reverse = false;

    bool plaintext_names = false;

    bool longnames = true;

    bool streams = true;

    bool do_init = false;

    bool siv = false;

    bool do_version = false;

    bool do_help = false;

    wstring fs_path;
    wstring config_path;
    wstring volume_name;

    static struct option long_options[] =
    {
        {L"init",   required_argument,  0, 'I'},        
        {L"config", required_argument, 0, 'c' },      
        {L"reverse",  no_argument, 0, 's' },
        {L"plaintextnames",  no_argument, 0, 'T' },
        {L"longnames",  required_argument, 0, 'L' },
        {L"streams",  required_argument, 0, 'b'},
        {L"volumename",  required_argument, 0, 'V'},
        {L"siv",  no_argument, 0, 'S'},        
        {L"version",  no_argument, 0, 'v' },
        {L"help",  no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };



    while (true) {
        c = getopt_long(argc, argv, L"I:c:sTL:b:V:Svh", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case '?':
            invalid_opt = true;
            break;
        case 'I':
            if (wcscmp(optarg, L"-v") == 0) {
                do_version = true;
            } else if (wcscmp(optarg, L"-h") == 0) {
                do_help = true;
            } else {
                do_init = true;
                fs_path = optarg;
            }
            break;
        case 'c':
            config_path = optarg;
            break;
        case 's':
            reverse = true;
            break;
        case 'T':
            plaintext_names = true;
            break;
        case 'L':
            if (get_binary_flag("longnames", optarg, longnames) != 0)
                return 1;
            break;           
        case 'b':
            if (get_binary_flag("streams", optarg, streams) != 0)
                return 1;
            break;
        case 'V':
            volume_name = optarg;
            break;
        case 'S':
            siv = true;
            break;
        case 'v':
            do_version = true;
            break;
        case 'h':
            do_help = true;
            break;      
        }
    }

    if (invalid_opt && !do_help) {
        wcerr << L"Invalid option. Try 'cppcryptfsctl --help' for more information." << endl;
        return 1;
    }

    if (do_version) {
        wstring prod, ver, copyright;
        GetProductVersionInfo(prod, ver, copyright);
        wcerr << prod << " " << ver << " " << copyright << endl;
    }     

    if (do_help || (!do_init && !do_version)) {       
        show_help();
        return 1;
    }
 
    wstring mes;

    if (do_init) {

        LockZeroBuffer<wchar_t> password(PASSWORD_BUFLEN, false);
        LockZeroBuffer<wchar_t> password2(PASSWORD_BUFLEN, false);

        if (!password.IsLocked()) {
            wcerr << L"unable to lock password buffer\n";
            return 1;
        }

        if (!::PathFileExists(fs_path.c_str())) {
            wcerr << L"the path to the file system does not exist." << endl;
            return 1;
        }

        if (!reverse && !can_delete_directory(fs_path.c_str())) {
            wcerr << L"the file system directory is not empty." << endl;
            return 1;
        }               

        wcout << L"Choose a password for protecting your files." << endl;

        if (_isatty(_fileno(stdin))) {

            LockZeroBuffer<wchar_t> password2(PASSWORD_BUFLEN, false);

            if (!password2.IsLocked()) {
                wcerr << L"unable to lock repeat password buffer\n";
                return 1;
            }            

            // prompt for password
            if (!read_password(password.m_buf, password.m_len, L"Password:")) {
                wcerr << L"error reading password" << endl;
                    return 1;
            }
            // prompt for repeat password
            if (!read_password(password2.m_buf, password2.m_len, L"Repeat:")) {
                wcerr << L"error reading repeat password" << endl;
                    return 1;
            }
            if (wcscmp(password.m_buf, password2.m_buf) != 0) {
                wcerr << L"passwords do not match" << endl;
                return 1;
            }
        } else {
            // we have stdin redirected, so read password from stdin         
            wcout << L"Reading password from stdin" << endl;
            if (!fgetws(password.m_buf, password.m_len, stdin)) {
                wcerr << "unable to read password from stdin\n";
                return 1;
            }
            if (wcslen(password.m_buf) > 0 && password.m_buf[wcslen(password.m_buf) - 1] == L'\n') {
                password.m_buf[wcslen(password.m_buf) - 1] = L'\0';
            }
        }

        if (wcslen(password.m_buf) < 1) {
            wcerr << L"password cannot be empty" << endl;
        }

        if (wcslen(password.m_buf) > MAX_PASSWORD_LEN) {
            wcerr << L"password too long.  max length is " << MAX_PASSWORD_LEN << endl;
        }        
    
        bool result = config.create(fs_path.c_str(), config_path.c_str(), password.m_buf, !plaintext_names, plaintext_names, longnames, reverse || siv, reverse, volume_name.c_str(), !streams, mes);

        if (!result) {
            wcerr << mes << endl;
            return 1;
        } else {
            wcout << L"The gocryptfs" << (reverse ? L"-reverse" : L"") <<  L" filesystem has been created successfully." << endl;
        }
    }

    return 0;
}

int wmain(int argc, wchar_t * const argv[])
{
    if (argc < 2)
        return 0;

    const wchar_t* init_switch_long = L"--init";
    const wchar_t* init_switch_short = L"-I";

    // if we are initializing a filesystem then we handle it in cppcryptfsctl instead
    // of passing command line to cppcryptfs
    for (int i = 1; i < argc; ++i) {
        if (wcsncmp(argv[i], init_switch_long, wcslen(init_switch_long)) == 0 || 
            wcsncmp(argv[i], init_switch_short, wcslen(init_switch_short)) == 0) {
            return do_init(argc, argv);
        }
    }

    wstring result;

    wstring err;

    if (argc == 2 && !lstrcmp(argv[1], L"-V")) {
        wstring prodname, prodver, copyright;
        if (GetProductVersionInfo(prodname, prodver, copyright)) {
            const wchar_t* bits = sizeof(void*) == 8 ? L" 64-bit " : L" 32-bit ";
            wcerr << prodname + L" " + prodver + bits + copyright << endl;
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

