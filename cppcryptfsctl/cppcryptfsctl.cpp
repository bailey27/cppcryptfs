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
#include "../libcppcryptfs/config/cryptconfig.h"
#include "../libcppcryptfs/util/getopt.h"
#include "../libcppcryptfs/util/util.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

const wchar_t* init_switch = L"--init";

#define MAX_PASSWORD_LEN 1000

static void show_help()
{
    wcerr << L"Usage: cppcryptfs [OPTIONS]\n";
    wcerr << L"Initializing:\n";
    wcerr << L"  --init=PATH\tInitialize encrypted filesystem located at PATH\n";
    wcerr << L"  --config=FILEPATH\t\tsepcify path to config file\n";
    wcerr << L"  --volumename=NAME\t\tsepcify volume name for filesystem\n";
    wcerr << L"  --plaintext\t\tuse plaintext filenames (otherwise AES256-EME will be used)\n";    
    wcerr << L"  --siv\t\tuse AES256-SIV for data encryption (otherwise GCM will be used)\n";
    wcerr << L"  --reverse\t\t create reverse-mode filesystem (implies siv)\n";
    wcerr << L"  --longnames [0|1]\t\t enble or disable long file names. defaults to enabled (1)\n";
    wcerr << L"  --streams [0|1]\t\t enble or disable alternate data streams. defaults to enabled (1)\n";
    wcerr << L"  -c, --config=PATH\tpath to config file\n";
    wcerr << L"  -s, --reverse\t\tmount reverse filesystem\n";  
    wcerr << L"  -v, --version\t\tprint version\n";
    wcerr << L"  -h, --help\t\tdisplay this help message\n";   
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

    bool invalid_opt;

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
        {L"init",   required_argument,  0, 'i'},        
        {L"config", required_argument, 0, 'c' },      
        {L"reverse",  no_argument, 0, 's' },
        {L"plaintextnames",  no_argument, 0, 'p' },
        {L"longnames",  required_argument, 0, 'l' },
        {L"streams",  required_argument, 0, 'S'},
        {L"volumename",  required_argument, 0, 'V'},
        {L"siv",  no_argument, 0, 's'},        
        {L"version",  no_argument, 0, 'v' },
        {L"help",  no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };



    while (true) {
        c = getopt_long(argc, argv, L"i:c:spl:S:V:svh", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case '?':
            invalid_opt = true;
            break;
        case 'i':
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
        case 'r':
            reverse = true;
            break;
        case 'p':
            plaintext_names = true;
            break;
        case 'l':
            if (get_binary_flag("longnames", optarg, longnames) != 0)
                return 1;
            break;           
        case 'S':
            if (get_binary_flag("streams", optarg, streams) != 0)
                return 1;
            break;
        case 'V':
            volume_name = optarg;
            break;
        case 's':
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

    if (do_version) {
        wstring prod, ver, copyright;
        GetProductVersionInfo(prod, ver, copyright);
        wcerr << prod << " " << ver << " " << copyright << endl;
    }     

    if (do_help || (!do_init && !do_version)) {       
        show_help();
        return 1;
    }

    wchar_t password[1024];
    wchar_t password2[1024];

    
    wstring mes;

    if (do_init) {

        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

        if (!hStdin) {
            wcerr << L"cannot get handle to std input\n";
            return 1;
        }

        DWORD mode;
        if (!GetConsoleMode(hStdin, &mode)) {
            // we have stdin redirected, so just read password from stdin
            wstring pwd;
            getline(wcin, pwd);
            if (pwd.length() > MAX_PASSWORD_LEN) {
                wcerr << L"max password length is 1000" << endl;
                return 1;
            }
            wcscpy_s(password, pwd.c_str());
        } else {
            if (!read_password(password, _countof(password), L"password:")) {
                wcerr << L"error reading password" << endl;
                    return 1;
            }

            if (wcslen(password) > MAX_PASSWORD_LEN) {
                wcerr << L"max password length is 1000" << endl;
                return 1;
            }

            if (!read_password(password2, _countof(password), L"repeat:")) {
                wcerr << L"error reading repeate password" << endl;
                    return 1;
            }

            if (wcscmp(password, password2)) {
                wcerr << L"passwords do not match" << endl;
                return 1;
            }

        }
    
        bool result = config.create(fs_path.c_str(), config_path.c_str(), password, !plaintext_names, plaintext_names, longnames, siv, reverse, volume_name.c_str(), !streams, mes);
        if (!result) {
            wcerr << mes << endl;
            return 1;
        }
    }

    return 0;
}

int letmego = 1;

int wmain(int argc, wchar_t * const argv[])
{
    if (argc < 2)
        return 0;

    while (!letmego)
        Sleep(1);

    // if we are initializing a filesystem then we handle it in cppcryptfsctl instead
    // of passing command line to cppcryptfs
    for (int i = 1; i < argc; ++i) {
        if (wcsncmp(argv[i], init_switch, wcslen(init_switch)) == 0) {
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

