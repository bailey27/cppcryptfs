/*
 * getopt - POSIX like getopt for Windows console Application
 *
 * win-c - Windows Console Library
 * Copyright (c) 2015 Koji Takami
 * Released under the MIT license
 * https://github.com/takamin/win-c/blob/master/LICENSE
 */
#include <stdio.h>
#include <string.h>
#include "getopt.h"

wchar_t* optarg = 0;
int optind = 1;
int opterr = 1;
int optopt = 0;

int postpone_count = 0;
int nextchar = 0;

static void postpone(int argc, wchar_t* const argv[], int index) {
    wchar_t** nc_argv = (wchar_t**)argv;
    wchar_t* p = nc_argv[index];
    int j = index;
    for(; j < argc - 1; j++) {
        nc_argv[j] = nc_argv[j + 1];
    }
    nc_argv[argc - 1] = p;
}
static int postpone_noopt(int argc, wchar_t* const argv[], int index) {
    int i = index;
    for(; i < argc; i++) {
        if(*(argv[i]) == '-') {
            postpone(argc, argv, index);
            return 1;
        }
    }
    return 0;
}
static int _getopt_(int argc, wchar_t* const argv[],
        const wchar_t* optstring,
        const struct option* longopts, int* longindex)
{
    while(1) {
        int c;
        const wchar_t* optptr = 0;
        if(optind >= argc - postpone_count) {
            c = 0;
            optarg = 0;
            break;
        }
        c = *(argv[optind] + nextchar);
        if(c == '\0') {
            nextchar = 0;
            ++optind;
            continue;
        }
        if(nextchar == 0) {
            if(optstring[0] != '+' && optstring[0] != '-') {
                while(c != '-') {
                    /* postpone non-opt parameter */
                    if(!postpone_noopt(argc, argv, optind)) {
                        break; /* all args are non-opt param */
                    }
                    ++postpone_count;
                    c = *argv[optind];
                }
            }
            if(c != '-') {
                if(optstring[0] == '-') {
                    optarg = argv[optind];
                    nextchar = 0;
                    ++optind;
                    return 1;
                }
                break;
            } else {
                if(wcscmp(argv[optind], L"--") == 0) {
                    optind++;
                    break;
                }
                ++nextchar;
                if(longopts != 0 && *(argv[optind] + 1) == '-') {
                    wchar_t const* spec_long = argv[optind] + 2;
                    wchar_t const* pos_eq = wcschr(spec_long, '=');
                    long long spec_len = (pos_eq == NULL ? wcslen(spec_long) : pos_eq - spec_long);
                    int index_search = 0;
                    int index_found = -1;
                    const struct option* optdef = 0;
                    while(longopts->name != 0) {
                        if(wcsncmp(spec_long, longopts->name, spec_len) == 0) {
                            if(optdef != 0) {
                                if(opterr) {
                                    fwprintf(stderr, L"ambiguous option: %s\n", spec_long);
                                }
                                return '?';
                            }
                            optdef = longopts;
                            index_found = index_search;
                        }
                        longopts++;
                        index_search++;
                    }
                    if(optdef == 0) {
                        if(opterr) {
                            fwprintf(stderr, L"no such a option: %s\n", spec_long);
                        }
                        return '?';
                    }
                    switch(optdef->has_arg) {
                        case no_argument:
                            optarg = 0;
                            if(pos_eq != 0) {
                                if(opterr) {
                                    fwprintf(stderr, L"no argument for %s\n", optdef->name);
                                }
                                return '?';
                            }
                            break;
                        case required_argument:
                            if(pos_eq == NULL) {
                                ++optind;
                                optarg = argv[optind];
                            } else {
                                optarg = (wchar_t*)pos_eq + 1;
                            }
                            break;
                    }
                    ++optind;
                    nextchar = 0;
                    if(longindex != 0) {
                        *longindex = index_found;
                    }
                    if(optdef->flag != 0) {
                        *optdef->flag = optdef->val;
                        return 0;
                    }
                    return optdef->val;
                }
                continue;
            }
        }
        optptr = wcschr(optstring, c);
        if(optptr == NULL) {
            optopt = c;
            if(opterr) {
                fwprintf(stderr,
                        L"%s: invalid option -- %c\n",
                        argv[0], c);
            }
            ++nextchar;
            return '?';
        }
        if(*(optptr+1) != ':') {
            nextchar++;
            if(*(argv[optind] + nextchar) == '\0') {
                ++optind;
                nextchar = 0;
            }
            optarg = 0;
        } else {
            nextchar++;
            if(*(argv[optind] + nextchar) != '\0') {
                optarg = argv[optind] + nextchar;
            } else {
                ++optind;
                if(optind < argc - postpone_count) {
                    optarg = argv[optind];
                } else {
                    optopt = c;
                    if(opterr) {
                        fwprintf(stderr,
                            L"%s: option requires an argument -- %c\n",
                            argv[0], c);
                    }
                    if(optstring[0] == ':' ||
                        (optstring[0] == '-' || optstring[0] == '+') &&
                        optstring[1] == ':')
                    {
                        c = ':';
                    } else {
                        c = '?';
                    }
                }
            }
            ++optind;
            nextchar = 0;
        }
        return c;
    }

    /* end of option analysis */

    /* fix the order of non-opt params to original */
    while((argc - optind - postpone_count) > 0) {
        postpone(argc, argv, optind);
        ++postpone_count;
    }

    nextchar = 0;
    postpone_count = 0;
    return -1;
}

int getopt(int argc, wchar_t* const argv[],
            const wchar_t* optstring)
{
    return _getopt_(argc, argv, optstring, 0, 0);
}
int getopt_long(int argc, wchar_t* const argv[],
        const wchar_t* optstring,
        const struct option* longopts, int* longindex)
{
    return _getopt_(argc, argv, optstring, longopts, longindex);
}
/********************************************************
int getopt_long_only(int argc, wchar_t* const argv[],
        const wchar_t* optstring,
        const struct option* longopts, int* longindex)
{
    return -1;
}
********************************************************/
