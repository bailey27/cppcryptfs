/*
 * getopt - POSIX like getopt for Windows console Application
 *
 * win-c - Windows Console Library
 * Copyright (c) 2015 Koji Takami
 * Released under the MIT license
 * https://github.com/takamin/win-c/blob/master/LICENSE
 */
 /* modified by Bailey Brown to use wchar_t instead of char */

#ifndef _GETOPT_H_
#define _GETOPT_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    int getopt(int argc, wchar_t* const argv[],
            const wchar_t* optstring);

    extern wchar_t *optarg;
    extern int optind, opterr, optopt;

#define no_argument 0
#define required_argument 1
#define optional_argument 2

    struct option {
        const wchar_t *name;
        int has_arg;
        int* flag;
        int val;
    };

    int getopt_long(int argc, wchar_t* const argv[],
            const wchar_t* optstring,
            const struct option* longopts, int* longindex);
/****************************************************************************
    int getopt_long_only(int argc, wchar_t* const argv[],
            const wchar_t* optstring,
            const struct option* longopts, int* longindex);
****************************************************************************/
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _GETOPT_H_
