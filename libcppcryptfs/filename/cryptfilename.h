/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <windows.h>
#include <vector>

#include "util/util.h"
#include "crypt/cryptdefs.h"
#include "crypt/crypt.h"
#include "config/cryptconfig.h"
#include "context/cryptcontext.h"
#include "crypt/eme.h"


#define LONGNAME_PREFIX_W L"gocryptfs.longname."
#define LONGNAME_SUFFIX_W L".name"

#define LONGNAME_PREFIX_A "gocryptfs.longname."
#define LONGNAME_SUFFIX_A ".name"

#define LONGNAME_PREFIX_LEN 19
#define LONGNAME_SUFFIX_LEN 5

#define SHORT_NAME_MAX 176 // (after utf8 transform)

bool is_long_name(const WCHAR *filename);

bool is_long_name_file(const WCHAR *filename);

bool // used for reverse mode
derive_path_iv(CryptContext *con, const WCHAR *path, unsigned char *iv, const char *type);

const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const BYTE *dir_iv, const WCHAR *path, const WCHAR *filename, wstring& storage);

const WCHAR * // get decrypted path (used only in reverse mode)
decrypt_path(CryptContext *con, const WCHAR *path, wstring& storage);

const WCHAR * // returns base64-encoded, encrypted filename
encrypt_filename(const CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, wstring& storage, string *actual_encrypted = NULL);

const WCHAR * // get encrypted path
encrypt_path(CryptContext *con, const WCHAR *path, wstring& storage, string *actual_encrypted = NULL);

bool write_encrypted_long_name(const WCHAR *filePath, const string& enc_data);

bool
derive_path_iv(CryptContext *con, const WCHAR *path, unsigned char *iv, const char *type);

const WCHAR *
decrypt_reverse_longname(CryptContext *con, LPCWSTR filename, LPCWSTR plain_path, const BYTE *dir_iv, wstring& decrypted_name);

// tests that are true only in reverse mode (rt is forreverse-test)
bool
rt_is_config_file(CryptContext *con, LPCWSTR FileName);

bool
rt_is_reverse_config_file(CryptContext *con, LPCWSTR FIleName);

bool
rt_is_dir_iv_file(CryptContext *con, LPCWSTR FileName);

bool
rt_is_name_file(CryptContext *con, LPCWSTR FileName);

bool
rt_is_virtual_file(CryptContext *con, LPCWSTR FileName);

bool
get_file_directory(LPCWSTR filepath, wstring& dirpath);

bool
get_bare_filename(LPCWSTR filepath, wstring& filename);

bool
get_actual_encrypted(CryptContext *con, LPCWSTR FileName, string& actual_encrypted);

const WCHAR *
remove_longname_suffix(const WCHAR *filepath, wstring& storage);

const WCHAR * // returns base64-encoded, encrypted stream name.  input stream name is expected to start with colon
encrypt_stream_name(const CryptContext *con, const unsigned char *dir_iv, const WCHAR *stream, wstring& storage);

const WCHAR * // returns UNICODE plaintext stream name.  input stream name is expected to start with colon
decrypt_stream_name(CryptContext *con, const BYTE *dir_iv, const WCHAR *stream, wstring& storage);
