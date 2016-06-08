#pragma once

#include <windows.h>
#include <vector>

#include "util.h"
#include "cryptdefs.h"
#include "crypt.h"
#include "cryptconfig.h"
#include "cryptcontext.h"
#include "eme.h"


#define LONGNAME_PREFIX_W L"gocryptfs.longname."
#define LONGNAME_SUFFIX_W L".name"

#define LONGNAME_PREFIX_A "gocryptfs.longname."
#define LONGNAME_SUFFIX_A ".name"

#define LONGNAME_PREFIX_LEN 19
#define LONGNAME_SUFFIX_LEN 5

bool is_long_name(const WCHAR *filename);

bool is_long_name_file(const WCHAR *filename);

const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const WCHAR *path, const WCHAR *filename, std::wstring& storage);

const char * // returns base64-encoded, encrypted filename
encrypt_filename(CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, std::string& storage, void *context, std::string *actual_encrypted = NULL);

const WCHAR * // returns base64-encoded, encrypted filename
encrypt_filename(CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, std::wstring& storage, void *context, std::string *actual_encrypted = NULL);

const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const WCHAR* path, const char *filename, std::wstring& storage);

const WCHAR * // get encrypted path
encrypt_path(CryptContext *con, const WCHAR *path, std::wstring& storage, std::string *actual_encrypted = NULL);

bool write_encrypted_long_name(const WCHAR *filePath, const std::string& enc_data);