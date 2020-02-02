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

#pragma once
#include "dokan/dokan.h"

#include <string>

#include "context/cryptcontext.h"

using namespace std;


// The FileNameEnc class has a contstructor that takes the necessary inputs
// for doing the filename encryption.  It saves them for later, at almost zero cost.
//
// If the encrypted filename is actually needed, then the instance of FileNameEnc
// is passed to one of various functions that take a const WCHAR * for the encrypted path
// (and possibly an actual_encrypted parameter).
//
// When the overloaded cast to const WCHAR * is performed, the filename will be encrypted, and
// the actual_encrypted data (if any) will be retrieved.
//
// A note on actual_encrypted:
//
// When creating a new file or directory, if a file or directory with a long name is being created,
// then the actual encrypted name must be written to the special gocryptfs.longname.XXXXX.name file.
// actual_encrypted will contain this data in that case.
//

class FileNameEnc {
private:
	PDOKAN_FILE_INFO m_dokan_file_info;
	wstring m_enc_path;
	wstring m_correct_case_path;
	string *m_actual_encrypted;
	wstring m_plain_path;
	CryptContext *m_con;
	KeyDecryptor m_KeyDecryptor;
	bool m_tried;
	bool m_failed;
	bool m_file_existed; // valid only if case cache is used
	bool m_force_case_cache_notfound;

public:
	LPCWSTR CorrectCasePath() {
		if (m_con->IsCaseInsensitive()) {
			Convert();
			return m_correct_case_path.c_str();
		} else {
			return m_plain_path.c_str();
		}
	};

	bool FileExisted() {
		_ASSERT(m_con->IsCaseInsensitive());
		Convert();
		return m_file_existed;
	};

	operator const WCHAR *() { return Convert(); };

private:
	const WCHAR *Convert();
	void AssignPlainPath(LPCWSTR plain_path);

public:
	FileNameEnc() = delete;
	FileNameEnc(PDOKAN_FILE_INFO DokanFileInfo, const WCHAR *fname,
		string *actual_encrypted = NULL,
		bool ignorecasecache = false);
	virtual ~FileNameEnc();
};
