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


#include "stdafx.h"
#include "openfiles.h"
#include "../util/util.h"


bool CryptOpenFiles::OpenFile(LPCWSTR path, HANDLE h)
{
    wstring ucpath;

	if (!touppercase(path, ucpath)) {
		assert(false);
		return false;
	}

	lock_guard<mutex> lock(m_mutex);

	auto it = m_openfiles.find(ucpath);

	if (it != m_openfiles.end()) {
		it->second->Open(h);
	} else {
		m_openfiles[ucpath] = make_shared<::CryptOpenFile>(h);
	}

	return true;
}

bool CryptOpenFiles::CloseFile(LPCWSTR path, HANDLE h)
{
	wstring ucpath;

	if (!touppercase(path, ucpath)) {
		assert(false);
		return false;
	}

	lock_guard<mutex> lock(m_mutex);

	auto it = m_openfiles.find(ucpath);

	if (it == m_openfiles.end()) {
		return true;
	}

	auto result = it->second->Close(h);
	if (!result) {
		DbgPrint(L"openfiles cannot close handle %llx\n", h);
	}

	if (it->second->Empty())
		m_openfiles.erase(it);

	return true;
}

shared_ptr<CryptOpenFile> CryptOpenFiles::GetOpenFile(LPCWSTR path)
{
	wstring ucpath;

	if (!touppercase(path, ucpath)) {
		return nullptr;
	}

	lock_guard<mutex> lock(m_mutex);

	auto it = m_openfiles.find(ucpath);

	if (it == m_openfiles.end()) {
		return nullptr;
	}

	return it->second;
}
