#pragma once
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2018 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "dokan/dokan.h"
#include "context/cryptcontext.h"
#include "cryptdokanpriv.h"
#include "CryptThreadData.h"


class MountPointManager {

private:
	unordered_map<wstring, CryptThreadData*> m_tdatas;
	MountPointManager() {}
public:
	// disallow copying
	MountPointManager(MountPointManager const&) = delete;
	void operator=(MountPointManager const&) = delete;

	virtual ~MountPointManager();

	static MountPointManager* getInstance() {
		static MountPointManager instance;

		return &instance;
	}

	// MountPointManager becomes owner of tdata
	bool add(const wchar_t *mountpoint, CryptThreadData* tdata);

	CryptThreadData *get(const wchar_t *mountpoint);

	bool destroy(const wchar_t *mountpoint);

	BOOL wait_and_destroy(const WCHAR* mountpoint);
private:
	BOOL wait_multiple_and_destroy(int count, HANDLE handles[], wstring mountpoints[]);
	
public:
	BOOL wait_all_and_destroy();

	friend BOOL list_files(const WCHAR *path, list<FindDataPair> &findDatas,
		wstring &err_mes);
};

