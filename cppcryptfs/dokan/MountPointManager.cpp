/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2024 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include "dokan/dokan.h"
#include "cryptdokan.h"
#include "cryptdokanpriv.h"
#include "context/cryptcontext.h"
#include "CryptThreadData.h"
#include "MountPointManager.h"
#include <unordered_map>
#include <string>
#include <crtdbg.h>


using namespace std;

MountPointManager::~MountPointManager()
{
	// should have already unmounted and destroyed everything
	// before exiting
	_ASSERT(m_tdatas.empty());
}

// MountPointManager becomes owner of tdata
bool MountPointManager::add(const wchar_t *mountpoint, CryptThreadData* tdata) 
{
	bool res = true;
	try {
		auto res = m_tdatas.emplace(mountpoint, tdata);
		_ASSERT(res.second);  // that it wasn't already there
	} catch (...) {
		delete tdata;
		res = false;
	}
	return res;
}

CryptThreadData *MountPointManager::get(const wchar_t *mountpoint) 
{
	wstring mpstr;
	if (!find(mountpoint, mpstr)) {
		return NULL;
	}
	auto it = m_tdatas.find(mpstr);
	if (it != m_tdatas.end()) {
		return it->second;
	} else {
		return NULL;
	}
}

bool MountPointManager::destroy(const wchar_t *mountpoint) 
{
	wstring mpstr;
	if (!find(mountpoint, mpstr)) {
		return false;
	}
	bool result = true;
	auto it = m_tdatas.find(mpstr);
	if (it != m_tdatas.end()) {
		delete it->second;
		m_tdatas.erase(it);
	} else {
		result = false;
	}
	return result;
}

BOOL MountPointManager::wait_and_destroy(const WCHAR* mountpoint) 
{

	wstring mpstr;

	if (!find(mountpoint, mpstr)) {
		return FALSE;
	}
	auto it = m_tdatas.find(mpstr);

	if (it == m_tdatas.end()) {
		return FALSE;
	}

	BOOL result = TRUE;
	
	DWORD wait_timeout = UNMOUNT_TIMEOUT;
	DWORD status = WaitForSingleObject(it->second->hThread,
		wait_timeout);

	if (status == WAIT_OBJECT_0) {
		result = destroy(mountpoint);
	} else {
		result = FALSE;
	}
	

	return result;
}


bool MountPointManager::unmount_all(bool wait)
{
	for (auto it = m_tdatas.begin(); it != m_tdatas.end(); ++it) {
		wstring wmes;
		if (!unmount_crypt_fs(it->first.c_str(), false, wmes)) {
			return false;
		}
	}
	bool result = true;
	if (wait) {
		result = this->wait_all_and_destroy();
	}
	return result;
}

BOOL MountPointManager::wait_multiple_and_destroy(int count, HANDLE handles[], wstring mountpoints[])
{

	const DWORD timeout = UNMOUNT_TIMEOUT;

	DWORD status = WaitForMultipleObjects(count, handles, TRUE, timeout);

	DWORD first = WAIT_OBJECT_0;
	DWORD last = WAIT_OBJECT_0 + (count - 1);

	if (status >= first && status <= last) {
		for (int i = 0; i < count; i++) {
			destroy(mountpoints[i].c_str());
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL MountPointManager::wait_all_and_destroy() {

	HANDLE handles[MAXIMUM_WAIT_OBJECTS];
	wstring mountpoints[MAXIMUM_WAIT_OBJECTS];

	int count = 0;
	for (auto &it : m_tdatas) {
		mountpoints[count] = it.first;
		handles[count++] = it.second->hThread;
		if (count == MAXIMUM_WAIT_OBJECTS) {
			if (!wait_multiple_and_destroy(count, handles, mountpoints))
				return FALSE;
			count = 0;
		}
	}

	if (count)
		return wait_multiple_and_destroy(count, handles, mountpoints);
	else
		return TRUE;

}

bool MountPointManager::find(const WCHAR * mountpoint, wstring & mpstr) const
{
	auto it = m_tdatas.find(mountpoint); 
	if (it != m_tdatas.end()) {
		mpstr = it->first;
		return true;
	}
	
	for (auto it = m_tdatas.begin(); it != m_tdatas.end(); ++it) {
		if (!lstrcmpi(it->first.c_str(), mountpoint)) {
			mpstr = it->first;
			return true;
		}
	}
	return false;
}

bool MountPointManager::get_path(const WCHAR *mountpoint, wstring& path)  const 
{
	wstring mpstr;
	if (!find(mountpoint, mpstr)) {
		return false;
	}
	auto it = m_tdatas.find(mpstr);
	if (it == m_tdatas.end()) {
		return false;
	}

	path = it->second->con.GetConfig()->m_basedir;

	// get rid of leading \\?\ for display
	if (!wcsncmp(path.c_str(), L"\\\\?\\", wcslen(L"\\\\?\\"))) {
		path = path.c_str() + wcslen(L"\\\\?\\");
	}
	return true;
}

void MountPointManager::get_mount_points(vector<wstring>& mps, function<bool(const wchar_t *)> filter) const
{
	for (auto it = m_tdatas.begin(); it != m_tdatas.end(); ++it) {
		if (filter) {
			if (filter(it->first.c_str())) {
				mps.push_back(it->first);
			}
		} else {
			mps.push_back(it->first);
		}
	}
}

void MountPointManager::apply(function<bool(const wchar_t*mountpoint, CryptThreadData*tdata)> f)
{
	for (auto it = m_tdatas.begin(); it != m_tdatas.end(); ++it) {
		if (!f(it->first.c_str(), it->second)) {
			return;
		}
	}
}


int MountPointManager::get_open_handle_count(const wchar_t *mountpoint) 
{
	int count = 0;

	if (!mountpoint) {
		for (auto& td : m_tdatas) {
			count += static_cast<int>(td.second->con.m_open_handles.size());
		}
	} else {
		auto it = m_tdatas.find(mountpoint);
		if (it == m_tdatas.end()) {
			return -1;
		}
		count = static_cast<int>(it->second->con.m_open_handles.size());
	}
	 
	return count;
}