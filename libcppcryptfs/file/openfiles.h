/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2025 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <memory>

using namespace std;

class CryptFileMutex {
private:
	// the outer mutex is for fairness so exclusive lockers can get in
	// because they need to do only a small portion of their work in exclusive mode
	mutex m_outer_mutex;  
	shared_mutex m_inner_mutex;
public:
	void lock() 
	{
		lock_guard<mutex> lck(m_outer_mutex);
		m_inner_mutex.lock();		
	}

	void lock_shared() 
	{		
		lock_guard<mutex> lck(m_outer_mutex);
		m_inner_mutex.lock_shared();
	}

	void unlock() 
	{
		m_inner_mutex.unlock();
	}

	void unlock_shared() 
	{
		m_inner_mutex.unlock_shared();
	}

};

class CryptOpenFile {
private:
	CryptFileMutex m_mutex;
	unordered_map<HANDLE, DWORD> m_handles;
public:
	CryptOpenFile() = delete;
	virtual ~CryptOpenFile() = default;

	CryptOpenFile(HANDLE h)
	{		
		m_handles[h] = 1;		
	}

	void Open(HANDLE h)
	{
		auto it = m_handles.find(h);
		if (it == m_handles.end()) {
			m_handles[h] = 1;
		} else {
			it->second++;
		}
	}

	bool Close(HANDLE h)
	{
		auto it = m_handles.find(h);
		if (it == m_handles.end()) {
			return false;
		}

		it->second--;

		if (it->second == 0)
			m_handles.erase(h);

		return true;
	}

	bool Empty()
	{
		return m_handles.empty();
	}

	void LockShared()
	{
		m_mutex.lock_shared();
	}

	void UnlockShared()
	{
		m_mutex.unlock_shared();
	}

	void LockExclusive()
	{
		m_mutex.lock();
	}

	void UnlockExclusive()
	{
		m_mutex.unlock();
	}

	// disallow copying
	CryptOpenFile(CryptOpenFile const&) = delete;
	void operator=(CryptOpenFile const&) = delete;
};

class CryptOpenFiles {
private:
	mutex m_mutex;
	unordered_map<wstring, shared_ptr<CryptOpenFile> > m_openfiles;
public:
	CryptOpenFiles() = default;
	virtual ~CryptOpenFiles() = default;

	bool OpenFile(LPCWSTR path, HANDLE h);

	bool CloseFile(LPCWSTR path, HANDLE h);

	bool Rename(LPCWSTR from, LPCWSTR to);

	shared_ptr<CryptOpenFile> GetOpenFile(LPCWSTR path);

	// disallow copying
	CryptOpenFiles(CryptOpenFiles const&) = delete;
	void operator=(CryptOpenFiles const&) = delete;
};
