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
#pragma once
#include "LockZeroBuffer.h"
#include "KeyCache.h"
#include <mutex>
#include <vector>

using namespace std;

class KeybufManager
{
public:
	mutex m_mutex;
	KeyCache::id_t m_key_cache_id;
	bool m_bActive;
	bool m_bFinalized;
	int m_refcount;
	DWORD m_total_len;

	vector<KeyBuf> m_bufs;
	vector<BYTE> m_encryptedBuf;
	BYTE m_optional_entropy[32];

	KeybufManager();
	
	virtual ~KeybufManager();
private:
	void RegisterBuf(BYTE* p, DWORD len);
	bool EnterInternal();
	void LeaveInternal();
public:
	template <typename T>
	void RegisterBuf(LockZeroBuffer<T> *pBuf) 
	{
		RegisterBuf(reinterpret_cast<BYTE*>(pBuf->m_buf), pBuf->m_len * sizeof(T));
	};

	void Activate() { m_bActive = true; };
	bool Finalize(bool use_key_cache);

	bool Enter() 
	{
		if (!m_bActive)
			return true;

		return EnterInternal();
	}
	void Leave()
	{
		if (!m_bActive)
			return;

		LeaveInternal();
	}

	// disallow copying
	KeybufManager(KeybufManager const&) = delete;
	void operator=(KeybufManager const&) = delete;
};

class KeyDecryptor {
	KeybufManager* m_mgr;
	bool m_bEntered;
public:
	KeyDecryptor() = delete;
	KeyDecryptor(KeybufManager* mgr, bool manual_enter = false)
	{
		m_bEntered = false;

		m_mgr = mgr;

		if (!m_mgr)
			return;

		if (!manual_enter)
			Enter();
	}
	void Enter()
	{
		if (m_bEntered || !m_mgr)
			return;

		if (!m_mgr->Enter())
			throw std::exception("KeyDecryptor enter failed");

		m_bEntered = true;
	}
	virtual ~KeyDecryptor()
	{
		if (m_bEntered)
			m_mgr->Leave();
	}
	// disallow copying
	KeyDecryptor(KeyDecryptor const&) = delete;
	void operator=(KeyDecryptor const&) = delete;
};