#pragma once
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

#include <mutex>
#include <unordered_map>
#include <vector>
#include "util/LockZeroBuffer.h"

using namespace std;

struct KeyBuf {
	BYTE* ptr;
	size_t len;
};

struct KeyCacheEntry {
	LockZeroBuffer<BYTE>* pbuf;
	bool valid;
	bool accessed;
	KeyCacheEntry()
	{
		pbuf = nullptr;
		valid = false;
		accessed = false;
	}
	void Clear()
	{
		pbuf->Clear();
		accessed = false;
		valid = false;
	}
	~KeyCacheEntry()
	{
		if (pbuf)
			delete pbuf;
	}
	// disallow copying
	KeyCacheEntry(KeyCacheEntry const&) = delete;
	void operator=(KeyCacheEntry const&) = delete;

	// move constructor
	KeyCacheEntry(KeyCacheEntry&& other)
		: pbuf(nullptr)
		, accessed(false), valid(false)
	{
		pbuf = other.pbuf;
		valid = other.valid;
		accessed = other.accessed;

		other.pbuf = nullptr;
		other.accessed = false;
		other.valid = false;
	}

	// move assignment operator
	KeyCacheEntry& operator=(KeyCacheEntry&& other)
	{
		if (this != &other) {
			if (pbuf)
				delete pbuf;

			pbuf = other.pbuf;
			accessed = other.accessed;
			valid = other.valid;

			other.pbuf = nullptr;
			other.accessed = false;
			other.valid = false;
		}

		return *this;
	}
};


class KeyCache
{
public:
	typedef unsigned long long id_t;
private:
	mutex m_mutex;
	id_t m_cur_id;  // we increment it and assign as unique id for registered clients
	unordered_map<id_t, KeyCacheEntry> m_entries;
	KeyCache();
	bool m_enabled;
	void ClearInternal(bool disable);
public:	
	static KeyCache* GetInstance();
	id_t Register(DWORD buf_size);
	bool Unregister(id_t id);
	void Enable();
	void Clear() { ClearInternal(false); }
	void Disable() { ClearInternal(true); }
	bool Store(id_t id, const BYTE* ptr, size_t len);
	bool Retrieve(id_t id, const vector<KeyBuf>& kbmb);

	static void CopyBuffers(const vector<KeyBuf>& kbv, const BYTE* ptr, size_t len)
	{
		// Must be locked when called if ptr is from cache

		size_t offset = 0;
		for (size_t i = 0; i < kbv.size(); i++) {
			memcpy(kbv[i].ptr, ptr + offset, kbv[i].len);
			offset += kbv[i].len;
		}
	}

	// disallow copying
	KeyCache(KeyCache const&) = delete;
	void operator=(KeyCache const&) = delete;
};

