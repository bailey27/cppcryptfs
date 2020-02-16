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
#include "KeyCache.h"


KeyCache::KeyCache()
{
	m_cur_id = 0;
	m_enabled = true;
}

KeyCache* KeyCache::GetInstance()
{
	static KeyCache instance;

	return &instance;
}

KeyCache::id_t KeyCache::Register(DWORD buf_size)
{
	lock_guard<mutex> lock(m_mutex);

	KeyCacheEntry ent;

	ent.pbuf = new LockZeroBuffer<BYTE>(buf_size, false, nullptr);

	if (!ent.pbuf->IsLocked()) {
		return 0;
	}

	m_cur_id++;

	m_entries[m_cur_id] = std::move(ent);

	return m_cur_id;

}

bool KeyCache::Unregister(id_t id)
{
	lock_guard<mutex> lock(m_mutex);

	auto it = m_entries.find(id);

	if (it == m_entries.end())
		return false;

	m_entries.erase(it);

	return true;
}

void KeyCache::Enable()
{
	lock_guard<mutex> lock(m_mutex);

	m_enabled = true;
}

void KeyCache::ClearInternal(bool disable)
{
	lock_guard<mutex> lock(m_mutex);

	if (!m_enabled)
		return;

	for (auto& it : m_entries) {
		if (it.second.valid && (disable || !it.second.accessed)) {
#ifdef _DEBUG
			char buf[64];
			sprintf_s(buf, "clearing keys for cache id %llu\n", it.first);
			OutputDebugStringA(buf);
#endif
			it.second.Clear();
		} else {
			it.second.accessed = false;
		}
	}

	if (disable)
		m_enabled = false;
}

bool KeyCache::Store(id_t id, void* ptr, size_t len)
{
	lock_guard<mutex> lock(m_mutex);

	if (!m_enabled)
		return true;

	auto it = m_entries.find(id);

	if (it == m_entries.end())
		return false;

	assert(it->second.pbuf->m_len == len);

	if (it->second.pbuf->m_len < len)
		return false;

	memcpy(it->second.pbuf->m_buf, ptr, len);

	it->second.valid = true;
	it->second.accessed = true;

	return true;
}

bool KeyCache::Retrieve(id_t id, void* ptr, size_t len)
{
	lock_guard<mutex> lock(m_mutex);

	if (!m_enabled)
		return false;

	auto it = m_entries.find(id);

	if (it == m_entries.end())
		return false;

	assert(it->second.pbuf->m_len == len);

	if (!it->second.valid)
		return false;

	if (it->second.pbuf->m_len < len)
		return false;

	memcpy(ptr, it->second.pbuf->m_buf, len);

	it->second.accessed = true;

	return true;
}