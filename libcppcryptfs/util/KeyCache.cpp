/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2021 Bailey Brown (github.com/bailey27/cppcryptfs)

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


static string get_local_time_string()
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	char buf[16];
	sprintf_s(buf, "%02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);

	return string(buf);
}


KeyCache::KeyCache()
{
	m_cur_id = 0;
	m_valid_count = 0;
	m_enabled = true;
	m_clearEvent = NULL;
	m_clearThread = NULL;
}

KeyCache::~KeyCache()
{
	assert(m_entries.empty());
	assert(m_valid_count == 0);
	assert(!m_clearEvent);
	assert(!m_clearThread);	
}

KeyCache* KeyCache::GetInstance()
{
	static KeyCache instance;

	return &instance;
}

static DWORD WINAPI ClearThreadProc(_In_ LPVOID lpParameter)
{
	HANDLE hEvent = lpParameter;

	while (true) {
		auto wait_result = WaitForSingleObject(hEvent, 1000);
		if (wait_result == WAIT_TIMEOUT) {
			KeyCache::GetInstance()->Clear();
		} else if (wait_result == WAIT_OBJECT_0) {
			break;
		} else {
			assert(false);
		}
	}	

	return 0;
}


bool KeyCache::InitClearThread()
{	
	
	static once_flag init_thread_once_flag;

	std::call_once(init_thread_once_flag, [this]() {
			m_clearEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
			if (m_clearEvent) {
				m_clearThread = CreateThread(NULL, 0, ClearThreadProc, m_clearEvent, 0, NULL);				
			}
		});

	return m_clearThread != NULL;
}

void KeyCache::StopClearThread()
{
	if (!m_clearThread)
		return;

	assert(m_clearEvent);

	SetEvent(m_clearEvent);

	auto wait_result = WaitForSingleObject(m_clearThread, INFINITE);

	assert(wait_result == WAIT_OBJECT_0);

	CloseHandle(m_clearThread);
	CloseHandle(m_clearEvent);

	m_clearEvent = NULL;
	m_clearThread = NULL;
}

KeyCache::id_t KeyCache::Register(DWORD buf_size)
{

	lock_guard<mutex> lock(m_mutex);

	if (!InitClearThread())
		return 0;

	KeyCacheEntry ent;

	ent.pbuf = new LockZeroBuffer<BYTE>(buf_size, false);

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

	assert(it != m_entries.end());

	if (it == m_entries.end())
		return false;

	if (it->second.valid)
		m_valid_count--;

	m_entries.erase(it);

	return true;
}

void KeyCache::Enable()
{
	lock_guard<mutex> lock(m_mutex);

#ifdef _DEBUG
	string mes = "enabling key cache at " + get_local_time_string() + "\n";
	OutputDebugStringA(mes.c_str());
#endif

	m_enabled = true;
}

void KeyCache::ClearInternal(bool disable)
{
	lock_guard<mutex> lock(m_mutex);

	if (m_valid_count > 0) {

		for (auto& it : m_entries) {
			if (it.second.valid && (disable || !it.second.accessed)) {
#ifdef _DEBUG
				//char buf[64];
				//sprintf_s(buf, "clearing keys for cache id %llu\n", it.first);
				//OutputDebugStringA(buf);
#endif
				it.second.Clear();
				m_valid_count--;
			} else {
				it.second.accessed = false;
			}
		}
	}

	if (disable) {
#ifdef _DEBUG
		string mes = "disabling key cache at " + get_local_time_string() + "\n";		
		OutputDebugStringA(mes.c_str());		
#endif
		m_enabled = false;
		assert(m_valid_count == 0);
	}
}

bool KeyCache::Store(id_t id, const BYTE* ptr, size_t len)
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
	m_valid_count++;

	return true;
}

bool KeyCache::Retrieve(id_t id, const vector<KeyBuf>& kbv)
{
	lock_guard<mutex> lock(m_mutex);

	if (!m_enabled)
		return false;

	auto it = m_entries.find(id);

	assert(it != m_entries.end());

	if (it == m_entries.end())
		return false;

	if (!it->second.valid)
		return false;

	KeyBuf::CopyBuffers(kbv, it->second.pbuf->m_buf, it->second.pbuf->m_len);

	it->second.accessed = true;

	return true;
}