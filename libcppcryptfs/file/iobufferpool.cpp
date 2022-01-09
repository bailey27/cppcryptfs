/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2022 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "iobufferpool.h"


IoBufferPool& IoBufferPool::getInstance()
{	
	static IoBufferPool instance;

	return instance;
}

void IoBuffer::reallocate(size_t bufferSize, size_t ivbufferSize)
{
	auto total_size = bufferSize + ivbufferSize;

	if (m_storage.size() < total_size) {
		m_storage.clear();
		m_storage.resize(max(total_size, min(m_storage.size() * 2, IoBufferPool::m_max_pool_buffer_size)));				
	}

	if (bufferSize > 0) {
		m_pBuf = &m_storage[0];
	} else {
		m_pBuf = nullptr;
	}

	if (ivbufferSize > 0) {
		m_pIvBuf = &m_storage[bufferSize];
	} else {
		m_pIvBuf = nullptr;
	}
}

IoBuffer::IoBuffer(bool fromPool, size_t bufferSize, size_t ivbufferSize) : m_bIsFromPool(fromPool)
{		
	reallocate(bufferSize, ivbufferSize);
}



IoBufferPool::~IoBufferPool()
{
#if 0
	char buf[64];
	sprintf_s(buf, "num iobuffers = %d\n", static_cast<int>(m_buffers.size()));
	OutputDebugStringA(buf);
#endif
	for (IoBuffer* pBuf : m_buffers) {
		delete pBuf;
	}	
}


IoBuffer * IoBufferPool::GetIoBuffer(size_t buffer_size, size_t ivbuffer_size)
{

	IoBuffer* pb = nullptr;

	bool will_be_from_pool = false;

	auto total_size = buffer_size + ivbuffer_size;

	if (total_size <= m_max_pool_buffer_size) {

		lock_guard<mutex> lock(m_mutex);

		if (!m_buffers.empty()) {
			pb = m_buffers.front();			
			if (total_size > pb->m_storage.size()) {				
				auto growth = total_size - pb->m_storage.size();
				if (m_current_size + growth > m_max_size) {			
					pb = nullptr;
				} else {
					m_current_size += growth;
				}
			}			
			if (pb) {
				m_buffers.pop_front();
			}
		} else if (m_current_size + total_size <= m_max_size) {
			will_be_from_pool = true;
			m_current_size += total_size;
		}		
	}

	try {
		if (pb) {
			pb->reallocate(buffer_size, ivbuffer_size);
		} else {
			pb = new IoBuffer(will_be_from_pool, buffer_size, ivbuffer_size);
		}
	} catch (const std::bad_alloc&) {
		pb = nullptr;
	}	
	
	return pb;
}

void IoBufferPool::ReleaseIoBuffer(IoBuffer * pBuf)
{

	if (!pBuf)
		return;

	if (pBuf->m_bIsFromPool) {
		lock_guard<mutex> lock(m_mutex);
		try {
			m_buffers.push_front(pBuf);
		} catch (const std::bad_alloc&) {
			delete pBuf;
		}		
	} else {
		delete pBuf;
	}
}


