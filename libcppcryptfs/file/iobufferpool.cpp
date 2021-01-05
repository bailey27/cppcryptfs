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
#include "iobufferpool.h"

IoBufferPool IoBufferPool::instance;

IoBufferPool& IoBufferPool::getInstance()
{	
	return instance;
}

void IoBuffer::reallocate(size_t bufferSize, size_t ivbufferSize)
{
	auto total_size = bufferSize + ivbufferSize;

	if (m_storage.size() < total_size) {
		m_storage.clear();
		m_storage.resize(total_size);
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

IoBuffer::IoBuffer(bool fromPool, size_t bufferSize, size_t ivbufferSize)
{
	m_bIsFromPool = fromPool;
	
	reallocate(bufferSize, ivbufferSize);
}



IoBufferPool::~IoBufferPool()
{
	for (IoBuffer* pBuf : m_buffers) {
		delete pBuf;
	}	
}

IoBuffer * IoBufferPool::GetIoBuffer(size_t buffer_size, size_t ivbuffer_size)
{
	IoBuffer* pb = nullptr;

	bool will_be_from_pool = false;

	m_mutex.lock();

	if (!m_buffers.empty()) {
		pb = m_buffers.front();
		m_buffers.pop_front();	
	} else if (m_num_buffers < m_max_buffers) {
		will_be_from_pool = true;
		++m_num_buffers;
	}

	m_mutex.unlock();

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
	if (pBuf->m_bIsFromPool) {
		m_mutex.lock();
		try {
			m_buffers.push_front(pBuf);
		} catch (const std::bad_alloc&) {
			delete pBuf;
		}
		m_mutex.unlock();
	} else {
		delete pBuf;
	}
}


