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

IoBufferPool* IoBufferPool::getInstance(size_t buffer_size)
{
	static IoBufferPool  instance;

	// We don't need to care about thread safety with this singleton
	// because getInstance() is called with an argument only during a mount operation which 
	// is always initiated from the main thread. If instance.m_buffer_size is not
	// 0 then init() won't be called again.
	// The methods that involve IoBuffers are all thread-safe.
	if (buffer_size == 0 && instance.m_buffer_size == 0) {
		throw std::runtime_error("error: attempting to use uninitialized IoBufferPool");
	}

	if (buffer_size != 0 && instance.m_buffer_size == 0) {
		instance.init(buffer_size);
	}
	return &instance;
}

IoBuffer::IoBuffer(bool fromPool, size_t bufferSize)
{
	m_bIsFromPool = fromPool;
	m_bufferSize = bufferSize;
	m_pBuf = NULL;
	m_pBuf = new unsigned char[bufferSize];
}

IoBuffer::~IoBuffer()
{
	if (m_pBuf)
		delete[] m_pBuf;
}

void IoBufferPool::lock()
{
	EnterCriticalSection(&m_crit);
}

void IoBufferPool::unlock()
{
	LeaveCriticalSection(&m_crit);
}

void IoBufferPool::init(size_t buffer_size)
{
	if (buffer_size == 0) {
		throw std::runtime_error("error: attempting to init IoBufferPool with buffer_size of 0");
	}
	m_buffer_size = buffer_size;
	m_num_buffers = 0;
	InitializeCriticalSection(&m_crit);
}

IoBufferPool::~IoBufferPool()
{
	for (IoBuffer* pBuf : m_buffers) {
		delete pBuf;
	}

	if (m_buffer_size) { // was initialized
		DeleteCriticalSection(&m_crit);
	}
}

IoBuffer * IoBufferPool::GetIoBuffer(size_t buffer_size)
{
	IoBuffer *pb = NULL;

	if (buffer_size <= m_buffer_size) {
		lock();
		try {
			if (m_buffers.size() > 0) {
				pb = m_buffers.front();
				m_buffers.pop_front();
			} else if (m_num_buffers < m_max_buffers) {
				pb = new IoBuffer(true, m_buffer_size);
				m_num_buffers++;
			}
		} catch (...) {
			pb = NULL;
		}
		unlock();
	} 
	if (pb == NULL) {
		try {
			pb = new IoBuffer(false, buffer_size);
		} catch (...) {
			pb = NULL;
		}
	}
	
	return pb;
}

void IoBufferPool::ReleaseIoBuffer(IoBuffer * pBuf)
{

	if (pBuf->m_bIsFromPool) {
		lock();
		m_buffers.push_front(pBuf);
		unlock();
	} else {
		delete pBuf;
	}
}


