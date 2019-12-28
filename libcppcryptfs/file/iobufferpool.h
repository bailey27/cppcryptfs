/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <list>
#include <stdexcept>

using namespace std;

class IoBuffer {
public:

	unsigned char *m_pBuf;
	size_t m_bufferSize;
	bool m_bIsFromPool;

	// disallow copying
	IoBuffer(IoBuffer const&) = delete;
	void operator=(IoBuffer const&) = delete;

	IoBuffer(bool fromPool, size_t bufferSize);
	virtual ~IoBuffer();

};

class IoBufferPool {
private:
	CRITICAL_SECTION m_crit;
	const int m_max_buffers = 10;
	int m_num_buffers;
	size_t m_buffer_size;
	list<IoBuffer*> m_buffers;
	void lock();
	void unlock();

	void init(size_t buffer_size);

	IoBufferPool() { m_buffer_size = 0; }

public:

	static IoBufferPool* getInstance(size_t buffer_size = 0)
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

	// disallow copying
	IoBufferPool(IoBufferPool const&) = delete;
	void operator=(IoBufferPool const&) = delete;

	virtual ~IoBufferPool();
	IoBuffer *GetIoBuffer(size_t buffer_size);
	void ReleaseIoBuffer(IoBuffer *pBuf);
};
