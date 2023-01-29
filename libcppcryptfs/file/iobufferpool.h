/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2023 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <vector>
#include <mutex>
#include <crypt/cryptdefs.h>

using namespace std;

class IoBuffer {
public:

	unsigned char *m_pBuf;
	unsigned char* m_pIvBuf;
	bool m_bIsFromPool;
	vector<unsigned char> m_storage;

	// disallow copying
	IoBuffer(IoBuffer const&) = delete;
	void operator=(IoBuffer const&) = delete;

	IoBuffer(bool fromPool, size_t bufferSize, size_t ivbuffer_size);

	void reallocate(size_t bufferSize, size_t ivbuffer_size);
	~IoBuffer() = default;

};

class IoBufferPool {
private:
	mutex m_mutex;		
	static const size_t m_max_size = 70*1024*1024;	
	size_t m_current_size;
	list<IoBuffer*> m_buffers;

	IoBufferPool() : m_current_size(0) {};	

public:

	// the size below is to accomodate the maximum i/o buffer size + enough IVs to write up to 64MB
	static const size_t m_max_pool_buffer_size = ((MAX_IO_BUFFER_KB * 1024) / PLAIN_BS) * CIPHER_BS + ((64 * 1024 * 1024) / PLAIN_BS) * BLOCK_IV_LEN;

	static IoBufferPool& getInstance();

	// disallow copying and moving
	IoBufferPool(IoBufferPool const&) = delete;
	void operator=(IoBufferPool const&) = delete;
	IoBufferPool(IoBufferPool const&&) = delete;
	void operator=(IoBufferPool const&&) = delete;

	~IoBufferPool();
	IoBuffer *GetIoBuffer(size_t buffer_size, size_t ivbufer_size);
	void ReleaseIoBuffer(IoBuffer *pBuf);
};
