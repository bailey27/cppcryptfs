#pragma once

#include <windows.h>

#define RANDOM_POOL_SIZE 4096

class RandomBytes {
private:
	unsigned char m_randbuf[RANDOM_POOL_SIZE];

	DWORD m_bufpos;

	CRITICAL_SECTION m_crit;

public:
	bool GetRandomBytes(unsigned char *buf, DWORD len);

	RandomBytes();
	virtual ~RandomBytes();
};

