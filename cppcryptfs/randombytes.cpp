#include "stdafx.h"

#include <windows.h>
#include "util.h"
#include "randombytes.h"

RandomBytes::RandomBytes()
{
	VirtualLock(m_randbuf, sizeof(m_randbuf));

	m_bufpos = RANDOM_POOL_SIZE;

	InitializeCriticalSection(&m_crit);
}

RandomBytes::~RandomBytes()
{
	SecureZeroMemory(m_randbuf, sizeof(m_randbuf));

	VirtualUnlock(m_randbuf, sizeof(m_randbuf));

	m_bufpos = 0;
}

bool RandomBytes::GetRandomBytes(unsigned char *buf, DWORD len)
{
	if (len > RANDOM_POOL_SIZE) {
		return get_sys_random_bytes(buf, len);
	}

	bool bret = true;

	EnterCriticalSection(&m_crit);

	if (m_bufpos + len < RANDOM_POOL_SIZE) {
		memcpy(buf, m_randbuf + m_bufpos, len);
		m_bufpos += len;
	} else {
		DWORD bytes_copied = 0;
		if (m_bufpos < RANDOM_POOL_SIZE) {
			memcpy(buf, m_randbuf + m_bufpos, RANDOM_POOL_SIZE - m_bufpos);
			bytes_copied += RANDOM_POOL_SIZE - m_bufpos;
			m_bufpos += bytes_copied;
		}
		if (get_sys_random_bytes(m_randbuf, RANDOM_POOL_SIZE)) {
			m_bufpos = 0;
			memcpy(buf + bytes_copied, m_randbuf + m_bufpos, len - bytes_copied);
			m_bufpos += len - bytes_copied;
		} else {
			bret = false;
		}
	}

	LeaveCriticalSection(&m_crit);

	return bret;
}
