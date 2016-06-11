#include "stdafx.h"
#include "PasswordBuffer.h"


PasswordBuffer::PasswordBuffer()
{
	VirtualLock(m_buf, sizeof(m_buf));
	m_buf[0] = '\0';
}


PasswordBuffer::~PasswordBuffer()
{
	SecureZeroMemory(m_buf, sizeof(m_buf));
	VirtualUnlock(m_buf, sizeof(m_buf));
}

PasswordBufferUtf8::PasswordBufferUtf8()
{
	VirtualLock(m_buf, sizeof(m_buf));
	m_buf[0] = '\0';
}


PasswordBufferUtf8::~PasswordBufferUtf8()
{
	SecureZeroMemory(m_buf, sizeof(m_buf));
	VirtualUnlock(m_buf, sizeof(m_buf));
}
