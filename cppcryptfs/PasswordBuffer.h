#pragma once

#define MAX_PASSWORD_LEN 255

class PasswordBuffer
{
public:
	WCHAR m_buf[MAX_PASSWORD_LEN + 1];
	PasswordBuffer();
	virtual ~PasswordBuffer();
};

class PasswordBufferUtf8
{
public:
	char m_buf[4*MAX_PASSWORD_LEN + 1]; // account for possible UTF8 growth
	PasswordBufferUtf8();
	virtual ~PasswordBufferUtf8();
};


