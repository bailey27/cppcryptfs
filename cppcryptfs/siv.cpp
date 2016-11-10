
#include "stdafx.h"
#include "crypt.h"

#include "siv.h"
#include "aes.h"

SivContext::SivContext()
{
	m_pKeys = NULL;
}

SivContext::~SivContext()
{
	if (m_pKeys)
		delete m_pKeys;
}

bool SivContext::SetKey(const unsigned char *key, int keylen)
{
	if (keylen != 32)
		return false;

	if (!m_pKeys)
		m_pKeys = new LockZeroBuffer<AES_KEY>(4, true);

	unsigned char key64[64];

	if (!sha512(key, 32, key64))
		return false;

	AES::initialize_keys(key64, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX], 
										&m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX]);

	AES::initialize_keys(key64 + 32 , 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX], 
											&m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX]);

	return true;
}