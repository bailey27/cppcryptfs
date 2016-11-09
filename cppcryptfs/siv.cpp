
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

#ifdef USE_AES_NI
	if (AES::use_aes_ni()) {
		aesni_set_encrypt_key(key64, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX]);
		aesni_set_decrypt_key(key64, 256, &m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX]);
		aesni_set_encrypt_key(key64 + 32, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX]);
		aesni_set_decrypt_key(key64 + 32, 256, &m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX]);
	} else 
#endif
	{
		AES_set_encrypt_key(key64, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX]);
		AES_set_decrypt_key(key64, 256, &m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX]);
		AES_set_encrypt_key(key64 + 32, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX]);
		AES_set_decrypt_key(key64 + 32, 256, &m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX]);
	}

	return true;
}