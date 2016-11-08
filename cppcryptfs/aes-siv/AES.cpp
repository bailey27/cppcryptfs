#include "stdafx.h"
#include "AES.h"

AES::AES()
{
	m_key_encrypt = NULL;
	m_key_decrypt = NULL;
}

AES::~AES()
{
	// don't delete keys
}

int AES::set_keys(const AES_KEY *key_encrypt, const AES_KEY *key_decrypt)
{
	m_key_encrypt = key_encrypt;
	m_key_decrypt = key_decrypt;

	return SUCCESS ;
}



/*  Encrypt a single block of 16 bytes */

int AES::encrypt (const unsigned char *plain, unsigned char *cipher)
{
 
	AES_encrypt(plain, cipher, m_key_encrypt);
	
	return SUCCESS ;
}


/*  Decrypt a single block of 16 bytes */

int  AES::decrypt(const unsigned char *cipher, unsigned char *plain)
{
	AES_decrypt(cipher, plain, m_key_decrypt);

	return SUCCESS ;
}


