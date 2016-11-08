#ifndef __AES_H__
#define __AES_H__

#include "openssl/aes.h"
#include "../LockZeroBuffer.h"
 

#define N_BLOCK   (16)

#define SUCCESS (0)
#define FAILURE (-1)


class AES
{
 public:

  int set_keys(const AES_KEY *key_encrypt, const AES_KEY *key_decrypt);
 
  int encrypt(const unsigned char* plain, unsigned char *cipher) ;
  
  int decrypt(const unsigned char *cipher, unsigned char *plain) ;
  
  AES();
  virtual ~AES();

 private:
	 const AES_KEY *m_key_encrypt;
	 const AES_KEY *m_key_decrypt;
};


#endif
