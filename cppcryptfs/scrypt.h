#ifndef _SCRYPT_H_INCLUDED
#define   _SCRYPT_H_INCLUDED 1

#ifdef __cplusplus 
extern "C" {
#endif

int EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen);

#ifdef __cplusplus 
};
#endif

#endif


