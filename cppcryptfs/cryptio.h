#pragma once

#include <windows.h>

class CryptContext;

int
read_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, unsigned char *ptbuf, void *crypt_context);

int
write_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, const unsigned char *ptbuf, int ptlen, void *crypt_context);