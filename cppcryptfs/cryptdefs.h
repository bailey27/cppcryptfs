#pragma once


#define CRYPT_VERSION 2

#define FILE_HEADER_LEN 18
#define FILE_ID_LEN 16
#define PLAIN_BS 4096
#define BLOCK_IV_LEN 16
#define MASTER_IV_LEN 12
#define DIR_IV_LEN 16
#define BLOCK_TAG_LEN 16
#define CIPHER_BLOCK_OVERHEAD (BLOCK_IV_LEN+BLOCK_TAG_LEN)
#define CIPHER_BS (PLAIN_BS+CIPHER_BLOCK_OVERHEAD)
#define CIPHER_FILE_OVERHEAD FILE_HEADER_LEN
#define MASTER_KEY_LEN 32

#define AES_MODE_CBC 1
#define AES_MODE_GCM 2


#define CONFIG_NAME (L"gocryptfs.conf")

#define DIR_IV_NAME (L"gocryptfs.diriv")


