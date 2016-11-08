/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#pragma once


#define CRYPT_VERSION 2

#define FILE_HEADER_LEN 18
#define FILE_ID_LEN 16
#define PLAIN_BS 4096
#define BLOCK_IV_LEN 16
#define BLOCK_SIV_LEN 16
#define MASTER_IV_LEN 12
#define DIR_IV_LEN 16
#define BLOCK_TAG_LEN 16
#define CIPHER_BLOCK_OVERHEAD (BLOCK_IV_LEN+BLOCK_TAG_LEN)
#define CIPHER_BS (PLAIN_BS+CIPHER_BLOCK_OVERHEAD)
#define CIPHER_FILE_OVERHEAD FILE_HEADER_LEN
#define MASTER_KEY_LEN 32

#define AES_MODE_GCM 1

#define SALT_LEN 32

#define DEFAULT_KEY_LEN 32


#define CONFIG_NAME (L"gocryptfs.conf")

#define DIR_IV_NAME (L"gocryptfs.diriv")

#define MAX_FILENAME_LEN 255

#define MAX_PASSWORD_LEN 255

#define MAX_VOLUME_NAME_LENGTH 32
#define MAX_FAT_VOLUME_NAME_LENGTH 11

