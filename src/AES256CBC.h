#ifndef AES256CBC_H_
#define AES256CBC_H_

#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "Base64.h"

#define AES_ROUNDS		5
#define AES_KEY_LEN		32

bool GenerateKeys(const unsigned char *password, int plen, unsigned char *aesSalt, unsigned char *aesKey, unsigned char *aesIV);
int Encrypt(char **cipher, const char *plain, int plen, unsigned char *aesKey, unsigned char *aesIV);
int Decrypt(char **plain, const char *cipher, int clen, unsigned char *aesKey, unsigned char *aesIV);


#endif
