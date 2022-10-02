#ifndef SAFECLOUD_AES_128_CBC_H
#define SAFECLOUD_AES_128_CBC_H

/* OpenSSL AES_128_CBC Utility Functions Definitions */

#include <openssl/evp.h>
#include <openssl/pem.h>

// TODO: Check if it is necessary to have a class
/*
class AES_128_CBC
 {

 };
*/

/**
 * @brief        Encrypts a plaintext of arbitrary size using the AES_128 cipher
 *               in CBC mode, safely deleting the plaintext afterwards
 * @param key    The AES_128 encryption key (128 bit, 16 bytes)
 * @param iv     The encryption's IV
 * @param ptAddr The plaintext initial address
 * @param ptSize The plaintext size
 * @param ctDest The address where to write the resulting ciphertext
 * @return       The resulting ciphertext's size in BYTES
 * @note         The plaintext to be encrypted must be of a size <= INT_MAX - AES_BLOCK_SIZE = 2^16 - 1 - 128
 * @throws       ERR_OSSL_AES_128_CBC_PT_TOO_LARGE The plaintext to encrypt is too large
 * @throws       ERR_OSSL_EVP_CIPHER_CTX_NEW       EVP_CIPHER context creation failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_INIT         EVP_CIPHER encrypt initialization failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_UPDATE       EVP_CIPHER encrypt update failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_FINAL        EVP_CIPHER encrypt final failed
 */
int AES_128_CBC_Encrypt(unsigned char* key, unsigned char* iv, unsigned char* ptAddr, int ptSize, unsigned char* ctDest);


#endif //SAFECLOUD_AES_128_CBC_H
