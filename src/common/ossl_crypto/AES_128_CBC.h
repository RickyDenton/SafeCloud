#ifndef SAFECLOUD_AES_128_CBC_H
#define SAFECLOUD_AES_128_CBC_H

/* OpenSSL AES_128_CBC Utility Functions Declarations */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "ConnMgr/IV/IV.h"

#define AES_128_KEY_SIZE 16      // The AES_128 key size in bytes    (128 bit)
#define AES_BLOCK_SIZE 16        // The AES block size in bytes      (128 bit)
#define AES_128_CBC_IV_SIZE 16   // The AES_128_CBC IV size in bytes (128 bit)

/* =========================== FUNCTIONS DECLARATIONS =========================== */

/**
 * @brief        Encrypts a plaintext using the AES_128 cipher in CBC mode,
 *               safely deleting the plaintext and incrementing the IV afterwards
 * @param key    The AES_128 encryption key (128 bit, 16 bytes)
 * @param iv     The encryption's IV        (128 bit, 16 bytes)
 * @param ptAddr The plaintext initial address
 * @param ptSize The plaintext size (must be <= INT_MAX - AES_BLOCK_SIZE = 2^16 - 1 - 16 bytes)
 * @param ctDest The address where to write the resulting ciphertext
 * @return       The resulting ciphertext's size in bytes
 * @note         The function assumes the "ctDest" destination buffer to be large enough to contain the resulting
 *               ciphertext (i.e. at least ptSize + AES_BLOCK_SIZE to account for the additional full padding block)
 * @throws       ERR_NON_POSITIVE_BUFFER_SIZE      The plaintext size is non-positive (probable overflow)
 * @throws       ERR_OSSL_AES_128_CBC_PT_TOO_LARGE The plaintext to encrypt is too large
 * @throws       ERR_OSSL_EVP_CIPHER_CTX_NEW       EVP_CIPHER context creation failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_INIT         EVP_CIPHER encrypt initialization failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_UPDATE       EVP_CIPHER encrypt update failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_FINAL        EVP_CIPHER encrypt final failed
 */
int AES_128_CBC_Encrypt(const unsigned char* key, IV* iv, unsigned char* ptAddr, int ptSize, unsigned char* ctDest);


/**
 * @brief        Decrypts a ciphertext using the AES_128 cipher in CBC mode
 * @param key    The AES_128 encryption key (128 bit, 16 bytes)
 * @param iv     The encryption's IV        (128 bit, 16 bytes)
 * @param ctAddr The ciphertext's initial address
 * @param ctSize The ciphertext's size
 * @param ptDest The address where to write the resulting plaintext
 * @return       The resulting plaintext size in bytes
 * @note         The function assumes the "ptDest" destination buffer to be large
 *               enough to contain the resulting plaintext (i.e. at least ctSize)
 * @throws       ERR_NON_POSITIVE_BUFFER_SIZE      The ciphertext size is non-positive (probable overflow)
 * @throws       ERR_OSSL_EVP_CIPHER_CTX_NEW       EVP_CIPHER context creation failed
 * @throws       ERR_OSSL_EVP_DECRYPT_INIT         EVP_CIPHER decrypt initialization failed
 * @throws       ERR_OSSL_EVP_DECRYPT_UPDATE       EVP_CIPHER decrypt update failed
 * @throws       ERR_OSSL_EVP_DECRYPT_FINAL        EVP_CIPHER decrypt final failed
 */
int AES_128_CBC_Decrypt(const unsigned char* key, IV* iv, unsigned char* ctAddr, int ctSize, unsigned char* ptDest);


#endif //SAFECLOUD_AES_128_CBC_H
