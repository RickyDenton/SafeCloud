/* OpenSSL AES_128_CBC Utility Functions Definitions */

#include "AES_128_CBC.h"
#include "errlog.h"


#define AES_128_CBC_IV_SIZE 16
#define AES_BLOCK_SIZE 128


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
int AES_128_CBC_Encrypt(unsigned char* key, unsigned char* iv, unsigned char* ptAddr, int ptSize, unsigned char* ctDest)
 {
  EVP_CIPHER_CTX* aesEncCTX;  // Cipher encryption context
  int encBytes;               // The number of encrypted bytes at an encryption's step (EVP_EncryptUpdate or EVP_EncryptFinal)
  int encBytesTot;            // The total number of encrypted bytes, eventually representing the resulting ciphertext's size

  // Assert the maximum size of the resulting ciphertext (ptSize + padding) not to overflow on
  // an "int" type (case in which  an erroneous negative ciphertext length would be returned)
  if(ptSize > INT_MAX - AES_BLOCK_SIZE)
   THROW_SCODE(ERR_OSSL_AES_128_CBC_PT_TOO_LARGE,std::to_string(ptSize));

  // Create the cipher encryption context
  aesEncCTX = EVP_CIPHER_CTX_new();
  if(!aesEncCTX)
   THROW_SCODE(ERR_OSSL_EVP_CIPHER_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the cipher encryption context specifying the cipher, key and IV
  if(EVP_EncryptInit(aesEncCTX, EVP_aes_128_cbc(), key, iv) != 1)
   THROW_SCODE(ERR_OSSL_EVP_ENCRYPT_INIT,OSSL_ERR_DESC);

  // Encrypt the plaintext to the ciphertext's buffer
  if(EVP_EncryptUpdate(aesEncCTX, ctDest, &encBytes, ptAddr, ptSize) != 1)
   THROW_SCODE(ERR_OSSL_EVP_ENCRYPT_UPDATE,OSSL_ERR_DESC);

  // Update the total number of encrypted bytes
  encBytesTot = encBytes;

  // Finalize the encryption by adding padding
  if(EVP_EncryptFinal(aesEncCTX, ctDest + encBytesTot, &encBytes) != 1)
   THROW_SCODE(ERR_OSSL_EVP_ENCRYPT_FINAL,OSSL_ERR_DESC);

  // Update the total number of encrypted bytes
  encBytesTot += encBytes;

  // Free the encryption context
  EVP_CIPHER_CTX_free(aesEncCTX);

  // Safely delete the plaintext from its buffer
  OPENSSL_cleanse(&ptAddr[0], ptSize);

  // Return the resulting ciphertext's size
  return encBytesTot;
 }



