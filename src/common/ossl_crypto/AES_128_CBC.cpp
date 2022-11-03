/* OpenSSL AES_128_CBC Utility Functions Definitions */

/* ================================== INCLUDES ================================== */
#include "AES_128_CBC.h"
#include "errCodes/execErrCodes/execErrCodes.h"


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief        Encrypts a plaintext using the AES_128 cipher in CBC mode,
 *               safely deleting the plaintext and incrementing the IV afterwards
 * @param key    The AES_128 encryption key (128 bit, 16 bytes)
 * @param iv     The encryption's IV        (128 bit, 16 bytes)
 * @param ptAddr The plaintext initial address
 * @param ptSize The plaintext size (must be <= INT_MAX - AES_BLOCK_SIZE = 2^16 - 1 - 16 bytes)
 * @param ctDest The address where to write the resulting ciphertext
 * @return       The resulting ciphertext's size in bytes
 * @note         The function assumes the "ctDest" destination buffer to be large
 *               enough to contain the resulting ciphertext (i.e. at least ptSize
 *               + AES_BLOCK_SIZE to account for the additional full padding block)
 * @throws       ERR_NON_POSITIVE_BUFFER_SIZE      The plaintext size is non-positive (probable overflow)
 * @throws       ERR_OSSL_AES_128_CBC_PT_TOO_LARGE The plaintext to encrypt is too large
 * @throws       ERR_OSSL_EVP_CIPHER_CTX_NEW       EVP_CIPHER context creation failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_INIT         EVP_CIPHER encrypt initialization failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_UPDATE       EVP_CIPHER encrypt update failed
 * @throws       ERR_OSSL_EVP_ENCRYPT_FINAL        EVP_CIPHER encrypt final failed
 */
int AES_128_CBC_Encrypt(const unsigned char* key, IV* iv, unsigned char* ptAddr, int ptSize, unsigned char* ctDest)
 {
  // Cipher encryption context
  EVP_CIPHER_CTX* aesEncCTX;

  // The number of encrypted bytes at an encryption's step (EVP_EncryptUpdate or EVP_EncryptFinal)
  int encBytes;

  // The total number of encrypted bytes, representing at the end the resulting ciphertext size
  int encBytesTot;

  // Assert the plaintext size to be positive
  if(ptSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "ptSize = " + std::to_string(ptSize));

  // Assert the resulting ciphertext maximum size (ptSize + AES_BLOCK_SIZE) not to overflow
  // on an "int" type, case in which an erroneous negative ciphertext size would be returned
  if(ptSize > INT_MAX - AES_BLOCK_SIZE)
   THROW_EXEC_EXCP(ERR_OSSL_AES_128_CBC_PT_TOO_LARGE, std::to_string(ptSize));

  // Create the cipher encryption context
  aesEncCTX = EVP_CIPHER_CTX_new();
  if(!aesEncCTX)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);

  // Initialize the cipher encryption context specifying the cipher, key and IV
  if(EVP_EncryptInit(aesEncCTX, EVP_aes_128_cbc(), key,
                     reinterpret_cast<const unsigned char*>(&(iv->iv_AES_CBC))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_INIT, OSSL_ERR_DESC);

  // Encrypt the plaintext to the ciphertext's buffer
  if(EVP_EncryptUpdate(aesEncCTX, ctDest, &encBytes, ptAddr, ptSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_UPDATE, OSSL_ERR_DESC);

  // Update the total number of encrypted bytes
  encBytesTot = encBytes;

  // Finalize the encryption by adding padding
  if(EVP_EncryptFinal(aesEncCTX, ctDest + encBytesTot, &encBytes) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_FINAL, OSSL_ERR_DESC);

  // Update the total number of encrypted bytes
  encBytesTot += encBytes;

  // Free the cipher encryption context
  EVP_CIPHER_CTX_free(aesEncCTX);

  // Safely delete the plaintext from its buffer
  OPENSSL_cleanse(&ptAddr[0], ptSize);

  // Increment the IV (with IV reuse not being
  // accounted for as explained in function's @note)
  iv->incIV();

  // Return the resulting ciphertext size
  return encBytesTot;
 }


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
int AES_128_CBC_Decrypt(const unsigned char* key, IV* iv, unsigned char* ctAddr, int ctSize, unsigned char* ptDest)
 {
  // Cipher decryption context
  EVP_CIPHER_CTX* aesDecCTX;

  // The number of decrypted bytes at a decryption step (EVP_DecryptUpdate or EVP_DecryptFinal)
  int decBytes;

  // The total number of decrypted bytes, representing at the end the resulting plaintext size
  int decBytesTot;

  // Assert the ciphertext size to be positive
  if(ctSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "ctSize = " + std::to_string(ctSize));

  // Create the cipher decryption context
  aesDecCTX = EVP_CIPHER_CTX_new();
  if(!aesDecCTX)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);

  // Initialize the cipher decryption context specifying the cipher, key and IV
  if(EVP_DecryptInit(aesDecCTX, EVP_aes_128_cbc(), key,
                     reinterpret_cast<const unsigned char*>(&(iv->iv_AES_CBC))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_INIT, OSSL_ERR_DESC);

  // Decrypt the ciphertext to the plaintext buffer
  if(EVP_DecryptUpdate(aesDecCTX, ptDest, &decBytes, ctAddr, ctSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_UPDATE, OSSL_ERR_DESC);

  // Update the total number of decrypted bytes
  decBytesTot = decBytes;

  // Finalize the decryption by removing padding
  if(EVP_DecryptFinal(aesDecCTX, ptDest + decBytesTot, &decBytes) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_FINAL, OSSL_ERR_DESC);

  // Update the total number of decrypted bytes
  decBytesTot += decBytes;

  // Free the cipher decryption context
  EVP_CIPHER_CTX_free(aesDecCTX);

  // Increment the IV (with IV reuse not being
  // accounted for as explained in function's @note)
  iv->incIV();

  // Return the resulting plaintext size
  return decBytesTot;
 }