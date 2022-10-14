#ifndef SAFECLOUD_AESGCMMGR_H
#define SAFECLOUD_AESGCMMGR_H

/*
 * This class represents the AES_128_GCM Manager used for encrypting, decrypting, and asserting
 * the integrity of data exchanged between the SafeCloud server and client in the session phase
 */

/* ================================== INCLUDES ================================== */
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "ConnMgr/IV/IV.h"

#define AES_128_GCM_TAG_SIZE 16

class AESGCMMgr
 {
  private:

   // AES_128_GCM Manager State enumeration
   enum AESGCMMgrState : uint8_t
    {
     READY = 0,       // Ready to start an encryption or decryption operation
     ENCRYPT_AAD,     // Expecting up to one Associated Authenticated Data (AAD) block (if any) for encryption
     ENCRYPT_UPDATE,  // Expecting one or more plaintext blocks for encryption
     DECRYPT_AAD,     // Expecting up to one Associated Authenticated Data (AAD) block (if any) for decryption
     DECRYPT_UPDATE   // Expecting one or more ciphertext blocks for decryption
    };

   /* ================================= ATTRIBUTES ================================= */

   // The current manager state
   AESGCMMgrState  _aesGcmMgrState;

   // The cipher context used in the current or the next AES_128_GCM encryption or decryption operation
   EVP_CIPHER_CTX* _aesGcmCTX;

   // A pointer to the AES_128_GCM symmetric key of AES_128_KEY_SIZE = 16 bytes
   unsigned char* _skey;

   // A pointer to the connection's initialization vector
   IV* _iv;

   // The total number of bytes encrypted or decrypted in the current encryption or decryption
   // operation, eventually representing the resulting ciphertext or plaintext size including any AAD
   int _sizeTot;

   // The number of bytes encrypted or decrypted by the last OpenSSL API call
   int _sizePart;

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  AES_128_GCM object constructor, setting the session's cryptographic
    *         quantities and initializing the first cipher encryption or decryption context
    * @param  skey The AES_128_GCM symmetric key to be used in the secure communication (16 bytes)
    * @param  iv   The already-initialized IV to be used in the secure communication
    * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW EVP_CIPHER context creation failed
    */
   AESGCMMgr(unsigned char* skey, IV* iv);

   /**
    * @brief AES_128_GCM object destructor, freeing its prepared cipher context
    * @note  It is assumed the secure erasure of the connection's cryptographic quantities
    *        (session key, IV) to be performed by the associated connection manager object
    */
   ~AESGCMMgr();

   /* ============================ OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Resets the AES_128_GCM manager state so to be
    *         ready for a new encryption or decryption operation
    * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW EVP_CIPHER context creation failed
    */
   void resetState();

   /* ---------------------------- Encryption Operation ---------------------------- */

   /**
    * @brief  Starts a new AES_128_GCM encryption operation within the manager
    * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT   EVP_CIPHER encrypt initialization failed
    */
   void encryptInit();

   /**
    * @brief Add the single, optional AAD block in the manager current encryption operation
    * @param aadAddr The AAD initial address
    * @param aadSize The AAD size
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    */
   void encryptAddAAD(unsigned char* aadAddr, int aadSize);

   /**
    * @brief Encrypts a plaintext block in the manager current
    *        encryption operation, safely deleting it afterwards
    * @param ptAddr The plaintext block initial address
    * @param ptSize The plaintext block size
    * @param ctDest The address where to write the resulting ciphertext block
    * @note         The function assumes the "ctDest" destination buffer to be large enough
    *               to contain the resulting ciphertext block (at least 'ptSize' bytes)
    * @return       The encryption operation's cumulative ciphertext size (AAD included)
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The plaintext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    */
   int encryptAddPT(unsigned char* ptAddr, int ptSize, unsigned char* ctDest);

   /**
    * @brief  Finalizes the manager current encryption operation and
    *         writes its resulting integrity tag into the specified buffer
    * @param  tagDest The buffer where to write the resulting integrity tag to (16 bytes)
    * @return The encryption operation's resulting ciphertext size (AAD included)
    * @note   The function assumes the "tagDest" buffer to be be large
    *         enough to contain the resulting integrity tag (16 bytes)
    * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL  EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED     Error in retrieving the resulting integrity tag
    */
   int encryptFinal(unsigned char* tagDest);

   /* ---------------------------- Decryption Operation ---------------------------- */

   /**
    * @brief  Starts a new AES_128_GCM decryption operation within the manager
    * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_DECRYPT_INIT   EVP_CIPHER decrypt initialization failed
    */
   void decryptInit();

   /**
    * @brief Add the single, optional AAD block in the manager current decryption operation
    * @param aadAddr The AAD initial address
    * @param aadSize The AAD size
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE  EVP_CIPHER decrypt update failed
    */
   void decryptAddAAD(unsigned char* aadAddr, int aadSize);

   /**
    * @brief  Decrypts a ciphertext block in the manager current decryption operation
    * @param  ctAddr The ciphertext block initial address
    * @param  ctSize The ciphertext block size
    * @param  ptDest The address where to write the resulting plaintext block
    * @return The decryption operation's cumulative plaintext size (AAD included)
    * @note   The function assumes the "ptDest" destination buffer to be large enough
    *         to contain the resulting plaintext block (at least 'ctSize' bytes)
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The ciphertext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE  EVP_CIPHER decrypt update failed
    */
   int decryptAddCT(unsigned char* ctAddr, int ctSize, unsigned char* ptDest);


   /**
    * @brief  Finalizes the manager current decryption operation and validates the
    *         integrity of the resulting plaintext against the expected integrity tag
    * @param  tagAddr The buffer where to read the expected integrity tag from (16 bytes)
    * @return The decryption operation's resulting plaintext size (AAD included)
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Plaintext integrity verification failed
    * @note   EVP_DecryptFinal() errors are all assimilated to plaintext integrity
    *         verification failures, which are thrown as session exceptions (sessErrExcp)
    *         so to preserve the connection between the SafeCloud server and client
    */
   int decryptFinal(unsigned char* tagAddr);
 };


#endif //SAFECLOUD_AESGCMMGR_H
