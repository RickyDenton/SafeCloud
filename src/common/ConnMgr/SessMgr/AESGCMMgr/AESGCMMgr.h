#ifndef SAFECLOUD_AESGCMMGR_H
#define SAFECLOUD_AESGCMMGR_H

/* AES_128_GCM Manager Declarations */

/* ================================== INCLUDES ================================== */
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "ConnMgr/IV/IV.h"

enum AESGCMMgrState : uint8_t
 {
  READY = 0,           // Ready for an encryption or decryption operation
  ENCRYPT_AAD,
  ENCRYPT_UPDATE,
  DECRYPT_AAD,
  DECRYPT_UPDATE
 };


class AESGCMMgr
 {
  private:
   AESGCMMgrState  _aesGcmMgrState;
   EVP_CIPHER_CTX* _aesGcmCTX;       // The cipher context used for both AES_GCM encryption and decryption
   unsigned char*  _skey;            // The AES_GCM symmetric key
   IV*             _iv;              // The AES_GCM IV
   int             _sizeTot;         // The total number of bytes encrypted or decrypted, eventually representing the resulting ciphertext (encryption) or plaintext (decryption) size
   int             _sizePart;        // The number of bytes encrypted or decrypted by the last OpenSSL API call (helper variable)

  public:

   AESGCMMgr(unsigned char* skey, IV* iv);
   ~AESGCMMgr();

   void resetState();

   void encryptInit();

   void encryptAddAAD(unsigned char* aadAddr, int aadSize);

   int encryptAddPT(unsigned char* ptAddr, int ptSize, unsigned char* ctDest);

   int encryptFinal(unsigned char* ctDest, unsigned char* tagDest);

   void decryptInit();

   void decryptAddAAD(unsigned char* aadAddr, int aadSize);

   int decryptAddPT(unsigned char* ctAddr, int ctSize, unsigned char* ptDest);

   int decryptFinal(unsigned char* ptDest, unsigned char* tagAddr);
 };



#endif //SAFECLOUD_AESGCMMGR_H
