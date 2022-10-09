/* AES_128_GCM Manager Definitions */

/* ================================== INCLUDES ================================== */
#include <string>
#include "AESGCMMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


AESGCMMgr::AESGCMMgr(unsigned char* skey, IV* iv) : _aesGcmMgrState(READY), _aesGcmCTX(EVP_CIPHER_CTX_new()), _skey(skey), _iv(iv), _sizeTot(0), _sizePart(0)
 {
  if(!_aesGcmCTX)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);
 }



AESGCMMgr::~AESGCMMgr()
 {
  EVP_CIPHER_CTX_free(_aesGcmCTX);
 }


void AESGCMMgr::resetState()
 {
  _sizeTot = 0;
  _sizePart = 0;

  if(_aesGcmMgrState != READY)
   {
    EVP_CIPHER_CTX_free(_aesGcmCTX);

    // Initialize the cipher context for the next encryption/decryption
    _aesGcmCTX = EVP_CIPHER_CTX_new();
    if(!_aesGcmCTX)
     THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);

   // _iv->incIV();
   }

  _aesGcmMgrState = READY;
 }



void AESGCMMgr::encryptInit()
 {
  if(_aesGcmMgrState != READY)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in encryptInit()");

  // Initialize the cipher encryption context specifying the cipher, key and IV
  if(EVP_EncryptInit(_aesGcmCTX, EVP_aes_128_gcm(), _skey, reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_INIT, OSSL_ERR_DESC);

  _aesGcmMgrState = ENCRYPT_AAD;
 }


void AESGCMMgr::encryptAddAAD(unsigned char* aadAddr, int aadSize)
 {
  if(_aesGcmMgrState != ENCRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in encryptAddAAD()");

  // Set the authenticated associated data (AAD)
  if(EVP_EncryptUpdate(_aesGcmCTX, NULL, &_sizeTot, aadAddr, aadSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_UPDATE, OSSL_ERR_DESC);

  _aesGcmMgrState = ENCRYPT_UPDATE;
 }


int AESGCMMgr::encryptAddPT(unsigned char* ptAddr, int ptSize, unsigned char* ctDest)
 {
  if(_aesGcmMgrState != ENCRYPT_AAD && _aesGcmMgrState != ENCRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in encryptAddPT()");

  _aesGcmMgrState = ENCRYPT_UPDATE;

  // Encrypt the plaintext to the ciphertext's buffer
  if(EVP_EncryptUpdate(_aesGcmCTX, ctDest, &_sizePart, ptAddr, ptSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_UPDATE, OSSL_ERR_DESC);

  _sizeTot += _sizePart;

  // Safely delete the plaintext from its buffer
  OPENSSL_cleanse(&ptAddr[0], ptSize);

  return _sizeTot;
 }


int AESGCMMgr::encryptFinal(unsigned char* ctDest, unsigned char* tagDest)
 {
  if(_aesGcmMgrState != ENCRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in encryptFinal()");

  // Finalize the encryption by adding padding
  if(EVP_EncryptFinal(_aesGcmCTX, ctDest + _sizeTot, &_sizePart) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_FINAL, OSSL_ERR_DESC);

  // Resulting ciphertext size
  int ctSize = _sizeTot + _sizePart;

  // Extract and write the tag to the specified buffer
  if(EVP_CIPHER_CTX_ctrl(_aesGcmCTX, EVP_CTRL_AEAD_GET_TAG, 16, tagDest) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_GET_TAG_FAILED, OSSL_ERR_DESC);

  // Reset the manager's state
  resetState();

  // Return the resulting ciphertext size
  return ctSize;
 }


void AESGCMMgr::decryptInit()
 {
  if(_aesGcmMgrState != READY)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in decryptInit()");

  // Initialize the cipher encryption context specifying the cipher, key and IV
  if(EVP_DecryptInit(_aesGcmCTX, EVP_aes_128_gcm(), _skey, reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_INIT, OSSL_ERR_DESC);

  _aesGcmMgrState = DECRYPT_AAD;
 }



void AESGCMMgr::decryptAddAAD(unsigned char* aadAddr, int aadSize)
 {
  if(_aesGcmMgrState != DECRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in decryptAddAAD()");

  // Set the authenticated associated data (AAD)
  if(EVP_DecryptUpdate(_aesGcmCTX, NULL, &_sizeTot, aadAddr, aadSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_UPDATE, OSSL_ERR_DESC);

  _aesGcmMgrState = DECRYPT_UPDATE;
 }


int AESGCMMgr::decryptAddPT(unsigned char* ctAddr, int ctSize, unsigned char* ptDest)
 {
  if(_aesGcmMgrState != DECRYPT_UPDATE && _aesGcmMgrState != DECRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in decryptAddPT()");

  _aesGcmMgrState = DECRYPT_UPDATE;

  // Decrypt the ciphertext to the plaintext buffer
  if(EVP_DecryptUpdate(_aesGcmCTX, ptDest, &_sizePart, ctAddr, ctSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_UPDATE, OSSL_ERR_DESC);

  _sizeTot += _sizePart;;

  return _sizeTot;
 }


int AESGCMMgr::decryptFinal(unsigned char* ptDest, unsigned char* tagAddr)
 {
  if(_aesGcmMgrState != DECRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState) + " in decryptFinal()");

  // Set the expected tag value
  if(!EVP_CIPHER_CTX_ctrl(_aesGcmCTX, EVP_CTRL_AEAD_SET_TAG, 16, tagAddr))
   THROW_EXEC_EXCP(ERR_OSSL_SET_TAG_FAILED);

  // TODO: This is a session exception
  // Finalize the decryption by removing padding and verifying the tag
  if(EVP_DecryptFinal(_aesGcmCTX, ptDest + _sizeTot, &_sizePart) <= 0)
   THROW_SESS_EXCP(ERR_OSSL_DECRYPT_VERIFY_FAILED,OSSL_ERR_DESC);

  // Resulting ciphertext size
  int ptSize = _sizeTot + _sizePart;

  // Reset the manager's state
  resetState();

  // Return the resulting plaintext size
  return ptSize;
 }