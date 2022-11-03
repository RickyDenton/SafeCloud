/* AES_128_GCM Manager Definitions */

/* ================================== INCLUDES ================================== */
#include "AESGCMMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief  AES_128_GCM object constructor, setting the session's cryptographic
 *         quantities and initializing the first cipher encryption or decryption context
 * @param  skey The AES_128_GCM symmetric key to be used in the secure communication (16 bytes)
 * @param  iv   The already-initialized IV to be used in the secure communication
 * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW EVP_CIPHER context creation failed
 */
AESGCMMgr::AESGCMMgr(unsigned char* skey, IV* iv)
 : _aesGcmMgrState(READY), _aesGcmCTX(EVP_CIPHER_CTX_new()),
   _skey(skey), _iv(iv), _sizeTot(0), _sizePart(0)
 {
  // Assert the cipher context to have been created
  if(!_aesGcmCTX)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);
 }


/**
 * @brief AES_128_GCM object destructor, freeing its prepared cipher context
 * @note  It is assumed the secure erasure of the connection's cryptographic quantities
 *        (session key, IV) to be performed by the associated connection manager object
 */
AESGCMMgr::~AESGCMMgr()
 { EVP_CIPHER_CTX_free(_aesGcmCTX); }


/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief  Resets the AES_128_GCM manager state so to be
 *         ready for a new encryption or decryption operation
 * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW EVP_CIPHER context creation failed
 */
void AESGCMMgr::resetState()
 {
  // Reset the total and partial number of encrypted or decrypted bytes
  _sizeTot = 0;
  _sizePart = 0;

  // If an encryption or decryption operation
  // has been completed or is in progress
  if(_aesGcmMgrState != READY)
   {
    // Free the current cipher context
    EVP_CIPHER_CTX_free(_aesGcmCTX);

    // Initialize a new cipher context for the
    // next encryption or decryption operation
    _aesGcmCTX = EVP_CIPHER_CTX_new();
    if(!_aesGcmCTX)
     THROW_EXEC_EXCP(ERR_OSSL_EVP_CIPHER_CTX_NEW, OSSL_ERR_DESC);

    // Increment the IV value
    _iv->incIV();
   }

  // Set the manager state to 'READY'
  _aesGcmMgrState = READY;
 }


/* ---------------------------- Encryption Operation ---------------------------- */

/**
 * @brief  Starts a new AES_128_GCM encryption operation within the manager
 * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT   EVP_CIPHER encrypt initialization failed
 */
void AESGCMMgr::encryptInit()
 {
  // Assert the manager to be ready to start an encryption operation
  if(_aesGcmMgrState != READY)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in encryptInit()");

  // Initialize the cipher encryption context specifying the cipher, key and IV
  if(EVP_EncryptInit(_aesGcmCTX, EVP_aes_128_gcm(), _skey,
                     reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_INIT, OSSL_ERR_DESC);

  // Set the manager to expect up to one AAD block (if any) for encryption
  _aesGcmMgrState = ENCRYPT_AAD;
 }


/**
 * @brief Add the single, optional AAD block in the manager current encryption operation
 * @param aadAddr The AAD initial address
 * @param aadSize The AAD size
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 */
void AESGCMMgr::encryptAddAAD(unsigned char* aadAddr, int aadSize)
 {
  // Assert the manager to be expecting encryption AAD
  if(_aesGcmMgrState != ENCRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in encryptAddAAD()");

  // Assert the AAD block size to be positive
  if(aadSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "aadSize = " + std::to_string(aadSize));

  /*
  // LOG: AAD Block in hexadecimal
  char aadBlockHex[(aadSize*2)+1];
  for(int i = 0; i < aadSize; i++)
   sprintf(aadBlockHex + 2 * i, "%.2x",aadAddr[i]);
  aadBlockHex[2 * aadSize] = '\0';
  printf("aadBlockHex = %s\n",aadBlockHex);
  */

  // Set the encryption AAD block
  if(EVP_EncryptUpdate(_aesGcmCTX, NULL, &_sizeTot, aadAddr, aadSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_UPDATE, OSSL_ERR_DESC);

  // Set the manager to expect any number of plaintext blocks for encryption
  _aesGcmMgrState = ENCRYPT_UPDATE;
 }


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
int AESGCMMgr::encryptAddPT(unsigned char* ptAddr, int ptSize, unsigned char* ctDest)
 {
  // Assert the manager to be expecting either
  // the AAD or a plaintext block for encryption
  if(_aesGcmMgrState != ENCRYPT_AAD && _aesGcmMgrState != ENCRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in encryptAddPT()");

  // Set the manager to expect any number of plaintext blocks for encryption
  _aesGcmMgrState = ENCRYPT_UPDATE;

  // Assert the plaintext block size to be positive
  if(ptSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "ptSize = " + std::to_string(ptSize));

  // Encrypt the plaintext block to the ciphertext buffer
  if(EVP_EncryptUpdate(_aesGcmCTX, ctDest, &_sizePart, ptAddr, ptSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_UPDATE, OSSL_ERR_DESC);

  /*
  // LOG: Plaintext Block in hexadecimal
  char ptBlockHex[(ptSize*2)+1];
  for(int i = 0; i < ptSize; i++)
   sprintf(ptBlockHex + 2 * i, "%.2x",ptAddr[i]);
  ptBlockHex[2 * ptSize] = '\0';
  printf("ptBlockHex = %s\n",ptBlockHex);

  // LOG: Ciphertext Block in hexadecimal
  char ctBlockHex[(ptSize*2)+1];
  for(int i = 0; i < ptSize; i++)
   sprintf(ctBlockHex + 2 * i, "%.2x",ctDest[i]);
  ctBlockHex[2 * ptSize] = '\0';
  printf("ctBlockHex = %s\n",ctBlockHex);

  // LOG: IV in hexadecimal
  char ivHex[25];
  for(int i = 0; i < 12; i++)
   sprintf(ivHex + 2 * i, "%.2x", reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))[i]);
  ivHex[24] = '\0';
  printf("ivHex = %s\n",ivHex);
  */

  // Update the encryption operation's cumulative ciphertext size
  _sizeTot += _sizePart;

  // Safely delete the plaintext from its buffer
  OPENSSL_cleanse(&ptAddr[0], ptSize);

  // Return the encryption operation's cumulative ciphertext size (AAD included)
  return _sizeTot;
 }


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
int AESGCMMgr::encryptFinal(unsigned char* tagDest)
 {
  // Assert the manager to be expecting a plaintext block for encryption
  if(_aesGcmMgrState != ENCRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in encryptFinal()");

  // Finalize the encryption operation
  if(EVP_EncryptFinal(_aesGcmCTX, NULL, &_sizePart) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_ENCRYPT_FINAL, OSSL_ERR_DESC);

  // Encryption operation resulting ciphertext size (AAD included)
  int ctSize = _sizeTot + _sizePart;

  // Extract the encryption operation's integrity
  // tag and write it into the specified buffer
  if(EVP_CIPHER_CTX_ctrl(_aesGcmCTX, EVP_CTRL_AEAD_GET_TAG, 16, tagDest) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_GET_TAG_FAILED, OSSL_ERR_DESC);

  /*
  // LOG: Integrity tag in hexadecimal
  char tagHex[33];
  for(int i = 0; i < 12; i++)
   sprintf(tagHex + 2 * i, "%.2x", tagDest[i]);
  tagHex[32] = '\0';
  printf("tagHex = %s\n",tagHex);
  */

  // Reset the AES_128_GCM manager state so to be ready
  // for a new encryption or decryption operation
  resetState();

  // Return the encryption operation resulting ciphertext size (AAD included)
  return ctSize;
 }


/* ---------------------------- Decryption Operation ---------------------------- */

/**
 * @brief  Starts a new AES_128_GCM decryption operation within the manager
 * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_DECRYPT_INIT   EVP_CIPHER decrypt initialization failed
 */
void AESGCMMgr::decryptInit()
 {
  // Assert the manager to be ready to start a decryption operation
  if(_aesGcmMgrState != READY)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in decryptInit()");

  // Initialize the cipher decryption context specifying the cipher, key and IV
  if(EVP_DecryptInit(_aesGcmCTX, EVP_aes_128_gcm(), _skey,
                     reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_INIT, OSSL_ERR_DESC);

  // Set the manager to expect up to one AAD block (if any) for decryption
  _aesGcmMgrState = DECRYPT_AAD;
 }


/**
 * @brief Add the single, optional AAD block in the manager current decryption operation
 * @param aadAddr The AAD initial address
 * @param aadSize The AAD size
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE  EVP_CIPHER decrypt update failed
 */
void AESGCMMgr::decryptAddAAD(unsigned char* aadAddr, int aadSize)
 {
  // Assert the manager to be expecting decryption AAD
  if(_aesGcmMgrState != DECRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in decryptAddAAD()");

  // Assert the AAD size to be positive
  if(aadSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "aadSize = " + std::to_string(aadSize));

  /*
  // LOG: AAD Block in hexadecimal
  char aadBlockHex[(aadSize*2)+1];
  for(int i = 0; i < aadSize; i++)
   sprintf(aadBlockHex + 2 * i, "%.2x",aadAddr[i]);
  aadBlockHex[2 * aadSize] = '\0';
  printf("aadBlockHex = %s\n",aadBlockHex);
  */

  // Set the decryption AAD block
  if(EVP_DecryptUpdate(_aesGcmCTX, NULL, &_sizeTot, aadAddr, aadSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_UPDATE, OSSL_ERR_DESC);

  // Set the manager to expect any number of ciphertext blocks for encryption
  _aesGcmMgrState = DECRYPT_UPDATE;
 }


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
int AESGCMMgr::decryptAddCT(unsigned char* ctAddr, int ctSize, unsigned char* ptDest)
 {
  // Assert the manager to be expecting either the AAD or a ciphertext block for decryption
  if(_aesGcmMgrState != DECRYPT_UPDATE && _aesGcmMgrState != DECRYPT_AAD)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in decryptAddCT()");

  // Set the manager to expect any number of ciphertext blocks for encryption
  _aesGcmMgrState = DECRYPT_UPDATE;

  // Assert the ciphertext block size to be positive
  if(ctSize <= 0)
   THROW_EXEC_EXCP(ERR_NON_POSITIVE_BUFFER_SIZE, "ctSize = " + std::to_string(ctSize));

  // Decrypt the ciphertext block to the plaintext buffer
  if(EVP_DecryptUpdate(_aesGcmCTX, ptDest, &_sizePart, ctAddr, ctSize) != 1)
   THROW_EXEC_EXCP(ERR_OSSL_EVP_DECRYPT_UPDATE, OSSL_ERR_DESC);

  /*
  // LOG: Plaintext Block in hexadecimal
  char ptBlockHex[(ctSize*2)+1];
  for(int i = 0; i < ctSize; i++)
   sprintf(ptBlockHex + 2 * i, "%.2x",ptDest[i]);
  ptBlockHex[2 * ctSize] = '\0';
  printf("ptBlockHex = %s\n",ptBlockHex);

  // LOG: Ciphertext Block in hexadecimal
  char ctBlockHex[(ctSize*2)+1];
  for(int i = 0; i < ctSize; i++)
   sprintf(ctBlockHex + 2 * i, "%.2x",ctAddr[i]);
  ctBlockHex[2 * ctSize] = '\0';
  printf("ctBlockHex = %s\n",ctBlockHex);

  // LOG: IV in hexadecimal
  char ivHex[25];
  for(int i = 0; i < 12; i++)
   sprintf(ivHex + 2 * i, "%.2x", reinterpret_cast<const unsigned char*>(&(_iv->iv_AES_GCM))[i]);
  ivHex[24] = '\0';
  printf("ivHex = %s\n",ivHex);
  */

  // Update and return the decryption operation's cumulative plaintext size
  _sizeTot += _sizePart;
  return _sizeTot;
 }


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
int AESGCMMgr::decryptFinal(unsigned char* tagAddr)
 {
  // Assert the manager to be expecting either the AAD or a ciphertext block for decryption
  if(_aesGcmMgrState != DECRYPT_UPDATE)
   THROW_EXEC_EXCP(ERR_AESGCMMGR_INVALID_STATE, "state " + std::to_string(_aesGcmMgrState)
                                                         + " in decryptFinal()");

  // Set the decryption operation's expected integrity tag
  if(!EVP_CIPHER_CTX_ctrl(_aesGcmCTX, EVP_CTRL_AEAD_SET_TAG, 16, tagAddr))
   THROW_EXEC_EXCP(ERR_OSSL_SET_TAG_FAILED);

  /*
  // LOG: Integrity tag in hexadecimal
  char tagHex[33];
  for(int i = 0; i < 12; i++)
   sprintf(tagHex + 2 * i, "%.2x", tagAddr[i]);
  tagHex[32] = '\0';
  printf("tagHex = %s\n",tagHex);
  */

  // Finalize the decryption operation by validating the integrity
  // of the resulting plaintext against the expected integrity tag
  if(EVP_DecryptFinal(_aesGcmCTX, NULL, &_sizePart) <= 0)
   {
    ERR_print_errors_fp(stderr);
    THROW_SESS_EXCP(ERR_OSSL_DECRYPT_VERIFY_FAILED, OSSL_ERR_DESC);
   }

  // Decryption operation resulting plaintext size (AAD included)
  int ptSize = _sizeTot + _sizePart;

  // Reset the AES_128_GCM manager state so to be ready
  // for a new encryption or decryption operation
  resetState();

  // Return the decryption operation resulting plaintext size (AAD included)
  return ptSize;
 }