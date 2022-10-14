/* SafeCloud Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SessMgr.h"
#include "errCodes/errCodes.h"
#include "SessMsg.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/* ============================= PROTECTED METHODS ============================= */

/* ------------------------------ Utility Methods ------------------------------ */

/**
 * @brief  Returns whether a session message type
 *         is a signaling session message type
 * @return 'true' if the provided session message type is
 *         a signaling session message type or 'false' otherwise
 */
bool SessMgr::isSessSignalingMsgType(SessMsgType sessMsgType)
 {
  // Check if the session message type is NOT a signaling session message
  // type, as there are less payload than signaling session message types
  if(sessMsgType == FILE_UPLOAD_REQ || sessMsgType == FILE_DOWNLOAD_REQ ||
    sessMsgType == FILE_DELETE_REQ || sessMsgType == FILE_RENAME_REQ ||
    sessMsgType == FILE_EXISTS || sessMsgType == POOL_INFO)
   return false;
  return true;
 }


/**
 * @brief Converts a session manager state to string
 * @return The session manager state as a string
 */
std::string SessMgr::sessMgrStateToStr(sessMgrState sesMgrState)
 {
  switch(sesMgrState)
   {
    case IDLE:
     return "idle";
    case UPLOAD:
     return "upload";
    case DOWNLOAD:
     return "download";
    case DELETE:
     return "delete";
    case RENAME:
     return "rename";
    case LIST:
     return "list";
   }
 }


/**
 * @brief Converts the current session manager state to string
 * @return The current session manager state as a string
 */
std::string SessMgr::currSessMgrStateToStr()
 { return sessMgrStateToStr(_sessMgrState); }


/**
 * @brief  Returns a string outlining the current
 *         operation that has been aborted, if any
 * @return A string outlining the current
 *         operation that has been aborted
 */
std::string SessMgr::abortedCmdToStr()
 {
  if(_sessMgrState != IDLE)
   return currSessMgrStateToStr() + " operation aborted";
  else
   return "no operation was aborted";
 }


/* -------------------- Session Messages Wrapping/Unwrapping -------------------- */

/**
 * @brief  Wraps a session message stored in the associated connection's
 *         secondary buffer into a session message wrapper in the connection's
 *         primary buffer, sending the resulting wrapper to the connection peer
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::wrapSendSessMsg()
 {
  /* ------------------ Session Message and Wrapper Sizes ------------------ */

  // Determine the size of the session message to be wrapped and send from
  // the first 16 bit of the associated connection manager's secondary buffer
  uint16_t sessMsgSize = ((uint16_t*)_connMgr._secBuf)[0];

  // Determine the session message wrapper size
  uint16_t sessWrapSize = sessMsgSize + sizeof(SessMsgWrapper);

  // Write the session message wrapper size in clear in the first
  // 16 bit of the associated connection manager's primary buffer
  memcpy(&_connMgr._priBuf[0], &sessWrapSize, sizeof(uint16_t));

  /* ---------------------- Session Message Encryption ---------------------- */

  // Initialize an AES_128_GCM encryption operation
  _aesGCMMgr.encryptInit();

  // Set the encryption operation's AAD to the session message wrapper size
  _aesGCMMgr.encryptAddAAD(reinterpret_cast<unsigned char*>(&sessWrapSize), sizeof(sessWrapSize));

  // Encrypt the session message from the secondary into the primary
  // connection buffer after the session message wrapper size
  _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0], sessMsgSize, &_connMgr._priBuf[sizeof(uint16_t)]);

  // Finalize the encryption by writing the resulting integrity tag after the encrypted
  // session message (or, equivalently, at the end of the session message wrapper)
  _aesGCMMgr.encryptFinal(&_connMgr._priBuf[sessWrapSize - AES_128_GCM_TAG_SIZE]);

  // Send the wrapped session message
  _connMgr.sendMsg();
 }


/**
 * @brief  Unwraps a session message wrapper stored in the associated connection's primary
 *         buffer into its associated session message in the connection's secondary buffer
 * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_DECRYPT_INIT      EVP_CIPHER decrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The AAD size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
 * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
 * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Session message integrity verification failed
 */
void SessMgr::unwrapSessMsg()
 {
  /* ------------------ Session Message and Wrapper Sizes ------------------ */

  // Determine the session message wrapper size as the first 16
  // bit of the associated connection manager's primary buffer
  uint16_t sessWrapSize = ((uint16_t*)_connMgr._priBuf)[0];

  // Determine the wrapped session message size by subtracting from the
  // session message wrapper size the constant size of a SessMsgWrapper struct
  uint16_t sessMsgSize = sessWrapSize - sizeof(SessMsgWrapper);

  /* ---------------------- Session Message Decryption ---------------------- */

  // Initialize an AES_128_GCM decryption operation
  _aesGCMMgr.decryptInit();

  // Set the decryption operation's AAD to the session message wrapper size
  _aesGCMMgr.decryptAddAAD(reinterpret_cast<unsigned char*>(&sessWrapSize), sizeof(sessWrapSize));

  // Decrypt the wrapped session message from the primary into the secondary connection buffer
  _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[sizeof(uint16_t)], sessMsgSize, &_connMgr._secBuf[0]);

  // Finalize the decryption by verifying the session wrapper's integrity tag
  _aesGCMMgr.decryptFinal(&_connMgr._priBuf[sessWrapSize - AES_128_GCM_TAG_SIZE]);
 }


/* --------------------- Session Signaling Messages Sending --------------------- */

/**
 * @brief Wraps and sends a session signaling message, i.e. a session
 *        session message with no payload, to the connection peer
 * @param sessMsgSignalingType          The session signaling message type to be sent
 * @throws ERR_SESS_INTERNAL_ERROR      Attempting to send a non-signaling session message
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::sendSessSignalMsg(SessMsgType sessMsgSignalingType)
 {
  // Ensure the session message type to be a signaling session message
  if(!isSessSignalingMsgType(sessMsgSignalingType))
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to send a non-signaling session message"
                                            "(" + std::to_string(sessMsgSignalingType) + ")");
   }

  // Interpret the contents of the connection manager's secondary buffer as a base session message
  SessMsg* sessSignalMsg = reinterpret_cast<SessMsg*>(_connMgr._secBuf);

  // Set the session message length to the size of a SessMsg struct
  sessSignalMsg->msgLen  = sizeof(SessMsg);

  // Set the session message type to the specified type
  sessSignalMsg->msgType = sessMsgSignalingType;

  // Wrap and send the session signaling message
  wrapSendSessMsg();
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Session manager object constructor, initializing
 *        session parameters and its child AESGCMMgr object
 * @param connMgr A reference to the connection manager parent object
 */
SessMgr::SessMgr(ConnMgr& connMgr)
  : _sessMgrState(IDLE), _connMgr(connMgr), _aesGCMMgr(_connMgr._skey, _connMgr._iv),
    _mainFileDscr(nullptr), _mainFileAbsPath(nullptr), _tmpFileDscr(nullptr),
    _tmpFileAbsPath(nullptr), _locFileInfo(nullptr), _remFileInfo(nullptr), _bytesRem(0),
    _recvSessMsgLen(0), _recvSessMsgType(ERR_UNKNOWN_SESSMSG_TYPE)
 {}

/**
 * @brief Session manager object destructor, performing cleanup operation
 * @note  It is assumed the secure erasure of the connection's cryptographic quantities
 *        (session key, IV) to be performed by the associated connection manager object
 */
SessMgr::~SessMgr()
 {
  // Reset the associated connection manager's reception mode to 'RECV_MSG'
  _connMgr._recvMode = ConnMgr::RECV_MSG;

  /* ------------------ Files Management Attributes Reset ------------------ */

  // If open, close the main file
  if(_mainFileDscr != nullptr)
   if(fclose(_mainFileDscr) != 0)
    LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_mainFileAbsPath, ERRNO_DESC);

  // If open, close the temporary file and delete it
  if(_tmpFileDscr != nullptr)
   {
    if(fclose(_tmpFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
    else
     if(remove(_tmpFileAbsPath->c_str()) == -1)
      LOG_EXEC_CODE(ERR_FILE_DELETE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
   }

  // Delete the dynamically allocated attributes
  delete _mainFileAbsPath;
  delete _tmpFileAbsPath;
  delete _locFileInfo;
  delete _remFileInfo;
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief Resets all session parameters in preparation to the next session command to be executed,
 *        also resetting the associated connection manager's reception mode to 'RECV_MSG'
 */
void SessMgr::resetSessState()
 {
  /* ------------------ General Session Attributes Reset ------------------ */
  // Reset the session manager state to 'IDLE'
  _sessMgrState = IDLE;

  // Reset the associated connection manager's reception mode to 'RECV_MSG'
  _connMgr._recvMode = ConnMgr::RECV_MSG;

  // Reset the state of the AESGCMMgr manager child object (causing its
  // IV to increment if an encryption or decryption operation was started)
  _aesGCMMgr.resetState();

  /* ------------------ Files Management Attributes Reset ------------------ */

  // If open, close the main file and reset its descriptor
  if(_mainFileDscr != nullptr)
   {
    if(fclose(_mainFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_mainFileAbsPath, ERRNO_DESC);
    _mainFileDscr = nullptr;
   }

  // Delete the main file absolute path and reset it
  delete _mainFileAbsPath;
  _mainFileAbsPath = nullptr;

  // If open, close the temporary file, delete it and reset its descriptor
  if(_tmpFileDscr != nullptr)
   {
    if(fclose(_tmpFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
    else
     if(remove(_tmpFileAbsPath->c_str()) == -1)
      LOG_EXEC_CODE(ERR_FILE_DELETE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
    _tmpFileDscr = nullptr;
   }

  // Delete the temporary file absolute path and reset it
  delete _tmpFileDscr;
  _tmpFileDscr = nullptr;

  // Delete the file name and metadata of the target local file
  delete _locFileInfo;
  _locFileInfo = nullptr;

  // Delete the file name and metadata of the target remote file
  delete _remFileInfo;
  _remFileInfo = nullptr;

  // Reset the number of bytes pending to be sent
  // or received in a raw data transmission
  _bytesRem = 0;

  /* -------------- Currently Received Session Message Header -------------- */

  // Reset the previously received session message header information
  _recvSessMsgLen = 0;
  _recvSessMsgType = ERR_UNKNOWN_SESSMSG_TYPE;

  // TODO: Remove
  printf("in resetSessState()\n");
 }