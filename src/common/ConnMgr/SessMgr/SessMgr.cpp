/* SafeCloud Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <sys/time.h>
#include <fstream>
#include "SessMgr.h"
#include "errCodes/errCodes.h"
#include "SessMsg.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "utils.h"


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
     sessMsgType == FILE_EXISTS || sessMsgType == POOL_SIZE)
   return false;
  return true;
 }


/**
 * @brief   Returns whether a session message type
 *          is a signaling error session message type
 * @return 'true' if the provided session message type is a signaling
 *          error session message type or 'false' otherwise
 */
bool SessMgr::isSessErrSignalingMsgType(SessMsgType sessMsgType)
 {
  if(sessMsgType == ERR_INTERNAL_ERROR || sessMsgType == ERR_UNEXPECTED_SESS_MESSAGE ||
     sessMsgType == ERR_MALFORMED_SESS_MESSAGE || sessMsgType == ERR_UNKNOWN_SESSMSG_TYPE)
   return true;
  return false;
 }


/**
 * @brief  Converts the current session manager operation to a lowercase string
 * @return The current session manager operation as a lowercase string
 */
std::string SessMgr::sessMgrOpToStrLowCase()
 {
  switch(_sessMgrOp)
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
 * @brief  Converts the current session manager operation to a uppercase string
 * @return The current session manager operation as a uppercase string
 */
std::string SessMgr::sessMgrOpToStrUpCase()
 {
  switch(_sessMgrOp)
   {
    case IDLE:
     return "'IDLE'";
    case UPLOAD:
     return "'UPLOAD'";
    case DOWNLOAD:
     return "'DOWNLOAD'";
    case DELETE:
     return "'DELETE'";
    case RENAME:
     return "'RENAME'";
    case LIST:
     return "'LIST'";
   }
 }


/**
 * @brief  Converts the current session manager operation step to a uppercase string
 * @return The current session manager operation step as a uppercase string
 */
std::string SessMgr::sessMgrOpStepToStrUpCase()
 {
  switch(_sessMgrOpStep)
   {
    case OP_START:
     return "'OP_START'";
    case WAITING_RESP:
     return "'WAITING_RESP'";
    case WAITING_CONF:
     return "'WAITING_CONF'";
    case WAITING_RAW:
     return "'WAITING_RAW'";
    case WAITING_COMPL:
     return "'WAITING_COMPL'";
   }
 }


/**
 * @brief  Returns a string outlining the current session manager
 *         operation, if any, that has been aborted in case of errors
 * @return A string outlining the current session manager operation,
 *         if any, that has been aborted in case of errors
 */
std::string SessMgr::abortedOpToStr()
 {
  if(_sessMgrOp != IDLE)
   return sessMgrOpToStrLowCase() + " operation aborted";
  else
   return "no operation was aborted";
 }


/* --------------------------- Session Files Methods --------------------------- */

/**
 * @brief  Asserts a string received from the connection
 *         peer to represent a valid Linux file name
 * @param  fileName The received file name string to be validated
 * @throws ERR_MALFORMED_SESS_MESSAGE The received string is not
 *                                    a valid Linux file name
 */
void SessMgr::validateRecvFileName(std::string& fileName)
 {
  // Assert the received file name string
  // to consist of a valid Linux file name
  try
   {  validateFileName(fileName); }
  catch(sessErrExcp& invalidFileNameExcp)
   {
    // If the file name string does not represent a valid
    // Linux file name, then the received message is malformed
    sendSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE);
    THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Invalid file name in the received session "
                                               "message (\"" + fileName + "\")");
   }
 }


/**
 * @brief Attempts to load into the '_mainFileInfo' attribute the information
 *        of the main file referred by the '_mainFileAbsPath' attribute
 * @throws ERR_SESS_INTERNAL_ERROR   The '_mainFileAbsPath' attribute has not been initialized
 * @throws ERR_SESS_MAIN_FILE_IS_DIR The main file was found to be a directory (!)
 */
void SessMgr::checkLoadMainFileInfo()
 {
  // Ensure the '_mainFileAbsPath' attribute to have been initialized
  if(_mainFileAbsPath == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to load the main file information time with a NULL '_mainFileAbsPath'");
   }

  // Attempt to load into the '_mainFileInfo' attribute the information
  // of the main file referred by the '_mainFileAbsPath' attribute
  try
   { _mainFileInfo = new FileInfo(*_mainFileAbsPath); }
  catch(sessErrExcp& mainFileError)
   {
    // If the main file was found to be a directory (!), notify the
    // connection peer of the internal error and rethrow the exception
    if(mainFileError.sesErrCode == ERR_SESS_FILE_IS_DIR)
     {
      sendSessSignalMsg(ERR_INTERNAL_ERROR);
      THROW_SESS_EXCP(ERR_SESS_MAIN_FILE_IS_DIR, *_mainFileAbsPath);
     }

    // Otherwise the main file was not found in the session's main directory
    _mainFileInfo = nullptr;
   }
 }


/**
 * @brief  Sets the main file last modification time to the one specified in the '_remFileInfo' attribute
 * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
 * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
 */
void SessMgr::mainToRemLastModTime()
 {
  // Ensure the '_mainFileAbsPath' attribute to have been initialized
  if(_mainFileAbsPath == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to mirror a last modification time with a NULL '_mainFileAbsPath'");
   }

  // Ensure the '_remFileInfo' attribute to have been initialized
  if(_remFileInfo == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to mirror a last modification time with a NULL '_remFileInfo'");
   }

  // Write the remote file last modification time in the second element of a 'timeval' array
  timeval timesArr[] = {{}, {_remFileInfo->meta->lastModTimeRaw, 0}};

  // Attempt to set the main file last modification time to the one specified in the '_remFileInfo' attribute
  if(utimes(_mainFileAbsPath->c_str(), timesArr) == -1)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_META_SET_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }
 }


/**
 * @brief  If present deletes the main empty file for then touching it and setting its
 *         last modified time to the one specified in the '_remFileInfo' attribute
 * @note   If present the main file is preliminarily deleted
 *         for the purposes of updating its creation time
 * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
 * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the main file
 * @throws ERR_SESS_FILE_OPEN_FAILED     Error in touching the main file
 * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the main file
 * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
 */
void SessMgr::touchEmptyFile()
 {
  // Ensure the '_mainFileAbsPath' attribute to have been initialized
  if(_mainFileAbsPath == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to touch an empty file with a NULL '_mainFileAbsPath'");
   }

  // Ensure the '_remFileInfo' attribute to have been initialized
  if(_remFileInfo == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to touch an empty file with a NULL '_remFileInfo'");
   }

  // If the main file already exists, delete it for
  // the purposes of updating its creation time
 if(_mainFileInfo != nullptr && remove(_mainFileAbsPath->c_str()) == -1)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_DELETE_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }

  // Touch the main empty file
  std::ofstream upFile(*_mainFileAbsPath);
  if(!upFile)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }

  // Close the main empty file
  upFile.close();
  if(upFile.fail())
   LOG_SESS_CODE(ERR_SESS_FILE_CLOSE_FAILED,*_mainFileAbsPath,ERRNO_DESC);

  // Set the main file last modification time to the one specified in the '_remFileInfo' attribute
  mainToRemLastModTime();
 }


/* -------------------------- Session Raw Send/Receive -------------------------- */

/**
 * @brief  Sends the AES_128_GCM integrity tag associated with
 *         the raw data that has been sent to the connection peer
 * @throws ERR_AESGCMMGR_INVALID_STATE Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED    Error in retrieving the resulting integrity tag
 * @throws ERR_SEND_OVERFLOW          Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED      The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED            send() fatal error
 */
void SessMgr::sendRawTag()
 {
  // Finalize the file encryption operation by writing the resulting
  // integrity tag at the start of the primary connection buffer
  _aesGCMMgr.encryptFinal(&_connMgr._priBuf[0]);

  // Send the file integrity tag to the client
  _connMgr.sendRaw(AES_128_GCM_TAG_SIZE);
 }


/**
 * @brief  Prepares the session manager to receive the raw
 *         contents of a file being uploaded or downloaded
 * @throws ERR_SESSABORT_INTERNAL_ERROR  Invalid session manager operation or step
 *                                       for receiving a file's raw contents
 * @throws ERR_SESS_FILE_OPEN_FAILED     Failed to open the temporary file
 *                                       descriptor in write-byte mode
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_DECRYPT_INIT     EVP_CIPHER decrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SessMgr::prepRecvFileRaw()
 {
  // Assert the session manager to be in the 'UPLOAD' or 'DOWNLOAD' operation
  if(_sessMgrOp != UPLOAD && _sessMgrOp != DOWNLOAD)
   THROW_EXEC_EXCP(ERR_SESSABORT_INTERNAL_ERROR, "Preparing to receive a file's raw contents with the "
                                                 "session manager in operation \"" + sessMgrOpToStrUpCase() +
                                                 "\", step " + sessMgrOpStepToStrUpCase());

  // Update the session manager step so to expect raw data
  _sessMgrOpStep = WAITING_RAW;

  // Set the reception mode of the associated connection manager to 'RECV_RAW'
  _connMgr._recvMode = ConnMgr::RECV_RAW;

  // Set the associated connection manager's expected data
  // block size to the size of the file to be received
  _connMgr._recvBlockSize = _remFileInfo->meta->fileSizeRaw;

  // Initialize the number of raw bytes to be received to the file size
  _rawBytesRem = _remFileInfo->meta->fileSizeRaw;

  // Open the temporary file descriptor in write-byte mode
  _tmpFileDscr = fopen(_tmpFileAbsPath->c_str(), "wb");
  if(!_tmpFileDscr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED,*_tmpFileAbsPath,ERRNO_DESC);
   }

  // Initialize the file AES_128_GCM decryption operation
  _aesGCMMgr.decryptInit();
 }


/**
 * @brief Finalizes a received file, whether uploaded or downloaded, by:
 *           1) Verifying its integrity tag
 *           2) Moving it from the temporary into the main directory
 *           3) Setting its last modified time to the one
 *              specified in the '_remFileInfo' object
 * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
 * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
 * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
 * @throws ERR_SESS_FILE_CLOSE_FAILED     Error in closing the temporary file
 * @throws ERR_SESS_FILE_RENAME_FAILED    Error in moving the temporary file to the main directory
 * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the main file's last modification time
 */
void SessMgr::finalizeRecvFileRaw()
 {
  // Finalize the file reception's decryption by verifying its
  // integrity tag available in the primary connection buffer
  // Finalize the upload decryption by verifying the file's integrity tag
  _aesGCMMgr.decryptFinal(&_connMgr._priBuf[0]);

  // Close and reset the temporary file descriptor
  if(fclose(_tmpFileDscr) != 0)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_CLOSE_FAILED,"Received file \"" + *_tmpFileAbsPath + "\"", ERRNO_DESC);
   }
  _tmpFileDscr = nullptr;

  // Move the temporary file from the temporary
  // directory into the main file in the main directory
  if(rename(_tmpFileAbsPath->c_str(),_mainFileAbsPath->c_str()))
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_RENAME_FAILED,"source: \"" + *_tmpFileAbsPath + "\", dest: "
                                                                                  "\"" + *_mainFileAbsPath + "\"", ERRNO_DESC);
   }

  // Set the received file last modified time to
  // the one specified in the '_remFileInfo' object
  mainToRemLastModTime();
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
 *         buffer into its resulting session message in the connection's secondary buffer
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

  // Determine the wrapped session message size by subtracting from the session
  // message wrapper size the constant size of a 'SessMsgWrapper' struct
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
 * @brief  Wraps and sends a session signaling message, i.e. a session
 *         session message with no payload, to the connection peer
 * @param  sessMsgSignalingType          The session signaling message type to be sent
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
void SessMgr::sendSessSignalMsg(SessMsgType sessMsgSignalingType) // NOLINT(misc-no-recursion)
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

  // Set the session message length to the size of a 'SessMsg' struct
  sessSignalMsg->msgLen  = sizeof(SessMsg);

  // Set the session message type to the specified type
  sessSignalMsg->msgType = sessMsgSignalingType;

  // Wrap and send the session signaling message
  wrapSendSessMsg();
 }


/**
 * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileInfo' session message
 *         of the specified type containing the name and metadata of the main file referred by the '_mainFileInfo'
 *         attribute, for then wrapping and sending the resulting session message wrapper to the connection peer
 * @param  sessMsgType The 'SessMsgFileInfo' session message type (FILE_UPLOAD_REQ || FILE_EXISTS)
 * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType' or uninitialized '_mainFileInfo' attribute
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::sendSessMsgFileInfo(SessMsgType sessMsgType)
 {
  // Ensure the session message type to be valid for a 'SessMsgFileInfo' message
  if(!(sessMsgType == FILE_UPLOAD_REQ || sessMsgType == FILE_EXISTS))
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Invalid 'SessMsgFileInfo' message type (" + std::to_string(sessMsgType) + ")");
   }

  // Ensure the '_mainFileInfo' attribute to have been initialized
  if(_mainFileInfo == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to prepare a 'SessMsgFileInfo' message with a NULL _mainFileInfo");
   }

  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileInfo' session message
  SessMsgFileInfo* sessMsgFileInfoMsg = reinterpret_cast<SessMsgFileInfo*>(_connMgr._secBuf);

  // Set the 'SessMsgFileInfo' message type to the provided argument
  sessMsgFileInfoMsg->msgType = sessMsgType;

  // Set the length of the 'SessMsgFileInfo' message to the length of its struct + the main file name
  // length (+1 for the '/0' character, -1 for the 'fileName' placeholder attribute in the struct)
  sessMsgFileInfoMsg->msgLen = sizeof(SessMsgFileInfo) + _mainFileInfo->fileName.length();

  // Write the main file's metadata into the 'SessMsgFileInfo' message
  sessMsgFileInfoMsg->fileSize     = _mainFileInfo->meta->fileSizeRaw;
  sessMsgFileInfoMsg->lastModTime  = _mainFileInfo->meta->lastModTimeRaw;
  sessMsgFileInfoMsg->creationTime = _mainFileInfo->meta->creationTimeRaw;

  // Write the main file name, '/0' character included, into the 'SessMsgFileInfo' message
  memcpy(reinterpret_cast<char*>(&sessMsgFileInfoMsg->fileName), _mainFileInfo->fileName.c_str(), _mainFileInfo->fileName.length() + 1);

  // Wrap the 'SessMsgFileInfo' message into its associated
  // session message wrapper and send it to the connection peer
  wrapSendSessMsg();
 }


/**
 * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileName'
 *         session message of the specified type and fileName value, for then wrapping
 *         and sending the resulting session message wrapper to the connection peer
 * @param  sessMsgType The 'SessMsgFileName' session message type (FILE_DOWNLOAD_REQ || FILE_DELETE_REQ)
 * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType'
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::sendSessMsgFileName(SessMsgType sessMsgType, std::string& fileName)
 {
  // Ensure the session message type to be valid for a 'SessMsgFileName' message
  if(!(sessMsgType == FILE_DOWNLOAD_REQ || sessMsgType == FILE_DELETE_REQ))
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Invalid 'SessMsgFileName' message type (" + std::to_string(sessMsgType) + ")");
   }

  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileName' session message
  SessMsgFileName* sessMsgFileNameMsg = reinterpret_cast<SessMsgFileName*>(_connMgr._secBuf);

  // Set the 'SessMsgFileName' message type to the provided argument
  sessMsgFileNameMsg->msgType = sessMsgType;

  // Set the length of the 'SessMsgFileName' message to the length of its struct + the fileName
  // length (+1 for the '/0' character, -1 for the 'fileName' placeholder attribute in the struct)
  sessMsgFileNameMsg->msgLen = sizeof(SessMsgFileName) + fileName.length();

  // Write the fileName, '/0' character included, into the 'SessMsgFileName' message
  memcpy(reinterpret_cast<char*>(&sessMsgFileNameMsg->fileName), fileName.c_str(), fileName.length() + 1);

  // Wrap the 'SessMsgFileName' message into its associated
  // session message wrapper and send it to the connection peer
  wrapSendSessMsg();
 }


/**
 * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileRename' session
 *         message of implicit type 'FILE_RENAME_REQ' containing the specified old and new file names,
 *         for then wrapping and sending the resulting session message wrapper to the connection peer
 * @param  oldFilename The name of the file to be renamed
 * @param  newFilename The name the file should be renamed to
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::sendSessMsgFileRename(std::string& oldFilename, std::string& newFilename)
 {
  // Interpret the contents of the connection manager's
  // secondary buffer as a 'SessMsgFileRename' session message
  SessMsgFileRename* sessMsgFileRenameMsg = reinterpret_cast<SessMsgFileRename*>(_connMgr._secBuf);

  // Set the 'SessMsgFileRename' message type to the implicit 'FILE_RENAME_REQUEST'
  sessMsgFileRenameMsg->msgType = FILE_RENAME_REQ;

  // Set the old filename length, '/0' character included, in the 'SessMsgFileRename' message
  sessMsgFileRenameMsg->oldFilenameLen = oldFilename.length() + 1;

  // Copy the old file name, '\0' character included, in the 'SessMsgFileRename' message
  memcpy(reinterpret_cast<char*>(&sessMsgFileRenameMsg->oldFileName), oldFilename.c_str(), oldFilename.length() + 1);

  // Copy the new file name, '\0' character included, in the 'SessMsgFileRename' message
  memcpy(reinterpret_cast<char*>(&sessMsgFileRenameMsg->oldFileName + oldFilename.length() + 1),
         newFilename.c_str(), newFilename.length() + 1);

  // Set the length of the 'SessMsgFileRename' message to the length of its struct + both file
  // names lengths (+2 for the 2 '/0' character, -2 for the placeholder attributes in the struct)
  sessMsgFileRenameMsg->msgLen = sizeof(SessMsgFileRename) + oldFilename.length() + newFilename.length();

  // Wrap the 'SessMsgFileRename' message into its associated
  // session message wrapper and send it to the connection peer
  wrapSendSessMsg();
 }


/**
 * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgPoolSize'
 *         session message of implicit type 'POOL_SIZE' containing the serialized size of
 *         the user's storage pool store in the '_rawBytesRem' attribute, for then wrapping
 *         and sending the resulting session message wrapper to the connection peer
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::sendSessMsgPoolSize()
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgPoolSize' session message
  SessMsgPoolSize* sessMsgPoolSizeMsg = reinterpret_cast<SessMsgPoolSize*>(_connMgr._secBuf);

  // Set the 'SessMsgPoolSize' message type to the implicit 'POOL_SIZE'
  sessMsgPoolSizeMsg->msgType = POOL_SIZE;

  // Set the 'SessMsgPoolSize' message length
  sessMsgPoolSizeMsg->msgLen = sizeof(SessMsgPoolSize);

  // Set the serialized size of the user's storage pool into the
  // 'SessMsgPoolSize' message to the value of the '_rawBytesRem' attribute
  sessMsgPoolSizeMsg->serPoolSize = _rawBytesRem;

  // Wrap the 'SessMsgPoolSize' message into its associated
  // session message wrapper and send it to the connection peer
  wrapSendSessMsg();
 }


/* ------------------------- Session Messages Reception ------------------------- */

/**
 * @brief Validates and loads into a FileInfo object pointed by the '_remFileInfo' attribute
 *        the name and metadata of a remote file embedded within a 'SessMsgFileInfo'
 *        session message stored in the associated connection manager's secondary buffer
 * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file values in the 'SessMsgFileInfo' message
 */
void SessMgr::loadRemSessMsgFileInfo()
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileInfo' session message
  SessMsgFileInfo* fileInfoMsg = reinterpret_cast<SessMsgFileInfo*>(_connMgr._secBuf);

  // Determine the remote file name length, '\0' character included
  unsigned char remFileNameLength = fileInfoMsg->msgLen - sizeof(SessMsgFileInfo);

  // Extract the remote file name from the 'SessMsgFileInfo' session message
  std::string remFileName(reinterpret_cast<char*>(fileInfoMsg->fileName),remFileNameLength);

  // Attempt to re-initialize the '_remFileInfo' attribute with the remote file information
  delete _remFileInfo;

  try
   { _remFileInfo = new FileInfo(remFileName,fileInfoMsg->fileSize,fileInfoMsg->lastModTime,fileInfoMsg->creationTime); }

   // An exception being raised by the FileInfo constructor implies that a malformed message was received
  catch(sessErrExcp& invalidFileNameExcp)
   {
    sendSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE);
    THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Invalid file values in the 'SessMsgFileInfo' message");
   }
 }


/**
 * @brief  Validates the 'fileName' string embedded within a 'SessMsgFileName' session message stored
 *         in the associated connection manager's secondary buffer and initializes the '_mainFileAbsPath'
 *         attribute to the concatenation of the session's main directory with such file name
 * @return The file name embedded in the 'SessMsgFileName' session message
 * @throws ERR_SESS_MALFORMED_MESSAGE The 'fileName' string does not represent a valid Linux file name
 */
std::string SessMgr::loadMainSessMsgFileName()
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileName' session message
  SessMsgFileName* sessFileNameMsg = reinterpret_cast<SessMsgFileName*>(_connMgr._secBuf);

  // Determine the length of the file name within the 'SessMsgFileName' message, '\0' character included
  unsigned char fileNameLength = sessFileNameMsg->msgLen - sizeof(SessMsgFileName);

  // Extract the file name from the 'SessMsgFileName' message
  std::string fileName(reinterpret_cast<char*>(sessFileNameMsg->fileName), fileNameLength);

  // Assert the received file name string to consist of a valid Linux file name
  validateRecvFileName(fileName);

  // Initialize the '_mainFileAbsPath' attribute to the concatenation
  // of the session's main directory with such file name
  _mainFileAbsPath = new std::string(*_mainDirAbsPath + fileName);

  // Return file name embedded in the 'SessMsgFileName' session message
  return fileName;
 }


/**
 * @brief Extracts and validates the old and new file names embedded within a 'SessMsgFileRename'
 *        session message stored in the associated connection manager's secondary buffer
 * @param oldFilenameDest The pointer to be initialized to the old file name
 * @param newFilenameDest The pointer to be initialized to the new file name
 * @throws ERR_SESS_MALFORMED_MESSAGE The old or new file name is not a valid Linux
 *                                    file name or the two file names coincide
 */
void SessMgr::loadSessMsgFileRename(std::string** oldFilenameDest, std::string** newFilenameDest)
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileRename' session message
  SessMsgFileRename* sessMsgFileRenameMsg = reinterpret_cast<SessMsgFileRename*>(_connMgr._secBuf);

  // Determine the new file name length, '\0' character included
  unsigned char newFilenameLen = sessMsgFileRenameMsg->msgLen - sizeof(SessMsgFileRename)
                                 - sessMsgFileRenameMsg->oldFilenameLen + 1;

  // Copy both the old and the new file names to their destination strings
  *oldFilenameDest = new std::string(reinterpret_cast<char*>(&sessMsgFileRenameMsg->oldFileName),
                                     sessMsgFileRenameMsg->oldFilenameLen - 1);

  *newFilenameDest = new std::string(reinterpret_cast<char*>(&sessMsgFileRenameMsg->oldFileName +
                                     sessMsgFileRenameMsg->oldFilenameLen),newFilenameLen);

  // Assert both the old and new to consist of valid Linux file names
  validateRecvFileName(**oldFilenameDest);
  validateRecvFileName(**newFilenameDest);

  // Assert the old and new file names to be different
  if(**oldFilenameDest == **newFilenameDest)
   {
    sendSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE);
    THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Same old and new file names in the 'SessMsgFileRename' message");
   }
 }


/**
 * @brief Reads the serialized size of a user's storage pool from a
 *        'SessMsgPoolSize' session  message into the '_rawBytesRem' attribute
 */
void SessMgr::loadSessMsgPoolSize()
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgPoolSize' session message
  SessMsgPoolSize* sessMsgPoolSizeMsg = reinterpret_cast<SessMsgPoolSize*>(_connMgr._secBuf);

  // Copy the serialized contents' size of the user's storage pool into the '_rawBytesRem' attribute
  _rawBytesRem = sessMsgPoolSizeMsg->serPoolSize;
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Session manager object constructor
 * @param connMgr A reference to the connection manager parent object
 * @param mainDir The session's main directory, consisting in the user's storage pool on
 *                the SafeCloud server or their downloads folder in the client application
 */
SessMgr::SessMgr(ConnMgr& connMgr, std::string* mainDir) :

  /* ------------------------ Constant Session Attributes ------------------------ */
  _connMgr(connMgr), _mainDirAbsPath(mainDir), _tmpDirAbsPath(_connMgr._tmpDir),

  /* -------------------------- Session State Attributes -------------------------- */
  _sessMgrOp(IDLE), _sessMgrOpStep(OP_START), _aesGCMMgr(_connMgr._skey, _connMgr._iv),
  _mainDirInfo(nullptr), _mainFileAbsPath(nullptr), _mainFileInfo(nullptr), _mainFileDscr(nullptr),
  _tmpFileAbsPath(nullptr), _tmpFileDscr(nullptr), _remFileInfo(nullptr),
  _rawBytesRem(0), _recvSessMsgLen(0), _recvSessMsgType(ERR_UNKNOWN_SESSMSG_TYPE)
 {}


/**
 * @brief Session manager object destructor,  performing cleanup operations on the session's
 *        state attributes and resetting the associated connection manager's reception mode
 *        to 'RECV_MSG' and marking the contents of its primary connection buffer as consumed
 * @note  It is assumed the connection's cryptographic quantities (session key, IV)
 *        to be securely erased by the associated connection manager parent object
 */
SessMgr::~SessMgr()
 {
  /* NOTE: The constant session attributes MUST NOT be deleted */

  /* ----------------- Session State Attributes Cleanup ----------------- */

  // If open, close the main file
  if(_mainFileDscr != nullptr)
   {
    if(fclose(_mainFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_mainFileAbsPath, ERRNO_DESC);
   }

  // If open, close and delete the temporary file
  if(_tmpFileDscr != nullptr)
   {
    if(fclose(_tmpFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
    else
     if(remove(_tmpFileAbsPath->c_str()) == -1)
      LOG_EXEC_CODE(ERR_FILE_DELETE_FAILED, *_tmpFileAbsPath, ERRNO_DESC);
   }

  // Delete the session manager state dynamic attributes
  delete _mainDirInfo;
  delete _mainFileAbsPath;
  delete _mainFileInfo;
  delete _tmpFileAbsPath;
  delete _remFileInfo;

  /* ----------------- Connection Manager State Cleanup ----------------- */

  // Reset the associated connection manager's reception mode to 'RECV_MSG'
  _connMgr._recvMode = ConnMgr::RECV_MSG;

  // Mark the contents of the associated connection
  // manager's primary buffer as consumed
  _connMgr.clearPriBuf();
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Returns whether the session manager is idle
 * @return A boolean indicating whether the connection manager is idle
 */
bool SessMgr::isIdle()
 { return _sessMgrOp == IDLE; }


/**
 * @brief Reset the session manager state in preparation to the next session operation by
 *        resetting and performing cleanup operation on all its session state attributes
 *        and by resetting the associated connection manager's reception mode to 'RECV_MSG'
 *        and by marking the contents of its primary connection buffer as consumed
 */
void SessMgr::resetSessState()
 {
  /* ------------------ Session State Attributes Reset ------------------ */

  // Reset the session manager current operation and operation step
  _sessMgrOp     = IDLE;
  _sessMgrOpStep = OP_START;

  // Reset the state of the AESGCMMgr child object (causing its IV to
  // increment if an encryption or decryption operation was pending)
  _aesGCMMgr.resetState();

  // If present, delete and reset the
  // contents of the session's main directory
  if(_mainDirInfo != nullptr)
   {
    delete _mainDirInfo;
    _mainDirInfo = nullptr;
   }

  // If present, reset the main file absolute path
  if(_mainFileAbsPath != nullptr)
   {
    delete _mainFileAbsPath;
    _mainFileAbsPath = nullptr;
   }

  // If present, delete and reset the main file information
  if(_mainFileInfo != nullptr)
   {
    delete _mainFileInfo;
    _mainFileInfo = nullptr;
   }

  // If open, close the main file and reset its descriptor
  if(_mainFileDscr != nullptr)
   {
    if(fclose(_mainFileDscr) != 0)
     LOG_EXEC_CODE(ERR_FILE_CLOSE_FAILED, *_mainFileAbsPath, ERRNO_DESC);
    _mainFileDscr = nullptr;
   }

  // If present, reset the temporary file absolute path
  if(_tmpFileAbsPath != nullptr)
   {
    delete _tmpFileAbsPath;
    _tmpFileAbsPath = nullptr;
   }

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

  // If present, delete the information on the remote file
  if(_remFileInfo != nullptr)
   {
    delete _remFileInfo;
    _remFileInfo = nullptr;
   }

  // Reset the number of remaining raw bytes to be
  // sent or received in a raw data transmission
  _rawBytesRem = 0;

  // Reset the length and type of the last received session message
  _recvSessMsgLen = 0;
  _recvSessMsgType = ERR_UNKNOWN_SESSMSG_TYPE;

  /* ------------------ Connection Manager State Reset ------------------ */

  // Reset the associated connection manager's reception mode to 'RECV_MSG'
  _connMgr._recvMode = ConnMgr::RECV_MSG;

  // Mark the contents of the associated connection
  // manager's primary buffer as consumed
  _connMgr.clearPriBuf();

  /*
  // LOG: Session state reset
  printf("in resetSessState()\n");
  */
 }


/**
 * @brief  Gracefully terminates the session and connection with the peer by sending the 'BYE'
 *         session signaling message and setting the associated connection manager to be closed
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SessMgr::closeSession()
 {
  // Send the 'BYE' session signaling message to the connection peer
  sendSessSignalMsg(BYE);

  // Set the associated connection manager to be closed
  _connMgr._shutdownConn = true;
 }