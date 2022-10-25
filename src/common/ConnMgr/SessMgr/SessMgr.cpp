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

// TODO: Section?

/**
 * @brief Validates and loads into a FileInfo object pointed by the '_remFileInfo' attribute
 *        the name and metadata of a remote file embedded within a 'SessMsgFileInfo'
 *        session message stored in the associated connection manager's secondary buffer
 * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file values in the 'SessMsgFileInfo' message
 */
void SessMgr::loadRemFileInfo()
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
std::string SessMgr::loadMainFileName()
 {
  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileName' session message
  SessMsgFileName* fileNameMsg = reinterpret_cast<SessMsgFileName*>(_connMgr._secBuf);

  // Determine the length of the file name within the 'SessMsgFileName' message, '\0' character included
  unsigned char fileNameLength = fileNameMsg->msgLen - sizeof(SessMsgFileName);

  // Extract the file name from the 'SessMsgFileName' message
  std::string fileName(reinterpret_cast<char*>(fileNameMsg->fileName), fileNameLength);

  // Assert the file name string to consist of a valid Linux file name
  try
   {  validateFileName(fileName); }
  catch(sessErrExcp& invalidFileNameExcp)
   {
    // If the received file name string does not represent a
    // valid Linux file name, the received message is malformed
    sendSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE);
    THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Invalid file name in the 'SessMsgFileName'"
                                               " message (\"" + fileName + "\")");
   }

  // Initialize the '_mainFileAbsPath' attribute to the concatenation
  // of the session's main directory with such file name
  _mainFileAbsPath = new std::string(*_mainDir + fileName);

  // Return file name embedded in the 'SessMsgFileName' session message
  return fileName;
 }


/**
 * @brief Attempts to load into the '_locFileInfo' attribute the information
 *        of the main file referred by the '_mainFileAbsPath' attribute
 * @throws ERR_SESS_INTERNAL_ERROR   The '_mainFileAbsPath' attribute has not been initialized
 * @throws ERR_SESS_MAIN_FILE_IS_DIR The main file was found to be a directory (!)
 */
void SessMgr::checkLoadMainFile()
 {
  // Ensure the '_mainFileAbsPath' attribute to have been initialized
  if(_mainFileAbsPath == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to load the main file information time with a NULL '_mainFileAbsPath'");
   }

  // Attempt to load into the '_locFileInfo' attribute the information
  // of the main file referred by the '_mainFileAbsPath' attribute
  try
   { _locFileInfo = new FileInfo(*_mainFileAbsPath); }
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
    _locFileInfo = nullptr;
   }
 }



/**
 * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileInfo' session message
 *         of the specified type containing the name and metadata of the local file referred by the '_locFileInfo'
 *         attribute, for then wrapping and sending the resulting session message wrapper to the connection peer
 * @param  sessMsgType The 'SessMsgFileInfo' session message type (FILE_UPLOAD_REQ || FILE_EXISTS || NEW_FILENAME_EXISTS)
 * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType' or the '_locFileInfo' attribute has not been initialized
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
  // TODO: Check if NEW_FILENAME_EXISTS is applicable (also in the function description)
  // Ensure the session message type to be valid for a 'SessMsgFileInfo' message
  if(!(sessMsgType == FILE_UPLOAD_REQ || sessMsgType == FILE_EXISTS || sessMsgType == NEW_FILENAME_EXISTS))
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Invalid 'SessMsgFileInfo' message type (" + std::to_string(sessMsgType) + ")");
   }

  // Ensure the '_locFileInfo' attribute to have been initialized
  if(_locFileInfo == nullptr)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Attempting to prepare a 'SessMsgFileInfo' message with a NULL _locFileInfo");
   }

  // Interpret the contents of the connection manager's secondary buffer as a 'SessMsgFileInfo' session message
  SessMsgFileInfo* sessMsgFileInfoMsg = reinterpret_cast<SessMsgFileInfo*>(_connMgr._secBuf);

  // Set the 'SessMsgFileInfo' message type to the provided argument
  sessMsgFileInfoMsg->msgType = sessMsgType;

  // Set the length of the 'SessMsgFileInfo' message to the length of its struct + the local file name
  // length (+1 for the '/0' character, -1 for the 'fileName' placeholder attribute in the struct)
  sessMsgFileInfoMsg->msgLen = sizeof(SessMsgFileInfo) + _locFileInfo->fileName.length();

  // Write the local file's metadata into the 'SessMsgFileInfo' message
  sessMsgFileInfoMsg->fileSize     = _locFileInfo->meta->fileSizeRaw;
  sessMsgFileInfoMsg->lastModTime  = _locFileInfo->meta->lastModTimeRaw;
  sessMsgFileInfoMsg->creationTime = _locFileInfo->meta->creationTimeRaw;

  // Write the local file name, '/0' character included, into the 'SessMsgFileInfo' message
  memcpy(reinterpret_cast<char*>(&sessMsgFileInfoMsg->fileName), _locFileInfo->fileName.c_str(), _locFileInfo->fileName.length() + 1);

  // Wrap the 'SessMsgFileInfo' message into its associated
  // session message wrapper and send it to the connection peer
  wrapSendSessMsg();
 }


/**
* @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileName'
 *        session message of the specified type and fileName value, for then wrapping
 *        and sending the resulting session message wrapper to the connection peer
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
 * @brief  Mirrors the remote file last modification time as for the '_remFileInfo' attribute into the main file
 * @param  fileAbsPath The absolute path of the local file whose last modification time is to be changed
 * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
 * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
 */
void SessMgr::mirrorRemLastModTime()
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

  // Attempt to mirror the remote file last modification time into the main local file
  if(utimes(_mainFileAbsPath->c_str(), timesArr) == -1)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_META_SET_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }
 }


/**
* @brief  Deletes if present the empty file in the main directory referred by the
*         '_mainFileAbsPath' and '_locFileInfo' attributes, for then touching it and
*         setting its last modified time to the one referred by the '_remFileInfo' object
* @note   If present the file is preliminarily deleted from the main
*         directory for the purposes of updating its creation time
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

  // If the file already exists in the main directory, delete
  // it for the purposes of updating its creation time
  if(_locFileInfo != nullptr && remove(_mainFileAbsPath->c_str()) == -1)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_DELETE_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }

  // Touch the empty file in the main directory
  std::ofstream upFile(*_mainFileAbsPath);
  if(!upFile)
   {
    sendSessSignalMsg(ERR_INTERNAL_ERROR);
    THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED,*_mainFileAbsPath,ERRNO_DESC);
   }

  // Close the touched empty file
  upFile.close();
  if(upFile.fail())
   LOG_SESS_CODE(ERR_SESS_FILE_CLOSE_FAILED,*_mainFileAbsPath,ERRNO_DESC);

  // Change the touched file last modified time to the one specified in the '_remFileInfo' object
  mirrorRemLastModTime();
 }


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
 * @brief  Returns whether a session message type
 *         is a signaling error session message type
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
 * @param connMgr The session's main directory, consisting in the user's storage
 *                pool on the server or their downloads folder on the client
 */
SessMgr::SessMgr(ConnMgr& connMgr, std::string* mainDir)
  : _sessMgrState(IDLE), _connMgr(connMgr), _aesGCMMgr(_connMgr._skey, _connMgr._iv),
    _mainDir(mainDir), _tmpDir(_connMgr._tmpDir), _mainFileDscr(nullptr), _mainFileAbsPath(nullptr),
    _tmpFileDscr(nullptr), _tmpFileAbsPath(nullptr), _locFileInfo(nullptr), _remFileInfo(nullptr),
    _rawBytesRem(0), _recvSessMsgLen(0), _recvSessMsgType(ERR_UNKNOWN_SESSMSG_TYPE)
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

  // Mark the contents of the associated connection
  // manager's primary buffer as consumed
  _connMgr.clearPriBuf();

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
  delete _tmpFileAbsPath;
  _tmpFileAbsPath = nullptr;

  // Delete the file name and metadata of the target local file
  delete _locFileInfo;
  _locFileInfo = nullptr;

  // Delete the file name and metadata of the target remote file
  delete _remFileInfo;
  _remFileInfo = nullptr;

  // Reset the number of bytes pending to be sent
  // or received in a raw data transmission
  _rawBytesRem = 0;

  /* -------------- Currently Received Session Message Header -------------- */

  // Reset the previously received session message header information
  _recvSessMsgLen = 0;
  _recvSessMsgType = ERR_UNKNOWN_SESSMSG_TYPE;

  // TODO: Remove
  printf("in resetSessState()\n");
 }