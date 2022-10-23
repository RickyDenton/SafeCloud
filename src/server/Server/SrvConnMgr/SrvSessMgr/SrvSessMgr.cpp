/* SafeCloud Server Session Manager Class Implementation */

/* ================================== INCLUDES ================================== */
#include <fstream>
#include "SrvSessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"
#include "../SrvConnMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/* ============================== PRIVATE METHODS ============================== */

/**
 * @brief Sends a session message signaling type to the client and performs the actions
 *        appropriate to session signaling types resetting or terminating the session
 * @param sessMsgSignalingType The session message signaling type to be sent to the client
 * @param errReason            An optional error reason to be embedded with the exception that
 *                             must be thrown after sending such session message signaling type
 * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message invalid for its current state
 * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
 * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType)
 { sendSrvSessSignalMsg(sessMsgSignalingType,""); }

void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason)
 {
  // Attempt to send the signaling session message
  try
   { sendSessSignalMsg(sessMsgSignalingType); }
  catch(execErrExcp& sendSessSignExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_CLI_DISCONNECTED error code
    if(sendSessSignExcp.exErrcode == ERR_PEER_DISCONNECTED)
     sendSessSignExcp.exErrcode = ERR_CLI_DISCONNECTED;

    // Rethrow the exception
    throw;
   }

  // In case of signaling messages resetting or terminating the session,
  // perform their associated actions or raise their associated exceptions
  switch(sessMsgSignalingType)
   {
    // The connection manager (and the SafeCloud server as a whole) is terminating
    case BYE:

     // Set that this client connection must be closed
     _srvConnMgr._keepConn = false;
     break;

    // The server session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    // A session message invalid for the current server session manager was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     if(!errReason.empty())
      THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);
     else
      THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    // The other signaling message types require no further action
    default:
     break;
   }
 }


void SrvSessMgr::dispatchRecvSessMsg()
 {
  switch(_sessMgrState)
   {

    case SessMgr::IDLE:
     switch(_recvSessMsgType)
      {
       case FILE_UPLOAD_REQ:
        _sessMgrState = UPLOAD;
        srvUploadStart();
        break;

       case FILE_DOWNLOAD_REQ:
        _sessMgrState = DOWNLOAD;
        //srvDownloadStart();
        break;

       case FILE_DELETE_REQ:
        _sessMgrState = DELETE;
        //srvDeleteStart();
        break;

       case FILE_RENAME_REQ:
        _sessMgrState = RENAME;
        //srvRenameStart();
        break;

       case FILE_LIST_REQ:
        _sessMgrState = LIST;
        //srvListStart();
        break;

       default:
        sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) + "\""
                                                         "session message received in the 'IDLE' session state");
      }
     break;

    // 'UPLOAD' server session manager state
    case SessMgr::UPLOAD:

     // Only the client confirmation of a pending upload can be received
     // in the 'UPLOAD' state with 'WAITING_CLI_CONF' substate
     if(_srvSessMgrSubstate == WAITING_CLI_CONF && _recvSessMsgType == CONFIRM)
      {
       // Prepare the server session manager to receive the raw file contents
       srvUploadSetRecvRaw();
       LOG_INFO("[" + *_srvConnMgr._name + "]  Upload of file \"" + _remFileInfo->fileName
                    + "\" confirmed, awaiting the file's raw data")
      }
     else
      sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) + "\""
                                                       "session message received in the 'UPLOAD' session state");
     break;


    // TODO

    default:
     sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Invalid server session manager state (" + std::to_string(_sessMgrState) + ")");
   }
 }


/* ------------------------- 'UPLOAD' Callback Methods ------------------------- */

/**
 * @brief Starts a file upload operation by:\n
 *           1) Loading into the '_remFileInfo' attribute the name and metadata of the file to be uploaded\n
 *           2) Checking whether a file with the same name of the one to be uploaded already exists in the client's storage pool\n
 *              2.1) If it does, the name and metadata of such file are sent to the client, with
 *                   their confirmation being required on whether such file should be overwritten\n
 *              2.2) If it does not:\n
 *                   2.2.1) If the file to be uploaded is empty, directly touch such file, set its last modified time to
 *                          the one provided by the client and inform them that the file has been successfully uploaded \n
 *                   2.2.2) If the file to be uploaded is NOT empty, inform the client
 *                          that the server is ready to receive the file's raw contents
 * @throws ERR_SESS_MALFORMED_MESSAGE   The file name in the 'SessMsgFileInfo' message is invalid
 * @throws ERR_INTERNAL_ERROR           Session manager status or file read/write error
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
void SrvSessMgr::srvUploadStart()
 {
  // Whether a file with the same name of the one to be
  // uploaded already exists in the client's storage pool
  bool fileNameAlreadyExists;

  // Load into the '_remFileInfo' attribute the name and
  // metadata of the file the client is requesting to upload
  loadRemFileInfo();

  // Initialize the main and temporary absolute paths of the file to be uploaded
  _mainFileAbsPath = new std::string(*_srvConnMgr._poolDir + _remFileInfo->fileName);
  _tmpFileAbsPath  = new std::string(*_srvConnMgr._tmpDir + _remFileInfo->fileName + "_PART");

  /*
  // LOG: Main and temporary files absolute paths
  std::cout << "_mainFileAbsPath = " << *_mainFileAbsPath << std::endl;
  std::cout << "_tmpFileAbsPath = " << *_tmpFileAbsPath << std::endl;

  // LOG: Remote file information
  _remFileInfo->printFileInfo();
  */

  // Check whether a file with the same name of the one to be uploaded already exists in the
  // client's storage pool, loading in such case its information into the '_locFileInfo' object
  try
   {
    _locFileInfo = new FileInfo(*_srvConnMgr._poolDir + "/" + _remFileInfo->fileName);
    fileNameAlreadyExists = true;
   }
  catch(sessErrExcp& locFileError)
   {
    _locFileInfo = nullptr;
    if(locFileError.sesErrCode == ERR_SESS_FILE_READ_FAILED)
     fileNameAlreadyExists = false;
    else
     if(locFileError.sesErrCode == ERR_SESS_FILE_IS_DIR)
      sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"The file \"" + _remFileInfo->fileName + "\" the client is attempting"
                                              " to upload already exists in their storage pool as a directory");
   }

  // If the file to be uploaded is empty
  if(_remFileInfo->meta->fileSizeRaw == 0)
   {
    // Touch the empty file in the client's storage pool
    touchEmptyFile();

    // Inform the client that the empty file has been successfully uploaded
    sendSrvSessSignalMsg(COMPLETED);

    LOG_INFO("[" + *_srvConnMgr._name + "] Uploaded empty file \""
             + _remFileInfo->fileName + "\" into the storage pool")

    // Reset the server session manager state and return
    resetSrvSessState();
    return;
   }

  // Otherwise, if a file with the same name of the one to
  // be uploaded was found in the client's storage pool
  if(fileNameAlreadyExists)
   {
    // Prepare a 'SessMsgFileInfo' session message of type 'FILE_EXISTS'
    // containing the local file name and metadata and send it to the client
    sendLocalFileInfo(FILE_EXISTS);

    // Further client confirmation is required before uploading the file
    _srvSessMgrSubstate = WAITING_CLI_CONF;

    LOG_INFO("[" + *_srvConnMgr._name + "] Received upload request of file \"" + _remFileInfo->fileName +
              "\" already existing in the storage pool, awaiting client confirmation")
   }

  // Otherwise, if a file with the same name of the one to
  // be uploaded was not found in the client's storage pool
  else
   {
    // Inform the client that a file with such name is not present in their
    // storage pool, and that the server is now expecting its raw contents
    sendSrvSessSignalMsg(FILE_NOT_EXISTS);

    // Prepare the server session manager to receive the raw file contents
    srvUploadSetRecvRaw();

    LOG_INFO("[" + *_srvConnMgr._name + "] Received upload request of file \"" + _remFileInfo->fileName +
             "\" not existing in the storage pool, awaiting the raw file data")
   }
 }


/**
 * @brief Prepares the server session manager to receive
 *        the raw contents of a file to be uploaded
 * @throws ERR_INTERNAL_ERROR            Could not open the temporary file descriptor in write-byte mode
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SrvSessMgr::srvUploadSetRecvRaw()
 {
  // Update the server's 'UPLOAD' sub-state so to expect raw data
  _srvSessMgrSubstate = WAITING_CLI_RAW_DATA;

  // Set the reception mode of the associated connection manager to 'RECV_RAW'
  _srvConnMgr._recvMode = ConnMgr::RECV_RAW;

  // Set the expected data block size in the associated
  // connection manager to the size of the file to be received
  _srvConnMgr._recvBlockSize = _remFileInfo->meta->fileSizeRaw;

  // Initialize the number of raw bytes to be received to the file size
  _bytesRem = _remFileInfo->meta->fileSizeRaw;

  // Open the temporary file descriptor in write-byte mode
  _tmpFileDscr = fopen(_tmpFileAbsPath->c_str(), "wb");
  if(!_tmpFileDscr)
   sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Error in opening the uploaded temporary file \""
                                           + *_tmpFileAbsPath + " \" (" + ERRNO_DESC + ")");

  // Initialize an AES_128_GCM decryption operation
  _aesGCMMgr.decryptInit();
 }


// TODO: Rewrite descr
void SrvSessMgr::recvUploadFileData(size_t recvBytes)
 {
  // fwrite() return, representing the number of bytes
  // written from to the temporary file descriptor
  size_t fwriteRet;

  // The file upload progress
  float progress;

  // If additional file bytes must be received
  if(_bytesRem > 0)
   {
    // Decrypt the wrapped session message from the primary into the secondary connection buffer
    _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[0], (int)recvBytes, &_connMgr._secBuf[0]);

    // Write the decrypted file bytes from the secondary
    // connection buffer into the temporary file descriptor
    fwriteRet = fwrite(_connMgr._secBuf, sizeof(char), recvBytes, _tmpFileDscr);

    // If lesser than the number of received bytes were written
    if(fwriteRet < recvBytes)
     THROW_EXEC_EXCP(ERR_FILE_WRITE_FAILED,*_tmpFileAbsPath,"written " + std::to_string(fwriteRet)
                                           + " < recvBytes = " + std::to_string(recvBytes) + " bytes");

    // Update the remaining number of bytes
    _bytesRem -= recvBytes;

    // The current file upload progress
    progress = (float)(_remFileInfo->meta->fileSizeRaw - _bytesRem) / (float)_remFileInfo->meta->fileSizeRaw * 100;

    LOG_DEBUG("[" + *_srvConnMgr._name + "] File \"" + _remFileInfo->fileName + "\" ("
              + _remFileInfo->meta->fileSizeStr + ") upload progress: " + std::to_string((int)progress) + "%")

    // If other file bytes are required, update the expected
    // size of the data block to be received to their number
    if(_bytesRem > 0)
     _connMgr._recvBlockSize = _bytesRem;

    // Otherwise, if the file was completely received, set the expected size of
    // the data block to be received to the size of the expected integrity tag
    else
     _connMgr._recvBlockSize = AES_128_GCM_TAG_SIZE;

    // Reset the index of the most significant byte in the primary connection buffer
    _connMgr._priBufInd = 0;
   }

  // Otherwise, if the file integrity tag must be received
  else

   // Wait for the file integrity tag to have been
   // fully received in the primary connection buffer
   if(_connMgr._priBufInd != AES_128_GCM_TAG_SIZE)
    return;

   // If the file integrity tag has been fully received
   else
    {
     // Finalize the file upload decryption by verifying its integrity tag
     _aesGCMMgr.decryptFinal(&_connMgr._priBuf[0]);

     // Close and reset the temporary file descriptor
     fclose(_tmpFileDscr);
     _tmpFileDscr = nullptr;

     // Move and rename the uploaded file from the user's
     // temporary directory to their storage pool
     if(rename(_tmpFileAbsPath->c_str(),_mainFileAbsPath->c_str()))
      sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Failed to move the uploaded file from the client's temporary"
                                              "directory to their storage pool (" + *_tmpFileAbsPath + ")");

     // Change the uploaded file last modified time to
     // the one specified in the '_remFileInfo' object
     mirrorRemLastModTime();

     // Signal the client that the upload operation has completed successfully
     sendSessSignalMsg(COMPLETED);

     LOG_INFO("[" + *_srvConnMgr._name + "] Uploaded file \"" + _remFileInfo->fileName +
              "\" (" + _remFileInfo->meta->fileSizeStr + ") into the storage pool")

     // Reset the server session state
     resetSrvSessState();
    }
 }





/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Server session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the srvConnMgr parent object
 * @param srvConnMgr A reference to the server connection manager parent object
 */
SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessMgrSubstate(SRV_IDLE), _srvConnMgr(srvConnMgr)
 {}

/* Same destructor of the SessMgr base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets all session parameters in preparation for the next
 *        session command to be executed by the server session manager
 */
void SrvSessMgr::resetSrvSessState()
 {
  // Reset the server session manage sub-state
  _srvSessMgrSubstate = SRV_IDLE;

  // Reset the base session parameters
  resetSessState();
 }


/**
 * @brief  Server Session message handler, which:\name
 *            1) Unwraps a received session message wrapper from
 *               the primary into the secondary connection buffer\n
 *            2) Asserts the resulting session message to be allowed in
 *               the current server session manager state and substate\n
 *            3) Handles session-resetting or terminating signaling messages\n
 *            4) Handles session error signaling messages\n
 *            5) Valid session messages requiring further action are
 *               dispatched to the session callback method associated
 *               with the session manager current state and substate
 * @throws TODO (most session exceptions)
 */
void SrvSessMgr::srvSessMsgHandler()
{
 // Unwrap the received session message wrapper stored in the connection's primary
 // buffer into its associated session message in the connection's secondary buffer
 unwrapSessMsg();

 // Interpret the contents of associated connection
 // manager's secondary buffer as a base session message
 SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_srvConnMgr._secBuf);

 // Copy the received session message length
 // and type into their dedicated attributes
 _recvSessMsgLen = sessMsg->msgLen;
 _recvSessMsgType = sessMsg->msgType;

 // If a signaling message type was received, assert the message
 // length to be equal to the size of a base session message
 if(isSessSignalingMsgType(_recvSessMsgType) && _recvSessMsgLen != sizeof(SessMsg))
  sendSrvSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received a session signaling message of invalid"
                                                  "length (" + std::to_string(_recvSessMsgLen) + ")");

 /*
  * Check whether the received session message type:
  *   1) Should trigger a session state reset or termination,
  *      directly performing the appropriate actions
  *   2) Is valid in the current server session manager state
  *      and substate, signaling the error to the client
  *      and throwing the associated exception otherwise
  */
 switch(_recvSessMsgType)
  {
   /* --------------------------- Command-Starting Session Message Types --------------------------- */

   // Command-starting session messages are allowed in the 'IDLE' state only
   case FILE_UPLOAD_REQ:
   case FILE_DOWNLOAD_REQ:
   case FILE_DELETE_REQ:
   case FILE_RENAME_REQ:
   case FILE_LIST_REQ:
    if(_sessMgrState != IDLE)
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) + "\""
                                                      "command-starting session message received in session"
                                                      " state \"" + currSessMgrStateToStr() + "\", sub-state "
                                                      + std::to_string(_srvSessMgrSubstate));
    break;

   /* -------------------------------- 'CONFIRM' Signaling Message -------------------------------- */

   // A client confirmation notification is allowed only in the 'UPLOAD',
   // 'DOWNLOAD' and 'DELETE' states with sub-state 'WAITING_CLI_CONF'
   case CONFIRM:
    if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
         && _srvSessMgrSubstate == WAITING_CLI_CONF))
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'CONFIRM' session message received in session state"
                                                      " \"" + currSessMgrStateToStr() + "\", sub-state "
                                                      + std::to_string(_srvSessMgrSubstate));
    break;

   /* --------------------------------- 'CANCEL' Signaling Message --------------------------------- */

   // A client cancellation notification is allowed only in the 'UPLOAD',
   // 'DOWNLOAD' and 'DELETE' states with sub-state 'WAITING_CLI_CONF'
   case CANCEL:

    // Since after sending a 'CANCEL' message the client has supposedly reset its session
    // state, in case such a message is received in an invalid state just log the error
    // without notifying the client that an unexpected session message was received
    if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
         && _srvSessMgrSubstate == WAITING_CLI_CONF))
     LOG_WARNING("Client \"" + *_srvConnMgr._name + "\" cancelled an operation with the session manager in "
                 "state '"+ currSessMgrStateToStr() + "', sub-state " + std::to_string(_srvSessMgrSubstate))

    // Otherwise, if the 'CANCEL' message is valid, log the operation that was cancelled
    else
     {
      if(_sessMgrState == UPLOAD)
       LOG_INFO("Client \"" + *_srvConnMgr._name + "\" cancelled a file upload (file: \""
                + _remFileInfo->fileName + "\", size: " + _remFileInfo->meta->fileSizeStr + ")")
      else
       if(_sessMgrState == DOWNLOAD)
        LOG_INFO("Client \"" + *_srvConnMgr._name + "\" cancelled a file download (file: \""
                 + _locFileInfo->fileName + "\", size: " + _locFileInfo->meta->fileSizeStr + ")")
       else
        LOG_INFO("Client \"" + *_srvConnMgr._name + "\" cancelled a file deletion (file: \""
                 + _locFileInfo->fileName + "\", size: " + _locFileInfo->meta->fileSizeStr + ")")
     }

    // Reset the server session state and return
    resetSrvSessState();
    return;

   /* ------------------------------- 'COMPLETED' Signaling Message ------------------------------- */

   // A client completion notification is allowed only in:
   //   1) The 'DOWNLOAD' state of any sub-state
   //   2) The 'LIST' state with sub-state 'WAITING_CLI_COMPL'
   case COMPLETED:

    // Since after sending a 'COMPLETED' message the client has supposedly
    // reset its session state, in case the message is received in an invalid
    // state just throw the associated exception without notifying the client
    if(!((_sessMgrState == DOWNLOAD) || (_sessMgrState == LIST && _srvSessMgrSubstate == WAITING_CLI_COMPL)))
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), "'COMPLETED'"
                                                 " session message received in session state \"" + currSessMgrStateToStr() +
                                                 "\", sub-state " + std::to_string(_srvSessMgrSubstate));
     break;

   /* ---------------------------------- 'BYE' Signaling Message ---------------------------------- */

   // The client graceful disconnect notification is allowed in the 'IDLE' state only
   case BYE:

    // If such a message is not received in the 'IDLE' state, just log the
    // error without notifying the client, as it is supposedly disconnecting
    if(_sessMgrState != IDLE)
     LOG_WARNING("Client \"" + *_srvConnMgr._name + "\" gracefully disconnecting with"
                 "the session manager in the \""+ currSessMgrStateToStr() + "\" state")

    // Set the associated connection manager to be terminated and return
    _srvConnMgr._keepConn = false;
    return;

   /* --------------------------------- Error Signaling Messages --------------------------------- */

   // The client reported to have experienced a recoverable internal error
   case ERR_INTERNAL_ERROR:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received an unexpected session message
   case ERR_UNEXPECTED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received a malformed session message
   case ERR_MALFORMED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received a session message of unknown type, an error to be attributed to
   // a desynchronization between the connection peers' IVs and that requires the connection to be reset
   case ERR_UNKNOWN_SESSMSG_TYPE:
    THROW_EXEC_EXCP(ERR_SESS_SRV_CLI_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   /* ----------------------------------- Unknown Message Type ----------------------------------- */

   // A session message of unknown type has been received, an error to be attributed to a
   // desynchronization between the connection peers' IVs and that requires the connection to be reset
   default:
    sendSrvSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE,std::to_string(_recvSessMsgType));
  }

 /*
  * At this point the received session message type is valid
  * for the current server session manager state and sub-state
  */

 /*
 // TODO: Comment
 // LOG: Received session message length and type
 std::cout << "_recvSessMsgLen = " << _recvSessMsgLen << std::endl;
 std::cout << "_recvSessMsgType = " << _recvSessMsgType << std::endl;
 */

 // Dispatch the received session message to the session callback method
 // associated with the session manager current state and substate
 dispatchRecvSessMsg();
}



// TODO: Rewrite descr
void SrvSessMgr::srvSessRawHandler(size_t recvBytes)
 {
  // The server can receive raw data only in an 'UPLOAD' operation

  /*
   * NOTE: Since the client may be sending raw data and so being unable to
   *       receive an error signaling message, the connection is dropped
   */
  if(_sessMgrState != UPLOAD || _srvSessMgrSubstate != WAITING_CLI_RAW_DATA)
   THROW_EXEC_EXCP(ERR_SESS_UNRECOVERABLE_INTERNAL_ERROR,"Receiving raw data with the server session manager"
                                                         " in state \"" + currSessMgrStateToStr() + "\", "
                                                         "sub-state " + std::to_string(_srvSessMgrSubstate));

  // Pass the number of bytes to the upload file data handler
  recvUploadFileData(recvBytes);
 }

