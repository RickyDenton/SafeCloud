/* SafeCloud Server Session Manager Implementation */

/* ================================== INCLUDES ================================== */

// System Headers
#include <cstring>

// SafeCloud Headers
#include "../SrvConnMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "errCodes/execErrCodes/execErrCodes.h"


/* ============================== PRIVATE METHODS ============================== */

/* ------------------- Server Session Manager Utility Methods ------------------- */

/**
 * @brief Sends a session message signaling type to the client and throws the
 *        associated exception in case of session error signaling message types
 * @param sessMsgSignalingType The session message signaling type to be sent to the client
 * @param errReason            An optional error reason to be embedded with the exception
 *                             associated with the session error signaling message type
 * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message
 *                                       invalid for its current operation or step
 * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received
 *                                       a malformed session message
 * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a
 *                                       session message of unknown type
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
  sendSessSignalMsg(sessMsgSignalingType);

  // If a session error signaling message type was sent, throw the associated exception
  switch(sessMsgSignalingType)
   {
    // The server session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr());

    // A session message invalid for the current
    // server session operation or step was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr());

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr());

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     if(!errReason.empty())
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr(), errReason);
     else
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, "Client: \""
                      + *_connMgr._name + "\", " + abortedOpToStr());

    // A non-error signaling message type was sent
    default:
     break;
   }
 }


/**
 * @brief  Dispatches a received session message to the callback method associated with
 *         its type and the server session manager current operation and implicit step
 * @note   The validity of the received session message type in the
 *         srvSessMsgHandler() server session message handler method
 * @throws ERR_SESS_UNEXPECTED_MESSAGE The received session message type is invalid
 *                                     for the current session manager operation
 *                                     and step (should NEVER happen)
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void SrvSessMgr::dispatchRecvSessMsg()
 {
  // Depending on the current server session manager operation
  switch(_sessMgrOp)
   {

    /* ---------------- 'IDLE' Server Session Manager Operation ---------------- */
    case SessMgr::IDLE:

     // Set the session manager operation to the one associated with the received
     // operation-starting session message and call its starting callback method
     switch(_recvSessMsgType)
      {
       // ----------------- 'FILE_UPLOAD_REQ' Session Message ----------------- //
       case FILE_UPLOAD_REQ:
        _sessMgrOp = UPLOAD;
        uploadStartCallback();
        break;

       // ---------------- 'FILE_DOWNLOAD_REQ' Session Message ---------------- //
       case FILE_DOWNLOAD_REQ:
        _sessMgrOp = DOWNLOAD;
        downloadStartCallback();
        break;

       // ----------------- 'FILE_DELETE_REQ' Session Message ----------------- //
       case FILE_DELETE_REQ:
        _sessMgrOp = DELETE;
        deleteStartCallback();
        break;

       // ----------------- 'FILE_RENAME_REQ' Session Message ----------------- //
       case FILE_RENAME_REQ:
        _sessMgrOp = RENAME;
        renameStartCallback();
        break;

       // ------------------ 'FILE_LIST_REQ' Session Message ------------------ //
       case FILE_LIST_REQ:
        _sessMgrOp = LIST;
        listStartCallback();
        break;

       // --------------------- Unexpected Session Message --------------------- //
       // Unexpected session message type
       default:
        sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE, "Client: \"" + *_connMgr._name + "\", "
                                                          "received session message type "
                                                          + std::to_string(_recvSessMsgType) +
                                                          " with the session manager being 'IDLE'");
      }
     break;


    /* --------------- 'UPLOAD' Server Session Manager Operation --------------- */
    case SessMgr::UPLOAD:

     // --------------------- 'CONFIRM' Signaling Message --------------------- //
     if(_recvSessMsgType == CONFIRM)
      uploadConfCallback();

     // ---------------------- Unexpected Session Message ---------------------- //
     else
      sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) +
                                                       "\" session message type received in the "
                                                       "'UPLOAD' operation, step "
                                                       + sessMgrOpStepToStrUpCase());
     break;


    /* -------------- 'DOWNLOAD' Server Session Manager Operation -------------- */
    case SessMgr::DOWNLOAD:

     // Depending on the type of the received session message
     switch(_recvSessMsgType)
      {
       // -------------------- 'CONFIRM' Signaling Message -------------------- //
       case CONFIRM:
        downloadConfSendFileCallback();
        return;

       // ------------------- 'COMPLETED' Signaling Message ------------------- //
       case COMPLETED:
        downloadComplCallback();
        return;

       // --------------------- Unexpected Session Message --------------------- //
       default:
        sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) +
                                                         "\" session message type received in the "
                                                         "'DOWNLOAD' operation, step "
                                                         + sessMgrOpStepToStrUpCase());
      }
     break;


    /* --------------- 'DELETE' Server Session Manager Operation --------------- */
    case SessMgr::DELETE:

     // --------------------- 'CONFIRM' Signaling Message --------------------- //
     if(_recvSessMsgType == CONFIRM)
      deleteConfCallback();

      // ---------------------- Unexpected Session Message ---------------------- //
     else
      sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) +
                                                       "\" session message type received in the "
                                                       "'DELETE' operation, step "
                                                       + sessMgrOpStepToStrUpCase());
     break;


    /* --------------- 'RENAME' Server Session Manager Operation --------------- */
    case SessMgr::RENAME:

     // The 'RENAME' operation has no callback methods other than the operation starting callback
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) +
                                                      "\" session message type received in the "
                                                      "'RENAME' operation, step "
                                                      + sessMgrOpStepToStrUpCase());
     break;


    /* ---------------- 'LIST' Server Session Manager Operation ---------------- */
    case SessMgr::LIST:

     // -------------------- 'COMPLETED' Signaling Message -------------------- //
     if(_recvSessMsgType == COMPLETED)
      listComplCallback();

     // ---------------------- Unexpected Session Message ---------------------- //
     else
      sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) +
                                                       "\" session message type received in the "
                                                       "'LIST' operation, step "
                                                       + sessMgrOpStepToStrUpCase());
     break;
   }
 }


/* --------------------- 'UPLOAD' Operation Callback Methods --------------------- */

/**
 * @brief 'UPLOAD' operation 'START' callback, which:\n\n
 *           1) Loads the name and metadata of the remote file to be uploaded\n\n
 *              2.1) If the file to be uploaded is empty and the file in the user's storage
 *                   pool does not exist or is empty, directly touch such a file in the user's
 *                   storage pool and notify them that the upload operation has completed\n\n
 *              2.2) If the file to be uploaded is NOT empty, depending on whether a file with
 *                   the same name already exists in the user's storage pool:\n\n
 *                   2.1.1) If it does, the local file information are sent to the client,
 *                          with their confirmation  being required on whether the upload
 *                          should proceed and so such file be overwritten\n\n
 *                   2.2.2) If it does not, notify the client that the server
 *                          is ready to receive the file's raw contents
 * @throws ERR_SESS_MALFORMED_MESSAGE    Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_MAIN_FILE_IS_DIR     The file to be uploaded was found as a
 *                                       directory in the client's storage pool (!)
 * @throws ERR_SESS_INTERNAL_ERROR       Invalid session manager operation
 *                                       or step or file read/write error
 * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the uploaded empty main file
 * @throws ERR_SESS_FILE_OPEN_FAILED     Error in opening the uploaded empty main file
 * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the uploaded empty main file
 * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the empty main file's metadata
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SrvSessMgr::uploadStartCallback()
 {
  // Load the name and metadata of the remote file to
  // be uploaded into the '_remFileInfo' attribute
  loadRemSessMsgFileInfo();

  // Initialize the main and temporary absolute paths of the file to be uploaded
  _mainFileAbsPath = new std::string(*_mainDirAbsPath + _remFileInfo->fileName);
  _tmpFileAbsPath  = new std::string(*_tmpDirAbsPath + _remFileInfo->fileName + "_PART");

  /*
  // LOG: Remote file information
  _remFileInfo->printFileInfo();

  // LOG: Main and temporary files absolute paths
  std::cout << "_mainFileAbsPath = " << *_mainFileAbsPath << std::endl;
  std::cout << "_tmpFileAbsPath = " << *_tmpFileAbsPath << std::endl;
  */

  // Check whether a file with the same name of the one to be uploaded
  // already exists in the user's storage pool by attempting to
  // load its information into the '_mainFileInfo' attribute
  checkLoadMainFileInfo();

  // If the file to be uploaded is empty and the file in
  // the user's storage pool does not exist or is empty
  if(_remFileInfo->meta->fileSizeRaw == 0 &&
    (_mainFileInfo == nullptr || _mainFileInfo->meta->fileSizeRaw == 0))
   {
    // Touch the empty file in the user's storage
    // pool, possibly overwriting the existing one
    touchEmptyFile();

    // Inform the client that the empty file has been successfully uploaded
    sendSrvSessSignalMsg(COMPLETED);

    LOG_INFO("[" + *_connMgr._name + "] Empty file \"" +
             _remFileInfo->fileName + "\" uploaded into the storage pool")

    // Reset the server session manager state and return
    resetSessState();
    return;
   }

  // Otherwise, if a file with the same name of the one to
  // be uploaded was found in the user's storage pool
  if(_mainFileInfo != nullptr)
   {
    // Prepare a 'SessMsgFileInfo' session message of type 'FILE_EXISTS'
    // containing the local file name and metadata and send it to the client
    sendSessMsgFileInfo(FILE_EXISTS);

    // Set the server session manager to expect the file upload confirmation
    _sessMgrOpStep = WAITING_CONF;

    LOG_INFO("[" + *_connMgr._name + "] Received upload request of already-existing \""
             + _remFileInfo->fileName + "\" file, awaiting client confirmation")
   }

  // Otherwise, if a file with the same name of the one to
  // be uploaded was not found in the user's storage pool
  else
   {
    // Inform the client that a file with such name is not present
    // in the user's storage pool, and so that the server is now
    // expecting the raw contents of the file to be uploaded
    sendSrvSessSignalMsg(FILE_NOT_EXISTS);

    // Prepare the server session manager to receive
    // the raw contents of the file to be uploaded
    prepRecvFileRaw();

    LOG_INFO("[" + *_connMgr._name + "] Received upload request of "
             "file \"" + _remFileInfo->fileName + "\" not existing "
             "in the storage pool, awaiting the raw file contents")
   }
 }


/**
 * @brief  'UPLOAD' operation 'CONFIRM' session message callback, which:\n\n
 *             1) [PATCH] If the file to be uploaded is empty, touch it in the user's
 *                storage pool, possibly overwriting the existing one, notify the client
 *                the success of the upload operation and reset the session state\n\n
 *             2) If the file to be uploaded is NOT empty, prepare the server session
 *                manager to receive its raw contents.
 * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the existing empty file
 * @throws ERR_SESS_FILE_OPEN_FAILED     Error in touching the empty file to be uploaded
 * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the empty file to be uploaded
 * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the metadata
 *                                       of the file to be uploaded
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 * @throws ERR_SESS_FILE_OPEN_FAILED     Failed to open the temporary file
 *                                       descriptor in write-byte mode
 */
void SrvSessMgr::uploadConfCallback()
 {
  /* [PATCH] */
  // If the file to be uploaded is empty
  if(_remFileInfo->meta->fileSizeRaw == 0)
   {
    // Touch the empty file in the user's storage
    // pool, possibly overwriting the existing one
    touchEmptyFile();

    // Inform the client that the empty file has been successfully uploaded
    sendSrvSessSignalMsg(COMPLETED);

    LOG_INFO("[" + *_connMgr._name + "] Empty file \""
             + _remFileInfo->fileName + "\" uploaded into the storage pool")

    // Reset the server session manager state and return
    resetSessState();
    return;
   }

   // Otherwise, if the file to be uploaded is NOT empty
  else
   {
    // Prepare the server session manager to receive
    // the raw contents of the file to be uploaded
    prepRecvFileRaw();

    LOG_INFO("[" + *_connMgr._name + "] Upload of file \""
             + _remFileInfo->fileName + "\" confirmed, awaiting "
             "the file's raw contents (" + _remFileInfo->meta->fileSizeStr + ")")
   }
 }


/**
 * @brief  'UPLOAD' operation raw file contents callback, which:\n\n
 *            1) If the file being uploaded has not been completely received yet, decrypts its received raw
 *               bytes and writes them into the session's temporary file in the user's temporary directory\n\n
 *            2) If the file being uploaded has been completely received, verifies its trailing integrity
 *               tag, moves the temporary into the associated main file in the user's storage pool, sets
 *               its last modified time to the one specified in the '_remFileInfo' object, notifies the
 *               success of the upload operation to the client and resets the server session manager state
 * @param  recvBytes The number of bytes received in the associated connection manager's primary buffer
 * @throws ERR_FILE_WRITE_FAILED          Error in writing to the temporary file
 * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
 * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
 * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
 * @throws ERR_SESS_FILE_CLOSE_FAILED     Error in closing the temporary file
 * @throws ERR_SESS_FILE_RENAME_FAILED    Error in moving the temporary file to the main directory
 * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the main file's last modification time
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT      EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE    EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL     EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED        Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED          The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED                send() fatal error
 * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
 *                                        file or NULL session attributes
 */
void SrvSessMgr::uploadRecvRawCallback(size_t recvBytes)
 {
  // fwrite() return, representing the number of bytes written
  // from the secondary connection buffer into the temporary file
  size_t fwriteRet;

#ifdef DEBUG_MODE
  // The file's current upload progress discretized between 0-100%
  unsigned char currUploadProg;
#endif

  /* -------------------------------- File Upload Loop -------------------------------- */

  // If the file being uploaded has not been completely received yet
  if(_rawBytesRem > 0)
   {
    // Decrypted the received file raw contents from
    // the primary into the secondary connection buffer
    _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[0], (int)recvBytes, &_connMgr._secBuf[0]);

    // Write the decrypted file contents from the secondary buffer into the temporary file
    fwriteRet = fwrite(_connMgr._secBuf, sizeof(char), recvBytes, _tmpFileDscr);

    // Writing into the temporary file less bytes than the ones received into the
    // primary connection buffer is a critical error that in the current session state
    // cannot be notified to the client and so require its connection to be dropped
    if(fwriteRet < recvBytes)
     THROW_EXEC_EXCP(ERR_FILE_WRITE_FAILED,"file: " + *_tmpFileAbsPath + "\", " + *_connMgr._name +
                                           "\" upload operation aborted","written " + std::to_string(fwriteRet)
                                           + " < recvBytes = " + std::to_string(recvBytes) + " bytes");

    // Update the number of remaining file of the file being uploaded
    _rawBytesRem -= recvBytes;

    // In DEBUG_MODE, compute and log the file's current upload progress
#ifdef DEBUG_MODE
    currUploadProg = (unsigned char)((float)(_remFileInfo->meta->fileSizeRaw - _rawBytesRem) /
                                     (float)_remFileInfo->meta->fileSizeRaw * 100);

    LOG_DEBUG("[" + *_connMgr._name + "] File \"" + _remFileInfo->fileName + "\" (" + _remFileInfo->meta->fileSizeStr +
              ") upload progress: " + std::to_string((int)currUploadProg) + "%")
#endif

    // If the file being uploaded has not been completely received yet, update the associated
    // connection manager's expected data block size to its number of remaining bytes
    if(_rawBytesRem > 0)
     _connMgr._recvBlockSize = _rawBytesRem;

    // Otherwise, if the file has been completely received, set the associated connection
    // manager's expected data block size to the size of an AES_128_GCM integrity tag
    else
     _connMgr._recvBlockSize = AES_128_GCM_TAG_SIZE;

    // Reset the index of the most significant byte in the primary connection buffer
    _connMgr._priBufInd = 0;
   }

  /* ------------------------ File Integrity Tag Verification ------------------------ */

  // Otherwise, if the file being uploaded has been fully received and so its
  // integrity must be verified via the trailing AES_128_GCM integrity tag
  else

   // If the complete integrity tag has not yet been received in
   // the primary connection buffer, wait for its additional bytes
   if(_connMgr._priBufInd != AES_128_GCM_TAG_SIZE)
    return;

   // Otherwise, if the file integrity tag has been fully received
   else
    {
     /*
      * Finalize the uploaded file by:
      *    1) Verifying its integrity tag
      *    2) Moving it from the temporary into the user's storage pool
      *    3) Setting its last modified time to the one
      *       specified in the '_remFileInfo' object
      */
     finalizeRecvFileRaw();

     // Notify the client that the file upload has been completed successfully
     sendSessSignalMsg(COMPLETED);

     // Log the successful upload operation
     LOG_INFO("[" + *_connMgr._name + "] File \"" + _remFileInfo->fileName + "\" ("
              + _remFileInfo->meta->fileSizeStr + ") uploaded into the storage pool")

     // Reset the server session state
     resetSessState();
    }
 }


/* -------------------- 'DOWNLOAD' Operation Callback Methods -------------------- */

/**
 * @brief  'DOWNLOAD' operation 'START' callback, checking whether a file with the same
 *         name of the one the client wants to download exists in their storage pool and:\n
 *            1) If such a file does not exist, notify the client that the
 *               download operation cannot proceed and reset the session state.\n
 *            2) If such a file exists, send its information to the client and set the
 *               session manager to expect the download operation completion or confirmation
 *               notification depending on whether the file to be downloaded is empty or not.
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file name in the 'SessMsgFileName' message
 * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be downloaded was found to be a directory (!)
 * @throws ERR_SESS_INTERNAL_ERROR      Failed to open the file descriptor
 *                                      of the file to be downloaded
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SrvSessMgr::downloadStartCallback()
 {
  // Retrieve the file name the client wants to download, also loading
  // its associated absolute path into the '_mainFileAbsPath' attribute
  std::string fileName = std::move(loadMainSessMsgFileName());

  // Check whether the file the client wants to download exists in their storage
  // pool by attempting to load its information into the '_mainFileInfo' attribute
  checkLoadMainFileInfo();

  // If the file the client wants to download was not found in their storage pool
  if(_mainFileInfo == nullptr)
   {
    // Notify the client that the file to be downloaded was not found
    sendSrvSessSignalMsg(FILE_NOT_EXISTS);

    LOG_INFO("[" + *_connMgr._name + "] Attempting to download "
             "file \""+ fileName + "\" not existing in the storage pool")

    // Reset the server session manager state and return
    resetSessState();
    return;
   }

  // Otherwise, if the file the client wants to download was found in their storage pool
  else
   {
    // If the file to be downloaded is empty
    if(_mainFileInfo->meta->fileSizeRaw == 0)
     {
      // Set the server session manager to expect the client completion notification
      _sessMgrOpStep = WAITING_COMPL;

      LOG_INFO("[" + *_connMgr._name + "] Received download request of empty file"
               " \"" + _mainFileInfo->fileName + "\", awaiting client completion")
     }

    // Otherwise, if the file to be downloaded is NOT empty
    else
     {
      // Attempt to open the file to be downloaded in read-byte mode
      _mainFileDscr = fopen(_mainFileAbsPath->c_str(), "rb");
      if(!_mainFileDscr)
       sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Failed to open the file descriptor of the"
                            " main file to be downloaded (" + *_mainFileAbsPath + ")");

      // Set the server session manager to expect the client confirmation notification
      _sessMgrOpStep = WAITING_CONF;

      LOG_INFO("[" + *_connMgr._name + "] Received download request"
               " of file \"" + _mainFileInfo->fileName + "\" ("
               + _mainFileInfo->meta->fileSizeStr + "), awaiting client confirmation")
     }

    // Prepare a 'SessMsgFileInfo' session message of type 'FILE_EXISTS' containing
    // the information on the file to be downloaded and send it to the client
    sendSessMsgFileInfo(FILE_EXISTS);
   }
 }


/**
 * @brief 'DOWNLOAD' operation 'CONFIRM' session message callback, sending the raw contents of
 *        the file to be downloaded and its resulting integrity tag to the client, and setting
 *        the server session manager to expect the client download completion notification
 * @throws ERR_FILE_WRITE_FAILED              Error in reading from the main file
 * @throws ERR_SESSABORT_UNEXPECTED_FILE_SIZE The sent file raw contents differ from its expected size
 * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The plaintext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
 * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED                    send() fatal error
 */
void SrvSessMgr::downloadConfSendFileCallback()
 {
  // fread() return, representing the number of bytes read
  // from main file into the secondary connection buffer
  size_t freadRet;

  // The total number of file bytes sent to the client
  size_t totBytesSent = 0;

#ifdef DEBUG_MODE
  // The file's current download progress discretized between 0-100%
  unsigned char currDownloadProg;
#endif

  // Initialize the file encryption operation
  _aesGCMMgr.encryptInit();

  // ------------------------------- File Download Loop ------------------------------- //

  do
   {
    // Read the file raw contents into the secondary buffer size (possibly filling it)
    freadRet = fread(_connMgr._secBuf, sizeof(char), _connMgr._secBufSize, _mainFileDscr);

    // An error occurred in reading the file raw contents is a critical
    // error that in the current session state cannot be notified
    // to the client and so require their connection to be dropped
    if(ferror(_mainFileDscr))
     THROW_EXEC_EXCP(ERR_FILE_READ_FAILED,"file: " + *_mainFileAbsPath + "\", "
                     + *_connMgr._name + "\" upload operation aborted", ERRNO_DESC);

    // If bytes were read from the file into the secondary connection buffer
    if(freadRet > 0)
     {
      // Encrypt the file raw contents from the secondary into the primary connection buffer
      _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0], (int)freadRet, &_connMgr._priBuf[0]);

      // Send the encrypted file contents to the client
      _connMgr.sendRaw(freadRet);

      // Update the total number of bytes sent to the client
      totBytesSent += freadRet;

      // In DEBUG_MODE, compute and log the file's current download progress
#ifdef DEBUG_MODE
      currDownloadProg = (unsigned char)((float)totBytesSent /
                         (float)_mainFileInfo->meta->fileSizeRaw * 100);

      LOG_DEBUG("[" + *_connMgr._name + "] File \"" + _mainFileInfo->fileName +
                "\" (" + _mainFileInfo->meta->fileSizeStr + ") download progress: "
                + std::to_string((int)currDownloadProg) + "%")
#endif
     }
   } while(!feof(_mainFileDscr)); // While the main file has not been completely read

  // ----------------------------- End File Download Loop ----------------------------- //

  // Having sent to the client  a number of bytes different from the file
  // size is a critical error that in the current session state cannot be
  // notified to the client and so require their connection to be dropped
  if(totBytesSent != _mainFileInfo->meta->fileSizeRaw)
   THROW_EXEC_EXCP(ERR_SESSABORT_UNEXPECTED_FILE_SIZE, "file: \"" + _mainFileInfo->fileName + "\", \""
                                                       + *_connMgr._name + "\" upload operation aborted",
                                                       std::to_string(totBytesSent) + " != "
                                                       + std::to_string(_mainFileInfo->meta->fileSizeRaw));

  // Finalize the file download operation by sending
  // the resulting integrity tag to the client
  sendRawTag();

  // Set the server session manager to expect the client download's completion
  _sessMgrOpStep = WAITING_COMPL;
 }


/**
 * @brief  'DOWNLOAD' operation 'COMPLETE' session message callback, logging the
 *         successful download operation and resetting the server session manager state
 */
void SrvSessMgr::downloadComplCallback()
 {
  // Log the success of the download operation depending
  // on whether the downloaded file is empty or not
  if(_mainFileInfo->meta->fileSizeRaw == 0)
   LOG_INFO("[" + *_connMgr._name + "] Empty file \""
            + _mainFileInfo->fileName + "\" downloaded from the storage pool")
  else
   LOG_INFO("[" + *_connMgr._name + "] File \"" + _mainFileInfo->fileName + "\" ("
            + _mainFileInfo->meta->fileSizeStr + ") downloaded from the storage pool")

  // Reset the server session manager state
  resetSessState();
 }


/* --------------------- 'DELETE' Operation Callback Methods --------------------- */

/**
 * @brief  'DELETE' operation 'START' callback, checking whether a file with the same
 *         name of the one the client wants to delete exists in their storage pool, and:\n
 *            1) If such a file does not exist, notify the client that the
 *               delete operation cannot proceed and reset the session state.\n
 *            2) If such a file exists, send its information to the client and set
 *               the session manager to expect the delete operation confirmation.
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file name in the 'SessMsgFileName' message
 * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be deleted was found to be a directory (!)
 * @throws ERR_SESS_INTERNAL_ERROR      Failed to open the file descriptor
 *                                      of the file to be deleted
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SrvSessMgr::deleteStartCallback()
 {
  // Retrieve the file name the client wants to delete, also loading
  // its associated absolute path into the '_mainFileAbsPath' attribute
  std::string fileName = std::move(loadMainSessMsgFileName());

  // Check whether the file the client wants to delete exists in their storage
  // pool by attempting to load its information into the '_mainFileInfo' attribute
  checkLoadMainFileInfo();

  // If the file the client wants to delete was not found in their storage pool
  if(_mainFileInfo == nullptr)
   {
    // Notify the client that the file was not found
    sendSrvSessSignalMsg(FILE_NOT_EXISTS);

    LOG_INFO("[" + *_connMgr._name + "] Attempting to delete "
             "file \""+ fileName + "\" not existing in the storage pool")

    // Reset the server session manager state and return
    resetSessState();
    return;
   }

   // Otherwise, if the file the client wants to delete was found in their storage pool
  else
   {
    // Prepare a 'SessMsgFileInfo' session message of type 'FILE_EXISTS' containing
    // the information on the file to be deleted and send it to the client
    sendSessMsgFileInfo(FILE_EXISTS);

    // Set the server session manager to expect the client confirmation notification
    _sessMgrOpStep = WAITING_CONF;

    LOG_INFO("[" + *_connMgr._name + "] Received delete request of file \""
             + _mainFileInfo->fileName + "\" (" + _mainFileInfo->meta->fileSizeStr +
             "), awaiting client confirmation")
   }
 }


/**
 * @brief  'DELETE' operation 'CONFIRM' session message callback, deleting the main file,
 *         notifying the client of its deletion and resetting the server session manager state
 * @throws ERR_SESS_INTERNAL_ERROR Failed to delete the main file
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SrvSessMgr::deleteConfCallback()
 {
  // Attempt to delete the main file
  if(remove(_mainFileAbsPath->c_str()) == -1)
   sendSrvSessSignalMsg(ERR_INTERNAL_ERROR, "Failed to delete file \"" + *_mainFileAbsPath +
                                            "\" (reason: " + ERRNO_DESC + ")");

  // Notify the client that the file has been successfully deleted
  sendSrvSessSignalMsg(COMPLETED);

  // Log the successful delete operation
  LOG_INFO("[" + *_connMgr._name + "] File \"" + _mainFileInfo->fileName +
           "\" (" + _mainFileInfo->meta->fileSizeStr + ") deleted from the storage pool")

  // Reset the server session state
  resetSessState();
 }


/* --------------------- 'RENAME' Operation Callback Methods --------------------- */

/**
 * @brief  'RENAME' operation 'START' callback, which:\n
 *            1) If the file to be renamed does not exist in the user's storage
 *               pool, notifies them that the rename operation cannot proceed.\n
 *            2) If a file with the same name of the one the user wants to rename
 *               the file to exists in their storage pool, sends them its
 *               information, implying that the rename operation cannot proceed.\n
 *            3) If the file to be renamed exists and a file with its new name does not,
 *               renames the file and notifies the client the success of the rename operation.\n
 *         The server session manager state is reset regardless of the outcome.
 * @throws ERR_SESS_MALFORMED_MESSAGE   The old or new file name is not a valid Linux
 *                                      file name or the two file names coincide
 * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be renamed or the one with its
 *                                      new name was found to be a directory (!)
 * @throws ERR_SESS_INTERNAL_ERROR      Failed to rename the file from its old to its new name
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void SrvSessMgr::renameStartCallback()
 {
  // The candidate old and new name of the file to be renamed
  std::string* oldFilename = nullptr;
  std::string* newFilename = nullptr;

  // Retrieve the candidate old and new name of the file to be
  // renamed, also loading their associated absolute paths into the
  // '_mainFileAbsPath' and '_tmpFileAbsPath' attributes respectively
  loadSessMsgFileRename(&oldFilename,&newFilename);

  // Initialize the absolute paths associated with the old and the new file names
  std::string oldFileNameAbsPath(*_mainDirAbsPath + *oldFilename);
  std::string newFileNameAbsPath(*_mainDirAbsPath + *newFilename);

  /*
  // LOG: old and new file names absolute paths
  std::cout << "oldFileNameAbsPath = " << oldFileNameAbsPath << std::endl;
  std::cout << "newFileNameAbsPath = " << newFileNameAbsPath << std::endl;
  */

  // Check whether the file the client wants to rename exists in their storage
  // pool by attempting to load its information into the '_mainFileInfo' attribute
  _mainFileAbsPath = &oldFileNameAbsPath;
  checkLoadMainFileInfo();

  // If the file the client wants to rename was not found in their storage pool
  if(_mainFileInfo == nullptr)
   {
    // Notify the client that the file to be renamed was not found
    sendSrvSessSignalMsg(FILE_NOT_EXISTS);

    LOG_INFO("[" + *_connMgr._name + "] Attempting to rename file \""
             + *oldFilename + "\" not existing in the storage pool")
   }

  // Otherwise, if the file the client wants to rename was found in their storage pool
  else
   {
    // Delete the information on the file the client wants to rename
    delete _mainFileInfo;

    // Check whether a file with the same name of the one the user wants
    // to rename the file to exists in their storage pool by attempting
    // to load its information into the '_mainFileInfo' attribute
    _mainFileAbsPath = &newFileNameAbsPath;
    checkLoadMainFileInfo();

    // If a file with the same name of the one the user wants
    // to rename the file to exists in their storage pool
    if(_mainFileInfo != nullptr)
     {
      // Prepare and send a 'SessMsgFileInfo' session message of type 'FILE_EXISTS'
      // containing the information on the file with the same name of the
      // one the user wants to rename the file to and send it to the client
      sendSessMsgFileInfo(FILE_EXISTS);

      LOG_INFO("[" + *_connMgr._name + "] Attempting to rename file \""+ *oldFilename + "\" to "
               "\"" + *newFilename + "\", with the latter already existing in the storage pool")
     }

    // Otherwise, if a file with the same name of the one the user
    // wants to rename the file to does not exist in their storage pool
    else
     {
      // Attempt to rename the file in the user's storage pool
      if(rename(oldFileNameAbsPath.c_str(),newFileNameAbsPath.c_str()))
       sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Failed to rename file \"" + *oldFilename
                            + "\" to \"" + *newFilename + "\" in the storage pool");

      // Notify the client of the success of the rename operation
      sendSessSignalMsg(COMPLETED);

      LOG_INFO("[" + *_connMgr._name + "] File \""+ *oldFilename
               + "\" renamed to \"" + *newFilename + "\"")
     }
   }

  // Delete the old and new file names strings
  // and reset the '_mainFileAbsPath' attribute
  delete oldFilename;
  delete newFilename;
  _mainFileAbsPath = nullptr;

  // Reset the server session manager state and return
  resetSessState();
 }


/* ---------------------- 'LIST' Operation Callback Methods ---------------------- */

/**
 * @brief  'LIST' operation 'START' callback, building a snapshot of the user's
 *         storage pool contents, sending its serialized size to the client and:\n
 *            1) If the user's storage pool is empty, reset the server session state.\n
 *            2) If the user's storage pool is NOT empty, send the client its
 *               serialized contents and set the server session manager to
 *               expect their completion notification.
 * @throws ERR_DIR_OPEN_FAILED                The user's storage pool was not found (!)
 * @throws ERR_SESS_FILE_READ_FAILED          Error in reading from the user's storage pool
 * @throws ERR_SESS_DIR_INFO_OVERFLOW         The storage pool information size exceeds 4GB
 * @throws ERR_SESS_INTERNAL_ERROR            The serialized size of the
 *                                            user's storage pool exceeds 4GB
 * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
 * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED                    send() fatal error
 * @throws ERR_SESSABORT_UNEXPECTED_POOL_SIZE The sent pool serialized contents
 *                                            differ from their expected size
 */
void SrvSessMgr::listStartCallback()
 {
  // Attempt to build a snapshot of the user storage
  // pool's contents into the '_mainDirInfo' attribute
  try
   { _mainDirInfo = new DirInfo(_mainDirAbsPath); }
  catch(sessErrExcp& poolDirExcp)
   {
    // Notify the client of the internal error
    sendSessSignalMsg(ERR_INTERNAL_ERROR);

    // Rethrow the exception
    throw;
   }

  /*
  // LOG: User storage pool contents and information
  _mainDirInfo->printDirContents();
  std::cout << "N?? files = " << _mainDirInfo->numFiles << std::endl;
  std::cout << "Pool contents' raw size = " << _mainDirInfo->dirRawSize << std::endl;
  */

  /*
   * The serialized size of the user's storage pool is given by the sum of
   * its contents' raw size ('poolInfo.dirRawSize') + 1 for each file in
   * the pool, which is due to the additional 'filenameLen''unsigned char'
   * attribute storing the file name length in the 'PoolFileInfo' struct
   */

  // Assert the serialized size of the user's storage
  // pool not to overflow an unsigned integer
  if(_mainDirInfo->dirRawSize > UINT_MAX - _mainDirInfo->numFiles)
   sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Storage pool serialized contents' size"
                                           "overflow (raw contents' size = "
                                           + std::to_string(_mainDirInfo->dirRawSize) +
                                           ", numFiles = " + std::to_string(_mainDirInfo->numFiles));

  // Compute and write the serialized size of the user's
  // storage pool in the '_rawBytesRem' attribute
  _rawBytesRem = _mainDirInfo->dirRawSize + _mainDirInfo->numFiles;

  // Prepare and send a 'SessMsgPoolSize' session message of implicit 'POOL_SIZE' type
  // containing the serialized size of the user's storage pool and send it to the client
  sendSessMsgPoolSize();

  // If the user's storage pool is empty
  if(_rawBytesRem == 0)
   {
    // Log that the user requested the contents of its empty storage pool
    LOG_INFO("[" + *_connMgr._name + "] Requested the empty storage pool's contents")

    // Reset the session state and return
    resetSessState();
   }

  // Otherwise, if the user's storage pool is NOT empty
  else
   {
    // Send the client the serialized contents of its storage pool
    sendPoolRawContents();

    // Set the server session manager to expect the
    // client pool contents' reception completion
    _sessMgrOpStep = WAITING_COMPL;

    LOG_INFO("[" + *_connMgr._name + "] Sent the requested storage pool's contents ("
             + std::to_string(_mainDirInfo->numFiles) + " files), awaiting client confirmation")
   }
 }


/**
 * @brief  Serializes and sends a user's pool contents and its associated integrity tag to the client
 * @throws ERR_SESSABORT_UNEXPECTED_POOL_SIZE The sent pool serialized contents
 *                                            differ from their expected size
 * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The plaintext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
 * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED                    send() fatal error
 */
void SrvSessMgr::sendPoolRawContents()
 {
  // The maximum secondary buffer index at which a 'PoolFileInfo'
  // struct of maximum size (filenameLen = 255) can be written
  unsigned int maxSecBufIndWrite = _connMgr._secBufSize - NAME_MAX - 3 * sizeof(signed long) - 3;

  // The serialized information size of a file in the user's storage pool
  unsigned short poolFileInfoSize;

  // The total serialized pool contents sent to the client
  size_t totBytesSent = 0;

  // Reset the index of the first available byte in the secondary
  // connection buffer at which writing the serialized pool contents
  _connMgr._secBufInd = 0;

  // Initialize the pool raw contents' encryption operation
  _aesGCMMgr.encryptInit();

  // ------------------ Serialized Pool Contents Sending Cycle ------------------ //

  // For each file in the user's storage pool
  for(const auto& poolFile : _mainDirInfo->dirFiles)
   {
    // If the index of the first available byte in the secondary
    // connection buffer is greater than the maximum index at which
    // a 'PoolFileInfo' struct of maximum size can be written
    if(_connMgr._secBufInd >= maxSecBufIndWrite)
     {
      // Encrypt the pool's serialized contents from the
      // secondary into the primary connection buffer
      _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0],
                              (int)(_connMgr._secBufInd), &_connMgr._priBuf[0]);

      // Send the encrypted serialized pool contents to the client
      _connMgr.sendRaw(_connMgr._secBufInd);

      // Update the total number of serialized pool bytes sent to the client
      totBytesSent += _connMgr._secBufInd;

      // Reset the index of the first available
      // byte in the secondary connection buffer
      _connMgr._secBufInd = 0;
     }

    // Interpret the contents starting at the index of the first available
    // byte in the secondary connection buffer as a 'PoolFileInfo' struct
    PoolFileInfo* serPoolFile = reinterpret_cast<PoolFileInfo*>(&_connMgr._secBuf[_connMgr._secBufInd]);

    // Initialize the 'PoolFileInfo' struct with the file information
    serPoolFile->filenameLen = poolFile->fileName.length();
    serPoolFile->fileSizeRaw = poolFile->meta->fileSizeRaw;
    serPoolFile->lastModTimeRaw = poolFile->meta->lastModTimeRaw;
    serPoolFile->creationTimeRaw = poolFile->meta->creationTimeRaw;
    memcpy(reinterpret_cast<char*>(serPoolFile->filename),
           poolFile->fileName.c_str(), poolFile->fileName.length());

    // Compute the 'PoolFileInfo' struct size from its 'filenameLen' member
    poolFileInfoSize = sizeof(unsigned char) + 3 * sizeof(long int) + poolFile->fileName.length();

    // Update the index of the first available byte in the secondary connection buffer
    _connMgr._secBufInd += poolFileInfoSize;
   }

  // If there are serialized pool contents remaining to be sent to the client
  if(_connMgr._secBufInd > 0)
   {
    // Encrypt the pool's serialized contents from the
    // secondary into the primary connection buffer
    _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0], (int)(_connMgr._secBufInd), &_connMgr._priBuf[0]);

    // Send the encrypted serialized pool contents to the client
    _connMgr.sendRaw(_connMgr._secBufInd);

    // Update the total number of serialized pool bytes sent to the client
    totBytesSent += _connMgr._secBufInd;
   }

  // ---------------- End Serialized Pool Contents Sending Cycle ---------------- //

  // Having sent the client a number of bytes different that the previously computed
  // serialized pool size is a critical error that in the current session state
  // cannot be notified to the client and so require their connection to be dropped
  if(totBytesSent != _rawBytesRem)
   THROW_EXEC_EXCP(ERR_SESSABORT_UNEXPECTED_POOL_SIZE, "\"" + *_connMgr._name + "\" LIST operation"
                                                       " aborted", std::to_string(totBytesSent) +
                                                       " != " + std::to_string(_rawBytesRem));

  // Finalize the serialized pool contents transmission
  // by sending the resulting integrity tag to the client
  sendRawTag();
 }


/**
 * @brief  'LIST' operation 'COMPLETED' session message callback, logging the success
 *         of the 'LIST' operation and resetting the server session manager state
 */
void SrvSessMgr::listComplCallback()
 {
  // Log the success of the 'LIST' operation
  LOG_INFO("[" + *_connMgr._name + "] Successfully received the storage pool's contents")

  // Reset the server session state
  resetSessState();
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Server session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the srvConnMgr parent object
 * @param srvConnMgr A reference to the server connection manager parent object
 */
SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr),srvConnMgr._poolDir)
 {}

/* Same destructor of the SessMgr base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief  Server Session message handler, which:\n\n
 *            1) Unwraps a received session message wrapper from
 *               the primary into the secondary connection buffer\n\n
 *            2) Asserts the resulting session message to be allowed in
 *               the current server session manager operation and step\n\n
 *            3) Handles session-resetting or terminating signaling messages\n\n
 *            4) Handles session error signaling messages\n\n
 *            5) Valid session messages requiring further action are
 *               dispatched to the session callback method associated
 *               with the current server session manager operation and step
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void SrvSessMgr::srvSessMsgHandler()
{
 // Unwrap the received session message wrapper stored in
 // the connection's primary buffer into its associated
 // session message in the connection's secondary buffer
 unwrapSessMsg();

 // Interpret the contents of associated connection
 // manager's secondary buffer as a base session message
 SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_connMgr._secBuf);

 // Copy the received session message length
 // and type into their dedicated attributes
 _recvSessMsgLen = sessMsg->msgLen;
 _recvSessMsgType = sessMsg->msgType;

 // If a signaling message type was received, assert the message
 // length to be equal to the size of a base session message
 if(isSessSignalingMsgType(_recvSessMsgType) && _recvSessMsgLen != sizeof(SessMsg))
  sendSrvSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received a session signaling message"
                                                  " of invalid length ("
                                                  + std::to_string(_recvSessMsgLen) + ")");

 /*
  * Check whether the received session message type:
  *   1) Should trigger a session state reset or termination,
  *      directly performing the appropriate actions.
  *   2) Is valid in the current server session manager
  *      operation and step, signaling the error to the client
  *      and throwing the associated exception otherwise.
  */
 switch(_recvSessMsgType)
  {
   /* -------------------------- Operation-Starting Payload Message Types -------------------------- */

   // Operation-starting payload session message types are allowed
   // only with the server session manager in the 'IDLE' operation
   case FILE_UPLOAD_REQ:
   case FILE_DOWNLOAD_REQ:
   case FILE_DELETE_REQ:
   case FILE_RENAME_REQ:
   case FILE_LIST_REQ:
    if(_sessMgrOp != IDLE)
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE, "\"" + std::to_string(_recvSessMsgType) + "\" "
                                                       "operation-starting session message type received in"
                                                       " session operation \"" + sessMgrOpToStrUpCase() +
                                                       "\", step "+ sessMgrOpStepToStrUpCase());
    break;

   /* ------------------------------ 'CONFIRM' Signaling Message Type ------------------------------ */

   // A 'CONFIRM' signaling message type is allowed only in the 'UPLOAD',
   // 'DOWNLOAD' and 'DELETE' operations with step 'WAITING_CONF'
   case CONFIRM:
    if(!((_sessMgrOp == UPLOAD || _sessMgrOp == DOWNLOAD || _sessMgrOp == DELETE)
         && _sessMgrOpStep == WAITING_CONF))
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'CONFIRM' session message received in "
                                                      "session operation \"" + sessMgrOpToStrUpCase() +
                                                      "\", step " + sessMgrOpStepToStrUpCase());
    break;

   /* ------------------------------- 'CANCEL' Signaling Message Type ------------------------------- */

   // A 'CANCEL' signaling message type is allowed only in the 'UPLOAD',
   // 'DOWNLOAD' and 'DELETE' operations with step 'WAITING_CONF'
   case CANCEL:

    // Since after sending a 'CANCEL' message the client has supposedly reset its session
    // state, in case such a message is received in an invalid operation or step just log
    // the error without notifying the client that an unexpected session message was received
    if(!((_sessMgrOp == UPLOAD || _sessMgrOp == DOWNLOAD || _sessMgrOp == DELETE)
         && _sessMgrOpStep == WAITING_CONF))
     LOG_WARNING("Client \"" + *_connMgr._name + "\" cancelled an operation with the session manager "
                 "in operation '" + sessMgrOpToStrUpCase() + "', step " + sessMgrOpStepToStrUpCase())

    // Otherwise, if the 'CANCEL' message is valid for the current
    // operation and step, log the operation that has been cancelled
    else
     {
      if(_sessMgrOp == UPLOAD)
       LOG_INFO("[" + *_connMgr._name + "] File upload cancelled (file: \""
                + _remFileInfo->fileName + "\", size: " + _remFileInfo->meta->fileSizeStr + ")")
      else
       if(_sessMgrOp == DOWNLOAD)
        LOG_INFO("[" + *_connMgr._name + "] File download cancelled (file: \""
                 + _mainFileInfo->fileName + "\", size: " + _mainFileInfo->meta->fileSizeStr + ")")
       else
        LOG_INFO("[" + *_connMgr._name + "] File deletion cancelled (file: \""
                 + _mainFileInfo->fileName + "\", size: " + _mainFileInfo->meta->fileSizeStr + ")")
     }

    // Reset the server session state and return
    resetSessState();
    return;

   /* ---------------------------- 'COMPLETED' Signaling Message Type ---------------------------- */

   /*
    * A 'COMPLETED' signaling message type is allowed only in:
    *   1) The 'DOWNLOAD' operation of any step
    *   2) The 'LIST' operation with step 'WAITING_COMPL'
    */
   case COMPLETED:

    // Since after sending a 'COMPLETED' message the client has supposedly reset its session state,
    // if such a message type is received in an invalid operation or step just throw the associated
    // exception without notifying the client that an unexpected session message was received
    if(!((_sessMgrOp == DOWNLOAD) || (_sessMgrOp == LIST && _sessMgrOpStep == WAITING_COMPL)))
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, "Client: \"" + *_connMgr._name + "\", " + abortedOpToStr(),
                                                  "'COMPLETED' session message received in session operation "
                                                  "\"" + sessMgrOpToStrUpCase() + "\", step "
                                                  + sessMgrOpStepToStrUpCase());
     break;

   /* ------------------------------- 'BYE' Signaling Message Type ------------------------------- */

   // A 'BYE' signaling message type is allowed in the 'IDLE' operation only
   case BYE:

    // Since after sending a 'BYE' message the client is supposedly shutting down the connection,
    // if such a message type is received in an invalid operation or step just throw the associated
    // exception without notifying the client that an unexpected session message was received
    if(_sessMgrOp != IDLE)
     LOG_WARNING("Client \"" + *_connMgr._name + "\" gracefully disconnecting with the session manager in"
                 "the \"" + sessMgrOpToStrUpCase() + "\" operation, step " + sessMgrOpStepToStrUpCase())

    // Set the associated server connection manager to be terminated and return
    _connMgr._shutdownConn = true;
    return;

   /* ------------------------------ Error Signaling Message Types ------------------------------ */

   /* Error Signaling Message Types are allowed in all operations and steps */

   // The client reported to have experienced a recoverable internal error
   case ERR_INTERNAL_ERROR:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_INTERNAL_ERROR, "Client: \"" + *_connMgr._name +
                                                     "\", " + abortedOpToStr());

   // The client reported to have received an unexpected session message
   case ERR_UNEXPECTED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE, "Client: \"" + *_connMgr._name +
                                                         "\", " + abortedOpToStr());

   // The client reported to have received a malformed session message
   case ERR_MALFORMED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_MALFORMED_MESSAGE, "Client: \"" + *_connMgr._name +
                                                        "\", " + abortedOpToStr());

   // The client reported to have received a session message of unknown type, an error to be attributed to
   // a desynchronization between the connection peers' IVs and that requires the connection to be reset
   case ERR_UNKNOWN_SESSMSG_TYPE:
    THROW_EXEC_EXCP(ERR_SESSABORT_SRV_CLI_UNKNOWN_SESSMSG_TYPE, "Client: \"" + *_connMgr._name +
                                                                "\", " + abortedOpToStr());

   /* ----------------------------------- Unknown Message Type ----------------------------------- */

   // A session message of unknown type has been received, an error to be attributed to a
   // desynchronization between the connection peers' IVs and that requires the connection to be reset
   default:
    sendSrvSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE,std::to_string(_recvSessMsgType));
  }

 /*
  * At this point the received session message type is VALID
  * for the current server session manager operation and step
  */

 /*
 // LOG: Received session message length and type
 std::cout << "_recvSessMsgLen = " << _recvSessMsgLen << std::endl;
 std::cout << "_recvSessMsgType = " << _recvSessMsgType << std::endl;
 */

 // Dispatch the received session message to the session callback method
 // associated with the session manager current operation and step
 dispatchRecvSessMsg();
}


/**
 * @brief  Server session raw handler, passing the number of bytes read from the
 *         connection socket into the primary connection buffer to the raw sub-handler
 *         associated with the current server session manager operation and step
 * @param  recvBytes The number of bytes read from the connection
 *                   socket into the primary connection buffer
 * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid server session manager operation
 *                                        and step for receiving raw data
 * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
 * @throws ERR_FILE_WRITE_FAILED          Failed to write into the temporary file
 * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
 * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
 * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
 *                                        file or NULL session attributes
 * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the uploaded file's metadata
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT      EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE    EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL     EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED        Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED          The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED                send() fatal error
 */
void SrvSessMgr::srvSessRawHandler(size_t recvBytes)
 {
  // In its current implementation the only operation and step in which the SafeCloud
  // server may receive raw data is when receiving the contents of a file being uploaded
  if(_sessMgrOp != UPLOAD || _sessMgrOpStep != WAITING_RAW)
   THROW_EXEC_EXCP(ERR_SESSABORT_INTERNAL_ERROR, "Receiving raw data with the server session manager"
                                                 " in operation \"" + sessMgrOpToStrUpCase() +
                                                 "\", step " + sessMgrOpStepToStrUpCase());

  // Pass the number of bytes read from the connection socket into
  // the primary connection buffer to 'UPLOAD' raw sub-handler
  uploadRecvRawCallback(recvBytes);
 }