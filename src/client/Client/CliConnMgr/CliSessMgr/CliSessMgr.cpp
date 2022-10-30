/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "../CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "sanUtils.h"
#include "../../Client.h"

/* =============================== PRIVATE METHODS =============================== */

/**
 * @brief Sends a session message signaling type to the server and throws the
 *        associated exception in case of session error signaling message types
 * @param sessMsgSignalingType The session message signaling type to be sent to the server
 * @param errReason            An optional error reason to be embedded with the exception
 *                             associated with the session error signaling message type
 * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message
 *                                       invalid for its current operation or step
 * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
 * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The server disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void CliSessMgr::sendCliSessSignalMsg(SessMsgType sessMsgSignalingType)
 { sendCliSessSignalMsg(sessMsgSignalingType,""); }

void CliSessMgr::sendCliSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason)
 {
  // Attempt to send the signaling session message
  sendSessSignalMsg(sessMsgSignalingType);

  // If a session error signaling message type was sent, throw the associated exception
  switch(sessMsgSignalingType)
   {
    // The client session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedOpToStr());

    // A session message invalid for the current client session operation or step was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedOpToStr());

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, abortedOpToStr());

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     if(!errReason.empty())
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, abortedOpToStr(), errReason);
     else
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, abortedOpToStr());

    // A non-error signaling message type was sent
    default:
     break;
   }
 }


/**
 * @brief  Client Session message reception handler, which:\n
 *            1) Blocks the execution until a complete session message wrapper has
 *               been received in the associated connection manager's primary buffer\n
 *            2) Unwraps the received session message wrapper from
 *               the primary into the secondary connection buffer\n
 *            3) Asserts the resulting session message to be allowed in
 *               the current client session manager operation and step\n
 *            4) Handles session-resetting or terminating signaling messages\n
 *            5) Handles session error signaling messages\n
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::recvCheckCliSessMsg()
 {
  // Block the execution until a complete session message wrapper has
  // been received in the associated connection manager's primary buffer
  _connMgr.recvFullMsg();

  // Unwrap the received session message wrapper stored in the connection's primary
  // buffer into its associated session message in the connection's secondary buffer
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
   sendCliSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received a session signaling message of invalid "
                                                   "length (" + std::to_string(_recvSessMsgLen) + ")");

  // With the client session manager in the 'IDLE' operation
  // only session error signaling messages can be received
  if(_sessMgrOp == IDLE && !isSessErrSignalingMsgType(_recvSessMsgType))
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type " +
                                                    std::to_string(_recvSessMsgType) + " with"
                                                    " an IDLE client session manager");

  /*
   * Check whether the received session message type:
   *   1) Should trigger a session state reset or termination,
   *      directly performing the appropriate actions.
   *   2) Is valid in the current client session manager
   *      operation and step, signaling the error to the server
   *      and throwing the associated exception otherwise.
   */
  switch(_recvSessMsgType)
   {
    /* ---------------------------- 'FILE_EXISTS' Payload Message Type ---------------------------- */

    // A 'FILE_EXISTS' payload message type is allowed in
    // all operations but 'LIST' with step 'WAITING_RESP'
    case FILE_EXISTS:
     if(!(_sessMgrOp != LIST && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_EXISTS' session message received in"
                                                       " session operation \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
      break;

    /* ----------------------------- 'POOL_SIZE' Payload Message Type ----------------------------- */

    // A 'POOL_SIZE' payload message type is allowed in the 'LIST' operation with step 'WAITING_RESP'
    case POOL_SIZE:
     if(!(_sessMgrOp == LIST && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'POOL_SIZE' session message received in session"
                                                       " operation \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
     break;


    /* ------------------------- 'FILE_NOT_EXISTS' Signaling Message Type ------------------------- */

    // A 'FILE_NOT_EXISTS' signaling message type is allowed
    // in all operations but 'LIST' with step 'WAITING_RESP'
    case FILE_NOT_EXISTS:
     if(!(_sessMgrOp != LIST && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_NOT_EXISTS' session message received in "
                                                       "session operation \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
     break;

    /* ---------------------------- 'COMPLETED' Signaling Message Type ---------------------------- */

    /*
     * A 'COMPLETED' signaling message type is allowed only in:
     *   1) The 'UPLOAD' operation of any step
     *   2) The 'DELETE' operation with step 'WAITING_COMPL'
     *   3) The 'RENAME' operation with step 'WAITING_RESP'
     */
    case COMPLETED:

     // Since after sending a 'COMPLETED' message the SafeCloud server has supposedly reset its session
     // state, if such a message type is received in an invalid operation or step just throw the
     // associated exception without notifying the server that an unexpected session message was received
     if(!((_sessMgrOp == UPLOAD) || (_sessMgrOp == DELETE && _sessMgrOpStep == WAITING_COMPL) ||
          (_sessMgrOp == RENAME && _sessMgrOpStep == WAITING_RESP)))
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedOpToStr(), "'COMPLETED' session message received in "
                                                                     "session operation \"" + sessMgrOpToStrUpCase() +
                                                                     "\", step " + sessMgrOpStepToStrUpCase());
      break;

    /* ------------------------------- 'BYE' Signaling Message Type ------------------------------- */

    // A 'BYE' signaling message type is allowed in the 'IDLE' operation only
    case BYE:

     // Since after sending a 'BYE' message the SafeCloud server is supposedly shutting down the
     // connection, if such a message type is received in an invalid operation or step just throw the
     // associated exception without notifying the server that an unexpected session message was received
     if(_sessMgrOp != IDLE)
      THROW_EXEC_EXCP(ERR_SESSABORT_SRV_GRACEFUL_DISCONNECT, abortedOpToStr());
     else
      THROW_EXEC_EXCP(ERR_SESSABORT_SRV_GRACEFUL_DISCONNECT);

    /* ------------------------------ Error Signaling Message Types ------------------------------ */

    /* Error Signaling Message Types are allowed in all operations and steps */

    // The server reported to have experienced a recoverable internal error
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_INTERNAL_ERROR, abortedOpToStr());

    // The server reported to have received an unexpected session message
    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE, abortedOpToStr());

    // The server reported to have received a malformed session message
    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_MALFORMED_MESSAGE, abortedOpToStr());

    // The server reported to have received a session message of unknown type, an error to be attributed to
    // a desynchronization between the connection peers' IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESSABORT_CLI_SRV_UNKNOWN_SESSMSG_TYPE, abortedOpToStr());

    /* ----------------------------------- Unknown Message Type ----------------------------------- */

    // The error of receiving a session message of unknown type is to be attributed to a
    // desynchronization between the connection peers' IVs and that requires the connection to be reset
    default:
     sendCliSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE,std::to_string(_recvSessMsgType));
   }

  /*
   * At this point the received session message type is VALID
   * for the current client session manager operation and step
   */

  /*
  // LOG: Received session message length and type
  std::cout << "_recvSessMsgLen = " << _recvSessMsgLen << std::endl;
  std::cout << "_recvSessMsgType = " << _recvSessMsgType << std::endl;
  */
 }


/**
 * @brief  Prints a table comparing the metadata of the main and remote file and asks the user
 *         whether to continue the current file upload or download operation, confirming or
 *         cancelling the operation on the SafeCloud server depending on the user's response
 * @return A boolean indicating whether the file upload or download operation should continue
 * @throws ERR_SESS_INTERNAL_ERROR      Invalid session operation or step or uninitialized
 *                                      '_mainFileInfo' or '_remFileInfo' attributes
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
bool CliSessMgr::askFileOpConf()
 {
  // Assert the client session manager operation and step to be valid to ask for a user's file operation confirmation
  if(!((_sessMgrOp == UPLOAD || _sessMgrOp == DOWNLOAD) && _sessMgrOpStep == WAITING_RESP))
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Attempting to ask for a user file " + sessMgrOpToStrLowCase() + " confirmation in "
                                           "operation \"" + sessMgrOpToStrUpCase() + "\", step " + sessMgrOpStepToStrUpCase());

  // Ensure the '_mainFileInfo' attribute to have been initialized
  if(_mainFileInfo == nullptr)
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Attempting to ask for a user file \"" + sessMgrOpToStrLowCase() +
                                           "\" confirmation with a NULL '_mainFileInfo'");

  // Ensure the '_remFileInfo' attribute to have been initialized
  if(_remFileInfo == nullptr)
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Attempting to ask for a user file \"" + sessMgrOpToStrLowCase() +
                                           "\" confirmation with a NULL '_remFileInfo'");

  // Print a table comparing the metadata of the main and remote file
  _mainFileInfo->compareMetadata(_remFileInfo);

  // Assemble the file operation confirmation question
  std::string fileOpContinueQuestion("Do you want to continue " + sessMgrOpToStrLowCase() + "ing the file?");

  // Ask the user the file operation confirmation question and, if they confirm
  if(Client::askUser(fileOpContinueQuestion.c_str()))
   {
    // Confirm the file operation to the SafeCloud server
    sendCliSessSignalMsg(CONFIRM);

    // Return that the file operation should continue
    return true;
   }

  // If otherwise the file operation should be cancelled
  else
   {
    // Notify the file cancellation operation to the SafeCloud server
    sendCliSessSignalMsg(CANCEL);

    // Return that the file operation should NOT continue
    return false;
   }
 }


/* ------------------------------ 'UPLOAD' Operation Methods ------------------------------ */

/**
 * @brief  Loads and sanitizes the information of the file to\n
 *         be uploaded to the SafeCloud storage pool by:\n
 *           1) Writing its canonicalized path into the '_mainFileAbsPath' attribute\n
 *           2) Opening its '_mainFileDscr' file descriptor in read-byte mode\n
 *           3) Loading the file name and metadata into the '_mainFileInfo' attribute\n
 * @param  filePath The relative or absolute path of the file to be uploaded
 * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
 * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
 * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
 * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
 */
void CliSessMgr::checkLoadUploadFile(std::string& filePath)
 {
  // Determine the canonicalized path of the file to be uploaded as a C string
  char* _targFileAbsPathC = realpath(filePath.c_str(),NULL);
  if(!_targFileAbsPathC)
   THROW_SESS_EXCP(ERR_SESS_FILE_NOT_FOUND);

  try
   {
    // Write the canonicalized file path of the file to
    // be uploaded into the '_mainFileAbsPath' attribute
    _mainFileAbsPath = new std::string(_targFileAbsPathC);

    // Attempt to open the file to be uploaded in read-byte mode
    _mainFileDscr = fopen(_targFileAbsPathC, "rb");
    if(!_mainFileDscr)
     THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED, filePath, ERRNO_DESC);

    // Attempt to load the name and metadata of the file to be uploaded
    _mainFileInfo = new FileInfo(*_mainFileAbsPath);

    // Assert the size of the file to be uploaded to be less or
    // equal than the allowed maximum upload file size (4GB - 1B)
    if(_mainFileInfo->meta->fileSizeRaw > FILE_UPLOAD_MAX_SIZE)
     THROW_SESS_EXCP(ERR_SESS_FILE_TOO_BIG, "it is " + std::string(_mainFileInfo->meta->fileSizeStr) + " >= 4GB");

    // Free the canonicalized path as a C string of the file to be uploaded
    free(_targFileAbsPathC);
   }
  catch(sessErrExcp& fileExcp)
   {
    // Free the canonicalized path as a C string of the file to be uploaded
    free(_targFileAbsPathC);

    // Change a ERR_SESS_FILE_IS_DIR or a ERR_SESS_FILE_TOO_BIG error in the more
    // specific ERR_SESS_UPLOAD_DIR and ERR_SESS_UPLOAD_TOO_BIG session error codes
    if(fileExcp.sesErrCode == ERR_SESS_FILE_IS_DIR)
     fileExcp.sesErrCode = ERR_SESS_UPLOAD_DIR;
    else
     if(fileExcp.sesErrCode == ERR_SESS_FILE_TOO_BIG)
      fileExcp.sesErrCode = ERR_SESS_UPLOAD_TOO_BIG;

    // Rethrow the exception
    throw;
   }
 }


/**
 * @brief  Parses the 'FILE_UPLOAD_REQ' session response message returned by the SafeCloud server, where:\n
 *            1) If the SafeCloud server has reported to have successfully uploaded
 *               the empty file, inform the user of the success of the operation.\n
 *            2) If the SafeCloud server has reported that a file with the same name of the one to be
 *               uploaded does not exist in the user's storage pool, the file upload operation should continue\n
 *            3) If the SafeCloud server has reported that a file with the same name of the one to be uploaded
 *               already exists in the user's storage pool:\n
 *                  3.1) If the file to be uploaded is empty and, at this point, the file with the
 *                       same name in the SafeCloud storage pool is not, inform the user and ask
 *                       for their confirmation on whether the upload operation should continue\n
 *                  3.2) If the file to be uploaded was more recently modified than the
 *                       one in the storage pool the file upload operation should continue\n
 *                  3.3) If the file to be uploaded has the same size and last modified time of
 *                       the one in the storage pool, or the latter was more recently modified,
 *                       ask for user confirmation on whether the upload operation should continue\n
 * @return A boolean indicating whether the upload operation should continue
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE  The server reported to have completed uploading a non-empty file or an
 *                                      invalid 'FILE_UPLOAD_REQ' session message response type was received
 */
bool CliSessMgr::parseUploadResponse()
 {
  // Depending on the 'FILE_UPLOAD_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that the empty file has been uploaded successfully
    case COMPLETED:

     // Ensure the file that was uploaded to be in fact empty, where, since
     // after sending a 'COMPLETED' message the server has supposedly reset
     // its session state, in case such a file is in fact NOT empty just throw
     // the associated exception without notifying the server of the error
     if(_mainFileInfo->meta->fileSizeRaw != 0)
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedOpToStr(),
                      "The server reported to have completed an upload operation of a non-empty file without actually receiving"
                      "its data (file: \"" + _mainFileInfo->fileName + "\", size: " + _mainFileInfo->meta->fileSizeStr + ")");

     // Inform the user that the empty file has been successfully uploaded to their storage pool
     std::cout << "\nEmpty file \"" + _mainFileInfo->fileName + "\" successfully uploaded to the SafeCloud storage pool\n" << std::endl;

     // As it has just completed, return that the upload operation should not proceed
     return false;

    // If the SafeCloud server has reported that a file with the same name of the one to be uploaded
    // does not exist in the user's storage pool, return that the file raw contents should be uploaded
    case FILE_NOT_EXISTS:
     return true;

    // If the SafeCloud server has reported that a file with the same name
    // of the one to be uploaded already exists in the user's storage pool
    case FILE_EXISTS:

     // Load into the '_remFileInfo' attribute the name and metadata of the file
     // in the user's storage pool with the same name of the one to be uploaded
     loadRemSessMsgFileInfo();

     // If the file to be uploaded is empty and, at this point, the
     // file with the same name in the SafeCloud storage pool is not
     if(_mainFileInfo->meta->fileSizeRaw == 0)
      {
       // Inform the user that the upload would result in overwriting
       // a non-empty with an empty file in their storage pool
       std::cout << "\nThe empty file to be uploaded would overwrite a non-empty file in your storage pool" << std::endl;

       // Ask for user confirmation on whether to continue the file upload, also sending
       // the operation confirmation or cancellation notification to the SafeCloud server
       return askFileOpConf();
      }

     // If the file to be uploaded was more recently modified than the one in
     // the storage pool, return that the file raw contents should be uploaded
     if(_mainFileInfo->meta->lastModTimeRaw > _remFileInfo->meta->lastModTimeRaw)
      {
       // Confirm the upload operation to the SafeCloud server
       sendCliSessSignalMsg(CONFIRM);

       // Return that the upload operation should continue
       return true;
      }

     // Otherwise, if the file to be uploaded and the one on the
     // storage pool have the same size and last modified time
     if(_mainFileInfo->meta->lastModTimeRaw == _remFileInfo->meta->lastModTimeRaw
        && _mainFileInfo->meta->fileSizeRaw == _remFileInfo->meta->fileSizeRaw)
      {
       // Inform the user that the file they want to upload probably already exists in their storage pool
       std::cout << "\nYour storage pool already contains a \"" + _mainFileInfo->fileName
                    + "\" file of the same size and last modified time of the one to be uploaded" << std::endl;

       // Ask for user confirmation on whether to continue the file upload, also sending
       // the operation confirmation or cancellation notification to the SafeCloud server
       return askFileOpConf();
      }

     // Otherwise, if the file in the storage pool was more
     // recently modified than the one to be uploaded
     if(_mainFileInfo->meta->lastModTimeRaw < _remFileInfo->meta->lastModTimeRaw)
      {
       // Inform the user that the file on the storage pool is more recent than the one they want to upload
       std::cout << "Your storage pool contains a more recent version of the \"" + _mainFileInfo->fileName + "\" file" << std::endl;

       // Ask for user confirmation on whether to continue the file upload, also sending
       // the operation confirmation or cancellation notification to the SafeCloud server
       return askFileOpConf();
      }

    // All other session message types do not represent valid
    // responses to a 'FILE_UPLOAD_REQ' session message
    default:
     sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type " +
                          std::to_string(_recvSessMsgType) + "as a 'FILE_UPLOAD_REQ' response");
     // [Unnecessary, just silences a warning]
     return false;
   }
 }


/**
 * @brief  Uploads the main file's raw contents and sends the
 *         resulting integrity tag to the SafeCloud server
 * @throws ERR_FILE_WRITE_FAILED              Error in reading from the main file
 * @throws ERR_SESSABORT_UNEXPECTED_FILE_SIZE The main file raw contents that were read differ from its size
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
void CliSessMgr::uploadFileData()
 {
  // fread() return, representing the number of bytes read
  // from main file into the secondary connection buffer
  size_t freadRet;

  // The total number of file bytes sent to the SafeCloud server
  size_t totBytesSent = 0;

  // A progress bar possibly used for displaying the
  // file's upload progress discretized between 0-100%
  ProgressBar uploadProgBar(100);

  // The previous and current upload progress discretized between 0-100%
  unsigned char prevUploadProg = 0;
  unsigned char currUploadProg;

  // If the file to be uploaded is large enough, display
  // the upload progress to the user via a progress bar
  bool showProgBar = _mainFileInfo->meta->fileSizeRaw > (_connMgr._priBufSize * 5);

  // Initialize the file encryption operation
  _aesGCMMgr.encryptInit();

  // If the upload progress bar should be displayed
  if(showProgBar)
   {
    // Print an introductory uploaded message
    std::cout << "\nUploading file \"" + _mainFileInfo->fileName + "\" ("
                 + _mainFileInfo->meta->fileSizeStr + ") to the storage pool:\n" << std::endl;

    // Display the progress bar with 0% completion
    uploadProgBar.update();
   }

  // -------------------------------- File Upload Loop -------------------------------- //

  do
   {
    // Read the file raw contents into the secondary buffer size (possibly filling it)
    freadRet = fread(_connMgr._secBuf, sizeof(char), _connMgr._secBufSize, _mainFileDscr);

    // An error occurred in reading the file raw contents is a critical error that in the current
    // session state cannot be notified to the server and so require the connection to be dropped
    if(ferror(_mainFileDscr))
     THROW_EXEC_EXCP(ERR_FILE_READ_FAILED, _mainFileInfo->fileName + ", upload operation aborted", ERRNO_DESC);

    // If bytes were read from the file into the secondary connection buffer
    if(freadRet > 0)
     {
      // Encrypt the file raw contents from the secondary into the primary connection buffer
      _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0], (int)freadRet, &_connMgr._priBuf[0]);

      // Send the encrypted file contents to the SafeCloud server
      _connMgr.sendRaw(freadRet);

      // Update the total number of bytes sent to the SafeCloud server
      totBytesSent += freadRet;

      // If the upload progress bar should be displayed
      if(showProgBar)
       {
        // Compute the current upload progress discretized between 0-100%
        currUploadProg = (unsigned char)((float)totBytesSent / (float)_mainFileInfo->meta->fileSizeRaw * 100);

        // Update the progress bar to the current upload progress
        for(unsigned char i = prevUploadProg; i < currUploadProg; i++)
         uploadProgBar.update();

        // Update the previous upload progress
        prevUploadProg = currUploadProg;
       }
     }
   } while(!feof(_mainFileDscr)); // While the main file has not been completely read

  // Indentation
  if(showProgBar)
   printf("\n");

  // ------------------------------ End File Upload Loop ------------------------------ //

  // Having sent to the SafeCloud server a number of bytes different from the
  // file size is a critical error that in the current session state cannot
  // be notified to the server and so require the connection to be dropped
  if(totBytesSent != _mainFileInfo->meta->fileSizeRaw)
   THROW_EXEC_EXCP(ERR_SESSABORT_UNEXPECTED_FILE_SIZE, "file: \"" + _mainFileInfo->fileName + "\", upload "
                                                       "operation aborted", std::to_string(totBytesSent) + " != "
                                                       + std::to_string(_mainFileInfo->meta->fileSizeRaw));

  // Finalize the file upload operation by sending
  // the resulting integrity tag to the server
  sendRawTag();
 }


/* ----------------------------- 'DOWNLOAD' Operation Methods ----------------------------- */

/**
 * @brief  Parses the 'FILE_DOWNLOAD_REQ' session response message returned by the SafeCloud server, where:\n
 *            1) If the SafeCloud server has reported that the file to be downloaded does not exist in
 *               the user's storage pool, inform the client that the download operation cannot proceed.\n
 *            2) If the SafeCloud server has returned the information on the existing file to be downloaded:\n
 *                  2.1) If the file to be downloaded is empty and a file with the same name in the user's
 *                       download directory does not exist or is empty the download operation should proceed\n
 *                  2.2) [PATCH] If the file to be downloaded is empty and a non-empty file with
 *                       the same name does exist in the user's download directory, ask for
 *                       their confirmation on whether the download operation should proceed\n
 *                  2.3) If the file to be downloaded is NOT empty and a file with such name does not exist
 *                       in the user's download directory, confirm the download operation to the server\n
 *                  2.4) If the file to be downloaded is NOT empty and a file with such name does exist in
 *                       the user's download directory, if the file in the storage pool:\n
 *                                    2.4.1) Was more recently modified than the one in the download
 *                                           directory, confirm the upload operation to the SafeCloud server\n
 *                                    2.4.2) Has the same size and last modified time of the one
 *                                           in the download directory, ask for user confirmation
 *                                           on whether the upload operation should continue\n
 *                                    2.4.3) Has a last modified time older than the one in the
 *                                           download directory, ask for user confirmation on
 *                                           whether the upload operation should continue
 * @return A boolean indicating whether the downloaded operation should continue
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_MAIN_FILE_IS_DIR    The main file was found to be a directory (!)
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_DOWNLOAD_REQ' session
 *                                      message response type was received
 */
bool CliSessMgr::parseDownloadResponse(std::string& fileName)
 {
  // Depending on the 'FILE_DOWNLOAD_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that the file to
    // be downloaded does not exist in the user's storage pool
    case FILE_NOT_EXISTS:

     // Inform the user that such a file does not exist in their storage pool,
     // and that they can retrieve its contents via the 'LIST remote' command
     std::cout << "File \"" + fileName + "\" was not found in your storage pool" << std::endl;
     std::cout << "Enter \"LIST remote\" to display the list of files in your storage pool" << std::endl;

     // Return that the download operation should not proceed
     return false;

    // Otherwise, if the SafeCloud server has returned the information on the file to be downloaded
    case FILE_EXISTS:

     // Load into the '_remFileInfo' attribute the name and
     // metadata of the file the client is requesting to download
     loadRemSessMsgFileInfo();

     // Ensure that the file information received from the server
     // refer to a file with the same name of the one to be downloaded
     if(_remFileInfo->fileName != fileName)
      sendCliSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received as a FILE_DOWNLOAD_REQ response information on a "
                                                      "file (\"" + _remFileInfo->fileName + "\") different from the "
                                                      "one the client wants to download (\"" + fileName + "\")");

     // Check whether a file with the same name of the one to be downloaded already exists in the client's
     // download directory by attempting to load its information into the '_mainFileInfo' attribute
     checkLoadMainFileInfo();

     // If the file to be downloaded is empty and the file in the user's download
     // directory does not exist or is empty, the download operation should proceed
     if(_remFileInfo->meta->fileSizeRaw == 0 &&
        (_mainFileInfo == nullptr || _mainFileInfo->meta->fileSizeRaw == 0))
      return true;

     // If a file with the same name of the one to be downloaded
     // was not found in the client's download directory
     if(_mainFileInfo == nullptr)
      {
       // Confirm the download operation on the SafeCloud server
       sendCliSessSignalMsg(CONFIRM);

       // Return that the download operation should proceed
       return true;
      }

     // Otherwise, if a file with the same name of the one to be
     // downloaded was found in the client's download directory
     else
      {

       /* [PATCH] */
       // If the file to be downloaded is empty and, at this point, the
       // file with the same name in the user's download directory is not
       if(_remFileInfo->meta->fileSizeRaw == 0)
        {
         // Inform the user that the download would result in overwriting
         // a non-empty with an empty file in their download directory
         std::cout << "\nThe empty file to be downloaded would overwrite a non-empty "
                      "file in your download directory" << std::endl;

         // Print a table comparing the metadata of the main and remote file
         _mainFileInfo->compareMetadata(_remFileInfo);

         // Ask the user whether the download operation should proceed
         if(Client::askUser("Do you want to continue downloading the file?"))
          return true;

          // Otherwise, if the download operation should not proceed
         else
          {
           // Inform the server that the download operation has completed
           sendCliSessSignalMsg(COMPLETED);

           // Return that the download operation should NOT continue
           return false;
          }
        }

       // If the file on the storage pool was more recently
       // modified than the one in the client's download directory
       if(_remFileInfo->meta->lastModTimeRaw > _mainFileInfo->meta->lastModTimeRaw)
        {
         // Confirm the download operation on the SafeCloud server
         sendCliSessSignalMsg(CONFIRM);

         // Return that the download operation should proceed
         return true;
        }

       // Otherwise, if the file on the storage pool and the one in the
       // download directory have the same size and last modified time
       if(_mainFileInfo->meta->lastModTimeRaw == _remFileInfo->meta->lastModTimeRaw
          && _mainFileInfo->meta->fileSizeRaw == _remFileInfo->meta->fileSizeRaw)
        {
         // Inform the user that the most recent version of the file they
         // want to download probably is already in their download directory
         std::cout << "\nYour download directory already contains a \"" + _mainFileInfo->fileName
                      + "\" file of the same size and last modified time of the one in your storage pool" << std::endl;

         // Ask for user confirmation on whether to continue the file download, also sending
         // the operation confirmation or cancellation notification to the SafeCloud server
         return askFileOpConf();
        }

       // Otherwise, if the file in the download directory was more
       // recently modified than the one in the client's storage pool
       if(_mainFileInfo->meta->lastModTimeRaw > _remFileInfo->meta->lastModTimeRaw)
        {
         // Inform the user that the file in their download directory is more recent than the one to be downloaded
         std::cout << "Your download directory contains a more recent version of the \"" + _mainFileInfo->fileName + "\" file" << std::endl;

         // Ask for user confirmation on whether to continue the file download, also sending
         // the operation confirmation or cancellation notification to the SafeCloud server
         return askFileOpConf();
        }
      }

    // All other session message types do not represent valid
    // responses to a 'FILE_DOWNLOAD_REQ' session message
    default:
     sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                          std::to_string(_recvSessMsgType) + "as a 'FILE_DOWNLOAD_REQ' response");
    // [Unnecessary, just silences a warning]
    return false;
   }
 }


/**
 * @brief Downloads a file's raw contents from the user's SafeCloud storage pool by:
 *            1) Preparing the client session manager to receive the file's raw contents..\n
 *            2) Receiving and decrypting the file's raw contents.\n
 *            3) Verifying the file trailing integrity tag.\n
 *            4) Moving the resulting temporary file into the associated
 *               associated main file in the user's download directory.\n
 *            5) Setting the main file last modified time to
 *               the one specified in the '_remFileInfo' object.\n
 *            6) Notifying the success of the download operation to the SafeCloud server.
 * @param  fileName The name of the file to be downloaded from the SafeCloud storage pool
 * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid session manager operation or step
 *                                        for receiving a file's raw contents
 * @throws ERR_SESS_FILE_OPEN_FAILED      Failed to open the temporary file
 *                                        descriptor in write-byte mode
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
 * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the downloaded temporary
 *                                        file or NULL session attributes
 */
void CliSessMgr::downloadFileData()
 {
  // Prepare the client session manager to receive
  // the raw contents of the file to be downloaded
  prepRecvFileRaw();

  // The number of raw file bytes read from the
  // connection socket into the primary connection buffer
  size_t recvBytes;

  // fwrite() return, representing the number of bytes written
  // from the secondary connection buffer into the temporary file
  size_t fwriteRet;

  // A progress bar possibly used for displaying the
  // file's download progress discretized between 0-100%
  ProgressBar downloadProgBar(100);

  // The previous and current download progress discretized between 0-100%
  unsigned char prevDownloadProg = 0;
  unsigned char currDownloadProg;

  // If the file to be downloaded is large enough, display
  // the download progress to the user via a progress bar
  bool showProgBar = _remFileInfo->meta->fileSizeRaw > (_connMgr._priBufSize * 5);

  // If the download progress bar should be displayed
  if(showProgBar)
   {
    // Print an introductory downloaded message
    std::cout << "\nDownloading file \"" + _remFileInfo->fileName + "\" ("
                 + _remFileInfo->meta->fileSizeStr + ") from the storage pool:\n" << std::endl;

    // Display the progress bar with 0% completion
    downloadProgBar.update();
   }

  // ------------------------------- File Download Loop ------------------------------- //

  do
   {
    // Receive any number of raw file bytes
    recvBytes = _connMgr.recvRaw();

    // Decrypted the received file raw bytes from the primary into the secondary connection buffer
    _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[0], (int)recvBytes, &_connMgr._secBuf[0]);

    // Write the decrypted file bytes from the secondary buffer into the temporary file
    fwriteRet = fwrite(_connMgr._secBuf, sizeof(char), recvBytes, _tmpFileDscr);

    // Writing into the temporary file less bytes than the ones received into the
    // primary connection buffer is a critical error that in the current session state
    // cannot be notified to the server and so require the connection to be dropped
    if(fwriteRet < recvBytes)
     THROW_EXEC_EXCP(ERR_FILE_WRITE_FAILED,"file: " + *_tmpFileAbsPath + ", download operation aborted","written " +
                     std::to_string(fwriteRet) + " < recvBytes = " + std::to_string(recvBytes) + " bytes");

    // Update the number of remaining bytes of the file being uploaded
    _rawBytesRem -= recvBytes;

    // If the download progress bar should be displayed
    if(showProgBar)
     {
      // Compute the current download progress discretized between 0-100%
      currDownloadProg = (unsigned char)((float)(_remFileInfo->meta->fileSizeRaw - _rawBytesRem) /
                                         (float)_remFileInfo->meta->fileSizeRaw * 100);

      // Update the progress bar to the current download progress
      for(unsigned char i = prevDownloadProg; i < currDownloadProg; i++)
       downloadProgBar.update();

      // Update the previous download progress
      prevDownloadProg = currDownloadProg;
     }

    // Update the associated connection manager's expected data block
    // size to the number of remaining file bytes to be received
    _connMgr._recvBlockSize = _rawBytesRem;

    // Reset the index of the most significant byte in the primary connection buffer
    _connMgr._priBufInd = 0;

   } while(_rawBytesRem != 0);

  // ------------------------ File Integrity Tag Verification ------------------------ //

  // Indentation
  if(showProgBar)
   printf("\n");

  // Reset the index of the most significant byte in the primary connection buffer
  _connMgr._priBufInd = 0;

  // Set the associated connection manager primary buffer to
  // receive bytes up to the size of an AES_128_GCM integrity tag
  _connMgr._recvBlockSize = AES_128_GCM_TAG_SIZE;

  // Block until the complete file integrity tag has been received
  while(_connMgr._priBufInd != AES_128_GCM_TAG_SIZE)
   _connMgr.recvRaw();

  /*
   * Finalize the downloaded file by:
   *    1) Verifying its integrity tag
   *    2) Moving it from the temporary into the download directory
   *    3) Setting its last modified time to the one
   *       specified in the '_remFileInfo' object
   */
  finalizeRecvFileRaw();
 }


/* ------------------------------ 'DELETE' Operation Methods ------------------------------ */

/**
 * @brief  Parses the 'FILE_DELETE_REQ' session response message returned by the SafeCloud server, where:\n
 *            1) If the SafeCloud server has reported that the file to be deleted does not exist in
 *               the user's storage pool, inform the client that the deletion operation cannot proceed.\n
 *            2) If the SafeCloud server has returned the information on the existing file
 *               to be deleted, print it on stdout and ask for user confirmation on whether
 *               proceeding deleting the file, sending the appropriate deletion operation
 *               confirmation or cancellation notification to the SafeCloud server.
 * @param  fileName The name of the file to be downloaded from the SafeCloud storage pool
 * @return A boolean indicating whether to expect the deletion completion notification from the SafeCloud server
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_DELETE_REQ' session message response type was received
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
bool CliSessMgr::parseDeleteResponse(std::string& fileName)
 {
  // Depending on the 'FILE_DELETE_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that the file to
    // be deleted does not exist in the user's storage pool
    case FILE_NOT_EXISTS:

     // Inform the user that such a file does not exist in their storage pool,
     // and that they can retrieve its contents via the 'LIST remote' command
     std::cout << "File \"" + fileName + "\" was not found in your storage pool" << std::endl;
     std::cout << "Enter \"LIST remote\" to display the list of files in your storage pool" << std::endl;

     // Return that the server completion notification is NOT expected
     return false;

    // Otherwise, if the SafeCloud server has returned
    // the information on the file to be deleted
    case FILE_EXISTS:

     // Load into the '_remFileInfo' attribute the name and
     // metadata of the file the client is requesting to delete
     loadRemSessMsgFileInfo();

     // Ensure that the file information received from the server
     // refer to a file with the same name of the one to be deleted
     if(_remFileInfo->fileName != fileName)
      sendCliSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE, "Received as a FILE_DELETE_REQ response information on a "
                                                       "file (\"" + _remFileInfo->fileName + "\") different from "
                                                       "the one the client wants to delete (\"" + fileName + "\")");

     // Print the information on the file to be deleted
     _remFileInfo->printFileInfo();

     // Ask for user confirmation on whether proceeding deleting the file
     if(Client::askUser("Are you sure to delete this file from your storage pool?"))
      {
       // Confirm the delete operation to the SafeCloud server
       sendCliSessSignalMsg(CONFIRM);

       // Return that the server completion notification is expected
       return true;
      }

     // Otherwise, if the file should not be deleted
     else
      {
       // Cancel the delete operation on the SafeCloud server
       sendCliSessSignalMsg(CANCEL);

       // Return that the server completion notification is NOT expected
       return false;
      }

    // All other session message types do not represent valid
    // responses to a 'FILE_DELETE_REQ' session message
    default:
     sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                          std::to_string(_recvSessMsgType) + "as a 'FILE_DELETE_REQ' response");
    // [Unnecessary, just silences a warning]
    return false;
   }
 }

/* ------------------------------ 'RENAME' Operation Methods ------------------------------ */

/**
 * @brief  Parses the 'FILE_RENAME_REQ' session response message returned by the SafeCloud server, where:\n
 *            1) If the SafeCloud server has reported that the file to be renamed does not exist in
 *               the user's storage pool, inform the client that the renaming operation cannot proceed.\n
 *            2) If the SafeCloud server has returned the information on a file with the same name of the
 *               one the user wants to rename the file to, prints them on stdout and inform the client that
 *               such a file should be renamed or deleted before attempting to rename the original file.\n
 *            3) If the SafeCloud server has reported that the file was renamed successfully, inform the
 *               client of the success of operation.
 * @param  oldFilename The name of the file to be renamed
 * @param  newFilename The name the file should be renamed to
 * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_RENAME_REQ' session message response type was received
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void CliSessMgr::parseRenameResponse(std::string& oldFileName, std::string& newFileName)
 {
  // Depending on the 'FILE_RENAME_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that the file to
    // be renamed does not exist in the user's storage pool
    case FILE_NOT_EXISTS:

     // Inform the user that such a file does not exist in their storage pool,
     // and that they can retrieve its contents via the 'LIST remote' command
     std::cout << "File \"" + oldFileName + "\" was not found in your storage pool" << std::endl;
     std::cout << "Enter \"LIST remote\" to display the list of files in your storage pool" << std::endl;
     break;

    // Otherwise, if the SafeCloud server has returned the information on a
    // file with the same name of the one the user wants to rename the file to
    case FILE_EXISTS:

     // Load into the '_remFileInfo' attribute the name and metadata of the
     // file with the same name of the one the user wants to rename the file to
     loadRemSessMsgFileInfo();

     // Ensure that the file information received from the server refer to a file with the same
     // name of the one the user wants to rename the file to, an error that should be thrown
     // directly without notifying the server as it has supposedly reset its session state
     if(_remFileInfo->fileName != newFileName)
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, "Received as a FILE_RESPONSE_REQ response information on a file"
                                                  " (\"" + _remFileInfo->fileName + "\") different from the one "
                                                  "the user wants to rename the file to (\"" + newFileName + "\")");

     // Inform the user that a file with the same name of the one they
     // want to rename the file to was found in their storage pool
     std::cout << "A file with the same name of the one the file should be renamed to is present in your storage pool " << std::endl;

     // Print the information on the file with the same name
     // of the use the user wants to rename the file to
     // Print the information on the file to be deleted
     _remFileInfo->printFileInfo();

     // Inform the user that such a file should be in turn
     // renamed or deleted before renaming the original file
     std::cout << "Please rename or delete such file before renaming the original file" << std::endl;
     break;

    // Otherwise, if the SafeCloud server has reported
    // that the file was renamed successfully
    case COMPLETED:

     // Inform the user of the success of the rename operation
     std::cout << "\nFile \"" + oldFileName + "\" successfully renamed to \""
     + newFileName + "\" in the storage pool\n" << std::endl;
     break;

    // All other session message types do not represent valid
    // responses to a 'FILE_RENAME_REQ' session message
    default:
     sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                          std::to_string(_recvSessMsgType) + "as a 'FILE_RENAME_REQ' response");
   }
 }


/* ------------------------------- 'LIST' Operation Methods ------------------------------- */

/**
 * @brief  Prepares the client session manager to receive the
 *         serialized contents of the user's storage pool
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_DECRYPT_INIT    EVP_CIPHER decrypt initialization failed
 * @throws ERR_SESSABORT_INTERNAL_ERROR Invalid session operation or expected
 *                                      serialized pool contents' size
 */
void CliSessMgr::prepRecvPoolRaw()
 {
  // Assert the client session manager to be in the 'LIST' operation
  if(_sessMgrOp != LIST)
   THROW_EXEC_EXCP(ERR_SESSABORT_INTERNAL_ERROR, "Preparing to receive the serialized user pool contents with the "
                                                 "client session manager in operation \"" + sessMgrOpToStrUpCase() +
                                                 "\", step " + sessMgrOpStepToStrUpCase());

  // Assert the expected serialized pool contents' not to be empty as for the '_rawBytesRem' attribute
  if(_rawBytesRem == 0)
   THROW_EXEC_EXCP(ERR_SESSABORT_INTERNAL_ERROR, "Attempting to receive the empty serialized user pool contents");

  // Update the client session manager step so to expect raw data
  _sessMgrOpStep = WAITING_RAW;

  // Set the reception mode of the associated connection manager to 'RECV_RAW'
  _connMgr._recvMode = ConnMgr::RECV_RAW;

  // Set the associated connection manager's expected block size to the
  // serialized pool contents' size stored in the '_rawBytesRem' attribute
  _connMgr._recvBlockSize = _rawBytesRem;

  // Initialize the 'DirInfo' object used for
  // storing the contents of the user's storage pool
  _mainDirInfo = new DirInfo();

  // Initialize the serialized pool contents' decryption operation
  _aesGCMMgr.decryptInit();
 }


/**
 * @brief  Receives the serialized contents of the user's storage
 *         pool and validates their associated integrity tag
 * @throws ERR_SESS_FILE_INVALID_NAME     Received a file of name
 * @throws ERR_SESS_FILE_META_NEGATIVE    Received a file with negative metadata values
 * @throws ERR_FILE_TOO_LARGE             Received a too large file (> 9999GB)
 * @throws ERR_SESS_DIR_INFO_OVERFLOW     The storage pool information size exceeds 4GB
 * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
 * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
 * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Plaintext integrity verification failed
 * @throws ERR_CSK_RECV_FAILED            Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED          The connection peer has abruptly disconnected
 */
void CliSessMgr::recvPoolRawContents()
 {
  // The number of serialized pool contents' bytes read from
  // the connection socket into the primary connection buffer
  size_t recvBytes;

  // The index of the first available byte in the secondary
  // connection buffer at which reading the serialized pool contents
  unsigned int secBufInd;

  // The maximum secondary connection buffer index at which a
  // complete 'PoolFileInfo' struct MAY be present (secondary
  // connection buffer size - minimum 'PoolFileInfo' struct size)
  unsigned int maxSecBufIndRead = _connMgr._secBufSize - (1 + 3 * sizeof(signed long) + 1);

  // The serialized information size of a file in the user's storage pool
  unsigned short poolFileInfoSize;

  // Name and metadata of a file in the user's storage pool
  FileInfo* fileInfo;

  // The number of bytes of an incomplete 'PoolFileInfo' struct in the
  // secondary connection buffer which have to be moved at its beginning
  // in order to read the complete struct in the next raw reception cycle
  unsigned short carryOverBytes = 0;

  // ----------------- Serialized Pool Contents Reception Cycle ----------------- //

  do
   {
    // Set the index of the first available byte in the primary connection buffer to
    // the number of bytes of the incomplete 'PoolFileInfo' struct that were moved
    // at the beginning of the secondary connection buffer in the previous cycle
    _connMgr._priBufInd = carryOverBytes;

    // Receive any number of serialized raw pool contents bytes
    recvBytes = _connMgr.recvRaw();

    // Decrypted the received serialized pool contents bytes
    // from the primary into the secondary connection buffer
    // after any bytes carried out from the previous cycle
    _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[carryOverBytes], (int)recvBytes,
                            &_connMgr._secBuf[carryOverBytes]);

    // Update the number of serialized pool contents' bytes to be received
    _rawBytesRem -= recvBytes;

    // Update the associated connection manager's expected block size
    // to the number of serialized pool contents' bytes to be received
    _connMgr._recvBlockSize = _rawBytesRem;

    // Reset the index of the first available byte in the secondary connection buffer
    secBufInd = 0;

    // ----------------- Secondary Connection Buffer Scan Cycle ----------------- //

    do
     {
      // If the index of the first available byte in the secondary connection
      // buffer is greater than the maximum index at which a complete
      // 'PoolFileInfo' struct can be read, stop the buffer scan cycle
      if(secBufInd > maxSecBufIndRead)
       break;

      /*
       * Interpret the contents starting at the index of the first available
       * byte in the secondary connection buffer as a 'PoolFileInfo' struct
       *
       * NOTE: This may lead to interpreting as the struct 'filename' attribute bytes that
       *       are either not significant or even overflow beyond the secondary connection
       *       buffer, a condition that are accounted in the following 'if' statement
       */
      PoolFileInfo* poolFileInfo = reinterpret_cast<PoolFileInfo*>(&_connMgr._secBuf[secBufInd]);

      // Compute the 'PoolFileInfo' struct size from its 'filenameLen' member
      poolFileInfoSize = sizeof(unsigned char) + 3 * sizeof(long int) + poolFileInfo->filenameLen;

      // If the 'PoolFileInfo' struct overflows the remaining number of significant
      // bytes in the secondary connection buffer, which is equal to the number of
      // significant bytes in the primary connection buffer, a complete 'PoolFileInfo'
      // struct has not been received yet and so the buffer scan cycle must be stopped
      if(secBufInd + poolFileInfoSize > _connMgr._priBufInd)
       break;

      /*
       * At this point a complete 'PoolFileInfo' struct
       * is available in the secondary connection buffer
       */

      // Read the file name from the 'PoolFileInfo' struct
      std::string fileName(reinterpret_cast<char*>(poolFileInfo->filename), poolFileInfo->filenameLen);

      // Initialize a FileInfo object containing the pool's file information
      fileInfo = new FileInfo(fileName, poolFileInfo->fileSizeRaw, poolFileInfo->lastModTimeRaw, poolFileInfo->creationTimeRaw);

      // Add the FileInfo to the DirInfo object storing the contents of the user's storage pool
      _mainDirInfo->addFileInfo(fileInfo);

      // Increment the index of the first available byte in the secondary connection
      // buffer of the size of the 'PoolFileInfo' struct that has been just read
      secBufInd += poolFileInfoSize;

       // While there are significant bytes in the secondary connection buffer
     } while(secBufInd != _connMgr._priBufInd);

     // --------------- Secondary Connection Buffer Scan Cycle End --------------- //

    /*
     * Determine as the difference between the primary and the secondary connection
     * buffers' first available bytes indexes whether bytes of an incomplete 'PoolFileInfo'
     * struct should be moved at the beginning of the secondary connection buffer
     * in order to be read in the next raw reception cycle (a quantity that will be
     * != 0 if the secondary connection buffer scan cycle exited with a 'break')
     */
    carryOverBytes = _connMgr._priBufInd - secBufInd;

    // If there are significant bytes to be moved at
    // the beginning of the secondary connection buffer
    if(carryOverBytes > 0)
     {
      // Move the significant bytes that were not processed in the
      // secondary connection buffer scan cycle at its beginning
      memcpy(&_connMgr._secBuf[0], &_connMgr._secBuf[secBufInd], carryOverBytes);

      /* [PATCH] */
      // Increment the associated connection manager's expected
      // block size of the number of significant bytes that were
      // moved at the beginning of the secondary connection buffer
      _connMgr._recvBlockSize += carryOverBytes;
     }

     // While the user's serialized pool contents have not been completely received
   } while(_rawBytesRem > 0);

  // --------------- End Serialized Pool Contents Reception Cycle --------------- //

  /*
  // LOG: User's storage pool contents
  _mainDirInfo->printDirContents();
  std::cout << "N° files = " << _mainDirInfo->numFiles << std::endl;
  std::cout << "Pool contents' raw size = " << _mainDirInfo->dirRawSize << std::endl;
  std::cout << "_connMgr._recvBlockSize = " << _connMgr._recvBlockSize << std::endl;
  */

  // ------------------- Pool Contents Integrity Tag Verification ------------------- //

  // Reset the index of the most significant byte in the primary connection buffer
  _connMgr._priBufInd = 0;

  // Set the associated connection manager primary buffer to
  // receive bytes up to the size of an AES_128_GCM integrity tag
  _connMgr._recvBlockSize = AES_128_GCM_TAG_SIZE;

  // Block until the complete pool contents' integrity tag has been received
  while(_connMgr._priBufInd != AES_128_GCM_TAG_SIZE)
   _connMgr.recvRaw();

  // Finalize the pool contents' decryption by verifying their integrity tag
  _aesGCMMgr.decryptFinal(&_connMgr._priBuf[0]);
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Client session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the cliConnMgr parent object
 * @param cliConnMgr A reference to the client connection manager parent object
 */
CliSessMgr::CliSessMgr(CliConnMgr& cliConnMgr)
 : SessMgr(reinterpret_cast<ConnMgr&>(cliConnMgr),cliConnMgr._downDir)
 {}

/* Same destructor of the 'SessMgr' base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/* ---------------------------- Session Operations API ---------------------------- */

/**
 * @brief  Uploads a file to the user's SafeCloud storage pool
 * @param  filePath The relative or absolute path of the file to be uploaded
 * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
 * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
 * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
 * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::uploadFile(std::string& filePath)
 {
  // Initialize the client session manager operation
  _sessMgrOp = UPLOAD;

  // Load and sanitize the information of the file to be uploaded to the SafeCloud storage pool
  checkLoadUploadFile(filePath);

  /*
  // LOG: Upload file info
  _mainFileInfo->printFileInfo();
  */

  // Prepare a 'SessMsgFileInfo' session message of type 'FILE_UPLOAD_REQ' containing the
  // name and metadata of the file to be uploaded and send it to the SafeCloud server
  sendSessMsgFileInfo(FILE_UPLOAD_REQ);

  LOG_DEBUG("Sent 'FILE_UPLOAD_REQ' message to the server (file = \""
            + *_mainFileAbsPath + "\", size = " + _mainFileInfo->meta->fileSizeStr + ")")

  // Update the operation step so to expect a 'FILE_UPLOAD_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_UPLOAD_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_UPLOAD_REQ' response, obtaining an indication on whether
  // the file raw contents should be uploaded to the SafeCloud server
  if(!parseUploadResponse())
   return;

  // If uploading a non-empty file, send its raw contents
  if(_mainFileInfo->meta->fileSizeRaw != 0)
   uploadFileData();

  // Update the operation step so to expect the server completion notification
  _sessMgrOpStep = WAITING_COMPL;

  // Block until the supposed server completion notification has been received
  recvCheckCliSessMsg();

  // Ensure that the server completion notification was received
  if(_recvSessMsgType != COMPLETED)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                                                    std::to_string(_recvSessMsgType) +
                                                    " while awaiting for the server's 'UPLOAD' completion");

  // Inform the user that the file has been successfully uploaded to
  // their storage pool depending on whether it is empty or not
  if(_mainFileInfo->meta->fileSizeRaw == 0)
   std::cout << "\nEmpty file \"" + _mainFileInfo->fileName + "\" successfully"
                " uploaded to the SafeCloud storage pool\n" << std::endl;
  else
   std::cout << "\nFile \"" + _mainFileInfo->fileName + "\" (" + _mainFileInfo->meta->fileSizeStr +
               ") successfully uploaded to the SafeCloud storage pool\n" << std::endl;
 }


/**
 * @brief  Downloads a file from the user's SafeCloud storage pool into their download directory
 * @param  fileName The name of the file to be downloaded from the user's SafeCloud storage pool
 * @throws ERR_SESS_FILE_INVALID_NAME The provided file name is not a valid Linux file name
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::downloadFile(std::string& fileName)
 {
  // Initialize the client session manager operation
  _sessMgrOp = DOWNLOAD;

  // Assert the file name string to consist of a valid Linux file name
  validateFileName(fileName);

  // Initialize the main and temporary absolute paths of the file to be downloaded
  _mainFileAbsPath = new std::string(*_mainDirAbsPath + "/" + fileName);
  _tmpFileAbsPath  = new std::string(*_tmpDirAbsPath + "/" + fileName + "_PART");

  /*
  // LOG: Main and temporary files absolute paths
  std::cout << "_mainFileAbsPath = " << *_mainFileAbsPath << std::endl;
  std::cout << "_tmpFileAbsPath = " << *_tmpFileAbsPath << std::endl;
  */

  // Prepare a 'SessMsgFileName' session message of type 'FILE_DOWNLOAD_REQ' containing
  // the name of the file to be uploaded and send it to the SafeCloud server
  sendSessMsgFileName(FILE_DOWNLOAD_REQ,fileName);

  LOG_DEBUG("Sent 'FILE_DOWNLOAD_REQ' message to the server (file = \"" + fileName + "\")")

  // Update the operation step so to expect a 'FILE_DOWNLOAD_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_DOWNLOAD_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_DOWNLOAD_REQ' response, obtaining an indication on
  // whether to proceed downloading the file from the SafeCloud server
  if(!parseDownloadResponse(fileName))
   return;

  // If downloading a non-empty file
  if(_remFileInfo->meta->fileSizeRaw != 0)
   {
    // Receive the file's raw contents
    downloadFileData();

    // Notify the server that the file download has been completed successfully
    sendSessSignalMsg(COMPLETED);

    // Inform the user that the file has been successfully downloaded to their download directory
    std::cout << "\nFile \"" + _remFileInfo->fileName + "\" (" + _remFileInfo->meta->fileSizeStr +
                 ") successfully downloaded into the download directory\n" << std::endl;
   }

  // Otherwise, if downloading an empty file
  else
   {
    // Touch the empty file in the client's download directory
    touchEmptyFile();

    // Notify the server that the empty file has been successfully downloaded
    sendCliSessSignalMsg(COMPLETED);

    // Inform the user that the empty file has been successfully downloaded
    std::cout << "\nEmpty file \"" + _remFileInfo->fileName + "\" successfully "
                 "downloaded from the SafeCloud storage pool\n" << std::endl;
   }
 }


/**
 * @brief  Deletes a file from the user's SafeCloud storage pool
 * @param  fileName The name of the file to be deleted from the user's SafeCloud storage pool
 * @throws ERR_SESS_FILE_INVALID_NAME The provided file name is not a valid Linux file name
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::deleteFile(std::string& fileName)
 {
  // Initialize the client session manager operation
  _sessMgrOp = DELETE;

  // Assert the file name string to consist of a valid Linux file name
  validateFileName(fileName);

  // Prepare a 'SessMsgFileName' session message of type 'FILE_DELETE_REQ' containing
  // the name of the file to be deleted and send it to the SafeCloud server
  sendSessMsgFileName(FILE_DELETE_REQ,fileName);

  LOG_DEBUG("Sent 'FILE_DELETE_REQ' message to the server (file = \"" + fileName + "\")")

  // Update the operation step so to expect a 'FILE_DOWNLOAD_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_DELETE_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_DELETE_REQ' response, obtaining an indication on whether
  // to expect the deletion completion notification from the SafeCloud server
  if(!parseDeleteResponse(fileName))
   return;

  // Update the operation step so to expect the server completion notification
  _sessMgrOpStep = WAITING_COMPL;

  // Block until the supposed server completion notification has been received
  recvCheckCliSessMsg();

  // Ensure that the server completion notification was received
  if(_recvSessMsgType != COMPLETED)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                                                    std::to_string(_recvSessMsgType) +
                                                    " while awaiting for the server's 'DELETE' completion");

  // Inform the user that the file on their storage pool has been deleted successfully
  std::cout << "\nFile \"" + _remFileInfo->fileName + "\" (" + _remFileInfo->meta->fileSizeStr +
               ") successfully deleted from the SafeCloud storage pool\n" << std::endl;
 }


/**
 * @brief  Renames a file in the user's SafeCloud storage pool
 * @param  oldFilename The name of the file to be renamed
 * @param  newFilename The name the file should be renamed to
 * @throws ERR_SESS_FILE_INVALID_NAME The old or new file name is not a valid Linux file name
 * @throws ERR_SESS_RENAME_SAME_NAME  The old and new file names coincide
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::renameFile(std::string& oldFilename, std::string& newFilename)
 {
  // Initialize the client session manager operation
  _sessMgrOp = RENAME;

  // Assert both file names to represent valid Linux file names
  validateFileName(oldFilename);
  validateFileName(newFilename);

  // Assert the old and new file names to be different
  if(oldFilename == newFilename)
   THROW_SESS_EXCP(ERR_SESS_RENAME_SAME_NAME);

  // Prepare a 'SessMsgFileRename' session message of implicit type 'FILE_RENAME_REQ'
  // the old and new file names and send it to the SafeCloud server
  sendSessMsgFileRename(oldFilename, newFilename);

  LOG_DEBUG("Sent 'FILE_RENAME_REQ' message to the server (oldFilename = \""
            + oldFilename + "\", newFilename = \"" + newFilename + "\")")

  // Update the operation step so to expect a 'FILE_RENAME_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_RENAME_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_RENAME_REQ' response, outlining the results of the rename operation
  parseRenameResponse(oldFilename, newFilename);
 }


/**
 * @brief Prints on stdout the list of files in the user's storage pool
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::listPoolFiles()
 {
  // Initialize the client session manager operation
  _sessMgrOp = LIST;

  // Send a 'FILE_LIST_REQ' signaling
  // message to the SafeCloud server
  sendCliSessSignalMsg(FILE_LIST_REQ);

  LOG_DEBUG("Sent 'FILE_LIST_REQ' message to the server")

  // Update the operation step so to expect a 'FILE_LIST_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_LIST_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Ensure that a 'SessMsgPoolSize' session message
  // of implicit 'POOL_SIZE' type was received
  if(_recvSessMsgType != POOL_SIZE)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                                                    std::to_string(_recvSessMsgType) +
                                                    " while awaiting for the server's 'FILE_LIST_REQ' response");

  // Read the serialized size of the user's storage pool from
  // the 'SessMsgPoolSize' into the '_rawBytesRem' attribute
  loadSessMsgPoolSize();

  // If the user's storage pool is empty, inform them and return
  if(_rawBytesRem == 0)
   {
    std::cout << "\nYour storage pool is empty\n" << std::endl;
    return;
   }

  // Otherwise, if the user's storage pool is NOT empty
  else
   {
    // Prepare the client session manager to receive the
    // serialized contents of the user's storage pool
    prepRecvPoolRaw();

    // Receive the serialized contents of the user's storage pool
    recvPoolRawContents();

    // Notify the server that the storage pool's
    // contents were successfully received
    sendSessSignalMsg(COMPLETED);

    // Print the user's storage pool contents on stdout
    _mainDirInfo->printDirContents();
   }
 }