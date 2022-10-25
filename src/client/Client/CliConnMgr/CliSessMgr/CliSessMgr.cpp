/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "../CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "../../../client_utils.h"
#include "utils.h"

/* =============================== PRIVATE METHODS =============================== */

/**
 * @brief Sends a session message signaling type to the server and performs the actions
 *        appropriate to session signaling types resetting or terminating the session
 * @param sessMsgSignalingType The session message signaling type to be sent to the server
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
 * @throws ERR_CLI_DISCONNECTED          The server disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void CliSessMgr::sendCliSessSignalMsg(SessMsgType sessMsgSignalingType)
 { sendCliSessSignalMsg(sessMsgSignalingType,""); }

void CliSessMgr::sendCliSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason)
 {
  // Attempt to send the signaling session message
  sendSessSignalMsg(sessMsgSignalingType);

  // In case of signaling messages resetting or terminating the session,
  // perform their associated actions or raise their associated exceptions
  switch(sessMsgSignalingType)
   {
    // The client session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedOpToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedOpToStr());

    // A session message invalid for the current client session manager state was received
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

    // The other signaling message types require no further action
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
   *      directly performing the appropriate actions
   *   2) Is valid in the current client session manager
   *      state, signaling the error to the server and
   *      throwing the associated exception otherwise
   */
  switch(_recvSessMsgType)
   {
    /* ---------------------------- 'FILE_EXISTS' Payload Message Type ---------------------------- */

    // A 'FILE_EXISTS' payload message type is allowed only with the client session
    // manager in the 'UPLOAD', 'DOWNLOAD' and 'DELETE' commands with step 'WAITING_RESP'
    case FILE_EXISTS:
     if(!((_sessMgrOp == UPLOAD || _sessMgrOp == DOWNLOAD || _sessMgrOp == DELETE)
          && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_EXISTS' session message received in"
                                                       " session state \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
      break;

    /* ----------------------------- 'POOL_SIZE' Payload Message Type ----------------------------- */

    // A 'POOL_SIZE' payload message type is allowed in the 'LIST' operation with step 'WAITING_RESP'
    case POOL_SIZE:
     if(!(_sessMgrOp == LIST && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'POOL_SIZE' session message received in"
                                                       " session state \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
     break;

    /* -------------------------- 'FILE_NOT_EXISTS' Payload Message Type -------------------------- */

    // A 'FILE_NOT_EXISTS' payload message type is allowed
    // in all operations but 'LIST' with step 'WAITING_RESP'
    case FILE_NOT_EXISTS:
     if(!(_sessMgrOp != LIST && _sessMgrOpStep == WAITING_RESP))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_NOT_EXISTS' session message received in"
                                                       " session state \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
     break;

    /* ------------------------ 'NEW_FILENAME_EXISTS' Payload Message Type ------------------------ */

    // A 'NEW_FILENAME_EXISTS' payload message type is allowed
    // only in the 'RENAME' operation with step 'WAITING_CONF'
    case NEW_FILENAME_EXISTS:
     if(!(_sessMgrOp == RENAME && _sessMgrOpStep == WAITING_CONF))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'NEW_FILENAME_EXISTS' session message received in"
                                                       " session state \"" + sessMgrOpToStrUpCase() +
                                                       "\", step " + sessMgrOpStepToStrUpCase());
     break;

    /* ---------------------------- 'COMPLETED' Signaling Message Type ---------------------------- */

    /*
     * A 'COMPLETED' signaling message type is allowed only in:
     *   1) The 'UPLOAD' operation of any step
     *   2) The 'DELETE' and 'RENAME' operations with step 'WAITING_COMPL'
     */
    case COMPLETED:

     // Since after sending a 'COMPLETED' message the SafeCloud server has supposedly
     // reset its session state, if such a message type is received in an invalid
     // state just throw the associated exception without notifying the server
     if(!((_sessMgrOp == UPLOAD) || ((_sessMgrOp == DELETE || _sessMgrOp == RENAME) &&
                                     _sessMgrOpStep == WAITING_COMPL)))
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedOpToStr(), "'COMPLETED' session message received in"
                                                                     " session state \"" + sessMgrOpToStrUpCase() +
                                                                     "\", step " + sessMgrOpStepToStrUpCase());
      break;

    /* ------------------------------- 'BYE' Signaling Message Type ------------------------------- */

    // A 'BYE' signaling message type is allowed in the 'IDLE' operation only
    case BYE:

     // Since after sending a 'BYE' message the SafeCloud server is supposedly
     // shutting down the connection, if such a message type is received in an invalid
     // state just throw the associated exception without notifying the server
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
 * @throws ERR_SESS_INTERNAL_ERROR      Invalid session state or uninitialized
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
  // Assert the client session manager command and step to be valid to ask for a user's file operation confirmation
  if(!((_sessMgrOp == UPLOAD || _sessMgrOp == DOWNLOAD) && _sessMgrOpStep == WAITING_RESP))
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Attempting to ask for a user file " + sessMgrOpToStrLowCase() + " confirmation in "
                                           "command \"" + sessMgrOpToStrUpCase() + "\", sub-state " + sessMgrOpStepToStrUpCase());

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
  if(askUser(fileOpContinueQuestion.c_str()))
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
 *                  3.1) If the file to be uploaded was more recently modified than the
 *                       one in the storage pool the file upload operation should continue\n
 *                  3.2) If the file to be uploaded has the same size and last modified time of
 *                       the one in the storage pool, or the latter was more recently modified,
 *                       ask for user confirmation on whether the upload operation should continue\n
 * @return A boolean indicating whether the upload operation should continue
 * @throws ERR_SESS_MALFORMED_MESSAGE  Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_UNEXPECTED_MESSAGE The server reported to have completed uploading a non-empty file or an
 *                                     invalid 'FILE_UPLOAD_REQ' session message response type was received
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

     // If the file to be uploaded was more recently modified than the one in
     // the storage pool, return that the file raw contents should be uploaded
     if(_mainFileInfo->meta->lastModTimeRaw > _remFileInfo->meta->lastModTimeRaw)
      return true;

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
 * @brief  Uploads the main file's raw contents and the
 *         resulting integrity tag to the SafeCloud server
 * @throws ERR_FILE_WRITE_FAILED         Error in reading from the main file
 * @throws ERR_FILE_READ_UNEXPECTED_SIZE The main file raw contents that were read differ from its size
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The plaintext block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_SEND_OVERFLOW             Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
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

  /* -------------------------------- File Upload Loop -------------------------------- */
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

  // Having sent to the SafeCloud server a number of bytes different from the
  // file size is a critical error that in the current session state cannot
  // be notified to the server and so require the connection to be dropped
  if(totBytesSent != _mainFileInfo->meta->fileSizeRaw)
   THROW_EXEC_EXCP(ERR_FILE_READ_UNEXPECTED_SIZE, _mainFileInfo->fileName + ", upload operation aborted",
                   std::to_string(totBytesSent) + " != " + std::to_string(_mainFileInfo->meta->fileSizeRaw));

  // Finalize the file encryption operation by writing the resulting
  // integrity tag at the start of the primary connection buffer
  _aesGCMMgr.encryptFinal(&_connMgr._priBuf[0]);

  // Send the file integrity tag to the SafeCloud server
  _connMgr.sendRaw(AES_128_GCM_TAG_SIZE);

  // Indentation
  if(showProgBar)
   printf("\n");
 }


/* ----------------------------- 'DOWNLOAD' Operation Methods ----------------------------- */


// TODO
bool CliSessMgr::parseDownloadResponse(std::string& fileName)
 {
  // Depending on the 'FILE_DOWNLOAD_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that the file to be downloaded does not exist in the user's storage pool
    case FILE_NOT_EXISTS:

     // Inform the client that such a file does not exist in their storage pool,
     // and that they can retrieve its list of files via the 'LIST remote' command
     // TODO: LOG Yellow?
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

     // If the file to be downloaded is empty
     if(_remFileInfo->meta->fileSizeRaw == 0)
      {
       // Touch the empty file in the client's download directory
       touchEmptyFile();

       // Inform the server that the empty file has been successfully downloaded
       sendCliSessSignalMsg(COMPLETED);

       // Inform the user that the empty file has been successfully downloaded
       std::cout << "\nEmpty file \"" + _remFileInfo->fileName + "\" successfully "
                    "downloaded from the SafeCloud storage pool\n" << std::endl;

       // Return that the download operation should not proceed
       return false;
      }

     // If the non-empty file to be downloaded was
     // not found in the client's download directory
     if(_mainFileInfo == nullptr)
      {
       // Confirm the download operation on the SafeCloud server
       sendCliSessSignalMsg(CONFIRM);

       // Return that the download operation should proceed
       return true;
      }

     // Otherwise, if the non-empty file to be downloaded
     // was found in the client's download directory
     else
      {
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


// TODO
void CliSessMgr::downloadFileData()
 {
  // TODO: Move in a "SessMgr::setRecvRaw() method after moving the sub-state into the 'SessMgr' class -----

  // Update the session manager operation step so to expect raw data
  _sessMgrOpStep = WAITING_RAW;

  // Set the reception mode of the associated connection manager to 'RECV_RAW'
  _connMgr._recvMode = ConnMgr::RECV_RAW;

  // Set the expected data block size in the associated
  // connection manager to the size of the file to be received
  _connMgr._recvBlockSize = _remFileInfo->meta->fileSizeRaw;

  // Initialize the number of raw bytes to be received to the file size
  _rawBytesRem = _remFileInfo->meta->fileSizeRaw;

  // Open the temporary file descriptor in write-byte mode
  _tmpFileDscr = fopen(_tmpFileAbsPath->c_str(), "wb");
  if(!_tmpFileDscr)
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Error in opening the uploaded temporary file \""
                                           + *_tmpFileAbsPath + " \" (" + ERRNO_DESC + ")");

  // Initialize an AES_128_GCM decryption operation
  _aesGCMMgr.decryptInit();

  // TODO: -------------------------------------------------------------------------------------------------

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

  /* ------------------------------- File Download Loop ------------------------------- */
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

    // Update the number of remaining file of the file being uploaded
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

    // If the file being downloaded has not been completely received yet, update the associated
    // connection manager's expected data block size to its number of remaining bytes
    if(_rawBytesRem > 0)
     _connMgr._recvBlockSize = _rawBytesRem;

     // Otherwise, if the file has been completely received, set the associated connection
     // manager's expected data block size to the size of an AES_128_GCM integrity tag
    else
     _connMgr._recvBlockSize = AES_128_GCM_TAG_SIZE;

    // Reset the index of the most significant byte in the primary connection buffer
    _connMgr._priBufInd = 0;
   } while(_rawBytesRem != 0);

  // Indentation
  if(showProgBar)
   printf("\n");

  /* ------------------------ File Integrity Tag Verification ------------------------ */

  // Block until the complete file integrity TAG has been received
  while(_connMgr._priBufInd != AES_128_GCM_TAG_SIZE)
   _connMgr.recvRaw();

  // Finalize the upload decryption by verifying the file's integrity tag
  _aesGCMMgr.decryptFinal(&_connMgr._priBuf[0]);

  // Close and reset the temporary file descriptor
  if(fclose(_tmpFileDscr) != 0)
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Failed to close the downloaded temporary file "
                                           "(" + *_tmpFileAbsPath + ") (reason = " + ERRNO_DESC + ")");
  _tmpFileDscr = nullptr;

  // Move the temporary file from the user's temporary directory
  // into the associated main file in their download directory
  if(rename(_tmpFileAbsPath->c_str(),_mainFileAbsPath->c_str()))
   sendCliSessSignalMsg(ERR_INTERNAL_ERROR,"Failed to move the downloaded temporary file from the client's temporary"
                                           " directory to their download directory (" + *_tmpFileAbsPath + ")");

  // Set the download file last modified time to the one specified in the '_remFileInfo' object
  mainToRemLastModTime();

  // Notify the server that the file download has been completed successfully
  sendSessSignalMsg(COMPLETED);
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

/* ---------------------------- Session Commands API ---------------------------- */

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

  // Update the command step so to expect a 'FILE_UPLOAD_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_UPLOAD_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_UPLOAD_REQ' response, obtaining an indication on whether
  // the file raw contents should be uploaded to the SafeCloud server
  if(!parseUploadResponse())
   return;

  // Send the file raw contents to the SafeCloud server
  uploadFileData();

  // Update the command step so to expect the server completion notification
  _sessMgrOpStep = WAITING_COMPL;

  // Block until the supposed server completion notification has been received
  recvCheckCliSessMsg();

  // Ensure that the server completion notification was received
  if(_recvSessMsgType != COMPLETED)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                                                    std::to_string(_recvSessMsgType) +
                                                    " while awaiting for the server's 'UPLOAD' completion");

  // Inform the user that the file has been successfully uploaded to their storage pool
  std::cout << "\nFile \"" + _mainFileInfo->fileName + "\" (" + _mainFileInfo->meta->fileSizeStr +
               ") successfully uploaded to the SafeCloud storage pool\n" << std::endl;
 }


// TODO
void CliSessMgr::downloadFile(std::string& fileName)
 {
  // Initialize the client session manager operation
  _sessMgrOp       = DOWNLOAD;

  // Assert the file name string to consist of a valid Linux file name
  validateFileName(fileName);

  // Initialize the main and temporary absolute paths of the file to be downloaded
  _mainFileAbsPath = new std::string(*_mainDirAbsPath + "/" + fileName);
  _tmpFileAbsPath  = new std::string(*_tmpDirAbsPath + "/" + fileName + "_PART");

  // TODO: Comment
  // LOG: Main and temporary files absolute paths
  std::cout << "_mainFileAbsPath = " << *_mainFileAbsPath << std::endl;
  std::cout << "_tmpFileAbsPath = " << *_tmpFileAbsPath << std::endl;

  // Prepare a 'SessMsgFileName' session message of type 'FILE_DOWNLOAD_REQ' containing
  // the name of the file to be uploaded and send it to the SafeCloud server
  sendSessMsgFileName(FILE_DOWNLOAD_REQ,fileName);

  LOG_DEBUG("Sent 'FILE_DOWNLOAD_REQ' message to the server (file = \"" + fileName + "\")")

  // Update the command step so to expect a 'FILE_DOWNLOAD_REQ' response
  _sessMgrOpStep = WAITING_RESP;

  // Block until the 'FILE_DOWNLOAD_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_DOWNLOAD_REQ' response, obtaining an indication on
  // whether to proceed downloading the file from the SafeCloud server
  if(!parseDownloadResponse(fileName))
   return;

  // Proceed downloading the file's raw contents
  downloadFileData();

  // Inform the user that the file has been successfully downloaded to their download directory
  std::cout << "\nFile \"" + _remFileInfo->fileName + "\" (" + _remFileInfo->meta->fileSizeStr +
               ") successfully downloaded into the download directory\n" << std::endl;
 }


// TODO: Placeholder implementation
void CliSessMgr::listRemoteFiles()
 {
  std::cout << "In listRemoteFiles()" << std::endl;
 }


// TODO: Placeholder implementation
void CliSessMgr::renameRemFile(std::string& oldFileName,std::string& newFileName)
 {
  std::cout << "In renameRemFile() (oldFileName = " << oldFileName << ", newFileName = " << newFileName << ")" << std::endl;
 }


/**
 * @brief  Sends the 'BYE session signaling message to the
 *         SafeCloud server, gracefully terminating the session
 * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
 * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED              send() fatal error
 */
void CliSessMgr::sendByeMsg()
 { sendSessSignalMsg(BYE); }

