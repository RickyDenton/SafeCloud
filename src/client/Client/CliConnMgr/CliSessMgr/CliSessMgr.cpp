/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "../CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "../../../client_utils.h"

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
  try
   { sendSessSignalMsg(sessMsgSignalingType); }
  catch(execErrExcp& sendSessSignExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_SRV_DISCONNECTED error code
    if(sendSessSignExcp.exErrcode == ERR_PEER_DISCONNECTED)
     sendSessSignExcp.exErrcode = ERR_SRV_DISCONNECTED;

    // Rethrow the exception
    throw;
   }

  // In case of signaling messages resetting or terminating the session,
  // perform their associated actions or raise their associated exceptions
  switch(sessMsgSignalingType)
   {
    // The client session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedCmdToStr());

    // A session message invalid for the current client session manager was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedCmdToStr());

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     if(!errReason.empty())
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, abortedCmdToStr(), errReason);
     else
      THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE, abortedCmdToStr());

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     if(!errReason.empty())
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, abortedCmdToStr(), errReason);
     else
      THROW_EXEC_EXCP(ERR_SESSABORT_UNKNOWN_SESSMSG_TYPE, abortedCmdToStr());

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
 *               the current client session manager state and substate\n
 *            4) Handles session-resetting or terminating signaling messages\n
 *            5) Handles session error signaling messages\n
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void CliSessMgr::recvCheckCliSessMsg()
 {
  // Block the execution until a complete session message wrapper has
  // been received in the associated connection manager's primary buffer
  _cliConnMgr.cliRecvFullMsg();

  // Unwrap the received session message wrapper stored in the connection's primary
  // buffer into its associated session message in the connection's secondary buffer
  unwrapSessMsg();

  // Interpret the contents of associated connection
  // manager's secondary buffer as a base session message
  SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_cliConnMgr._secBuf);

  // Copy the received session message length
  // and type into their dedicated attributes
  _recvSessMsgLen = sessMsg->msgLen;
  _recvSessMsgType = sessMsg->msgType;

  // If a signaling message type was received, assert the message
  // length to be equal to the size of a base session message
  if(isSessSignalingMsgType(_recvSessMsgType) && _recvSessMsgLen != sizeof(SessMsg))
   sendCliSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received a session signaling message of invalid"
                                                   "length (" + std::to_string(_recvSessMsgLen) + ")");

  // With the client session manager in the 'IDLE' state
  // only session error signaling messages can be received
  if(_sessMgrState == IDLE && !isSessErrSignalingMsgType(_recvSessMsgType))
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type " +
                                                    std::to_string(_recvSessMsgType) + " with"
                                                    "the client session manager in the 'IDLE' state");

  /*
   * Check whether the received session message type:
   *   1) Should trigger a session state reset or termination,
   *      directly performing the appropriate actions
   *   2) Is valid in the current client session manager state
   *      and substate, signaling the error to the server
   *      and throwing the associated exception otherwise
   */
  switch(_recvSessMsgType)
   {
    /* ------------------------------- 'FILE_EXISTS' Payload Message ------------------------------- */

    // A file existence notification is allowed only in the 'UPLOAD',
    // 'DOWNLOAD' and 'DELETE' states with sub-state 'WAITING_FILE_STATUS'
    case FILE_EXISTS:
     if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
          && _cliSessMgrSubstate == WAITING_FILE_STATUS))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_EXISTS' session message received in"
                                                       "session state" "\"" + currSessMgrStateToStr() +
                                                       "\", sub-state " + std::to_string(_cliSessMgrSubstate));
      break;

    /* -------------------------------- 'POOL_INFO' Payload Message -------------------------------- */

    // Client storage pool information is allowed only in
    // the 'LIST' state with sub-state 'WAITING_POOL_INFO'
    case POOL_INFO:
     if(!(_sessMgrState == LIST && _cliSessMgrSubstate == WAITING_POOL_INFO))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'POOL_INFO' session message received in"
                                                       "session state" "\"" + currSessMgrStateToStr() +
                                                       "\", sub-state " + std::to_string(_cliSessMgrSubstate));
     break;

    /* ---------------------------- 'FILE_NOT_EXISTS' Signaling Message ---------------------------- */

    // A file non-existence notification is allowed in ALL but
    // the 'LIST' state with sub-state 'WAITING_FILE_STATUS'
    case FILE_NOT_EXISTS:
     if(!(_sessMgrState != LIST && _cliSessMgrSubstate == WAITING_FILE_STATUS))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'FILE_NOT_EXISTS' session message received in"
                                                       "session state" "\"" + currSessMgrStateToStr() +
                                                       "\", sub-state " + std::to_string(_cliSessMgrSubstate));
     break;

    /* -------------------------- 'NEW_FILENAME_EXISTS' Signaling Message -------------------------- */

    // A notification that a file with the specified new name already exists in the client's
    // storage pool is allowed only in the 'RENAME' state with sub-state 'WAITING_SRV_CONF'
    case NEW_FILENAME_EXISTS:
     if(!(_sessMgrState == RENAME && _cliSessMgrSubstate == WAITING_SRV_CONF))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'NEW_FILENAME_EXISTS' session message received in"
                                                       "session state" "\"" + currSessMgrStateToStr() +
                                                       "\", sub-state " + std::to_string(_cliSessMgrSubstate));
     break;

    /* ------------------------------- 'COMPLETED' Signaling Message ------------------------------- */

    // A server completion notification is allowed only in
    //   1) The 'DOWNLOAD' state of any sub-state
    //   2) The 'DELETE' and 'RENAME' states with sub-state 'WAITING_SRV_COMPL'
    case COMPLETED:

     // Since after sending a 'COMPLETED' message the SafeCloud server has supposedly
     // reset its session state, in case the message is received in an invalid
     // state just throw the associated exception without notifying the server
     if(!((_sessMgrState == UPLOAD) || ((_sessMgrState == DELETE || _sessMgrState == RENAME) &&
                                         _cliSessMgrSubstate == WAITING_SRV_COMPL)))
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedCmdToStr(), "'COMPLETED' session message received in"
                                                                      "session state" "\"" + currSessMgrStateToStr() +
                                                                      "\", sub-state " + std::to_string(_cliSessMgrSubstate));
      break;

    /* ---------------------------------- 'BYE' Signaling Message ---------------------------------- */

    // The server graceful disconnect notification is allowed in the 'IDLE' state only
    case BYE:

     // If such a message is not received in the 'IDLE' state, just throw the associated
     // exception without notifying the server, as it is supposedly disconnecting
     if(_sessMgrState != IDLE)
      THROW_EXEC_EXCP(ERR_SESSABORT_SRV_GRACEFUL_DISCONNECT, abortedCmdToStr());
     else
      THROW_EXEC_EXCP(ERR_SESSABORT_SRV_GRACEFUL_DISCONNECT);

    /* --------------------------------- Error Signaling Messages --------------------------------- */

    // The server reported to have experienced a recoverable internal error
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_INTERNAL_ERROR,abortedCmdToStr());

    // The server reported to have received an unexpected session message
    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE,abortedCmdToStr());

    // The server reported to have received a malformed session message
    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_MALFORMED_MESSAGE,abortedCmdToStr());

    // The server reported to have received a session message of unknown type, an error to be attributed to
    // a desynchronization between the connection peers' IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESSABORT_CLI_SRV_UNKNOWN_SESSMSG_TYPE, abortedCmdToStr());

    /* ----------------------------------- Unknown Message Type ----------------------------------- */

    // A session message of unknown type has been received, an error to be attributed to a
    // desynchronization between the connection peers' IVs and that requires the connection to be reset
    default:
     sendCliSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE,std::to_string(_recvSessMsgType));
   }

  /*
   * At this point the received session message type is valid
   * for the current client session manager state and sub-state
   */

  /*
  // LOG: Received session message length and type
  std::cout << "_recvSessMsgLen = " << _recvSessMsgLen << std::endl;
  std::cout << "_recvSessMsgType = " << _recvSessMsgType << std::endl;
  */
 }


/* -------------------------------- File Upload -------------------------------- */


/**
 * @brief  Parses a file to be uploaded to the SafeCloud storage pool by:\n
 *           1) Writing its canonicalized path into the '_mainFileAbsPath' attribute\n
 *           2) Opening its '_mainFileDscr' file descriptor in read-byte mode\n
 *           3) Loading the file name and metadata into the '_locFileInfo' attribute\n
 * @param  filePath The relative or absolute path of the file to be uploaded
 * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
 * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
 * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
 * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
 */
void CliSessMgr::parseUploadFile(std::string& filePath)
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
    _locFileInfo = new FileInfo(*_mainFileAbsPath);

    // Assert the size of the file to be uploaded to be less or
    // equal than the allowed maximum upload file size (4GB - 1B)
    if(_locFileInfo->meta->fileSizeRaw > FILE_UPLOAD_MAX_SIZE)
     THROW_SESS_EXCP(ERR_SESS_FILE_TOO_BIG,"it is " + std::string(_locFileInfo->meta->fileSizeStr) + " >= 4GB");

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
 * @brief  Parses the 'FILE_UPLOAD_REQ' session response message returned by the SafeCloud server, where:
 *            1) If the SafeCloud server has reported that a file with the same name of the one to be
 *               uploaded does not exist in the user's storage pool, the file upload operation should continue
 *            2) If the SafeCloud server has reported that a file with the same name of the one to be uploaded
 *               already exists in the user's storage pool:
 *                  2.1) If the file to be uploaded was more recently modified than the
 *                       one in the storage pool the file upload operation should continue
 *                  2.2) If the file to be uploaded has the same size and last modified time of
 *                       the one in the storage pool, or the latter was more recently modified,
 *                       ask for user confirmation on whether the upload operation should continue
 *            3) If the SafeCloud server has reported that the empty file has been
 *               uploaded successfully, inform the user of the success of the operation
 * @return A boolean indicating whether the file raw contents should be uploaded to the SafeCloud server
 * @throws ERR_SESS_MALFORMED_MESSAGE  Invalid file values in the 'SessMsgFileInfo' message
 * @throws ERR_SESS_UNEXPECTED_MESSAGE The server reported to have completed uploading a non-empty file or an
 *                                     invalid 'FILE_UPLOAD_REQ' session message response type was received
 */
bool CliSessMgr::parseUploadResponse()
 {
  // Depending on the 'FILE_UPLOAD_REQ' response message type:
  switch(_recvSessMsgType)
   {
    // If the SafeCloud server has reported that a file with the same name of the one to be uploaded
    // does not exist in the user's storage pool, return that the file raw contents should be uploaded
    case FILE_NOT_EXISTS:
     return true;

    // If the SafeCloud server has reported that a file with the same name
    // of the one to be uploaded already exists in the user's storage pool
    case FILE_EXISTS:

     // Load into the 'remFileInfo' attribute the name and metadata of the file
     // in the user's storage pool with the same name of the one to be uploaded
     loadRemFileInfo();

     // If the file to be uploaded was more recently modified than the one in
     // the storage pool, return that the file raw contents should be uploaded
     if(_locFileInfo->meta->lastModTimeRaw > _remFileInfo->meta->lastModTimeRaw)
      return true;

     // Otherwise, if the file to be uploaded and the one on the
     // storage pool have the same size and last modified time
     if(_locFileInfo->meta->lastModTimeRaw == _remFileInfo->meta->lastModTimeRaw
        && _locFileInfo->meta->fileSizeRaw == _remFileInfo->meta->fileSizeRaw)
      {
       // Inform the user that the file they want to upload probably already exists in their storage pool
       std::cout << "\nYour storage pool already contains a \"" + _locFileInfo->fileName
                    + "\" file of the same size and last modified time of the one to be uploaded" << std::endl;

       // Print a table comparing the metadata of the file
       // to be uploaded and the one in the user's storage pool
       _locFileInfo->compareMetadata(_remFileInfo);

       // Ask the user if the upload operation should continue and, if it should
       if(askUser("Do you want to continue uploading the file?"))
        {
         // Confirm the upload operation to the SafeCloud server
         sendCliSessSignalMsg(CONFIRM);

         // Return that the file raw contents should be uploaded
         return true;
        }

       // If otherwise the upload operation should be cancelled
       else
        {
         // Notify the operation cancellation to the server
         sendCliSessSignalMsg(CANCEL);

         // Return the file raw contents should NOT be uploaded
         return false;
        }
      }

     // Otherwise, if the file in the storage pool was more
     // recently modified than the one to be uploaded
     if(_locFileInfo->meta->lastModTimeRaw < _remFileInfo->meta->lastModTimeRaw)
      {
       // Inform the user that the file on the storage pool is more recent than the one they want to upload
       std::cout << "Your storage pool contains a more recent version of the \"" + _locFileInfo->fileName + "\" file" << std::endl;

       // Print a table comparing the metadata of the file
       // to be uploaded and the one in the user's storage pool
       _locFileInfo->compareMetadata(_remFileInfo);

       // Ask the user if the upload operation should continue and, if it should
       if(askUser("Do you want to continue uploading the file?"))
        {
         // Confirm the upload operation to the SafeCloud server
         sendCliSessSignalMsg(CONFIRM);

         // Return that the file raw contents should be uploaded
         return true;
        }

       // If otherwise the upload operation should be cancelled
       else
        {
         // Notify the operation cancellation to the server
         sendCliSessSignalMsg(CANCEL);

         // Return the file raw contents should NOT be uploaded
         return false;
        }
      }

    // If the SafeCloud server has reported that the empty file has been uploaded successfully
    case COMPLETED:

     // Ensure the file that was uploaded to be in fact empty, where, since
     // after sending a 'COMPLETED' message the server has supposedly reset
     // its session state, in case such a file is in fact NOT empty just throw
     // the associated exception without notifying the server of the error
     if(_locFileInfo->meta->fileSizeRaw != 0)
      THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedCmdToStr(),
                      "The server reported to have completed an upload operation of a non-empty file without actually receiving"
                      "its data (file: \"" + _locFileInfo->fileName + "\", size: " + _locFileInfo->meta->fileSizeStr + ")");

     // Inform the user that the file has been successfully uploaded to their storage pool
     std::cout << "\nEmpty file \"" + _locFileInfo->fileName + "\" successfully uploaded to the SafeCloud storage pool\n" << std::endl;

     // As the file was empty, return that its raw contents should NOT be uploaded
     return false;


    // All other session message types do not represent valid
    // responses to a 'FILE_UPLOAD_REQ' session message
    default:
     sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
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
  bool showProgBar = _locFileInfo->meta->fileSizeRaw > (_connMgr._priBufSize * 5);

  // Initialize the file encryption operation
  _aesGCMMgr.encryptInit();

  // If the upload progress bar should be displayed
  if(showProgBar)
   {
    // Print an introductory uploaded message
    std::cout << "\nUploading file \"" + _locFileInfo->fileName + "\" ("
                 + _locFileInfo->meta->fileSizeStr + ") to the storage pool:\n" << std::endl;

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
     THROW_EXEC_EXCP(ERR_FILE_READ_FAILED, _locFileInfo->fileName + ", upload operation aborted", ERRNO_DESC);

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
        currUploadProg = (unsigned char)((float)totBytesSent / (float)_locFileInfo->meta->fileSizeRaw * 100);

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
  if(totBytesSent != _locFileInfo->meta->fileSizeRaw)
   THROW_EXEC_EXCP(ERR_FILE_READ_UNEXPECTED_SIZE, _locFileInfo->fileName + ", upload operation aborted",
                   std::to_string(totBytesSent) + " != " + std::to_string(_locFileInfo->meta->fileSizeRaw));

  // Finalize the file encryption operation by writing the resulting
  // integrity tag at the start of the primary connection buffer
  _aesGCMMgr.encryptFinal(&_connMgr._priBuf[0]);

  // Send the file integrity tag to the SafeCloud server
  _connMgr.sendRaw(AES_128_GCM_TAG_SIZE);

  // Indentation
  if(showProgBar)
   printf("\n");
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Client session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the cliConnMgr parent object
 * @param cliConnMgr A reference to the client connection manager parent object
 */
CliSessMgr::CliSessMgr(CliConnMgr& cliConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(cliConnMgr)), _cliSessMgrSubstate(CLI_IDLE), _cliConnMgr(cliConnMgr)
 {}

/* Same destructor of the SessMgr base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets all session parameters in preparation for the next
 *        session command to be executed by the client session manager
 */
void CliSessMgr::resetCliSessState()
 {
  // Reset the client session manage sub-state
  _cliSessMgrSubstate = CLI_IDLE;

  // Reset the base session parameters
  resetSessState();
 }


/* ---------------------------- Session Commands API ---------------------------- */

/**
 * @brief  Uploads a file to the user's storage pool within the SafeCloud server
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
  // Initialize the client session manager state and substate
  _sessMgrState       = UPLOAD;
  _cliSessMgrSubstate = CMD_START;

  /*
   * Parse the target file to be uploaded by:
   *    1) Writing its canonicalized path into the '_mainFileAbsPath' attribute
   *    2) Opening its '_mainFileDscr' file descriptor in read-byte mode
   *    3) Loading the file name and metadata into the '_locFileInfo' attribute
   */
  parseUploadFile(filePath);

  /*
  // LOG: Upload file info
  _locFileInfo->printFileInfo();
  */

  // Prepare a 'SessMsgFileInfo' session message of type 'FILE_UPLOAD_REQ' containing the
  // name and metadata of the file to be uploaded and send it to the SafeCloud server
  sendLocalFileInfo(FILE_UPLOAD_REQ);

  LOG_DEBUG("Sent 'FILE_UPLOAD_REQ' message to the server (target file = \""
            + *_mainFileAbsPath + "\", size = " + _locFileInfo->meta->fileSizeStr + ")")

  // Update the client session manager sub-state so to expect a 'FILE_UPLOAD_REQ' response
  _cliSessMgrSubstate = WAITING_FILE_STATUS;

  // Block until the 'FILE_UPLOAD_REQ' response is received from the SafeCloud server
  recvCheckCliSessMsg();

  // Parse the 'FILE_UPLOAD_REQ' response, obtaining an indication on whether
  // the file raw contents should be uploaded to the SafeCloud server
  if(!parseUploadResponse())
   return;

  // Send the file raw contents to the SafeCloud server
  uploadFileData();

  // Update the client session manager sub-state so to expect the server completion notification
  _cliSessMgrSubstate = WAITING_SRV_COMPL;

  // Block until the supposed server completion notification has been received
  recvCheckCliSessMsg();

  // Ensure that the server completion notification was received
  if(_recvSessMsgType != COMPLETED)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"Received a session message of type" +
                                                    std::to_string(_recvSessMsgType) +
                                                    " while awaiting for the server's 'UPLOAD' completion");

  // Inform the user that the file has been successfully uploaded to their storage pool
  std::cout << "\nFile \"" + _locFileInfo->fileName + "\" (" + _locFileInfo->meta->fileSizeStr + ") successfully uploaded to the SafeCloud storage pool\n" << std::endl;
 }


// TODO: Placeholder implementation
void CliSessMgr::downloadFile(std::string& fileName)
 {
  std::cout << "In downloadFile() (fileName = " << fileName << ")" << std::endl;
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
 *         SafeCloud server, gracefully terminating the connection
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

