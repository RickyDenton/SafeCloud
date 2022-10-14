/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "../CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"

/* =============================== PRIVATE METHODS =============================== */

// TODO
void CliSessMgr::sendCliSessSignalMsg(SessMsgType sessMsgType)
 {
  // Send the session signaling message
  sendSessSignalMsg(sessMsgType);

  // In case of session state resetting, terminating or errors,
  // perform the appropriate actions or raise the appropriate exception
  switch(sessMsgType)
   {
    /* -------------- Error Signaling Messages -------------- */
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR, abortedCmdToStr());

    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,abortedCmdToStr());

    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,abortedCmdToStr());

    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,abortedCmdToStr());

    // No action
    default:
     break;
   }
 }


// TODO
void CliSessMgr::recvCheckCliSessMsg()
 {
  // TODO: Remove
  std::cout << "in recvCheckCliSessMsg()" << std::endl;

  // unwrap the received session message into the
  // associated connection manager's secondary buffer
  unwrapSessMsg();

  // Interpret the contents of the associated connection
  // manager's secondary buffer as a session message
  SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_cliConnMgr._secBuf);

  // The client session manager shouldn't receive messages in the 'IDLE' status
  if(_sessMgrState == IDLE)
   sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

  /*
   * Check whether the received session message type:
   *   1) Is session-resetting or terminating
   *   2) Is allowed in the client session manager state
   */
  switch(sessMsg->msgType)
   {
    // File existence notification, which can be received in the
    // 'UPLOAD', 'DOWNLOAD' and 'DELETE'  client session manager states
    case FILE_EXISTS:
     if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
          && _cliSessMgrSubstate == WAITING_FILE_STATUS))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

    // File non-existence notification, which can be received in all but the 'LIST'
    // client session manager state (and 'IDLE' that was previously accounted for)
    case FILE_NOT_EXISTS:
     if(!(_sessMgrState != LIST && _cliSessMgrSubstate == WAITING_FILE_STATUS))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

    // Notification that a file with the specified target name already exists on the
    // server, which can be received only in the 'RENAME' client session manager state
    case NEW_FILENAME_EXISTS:
     if(!(_sessMgrState == RENAME && _cliSessMgrSubstate == WAITING_SRV_CONF))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

    // Client storage pool information, which can be received
    // only in the 'LIST' client session manager state
    case POOL_INFO:
     if(!(_sessMgrState == LIST && _cliSessMgrSubstate == WAITING_POOL_INFO))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

    // The server informs that it has successfully completed
    // the current upload, delete or rename operation
    case COMPLETED:
     if(!((_sessMgrState == UPLOAD || _sessMgrState == DELETE || _sessMgrState == RENAME)
          && _cliSessMgrSubstate == WAITING_SRV_COMPL))
      sendCliSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

    // The server is gracefully disconnecting
    case BYE:
     THROW_EXEC_EXCP(ERR_SESS_SRV_GRACEFUL_DISCONNECT,abortedCmdToStr());

    /* ---------------- Recoverable Errors ---------------- */

    // The server has experienced a recoverable internal error
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_INTERNAL_ERROR,abortedCmdToStr());

    // The server has received an unexpected session message
    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE,abortedCmdToStr());

    // The server has received a malformed session message
    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_CLI_SRV_MALFORMED_MESSAGE,abortedCmdToStr());

    /* ---------------- Unrecoverable Errors ---------------- */

    // The server has received a session message of unknown type, with
    // its cause associated to a desynchronization between the server
    // and client IV, from which the connection must be aborted
    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESS_CLI_SRV_UNKNOWN_SESSMSG_TYPE,abortedCmdToStr());

    // Unknown Message type
    default:
     sendCliSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE);
   }

  // At this point the received session message is
  // valid for the current client session manager state

  // LOG: Session message length and msgType
  std::cout << "sessMsg->wrapLen" << sessMsg->msgLen << std::endl;
  std::cout << "sessMsg->msgType" << sessMsg->msgType << std::endl;
 }



void CliSessMgr::sendCliSessPayloadMsg(SessMsgType sessMsgType)
 {
  switch(sessMsgType)
   {
    case FILE_UPLOAD_REQ:

     // Interpret the contents of the connection manager's secondary buffer as a 'FILE_UPLOAD_REQ' session message
     SessMsgUploadReq* fileUpPayload = reinterpret_cast<SessMsgUploadReq*>(_cliConnMgr._secBuf);

     // Set the session message length (+1 '/0' character, -1 placeholder "filename" attribute in the SessMsgUploadReq struct)
     fileUpPayload->msgLen = sizeof(SessMsgUploadReq) + _locFileInfo->fileName.length();

     // Set the session message type
     fileUpPayload->msgType = FILE_UPLOAD_REQ;

     // Set the file's size
     fileUpPayload->fileSize = _locFileInfo->fileMeta.fileSize;

     // Set the file's name, including the '/0' terminating character
     memcpy(reinterpret_cast<char*>(&fileUpPayload->fileName), _locFileInfo->fileName.c_str(), _locFileInfo->fileName.length() + 1);

     // Wrap the session message and send it to the SafeCloud server
     wrapSendSessMsg();
   }
 }





/**
 * @brief  Parses a target file to be uploaded by:\n
 *           1) Initializing its canonicalized path\n
 *           2) Opening its file descriptor in read-byte mode\n
 *           3) Determining its file name and metadata\n
 * @param  filePath The relative or absolute path of the target file to be uploaded
 * @throws ERR_SESS_FILE_NOT_FOUND   The target file was not found
 * @throws ERR_SESS_FILE_OPEN_FAILED The target file could not be opened in read mode
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading the target file's metadata
 * @throws ERR_SESS_UPLOAD_DIR       The target file is a directory
 * @throws ERR_SESS_UPLOAD_TOO_BIG   The target file is too large (> 4GB)
 */
void CliSessMgr::parseUploadFile(std::string& filePath)
 {
  // Derive the expected absolute, or canonicalized, file path as a C string
  char* _targFileAbsPathC = realpath(filePath.c_str(),NULL);
  if(!_targFileAbsPathC)
   THROW_SESS_EXCP(ERR_SESS_FILE_NOT_FOUND);

  try
   {
    // Initialize the absolute, or canonicalized, file path
    _mainFileAbsPath = new std::string(_targFileAbsPathC);

    // Attempt to open the file
    _mainFileDscr = fopen(_targFileAbsPathC, "rb");
    if(!_mainFileDscr)
     THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED, filePath, ERRNO_DESC);

    // Attempt to retrieve the file's metadata
    _locFileInfo = new FileInfo(*_mainFileAbsPath);

    // Ensure the file size to be less or equal than the maximum upload file size
    if(_locFileInfo->fileMeta.fileSize > FILE_UPLOAD_MAX_SIZE)
     THROW_SESS_EXCP(ERR_SESS_FILE_TOO_BIG);

    // Free the target absolute file path in C
    free(_targFileAbsPathC);
   }
  catch(sessErrExcp& fileExcp)
   {
    free(_targFileAbsPathC);

    // more specific
    if(fileExcp.sesErrCode == ERR_SESS_FILE_IS_DIR)
     fileExcp.sesErrCode = ERR_SESS_UPLOAD_DIR;
    else
     if(fileExcp.sesErrCode == ERR_SESS_FILE_TOO_BIG)
      fileExcp.sesErrCode = ERR_SESS_UPLOAD_TOO_BIG;

    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

// TODO
CliSessMgr::CliSessMgr(CliConnMgr& cliConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(cliConnMgr)), _cliSessMgrSubstate(CLI_IDLE),
    _cliConnMgr(cliConnMgr), _progBar(100), _progBarUnitSize(0), _progBarLeftovers(0)
 {}

// Same destructor of the SessMgr base class

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets the client session manager state
 *        to be ready for the next session command
 */
void CliSessMgr::resetCliSessState()
 {
  // Reset the base class state
  resetSessState();

  // Reset the manager's progress bar
  _progBar.reset();
  _progBarUnitSize = 0;
  _progBarLeftovers = 0;
 }


// TODO
void CliSessMgr::sendByeMsg()
 { sendSessSignalMsg(BYE); }



void sendFileUploadReq()
 {

  SessMsgFileInfo

 }



 //TODO
void CliSessMgr::uploadFile(std::string& filePath)
 {
  // Determine and initialize the canonicalized path, the descriptor,
  // the name and metadata of the target file to be uploaded
   parseUploadFile(filePath);

  // LOG: Target file absolute path, descriptor and info
  std::cout << "_mainFileAbsPath = " << *_mainFileAbsPath << std::endl;
  std::cout << "_mainFileDscr = " << _mainFileDscr << std::endl;
  _locFileInfo->printInfo();

  // Prepare and send the file upload request message
  sendFileUploadReq();

  // Prepare and send the 'FILE_UPLOAD_REQ' message
   sendCliSessPayloadMsg(FILE_UPLOAD_REQ);
 }



// TODO: STUB
void CliSessMgr::downloadFile(std::string& fileName)
 {
  std::cout << "In downloadFile() (fileName = " << fileName << ")" << std::endl;
 }

// TODO: STUB
void CliSessMgr::listRemoteFiles()
 {
  std::cout << "In listRemoteFiles()" << std::endl;
 }

// TODO: STUB
void CliSessMgr::renameRemFile(std::string& oldFileName,std::string& newFileName)
 {
  std::cout << "In renameRemFile() (oldFileName = " << oldFileName << ", newFileName = " << newFileName << ")" << std::endl;
 }