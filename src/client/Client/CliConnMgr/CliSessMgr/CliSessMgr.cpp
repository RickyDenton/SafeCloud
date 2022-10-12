/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "../CliConnMgr.h"

/* =============================== PRIVATE METHODS =============================== */


void CliSessMgr::sendCliSessMsg(SessMsgType sessMsgType)
 {
  switch(sessMsgType)
   {
    case FILE_UPLOAD_REQ:

     // Interpret the contents of the connection manager's secondary buffer as a 'FILE_UPLOAD_REQ' session message
     SessMsgUploadReq* fileUpPayload = reinterpret_cast<SessMsgUploadReq*>(_cliConnMgr._secBuf);

     // Set the payload length (+1 '/0' character, -1 placeholder "filename" attribute in the SessMsgUploadReq struct)
     fileUpPayload->msgLen = sizeof(SessMsgUploadReq) + _targFileInfo->fileName.length();

     // Set the session message type
     fileUpPayload->msgType = FILE_UPLOAD_REQ;

     // Set the file's size
     fileUpPayload->fileSize = _targFileInfo->fileMeta.fileSize;

     // Set the file's name, including the '/0' terminating character
     memcpy(reinterpret_cast<char*>(&fileUpPayload->fileName),_targFileInfo->fileName.c_str(),_targFileInfo->fileName.length()+1);

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
    _targFileAbsPath = new std::string(_targFileAbsPathC);

    // Attempt to open the file
    _targFileDscr = fopen(_targFileAbsPathC, "rb");
    if(!_targFileDscr)
     THROW_SESS_EXCP(ERR_SESS_FILE_OPEN_FAILED, filePath, ERRNO_DESC);

    // Attempt to retrieve the file's metadata
    _targFileInfo = new FileInfo(*_targFileAbsPath);

    // Ensure the file size to be less or equal than the maximum upload file size
    if(_targFileInfo->fileMeta.fileSize > FILE_UPLOAD_MAX_SIZE)
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
  : SessMgr(reinterpret_cast<ConnMgr&>(cliConnMgr)), _cliSessCmdState(CLI_IDLE),
    _cliConnMgr(cliConnMgr), _progBar(100), _tProgUnit(0), _tProgTemp(0)
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
  _tProgUnit = 0;
  _tProgTemp = 0;
 }


 //TODO
void CliSessMgr::uploadFile(std::string& filePath)
 {
  // Determine and initialize the canonicalized path, the descriptor,
  // the name and metadata of the target file to be uploaded
   parseUploadFile(filePath);

  // LOG: Target file absolute path, descriptor and info
  std::cout << "_targFileAbsPath = " << *_targFileAbsPath << std::endl;
  std::cout << "_targFileDscr = " << _targFileDscr << std::endl;
  _targFileInfo->printInfo();

  // Prepare and send the 'FILE_UPLOAD_REQ' message
  sendCliSessMsg(FILE_UPLOAD_REQ);
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