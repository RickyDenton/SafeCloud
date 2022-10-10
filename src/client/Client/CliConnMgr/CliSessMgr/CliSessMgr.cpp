/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"
#include "errCodes/errCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"



void CliSessMgr::parseOpenFile(std::string& filePath)
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
   }
  catch(sessErrExcp& fileExcp)
   {
    free(_targFileAbsPathC);
    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

CliSessMgr::CliSessMgr(CliConnMgr& cliConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(cliConnMgr)), _cliSessCmdState(CLI_IDLE),
    _cliConnMgr(cliConnMgr), _progBar(100), _tProgUnit(0), _tProgTemp(0)
 {}

// Same destructor of the SessMgr base class

/* ============================= OTHER PUBLIC METHODS ============================= */

// TODO
void CliSessMgr::resetCliSessState()
 {
  resetSessState();
  _progBar.reset();

  _tProgUnit = 0;
  _tProgTemp = 0;
 }

// TODO: STUB
void CliSessMgr::uploadFile(std::string& filePath)
 {
  parseOpenFile(filePath);

  std::cout << "_targFileAbsPath = " << _targFileAbsPath << std::endl;
  std::cout << "_targFileDscr = " << _targFileDscr << std::endl;

  _targFileInfo->printInfo();
  resetCliSessState();
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