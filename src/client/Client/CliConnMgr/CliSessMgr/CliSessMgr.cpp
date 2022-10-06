/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSessMgr.h"

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

// TODO: Check arguments' value and throw an exception if wrong?
/**
 * @brief         SessMgr object constructor
 * @param csk     The session's connection socket
 * @param tmpDir  The session's temporary directory
 * @param buf     Session Buffer
 * @param bufSize Session Buffer size
 * @param iv      The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
 * @param skey    The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)
 * @param downDir The client's download directory
 */
CliSessMgr::CliSessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey, char* downDir)
                       : SessMgr(csk,tmpDir,buf,bufSize,iv,skey), _downDir(downDir)
 {}



// TODO: STUB
void CliSessMgr::uploadFile(std::string& filePath)
 {
  std::cout << "In uploadFile() (filePath = " << filePath << ")" << std::endl;
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