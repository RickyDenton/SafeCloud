/* SafeCloud Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <unistd.h>
#include <string>
#include "ConnMgr.h"
#include "defaults.h"
#include "scode.h"
#include "errlog.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include <dirent.h>
#include <arpa/inet.h>


/* ============================== PROTECTED METHODS ============================== */

/**
 * @brief Deletes the contents of the connection's temporary directory
 */
void ConnMgr::cleanTmpDir()
 {
  DIR*           tmpDir;    // Temporary directory file descriptor
  struct dirent* tmpFile;   // Information on a file in the temporary directory

  // Convert the connection's temporary directory path to a C string
  const char* _tmpDirC = _tmpDir->c_str();

  // Absolute path of a file in the temporary directly, whose maximum length is given by the
  // length of the temporary directory's path plus the maximum file name length (+1 for the '/')
  char tmpFileAbsPath[strlen(_tmpDirC) + NAME_MAX + 1];

  // Open the temporary directory
  tmpDir = opendir(_tmpDirC);
  if(!tmpDir)
   LOG_SCODE(ERR_TMPDIR_OPEN_FAILED,*_tmpDir,ERRNO_DESC);
  else
   {
    // For each file in the temporary folder
    while((tmpFile = readdir(tmpDir)) != NULL)
     {
      // Skip the directory and its parent's pointers
      if(!strcmp(tmpFile->d_name,".") ||!strcmp(tmpFile->d_name,".."))
       continue;

      // Build the file's absolute path
      sprintf(tmpFileAbsPath, "%s/%s",_tmpDirC, tmpFile->d_name);

      // Delete the file
      if(remove(tmpFileAbsPath) == -1)
       LOG_SCODE(ERR_TMPFILE_DELETE_FAILED,std::string(tmpFileAbsPath),ERRNO_DESC);
     }

    // Close the temporary folder
    if(closedir(tmpDir) == -1)
     LOG_SCODE(ERR_FILE_CLOSE_FAILED,*_tmpDir, ERRNO_DESC);
   }
 }


/* ---------------------------------- Data I/O ---------------------------------- */

/**
 * @brief Marks the contents of the primary connection buffer as
 *        consumed, resetting the index of its first significant byte
 *        and the expected size of a data block being received
 */
void ConnMgr::clearPriBuf()
 {
  _priBufInd = 0;
  _recvBlockSize = 0;
 }


/**
 * @brief Marks the contents of the secondary connection buffer as
 *        consumed, resetting the index of its first significant byte
 */
void ConnMgr::clearSecBuf()
 { _secBufInd = 0; }


/**
 * @brief  Reads bytes belonging to a same data block from the connection socket into the primary connection buffer,
 *         updating the number of significant bytes in it and possibly the expected size of the data block to be received
 * @return A boolean indicating whether a full data block is available for consumption in the primary connection buffer
 * @throws ERR_CSK_RECV_FAILED   Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED Abrupt peer disconnection
 */
bool ConnMgr::recvData()
 {
  size_t maxReadBytes;  // Maximum number of bytes that can be read from the connection socket
  ssize_t recvRet;      // Connection socket recv() return

  /* Determine the maximum number of bytes that can be read from connection socket into the primary connection buffer as:
       - If the expected size of the data block to be received is NOT known (_recvBlockSize == 0), as the difference
         between the buffer's size and the index of its first available byte (for preventing buffer overflows)
       - If instead the expected size of the data block to be received IS known (_recvBlockSize > 0), as the minimum
         between the previous difference and the difference between such expected size and the index of the first
         available byte in the buffer (for preventing reading a possible following block in the buffer)               */
  if(_recvBlockSize == 0)
   maxReadBytes = (_bufSize - _priBufInd);
  else
   maxReadBytes = std::min((_bufSize - _priBufInd),(_recvBlockSize - _priBufInd));

  // Attempt to read up to the maximum allowed bytes from the connection socket into the primary connection buffer
  recvRet = recv(_csk, _priBuf, maxReadBytes, 0);

  LOG_DEBUG(*_name + " recv() returned " + std::to_string(recvRet) + " (maxReadBytes = " + std::to_string(recvRet) + ")")

  // Depending on the recv() return
  switch(recvRet)
   {
    // recv() FATAL error
    case -1:
     THROW_SCODE(ERR_CSK_RECV_FAILED,ERRNO_DESC);

    // Abrupt server disconnection
    case 0:
     THROW_SCODE(ERR_PEER_DISCONNECTED,*_name);

    // > 0 => recvRet = number of bytes read from socket (<= maxReadBytes)
    default:

     std::cout << "_recvBlockSize = " << _recvBlockSize << " _priBufInd = " << _priBufInd << std::endl;

    // If the expected size of the data block to be received is NOT known (_recvBlockSize == 0),
    // set it to the first 16 bytes of the received data ("msgSize" field of a sMsgHeader)
    if(_recvBlockSize == 0)
     _recvBlockSize = ((STSMMsg&&)_priBuf).header.len;

    // Update the number of significant bytes in the primary buffer
    _priBufInd += recvRet;

    std::cout << "_recvBlockSize = " << _recvBlockSize << " _priBufInd = " << _priBufInd << std::endl;

    // Return whether a full data block is available for consumption in the primary connection buffer
    if(_recvBlockSize == _priBufInd)
     return true;
    else
     return false;
   }
 }


// TODO: Write better
void ConnMgr::sendMsg()
 {
  // Retrieve the length of the data block to be sent from the first 16 bits in the primary connection buffer
  // uint16_t blockLen = (uint16_t)_priBuf[0];


  size_t blockLen = ((STSMMsg&&)_priBuf).header.len;


  // Inform the user that the login was successful
  send(_csk, (const void*)&_priBuf, blockLen, 0);

  // Reset the index of the most significant byte in the primary connection
  // buffer as well as the expected size of a data block being received
  clearPriBuf();

  LOG_DEBUG("Sent " + std::to_string(blockLen) + " bytes")

  // TODO
  // If the IV has been initialized, increment it, and if it notifies that IV
  // reuse is about to occur, prepare and send a rekeying message (SESSION ONLY)
  if(_iv != nullptr && _iv->incIV())
   {


   }

 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief        ConnMgr object constructor
 * @param csk    The connection socket associated with this manager
 * @param name   The client name associated with this connection
 * @param tmpDir The connection's temporary directory
 */
ConnMgr::ConnMgr(int csk, std::string* name, std::string* tmpDir) : _connState(KEYXCHANGE), _csk(csk), _name(name), _tmpDir(tmpDir), _priBuf(), _priBufInd(0),
                                                                    _secBuf(), _secBufInd(0), _bufSize(CONN_BUF_SIZE), _recvBlockSize(0), _skey(), _iv(nullptr)
 {}


/**
 * @brief Connection Manager object destructor, which:\n
 *          1) Closes its associated connection socket\n
 *          2) Delete the contents of the connection's temporary directory\n
 *          3) Safely deletes all the connection's sensitive information
 */
ConnMgr::~ConnMgr()
 {
  // Delete the connection's symmetric key and IV
  OPENSSL_cleanse(&_skey[0], AES_128_KEY_SIZE);
  delete _iv;

  // Safely delete the connection's buffers
  OPENSSL_cleanse(&_priBuf[0], _bufSize);
  OPENSSL_cleanse(&_secBuf[0], _bufSize);

  // Close the connection socket
  if(close(_csk) != 0)
   LOG_SCODE(ERR_CSK_CLOSE_FAILED,std::to_string(_csk),ERRNO_DESC);

  // If set, delete the contents of the connection's temporary directory
  if(_tmpDir != nullptr)
   cleanTmpDir();
 }


/* ============================ OTHER PUBLIC METHODS ============================ */



// sendOk()
// sendClose()
// sendCloseError()