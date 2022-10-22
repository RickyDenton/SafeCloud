/* SafeCloud Connection Manager Definitions */

/* ================================== INCLUDES ================================== */
#include <unistd.h>
#include <string>
#include "ConnMgr.h"
#include "defaults.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include <dirent.h>
#include <arpa/inet.h>


/* ============================== PROTECTED METHODS ============================== */

/**
 * @brief Deletes the contents of the connection's temporary directory
 *        (called within the connection manager's destructor)
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
   LOG_EXEC_CODE(ERR_DIR_OPEN_FAILED, *_tmpDir, ERRNO_DESC);
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
       LOG_EXEC_CODE(ERR_FILE_DELETE_FAILED, std::string(tmpFileAbsPath), ERRNO_DESC);
     }

    // Close the temporary folder
    if(closedir(tmpDir) == -1)
     LOG_EXEC_CODE(ERR_DIR_CLOSE_FAILED, *_tmpDir, ERRNO_DESC);
   }
 }


/* ---------------------------------- Data I/O ---------------------------------- */

/**
 * @brief Marks the contents of the primary connection buffer as consumed,
 *        resetting the index of its first significant byte and the
 *        expected size of the data block (message or raw) to be received
 */
void ConnMgr::clearPriBuf()
 {
  _priBufInd = 0;
  _recvBlockSize = 0;
 }


/**
 * @brief Sends bytes from the start of the primary connection buffer to the connection peer
 * @param numBytes The number of bytes to be sent (must be <= _priBufSize)
 * @throws ERR_SEND_OVERFLOW     Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED       send() fatal error
 */
void ConnMgr::sendData(unsigned int numBytes)
 {
  // Connection socket send() return, representing, if no error has occurred, the number
  // of bytes read sent from the primary connection buffer through the connection socket
  ssize_t sendRet;

  // Assert the number of bytes to be sent to be less
  // or equal than the primary connection buffer size
  if(numBytes > _priBufSize)
   THROW_EXEC_EXCP(ERR_SEND_OVERFLOW,std::to_string(numBytes) + " > _priBufSize = " + std::to_string(_priBufSize));

  // Reset the index of the most significant byte in the primary connection buffer
  _priBufInd = 0;

  do
   {
    // Attempt to send the pending message bytes through the connection socket
    sendRet = send(_csk, (const char*)&_priBuf + _priBufInd, numBytes - _priBufInd, 0);

    // If any number of bytes were successfully sent, increment the index of the
    // ost significant byte in the primary connection buffer of that amount
    if(sendRet > 0)
     _priBufInd += sendRet;
    else

     // Otherwise, if the send() failed, depending on its error
     if(sendRet == -1)
      switch(errno)
       {
        // If the process was interrupted
        // within the send(), retry sending
        case EINTR:
         break;

        // If the peer abruptly closed the connection while
        // data was being sent, throw the associated exception
        case ECONNRESET:
         THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED, *_name);

        // All other send() errors are FATAL errors
        default:
         THROW_EXEC_EXCP(ERR_SEND_FAILED, *_name,ERRNO_DESC);
       }

      // Otherwise, if no error has occurred and no
      // bytes was sent (sendRet == 0), retry sending
     else
      LOG_WARNING("send() sent 0 bytes (numBytes = " + std::to_string(numBytes)
                  + ", _priBufInd = " + std::to_string(_priBufInd) + ")")
   } while(_priBufInd != numBytes);

  // Reset the index of the most significant byte in the primary connection buffer
  _priBufInd = 0;
 }


/**
 * @brief Sends a message stored in the primary communication buffer, with
 *        its first 16 bits representing its size, to the connection peer
 * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED       send() fatal error
 */
void ConnMgr::sendMsg()
 {
  // Determine the message's size as the first 16 bits of the primary communication
  // buffer (representing the "len" field of a STSMMsg or a SessMessageWrapper messages)
  uint16_t msgSize = ((uint16_t*)_priBuf)[0];

  // Send the message to the connection peer
  sendData(msgSize);

  // Reset the index of the first significant byte of the primary connection
  // buffer as well as the expected size of the data block to be received
  clearPriBuf();

  LOG_DEBUG("Sent message of " + std::to_string(msgSize) + " bytes")
 }




bool ConnMgr::recvMsgLength()
 {
  // Connection socket recv() return, representing, if no error has occurred, the
  // number of bytes read from the connection socket into the primary connection buffer
  ssize_t recvRet;

  // Ensure the connection manager to be in the RECV_MSG reception mode
  if(_recvMode != RECV_MSG)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive a message in RECV_RAW mode");

  clearPriBuf();

  // Attempt to read 2 bytes from the connection socket into the primary connection
  // buffer, representing the length of a received message
  recvRet = recv(_csk, &_priBuf[0], 2, MSG_WAITALL);

  // Depending on the recv() return
  switch(recvRet)
   {
    // recv() FATAL error
    case -1:
     THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED, ERRNO_DESC);

    // Abrupt peer disconnection
    case 0:
     THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED, *_name);

    // Message length read
    case 2:

     // Update the number of significant bytes in the primary connection buffer
     _priBufInd += recvRet;

     // Set message length
     _recvBlockSize = ((uint16_t*)_priBuf)[0];

     // Check message length value
     if(_recvBlockSize < 3)
      LOG_ERROR("_recvBlockSize == " + std::to_string(_recvBlockSize) + " < 3")
     break;

    default:
     LOG_ERROR("UNEXPECTED recvRet() return" + std::to_string(recvRet))
   }
 }


bool ConnMgr::recvMsgData()
 {
  // Ensure the connection manager to be in the RECV_MSG reception mode
  if(_recvMode != RECV_MSG)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive a message in RECV_RAW mode");

  // Message length missing
  if(_recvBlockSize == 0)
   recvMsgLength();

  recvRaw();

  if(_recvBlockSize == _priBufInd)
   return true;
  else
   {
    if(_priBufSize == _priBufInd)
     LOG_ERROR("MESSAGE BUFFER FULL")
    return false;
   }
 }



unsigned int ConnMgr::recvRaw()
 {
  if(_recvBlockSize == 0)
   LOG_ERROR("UNKNOWN MAX RECEIVE SIZE")

  // Connection socket recv() return, representing, if no error has occurred, the
  // number of bytes read from the connection socket into the primary connection buffer
  ssize_t recvRet;

  // Maximum number of bytes that can be read from the connection socket
  // into the primary connection buffer in this recvData() execution
  size_t maxReadBytes = std::min((_priBufSize - _priBufInd), (_recvBlockSize - _priBufInd));

  // Attempt to read raw data
  // Attempt to read the remaining bytes from the connection socket into the primary connection buffer
  recvRet = recv(_csk, &_priBuf[_priBufInd], maxReadBytes, 0);

  // Depending on the recv() return
  switch(recvRet)
   {
    // recv() FATAL error
    case -1:
     THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED, ERRNO_DESC);

    // Abrupt peer disconnection
    case 0:
     THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED, *_name);

    // > 0 => recvRet = number of bytes read from the connection socket (<= maxReadBytes)
    default:

     // Update the number of significant bytes in the primary connection buffer
     _priBufInd += recvRet;
     return recvRet;
   }
 }



/**
 * @brief Blocks until a full message has been read from the
 *        connection socket into the primary communication buffer
 * @throws ERR_CONNMGR_INVALID_STATE Attempting to receive a message while the
 *                                   connection manager is in the RECV_RAW mode
 * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
 */
void ConnMgr::recvFullMsg()
 {
  // Ensure the connection manager to be in the RECV_MSG reception mode
  if(_recvMode != RECV_MSG)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive a message in RECV_RAW mode");

  recvMsgLength();

  do
   {
    recvRaw();

    if(_recvBlockSize != _priBufInd && _priBufSize == _priBufInd)
     LOG_ERROR("MESSAGE BUFFER FULL")

   } while(_recvBlockSize != _priBufInd);

 }







/*

  // Attempt to read 2 bytes from the connection socket into the primary connection
  // buffer,

  // Attempt to read up to the maximum allowed bytes from the connection socket
  // into the primary connection buffer, blocking if no data is available
  recvRet = recv(_csk, _priBuf, maxReadBytes, 0);


  // Block and read data from the connection socket into the primary
  // communication buffer until a complete message has been read
  while(!recvData())
   ;
 }

*/

/**
 * @brief  Reads bytes belonging to a same data block from the connection socket into the primary connection buffer,
 *         updating its number of significant bytes and, with the manager in RECV_MSG mode, the expected size of the
 *         message to be received, if such quantity is not already set
 * @return - ConnMgr in RECV_MSG mode: A boolean indicating whether a complete message\n
 *                                     has been received in the primary connection buffer\n
 *         - ConnMgr in RECV_RAW mode: The number of bytes read in the primary connection buffer
 * @throws ERR_CSK_RECV_FAILED   Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED The connection peer has abruptly disconnected
 */
size_t ConnMgr::recvData()
 {
  // Maximum number of bytes that can be read from the connection socket
  // into the primary connection buffer in this recvData() execution
  size_t maxReadBytes;

  // Connection socket recv() return, representing, if no error has occurred, the
  // number of bytes read from the connection socket into the primary connection buffer
  ssize_t recvRet;

  /*
   * Determine the maximum number of bytes that can be read from the connection
   * socket into the primary connection buffer in this recv() data execution as:
   *
   *  - If the expected size of the data block (message or raw) to be received is NOT known
   *    (_recvBlockSize == 0), as the difference between the primary connection buffer's size
   *    and the index of its first available byte (so to prevent buffer overflows)
   *  - If the expected size of the data block (message or raw) to be received IS instead known,
   *    as the minimum between the previous quantity and the difference between such expected
   *    size and the index of the first available byte in the primary connection's buffer
   *    (so to prevent reading data belonging to the next data block)
   */
  if(_recvBlockSize == 0)
   {
    maxReadBytes = (_priBufSize - _priBufInd);
    std::cout << "_recvBlockSize == 0" << std::endl;
    std::cout << "_priBufSize = " << _priBufSize << std::endl;
    std::cout << "_priBufInd = " << _priBufInd << std::endl;
   }
  else
   {
    maxReadBytes = std::min((_priBufSize - _priBufInd), (_recvBlockSize - _priBufInd));
    std::cout << "_recvBlockSize = " << _recvBlockSize << std::endl;
    std::cout << "_priBufSize = " << _priBufSize << std::endl;
    std::cout << "_priBufInd = " << _priBufInd << std::endl;
   }

  // Attempt to read up to the maximum allowed bytes from the connection socket
  // into the primary connection buffer, blocking if no data is available
  recvRet = recv(_csk, _priBuf, maxReadBytes, 0);

  LOG_DEBUG(*_name + " recv() returned " + std::to_string(recvRet) + " (maxReadBytes = " + std::to_string(recvRet) + ")")

  // Depending on the recv() return
  switch(recvRet)
   {
    // recv() FATAL error
    case -1:
     THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED, ERRNO_DESC);

    // Abrupt peer disconnection
    case 0:
     THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED, *_name);

    // > 0 => recvRet = number of bytes read from the connection socket (<= maxReadBytes)
    default:

     // Update the number of significant bytes in the primary connection buffer
     _priBufInd += recvRet;

     // If the connection manager is in the RECV_MSG mode
     if(_recvMode == RECV_MSG)
      {
       /*
        * if the expected size of the data block (message or raw) to be received
        * is NOT known, set it to first 16 bytes that have been just read
        * (representing the "len" field of a STSMMsg or a SessMessageWrapper messages)
        */
       if(_recvBlockSize == 0)
        _recvBlockSize = ((uint16_t*)_priBuf)[0];

       // Return whether a complete message has been received in the primary connection buffer
       return (_recvBlockSize == _priBufInd);
      }

     // Otherwise, if the connection manager is in the RECV_RAW mode, just
     // return the bytes that have been read in the primary connection's buffer
     else
      return recvRet;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief        ConnMgr object constructor
 * @param csk    The connection socket associated with this manager
 * @param name   The name of the client associated with this connection
 * @param tmpDir The absolute path of the temporary directory associated with this connection
 */
ConnMgr::ConnMgr(int csk, std::string* name, std::string* tmpDir)
 : _connPhase(KEYXCHANGE),_recvMode(RECV_MSG), _csk(csk),  _priBuf(), _priBufSize(CONN_BUF_SIZE + AES_128_GCM_TAG_SIZE),
   _priBufInd(0), _recvBlockSize(0), _secBuf(), _secBufSize(CONN_BUF_SIZE), _skey(), _iv(nullptr), _name(name), _tmpDir(tmpDir)
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
  OPENSSL_cleanse(&_priBuf[0], _priBufSize);
  OPENSSL_cleanse(&_secBuf[0], _secBufSize);

  // Close the connection socket
  if(close(_csk) != 0)
   LOG_EXEC_CODE(ERR_CSK_CLOSE_FAILED, std::to_string(_csk), ERRNO_DESC);

  // If set, delete the contents of the connection's temporary directory
  if(_tmpDir != nullptr)
   cleanTmpDir();
 }