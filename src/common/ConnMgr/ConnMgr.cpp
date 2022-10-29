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

/* ------------------------------- Utility Methods ------------------------------- */

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


/* ----------------------- SafeCloud Messages Send/Receive ----------------------- */

/**
 * @brief Sends a SafeCloud message (STSMMsg or SessMsg) stored in
 *        the primary connection buffer to the connection peer
 * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED       send() fatal error
 */
void ConnMgr::sendMsg()
 {
  // Determine the message's length as the first 16 bits of the primary communication
  // buffer (representing the "len" field of a STSMMsg or a SessMessageWrapper messages)
  uint16_t msgLen = ((uint16_t*)_priBuf)[0];

  // Send the message to the connection peer
  sendRaw(msgLen);

  // Reset the index of the first significant byte of the primary connection
  // buffer as well as the expected size of the data block to be received
  clearPriBuf();

  LOG_DEBUG("Sent message of " + std::to_string(msgLen) + " bytes")
 }


/**
 * @brief  Blocks until a SafeCloud message length header of MSG_LEN_HEAD_SIZE bytes (2)
 *         is received from the connection socket into the primary connection buffer
 * @throws ERR_CSK_RECV_FAILED    Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED  The connection peer has abruptly disconnected
 * @throws ERR_MSG_LENGTH_INVALID Received an invalid message length value
 */
void ConnMgr::recvMsgLenHeader()
 {
  // Connection socket recv() return, representing, if no error has occurred, the
  // number of bytes read from the connection socket into the primary connection buffer
  ssize_t recvRet;

  // Reset the index of the first significant byte of the primary connection
  // buffer as well as the expected size of the data block to be received
  clearPriBuf();

  // Block until a message length header is received from the
  // connection socket into the primary connection buffer
  recvRet = recv(_csk, &_priBuf[0], MSG_LEN_HEAD_SIZE, MSG_WAITALL);

  // Depending on the recv() return
  switch(recvRet)
   {
    /* ------------------ recv() error ------------------ */
    case -1:

     // If the peer abruptly disconnected
     if(errno == ECONNRESET)
      THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED);

     // Otherwise it is a recv() FATAL error
     else
      THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED, ERRNO_DESC);

    /* ------------ Abrupt peer disconnection ------------ */
    case 0:
     THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED);

    /* ----------- Message length header read ----------- */
    // Message length header read
    case MSG_LEN_HEAD_SIZE:

     // Update the number of significant bytes in the primary connection buffer
     _priBufInd += MSG_LEN_HEAD_SIZE;

     // Set the expected size of the message to be received to the message length header
     _recvBlockSize = ((uint16_t*)_priBuf)[0];

     // Assert the message length to be valid, i.e. to be larger than a message
     // length header but not larger than the whole primary connection buffer
     if(_recvBlockSize < MSG_LEN_HEAD_SIZE + 1 || _recvBlockSize > _priBufSize)
      THROW_EXEC_EXCP(ERR_MSG_LENGTH_INVALID, std::to_string(_recvBlockSize));
     break;

    /* ---------- Invalid number of bytes read ---------- */
    default:
     THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED,"recv() returned " + std::to_string(recvRet) +
                                         " != " + std::to_string(MSG_LEN_HEAD_SIZE) +
                                         " bytes in receiving a message length header");
   }
 }


/**
 * @brief  Blocks until a full SafeCloud message (STSMMsg or SessMsg) has been
 *         received from the connection socket into the primary communication buffer
 * @throws ERR_CONNMGR_INVALID_STATE Attempting to receive a message with
 *                                   the connection manager in RECV_RAW mode
 * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
 * @throws ERR_MSG_LENGTH_INVALID    Received an invalid message length value
 */
void ConnMgr::recvFullMsg()
 {
  // Ensure the connection manager to be in the 'RECV_MSG' reception mode
  if(_recvMode != RECV_MSG)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive a full message in RECV_RAW mode");

  // Block until a SafeCloud message length header of MSG_LEN_HEAD_SIZE bytes (2)
  // is received from the connection socket into the primary connection buffer
  recvMsgLenHeader();

  // Blocks until a full SafeCloud message has been read from
  // the connection socket into the primary connection buffer
  while(_recvBlockSize != _priBufInd)
   recvRaw();
 }


/* ---------------------------- Raw Data Send/Receive ---------------------------- */

/**
 * @brief Sends bytes from the start of the primary connection buffer to the connection peer
 * @param numBytes The number of bytes to be sent (must be <= _priBufSize)
 * @throws ERR_SEND_OVERFLOW     Attempting to send a number of bytes > _priBufSize
 * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
 * @throws ERR_SEND_FAILED       send() fatal error
 */
void ConnMgr::sendRaw(unsigned int numBytes)
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
 * @brief  Blocks until any number of bytes belonging to the data block to be received (message
 *         or raw) are read from the connection socket into the primary connection buffer
 * @return The number of bytes read from the connection socket into the primary connection buffer
 * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
 * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
 * @throws ERR_CONNMGR_INVALID_STATE The expected data block size is unknown or not greater than the
 *                                   index of the first available byte in the primary connection buffer
 */
unsigned int ConnMgr::recvRaw()
 {
  // Connection socket recv() return, representing, if no error has occurred, the
  // number of bytes read from the connection socket into the primary connection buffer
  ssize_t recvRet;

  // Maximum number of bytes that can be read from the connection socket
  // into the primary connection buffer in this recvRaw() execution
  size_t maxReadBytes;

  // Assert the expected data block size be known
  if(_recvBlockSize == 0)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive raw data with"
                                              "an unknown expected data block size");

  // Assert the expected data block size to be greater than the
  // index of the first available byte in the primary connection buffer
  if(_recvBlockSize <= _priBufInd)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Attempting to receive raw data with an  expected data"
                                              "block size smaller or equal than the index of the "
                                              "first available byte in the primary connection buffer");

  /*
   * Determine the maximum number of bytes that can be read from the connection socket into the primary
   * connection buffer as the minimum between:
   *    - The difference between the size of the primary connection buffer and
   *      the index of its first available byte (buffer overflow prevention)
   *    - The difference between the expected data block size and the index of the first available byte
   *      in the primary connection buffer (so to prevent reading bytes belonging to the next data block)
   */
  maxReadBytes = std::min((_priBufSize - _priBufInd), (_recvBlockSize - _priBufInd));

  // Block until any number of bytes up to 'maxReadBytes' are received from the
  // connection socket to the first available byte in the primary connection buffer
  recvRet = recv(_csk, &_priBuf[_priBufInd], maxReadBytes, 0);

  // Depending on the recv() return
  switch(recvRet)
   {
    /* ------------------ recv() error ------------------ */
    case -1:

     // If the peer abruptly disconnected
     if(errno == ECONNRESET)
      THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED);

      // Otherwise it is a recv() FATAL error
     else
      THROW_EXEC_EXCP(ERR_CSK_RECV_FAILED, ERRNO_DESC);

    /* ------------ Abrupt peer disconnection ------------ */
    case 0:
     THROW_EXEC_EXCP(ERR_PEER_DISCONNECTED);

    /* ---------------- Valid bytes read ---------------- */

    // recvRet > 0 => recvRet =  number of bytes
    // read from the connection socket (<= maxReadBytes)
    default:

     // Update the number of significant bytes
     // in the primary connection buffer
     _priBufInd += recvRet;

     // Return the number of bytes that were read
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
 : _connPhase(KEYXCHANGE), _recvMode(RECV_MSG), _csk(csk), _shutdownConn(false), _priBuf(), _priBufSize(CONN_BUF_SIZE),
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


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Returns whether the connection manager should be terminated
 * @return A boolean indicating whether the connection manager should be terminated
 */
bool ConnMgr::shutdownConn() const
 { return _shutdownConn; }