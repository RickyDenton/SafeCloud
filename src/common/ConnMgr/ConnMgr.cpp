/* SafeCloud Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <unistd.h>
#include <string>
#include "ConnMgr.h"
#include "defaults.h"
#include "scode.h"
#include "errlog.h"
#include <dirent.h>
#include <arpa/inet.h>

/* =============================== PRIVATE METHODS =============================== */
// TODO

/**
 * @brief Deletes the contents of the connection's temporary directory
 */
void ConnMgr::cleanTmpDir()
 {
  DIR*           tmpDir;    // Temporary directory file descriptor
  struct dirent* tmpFile;   // Information on a file in the temporary directory

  // Absolute path of a file in the temporary directly, whose maximum length is given by the length
  // of the temporary directory's path plus the maximum file name length (+1 for the '\0' terminator)
  char tmpFileAbsPath[strlen(_tmpDir->c_str() + NAME_MAX + 1)];

  // Convert the temporary directory's path to a C string
  const char* _tmpDirC = _tmpDir->c_str();

  // Open the temporary directory
  tmpDir = opendir(_tmpDirC);
  if(!tmpDir)
   LOG_SCODE(ERR_TMPDIR_OPEN_FAILED,*_tmpDir,ERRNO_DESC);
  else
   {
    // For each file in the temporary folder
    while((tmpFile = readdir(tmpDir)) != NULL)
     {
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

  // Free the temporary directory's path as a C string
  delete _tmpDirC;
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief        ConnMgr object constructor
 * @param csk    The connection socket's file descriptor
 * @param name   The client's name associated with this connection
 * @param tmpDir The connection's temporary directory
 */
ConnMgr::ConnMgr(int csk, std::string* name, std::string* tmpDir) : _connState(KEYXCHANGE), _csk(csk), _name(name), _tmpDir(tmpDir), _buf(),
                                                                    _bufSize(CONN_BUF_SIZE), _bufInd(0), _iv(), _ivSize(IV_SIZE), _skey(), _skeySize(SKEY_SIZE)
 {}


/**
 * @brief Connection Manager object destructor, which closes its associated connection
 *        socket and safely deletes all the connection's sensitive information
 */
ConnMgr::~ConnMgr()
 {
  // Close the connection socket
  // TODO: Check if adding a "bye" message here, but it should probably be implemented elsewhere
  if(close(_csk) != 0)
   LOG_SCODE(ERR_CSK_CLOSE_FAILED,std::to_string(_csk),ERRNO_DESC);

  // If set, delete the contents of the connection's temporary directory
  if(_tmpDir != nullptr)
   cleanTmpDir();

  // Safely delete all the connection's sensitive information
  if(_name != nullptr)
   OPENSSL_cleanse(_name, _name->length()+1);
  if(_tmpDir != nullptr)
   OPENSSL_cleanse(_tmpDir, _tmpDir->length()+1);
  OPENSSL_cleanse(_buf, _bufSize);
  OPENSSL_cleanse(_iv, _ivSize);
  OPENSSL_cleanse(_skey, _skeySize);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

// TODO

// ERR_CSK_RECV_FAILED

bool ConnMgr::recvData()
 {
  ssize_t recvRet; // Number of bytes read from the connection socket

  // Attempt to read up to (_bufSize - _bufInd) bytes from the connection socket into the general purpose buffer
  recvRet = recv(_csk, _buf, (_bufSize - _bufInd), 0);

  LOG_DEBUG(*_name + " recv() returned " + std::to_string(recvRet))

  // Depending on the number of bytes that were read from the connection socket
  switch(recvRet)
   {
    // recv() error
    case -1:
     THROW_SCODE(ERR_CSK_RECV_FAILED,*_name,ERRNO_DESC);

    // Abrupt peer disconnection
    case 0:
     THROW_SCODE(ERR_PEER_DISCONNECTED,*_name);

    // > 0 => number of bytes read from socket
    default:

     // Process the incoming client data
     // _bufInd += recvRet;

     // TODO: implement appropriately
     // TODO --------------------------------------------------------------------------------------------------------
     _buf[_bufInd + recvRet] = '\0';

     char cliMsg[1024];
     memcpy(cliMsg,&_buf[_bufInd],recvRet+1);

     char hello[] = "Hello from server";
     char login_success[] = "Login successful";

     if(!strcmp(cliMsg, "close"))
      return false;

     // If the client "logged in"
     if(!strcmp(cliMsg, "login"))
      {
       // Inform the user that the login was successful
       send(_csk, (const void*)login_success, sizeof(login_success), 0);

       // Log that the user has logged in
       LOG_INFO("\"" + *_name + "\" has logged in as \"Alice" + std::to_string(_csk) + "\"")

       // Set the user's "name"
       *_name = "Alice" + std::to_string(_csk);

       // Return that the client connection must be maintained
       return true;
      }

    // Otherwise, it is just a random message

    // Echo the client message
    std::cout << "\"" << *_name << "\" says \"" << cliMsg << "\"" << std::endl;

    // Reply a predefined message
    send(_csk, (const void*)hello, sizeof(hello), 0);

    // Return that the client connection must be maintained
    return true;
    // TODO --------------------------------------------------------------------------------------------------------

   }

 }

// sendOk()
// sendClose()
// sendCloseError()