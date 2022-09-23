/* SafeCloud Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include "ConnMgr.h"
#include "defaults.h"
#include "utils.h"
#include "scode.h"
#include "errlog.h"
#include <dirent.h>

/* =============================== PRIVATE METHODS =============================== */
// TODO

/**
 * @brief Deletes the contents of the connection's temporary directory
 */
void ConnMgr::cleanTmpDir()
 {
  DIR*           tmpDir;    // Temporary directory file descriptor
  struct dirent* tmpFile;   // Information on a file in the temporary directory

  // Absolute path of a file in the temporary length, whose max length is obtained by the
  // of length the temporary directory path plus the maximum file name length (+1 for the '\0')
  char tmpFileAbsPath[strlen(_tmpDir.c_str() + NAME_MAX + 1)];

  // Open the temporary directory
  tmpDir = opendir(_tmpDir.c_str());
  if(!tmpDir)
   LOG_SCODE(ERR_TMPDIR_OPEN_FAILED,std::string(_tmpDir),ERRNO_DESC);
  else
   {
    // For each file in the temporary folder
    while((tmpFile = readdir(tmpDir)) != NULL)
     {
      // Build the file's absolute path
      sprintf(tmpFileAbsPath, "%s/%s", "path/of/folder", tmpFile->d_name);

      // Delete the file
      if(remove(tmpFileAbsPath) == -1)
       LOG_SCODE(ERR_TMPFILE_DELETE_FAILED,std::string(tmpFileAbsPath),ERRNO_DESC);
     }

    // Close the temporary folder
    if(closedir(tmpDir) == -1)
     LOG_SCODE(ERR_FILE_CLOSE_FAILED,std::string(_tmpDir), ERRNO_DESC);
   }
 }


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief        ConnMgr object constructor
 * @param csk    The connection socket's file descriptor
 * @param ip     The connection endpoint's IP address
 * @param port   The connection endpoint's port
 * @param name   The client's name associated with this connection
 * @param tmpDir The connection's temporary directory
 */
ConnMgr::ConnMgr(int csk, std::string& name, std::string& tmpDir) : _connState(NOCONN), _csk(csk), _name(name), _tmpDir(tmpDir),
_buf(), _bufSize(CONN_BUF_SIZE), _oobBuf(), _oobBufSize(CONN_OOBUF_SIZE), _iv(), _ivSize(IV_SIZE), _skey(), _skeySize(SKEY_SIZE)
 {
  // Allocate the connection's buffers
  _buf = (unsigned char*)malloc(CONN_BUF_SIZE);
  _oobBuf = (unsigned char*)malloc(CONN_OOBUF_SIZE);
 }


/**
 * @brief Connection Manager object destructor, which closes its associated connection socket and safely deletes
 *        sensitive information such as the general-purpose and out-of band buffers, the IV and the session key
 */
ConnMgr::~ConnMgr()
 {
  // Close the connection socket
  // TODO: Check if adding a "bye" message here, but it should probably be implemented elsewhere
  if(close(_csk) != 0)
   LOG_SCODE(ERR_CSK_CLOSE_FAILED,std::string(strerror(errno)));
  else
    LOG_DEBUG("Connection socket '" + std::to_string(_csk) + "' closed")

  // Delete the contents of the connection's temporary directory
  cleanTmpDir();

  // Safely delete all the connection's sensitive information
  safeFree(reinterpret_cast<void*&>(_buf), _bufSize);
  safeFree(reinterpret_cast<void*&>(_oobBuf), _oobBufSize);
  safeFree(reinterpret_cast<void*&>(_iv), _ivSize);
  safeFree(reinterpret_cast<void*&>(_skey), _skeySize);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

// TODO

// sendOk()
// sendClose()
// sendCloseError()