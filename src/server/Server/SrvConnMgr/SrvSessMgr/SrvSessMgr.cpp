/* SafeCloud Server Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSessMgr.h"

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
 * @param poolDir The client's pool directory
 */
SrvSessMgr::SrvSessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey, char* poolDir)
  : SessMgr(csk,tmpDir,buf,bufSize,iv,skey), _poolDir(poolDir)
 {}

