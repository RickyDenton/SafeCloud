/* SafeCloud Client Session Manager Implementation */

/* ================================== INCLUDES ================================== */
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

