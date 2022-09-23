/* SafeCloud Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SessMgr.h"


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
 */
SessMgr::SessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey)
                 : _sessOp(IDLE), _csk(csk), _tmpDir(tmpDir), _buf(buf), _bufInd(0), _bufSize(bufSize), _iv(iv), _skey(skey)//, _sentMsg(nullptr), _recvMsg(nullptr)
 {}


/**
 * @brief SessMgr object constructor, which safely deletes its sensitive attributes
 * @note  Apart from the last received and sent session messages all other sensitive attributes are safely
 *        deleted within the associated ConnMgr destructor (which is called immediately after this one)
 */
SessMgr::~SessMgr()
 {
  // Delete the last received and sent session messages
//  delete _sentMsg;
//  delete _recvMsg;
 }