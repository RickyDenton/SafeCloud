#ifndef SAFECLOUD_SESSMGR_H
#define SAFECLOUD_SESSMGR_H

/* SafeCloud Session Manager */

#include <openssl/evp.h>

/* -------------------------- Session Operations -------------------------- */
enum sessionOp
 {
  IDLE,      // No operation in progress
  UPLOAD,    // File upload in progress
  DOWNLOAD,  // File download in progress
  RENAME,    // File rename in progress
  DELETE,    // File delete in progress
  LIST,      // Retrieving client's file list in the SafeCloud server
  CLOSE,     // Session closing
 };


class SessMgr
 {
   protected:

    /* ========================= Attributes ========================= */

    // General session information
    sessionOp _sessOp;            // The current session operation
    const int _csk;               // The session's connection socket
    char*     _tmpDir;            // The session's temporary directory

    // Buffer for sending and receiving session messages
    unsigned char*     _buf;      // Session Buffer
    unsigned int       _bufInd;   // Index to the first available byte in the Session buffer
    const unsigned int _bufSize;  // Session Buffer size

    // Cryptographic quantities
    unsigned char* _iv;           // The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
    unsigned char* _skey;         // The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)

    // Last sent and received session messages
//    sMsg* _sentMsg;               // The last sent session message
//    sMsg* _recvMsg;               // The last received session message


   public:

    /* ================= Constructors and Destructor ================= */
    SessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey);
    ~SessMgr();

    /* ======================== Other Methods ======================== */

    // TODO
    // send(sMsg)?
    // sendBye()?
    // sendError()?
 };


#endif //SAFECLOUD_SESSMGR_H
