#ifndef SAFECLOUD_CLICONNMGR_H
#define SAFECLOUD_CLICONNMGR_H

/* SafeCloud Client Connection Manager  */

#include "ConnMgr.h"
#include "CliSTSMMgr.h"
#include "CliSessMgr.h"
#include <openssl/evp.h>

class CliConnMgr : ConnMgr
 {
  private:

   /* ------------------------- Attributes ------------------------- */
   X509_STORE* _cliStore;    // The client's X.509 certificate store used for validating the server's signature
   char*       _downDir;     // The client's download directory

   // TODO: From here, initializations?
   CliSTSMMgr* _cliSTSMMgr;  // The client's STSM key handshake manager
   CliSessMgr* _cliSessMgr;  // The client's session manager

   /* ================= Constructors and Destructor ================= */
   CliConnMgr(int csk, char* ip, int port, char* name, char* tmpDir, X509_STORE* cliStore, char* downDir);
   // Same destructor of the ConnMgr base class

  /* ======================== Other Methods ======================== */
  // TODO
  // uploadFile()
  // downloadFile()
  // renameFile()
  // deleteFile()
  // listFiles()
  // close()
 };


#endif //SAFECLOUD_CLICONNMGR_H
