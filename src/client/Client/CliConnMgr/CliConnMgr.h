#ifndef SAFECLOUD_CLICONNMGR_H
#define SAFECLOUD_CLICONNMGR_H

/* SafeCloud Client Connection Manager  */

#include "ConnMgr/ConnMgr.h"
#include "CliSTSMMgr/CliSTSMMgr.h"
#include "CliSessMgr/CliSessMgr.h"
#include <openssl/evp.h>

class CliConnMgr : ConnMgr
 {
  private:

   /* ------------------------- Attributes ------------------------- */
   X509_STORE*  _cliStore;    // The client's X.509 certificate store used for validating the server's signature
   std::string& _downDir;     // The client's download directory

   CliSTSMMgr* _cliSTSMMgr;  // The client's STSM key handshake manager
   CliSessMgr* _cliSessMgr;  // The client's session manager

  public:

   /* ================= Constructors and Destructor ================= */
   CliConnMgr(int csk, std::string& name, std::string& tmpDir, X509_STORE* cliStore, std::string& downDir);
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
