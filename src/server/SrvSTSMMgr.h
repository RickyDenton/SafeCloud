#ifndef SAFECLOUD_SRVSTSMMGR_H
#define SAFECLOUD_SRVSTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager */

#include "STSMMgr.h"

/* ----------------------------- STSM Server States ----------------------------- */
enum STSMSrvState
 {
  // The server has not yet received the client's 'hello' message
  WAITING_CLI_HELLO,

  // The server has sent its 'auth' message and is awaiting the client's one
  WAITING_CLI_AUTH
 };


class SrvSTSMMgr : STSMMgr
 {
   private:

    /* ------------------------- Attributes ------------------------- */
    enum STSMSrvState _stsmSrvState;  // Current server state in the STSM key exchange protocol
    X509*             _srvCert;       // The server's X.509 certificate

   public:

    /* ---------------- Constructors and Destructor ---------------- */
    SrvSTSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey, X509* srvCert);
    // Same destructor of the STSMMgr base class

  /* ------------------------------- Other Methods ------------------------------- */

  // TODO:
  //
  // NOTE: 1) All return the success of the operation TODO: exceptions?
  //       2) All check for the STSMError message before doing their thing
  //
  // bool rcvHello();
  // bool sendSrvAuth();
  // bool recvCliAuth();
  // bool sendSrvOK();
 };

#endif //SAFECLOUD_SRVSTSMMGR_H
