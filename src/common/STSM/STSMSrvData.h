#ifndef SAFECLOUD_STSMSRVDATA_H
#define SAFECLOUD_STSMSRVDATA_H

/* Station-To-Station-Modified (STSM) key exchange protocol server class interface */

#include "STSMData.h"


/* ----------------------------- STSM Server States ----------------------------- */
enum STSMSrvState
 {
  // The server has not yet received the client's hello message
  WAITING_CLI_HELLO,

  // The server has sent its authentication
  // message and is awaiting the client's one
  WAITING_CLI_AUTH
 };


class STSMSrvData : STSMData
 {
   private:

    /* ------------------------- Attributes ------------------------- */
    enum STSMSrvState _stsmSrvState;  // The current server state in the STSM key exchange protocol
    X509*             _srvCert;       // The server's X.509 certificate

   public:

    /* ---------------- Constructors and Destructor ---------------- */
    STSMSrvData(EVP_PKEY* myRSALongPrivKey, X509* srvCert);
    // The class's constructor is the same of the base class

  /* ------------------------------- Other Methods ------------------------------- */

  // TODO
 };

#endif //SAFECLOUD_STSMSRVDATA_H
