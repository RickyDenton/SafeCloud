#ifndef SAFECLOUD_STSMCLIDATA_H
#define SAFECLOUD_STSMCLIDATA_H

/* Station-To-Station-Modified (STSM) key exchange protocol client class interface */

#include "STSMData.h"

/* ------------------------- STSM Client States ------------------------- */
enum STSMCliState
 {
  // The client has not yet sent its hello message
  INIT,

  // The client has sent their ephemeral DH public key to
  // the server and is awaiting its authentication message
  WAITING_SRV_AUTH,

  // The client has sent their authentication message
  // and is awaiting the server's login confirmation
  WAITING_SRV_OK
 };


class STSMCliData : STSMData
 {
  private:

   /* ------------------------- Attributes ------------------------- */
   enum STSMCliState _stsmCliState;  // The current client state in the STSM key exchange protocol
   X509_STORE*       _cliStore;      // The client's X.509 certificates store used for verifying the server's certificate

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   STSMCliData(EVP_PKEY* myRSALongPrivKey, X509_STORE* cliStore);
   // The class's constructor is the same of the base class

   /* ------------------------------- Other Methods ------------------------------- */

   // TODO:
   // bool sendHelloMessage(int csk);
   // bool recvSrvAuth(int csk);
   // bool sendCliAuth(int csk);
   // bool recvSrvOk(int csk);
 };


#endif //SAFECLOUD_STSMCLIDATA_H
