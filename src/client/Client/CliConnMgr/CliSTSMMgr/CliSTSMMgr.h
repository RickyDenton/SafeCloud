#ifndef SAFECLOUD_CLISTSMMGR_H
#define SAFECLOUD_CLISTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager */

#include "ConnMgr/STSMMgr/STSMMgr.h"

/* ------------------------- STSM Client States ------------------------- */
enum STSMCliState
 {
  // The client has yet to send its 'hello' message
  INIT,

  // The client has sent its 'hello' message and is awaiting the server's 'auth' message
  WAITING_SRV_AUTH,

  // The client has sent its 'auth' message and is awaiting the server 'ok' message
  WAITING_SRV_OK
 };


class CliSTSMMgr : STSMMgr
 {
  private:

   /* ------------------------- Attributes ------------------------- */
   enum STSMCliState _stsmCliState;  // Current client state in the STSM key exchange protocol
   X509_STORE*       _cliStore;      // The client's already-initialized X.509 certificate store used for validating the server's signature

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   CliSTSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey, X509_STORE* cliStore);
   // Same destructor of the STSMMgr base class

   /* ------------------------------- Other Methods ------------------------------- */

   // TODO:
   //
   // NOTE: 1) All return the success of the operation TODO: exceptions?
   //       2) All check for the STSMError message before doing their thing
   //
   // bool sendHello();
   // bool recvSrvAuth ();
   // bool sendCliAuth();
   // bool recvSrvOK();
 };


#endif //SAFECLOUD_CLISTSMMGR_H
