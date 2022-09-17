#ifndef SAFECLOUD_STSMDATA_H
#define SAFECLOUD_STSMDATA_H

/* Interface of the base class used by client and server in the Station-To-Station-Modified (STSM) key exchange protocol */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>


// TODO: WRITE STSM DESCRIPTION

/*v
 *  The server authentication message comprises:
 *
 *  1) The server's ephemeral DH public key "Ys"
 *  2) The server signature of the concatenation of both ephemeral public
 *     keys encrypted with the resulting session key "{<Yc||Ys>privk_srv}k"
 *  3) The server's certificate "srvCert"
 */


/* Base STSM information used by client and server alike */
class STSMData
 {
  protected:

   /* ------------------------- Attributes ------------------------- */
   EVP_PKEY*          _myRSALongPrivKey;  // The actor's long-term RSA private key
   EVP_PKEY*          _myDHEKey;          // The actor's ephemeral DH key pair
   EVP_PKEY*          _otherDHEPubKey;    // The other actor's ephemeral DH public key

   unsigned char*     _iv;          // The current initialization vector (12 byte)
   const unsigned int _ivSize;    // Initialization vector size (12 bytes = 96 bits using AES_GCM)

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   STSMData(EVP_PKEY* myRSALongPrivKey);
   ~STSMData();
 };


#endif //SAFECLOUD_STSMDATA_H
