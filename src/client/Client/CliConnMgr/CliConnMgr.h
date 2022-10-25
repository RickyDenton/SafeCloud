#ifndef SAFECLOUD_CLICONNMGR_H
#define SAFECLOUD_CLICONNMGR_H

/* SafeCloud Client Connection Manager  */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/ConnMgr.h"
#include "CliSTSMMgr/CliSTSMMgr.h"
#include "CliSessMgr/CliSessMgr.h"
#include <openssl/evp.h>

class CliConnMgr : public ConnMgr
 {
  private:

   /* ================================= ATTRIBUTES ================================= */
   std::string* _downDir;    // The absolute path of the client's download directory

   CliSTSMMgr* _cliSTSMMgr;  // The child client STSM key establishment manager object
   CliSessMgr* _cliSessMgr;  // The child client Session Manager object


   /* =============================== FRIEND CLASSES =============================== */
   friend class CliSTSMMgr;
   friend class CliSessMgr;

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief           CliConnMgr object constructor
    * @param csk       The connection socket associated with this manager
    * @param name      The client name associated with this connection
    * @param tmpDir    The connection's temporary directory
    * @param downDir   The client's download directory
    * @param rsaKey    The client's long-term RSA key pair
    * @param certStore The client's X.509 certificates store
    * @note The constructor also initializes the _cliSTSMMgr child object
    */
   CliConnMgr(int csk, std::string* name, std::string* tmpDir, std::string* downDir, EVP_PKEY* rsaKey, X509_STORE* certStore);

   /**
    * @brief CliConnMgr object destructor, safely deleting the
    *        client-specific connection sensitive information
    */
   ~CliConnMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Executes the STSM client protocol, and
    *         initializes the communication's session phase
    * @throws All the STSM exceptions and most of the OpenSSL
    *         exceptions (see "execErrCode.h" for more details)
    */
   void startCliSTSM();

   /**
    * @brief  Returns a pointer to the session manager's child object
    * @return A pointer to the session manager's child object
    * @throws ERR_CONNMGR_INVALID_STATE The connection is not in the session phase
    */
   CliSessMgr* getSession();
 };


#endif //SAFECLOUD_CLICONNMGR_H
