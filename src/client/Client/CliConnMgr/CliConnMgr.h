#ifndef SAFECLOUD_CLICONNMGR_H
#define SAFECLOUD_CLICONNMGR_H

/* SafeCloud Client Connection Manager  */

#include "ConnMgr/ConnMgr.h"
#include "CliSTSMMgr/CliSTSMMgr.h"
#include "CliSessMgr/CliSessMgr.h"
#include <openssl/evp.h>

class CliConnMgr : public ConnMgr
 {
  private:

   /* ================================= ATTRIBUTES ================================= */
   std::string* _downDir;     // The client's download directory

   CliSTSMMgr* _cliSTSMMgr;  // The child client STSM key establishment manager
   CliSessMgr* _cliSessMgr;  // The child client session manager

   /* =============================== FRIEND CLASSES =============================== */
   friend class CliSTSMMgr;
   friend class CliSessMgr;

   /* ============================== PRIVATE METHODS ============================== */

   /**
    * @brief Waits and reads data from the connection socket
    *        until a full data block has been received
    * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
    * @throws ERR_SRV_DISCONNECTED Abrupt server disconnection
    */
   void recvMsg();


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
    *         exceptions (see "scode.h" for more details)
    */
   void startCliSTSM();

   /**
    * @brief  Returns a pointer to the session manager's child object
    * @return A pointer to the session manager's child object
    * @throws ERR_CONN_NO_SESSION The connection is not in the session phase
    */
   CliSessMgr* getSession();



   // TODO
   // uploadFile()
   // downloadFile()
   // renameFile()
   // deleteFile()
   // listFiles()
   // close()
 };


#endif //SAFECLOUD_CLICONNMGR_H
