#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud Application Client */

#include <openssl/evp.h>
#include <netinet/in.h>
#include "CliConnMgr/CliConnMgr.h"

class Client
 {
  private:

   /* ========================= Attributes ========================= */

   /* -------------------- General Information -------------------- */
   struct sockaddr_in _srvAddr;     // The SafeCloud server listening socket type, IP and Port in network representation order
   X509_STORE*        _certStore;   // The client's X.509 certificates store
   CliConnMgr*        _cliConnMgr;  // The client's connection manager object

   /* ---------------- Client Personal Information ---------------- */
   char*     _name;     // The client's username (unique in the SafeCloud application)
   char*     _downDir;  // The client's download directory
   char*     _tempDir;  // The client's temporary files directory
   EVP_PKEY* _rsaKey;   // The client's Long-term RSA key pair

   /* -------------------- Client Object Flags -------------------- */
   bool _loggedIn;   // Whether the client has logged in within the SafeCloud application (locally, meaning that its personal parameters have been initialized)
   bool _connected;  // Whether the client is connected with the remote SafeCloud server
   bool _shutdown;   // Used to inform the client object to gracefully terminate upon receiving an OS signal


   /* =========================== Methods =========================== */

   /* ---------------- Client Object Initialization ---------------- */

   /**
     * @brief Sets the IP address and port of the SafeCloud server to connect to
     * @param srvIP   The SafeCloud server IP address
     * @param srvPort The SafeCloud server port
     * @throws ERR_INVALID_SRV_ADDR Invalid IP address format
     * @throws ERR_INVALID_SRV_PORT Invalid Port
     */
   void setSrvEndpoint(const char* srvIP, uint16_t& srvPort);

   /**
     * @brief Loads the CA's certificate from its file (buildX509Store() utility function)
     * @throws ERR_CA_CERT_OPEN_FAILED  The CA Certificate file could not be opened
     * @throws ERR_CA_CERT_CLOSE_FAILED The CA Certificate file could not be closed
     * @throws ERR_CA_CERT_INVALID      The CA Certificate is invalid
     */
   static X509* getCACert();

   /**
     * @brief Loads the CA's certificate revocation list from its file (buildX509Store() utility function)
     * @throws ERR_CA_CRL_OPEN_FAILED  The CA CRL file could not be opened
     * @throws ERR_CA_CRL_CLOSE_FAILED The CA CRL file could not be closed
     * @throws ERR_CA_CRL_INVALID      The CA CRL is invalid
     */
   static X509_CRL* getCACRL();

   /**
     * @brief Builds the client's X.509 certificate store used for verifying the validity of the server's certificate
     * @throws ERR_CA_CERT_OPEN_FAILED         The CA Certificate file could not be opened
     * @throws ERR_CA_CERT_CLOSE_FAILED        The CA Certificate file could not be closed
     * @throws ERR_CA_CERT_INVALID             The CA Certificate is invalid
     * @throws ERR_CA_CRL_OPEN_FAILED          The CA CRL file could not be opened
     * @throws ERR_CA_CRL_CLOSE_FAILED         The CA CRL file could not be closed
     * @throws ERR_CA_CRL_INVALID              The CA CRL is invalid
     * @throws ERR_STORE_INIT_FAILED           The X.509 certificate store could not be initalized
     * @throws ERR_STORE_ADD_CACERT_FAILED     Error in adding the CA certificate to the X.509 store
     * @throws ERR_STORE_ADD_CACRL_FAILED      Error in adding the CA CRL to the X.509 store
     * @throws ERR_STORE_REJECT_REVOKED_FAILED Error in configuring the X.509 store to reject revoked certificates
     */
   void buildX509Store();


   // TODO
   // bool srvConnect();
   // bool uploadFile();
   // bool downloadFile();
   // bool deleteFile();
   // bool renameFile();
   // bool listFiles();

  public:

   /* ================= Constructors and Destructor ================= */

   /**
    * @brief         Client object constructor, which initializes the IP and port of the
    *                SafeCloud server to connect to and the client's X.509 certificates store
    * @param srvIP   The IP address as a string of the SafeCloud server to connect to
    * @param srvPort The port of the SafeCloud server to connect to
    * @throws ERR_INVALID_SRV_ADDR            Invalid IP address format
    * @throws ERR_INVALID_SRV_PORT            Invalid Port
    * @throws ERR_CA_CERT_OPEN_FAILED         The CA Certificate file could not be opened
    * @throws ERR_CA_CERT_CLOSE_FAILED        The CA Certificate file could not be closed
    * @throws ERR_CA_CERT_INVALID             The CA Certificate is invalid
    * @throws ERR_CA_CRL_OPEN_FAILED          The CA CRL file could not be opened
    * @throws ERR_CA_CRL_CLOSE_FAILED         The CA CRL file could not be closed
    * @throws ERR_CA_CRL_INVALID              The CA CRL is invalid
    * @throws ERR_STORE_INIT_FAILED           The X.509 certificate store could not be initalized
    * @throws ERR_STORE_ADD_CACERT_FAILED     Error in adding the CA certificate to the X.509 store
    * @throws ERR_STORE_ADD_CACRL_FAILED      Error in adding the CA CRL to the X.509 store
    * @throws ERR_STORE_REJECT_REVOKED_FAILED Error in configuring the X.509 store to reject revoked certificates
    */
   Client(char* srvIP, uint16_t srvPort);

   /**
    * @brief Client object destructor, which safely deletes its sensitive attributes
    */
   ~Client();

   /* ======================== Other Methods ======================== */


   bool login();


   /**
    * @brief Informs the client object that they should
    *        close the connection and gracefully terminate
    */
   void shutdownSignal();

   /**
     * @brief  Returns whether the client is locally logged in within the SafeCloud application
     * @return 'true' if logged in, 'false' otherwise
     */
   bool isLoggedIn();

   /**
    * @brief  Returns whether the client is currently connected with the SafeCloud server
    * @return 'true' if connected, 'false' otherwise
    */
   bool isConnected();

   /**
     * @brief  Returns whether the client has received the shutdown signal
     * @return 'true' if it is shutting down, 'false' otherwise
     */
   bool isShuttingDown();


   // TODO
   // void clientBody();
 };


#endif //SAFECLOUD_CLIENT_H
