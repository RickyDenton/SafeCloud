#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud Application Client */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <netinet/in.h>
#include "CliConnMgr/CliConnMgr.h"
#include "errlog.h"
#include <string>


class Client
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* ---------------------------- General Information ---------------------------- */
   struct sockaddr_in _srvAddr;           // The SafeCloud server listening socket type, IP and Port in network representation order
   X509_STORE*        _certStore;         // The client's X.509 certificates store
   CliConnMgr*        _cliConnMgr;        // The client's connection manager object
   unsigned char      _remLoginAttempts;  // The remaining number of client's login attempts

   /* ------------------------ Client Personal Information ------------------------ */
   std::string _name;     // The client's username (unique in the SafeCloud application)
   std::string _downDir;  // The client's download directory
   std::string _tempDir;  // The client's temporary files directory
   EVP_PKEY*   _rsaKey;   // The client's long-term RSA key pair

   /* ---------------------------- Client Object Flags ---------------------------- */
   bool _connected;  // Whether the client is connected with the remote SafeCloud server
   bool _shutdown;   // Whether the client object is shutting down


   /* =============================== PRIVATE METHODS =============================== */

   /* ------------------------ Client Object Initialization ------------------------ */

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
     * @throws ERR_STORE_INIT_FAILED           The X.509 certificate store could not be initialized
     * @throws ERR_STORE_ADD_CACERT_FAILED     Error in adding the CA certificate to the X.509 store
     * @throws ERR_STORE_ADD_CACRL_FAILED      Error in adding the CA CRL to the X.509 store
     * @throws ERR_STORE_REJECT_REVOKED_FAILED Error in configuring the X.509 store to reject revoked certificates
     */
   void buildX509Store();


   /* -------------------------------- Client Login -------------------------------- */

   /**
    * @brief Prints the SafeCloud client welcome message
    */
   static void printWelcomeMessage();

   /**
    * @brief Safely deletes all client's information
    */
   void delCliInfo();

   /**
    * @brief           Client's login error handler, which deletes the client's personal
    *                  information and decreases the number of remaining login attempts
    * @param loginExcp The login-related sCodeException
    * @throws          ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
    */
   void loginError(sCodeException& loginExcp);

   /**
     * @brief   Reads a character from stdin while temporarily disabling
     *          its echoing on stdout (getUserPwd() helper function)
     * @return  The character read from stdin
     */
   static signed char getchHide();


   /**
     * @brief  Reads the user's password while concealing its
     *         characters with asterisks "*" (login() helper function)
     * @return The user-provided password
     */
   static std::string getUserPwd();

   /**
    * @brief           Attempts to locally authenticate the user by retrieving and decrypting
    *                  its RSA long-term private key (login() helper function)
    * @param username  The candidate user name
    * @param password  The candidate user password
    */
   void getUserRSAKey(std::string& username,std::string& password);

   /**
    * @brief Attempts to locally authenticate a client within the SafeCloud application by prompting
    *        for its username and password, authentication consisting in successfully retrieving the
    *        user's long-term RSA key pair encrypted with such password stored in a ".pem" file with
    *        a predefined path function of the provided username
    * @throws ERR_CLI_LOGIN_FAILED Client's login attempts expired
    */
  void login();

  /* ----------------------------- Server Connection ----------------------------- */

  /**
   * @brief           Client's connection error handler, which resets the server's connection and, in case of
   *                  non-fatal errors, prompt the user whether a reconnection attempt should be performed
   * @param loginExcp The connection-related sCodeException
   * @throws          ERR_SRV_LOGIN_FAILED Server-side client authentication failed (rethrown
   *                                       for it to be handled in the loginError() handler)
   */
  void connError(sCodeException& connExcp);


   // TODO: Write description
   // Server TCP connection + STSM Handshake
   void srvConnect();

  /* ------------------------------ Client Commands ------------------------------ */

  // TODO

  void listDownloadDir();

  static void printCmdHelp();

  bool parseUserCmd1(std::string& cmd);

  bool parseUserCmd2(std::string& cmd, std::string& arg1);

  bool parseUserCmd3(std::string& cmd, std::string& arg1, std::string& arg2);

  bool parseUserCmd(std::string& cmdLine);

  bool userCmdPrompt();;


  // TODO
   // bool uploadFile();
   // bool downloadFile();
   // bool deleteFile();
   // bool renameFile();
   // bool listFiles();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief         SafeCloud client object constructor, which initializes the IP and port of the
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
    * @throws ERR_STORE_INIT_FAILED           The X.509 certificate store could not be initialized
    * @throws ERR_STORE_ADD_CACERT_FAILED     Error in adding the CA certificate to the X.509 store
    * @throws ERR_STORE_ADD_CACRL_FAILED      Error in adding the CA CRL to the X.509 store
    * @throws ERR_STORE_REJECT_REVOKED_FAILED Error in configuring the X.509 store to reject revoked certificates
    */
   Client(char* srvIP, uint16_t srvPort);

   /**
    * @brief Client object destructor, which safely deletes its sensitive attributes
    */
   ~Client();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Starts the SafeCloud Client by:
    *          1) Asking the user to locally login within the application via its username and password
    *          2) Attempting to connect with the SafeCloud server
    *          3) Establishing a shared secret key via the STSM protocol
    *          4) Prompting and executing client's commands
    * @throws TODO
    */
   void start();

   /**
    * @brief Asynchronously instructs the client object to
    *        gracefully close the server connection and shut down
    */
   void shutdownSignal();

   /**
    * @brief  Returns whether the client is currently connected with the SafeCloud server
    * @return 'true' if connected, 'false' otherwise
    */
   bool isConnected() const;

   /**
    * @brief   Returns whether the client object is shutting down
    * @return 'true' if the client object is shutting down, 'false' otherwise
    */
   bool isShuttingDown() const;


   // TODO
   // void clientBody();
 };


#endif //SAFECLOUD_CLIENT_H
