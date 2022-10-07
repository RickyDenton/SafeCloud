#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud Application Client */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <netinet/in.h>
#include "CliConnMgr/CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
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
    * @param loginExcp The login-related execErrExcp
    * @throws          ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
    */
   void loginError(execErrExcp& loginExcp);

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
    * @param loginExcp The connection-related execErrExcp
    * @throws          ERR_SRV_LOGIN_FAILED Server-side client authentication failed (rethrown
    *                                       for it to be handled in the loginError() handler)
    */
   void connError(execErrExcp& connExcp);


   /**
    * @brief Attempts to establish a secure connection with the SafeCloud server by:
    *           1) Establishing a TCP connection with its IP:Port
    *           2) Creating the client's connection and STSM key establishment manager objects
    *           3) Performing the STSM key establishment protocol so to authenticate the
    *              client and server with one another and to establish a shared session key
    * @throws ERR_CSK_INIT_FAILED Connection socket creation failed
    * @throws ERR_SRV_UNREACHABLE Failed to connect with the SafeCloud server
    * @throws ERR_CSK_CONN_FAILED Fatal error in connecting with the SafeCloud server
    * @throws All the STSM exceptions and most of the OpenSSL
    *         exceptions (see "execErrCode.h" for more details)
    */
   void srvSecureConnect();

   /* -------------------------- Client Session Commands -------------------------- */

   // TODO
   void listDownloadDir();

   /**
    * @brief Prints the user command prompt contextual help
    */
   static void printCmdHelp();

   /**
    * @brief  Parses and executes a user's input command consisting
    *         of 1 word (parseUserCmd() helper function)
    * @param  cmd The command word
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    */
   void parseUserCmd1(std::string& cmd);

   /**
    * @brief  Parses and executes a user's input command consisting
    *         of 2 words (parseUserCmd() helper function)
    * @param  cmd  The command word
    * @param  arg1 The command word first argument
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    */
   void parseUserCmd2(std::string& cmd, std::string& arg1);

   /**
    * @brief  Parses and executes a user's input command consisting
    *         of 3 words (parseUserCmd() helper function)
    * @param  cmd  The command word
    * @param  arg1 The command word first argument
    * @param  arg2 The command word second argument
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    */
   void parseUserCmd3(std::string& cmd, std::string& arg1, std::string& arg2);

   /**
    * @brief  Parses a user's input command line and executes its associated
    *         SafeCloud command, if any (userCmdPrompt() helper function)
    * @param  cmdLine The user's input command line
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    */
   void parseUserCmd(std::string& cmdLine);

   /**
    * @brief User command prompt loop, reading and executing user session commands
    * @throws TODO (exec exceptions)
    */
   void userCmdPrompt();

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
 };


#endif //SAFECLOUD_CLIENT_H
