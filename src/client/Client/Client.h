#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud Client Application Declaration */

/* ================================== INCLUDES ================================== */
#include "errCodes/execErrCodes/execErrCodes.h"
#include "SafeCloudApp/SafeCloudApp.h"
#include "CliConnMgr/CliConnMgr.h"

class Client : public SafeCloudApp
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* ---------------------------- General Information ---------------------------- */
   X509_STORE*        _certStore;         // The client's X.509 certificates store
   CliConnMgr*        _cliConnMgr;        // The client's connection manager object
   unsigned char      _remLoginAttempts;  // The remaining number of client's login attempts

   /* ------------------------ Client Personal Information ------------------------ */
   std::string _name;     // The client's username (unique in the SafeCloud application)
   std::string _downDir;  // The client's download directory
   std::string _tempDir;  // The client's temporary files directory

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
     * @brief Loads the CA X.509 certificate from its default
     *        ".pem" file (buildX509Store() utility function)
     * @throws ERR_CA_CERT_OPEN_FAILED  The CA Certificate file could not be opened
     * @throws ERR_CA_CERT_CLOSE_FAILED The CA Certificate file could not be closed
     * @throws ERR_CA_CERT_INVALID      The CA Certificate is invalid
     */
   static X509* getCACert();

   /**
     * @brief Loads the CA's certificate revocation list
     *        from its file (buildX509Store() utility function)
     * @throws ERR_CA_CRL_OPEN_FAILED  The CA CRL file could not be opened
     * @throws ERR_CA_CRL_CLOSE_FAILED The CA CRL file could not be closed
     * @throws ERR_CA_CRL_INVALID      The CA CRL is invalid
     */
   static X509_CRL* getCACRL();

   /**
     * @brief Builds the client's X.509 certificate store used for
     *        verifying the validity of the server's certificate
     * @throws ERR_CA_CERT_OPEN_FAILED     The CA Certificate file could not be opened
     * @throws ERR_CA_CERT_CLOSE_FAILED    The CA Certificate file could not be closed
     * @throws ERR_CA_CERT_INVALID         The CA Certificate is invalid
     * @throws ERR_CA_CRL_OPEN_FAILED      The CA CRL file could not be opened
     * @throws ERR_CA_CRL_CLOSE_FAILED     The CA CRL file could not be closed
     * @throws ERR_CA_CRL_INVALID          The CA CRL is invalid
     * @throws ERR_STORE_INIT_FAILED       The X.509 certificate store could not be initialized
     * @throws ERR_STORE_ADD_CACERT_FAILED Error in adding the CA certificate to the X.509 store
     * @throws ERR_STORE_ADD_CACRL_FAILED  Error in adding the CA CRL to the X.509 store
     * @throws ERR_STORE_REJECT_SET_FAILED Error in setting the X.509
     *                                     store to reject revoked certificates
     */
   void buildX509Store();

   /* -------------------- Client I/O Utility Methods Functions -------------------- */

   /**
    * @brief Prints the SafeCloud Client welcome message
    */
   static void printWelcomeMessage();

   /**
    * @brief Flushes carriage return and EOF characters from stdin
    */
   static void flush_CR_EOF();

   /**
    * @brief Reads the first non-carriage return character from stdin,
    *        flushing following carriage returns and 'EOF' characters
    * @return The the first non-carriage return character read from stdin
    */
   static int get1char();

   /**
    * @brief Reads a character representing a binary choice (y/Y or n/N) read
    *        from stdin, prompting the user until a valid character is provided
    * @return The y/Y or n/N character provided by the user
    */
   static int getYNChar();

   /**
    * @brief   Reads a character from stdin while temporarily disabling
    *          its echoing on stdout (getUserPwd() helper function)
    * @return  The character read from stdin
    */
   static signed char getchHide();

   /* ---------------------------- Client Login Methods ---------------------------- */

   /**
    * @brief Safely deletes all the user's sensitive information
    */
   void delUserInfo();

   /**
    * @brief  Client's login error handler, which deletes the client's personal
    *         information and decreases the number of remaining login attempts
    * @param  loginExcp The login-related execErrExcp
    * @throws ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
    */
   void loginError(execErrExcp& loginExcp);

   /**
    * @brief  Reads the user's password while concealing
    *         its characters (login() helper function)
    * @return The user-provided password
    */
   static std::string getUserPwd();

   /**
    * @brief  Attempts to locally authenticate the user by retrieving and
    *         decrypting its RSA long-term private key (login() helper function)
    * @param  username The candidate user name
    * @param  password The candidate user password
    * @throws ERR_LOGIN_PRIVKFILE_NOT_FOUND   The user RSA private key file was not found
    * @throws ERR_LOGIN_PRIVKFILE_OPEN_FAILED Error in opening the user's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED           Error in closing the user's RSA private key file
    * @throws ERR_LOGIN_PRIVK_INVALID         The contents of the user's private key file
    *                                         could not be interpreted as a valid RSA key pair
    */
   void getUserRSAKey(std::string& username,std::string& password);

   /**
    * @brief  Attempts to locally log-in a client within the SafeCloud application by prompting
    *         for its username and password, with the authentication consisting in successfully
    *         retrieving the user's long-term RSA key pair encrypted with such password stored
    *         in a ".pem" file with a predefined path function of the provided username
    * @throws ERR_LOGIN_NAME_EMPTY            Username is empty
    * @throws ERR_LOGIN_NAME_TOO_LONG         Username it too long
    * @throws ERR_LOGIN_NAME_WRONG_FORMAT     First non-alphabet character in the username
    * @throws ERR_LOGIN_NAME_INVALID_CHARS    Invalid characters in the username
    * @throws ERR_LOGIN_PWD_EMPTY             The user's password is empty
    * @throws ERR_LOGIN_PWD_TOO_LONG          The user's password is too long
    * @throws ERR_LOGIN_PRIVKFILE_NOT_FOUND   The user RSA private key file was not found
    * @throws ERR_LOGIN_PRIVKFILE_OPEN_FAILED Error in opening the user's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED           Error in closing the user's RSA private key file
    * @throws ERR_LOGIN_PRIVK_INVALID         The contents of the user's private key file
    *                                         could not be interpreted as a valid RSA key pair
    * @throws ERR_DOWNDIR_NOT_FOUND           The authenticated client's
    *                                         download directory was not found
    * @throws ERR_TMPDIR_NOT_FOUND            The authenticated client's
    *                                         temporary directory was not found
    */
   void login();

   /* ------------------------- Server Connection Methods ------------------------- */

   /**
    * @brief  Client's connection error handler, which resets the server's
    *         connection and, in case of non-fatal errors, prompt the
    *         user whether a reconnection attempt should be performed
    * @param  loginExcp The connection-related execErrExcp
    * @throws ERR_STSM_CLI_CLIENT_LOGIN_FAILED Server-side STSM client authentication
    *                                          failed (rethrown for it to be handled
    *                                          in the loginError() handler)
    */
   void connError(execErrExcp& connExcp);

   /**
    * @brief Attempts to establish a secure connection with the SafeCloud server by:\n\n
    *           1) Establishing a TCP connection with its IP:Port\n\n
    *           2) Creating the client's connection and STSM key establishment manager objects\n\n
    *           3) Performing the STSM key establishment protocol so to authenticate the
    *              client and server with one another and to establish a shared session key
    * @throws ERR_CSK_INIT_FAILED Connection socket creation failed
    * @throws ERR_SRV_UNREACHABLE Failed to connect with the SafeCloud server
    * @throws ERR_CSK_CONN_FAILED Fatal error in connecting with the SafeCloud server
    * @throws All the STSM exceptions and most of the OpenSSL
    *         exceptions (see "execErrCode.h" for more details)
    */
   void srvSecureConnect();

   /* ----------------------- User Session Commands Methods ----------------------- */

   /**
    * @brief Prints the indented metadata and name of
    *        all files in the user's download directory
    */
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
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void parseUserCmd1(std::string& cmd);

   /**
    * @brief  Parses and executes a user's input command consisting
    *         of 2 words (parseUserCmd() helper function)
    * @param  cmd  The command word
    * @param  arg1 The command word first argument
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void parseUserCmd2(std::string& cmd, std::string& arg1);

   /**
    * @brief  Parses and executes a user's input command consisting
    *         of 3 words (parseUserCmd() helper function)
    * @param  cmd  The command word
    * @param  arg1 The command word first argument
    * @param  arg2 The command word second argument
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void parseUserCmd3(std::string& cmd, std::string& arg1, std::string& arg2);

   /**
    * @brief  Parses a user's input command line and executes its associated
    *         SafeCloud command, if any (userCmdPrompt() helper function)
    * @param  cmdLine The user's input command line
    * @throws ERR_UNSUPPORTED_CMD Unsupported command
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void parseUserCmd(std::string& cmdLine);

   /**
    * @brief  User command prompt loop, reading
    *         and executing user session commands
    * @throws All session- and connection-related execution
    *         exceptions (see "execErrCode.h" for more details)
    */
   void userCmdPrompt();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  SafeCloud client object constructor, initializing the IP and port of the
    *         SafeCloud server to connect to and the client's X.509 certificates store
    * @param  srvIP   The IP address as a string of the SafeCloud server to connect to
    * @param  srvPort The port of the SafeCloud server to connect to
    * @throws ERR_INVALID_SRV_ADDR        Invalid IP address format
    * @throws ERR_INVALID_SRV_PORT        Invalid Port
    * @throws ERR_CA_CERT_OPEN_FAILED     The CA Certificate file could not be opened
    * @throws ERR_CA_CERT_CLOSE_FAILED    The CA Certificate file could not be closed
    * @throws ERR_CA_CERT_INVALID         The CA Certificate is invalid
    * @throws ERR_CA_CRL_OPEN_FAILED      The CA CRL file could not be opened
    * @throws ERR_CA_CRL_CLOSE_FAILED     The CA CRL file could not be closed
    * @throws ERR_CA_CRL_INVALID          The CA CRL is invalid
    * @throws ERR_STORE_INIT_FAILED       The X.509 certificate store could not be initialized
    * @throws ERR_STORE_ADD_CACERT_FAILED Error in adding the CA certificate to the X.509 store
    * @throws ERR_STORE_ADD_CACRL_FAILED  Error in adding the CA CRL to the X.509 store
    * @throws ERR_STORE_REJECT_SET_FAILED Error in configuring the X.509
    *                                     store to reject revoked certificates
    */
   Client(char* srvIP, uint16_t srvPort);

   /**
    * @brief SafeCloud client object destructor,
    *        safely deleting its sensitive attributes
    */
   ~Client();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Asks the user a yes-no question, continuously reading a character
    *         from stdin until a valid response is provided (y/Y or n/N)
    * @return 'true' if the user answers y/Y or 'false' if it answers 'n/N'
    */
   static bool askUser(const char* question);

   /**
    * @brief  Client object shutdown signal handler, returning, depending on whether it has
    *         requests pending, if it can be terminated directly or if it will autonomously
    *         terminate as soon as such requests will have been served
    * @return A boolean indicating whether the client object can be terminated immediately
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   bool shutdownSignalHandler();

   /**
    * @brief  Starts the SafeCloud Client by:\n\n
    *           1) Asking the user to locally login within the
    *              application via their username and password\n\n
    *           2) Attempting to connect with the SafeCloud server\n\n
    *           3) Establishing a shared secret key via the STSM protocol\n\n
    *           4) Prompting and executing client's commands\n
    * @throws ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
    */
   void start();
 };


#endif //SAFECLOUD_CLIENT_H