/* SafeCloud Application Client Implementation */

/* ================================== INCLUDES ================================== */
#include "Client.h"
#include "sanUtils.h"
#include <openssl/x509_vfy.h>
#include <arpa/inet.h>
#include <string>
#include <termios.h>

#include <unistd.h>
#include <vector>
#include <sstream>
#include <iterator>
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "DirInfo/DirInfo.h"
#include <bits/stdc++.h>

/* =============================== PRIVATE METHODS =============================== */

/* ------------------------ Client Object Initialization ------------------------ */

/**
 * @brief Sets the IP address and port of the SafeCloud server to connect to
 * @param srvIP   The SafeCloud server IP address
 * @param srvPort The SafeCloud server port
 * @throws ERR_SRV_ADDR_INVALID Invalid server IP address
 * @throws ERR_SRV_PORT_INVALID Invalid server port
 */
void Client::setSrvEndpoint(const char* srvIP, uint16_t& srvPort)
 {
  // Set the server socket type to IPv4
  _srvAddr.sin_family = AF_INET;

  // "srvIP" must consist of a valid IPv4 address, which can be ascertained
  // by converting its value from string to its network representation as:
  if(inet_pton(AF_INET, srvIP, &_srvAddr.sin_addr.s_addr) <= 0)
   THROW_EXEC_EXCP(ERR_SRV_ADDR_INVALID);

  // If srvPort >= SRV_PORT_MIN, convert it to the
  // network byte order within the "_srvAddr" structure
  if(srvPort >= SRV_PORT_MIN)
   _srvAddr.sin_port = htons(srvPort);

   // Otherwise, throw an exception
  else
   THROW_EXEC_EXCP(ERR_SRV_PORT_INVALID);

  // At this point the SafeCloud server IP and port parameters are valid
  LOG_DEBUG("SafeCloud server address set to "
            + std::string(srvIP) + ":" + std::to_string(srvPort))
 }


/**
 * @brief Loads the CA X.509 certificate from its default
 *        ".pem" file (buildX509Store() utility function)
 * @throws ERR_CA_CERT_OPEN_FAILED The CA certificate file could not be opened
 * @throws ERR_FILE_CLOSE_FAILED   The CA certificate file could not be closed
 * @throws ERR_CA_CERT_INVALID     The CA certificate is invalid
 */
X509* Client::getCACert()
 {
  FILE* CACertFile;   // CA Certificate file descriptor
  X509* CACert;       // CA X.509 Certificate

  // Attempt to open the CA certificate from its .pem file
  CACertFile = fopen(CLI_CA_CERT_PATH, "r");
  if(!CACertFile)
   THROW_EXEC_EXCP(ERR_CA_CERT_OPEN_FAILED, CLI_CA_CERT_PATH, ERRNO_DESC);

  // Read the X.509 CA certificate from its file
  CACert = PEM_read_X509(CACertFile, NULL, NULL, NULL);

  // Close the CA certificate file
  if(fclose(CACertFile) != 0)
   THROW_EXEC_EXCP(ERR_FILE_CLOSE_FAILED, CLI_CA_CERT_PATH, ERRNO_DESC);

  // Ensure the contents of the CA certificate
  // file to consist of a valid certificate
  if(!CACert)
   THROW_EXEC_EXCP(ERR_CA_CERT_INVALID, CLI_CA_CERT_PATH, OSSL_ERR_DESC);

  // At this point the CA certificate has been loaded successfully
  // and, in DEBUG_MODE, print its subject and issuer
#ifdef DEBUG_MODE
  std::string certSubject = X509_NAME_oneline(X509_get_subject_name(CACert), NULL, 0);
  LOG_DEBUG("CA certificate successfully loaded: " + certSubject)
#endif

  // Return the valid CA certificate
  return CACert;
 }


/**
 * @brief Loads the CA's certificate revocation list
 *        from its file (buildX509Store() utility function)
 * @throws ERR_CA_CRL_OPEN_FAILED  The CA CRL file could not be opened
 * @throws ERR_CA_CRL_CLOSE_FAILED The CA CRL file could not be closed
 * @throws ERR_CA_CRL_INVALID      The CA CRL is invalid
 */
X509_CRL* Client::getCACRL()
 {
  FILE*     CACRLFile;  // CA CRL file descriptor
  X509_CRL* CACRL;      // CA Certificate Revocation list

  // Attempt to open the CA CRL from its .pem file
  CACRLFile = fopen(CLI_CA_CRL_PATH, "r");
  if(!CACRLFile)
   THROW_EXEC_EXCP(ERR_CA_CRL_OPEN_FAILED, CLI_CA_CRL_PATH, ERRNO_DESC);

  // Read the CA X.509 CRL from its file
  CACRL = PEM_read_X509_CRL(CACRLFile, NULL, NULL, NULL);

  // Close the CA CRL file
  if(fclose(CACRLFile) != 0)
   THROW_EXEC_EXCP(ERR_FILE_CLOSE_FAILED, CLI_CA_CRL_PATH, ERRNO_DESC);

  // Ensure the contents of the CA CRL file to consist
  // of a valid X.509 certificate revocation list
  if(!CACRL)
   THROW_EXEC_EXCP(ERR_CA_CRL_INVALID, CLI_CA_CRL_PATH, OSSL_ERR_DESC);

  // At this point the CA CRL has been loaded successfully
  LOG_DEBUG("CA CRL successfully loaded")

  // Return the valid CA CRL
  return CACRL;
 }


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
 * @throws ERR_STORE_REJECT_SET_FAILED Error in configuring the X.509
 *                                     store to reject revoked certificates
 */
void Client::buildX509Store()
 {
  X509*       CACert;    // CA X.509 certificate
  X509_CRL*   CACRL;     // CA X.509 Certificate Revocation List

  // Load and validate the CA certificate from its .pem file
  CACert = getCACert();

  // Load and validate the CA CRL from its .pem file
  CACRL = getCACRL();

  // Initialize the client X.509 certificates store
  _certStore = X509_STORE_new();
  if(!_certStore)
   THROW_EXEC_EXCP(ERR_STORE_INIT_FAILED, OSSL_ERR_DESC);

  // Add the CA's certificate to the store
  if(X509_STORE_add_cert(_certStore, CACert) != 1)
   THROW_EXEC_EXCP(ERR_STORE_ADD_CACERT_FAILED, OSSL_ERR_DESC);

  // Add the CA's CRL to the store
  if(X509_STORE_add_crl(_certStore, CACRL) != 1)
   THROW_EXEC_EXCP(ERR_STORE_ADD_CACRL_FAILED, OSSL_ERR_DESC);

  // Configure the store NOT to accept certificates
  // that have been revoked in the CRL
  if(X509_STORE_set_flags(_certStore, X509_V_FLAG_CRL_CHECK) != 1)
   THROW_EXEC_EXCP(ERR_STORE_REJECT_SET_FAILED, OSSL_ERR_DESC);

  // At this point the client's certificate
  // store has been successfully initialized
  LOG_DEBUG("X.509 certificate store successfully initialized")
 }


/* -------------------- Client I/O Utility Methods Functions -------------------- */

/**
 * @brief Prints the SafeCloud Client welcome message
 */
void Client::printWelcomeMessage()
 {
  std::cout << "   _____        __      _____ _                 _ \n";
  std::cout << "  / ____|      / _|    / ____| |               | |\n";
  std::cout << " | (___   __ _| |_ ___| |    | | ___  _   _  __| |\n";
  std::cout << "  \\___ \\ / _` |  _/ _ \\ |    | |/ _ \\| | | |/ _` |\n";
  std::cout << "  ____) | (_| | ||  __/ |____| | (_) | |_| | (_| |\n";
  std::cout << " |_____/ \\__,_|_| \\___|\\_____|_|\\___/ \\__,_|\\__,_|" << std::endl;
 }


/**
 * @brief Flushes carriage return and EOF characters from stdin
 */
void Client::flush_CR_EOF()
 {
  // Flush carriage return and EOF characters from the input stream
  int c;

  do
   c = getchar();
  while ((c != '\n') && (c != EOF));
 }


/**
 * @brief Reads the first non-carriage return character from stdin,
 *        flushing following carriage returns and 'EOF' characters
 * @return The the first non-carriage return character read from stdin
 */
int Client::get1char()
 {
  int ret;  // First non-carriage return character in the stdin to return

  // Read the first non-carriage return from the
  // stdin, prompting user input if it is not present
  do
   ret = getchar();
  while (ret == '\n');

  // Flush carriage return and EOF characters from the input stream
  flush_CR_EOF();

  // Return the first non-carriage return character read from stdin
  return ret;
 }


/**
 * @brief Reads a character representing a binary choice (y/Y or n/N) read
 *        from stdin, prompting the user until a valid character is provided
 * @return The y/Y or n/N character provided by the user
 */
int Client::getYNChar()
 {
  int ret; // Character to return

  // Read the first character from stdin until a y/Y or n/N is provided
  do
   {
    ret = get1char();
    if((ret != 'Y') && (ret != 'N') && (ret != 'y') && (ret != 'n'))
     std::cout << "Please answer \"yes\" (y/Y) or \"no\" (n/N): ";
   } while((ret != 'Y') && (ret != 'N') && (ret != 'y') && (ret != 'n'));

  return ret;
 }


/**
 * @brief   Reads a character from stdin while temporarily disabling
 *          its echoing on stdout (getUserPwd() helper function)
 * @return  The character read from stdin
 */
signed char Client::getchHide()
 {
  // Used to temporarily change the terminal configuration
  struct termios t_old{}, t_new{};

  // Character read from terminal
  signed char ch;

  // Temporarily change the terminal
  // configuration so to not echo characters
  tcgetattr(STDIN_FILENO, &t_old);
  t_new = t_old;
  t_new.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

  // Read a character from stdin
  ch = static_cast<signed char>(getchar());

  // Restore the previous terminal configuration
  tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

  // Return the character that was read
  return ch;
 }


/* ---------------------------- Client Login Methods ---------------------------- */

/**
 * @brief Safely deletes all the user's sensitive information
 */
void Client::delUserInfo()
 {
  OPENSSL_cleanse(&_name[0], _name.size());
  OPENSSL_cleanse(&_downDir[0], _downDir.size());
  OPENSSL_cleanse(&_tempDir[0], _tempDir.size());
  EVP_PKEY_free(_rsaKey);
 }


/**
 * @brief  Client's login error handler, which deletes the client's personal
 *         information and decreases the number of remaining login attempts
 * @param  loginExcp The login-related execErrExcp
 * @throws ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
 */
void Client::loginError(execErrExcp& loginExcp)
 {
  // Safely delete all client's information
  delUserInfo();

  // In DEBUG_MODE always log the login exception in its entirety
#ifdef DEBUG_MODE
  handleExecErrException(loginExcp);
#else
  /*
   * In release mode only log in their entirety errors of CRITICAL
   * severity, while all others are concealed with a generic "wrong
   * username or password" error so to not provide information
   * whether a client with the provided username exists or not
   */
  if(loginExcp.exErrcode != ERR_FILE_CLOSE_FAILED && loginExcp.exErrcode
     != ERR_DOWNDIR_NOT_FOUND && loginExcp.exErrcode != ERR_DIR_OPEN_FAILED)
   {
    loginExcp.exErrcode = ERR_LOGIN_WRONG_NAME_OR_PWD;
    loginExcp.addDscr = nullptr;
    loginExcp.reason = nullptr;
   }
  handleExecErrException(loginExcp);
#endif

  // For non-FATAL errors, decrease the number of
  // client's login attempts and, if none is left
  if(--_remLoginAttempts == 0)
   {
    // Set the client as shutting down AND throw
    // that they have expired their login attempts
    /*
     * NOTE: Setting that the client is shutting down is
     *       more for semantics/error prevention purposes,
     *       as the ERR_CLI_LOGIN_FAILED execErrExcp is
     *       necessarily handled outside the start() method
     */
    _shutdown = true;
    THROW_EXEC_EXCP(ERR_CLI_LOGIN_FAILED);
   }
 }


/**
 * @brief  Reads the user's password while concealing
 *         its characters (login() helper function)
 * @return The user-provided password
 */
std::string Client::getUserPwd()
 {
  // Character errors
  const char BACKSPACE = 127;  // Backspace code
  const char RETURN = 10;      // Return code
  signed char ch;              // Password character index
  std::string password;        // The user password to be returned

  // Read characters without them being
  // echoed as the user does not press "enter"
  while((ch = getchHide()) != RETURN)
   {
    // If a backspace was read, remove the password's last character
    if(ch == BACKSPACE && password.length() != 0)
     {
      // For deleting an asterisk "*"
      // std::cout <<"\b \b";
      password.resize(password.length()-1);
     }

    // Otherwise append the new character into the password
    else
     {
      password += ch;
      // For printing an asterisk "*" instead of concealing the character
      // std::cout <<'*';
     }
   }

  // Print a newline and return the password
  std::cout << std::endl;
  return password;
 }


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
void Client::getUserRSAKey(std::string& username,std::string& password)
 {
  FILE* RSAKeyFile;     // The user's long-term RSA private key file (.pem)
  char* RSAKeyFilePath; // The user's long-term RSA private key file path

  // Derive the expected absolute, or canonicalized, path of the user's private key file
  RSAKeyFilePath = realpath(std::string(CLI_USER_PRIVK_PATH(username)).c_str(),NULL);
  if(!RSAKeyFilePath)
   THROW_EXEC_EXCP(ERR_LOGIN_PRIVKFILE_NOT_FOUND, CLI_USER_PRIVK_PATH(username), ERRNO_DESC);

  // Try-catch block to allow the RSAKeyFilePath
  // both to be freed and reported in case of errors
  try
   {
    // Attempt to open the user's RSA private key file
    RSAKeyFile = fopen(RSAKeyFilePath, "r");
    if(!RSAKeyFile)
     THROW_EXEC_EXCP(ERR_LOGIN_PRIVKFILE_OPEN_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Attempt to read the user's long-term RSA private key from its file
    _rsaKey = PEM_read_PrivateKey(RSAKeyFile, NULL, NULL, (void*)password.c_str());

    // Safely delete the user's password, as it is no longer required
    OPENSSL_cleanse(&password[0], password.size());

    // Close the RSA private key file
    if(fclose(RSAKeyFile) != 0)
     THROW_EXEC_EXCP(ERR_FILE_CLOSE_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Ensure that a valid private key has been read
    if(!_rsaKey)
      THROW_EXEC_EXCP(ERR_LOGIN_PRIVK_INVALID, RSAKeyFilePath, OSSL_ERR_DESC);

    // At this point, being the RSA private key valid,
    // the client has successfully locally authenticated
    LOG_DEBUG("Client long-term private key successfully loaded")

    // Free the RSA key file path
    free(RSAKeyFilePath);
   }
  catch(execErrExcp& excp)
   {
    // Free the RSA key file path
    free(RSAKeyFilePath);

    // Re-throw the exception
    throw;
   }
 }


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
void Client::login()
 {
  std::string username;  // The candidate client's name
  std::string password;  // The candidate client's password

  try
   {
    // Prompt for the client's name
    std::cout << "Username: ";
    std::getline(std::cin, username);
    LOG_DEBUG("User-provided name: \"" + username + "\"")

    // Prompt for the client's password, concealing its input characters
    std::cout << "Password: ";
    password = getUserPwd();
    LOG_DEBUG("User-provided password: \"" + password + "\"")

    // Sanitize the provided username
    sanitizeUsername(username);
    LOG_DEBUG("Sanitized username: \"" + username + "\"")

    // Ensure the password not to be empty
    if(password.empty())
     THROW_EXEC_EXCP(ERR_LOGIN_PWD_EMPTY);

    // Ensure the password to be at most "CLI_PWD_MAX_LENGTH" characters
    if(password.length() > CLI_PWD_MAX_LENGTH)
     THROW_EXEC_EXCP(ERR_LOGIN_PWD_TOO_LONG, password);

    // Attempt to locally authenticate the user by retrieving
    // and decrypting its RSA long-term private key
    getUserRSAKey(username, password);

    /*
     * At this point, being the RSA private key valid,
     * the client has successfully authenticated locally
     */

    // Set the client's name
    _name = username;

    // Set the client's download directory
    _downDir = realpath(std::string(CLI_USER_DOWN_PATH(username)).c_str(), NULL);
    if(_downDir.empty())
     THROW_EXEC_EXCP(ERR_DOWNDIR_NOT_FOUND, CLI_USER_DOWN_PATH(username), ERRNO_DESC);

    // Set the client's temporary files directory
    _tempDir = realpath(std::string(CLI_USER_TEMP_DIR_PATH(username)).c_str(), NULL);
    if(_tempDir.empty())
     THROW_EXEC_EXCP(ERR_DIR_OPEN_FAILED, CLI_USER_TEMP_DIR_PATH(username), ERRNO_DESC);

    LOG_DEBUG("User \"" + _name + "\" successfully logged in")
    LOG_DEBUG("Download directory: " + _downDir)
    LOG_DEBUG("Temporary directory " + _tempDir)
   }

  // In case of errors, safely delete the "username" and "password"
  // strings and re-throw the exception for its handling to continue
  // at the end of the client login() loop in the start() function
  catch(execErrExcp& excp)
    {
     OPENSSL_cleanse(&password[0], password.size());
     OPENSSL_cleanse(&username[0], username.size());
     throw;
    }
 }


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
void Client::connError(execErrExcp& connExcp)
 {
  // Reset the client's connection
  delete _cliConnMgr;
  _cliConnMgr = nullptr;
  _connected = false;

  // Change a ERR_PEER_DISCONNECTED into the more
  // specific ERR_SRV_DISCONNECTED error code
  if(connExcp.exErrcode == ERR_PEER_DISCONNECTED)
   connExcp.exErrcode = ERR_SRV_DISCONNECTED;

  // The special ERR_STSM_CLI_CLIENT_LOGIN_FAILED execErrCode (which as for
  // the current application's version should NEVER happen) requires the user
  // to log-in again, and must be handled in catch clause of the login loop
  if(connExcp.exErrcode == ERR_STSM_CLI_CLIENT_LOGIN_FAILED)
   throw;

  // Otherwise handle the exception via its default handler
  handleExecErrException(connExcp);

  // In case of non-FATAL errors and if the client is not already shutting
  // down, prompt the user whether a reconnection attempt with the
  // server should be performed (preserving its login information)
  if(!_shutdown)
   {
    bool connRetry = askUser("Do you want to attempt to reconnect with the server?");

    // If the client answered no, shut down the application, otherwise
    // restart the client's connection loop in the start() method
    if(!connRetry)
     _shutdown = true;
   }
 }


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
void Client::srvSecureConnect()
 {
  int csk;      // The connection socket towards the SafeCloud server
  int connRes;  // connect() operation result

  // Attempt to create a connection socket, with failure
  // to do so representing an unrecoverable error
  csk = socket(AF_INET, SOCK_STREAM, 0);
  if(csk == -1)
   THROW_EXEC_EXCP(ERR_CSK_INIT_FAILED, ERRNO_DESC);

// In DEBUG_MODE, log the TCP connection attempt
#ifdef DEBUG_MODE
  char srvIP[16];
  inet_ntop(AF_INET, &_srvAddr.sin_addr.s_addr, srvIP, INET_ADDRSTRLEN);
  LOG_DEBUG("Attempting to establish a TCP connection with the SafeCloud server at "
            + std::string(srvIP) + ":" + std::to_string(ntohs(_srvAddr.sin_port)) + "...")
#endif

  // Attempt to establish a connection with the SafeCloud server
  connRes = connect(csk, (const struct sockaddr*)&_srvAddr, sizeof(_srvAddr));

  // If the connection attempt failed, throw an exception depending
  // on the error's severity as for the 'errno' global variable
  if(connRes != 0)
   {
    // Recoverable connection errors
    if(errno == ECONNREFUSED || errno == ENETUNREACH || errno == ETIMEDOUT)
     THROW_EXEC_EXCP(ERR_SRV_UNREACHABLE, ERRNO_DESC);

    // All others are non-recoverable FATAL errors
    THROW_EXEC_EXCP(ERR_CSK_CONN_FAILED, ERRNO_DESC);
   }

  // Initialize the connection's manager
  _cliConnMgr = new CliConnMgr(csk,&_name,&_tempDir,&_downDir,_rsaKey,_certStore);

  // At this point the client has successfully connected with the server
  _connected = true;

  // Establish a shared session key with the server
  _cliConnMgr->startCliSTSM();

  // Log that a secure connection with the SafeCloud Server has been established
  LOG_INFO("Successfully established a secure connection with the SafeCloud Server")
 }


/* ----------------------- User Session Commands Methods ----------------------- */

/**
 * @brief Prints the indented metadata and name of
 *        all files in the user's download directory
 */
void Client::listDownloadDir()
 {
  // Build a snapshot of the contents of the user's download directory
  DirInfo downInfo(&_downDir);

  // Print the indented metadata and name of all
  // files in the user's download directory
  if(!downInfo.printDirContents())
   std::cout << "\nThe download directory is empty "
                "(\"" << _downDir << "\")\n" << std::endl;
 }


/**
 * @brief Prints the user command prompt contextual help
 */
void Client::printCmdHelp()
 {
  std::cout << "\nAvailable Commands" << std::endl;
  std::cout << "------------------" << std::endl;
  std::cout << "UP   filename                  - Uploads a file to your SafeCloud storage pool (< 4GB)" << std::endl;
  std::cout << "DOWN filename                  - Downloads a file from your SafeCloud storage pool into the download directory" << std::endl;
  std::cout << "DEL  filename                  - Deletes a file from your SafeCloud storage pool" << std::endl;
  std::cout << "REN  old_filename new_filename - Renames a file within your SafeCloud storage pool" << std::endl;
  std::cout << "LIST pool                      - List the files within your Safecloud storage pool" << std::endl;
  std::cout << "LIST local                     - List the files within your local download directory" << std::endl;
  std::cout << "HELP                           - Prints this list of available commands" << std::endl;
  std::cout << "LOGOUT/EXIT/QUIT/BYE           - Closes the application\n" << std::endl;
 }


/**
 * @brief  Parses and executes a user's input command consisting
 *         of 1 word (parseUserCmd() helper function)
 * @param  cmd The command word
 * @throws ERR_UNSUPPORTED_CMD Unsupported command
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void Client::parseUserCmd1(std::string& cmd)
 {
  // ---------------- 'HELP' Command ---------------- //
  if(cmd == "HELP" || cmd == "H")
   {
    // Print the command prompt contextual help
    printCmdHelp();
    return;
   }

  // --------------- 'LOGOUT' Command --------------- //
  if(cmd == "LOGOUT" || cmd == "EXIT" || cmd == "QUIT"
     || cmd == "CLOSE" || cmd == "BYE")
   {
    // Send the 'BYE' session message to the server
    _cliConnMgr->getSession()->closeSession();
    return;
   }

  // ------------- Unsupported Command ------------- //
  THROW_SESS_EXCP(ERR_UNSUPPORTED_CMD);
 }


/**
 * @brief  Parses and executes a user's input command consisting
 *         of 2 words (parseUserCmd() helper function)
 * @param  cmd  The command word
 * @param  arg1 The command word first argument
 * @throws ERR_UNSUPPORTED_CMD Unsupported command
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void Client::parseUserCmd2(std::string& cmd, std::string& arg1)
 {
  // ------------------------- 'UPLOAD' Command ------------------------- //
  if(cmd == "UP" || cmd == "UPLOAD")
   {
    // Attempt to upload the specified file to the SafeCloud storage pool
    _cliConnMgr->getSession()->uploadFile(arg1);

    // Reset the client session manager state
    _cliConnMgr->getSession()->resetSessState();

    return;
   }

  // ------------------------ 'DOWNLOAD' Command ------------------------ //
  if(cmd == "DOWN" || cmd == "DOWNLOAD")
   {
    // Attempt to download the specified file from the SafeCloud storage pool
    _cliConnMgr->getSession()->downloadFile(arg1);

    // Reset the client session manager state
    _cliConnMgr->getSession()->resetSessState();

    return;
   }

  // ------------------------- 'DELETE' Command ------------------------- //
  if(cmd == "DEL" || cmd == "DELETE")
   {
    // Attempt to delete the specified file from the SafeCloud storage pool
    _cliConnMgr->getSession()->deleteFile(arg1);

    // Reset the client session manager state
    _cliConnMgr->getSession()->resetSessState();

    return;
   }

  /* ------------------------- 'LIST dest' Command ------------------------- */
  if(cmd == "LIST")
   {
    // Convert the LIST argument to lower case
    transform(arg1.begin(), arg1.end(), arg1.begin(), ::tolower);

    // ----------------------- 'LIST local' Command ----------------------- //
    if(arg1 == "local" || arg1 == "down"|| arg1 == "download")

     // List the files in the user's download directory
     listDownloadDir();

    else

     // ----------------------- 'LIST pool' Command ----------------------- //
     if(arg1 == "pool" || arg1 == "remote" || arg1 == "storage")
      {
       // List the files in the SafeCloud storage pool
       _cliConnMgr->getSession()->listPoolFiles();

       // Reset the client session manager state
       _cliConnMgr->getSession()->resetSessState();
      }

      // ---------------------- Unsupported Command ---------------------- //
     else
      THROW_SESS_EXCP(ERR_UNSUPPORTED_CMD);

    return;
   }

  // ----------------------- Unsupported Command ----------------------- //
  THROW_SESS_EXCP(ERR_UNSUPPORTED_CMD);
 }


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
void Client::parseUserCmd3(std::string& cmd, std::string& arg1, std::string& arg2)
 {
  // ------------------------- 'RENAME' Command ------------------------- //
  if(cmd == "RENAME" || cmd == "REN")
   {
    // Attempt to rename the "arg1" file on SafeCloud storage pool to "arg2"
    _cliConnMgr->getSession()->renameFile(arg1, arg2);

    // Reset the client session manager state
    _cliConnMgr->getSession()->resetSessState();

    return;
   }

  // ----------------------- Unsupported Command ----------------------- //
  THROW_SESS_EXCP(ERR_UNSUPPORTED_CMD);
 }


/**
 * @brief  Parses a user's input command line and executes its associated
 *         SafeCloud command, if any (userCmdPrompt() helper function)
 * @param  cmdLine The user's input command line
 * @throws ERR_UNSUPPORTED_CMD Unsupported command
 * @throws Most of the session and OpenSSL exceptions (see
 *         "execErrCode.h" and "sessErrCodes.h" for more details)
 */
void Client::parseUserCmd(std::string& cmdLine)
 {
  // Initialize an input string stream to the contents of the user's command line
  std::istringstream cmdStringStream(cmdLine);

  // Create a string vector and initialize it to the words of the user's command line
  std::vector<std::string> cmdLineWords{std::istream_iterator<std::string>{cmdStringStream}, std::istream_iterator<std::string>{}};

  // Number of words in the user's command line
  size_t numCmdLineWords = cmdLineWords.size();

  // If the user provided an empty string, just return so to print again the command prompt
  if(numCmdLineWords == 0)
   return;

  // Otherwise, convert the first word in the command line to upper case
  transform(cmdLineWords[0].begin(), cmdLineWords[0].end(), cmdLineWords[0].begin(), ::toupper);

  // Parse the command line depending on its number of words
  switch(numCmdLineWords)
   {
    case 1:
     parseUserCmd1(cmdLineWords[0]);
     return;

    case 2:
     parseUserCmd2(cmdLineWords[0], cmdLineWords[1]);
     return;

    case 3:
     parseUserCmd3(cmdLineWords[0], cmdLineWords[1], cmdLineWords[2]);
     return;

    // Currently commands up to 3 words are supported
    default:
     THROW_SESS_EXCP(ERR_UNSUPPORTED_CMD);
   }
 }


/**
 * @brief  User command prompt loop, reading
 *         and executing user session commands
 * @throws All session- and connection-related execution
 *         exceptions (see "execErrCode.h" for more details)
 */
void Client::userCmdPrompt()
 {
  // The user's input command line, comprised in general of multiple words
  std::string cmdLine;

  // Whether the client connection manager should be closed
  bool closeConn;

  // Command prompt contextual help suggestion
  std::cout << "Type \"help\" for the list of available commands\n" << std::endl;

  // ----------------------- User Command Prompt Loop ----------------------- //

  do
   {
    try
     {
      // Print the command prompt
      std::cout << "> ";

      // Read the user command line
      getline(std::cin, cmdLine);

      // Parse the user command line and execute
      // the associated SafeCloud command
      parseUserCmd(cmdLine);

      // Read whether the client connection
      // manager should be closed
      closeConn = _cliConnMgr->shutdownConn();

      // If the client connection manager should
      // not be closed, but a shutdown signal was received
      if(!closeConn && _shutdown)
       {
        // Close the session with the server by
        // sending the 'BYE' session signaling message
        _cliConnMgr->getSession()->closeSession();

        // Terminate the client application
        return;
       }

      // Otherwise 'OR' the Client object's shutdown
      // flag with the one of the CliConnMgr
      else
       _shutdown = _shutdown || _cliConnMgr->shutdownConn();
     }
    catch(sessErrExcp& sessErrExcp)
     {
      // In case an unsupported command was provided, "gently" inform the user
      // that they can print the list of available commands via the "HELP" command
      if(sessErrExcp.sesErrCode == ERR_UNSUPPORTED_CMD)
       { std::cout << "Unsupported command (type \"HELP\" for"
                      "the list of available commands) " << std::endl; }

      // Otherwise handle the recoverable session exception via its default handler
      else
       {
        // Handle the session error exception
        handleSessErrException(sessErrExcp);

        // Reset the session manager state
        _cliConnMgr->getSession()->resetSessState();
       }
     }
   } while(!_shutdown); // While the application should not terminate

  // --------------------- End User Command Prompt Loop --------------------- //
 }


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
Client::Client(char* srvIP, uint16_t srvPort)
 : SafeCloudApp(), _certStore(nullptr), _cliConnMgr(nullptr),
   _remLoginAttempts(CLI_MAX_LOGIN_ATTEMPTS), _name(), _downDir(), _tempDir()
 {
  // Attempt to set up the server endpoint parameters
  setSrvEndpoint(srvIP, srvPort);

  // Attempt to build the client's X.509 certificates
  // store loaded with the CA's certificate and CRL
  buildX509Store();
 }


/**
 * @brief SafeCloud client object destructor,
 *        safely deleting its sensitive attributes
 */
Client::~Client()
 {
  // Safely delete the cliConnMgr object
  delete _cliConnMgr;

  // Safely delete all client's information
  delUserInfo();

  // Free the client's X.509 certificates store
  X509_STORE_free(_certStore);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Asks the user a yes-no question, continuously reading a character
 *         from stdin until a valid response is provided (y/Y or n/N)
 * @return 'true' if the user answers y/Y or 'false' if it answers 'n/N'
 */
bool Client::askUser(const char* question)
 {
  // Ask the user the question
  std::cout << question << " (Y/N): ";

  // Read the user's y/N or n/N answer
  int userAnswer = getYNChar();

  // Return true or false depending on the user's answer
  if((userAnswer == 'Y') || (userAnswer == 'y'))
   return true;
  return false;
 }


// TODO

/**
 * @brief Asynchronously instructs the client object to
 *        gracefully close the server connection and terminate
 */

bool Client::shutdownSignalHandler()
 {
  // If the client is not connected with the
  // SafeCloud server, it can be shut down directly
  if(!_connected)
   return true;

  // If the client connection manager is the
  // session phase in the 'IDLE' operation
  if(_cliConnMgr != nullptr && _cliConnMgr->isInSessionPhase()
     && _cliConnMgr->getSession()->isIdle())
   {
    // Close the session with the server by
    // sending the 'BYE' session signaling message
    _cliConnMgr->getSession()->closeSession();

    // Return that the client application
    // can be shut down directly
    return true;
   }

  // Otherwise set the '_shutdown' flag and return that the
  // client application will shut down as soon as possible
  _shutdown = true;
  return false;
 }


/**
 * @brief  Starts the SafeCloud Client by:\n
 *           1) Asking the user to locally login within the
 *              application via their username and password\n
 *           2) Attempting to connect with the SafeCloud server\n
 *           3) Establishing a shared secret key via the STSM protocol\n
 *           4) Prompting and executing client's commands\n
 * @throws ERR_CLI_LOGIN_FAILED Maximum number of login attempts reached
 */
void Client::start()
 {
  // Print the SafeCloud client welcome message
  printWelcomeMessage();

  // Print the user login header
  std::cout << "\nLOGIN" << std::endl;
  std::cout << "-----" << std::endl;

  // --------------------------  1) Client Login Loop -------------------------- //
  do
   {
    try
     {
      // Attempt to log in the user in the application
      login();

      // ----------------------  2) Server Connection Loop ---------------------- //
      do
       {
        try
         {
          // Attempt to establish a secure connection with the SafeCloud server
          srvSecureConnect();

          // With the secure connection in the session phase,
          // prompt and execute user session commands
          userCmdPrompt();
         }

        // Connection error handler
        catch(execErrExcp& connExcp)
         { connError(connExcp); }

       } while(!_shutdown);

      // ----------------------  2- Server Connection Loop ---------------------- //
     }

    // Login error handler
    catch(execErrExcp& loginExcp)
     { loginError(loginExcp); }
   } while(!_shutdown);

  // --------------------------  1- Client Login Loop -------------------------- //

  /*
   * Execution reaching here implies that the
   * SafeCloud client has terminated successfully
   */
 }