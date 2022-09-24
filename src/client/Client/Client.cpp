/* SafeCloud Application Client Implementation*/

/* ================================== INCLUDES ================================== */
#include "Client.h"
#include "utils.h"
#include <openssl/x509_vfy.h>
#include <arpa/inet.h>
#include <string>
#include <termios.h>

#include <unistd.h>
#include "errlog.h"
#include "../client_utils.h"

/* =============================== PRIVATE METHODS =============================== */

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
   THROW_SCODE(ERR_SRV_ADDR_INVALID);

  // If srvPort >= SRV_PORT_MIN, convert it to the network byte order within the "_srvAddr" structure
  if(srvPort >= SRV_PORT_MIN)
   _srvAddr.sin_port = htons(srvPort);
  else   // Otherwise, throw an exception
   THROW_SCODE(ERR_SRV_PORT_INVALID);

  // At this point the SafeCloud server IP and port parameters are valid
  LOG_DEBUG("SafeCloud server address set to " + std::string(srvIP) + ":" + std::to_string(srvPort))
 }


/* ======================== X.509 CERTIFICATES STORE INITIALIZATION ======================== */

/**
 * @brief Loads the CA X.509 certificate from its default ".pem" file (buildX509Store() utility function)
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
   THROW_SCODE(ERR_CA_CERT_OPEN_FAILED,CLI_CA_CERT_PATH,ERRNO_DESC);

  // Read the X.509 CA certificate from its file
  CACert = PEM_read_X509(CACertFile, NULL, NULL, NULL);

  // Close the CA certificate file
  if(fclose(CACertFile) != 0)
   THROW_SCODE(ERR_FILE_CLOSE_FAILED,CLI_CA_CERT_PATH,ERRNO_DESC);

  // Ensure the contents of the CA certificate file to consist of a valid certificate
  if(!CACert)
   THROW_SCODE(ERR_CA_CERT_INVALID,CLI_CA_CERT_PATH,OSSL_ERR_DESC);

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
 * @brief Loads the CA's certificate revocation list from its file (buildX509Store() utility function)
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
   THROW_SCODE(ERR_CA_CRL_OPEN_FAILED,CLI_CA_CRL_PATH,ERRNO_DESC);

  // Read the CA X.509 CRL from its file
  CACRL = PEM_read_X509_CRL(CACRLFile, NULL, NULL, NULL);

  // Close the CA CRL file
  if(fclose(CACRLFile) != 0)
   THROW_SCODE(ERR_FILE_CLOSE_FAILED,CLI_CA_CRL_PATH,ERRNO_DESC);

  // Ensure the contents of the CA CRL file to consist of a valid X.509 certificate revocation list
  if(!CACRL)
   THROW_SCODE(ERR_CA_CRL_INVALID,CLI_CA_CRL_PATH,OSSL_ERR_DESC);

  // At this point the CA CRL has been loaded successfully
  LOG_DEBUG("CA CRL successfully loaded")

  // Return the valid CA CRL
  return CACRL;
 }


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
   THROW_SCODE(ERR_STORE_INIT_FAILED, OSSL_ERR_DESC);

  // Add the CA's certificate to the store
  if(X509_STORE_add_cert(_certStore, CACert) != 1)
   THROW_SCODE(ERR_STORE_ADD_CACERT_FAILED, OSSL_ERR_DESC);

  // Add the CA's CRL to the store
  if(X509_STORE_add_crl(_certStore, CACRL) != 1)
   THROW_SCODE(ERR_STORE_ADD_CACRL_FAILED, OSSL_ERR_DESC);

  // Configure the store NOT to accept certificates that have been revoked in the CRL
  if(X509_STORE_set_flags(_certStore, X509_V_FLAG_CRL_CHECK) != 1)
   THROW_SCODE(ERR_STORE_REJECT_REVOKED_FAILED, OSSL_ERR_DESC);

  // At this point the client's certificate store has been successfully initialized
  LOG_DEBUG("X.509 certificate store successfully initialized")
 }


/* ================================ CLIENT LOGIN UTILITIES ================================ */


/**
 * @brief   Reads a character from stdin while temporarily disabling
 *          its echoing on stdout (getUserPwd() helper function)
 * @return  The character read from stdin
 */
signed char Client::getchHide()
 {
  struct termios t_old{}, t_new{}; // Used to temporarily change the terminal configuration
  signed char ch;                  // Character read from terminal

  // Temporarily change the terminal configuration so to not echo characters
  tcgetattr(STDIN_FILENO, &t_old);
  t_new = t_old;
  t_new.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

  // Read a character from stdin
  // TODO: Check the static cast to be correct
  ch = static_cast<signed char>(getchar());

  // Restore the previous terminal configuration
  tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

  // Return the character that was read
  return ch;
 }


/**
 * @brief  Reads the user's password while concealing its characters(login() helper function)
 * @return The user-provided password
 */
std::string Client::getUserPwd()
 {
  // Character codes
  const char BACKSPACE = 127;  // Backspace code
  const char RETURN = 10;      // Return code
  signed char ch;              // Password character index
  std::string password;        // The user password to be returned

  // Read characters without them being echoed as the user does not press "enter"
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
 * @brief                                  Attempts to locally authenticate the user by retrieving and decrypting
 *                                         its RSA long-term private key (login() helper function)
 * @param username                         The candidate user name
 * @param password                         The candidate user password
 * @throws ERR_LOGIN_PRIVKFILE_NOT_FOUND   The user RSA private key file was not found
 * @throws ERR_LOGIN_PRIVKFILE_OPEN_FAILED Error in opening the user's RSA private key file
 * @throws ERR_FILE_CLOSE_FAILED           Error in closing the user's RSA private key file
 * @throws ERR_LOGIN_PRIVK_INVALID         The contents of the user's private key file could not be interpreted as a valid RSA key pair
 */
void Client::getUserRSAKey(std::string& username,std::string& password)
 {
  FILE* RSAKeyFile;     // The user's long-term RSA private key file (.pem)
  char* RSAKeyFilePath; // The user's long-term RSA private key file path

  // Derive the expected absolute, or canonicalized, path of the user's private key file
  RSAKeyFilePath = realpath(std::string(CLI_USER_PRIVK_PATH(username)).c_str(),NULL);
  if(!RSAKeyFilePath)
   THROW_SCODE(ERR_LOGIN_PRIVKFILE_NOT_FOUND,CLI_USER_PRIVK_PATH(username),ERRNO_DESC);

  // Try-catch block to allow the RSAKeyFilePath both to be freed and reported in an exception
  try
   {
    // Attempt to open the user's RSA private key file
    RSAKeyFile = fopen(RSAKeyFilePath, "r");
    if(!RSAKeyFile)
     THROW_SCODE(ERR_LOGIN_PRIVKFILE_OPEN_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Attempt to read the user's long-term RSA private key from its file
    _rsaKey = PEM_read_PrivateKey(RSAKeyFile, NULL, NULL, (void*)password.c_str());

    // Safely delete the user's password, as it is no longer required
    OPENSSL_cleanse(&password[0], password.size());

    // Close the RSA private key file
    if(fclose(RSAKeyFile) != 0)
     THROW_SCODE(ERR_FILE_CLOSE_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Ensure that a valid private key has been read
    if(!_rsaKey)
      THROW_SCODE(ERR_LOGIN_PRIVK_INVALID, RSAKeyFilePath, OSSL_ERR_DESC);

    // At this point, being the RSA private key valid,
    // the client has successfully locally authenticated
    LOG_DEBUG("Client long-term private key successfully loaded")

    // Free the RSA key file path
    free(RSAKeyFilePath);
   }
  catch(sCodeException& excp)
   {
    // Free the RSA key file path
    free(RSAKeyFilePath);

    // Re-throw the exception
    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief         SafeCloud client object constructor, which initializes the IP and port of
 *                the SafeCloud server to connect to and the client's X.509 certificates store
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
Client::Client(char* srvIP, uint16_t srvPort) : _srvAddr(), _certStore(nullptr), _cliConnMgr(nullptr), _name(), _downDir(),
                                                _tempDir(), _rsaKey(nullptr), _loggedIn(false), _connected(false), _shutdown(false)
 {
  // Attempt to set up the server endpoint parameters
  setSrvEndpoint(srvIP, srvPort);

  // Attempt to build the client's X.509 certificates
  // store loaded with the CA's certificate and CRL
  buildX509Store();
 }


/**
 * @brief SafeCloud client object destructor, which safely deletes its sensitive attributes
 */
Client::~Client()
 {
  // Safely delete the cliConnMgr object
  delete _cliConnMgr;

  // Safely delete the client's cryptographic data
  EVP_PKEY_free(_rsaKey);
  X509_STORE_free(_certStore);

  // Safely delete the client name and directory paths
  OPENSSL_cleanse(&_name[0], _name.size());
  OPENSSL_cleanse(&_downDir[0], _downDir.size());
  OPENSSL_cleanse(&_tempDir[0], _tempDir.size());
 }


/* ============================ OTHER PUBLIC METHODS ============================ */


// TODO: Check everything back
int Client::srvConnect()
 {
  // If not connected, bla bla bla

  /* ---------------------- Local Variables ---------------------- */
  int connRes;    // Stores the server connection establishment result
  int csk;


  // Attempt to create a connection socket
  csk = socket(AF_INET, SOCK_STREAM, 0);
  if(csk == -1)
   THROW_SCODE(ERR_CSK_INIT_FAILED, strerror(errno));

  LOG_DEBUG("Connection socket file descriptor: " + std::to_string(csk))

  //cout << "Attempting to connect with SafeCloud server at " << srvIP << ":" << ntohs(srvAddr.sin_port) << "..." << endl;

  // Server connection attempt (which for recoverable errors can be repeated on user's discretion)
  do
   {
    connRes = connect(csk, (const struct sockaddr*)&_srvAddr, sizeof(_srvAddr));

    // If a connection could not be established
    if(connRes != 0)
     {
      // Log the connection error as for the ERRNO variable
      switch(errno)
       {
        /* These represent recoverable errors, which prompt the user whether to retry the connection */
        case ECONNREFUSED:
         LOG_WARNING("Connection refused from remote host (probably the SafeCloud server is not running)")
        break;

        case ENETUNREACH:
         LOG_ERROR("Network is unreachable")
        break;

        case ETIMEDOUT:
         LOG_ERROR("Server timeout in accepting the connection")
        break;

        /* Others are non-recoverable errors, with the client application that should be terminated */
        default:
         LOG_SCODE(ERR_CSK_CONN_FAILED, ERRNO_DESC);
       }

      // In case of recoverable errors, ask the user whether another connection
      // attempt should be performed, closing the client application if it should not
      if(!askReconnection())
       return -1; // RETURN FALSE?

     } // if(!connRes)

   } while(connRes != 0);

  // At this point, connection with the server was established successfully
  // cout << "Successfully connected with SafeCloud server at " << srvIP << ":" << to_string(ntohs(srvAddr.sin_port)) << endl;
  return csk;
 }



/**
 * @brief Attempts to locally authenticate a client within the SafeCloud application by prompting
 *        for its username and password, authentication consisting in successfully retrieving the
 *        user's long-term RSA key pair encrypted with such password stored in a ".pem" file with
 *        a predefined path function of the provided username
 * @return 'true' if the client successfully logged in or 'false' otherwise
 * @throws ERR_CLIENT_ALREADY_CONNECTED The client is already connected with the SafeCloud server
 * @throws ERR_CLIENT_ALREADY_LOGGED_IN The client is already logged in within the SafeCloud application
 */
bool Client::login()
 {
  uint8_t remLoginAttempts = CLI_MAX_AUTH_ATTEMPTS; // Maximum login attempts
  std::string username;                             // The candidate client's name
  std::string password;                             // The candidate client's password

  // Ensure that the client is neither connected nor logged-in
  if(_connected)
   THROW_SCODE(ERR_CLIENT_ALREADY_CONNECTED);
  if(_loggedIn)
   THROW_SCODE(ERR_CLIENT_ALREADY_LOGGED_IN);

  // Print the login header
  std::cout << "\nLogin" << std::endl;
  std::cout << "-----" << std::endl;

  while(remLoginAttempts > 0)
   {
    try
     {
      // Retrieve the client's username
      std::cout << "Username: ";
      std::getline(std::cin,username);
      LOG_DEBUG("User-provided name: \"" + username + "\"")

      // Retrieve the client's password, hiding the user's input characters
      std::cout << "Password: ";
      password = getUserPwd();
      LOG_DEBUG("User-provided password: \"" + password + "\"")

      // Sanitize the provided username
      sanitizeUsername(username);
      LOG_DEBUG("Sanitized username: \"" + username + "\"")

      // Ensure the password not to be empty
      if(password.empty())
       THROW_SCODE(ERR_LOGIN_PWD_EMPTY);

      // Ensure the password to be at most "CLI_PWD_MAX_LENGTH" characters
      if(password.length() > CLI_PWD_MAX_LENGTH)
       THROW_SCODE(ERR_LOGIN_PWD_TOO_LONG, password);

      // Attempt to locally authenticate the user by retrieving
      // and decrypting its RSA long-term private key
      getUserRSAKey(username, password);

      /* At this point, being the RSA private key valid, the client has successfully authenticated locally */

      // Set the client's name
      _name = username;

      // Set the client's download directory
      _downDir = realpath(std::string(CLI_USER_DOWN_PATH(username)).c_str(),NULL);
      if(_downDir.empty())
       THROW_SCODE(ERR_DOWNDIR_NOT_FOUND,CLI_USER_DOWN_PATH(username),ERRNO_DESC);

      // Set the client's temporary files directory
      _tempDir = realpath(std::string(CLI_USER_TEMP_DIR_PATH(username)).c_str(),NULL);
      if(_tempDir.empty())
       THROW_SCODE(ERR_TMPDIR_NOT_FOUND,CLI_USER_TEMP_DIR_PATH(username),ERRNO_DESC);

      LOG_DEBUG("User \"" + _name + "\" successfully logged in")
      LOG_DEBUG("Download directory: " + _downDir)
      LOG_DEBUG("Temporary directory " + _tempDir)

      // Set the user as logged in and return the success of the operation
      _loggedIn = true;
      return true;
     }
    catch(sCodeException& excp)
     {
      // In case of errors, safely delete the client's personal information
      OPENSSL_cleanse(&password[0], password.size());
      OPENSSL_cleanse(&username[0], username.size());
      OPENSSL_cleanse(&_name[0], _name.size());
      OPENSSL_cleanse(&_downDir[0], _downDir.size());
      OPENSSL_cleanse(&_tempDir[0], _tempDir.size());
      EVP_PKEY_free(_rsaKey);

      // In DEBUG_MODE always log the exception in its entirety
#ifdef DEBUG_MODE
      handleScodeException(excp);
#else
      // In release mode only log in their entirety errors of CRITICAL severity, while all
      // others are concealed with a generic "wrong username or password" error so to not
      // provide information whether a client with the provided username exists or not
      if(excp.scode != ERR_FILE_CLOSE_FAILED && excp.scode != ERR_DOWNDIR_NOT_FOUND && excp.scode != ERR_TMPDIR_NOT_FOUND)
       {
        excp.scode = ERR_LOGIN_WRONG_NAME_OR_PWD;
        excp.addDscr = "";
        excp.reason = "";
       }
      handleScodeException(excp);
#endif

      // Decrement the remaining number of client authentication attempts
      remLoginAttempts--;
     }
   } // while(remLoginAttempts > 0)

  // If the client has exhausted their login attempts, print
  // an error and return that the login was unsuccessful
  LOG_ERROR("Maximum number of login attempts reached, please try again later")
  return false;
 }


/**
 * @brief Asynchronously instructs the client object to
 *        gracefully close the server connection and terminate
 */
void Client::shutdownSignal()
 { _shutdown = true; }


/**
 * @brief  Returns whether the client is locally logged in within the SafeCloud application
 * @return 'true' if logged in, 'false' otherwise
 */
bool Client::isLoggedIn()
 { return _loggedIn; }


/**
 * @brief  Returns whether the client is currently connected with the SafeCloud server
 * @return 'true' if connected, 'false' otherwise
 */
bool Client::isConnected()
 { return _connected; }


/**
 * @brief   Returns whether the client object has been instructed
 *          to gracefully close all connections and terminate
 * @return 'true' if the client object is shutting down, 'false' otherwise
 */
bool Client::isShuttingDown()
 { return _shutdown; }

// TODO:
// bool srvConnect();
// bool uploadFile();
// bool downloadFile();
// bool deleteFile();
// bool renameFile();
// bool listFiles();


/**
 * @brief         Attempts to establish a connection with the SafeCloud server, prompting the user on whether
 *                to retry the connection in case of recoverable errors (ECONNREFUSED, ENETUNREACH, ETIMEDOUT)
 */
//void serverConnect()
// {
//  /* ---------------------- Local Variables ---------------------- */
//  char srvIP[16]; // The server IP address (logging purposes)
//  int connRes;    // Stores the server connection establishment result
//
//
//  // Convert the server IP address from network to string representation for logging purposes
//  inet_ntop(AF_INET, &srvAddr.sin_addr.s_addr, srvIP, INET_ADDRSTRLEN);
//
//  /* ----------------------- Function Body ----------------------- */
//
//  // Attempt to create a connection socket
//  csk = socket(AF_INET, SOCK_STREAM, 0);
//  if(csk == -1)
//   {
//    LOG_CODE_DSCR_FATAL(ERR_CSK_INIT_FAILED, strerror(errno))
//    exit(EXIT_FAILURE);
//   }
//
//  LOG_DEBUG("Connection socket file descriptor: " + to_string(csk))
//
//  // Server connection attempt (which for recoverable errors can be repeated on user's discretion)
//  do
//   {
//    LOG_DEBUG("Attempting to connect with SafeCloud server at " + string(srvIP) + ":" + to_string(ntohs(srvAddr.sin_port)) + "...")
//
//    connRes = connect(csk, (const struct sockaddr*)&srvAddr, sizeof(srvAddr));
//
//    // If a connection could not be established
//    if(connRes != 0)
//     {
//      // Log the connection error as for the ERRNO variable
//      switch(errno)
//       {
//        /* These represent recoverable errors, which prompt the user whether to retry the connection */
//        case ECONNREFUSED:
//         LOG_WARNING("Connection refused from remote host (probably the SafeCloud server is not running)")
//        break;
//
//        case ENETUNREACH:
//         LOG_ERROR("Network is unreachable")
//        break;
//
//        case ETIMEDOUT:
//         LOG_ERROR("Server timeout in accepting the connection")
//        break;
//
//        /* Others are non-recoverable errors, with the client application that should be terminated */
//        default:
//         LOG_CODE_DSCR_FATAL(ERR_CSK_CONN_FAILED, strerror(errno))
//        clientShutdown(EXIT_FAILURE);
//       }
//
//      // In case of recoverable errors, ask the user whether another connection
//      // attempt should be performed, closing the client application if it should not
//      if(!askReconnection())
//       clientShutdown(EXIT_SUCCESS);
//
//     } // if(!connRes)
//
//   } while(connRes != 0);
//
//  // At this point, connection with the server was established successfully
//  cout << "Successfully connected with SafeCloud server at " << srvIP << ":" << to_string(ntohs(srvAddr.sin_port)) << endl;
// }

