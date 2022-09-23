#include "Server.h"

/* SafeCloud Application Server Implementation*/

/* ================================== INCLUDES ================================== */
#include "scode.h"
#include "errlog.h"
#include "defaults.h"
#include <unistd.h>

/* =============================== PRIVATE METHODS =============================== */

/* ---------------------------- Server Initialization ---------------------------- */

/**
 * @brief         Sets the server IP:Port endpoint parameters
 * @param srvPort The OS port the SafeCloud server must bind on
 * @throws ERR_SRV_PORT_INVALID Invalid server port
 */
void Server::setSrvEndpoint(uint16_t& srvPort)
 {
  // Set the server socket type to IPv4 and to be associated to all host network interfaces (i.e. IP 0.0.0.0)
  _srvAddr.sin_family = AF_INET;
  _srvAddr.sin_addr.s_addr = INADDR_ANY;

  // If srvPort >= SRV_PORT_MIN, convert it to the network byte order within the "_srvAddr" structure
  if(srvPort >= SRV_PORT_MIN)
   _srvAddr.sin_port = htons(srvPort);
  else   // Otherwise, throw an exception
   THROW_SCODE(ERR_SRV_PORT_INVALID);

  LOG_DEBUG("SafeCloud server port set to" + std::to_string(srvPort))
 }


/**
 * @brief                                Retrieves the SafeCloud server long-term RSA private key from its ".pem" file
 * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
 * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
 * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA private key file
 * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file could not be interpreted as a valid RSA key pair
 */
void Server::getServerRSAKey()
 {
  FILE* RSAKeyFile;     // The server's long-term RSA private key file (.pem)
  char* RSAKeyFilePath; // The server's long-term RSA private key file path

  // Derive the expected absolute, or canonicalized, path of the server's private key file
  RSAKeyFilePath = realpath(SRV_CERT_PATH,NULL);
  if(!RSAKeyFilePath)
   THROW_SCODE(ERR_SRV_PRIVKFILE_NOT_FOUND, SRV_CERT_PATH, ERRNO_DESC);

  // Attempt to open the server's RSA private key file
  RSAKeyFile = fopen(RSAKeyFilePath, "r");
  if(!RSAKeyFile)
   {
    free(RSAKeyFilePath);
    THROW_SCODE(ERR_SRV_PRIVKFILE_OPEN_FAILED, RSAKeyFilePath, ERRNO_DESC);
   }

  // Attempt to read the server's long-term RSA private key from its file
  _rsaKey = PEM_read_PrivateKey(RSAKeyFile, NULL, NULL, NULL);

  // Close the RSA private key file
  if(fclose(RSAKeyFile) != 0)
   {
    free(RSAKeyFilePath);
    THROW_SCODE(ERR_FILE_CLOSE_FAILED, RSAKeyFilePath, ERRNO_DESC);
   }

  // Ensure that a valid private key has been read
  if(!_rsaKey)
   {
    free(RSAKeyFilePath);
    THROW_SCODE(ERR_SRV_PRIVK_INVALID, RSAKeyFilePath, OSSL_ERR_DESC);
   }

  // At this point the server's long-term RSA private key is valid
  LOG_DEBUG("Server long-term private key successfully loaded")

  // Free the RSA key file path
  free(RSAKeyFilePath);
 }


/**
 * @brief Loads the server X.509 certificate from its default ".pem" file
 * @throws ERR_SRV_CERT_OPEN_FAILED The server certificate file could not be opened
 * @throws ERR_FILE_CLOSE_FAILED    The server certificate file could not be closed
 * @throws ERR_SRV_CERT_INVALID     The server certificate is invalid
 */
void Server::getServerCert()
 {
  FILE* srvCertFile;   // Server Certificate file descriptor
  X509* srvCert;       // Server X.509 Certificate

  // Attempt to open the server certificate from its .pem file
  srvCertFile = fopen(SRV_CERT_PATH, "r");
  if(!srvCertFile)
   THROW_SCODE(ERR_SRV_CERT_OPEN_FAILED,SRV_CERT_PATH,ERRNO_DESC);

  // Read the X.509 server certificate from its file
  srvCert = PEM_read_X509(srvCertFile, NULL, NULL, NULL);

  // Close the CA certificate file
  if(fclose(srvCertFile) != 0)
   THROW_SCODE(ERR_FILE_CLOSE_FAILED,SRV_CERT_PATH,ERRNO_DESC);

  // Ensure the contents of the CA certificate file to consist of a valid certificate
  if(!srvCert)
   THROW_SCODE(ERR_SRV_CERT_INVALID,SRV_CERT_PATH,OSSL_ERR_DESC);

  // At this point the server certificate has been loaded successfully
  // and, in DEBUG_MODE, print its subject and issuer
#ifdef DEBUG_MODE
  std::string certSubject = X509_NAME_oneline(X509_get_subject_name(srvCert), NULL, 0);
  LOG_DEBUG("Server certificate successfully loaded: " + certSubject)
#endif

  // Set the valid server certificate
  _srvCert = srvCert;
 }


/**
 * @brief Initializes the server's listening socket and binds it to the specified host port
 * @throws ERR_LSK_INIT_FAILED         Listening socket initialization failed
 * @throws ERR_LSK_SO_REUSEADDR_FAILED Error in setting the listening socket's SO_REUSEADDR option
 * @throws ERR_LSK_BIND_FAILED         Error in binding the listening socket on the specified host port
 */
void Server::initLsk()
 {
  int lskOptSet = 1;   // Used for enabling the listening socket options

  // Attempt to initialize the server listening socket
  _lsk = socket(AF_INET, SOCK_STREAM, 0);
  if(_lsk == -1)
   THROW_SCODE(ERR_LSK_INIT_FAILED,ERRNO_DESC);

  LOG_DEBUG("Created listening socket with file descriptor '" + std::to_string(_lsk) + "'")

  // Attempt to set the listening socket's SO_REUSEADDR option for enabling fast rebinds in case of failures
  if(setsockopt(_lsk, SOL_SOCKET, SO_REUSEADDR, &lskOptSet, sizeof(lskOptSet)) == -1)
   THROW_SCODE(ERR_LSK_SO_REUSEADDR_FAILED,ERRNO_DESC);

  // Attempt to bind the listening socket on the specified OS port
  if(bind(_lsk, (struct sockaddr*)&_srvAddr, sizeof(_srvAddr)) < 0)
   THROW_SCODE(ERR_LSK_BIND_FAILED,ERRNO_DESC);

  LOG_DEBUG("SafeCloud server listening socket successfully initialized")
 }


/*
// Attempt to make the server listen on the listening socket
if(listen(lsk, SRV_MAX_QUEUED_CONN) < 0)
{
LOG_CODE_DSCR_FATAL(ERR_LSK_LISTEN_FAILED,strerror(errno))
exit(EXIT_FAILURE);
}

// Log that the server's listening socket was initialized successfully
LOG_INFO("SafeCloud server now listening on all local network interfaces on port " + to_string(ntohs(srvAddr.sin_port)) + ", awaiting client connections...")
  */


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief                                SafeCloud server object constructor
 * @param srvPort                        The OS port the server should bind on
 * @throws ERR_SRV_PORT_INVALID          Invalid server port
 * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
 * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
 * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA private key OR certificate file
 * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file could not be interpreted as a valid RSA key pair
 * @throws ERR_SRV_CERT_OPEN_FAILED      The server certificate file could not be opened
 * @throws ERR_SRV_CERT_INVALID          The server certificate is invalid
 * @throws ERR_LSK_INIT_FAILED           Listening socket initialization failed
 * @throws ERR_LSK_SO_REUSEADDR_FAILED   Error in setting the listening socket's SO_REUSEADDR option
 * @throws ERR_LSK_BIND_FAILED           Error in binding the listening socket on the specified host port
 */
Server::Server(uint16_t srvPort) : _srvAddr(), _lsk(-1), _rsaKey(nullptr), _srvCert(nullptr), _guestIdx(1),
                                   _started(false), _connected(false), _shutdown(false)
 {
  // Set the server endpoint parameters
  setSrvEndpoint(srvPort);

  // Retrieve the server's long-term RSA key pair
  getServerRSAKey();

  // Retrieve the server's certificate
  getServerCert();

  // Initialize the server's listening socket and bind it on the specified OS port
  initLsk();
 }


/**
 * @brief SafeCloud server object destructor, which closes open connections and safely deletes its sensitive attributes
 */
Server::~Server()
 {
  // Cycle through the entire connected clients' map and delete the associated SrvConnMgr objects
  for(cliMapIt it = _cliMap.begin(); it != _cliMap.end(); ++it)
   { delete it->second; }

  // If open, close the listening socket
  if(_lsk != -1 && close(_lsk) != 0)
   LOG_SCODE(ERR_LSK_CLOSE_FAILED, strerror(errno));

  // Safely erase all sensitive attributes
  EVP_PKEY_free(_rsaKey);
  X509_free(_srvCert);
 }


/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Asynchronously instructs the server object to
 *        gracefully close all connections and terminate
 */
void Server::shutdownSignal()
 { _shutdown = true; }


/**
  * @brief  Returns whether the server has started listening on its listening socket
  * @return 'true' if it is listening, 'false' otherwise
  */
bool Server::isStarted()
 { return _started; }


/**
 * @brief  Returns whether the server is currently connected with at least one client
 * @return 'true' if connected with at least one client, 'false' otherwise
 */
bool Server::isConnected()
 { return _connected; }


/**
  * @brief   Returns whether the server object has been instructed
  *          to gracefully close all connections and terminate
  * @return 'true' if the server object is shutting down, 'false' otherwise
  */
bool Server::isShuttingDown()
 { return _shutdown; }