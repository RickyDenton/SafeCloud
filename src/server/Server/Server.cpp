#include "Server.h"

/* SafeCloud Application Server Implementation*/

/* ================================== INCLUDES ================================== */
#include "err/execErrCodes.h"
#include "defaults.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <string>

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
   THROW_EXEC_EXCP(ERR_SRV_PORT_INVALID);

  LOG_DEBUG("SafeCloud server port set to " + std::to_string(srvPort))
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
  RSAKeyFilePath = realpath(SRV_PRIVK_PATH,NULL);
  if(!RSAKeyFilePath)
   THROW_EXEC_EXCP(ERR_SRV_PRIVKFILE_NOT_FOUND, SRV_PRIVK_PATH, ERRNO_DESC);

  // Try-catch block to allow the RSAKeyFilePath both to be freed and reported in an exception
  try
   {
    // Attempt to open the server's RSA private key file
    RSAKeyFile = fopen(RSAKeyFilePath, "r");
    if(!RSAKeyFile)
     THROW_EXEC_EXCP(ERR_SRV_PRIVKFILE_OPEN_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Attempt to read the server's long-term RSA private key from its file
    _rsaKey = PEM_read_PrivateKey(RSAKeyFile, NULL, NULL, NULL);

    // Close the RSA private key file
    if(fclose(RSAKeyFile) != 0)
     THROW_EXEC_EXCP(ERR_FILE_CLOSE_FAILED, RSAKeyFilePath, ERRNO_DESC);

    // Ensure that a valid private key has been read
    if(!_rsaKey)
     THROW_EXEC_EXCP(ERR_SRV_PRIVK_INVALID, RSAKeyFilePath, OSSL_ERR_DESC);

    // At this point the server's long-term RSA private key is valid
    LOG_DEBUG("SafeCloud server long-term RSA private key successfully loaded")

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
   THROW_EXEC_EXCP(ERR_SRV_CERT_OPEN_FAILED, SRV_CERT_PATH, ERRNO_DESC);

  // Read the X.509 server certificate from its file
  srvCert = PEM_read_X509(srvCertFile, NULL, NULL, NULL);

  // Close the CA certificate file
  if(fclose(srvCertFile) != 0)
   THROW_EXEC_EXCP(ERR_FILE_CLOSE_FAILED, SRV_CERT_PATH, ERRNO_DESC);

  // Ensure the contents of the CA certificate file to consist of a valid certificate
  if(!srvCert)
   THROW_EXEC_EXCP(ERR_SRV_CERT_INVALID, SRV_CERT_PATH, OSSL_ERR_DESC);

  // At this point the server certificate has been loaded successfully
  // and, in DEBUG_MODE, print its subject and issuer
#ifdef DEBUG_MODE
  std::string certSubject = X509_NAME_oneline(X509_get_subject_name(srvCert), NULL, 0);
  LOG_DEBUG("SafeCloud server certificate successfully loaded: " + certSubject)
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
   THROW_EXEC_EXCP(ERR_LSK_INIT_FAILED, ERRNO_DESC);

  LOG_DEBUG("Created listening socket with file descriptor '" + std::to_string(_lsk) + "'")

  // Attempt to set the listening socket's SO_REUSEADDR option for enabling fast rebinds in case of failures
  if(setsockopt(_lsk, SOL_SOCKET, SO_REUSEADDR, &lskOptSet, sizeof(lskOptSet)) == -1)
   THROW_EXEC_EXCP(ERR_LSK_SO_REUSEADDR_FAILED, ERRNO_DESC);

  // Attempt to bind the listening socket on the specified OS port
  if(bind(_lsk, (struct sockaddr*)&_srvAddr, sizeof(_srvAddr)) < 0)
   THROW_EXEC_EXCP(ERR_LSK_BIND_FAILED, ERRNO_DESC);

  // Add the listening socket to the set of file descriptors of open
  // sockets and initialize the maximum socket file descriptor value to it
  FD_SET(_lsk, &_skSet);
  _skMax = _lsk;

  LOG_DEBUG("SafeCloud server listening socket successfully initialized")
 }

/* --------------------------------- Server Loop --------------------------------- */

/**
 * @brief       Closes a client connection by deleting its associated SrvConnMgr
 *              object and removing its associated entry from the connections' map
 * @param cliIt The iterator to the client's entry in the connections' map
 */
void Server::closeConn(connMapIt cliIt)
 {
  size_t connClients;  // Number of connected clients AFTER the client's disconnection

  // Remove the connection socket from the set of file descriptors of open sockets
  FD_CLR(cliIt->first, &_skSet);

  // Delete the client's connection manager
  delete(cliIt->second);

  // Remove the client's entry from the connections' map
  _connMap.erase(cliIt);

  // Retrieve the updated number of connected clients
  connClients = _connMap.size();

  // If the last client has disconnected, reset the "_connected" status variable
  if(connClients == 0)
   _connected = false;

  LOG_DEBUG("Number of connected clients: " + std::to_string(connClients))
 }


/**
 * @brief     Passes the incoming client data to its associated SrvConnMgr object,
 *            which returns whether to maintain or close the client's connection
 * @param ski The connection socket with available input data
 */
void Server::newClientData(int ski)
 {
  connMapIt connIt;        // _connMap iterator
  SrvConnMgr* srvConnMgr;  // The client's assigned connection manager
  bool keepConn;           // Indicates whether the client connection should be maintained or not

  // Retrieve the connection's map entry associated with "ski"
  connIt = _connMap.find(ski);

  // If the entry was not found (which should NEVER happen)
  if(connIt == _connMap.end())
   {
    // Attempt to manually close the unmatched connection socket as
    // an error recovery mechanism, discarding any possible error
    close(ski);

    // Log the error and continue checking the next
    // socket descriptor in the server's main loop
    LOG_EXEC_CODE(ERR_CSK_MISSING_MAP, std::to_string(ski));
    return;
   }

  // Retrieve the pointer to the client's connection manager
  srvConnMgr = connIt->second;

  // Pass the incoming client data to the SrvConnMgr object, which
  // returns whether to maintain or close the client's connection
  try
   { keepConn = srvConnMgr->recvHandleData(); }
  catch(execErrExcp& excp)
   {
    // TODO: Check
    handleExecErrException(excp);

    // The connection must be closed
    keepConn = false;
   }

  // If necessary close the client's connection and continue
  // checking the next socket descriptor in the server's main loop
  if(!keepConn)
   closeConn(connIt);
 }


/**
 * @brief Accepts an incoming client connection, creating its client object and entry in the connections' map
 */
void Server::newClientConnection()
 {
  /* ----------------- Client Endpoint Information ----------------- */
  struct sockaddr_in  cliAddr{};                         // The client socket type, IP and Port
  static unsigned int cliAddrLen = sizeof(sockaddr_in);  // The (static) size of a sockaddr_in structure
  char cliIP[16];                                        // The client IP address
  int  cliPort;                                          // The client port

  /* ----------------- Client SrvConnMgr Creation ----------------- */
  int          csk = -1;     // The client's assigned connection socket
  size_t       connClients;  // Number of connected clients BEFORE the client's connection
  SrvConnMgr*  srvConnMgr;   // The client's assigned connection manager

  // Used to check whether the newly created server connection
  // manager was successfully added to the connections' map
  std::pair<connMapIt,bool> empRet;


  // Attempt to accept the incoming client connection, obtaining
  // the file descriptor of its assigned connection socket
  csk = accept(_lsk, (struct sockaddr*)&cliAddr, &cliAddrLen);

  // If the accept() failed, log the error and continue checking
  // the next socket descriptor in the server's main loop
  if(csk == -1)
   {
    LOG_EXEC_CODE(ERR_CSK_ACCEPT_FAILED, ERRNO_DESC);
    return;
   }

  // Retrieve the new client's IP and Port
  inet_ntop(AF_INET, &cliAddr.sin_addr.s_addr, cliIP, INET_ADDRSTRLEN);
  cliPort = ntohs(cliAddr.sin_port);

  // Retrieve the number of currently connected clients
  connClients = _connMap.size();

  // Ensure that the maximum number of client connections has not been reached
  /*
   * NOTE: This constraint is due to the fact that the pselect() allows to monitor
   *       up to FD_SETSIZE = 1024 file descriptors, listening socket included
   */
  if(connClients == SRV_MAX_CONN)
   {
    // Inform the client that the server cannot accept further connections
    // TODO: Implement in a SafeCloud Message

    // Log the error and continue checking the next socket descriptor in the server's main loop
    LOG_EXEC_CODE(ERR_CSK_MAX_CONN, std::string(cliIP) + std::to_string(cliPort));
    return;
   }

  // Attempt to initialize the client's connection manager
  try
   { srvConnMgr = new SrvConnMgr(csk,_guestIdx,_rsaKey,_srvCert); }
  catch(execErrExcp& excp)
   {
    // TODO: check how to implement this
    // Log the error
    handleExecErrException(excp);

    // Delete the srvConnMgr object
    delete srvConnMgr;

    // Continue checking the next socket descriptor in the server's main loop
    return;
   }

  // If the temporary guest identifier would overflow, reset it to 1
  if(++_guestIdx == 0)
   {
    LOG_INFO("Maximum number of guest identifiers reached (" + std::to_string(UINT_MAX) + "), starting back from \'1\'")
    _guestIdx = 1;
   }

  // Create the client's entry in the connections' map
  empRet = _connMap.emplace(csk, srvConnMgr);

  // Ensure the newly assigned connection socket not to be already present in the connection map
  // NOTE: With no errors in the server's logic this check is unnecessary, but it's still performed for its negligible cost
  if(!empRet.second)
   {
    LOG_CRITICAL("The connection socket assigned to a new client is already present in the connections' map! (" + std::to_string(csk) + ")")

    // Close the pre-existing client connection and remove its entry from the connections' map as
    // an error recovery mechanism (as the kernel is probably more right than the application)
    closeConn(empRet.first);

    // Re-insert the new client manager into the connections' map (operation that in this case is always supposed to succeed)
    _connMap.emplace(csk, srvConnMgr);
   }

  // Add the new client's connection socket to the set of file descriptors of open sockets
  // and, if it's the one of maximum value, update the "_skMax" variable accordingly
  FD_SET(csk, &_skSet);
  _skMax = std::max(_skMax, csk);

  // If this is the first client to have connected, set the "_connected" status variable
  if(connClients == 0)
   _connected = true;

  // Log the new client connection and continue checking
  // the next socket descriptor in the server's main loop
  LOG_DEBUG("Number of connected clients: " + std::to_string(connClients+1))
 }


/**
 * @brief  Server main loop, awaiting and serving input data on any open socket
 *         (listening + connection socket) and managing external shutdown requests
 * @note   This method returns only in case of errors or should the server
 *         be instructed to terminate via the shutdownSignal() method
 * @throws ERR_SRV_PSELECT_FAILED pselect() call failed
 */
void Server::srvLoop()
 {
  // Set of file descriptors of open sockets used
  // for asynchronously reading incoming client data
  fd_set skReadSet;

  // pselect() return
  int pselRet;

  // Structure used for specifying a pselect() timeout
  struct timespec selTimeout = {SRV_PSELECT_TIMEOUT,0};

  // Initialize the set of file descriptor of open sockets
  // used for asynchronously reading incoming client data
  FD_ZERO(&skReadSet);

  while(1)
   {
    // Reset the list of sockets to wait input data from to all open sockets
    skReadSet = _skSet;

    // Wait for input data to be available on any open socket up to a predefined timeout
    pselRet = pselect(_skMax + 1, &skReadSet, NULL, NULL, &selTimeout, NULL);

    // Depending on the pselect() return
    switch(pselRet)
     {
      /* pselect() error */
      case -1:

       // The only allowed pselect() error is it being interrupted by receiving an OS signal
       if(errno == EINTR)
        {
         // TODO: At this point _shutdown == 1, so perform the cleanup operations...
        }

       // Otherwise it is a fatal error, and the SafeCloud server must be aborted
       else
        THROW_EXEC_EXCP(ERR_SRV_PSELECT_FAILED, ERRNO_DESC);

      /* pselect() timeout */
      case 0:
       // TODO: Check server shutdown (MAYBE NOT NECESSARY BECAUSE IT BECOMES INTERRUPTED? BUT DO SO ANYWAY)
       break;

      /* pselRet = Number of open sockets with available input data */
      default:

       LOG_DEBUG("Number of sockets with available input data: " + std::to_string(pselRet))

       // Browse all sockets file descriptors from 0 to _skMax
       for(int ski = 0; ski <= _skMax; ski++)

        // If input data is available on socket "ski"
        if(FD_ISSET(ski, &skReadSet))
         {
          // If "ski" is the server's listening socket, a new client is attempting to connect with the SafeCloud server
          if(ski == _lsk)
           newClientConnection();

          // Otherwise "ski" is a connection socket of an existing client which has sent new data to the server
          else
           newClientData(ski);

          // Once the listening or connection socket has been served, decrement the number of sockets with pending
          // input data and, if no other is present, break the "for" loop for restarting the main server loop
          if(--pselRet == 0)
           break;
         }
     } // switch(pselRet)
   } // while(1)
 } // srvLoop()


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
Server::Server(uint16_t srvPort) : _srvAddr(), _lsk(-1), _rsaKey(nullptr), _srvCert(nullptr), _connMap(), _skSet(),
                                   _skMax(-1), _guestIdx(1), _started(false), _connected(false), _shutdown(false)
 {
  // Set the server endpoint parameters
  setSrvEndpoint(srvPort);

  // Retrieve the server's long-term RSA key pair
  getServerRSAKey();

  // Retrieve the server's certificate
  getServerCert();

  // Initialize the sets of file descriptors used for asynchronously
  // reading client data from sockets via the pselect()
  FD_ZERO(&_skSet);

  // Initialize the server's listening socket and bind it on the specified OS port
  initLsk();
 }


/**
 * @brief SafeCloud server object destructor, which closes open connections and safely deletes its sensitive attributes
 */
Server::~Server()
 {
  // Cycle through the entire connected clients' map and delete the associated SrvConnMgr objects
  for(connMapIt it = _connMap.begin(); it != _connMap.end(); ++it)
   { delete it->second; }

  // If open, close the listening socket
  if(_lsk != -1 && close(_lsk) != 0)
   LOG_EXEC_CODE(ERR_LSK_CLOSE_FAILED, ERRNO_DESC);

  // Safely erase all sensitive attributes
  EVP_PKEY_free(_rsaKey);
  X509_free(_srvCert);
 }


/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief  Starts the SafeCloud server operations by listening on the listening socket and processing incoming client connections and data
 * @note   This method returns only in case of errors or should the server be instructed to terminate via the shutdownSignal() method
 + @throws ERR_SRV_ALREADY_STARTED The server has already started listening on its listening socket
 * @throws ERR_LSK_LISTEN_FAILED   Failed to listen on the server's listening socket
 * @throws ERR_SRV_PSELECT_FAILED  pselect() call failed
 */
void Server::start()
 {
  // Check that the server has not already started
  if(_started)
   THROW_EXEC_EXCP(ERR_SRV_ALREADY_STARTED);

  // Start listening on the listening socket, allowing up to a predefined maximum number of queued connections
  if(listen(_lsk, SRV_MAX_QUEUED_CONN) < 0)
   THROW_EXEC_EXCP(ERR_LSK_LISTEN_FAILED, ERRNO_DESC);

  // Set that the SafeCloud server has started
  _started = true;

  // Log that the server is now listening on the listening socket
  LOG_INFO("SafeCloud server now listening on all local network interfaces on port " + std::to_string(ntohs(_srvAddr.sin_port)) + ", awaiting client connections...")

  // Call the server main loop
  srvLoop();
 }

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