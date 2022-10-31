#include "Server.h"

/* SafeCloud Application Server Implementation */

/* ================================== INCLUDES ================================== */
#include "errCodes/execErrCodes/execErrCodes.h"
#include "defaults.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
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
 * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file
 *                                       could not be interpreted as a valid RSA key pair
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

  // Attempt to set the listening socket's SO_REUSEADDR
  // option for enabling fast rebinds in case of failures
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
  // _connMap iterator
  connMapIt connIt;

  // The client's assigned connection manager
  SrvConnMgr* srvConnMgr;

  // Whether the client connection should be terminated
  bool shutdownCliConn;

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

  try
   {
    // Parse the incoming data via the client data general
    // handler of the associated SrvConnMgr object
    srvConnMgr->srvRecvHandleData();

    // Determine whether the client connection should be terminated
    shutdownCliConn = srvConnMgr->shutdownConn();
   }
  catch(execErrExcp& excp)
   {
    // Change a ERR_PEER_DISCONNECTED into the
    // more specific ERR_CLI_DISCONNECTED error code
    if(excp.exErrcode == ERR_PEER_DISCONNECTED)
     excp.exErrcode = ERR_CLI_DISCONNECTED;

    // Handle the execution exception that was raised
    handleExecErrException(excp);

    // The client connection must always be terminated
    shutdownCliConn = true;
   }
  catch(sessErrExcp& sessExcp)
   {
    // Handle the session exception that was raised
    handleSessErrException(sessExcp);

    // Reset the server session manager's state
    srvConnMgr->getSession()->resetSessState();
   }

  // If the client's connection should be terminated due to it gracefully
  // disconnecting or because an execution exception has occurred
  if(shutdownCliConn)
   closeConn(connIt);
  else

   // Otherwise, if the client connection should be terminated because
   // the SafeCloud server is shutting down, if the server session
   // manager is in the session phase in the 'IDLE' operation
   if(_shutdown && srvConnMgr->isInSessionPhase()
      && srvConnMgr->getSession()->isIdle())
    {
      // Close the session with the client by
      // sending the 'BYE' session signaling message
      srvConnMgr->getSession()->closeSession();

      LOG_DEBUG("Sent 'BYE' session message to user \""
                + *srvConnMgr->getName() + "\"")

      // Close the client connection
      closeConn(connIt);
    }

  // Continue checking the next socket descriptor in the server's main loop
 }


/**
 * @brief Accepts an incoming client connection, creating its
 *       client object and entry in the connections' map
 * @TODO: throws?
 */
void Server::newClientConnection()
 {
  /* ----------------- Client Endpoint Information ----------------- */

  // The client socket type, IP and Port
  struct sockaddr_in  cliAddr{};

  // The (static) size of a sockaddr_in structure
  static unsigned int cliAddrLen = sizeof(sockaddr_in);

  // The client IP address and port
  char cliIP[16];
  int  cliPort;

  /* ----------------- Client SrvConnMgr Creation ----------------- */

  // The client's assigned connection socket
  int          csk = -1;

  // Number of connected clients BEFORE the client's connection
  size_t       connClients;

  // The client's assigned connection manager object
  SrvConnMgr*  srvConnMgr;

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
   * NOTE: This constraint is due to the select() allowing to monitor up to
   *       FD_SETSIZE = 1024 file descriptors, listening socket included
   */
  if(connClients == SRV_MAX_CONN)
   {
    // Inform the client that the server cannot accept further connections
    // TODO: Implement in a SafeCloud Message

    // Log the error and continue checking the next
    // socket descriptor in the server's main loop
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
    LOG_INFO("Maximum number of guest identifiers reached ("
             + std::to_string(UINT_MAX) + "), starting back from \'1\'")
    _guestIdx = 1;
   }

  // Create the client's entry in the connections' map
  empRet = _connMap.emplace(csk, srvConnMgr);

  /*
   * Ensure the newly assigned connection socket not
   * to be already present in the connection map
   *
   * NOTE: With no errors in the server's logic this check is
   *       unnecessary, but it's still performed for its negligible cost
   */
  if(!empRet.second)
   {
    LOG_CRITICAL("The connection socket assigned to a new client is already "
                 "present in the connections' map! (" + std::to_string(csk) + ")")

    // Close the pre-existing client connection and remove its entry
    // from the connections' map as an error recovery mechanism
    // (as the kernel is probably more right than the application)
    closeConn(empRet.first);

    // Re-insert the new client manager into the connections' map
    // (operation that in this case is always supposed to succeed)
    _connMap.emplace(csk, srvConnMgr);
   }

  // Add the new client's connection socket to the set of
  // file descriptors of open sockets and, if it's the one of
  // maximum value, update the "_skMax" variable accordingly
  FD_SET(csk, &_skSet);
  _skMax = std::max(_skMax, csk);

  // If this is the first client to have connected,
  // set the "_connected" status variable
  if(connClients == 0)
   _connected = true;

  // Log the new client connection and continue checking
  // the next socket descriptor in the server's main loop
  LOG_DEBUG("Number of connected clients: " + std::to_string(connClients+1))
 }


/**
 * @brief  Server main loop, awaiting and processing incoming data on any
 *         open socket (listening + connection sockets)  until the SafeCloud
 *         server has been instructed to shut down and no client is connected
 * @throws ERR_SRV_SELECT_FAILED select() call failed
 */
void Server::srvLoop()
 {
  // Set of file descriptors of open sockets used
  // for asynchronously reading incoming client data
  fd_set skReadSet;

  // select() return
  int selRet;

  // Initialize the set of file descriptor of open sockets
  // used for asynchronously reading incoming client data
  FD_ZERO(&skReadSet);

  // ----------------------------- SafeCloud Server Main Loop ----------------------------- //

  while(1)
   {
    // If the SafeCloud server is shutting down
    if(_shutdown)
     {
      // If there are no more clients connected, break the main
      // loop and terminate the SafeCloud server application
      if(!_connected)
       break;

      // Otherwise, if the server is listening on its listening socket
      else
       if(_lsk != -1)
        {
         // Close the listening socket to prevent accepting further client connections
         if(close(_lsk) != 0)
          LOG_EXEC_CODE(ERR_LSK_CLOSE_FAILED, ERRNO_DESC);

         // Remove the listening socket from the list of open file descriptors
         FD_CLR(_lsk, &_skSet);

         // Reset the listening socket
         _lsk = -1;
        }
     }

    // Reset the list of sockets to wait input data from to all open sockets
    skReadSet = _skSet;

    // Wait indefinitely for input data to be available on any open socket
    selRet = select(_skMax + 1, &skReadSet, NULL, NULL, NULL);

    // Depending on the select() return
    switch(selRet)
     {
      // -------------------------------- select() error -------------------------------- //
      case -1:

       // The only select() error that is allowed is being interrupted by an OS signal
       if(errno != EINTR)
        THROW_EXEC_EXCP(ERR_SRV_SELECT_FAILED, ERRNO_DESC);
       break;

      // ------------------------------- select() timeout ------------------------------- //
      case 0:

       // As it is not implemented, a select() timeout is a fatal error
       THROW_EXEC_EXCP(ERR_SRV_SELECT_FAILED, "select() timeout", ERRNO_DESC);

      // ------------- selRet = Number of sockets with available input data ------------- //
      default:

       /*
       // LOG: Number of sockets with available input data
       LOG_DEBUG("Number of sockets with available input data: " + std::to_string(selRet))
       */

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
          if(--selRet == 0)
           break;
         }
     } // switch(selRet)
   } // while(1)

  // --------------------------- End SafeCloud Server Main Loop --------------------------- //
 }


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
Server::Server(uint16_t srvPort) : SafeCloudApp(), _lsk(-1), _srvCert(nullptr), _connMap(), _skSet(), _skMax(-1), _guestIdx(1)
 {
  // Set the server endpoint parameters
  setSrvEndpoint(srvPort);

  // Retrieve the server's long-term RSA key pair
  getServerRSAKey();

  // Retrieve the server's certificate
  getServerCert();

  // Initialize the sets of file descriptors used for asynchronously
  // reading client data from sockets via the select()
  FD_ZERO(&_skSet);

  // Initialize the server's listening socket and bind it on the specified OS port
  initLsk();
 }


/**
 * @brief SafeCloud server object destructor, closing open client
 *        connections and safely deleting the server's sensitive attributes
 */
Server::~Server()
 {
  // Delete the SrvConnMgr object associated with each connected client
  for(connMapIt it = _connMap.begin(); it != _connMap.end(); ++it)
   { delete it->second; }

  // If the server is listening on its listening socket
  if(_lsk != -1)
   {
    // Close the listening socket to prevent
    // accepting further client connections
    if(close(_lsk) != 0)
     LOG_EXEC_CODE(ERR_LSK_CLOSE_FAILED, ERRNO_DESC);

    // Reset the listening socket
    _lsk = -1;
   }

  // Safely erase all sensitive attributes
  EVP_PKEY_free(_rsaKey);
  X509_free(_srvCert);
 }


/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief  Server object shutdown signal handler, returning, depending on whether
 *         there are client requests pending, if it can be terminated directly or
 *         if it will autonomously terminate as soon as such requests are served
 * @return A boolean indicating whether the server object can be terminated directly
 * @note   If the Server object cannot be terminated directly, its listening socket
 *         will be closed in the next server loop iteration to prevent accepting
 *         further client connections
 */
bool Server::shutdownSignalHandler()
 {
  // List of iterators of the connected clients' map whose
  // associated 'SrvConnMgr' objects are in the session 'IDLE' state
  std::forward_list<connMapIt> idleCliConnList;

  // Cycle the entire connected clients' map
  for(connMapIt it = _connMap.begin(); it != _connMap.end(); ++it)
   {
    // If the client's server session manager is in the session 'IDLE'
    // state, add its associated iterator to the 'idleCliConnList'
    if(it->second != nullptr && it->second->isInSessionPhase()
       && it->second->getSession()->isIdle())
     idleCliConnList.emplace_front(it);
   }

  // For each iterator of the connected clients' map whose
  // associated 'SrvConnMgr' object is in the session 'IDLE' state
  for(const auto& it : idleCliConnList)
   {
    // Attempt to close the client session by sending
    // them the 'BYE' session signaling message
    try
     {
      it->second->getSession()->closeSession();

      LOG_DEBUG("Sent 'BYE' session message to user \""
                + *it->second->getName() + "\"")
     }

    // If an execution exception has occurred, handle it
    catch(execErrExcp& cliExecExcp)
     { handleExecErrException(cliExecExcp); }

    // In any case, close the client connection
    closeConn(it);
   }

  // If the SafeCloud server is no longer connected with
  // any client, return that it can be terminated directly
  if(!_connected)
   return true;

  // Otherwise set the '_shutdown' flag and return that
  // the server object will autonomously terminate once
  // the clients' pending requests will have been served
  _shutdown = true;
  return false;
 }


// TODO: Update Descr

/**
 * @brief  Starts the SafeCloud server operations by listening on the listening socket and processing incoming client connections and data
 * @note   This method returns only in case of errors or should the server be instructed to terminate via the shutdownSignal() method
 * @throws ERR_LSK_LISTEN_FAILED   Failed to listen on the server's listening socket
 * @throws ERR_SRV_SELECT_FAILED  select() call failed
 */
void Server::start()
 {
  // Start listening on the listening socket, allowing up to a predefined maximum number of queued connections
  if(listen(_lsk, SRV_MAX_QUEUED_CONN) < 0)
   THROW_EXEC_EXCP(ERR_LSK_LISTEN_FAILED, ERRNO_DESC);

  // Log that the server is now listening on the listening socket
  LOG_INFO("SafeCloud server now listening on all local network interfaces on port "
           + std::to_string(ntohs(_srvAddr.sin_port)) + ", awaiting client connections...")

  // Call the server main loop
  srvLoop();
 }