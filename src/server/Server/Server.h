#ifndef SAFECLOUD_SERVER_H
#define SAFECLOUD_SERVER_H

/* SafeCloud Server Application Declaration */

/* ================================== INCLUDES ================================== */
#include "SafeCloudApp/SafeCloudApp.h"
#include "SrvConnMgr/SrvConnMgr.h"


class Server : public SafeCloudApp
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* ------------------------- General Server Parameters ------------------------- */
   int   _lsk;       // The server listening socket's file descriptor
   X509* _srvCert;   // The server's X.509 certificate

   /* ----------------------- Client Connections Management ----------------------- */

   // A map associating the file descriptors of open connection
   // sockets to their associated srvConnMgr objects (one per client)
   connMap _connMap;

  // The set of file descriptors of open sockets
  // (listening socket + connection sockets)
   fd_set _skSet;

   // The maximum socket file descriptor value in the
   // server's execution (select() optimization purposes)
   /*
    * NOTE: This value may refer to a socket that is no longer open, as updating
    *       it in case the SrvConnMgr with the maximum "csk" value terminates
    *       would require searching for the new maximum file descriptor in the
    *       '_connMap' map, which is inefficient due to it being an unordered map
    *       (and changing it to an ordered map would in turn make all other
    *       operations less efficient, nullifying the advantages of such approach)
    */
   int _skMax;

   // Used as a temporary identifier for users that
   // have not yet authenticated within the server
   unsigned int _guestIdx;

   /* =============================== PRIVATE METHODS =============================== */

   /* ---------------------------- Server Initialization ---------------------------- */

   /**
    * @brief  Sets the server IP:Port endpoint parameters
    * @param  srvPort The OS port the SafeCloud server must bind on
    * @throws ERR_SRV_PORT_INVALID Invalid server port
    */
   void setSrvEndpoint(uint16_t& srvPort);

   /**
    * @brief  Retrieves the SafeCloud server long-term RSA private key from its ".pem" file
    * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
    * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA private key file
    * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file
    *                                       could not be interpreted as a valid RSA key pair
    */
   void getServerRSAKey();

   /**
    * @brief  Loads the server X.509 certificate from its default ".pem" file
    * @throws ERR_SRV_CERT_OPEN_FAILED The server certificate file could not be opened
    * @throws ERR_FILE_CLOSE_FAILED    The server certificate file could not be closed
    * @throws ERR_CA_CERT_INVALID      The server certificate is invalid
    */
   void getServerCert();

   /**
    * @brief  Initializes the server's listening socket
    *         and binds it to the specified host port
    * @throws ERR_LSK_INIT_FAILED         Listening socket initialization failed
    * @throws ERR_LSK_SO_REUSEADDR_FAILED Error in setting the listening
    *                                     socket's SO_REUSEADDR option
    * @throws ERR_LSK_BIND_FAILED         Error in binding the listening
    *                                     socket on the specified host port
    */
  void initLsk();

  /* --------------------------------- Server Loop --------------------------------- */

  /**
   * @brief Closes a client connection by deleting its associated SrvConnMgr
   *        object and removing its associated entry from the connections' map
   * @param cliIt The iterator to the client's entry in the connections' map
   */
  void closeConn(connMapIt cliIt);

  /**
   * @brief Passes the incoming client data to its associated SrvConnMgr object,
   *        which returns whether to maintain or close the client's connection
   * @param ski The connection socket with available input data
   */
  void newClientData(int ski);

  /**
   * @brief Accepts an incoming client connection, creating its
   *        client object and entry in the connections' map
   */
  void newClientConnection();

  /**
   * @brief  Server main loop, awaiting and processing incoming data on any
   *         open socket (listening + connection sockets)  until the SafeCloud
   *         server has been instructed to shut down and no client is connected
   * @throws ERR_SRV_SELECT_FAILED select() call failed
   */
  void srvLoop();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  SafeCloud server object constructor
    * @param  srvPort The OS port the server should bind on
    * @throws ERR_SRV_PORT_INVALID          Invalid server port
    * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
    * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA
    *                                       private key OR certificate file
    * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file
    *                                       could not be interpreted as a valid RSA key pair
    * @throws ERR_SRV_CERT_OPEN_FAILED      The server certificate file could not be opened
    * @throws ERR_SRV_CERT_INVALID          The server certificate is invalid
    * @throws ERR_LSK_INIT_FAILED           Listening socket initialization failed
    * @throws ERR_LSK_SO_REUSEADDR_FAILED   Error in setting the listening
    *                                       socket's SO_REUSEADDR option
    * @throws ERR_LSK_BIND_FAILED           Error in binding the listening
    *                                       socket on the specified host port
    */
   explicit Server(uint16_t srvPort);

   /**
    * @brief SafeCloud server object destructor, closing open client
    *        connections and safely deleting the server's sensitive attributes
    */
   ~Server();

  /* ============================= OTHER PUBLIC METHODS ============================= */

  /**
   * @brief  Server object shutdown signal handler, returning, depending on whether
   *         there are client requests pending, if it can be terminated directly or
   *         if it will autonomously terminate as soon as such requests are served
   * @return A boolean indicating whether the server object can be terminated directly
   * @note   If the Server object cannot be terminated directly, its
   *         listening socket will be closed in the next server loop
   *         iteration to prevent accepting further client connections
   */
  bool shutdownSignalHandler();

  /**
   * @brief  Starts the SafeCloud Server by starting listening on the listening
   *         socket and serving incoming client connection and application requests
   * @note   This method returns only once all pending client requests have been served
   *         following the reception of a shutdown signal (shutdownSignalHandler() method)
   * @throws ERR_LSK_LISTEN_FAILED Failed to listen on the server's listening socket
   * @throws ERR_SRV_SELECT_FAILED select() call failed
   */
  void start();
 };


#endif //SAFECLOUD_SERVER_H