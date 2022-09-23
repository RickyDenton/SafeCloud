#ifndef SAFECLOUD_SERVER_H
#define SAFECLOUD_SERVER_H

/* SafeCloud Application Server */

#include <openssl/evp.h>
#include <netinet/in.h>
#include "SrvConnMgr/SrvConnMgr.h"

class Server
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* ----------------------- Server Connection Parameters ----------------------- */
   struct sockaddr_in _srvAddr;   // The server's listening socket type, IP and Port in network representation order
   int                _lsk;       // The server listening socket's file descriptor

   /* ---------------------- Server Cryptographic Quantities ---------------------- */
   EVP_PKEY* _rsaKey;              // Long-term server RSA key pair
   X509*     _srvCert;             // The server's X.509 certificate

   /* ----------------------- Client Connections Management ----------------------- */

  // A map associating the file descriptors of open connection
   // sockets to their associated srvConnMgr objects (one per client)
   cliMap _cliMap;

   // Used as a temporary identifier for users that
   // have not yet authenticated within the application
   unsigned int _guestIdx;

   /* ---------------------------- Server Object Flags ---------------------------- */
   bool _started;   // Whether the server object has started listening on its listening socket
   bool _connected; // Whether at least one client is connected with the SafeCloud server
   bool _shutdown;  // Whether the server object should gracefully close all connections and terminate


   /* =============================== PRIVATE METHODS =============================== */

   /* ---------------------------- Server Initialization ---------------------------- */

   /**
    * @brief         Sets the server IP:Port endpoint parameters
    * @param srvPort The OS port the SafeCloud server must bind on
    * @throws ERR_SRV_PORT_INVALID Invalid server port
    */
   void setSrvEndpoint(uint16_t& srvPort);

   /**
    * @brief                                Retrieves the SafeCloud server long-term RSA private key from its ".pem" file
    * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
    * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA private key file
    * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file could not be interpreted as a valid RSA key pair
    */
   void getServerRSAKey();

   /**
    * @brief Loads the server X.509 certificate from its default ".pem" file
    * @throws ERR_SRV_CERT_OPEN_FAILED The server certificate file could not be opened
    * @throws ERR_FILE_CLOSE_FAILED    The server certificate file could not be closed
    * @throws ERR_CA_CERT_INVALID      The server certificate is invalid
    */
   void getServerCert();

   /**
    * @brief Initializes the server's listening socket and binds it to the specified host port
    * @throws ERR_LSK_INIT_FAILED         Listening socket initialization failed
    * @throws ERR_LSK_SO_REUSEADDR_FAILED Error in setting the listening socket's SO_REUSEADDR option
    * @throws ERR_LSK_BIND_FAILED         Error in binding the listening socket on the specified host port
    */
  void initLsk();


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief                                SafeCloud server object constructor
    * @param srvPort                        The OS port the server should bind on
    * @throws ERR_SRV_PORT_INVALID          Invalid server port
    * @throws ERR_SRV_PRIVKFILE_NOT_FOUND   The server RSA private key file was not found
    * @throws ERR_SRV_PRIVKFILE_OPEN_FAILED Error in opening the server's RSA private key file
    * @throws ERR_FILE_CLOSE_FAILED         Error in closing the server's RSA private key file
    * @throws ERR_SRV_PRIVK_INVALID         The contents of the server's private key file could not be interpreted as a valid RSA key pair
    * @throws ERR_SRV_CERT_OPEN_FAILED      The server certificate file could not be opened
    * @throws ERR_FILE_CLOSE_FAILED         The server certificate file could not be closed
    * @throws ERR_CA_CERT_INVALID           The server certificate is invalid
    * @throws ERR_LSK_INIT_FAILED           Listening socket initialization failed
    * @throws ERR_LSK_SO_REUSEADDR_FAILED   Error in setting the listening socket's SO_REUSEADDR option
    * @throws ERR_LSK_BIND_FAILED           Error in binding the listening socket on the specified host port
    */
   explicit Server(uint16_t srvPort);

   /**
    * @brief SafeCloud server object destructor, which closes open connections and safely deletes its sensitive attributes
    */
   ~Server();

  /* ============================= OTHER PUBLIC METHODS ============================= */

  /**
   * @brief Asynchronously instructs the server object to
   *        gracefully close all connections and terminate
   */
  void shutdownSignal();

  /**
    * @brief  Returns whether the server has started listening on its listening socket
    * @return 'true' if it is listening, 'false' otherwise
    */
  bool isStarted();

  /**
   * @brief  Returns whether the server is currently connected with at least one client
   * @return 'true' if connected with at least one client, 'false' otherwise
   */
  bool isConnected();

  /**
    * @brief   Returns whether the server object has been instructed
    *          to gracefully close all connections and terminate
    * @return 'true' if the server object is shutting down, 'false' otherwise
    */
  bool isShuttingDown();

  // TODO
  // void serverBody();
 };


#endif //SAFECLOUD_SERVER_H
