#include "Server.h"

/* SafeCloud Application Server Implementation*/

/* ================================== INCLUDES ================================== */
#include "Server.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief          Server object constructor
 * @param lsk      The file descriptor of the server's listening socket
 * @param srvAddr  The server's listening socket type, IP and Port in network representation order
 * @param rsaKey   Long-term server RSA key pair
 * @param srvCert  The server's X.509 certificate
 */
Server::Server(int lsk, struct sockaddr_in* srvAddr, EVP_PKEY* rsaKey, X509* srvCert)
               : _lsk(lsk), _srvAddr(srvAddr), _rsaKey(rsaKey), _srvCert(srvCert), _guestIdx(1)
 {}


/**
 * @brief Server object destructor, which closes open connections and safely deletes its sensitive attributes
 */
Server::~Server()
 {
  // Cycle through the entire connected clients' map and delete the associated SrvConnMgr objects
  for(cliMapIt it = _cliMap.begin(); it != _cliMap.end(); ++it)
   { delete it->second; }

  // Safely erase all sensitive attribute
  // TODO: Maybe do in server_main.cpp?
  EVP_PKEY_free(_rsaKey);
  X509_free(_srvCert);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */