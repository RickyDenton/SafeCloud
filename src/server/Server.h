#ifndef SAFECLOUD_SERVER_H
#define SAFECLOUD_SERVER_H

/* SafeCloud Application Server */

#include <openssl/evp.h>
#include <netinet/in.h>
#include "SrvConnMgr.h"

class Server
 {
  private:

   /* ========================= Attributes ========================= */

   // Server connection parameters
   int                 _lsk;       // The file descriptor of the server's listening socket
   struct sockaddr_in* _srvAddr;   // The server's listening socket type, IP and Port in network representation order

   // Server Cryptographic Data
   EVP_PKEY* _rsaKey;              // Long-term server RSA key pair
   X509*     _srvCert;             // The server's X.509 certificate

   // A map associating the file descriptors of open connection
   // sockets to their associated srvConnMgr object (one per client)
   cliMap _cliMap;

   // Used as a temporary identifier for users that
   // have not yet authenticated within the application
   unsigned int _guestIdx;


   /* =========================== Methods =========================== */
   // TODO

  public:

   /* ================= Constructors and Destructor ================= */
   Server(int lsk, struct sockaddr_in* srvAddr, EVP_PKEY* rsaKey, X509* srvCert);
   ~Server();

  /* ======================== Other Methods ======================== */

  // TODO
  // void serverBody();
 };


#endif //SAFECLOUD_SERVER_H
