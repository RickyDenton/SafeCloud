#ifndef SAFECLOUD_SRVCONNMGR_H
#define SAFECLOUD_SRVCONNMGR_H

/* SafeCloud Server Connection Manager  */

#include "ConnMgr/ConnMgr.h"
#include "SrvSTSMMgr/SrvSTSMMgr.h"
#include "SrvSessMgr/SrvSessMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include <openssl/evp.h>
#include <unordered_map>

class SrvConnMgr : public ConnMgr
 {
  private:


    /* ================================= ATTRIBUTES ================================= */
    std::string*       _poolDir;     // The connected client's pool directory

    SrvSTSMMgr*        _srvSTSMMgr;  // The child server STSM key establishment manager
    SrvSessMgr*        _srvSessMgr;  // The child server session manager



   /* =============================== FRIEND CLASSES =============================== */
   friend class SrvSTSMMgr;
   friend class SrvSessMgr;

   /* =============================== PRIVATE METHODS =============================== */


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief          SrvConnMgr object constructor
    * @param csk      The connection socket associated with this manager
    * @param guestIdx The connected client's temporary identifier
    * @param rsaKey   The server's long-term RSA key pair
    * @param srvCert  The server's X.509 certificate
    * @note The constructor also initializes the _srvSTSMMgr child object
    */
   SrvConnMgr(int csk, unsigned int guestIdx, EVP_PKEY* rsaKey, X509* srvCert);

   /**
    * @brief SrvConnMgr object destructor, which safely deletes
    *        the server-specific connection sensitive information
    */
   ~SrvConnMgr();

  /* ============================= OTHER PUBLIC METHODS ============================= */

  /**
   * @brief  Returns a pointer to the session manager's child object
   * @return A pointer to the session manager's child object
   * @throws ERR_CONN_NO_SESSION The connection is not in the session phase
   */
  SrvSessMgr* getSession();

  // TODO: Possibly update the description depending on the "_srvSessMgr.bufferFull()" implementation
  /**
   * @brief  Reads data from the client's connection socket and, if a complete data block was received, calls
   *         the handler associated with the connection's current state (KEYXCHANGE or SESSION), returning
   *         an indication to the Server object whether this client connection should be maintained
   * @return 'true' if the client connection must be maintained or 'false' otherwise
   * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
   * @throws ERR_CLI_DISCONNECTED Abrupt client disconnection
   * @throws TODO (probably all connection exceptions)
   */
  bool recvHandleData();




 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map mapping the file descriptors of open connection sockets with
// their associated srvConnMgr object, and thus a client connected with the server
typedef std::unordered_map<int,SrvConnMgr*> connMap;

// connMap msgType iterator
typedef std::unordered_map<int,SrvConnMgr*>::iterator connMapIt;

#endif //SAFECLOUD_SRVCONNMGR_H
