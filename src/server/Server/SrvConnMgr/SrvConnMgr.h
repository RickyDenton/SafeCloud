#ifndef SAFECLOUD_SRVCONNMGR_H
#define SAFECLOUD_SRVCONNMGR_H

/* SafeCloud Server Connection Manager  */

/* ================================== INCLUDES ================================== */
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

    // Whether the client's connection should be
    // maintained after receiving and parsing its data
    bool               _keepConn;

    // The absolute path of the storage pool of the
    // authenticated client associated with this manager
    std::string*       _poolDir;

    // The child server STSM key establishment manager object
    SrvSTSMMgr*        _srvSTSMMgr;

    // The child server Session Manager object
    SrvSessMgr*        _srvSessMgr;


   /* =============================== FRIEND CLASSES =============================== */
   friend class SrvSTSMMgr;
   friend class SrvSessMgr;

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
   * @brief  Returns whether the client's connection should be maintained
   * @return whether the client's connection should be maintained
   */
  bool keepConn() const;

  /**
   * @brief  Returns a pointer to the session manager's child object
   * @return A pointer to the session manager's child object
   * @throws ERR_CONNMGR_INVALID_STATE The connection is not in the session phase
   */
  SrvSessMgr* getSession();

  /**
   * @brief  Reads data from the manager's connection socket and:\n
   *           - ConnMgr in RECV_MSG mode: If a complete message has been read, depending on the connection state the
   *                                       message handler of the srvSTSMMgr or srvSessMgr child object is invoked\n
   *           - ConnMgr in RECV_RAW mode: The raw data handler of the srvSessMgr child object is invoked\n
   * @note:  In RECV_MSG mode, if the message being received is incomplete no other action is performed
   * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
   * @throws ERR_CLI_DISCONNECTED The client has abruptly disconnected
   * @throws ERR_CONNMGR_INVALID_STATE Attempting to receive raw data with the
   *                                   connection in the STSM key establishment phase
   * @throws All of the STSM, session, and most of the OpenSSL exceptions
   *         (see "execErrCode.h" and "sessErrCodes.h" for more details)
   */
  void recvHandleData();
 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map mapping the file descriptors of open connection sockets with
// their associated srvConnMgr objects and thus their associated guests or clients
typedef std::unordered_map<int,SrvConnMgr*> connMap;

// connMap iterator type
typedef std::unordered_map<int,SrvConnMgr*>::iterator connMapIt;


#endif //SAFECLOUD_SRVCONNMGR_H
