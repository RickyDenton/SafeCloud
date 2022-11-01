#ifndef SAFECLOUD_SRVCONNMGR_H
#define SAFECLOUD_SRVCONNMGR_H

/* SafeCloud Server Connection Manager  */

/* ================================== INCLUDES ================================== */
#include "SafeCloudApp/ConnMgr/ConnMgr.h"
#include "SrvSTSMMgr/SrvSTSMMgr.h"
#include "SrvSessMgr/SrvSessMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include <openssl/evp.h>
#include <unordered_map>


class SrvConnMgr : public ConnMgr
 {
  private:

    /* ================================= ATTRIBUTES ================================= */

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

    /* ============================== PRIVATE METHODS ============================== */

    /**
     * @brief  Reads data belonging to a SafeCloud message (STSMMsg or SessMsg)
     *         from the connection socket into the primary connection buffer
     * @return Whether a complete SafeCloud message has
     *         been received in the primary connection buffer
     * @throws ERR_CSK_RECV_FAILED    Error in receiving data from the connection socket
     * @throws ERR_PEER_DISCONNECTED  The connection peer has abruptly disconnected
     * @throws ERR_MSG_LENGTH_INVALID Received an invalid message length value
     */
    bool srvRecvMsgData();

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
   * @throws ERR_CONNMGR_INVALID_STATE The connection is not in the session phase
   */
  SrvSessMgr* getSession();

  /**
   * @brief  SafeCloud client data general handler, which depending on the connection manager's reception mode:\n
   *            - RECV_MSG: Reads bytes belonging to a SafeCloud message into the primary connection
   *                        buffer, calling, depending on the connection state, the associated
   *                        STSMMsg or SessMsg handler if a full message has been received.\n
   *            - RECV_RAW: Reads bytes belonging to the same data block into the primary\n
   *                        connection buffer and passes them to the session raw handler
   * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
   * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
   * @throws ERR_MSG_LENGTH_INVALID    Received an invalid message length value
   * @throws ERR_CONNMGR_INVALID_STATE The connection manager is in the 'RECV_RAW'
   *                                   mode in the STSM Key establishment phase
   * @throws All of the STSM, session, and most of the OpenSSL exceptions
   *         (see "execErrCode.h" and "sessErrCodes.h" for more details)
   */
  void srvRecvHandleData();
 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map mapping the file descriptors of open connection sockets with
// their associated srvConnMgr objects and thus their associated guests or clients
typedef std::unordered_map<int,SrvConnMgr*> connMap;

// connMap iterator type
typedef std::unordered_map<int,SrvConnMgr*>::iterator connMapIt;


#endif //SAFECLOUD_SRVCONNMGR_H
