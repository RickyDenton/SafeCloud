/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errlog.h"

/* =============================== PRIVATE METHODS =============================== */

// TODO: Fix description depending on the _srvSessMgr.bufferFull() implementation
/**
 * @brief Reads data from the client's connection socket and, if a full data block has been received.
 *        passes it to the appropriate handler depending on the connection state, propagating its
 *        indication on whether to maintain the client's connection to the Server object
 * @return 'true' if the client connection must be maintained or 'false' otherwise
 * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
 * @throws ERR_CLI_DISCONNECTED Abrupt client disconnection
 */
bool SrvConnMgr::recvHandleData()
 {
  try
   {
    // Read data from the connection socket and, if a full data block was NOT received
    if(!recvData())
     {
      /* TODO
         If the primary connection buffer is full (which may occur only in the session phase
         when sending/receiving large data), call the SessionMgr bufferFull() data to handle
         it (which at the end should clear the primary input buffer before proceeding)

      if(_priBufInd == _bufSize + 1)
       _srvSessMgr.bufferFull();
      */

      // Return that the client connection should be maintained
      return true;
     }

    // Otherwise, if a full data block was received from the connection socket, call
    // the appropriate handle depending on the connection's state, propagating its
    // indication on whether to persist the client's connection to the Server object
    else
     if(_connState == KEYXCHANGE)
      return _srvSTSMMgr->STSMMsgHandler();
     else
      return _srvSessMgr->SessBlockHandler();
   }
  catch(sCodeException& recvExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_CLI_DISCONNECTED error code
    if(recvExcp.scode == ERR_PEER_DISCONNECTED)
     recvExcp.scode = ERR_CLI_DISCONNECTED;

    // Rethrow the exception
    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief          SrvConnMgr object constructor
 * @param csk      The connection socket associated with this manager
 * @param guestIdx The connected client's temporary identifier
 * @param rsaKey   The server's long-term RSA key pair
 * @param srvCert  The server's X.509 certificate
 * @note The constructor also initializes the _srvSTSMMgr child object
 */
SrvConnMgr::SrvConnMgr(int csk, unsigned int guestIdx, EVP_PKEY* rsaKey, X509* srvCert)
  : ConnMgr(csk,new std::string("Guest" + std::to_string(guestIdx)),nullptr),
    _poolDir(nullptr), _srvSTSMMgr(new SrvSTSMMgr(rsaKey,*this,srvCert)), _srvSessMgr(nullptr)
 {
  // Log the client's connection
  LOG_INFO("\"" + *_name + "\" has connected")
 }


/**
 * @brief SrvConnMgr object destructor, safely deleting the
 *        server-specific connection sensitive information
 */
SrvConnMgr::~SrvConnMgr()
 {
  // Delete the connection manager's child objects
  delete _srvSTSMMgr;
  delete _srvSessMgr;
 }

/* ============================ OTHER PUBLIC METHODS ============================ */
