/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"

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
    _keepConn(true), _poolDir(nullptr), _srvSTSMMgr(new SrvSTSMMgr(rsaKey,*this,srvCert)), _srvSessMgr(nullptr)
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

  //Log the client's disconnection
  LOG_INFO("\"" + *_name + "\" has disconnected")
 }

/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Returns whether the client's connection should be maintained
 * @return whether the client's connection should be maintained
 */
bool SrvConnMgr::keepConn() const
 { return _keepConn; }

/**
 * @brief  Returns a pointer to the session manager's child object
 * @return A pointer to the session manager's child object
 * @throws ERR_CONNMGR_INVALID_STATE The connection is not in the session phase
 */
SrvSessMgr* SrvConnMgr::getSession()
 {
  if(_connPhase != SESSION || _srvSessMgr == nullptr)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE,
                   "Attempting to retrieve the child session object with "
                   "the connection still in the STSM key exchange phase");
  return _srvSessMgr;
 }


// TODO: Possibly update the description depending on the "_srvSessMgr.bufferFull()" implementation
/**
 * @brief  Reads data from the client's connection socket and, if a complete data block was received, calls
 *         the handler associated with the connection's current state (KEYXCHANGE or SESSION)
 * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
 * @throws ERR_CLI_DISCONNECTED Abrupt client disconnection
 * @throws TODO (probably all connection exceptions)
 */




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
void SrvConnMgr::recvHandleData()
 {
  try
   {
    /*
     * If the connection manager is in the RECV_MSG mode and a
     * complete message has been read in the primary connection buffer
     *
     * NOTE: In RECV_MSG mode, if the message being received
     *       is incomplete no other action is performed
     */
    if(_recvMode == RECV_MSG && recvData())
     {
      // If the connection is in the STSM Key establishment phase
      if(_connPhase == KEYXCHANGE)
       {
        // Call the child SrvSTSMMgr object message handler and, if it returns
        // that the key establishment protocol has completed successfully
        if(_srvSTSMMgr->STSMMsgHandler())
         {
          // Delete the SrvSTSMMgr child object
          delete _srvSTSMMgr;
          _srvSTSMMgr = nullptr;

          // Instantiate the SrvSessMgr child object
          _srvSessMgr = new SrvSessMgr(*this);

          // Switch the connection to the SESSION phase
          _connPhase = SESSION;
         }
       }

      // Otherwise if the connection is in the session phase,
      // call the child SrvSessMgr object message handler
      else
       _srvSessMgr->SessMsgHandler();
     }

    // Otherwise, if the connection manager is in the RECV_MSG
    else
     if(_recvMode == RECV_RAW)
      {
       // Ensure the connection to be in the session phase and the
       // SrvSessMgr child object to have been instantiated
       if(_connPhase != SESSION || _srvSessMgr == nullptr)
        THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE,"RECV_RAW mode set in the STSM Key establishment phase");

       // Read raw data from the connection socket
       size_t recvBytes = recvData();

       // Call the child SrvSessMgr object raw data handler passing the
       // number of bytes that have been read from the connection socket
       _srvSessMgr->recvRaw(recvBytes);
      }
   }
  catch(execErrExcp& recvExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_CLI_DISCONNECTED error code
    if(recvExcp.exErrcode == ERR_PEER_DISCONNECTED)
     recvExcp.exErrcode = ERR_CLI_DISCONNECTED;

    // Rethrow the exception
    throw;
   }
 }