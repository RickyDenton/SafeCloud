/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"

/* =============================== PRIVATE METHODS =============================== */

/**
 * @brief  Returns a pointer to the session manager's child object
 * @return A pointer to the session manager's child object
 * @throws ERR_CONN_NO_SESSION The connection is not in the session phase
 */
SrvSessMgr* SrvConnMgr::getSession()
 {
  if(_connState != SESSION || _srvSessMgr == nullptr)
   THROW_EXEC_EXCP(ERR_CONN_NO_SESSION);
  return _srvSessMgr;
 }


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
bool SrvConnMgr::recvHandleData()
 {
  try
   {
    // Read data from the connection socket and, if a full data block was NOT received
    if(!recvData())
     {
      // If the connection is in the session phase and the SessMgr child object is expecting raw data, call the appropriate handler
      if(_connState == SESSION && _srvSessMgr != nullptr && _srvSessMgr->passRawData())
       _srvSessMgr->recvRaw();

      // Reset the index of the most significant byte in the primary connection buffer
      _priBufInd = 0;

      // Inform the Server object that the client connection must be maintained
      return true;
     }

    // Otherwise, if a complete data block was received, depending on
    // the connection's current state (key establishment or session)
    else

     // Key establishment phase (STSM protocol)
     if(_connState == KEYXCHANGE)
      {
       // Call the STSM message handler and, if it informs that the
       // STSM key establishment protocol was completed successfully
       if(_srvSTSMMgr->STSMMsgHandler())
        {
         // Delete the SrvSTSMMgr child object
         delete _srvSTSMMgr;
         _srvSTSMMgr = nullptr;

         // Instantiate the SrvSessMgr child object
         _srvSessMgr = new SrvSessMgr(*this);

         // Switch the connection to the SESSION phase
         _connState = SESSION;
        }

       // Inform the Server object that the client connection must be maintained
       return true;
      }

     // Session Phase
     else
      {
       // Call the server session message handler, propagating its indication on whether
       // the client's connection should be maintained to the Server's object
       return _srvSessMgr->recvSrvSessMsg();
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

  //Log the client's disconnection
  LOG_INFO("\"" + *_name + "\" has disconnected")
 }

/* ============================ OTHER PUBLIC METHODS ============================ */
