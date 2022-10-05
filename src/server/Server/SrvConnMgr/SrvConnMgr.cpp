/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errlog.h"

/* =============================== PRIVATE METHODS =============================== */

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
      /* TODO
         If the primary connection buffer is full (which may occur only in the session phase
         when sending/receiving large data), call the SessionMgr bufferFull() data to handle
         it (which at the end should clear the primary input buffer before proceeding)

      if(_priBufInd == _bufSize + 1)
       _srvSessMgr.bufferFull();
      */

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

         // Switch the connection to the SESSION phase
         _connState = SESSION;
        }

       // Inform the Server object that the client connection must be maintained
       return true;
      }

     // Session Phase
     else
      {
       // TODO
       // Call the session's message handler, propagating its indication on whether
       // the client's connection should be maintained to the Server's object
       return _srvSessMgr->SessBlockHandler();
      }
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

  //Log the client's disconnection
  LOG_INFO("\"" + *_name + "\" has disconnected")
 }

/* ============================ OTHER PUBLIC METHODS ============================ */
