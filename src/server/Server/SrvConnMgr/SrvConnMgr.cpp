/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"


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
bool SrvConnMgr::srvRecvMsgData()
 {
  /*
   * If the expected length of the message to be received is not known,
   * receive it from the connection socket into the primary connection buffer
   *
   * NOTE: As by means of the select() in Server.ccp the connection socket
   *       has input data available, supposing that at least two bytes
   *       were received the recvMsgLenHeader() function never blocks
   */
  if(_recvBlockSize == 0)
   recvMsgLenHeader();

  // Receive part of the message's contents, if any
  recvRaw();

  // Return whether a complete SafeCloud message (STSMMsg or
  // SessMsg) has been received in the primary connection buffer
  return (_recvBlockSize == _priBufInd);
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
void SrvConnMgr::srvRecvHandleData()
 {
  // If the connection manager is in the 'RECV_MSG' reception mode
  if(_recvMode == RECV_MSG)
   {
    // Read data belonging to a SafeCloud message (STSMMsg or SessMsg) from the connection socket
    // into the primary connection buffer, returning if a full message has not been received yet
    if(!srvRecvMsgData())
     return;

     // If a full SafeCloud message has been received
    else
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
       _srvSessMgr->srvSessMsgHandler();

      /* ---------- Message Reception Cleanup ---------- */

      // Reset the index of the most significant
      // byte in the primary connection buffer
      _priBufInd = 0;

      // If the reception mode is still 'RECV_MSG', reset
      // the expected size of the message  to be received
      if(_recvMode == RECV_MSG)
       _recvBlockSize = 0;
     }
   }

   // Otherwise, if the connection manager is in the 'RECV_RAW' reception mode
  else
   if(_recvMode == RECV_RAW)
    {
     // Ensure the connection to be in the session phase and
     // the 'SrvSessMgr' child object to have been instantiated
     if(_connPhase != SESSION || _srvSessMgr == nullptr)
      THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE, "Connection manager in RECV_RAW mode"
                                                 "during the STSM Key establishment phase");

     // Reads bytes belonging to the same data block from the connection socket into
     // the primary connection buffer and pass them to the session raw  handler
     _srvSessMgr->srvSessRawHandler(recvRaw());
    }
 }