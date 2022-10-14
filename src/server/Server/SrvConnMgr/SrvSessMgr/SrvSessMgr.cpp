/* SafeCloud Server Session Manager Class Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"
#include "../SrvConnMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/**
 * @brief Sends a session message signaling type to the client and performs the actions
 *        appropriate to session signaling types resetting or terminating the session
 * @param sessMsgSignalingType The session message signaling type to be sent to the client
 * @param errReason            An optional error reason to be embedded with the exception that
 *                             must be thrown after sending such session message signaling type
 * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message invalid for its current state
 * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
 * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType)
 { sendSrvSessSignalMsg(sessMsgSignalingType,""); }

void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason)
 {
  // Attempt to send the signaling session message
  try
   { sendSessSignalMsg(sessMsgSignalingType); }
  catch(execErrExcp& sendSessSignExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_CLI_DISCONNECTED error code
    if(sendSessSignExcp.exErrcode == ERR_PEER_DISCONNECTED)
     sendSessSignExcp.exErrcode = ERR_CLI_DISCONNECTED;

    // Rethrow the exception
    throw;
   }

  // In case of signaling messages resetting or terminating the session,
  // perform their associated actions or raise their associated exceptions
  switch(sessMsgSignalingType)
   {
    // The connection manager (and the SafeCloud server as a whole) is terminating
    case BYE:

     // Set that this client connection must be closed
     _srvConnMgr._keepConn = false;
     break;

    // The server session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A session message invalid for the current server session manager was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // The other signaling message types require no further action
    default:
     break;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Server session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the srvConnMgr parent object
 * @param srvConnMgr A reference to the server connection manager parent object
 */
SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessMgrSubstate(SRV_IDLE), _srvConnMgr(srvConnMgr)
 {}

/* Same destructor of the SessMgr base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets all session parameters in preparation for the next
 *        session command to be executed by the server session manager
 */
void SrvSessMgr::resetSrvSessState()
 {
  // Reset the server session manage sub-state
  _srvSessMgrSubstate = SRV_IDLE;

  // Reset the base session parameters
  resetSessState();

  // TODO: Necessary? why?
  // Set that the client connection must be maintained
  // _srvConnMgr._keepConn = true;
 }



// TODO
void SrvSessMgr::SessMsgHandler()
{
 // TODO: Remove
 std::cout << "in SessMsgHandler()" << std::endl;

 // unwrap the received session message into the
 // associated connection manager's secondary buffer
  unwrapSessMsg();

 // Interpret the contents of the associated connection
 // manager's secondary buffer as a session message
 SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_srvConnMgr._secBuf);

 // Ensure that a session message valid for the current
 // command and command sub-state have been received,

 /*
  * Check whether the received session message type:
  *   1) Is session-resetting or terminating
  *   2) Is allowed in the current server session manager state
  */
 switch(sessMsg->msgType)
  {
   // Command-starting session messages, which can be
   // received exclusively in the "IDLE" command state
   case FILE_UPLOAD_REQ:
   case FILE_DOWNLOAD_REQ:
   case FILE_DELETE_REQ:
   case FILE_RENAME_REQ:
   case FILE_LIST_REQ:
    if(_sessMgrState != IDLE)
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);
    break;

   // The client is confirming an upload, download or delete commandon
   case CONFIRM:
    if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
         && _srvSessMgrSubstate == WAITING_CLI_CONF))
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);
    break;

   // The client informs that it has successfully
   // completed the current download or list operation
   case COMPLETED:
    if(!((_sessMgrState == DOWNLOAD || _sessMgrState == LIST)
         && _srvSessMgrSubstate == WAITING_CLI_COMPL))
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE);

   // The client has requested to cancel the operation
   case CANCEL:

    // This command should not be received with the server session manager in the IDLE state
    if(_sessMgrState == IDLE)
     LOG_WARNING("[" + *_srvConnMgr._name + "]: Received a session operation cancellation request with the session manager being idle")
    else
     // Log the client-cancelled operation
     LOG_INFO("[" + *_srvConnMgr._name + "]: " + sessMgrStateToStr() + " operation cancelled")

    // Reset the session state and return
    resetSrvSessState();
    return;

   // The client is gracefully disconnecting
   case BYE:

    // Set that the client connection must be closed
    _srvConnMgr._keepConn = false;
    return;

   /* ---------------- Recoverable Errors ---------------- */

   // The client has experienced a recoverable internal error
   case ERR_INTERNAL_ERROR:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client has received an unexpected session message
   case ERR_UNEXPECTED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client has received a malformed session message
   case ERR_MALFORMED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   /* ---------------- Unrecoverable Errors ---------------- */

   // The client has received a session message of unknown type, with
   // its cause associated to a desynchronization between the server
   // and client IV, from which the connection must be aborted
   case ERR_UNKNOWN_SESSMSG_TYPE:
    THROW_EXEC_EXCP(ERR_SESS_SRV_CLI_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // Unknown Message type
   default:
    sendSrvSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE);
  }

 // At this point the received session message is
 // valid for the current server session manager state

 // LOG: Session message length and msgType
 std::cout << "sessMsg->wrapLen" << sessMsg->msgLen << std::endl;
 std::cout << "sessMsg->msgType" << sessMsg->msgType << std::endl;

}


void SrvSessMgr::recvRaw(size_t recvBytes)
 {
  std::cout << "In recvRaw()" << std::endl;
 }