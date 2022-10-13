/* SafeCloud Server Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"
#include "../SrvConnMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"




void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgType)
 {
  // Send the session signaling message
  sendSessSignalMsg(sessMsgType);

  // In case of session state resetting, terminating or errors,
  // perform the appropriate actions or raise the appropriate exception
  switch(sessMsgType)
   {
    case BYE:

     // Set that the client connection must be closed
     _srvConnMgr._keepConn = false;
     break;

    /* -------------- Error Signaling Messages -------------- */
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

    // No action
    default:
     break;
   }
 }



/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessMgrSubstate(SRV_IDLE), _srvConnMgr(srvConnMgr)
 {}

// Same destructor of the SessMgr base class

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets the server session manager state
 *        to be ready for the next session command
 */
void SrvSessMgr::resetSrvSessState()
 {
  // Reset the base class state
  resetSessState();

  // Set that the client connection must be maintained
  _srvConnMgr._keepConn = true;
 }








// TODO
void SrvSessMgr::SessMsgHandler()
{
 // TODO: Remove
 std::cout << "in SessMsgHandler()" << std::endl;

 // unwrap the received session message into the
 // associated connection manager's secondary buffer
 unWrapSessMsg();

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